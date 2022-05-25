use std::collections::HashSet;
use std::hash::Hasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder};
use ipext::IpExt;
use siphasher::sip128::Hasher128;
use tokio::net::UdpSocket;

use crate::errors::*;
use crate::*;

pub const ANONYMIZED_DNSCRYPT_V1_QUERY_MAGIC: [u8; 10] =
    [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00];

pub const ANONYMIZED_DNSCRYPT_OVERHEAD: usize = 16 + 2;

pub const ANONYMIZED_DNSCRYPT_V1_HEADER_LEN: usize =
    ANONYMIZED_DNSCRYPT_V1_QUERY_MAGIC.len() + ANONYMIZED_DNSCRYPT_OVERHEAD;

// for TLV like version 2 format
pub const ANONYMIZED_DNSCRYPT_V2_QUERY_MAGIC: [u8; 10] =
    [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00];

pub const RELAYED_CERT_CACHE_SIZE: usize = 1000;
pub const RELAYED_CERT_CACHE_TTL: u32 = 600;

fn get_new_node(bin: &[u8]) -> std::net::SocketAddr {
    let ip_bin = &bin[..16];
    let port_bin = &bin[16..18];

    let ip_v6 = Ipv6Addr::new(
        BigEndian::read_u16(&ip_bin[0..2]),
        BigEndian::read_u16(&ip_bin[2..4]),
        BigEndian::read_u16(&ip_bin[4..6]),
        BigEndian::read_u16(&ip_bin[6..8]),
        BigEndian::read_u16(&ip_bin[8..10]),
        BigEndian::read_u16(&ip_bin[10..12]),
        BigEndian::read_u16(&ip_bin[12..14]),
        BigEndian::read_u16(&ip_bin[14..16]),
    );
    let ip = match ip_v6.to_ipv4() {
        Some(ip_v4) => IpAddr::V4(ip_v4),
        None => IpAddr::V6(ip_v6),
    };
    let port = BigEndian::read_u16(port_bin);

    std::net::SocketAddr::new(ip, port)
}

pub async fn handle_anonymized_dns(
    globals: Arc<Globals>,
    client_ctx: ClientCtx,
    relayed_packet: &[u8],
    version: usize,
) -> Result<(), Error> {
    ensure!(
        relayed_packet.len() > ANONYMIZED_DNSCRYPT_OVERHEAD,
        "Short packet"
    );
    ensure!(version == 1 || version == 2, "Invalid version");
    // version params
    let (offset_ip_addr, ip_port_block_size) = if version == 1 {
        (
            0,
            ANONYMIZED_DNSCRYPT_V1_QUERY_MAGIC.len() + ANONYMIZED_DNSCRYPT_OVERHEAD,
        )
    } else {
        (2, ANONYMIZED_DNSCRYPT_OVERHEAD)
    };

    let nexthop_node = get_new_node(
        &relayed_packet[offset_ip_addr..(offset_ip_addr + ANONYMIZED_DNSCRYPT_OVERHEAD)],
    );
    let nexthop_ip = nexthop_node.ip();
    let nexthop_port = nexthop_node.port();

    #[cfg(feature = "metrics")]
    globals.varz.anonymized_queries.inc();

    ensure!(IpExt::is_global(&nexthop_ip), "Forbidden upstream address");
    ensure!(
        !globals.anonymized_dns_blacklisted_ips.contains(&nexthop_ip),
        "Blacklisted upstream IP"
    );
    ensure!(
        (globals.anonymized_dns_allow_non_reserved_ports && nexthop_port >= 1024)
            || globals.anonymized_dns_allowed_ports.contains(&nexthop_port),
        "Forbidden upstream port"
    );
    let upstream_address = SocketAddr::new(nexthop_ip, nexthop_port);
    ensure!(
        !globals.listen_addrs.contains(&upstream_address)
            && globals.external_addr != Some(upstream_address),
        "Would be relaying to self"
    );
    let encrypted_packet = &relayed_packet[(offset_ip_addr + ANONYMIZED_DNSCRYPT_OVERHEAD)..];
    let encrypted_packet_len = encrypted_packet.len();
    ensure!(
        (DNS_HEADER_SIZE..=DNSCRYPT_UDP_QUERY_MAX_SIZE).contains(&encrypted_packet_len),
        "Unexpected encapsulated query length"
    );
    ensure!(
        encrypted_packet_len > 8 && [0u8, 0, 0, 0, 0, 0, 0, 1] != encrypted_packet[..8],
        "Protocol confusion with QUIC"
    );
    debug_assert!(
        DNSCRYPT_UDP_QUERY_MIN_SIZE > ANONYMIZED_DNSCRYPT_V1_QUERY_MAGIC.len()
            || DNSCRYPT_UDP_QUERY_MIN_SIZE > ANONYMIZED_DNSCRYPT_V2_QUERY_MAGIC.len() + 2
    );

    /////////////////////////////
    // parse subsequent nodes (including final target = DNS server) after nexthop
    // TODO: V2分岐うざい
    let subsq_nodes_after_nexthop = if version == 1 {
        parse_subsq_after_nexthop_v1(encrypted_packet)?
    } else {
        #[cfg(feature = "metrics")]
        globals.varz.anonymized_queries_modns_v2.inc();
        parse_subsq_after_nexthop_v2(encrypted_packet, BigEndian::read_u16(&relayed_packet[..2]))?
    };
    // limit of max subsequent relays
    ensure!(
        !(subsq_nodes_after_nexthop.len() > globals.anonymized_dns_max_subsequent_relays),
        "Exceeds the maximum allowed number of subsequent relays"
    );

    /////////////////////////////
    // loop detection. if dups are detected, terminate forwarding.
    // TODO: more intelligent loop detection?
    let mut trail: Vec<String> = (&subsq_nodes_after_nexthop)
        .iter()
        .map(|x| x.to_string())
        .collect();
    trail.insert(0, nexthop_node.to_string());
    debug!("[FORK!] trail after this node: {:?}", trail); // for debug
    let my_addrs: Vec<String> = globals
        .listen_addrs_ext
        .iter()
        .map(|x| (x.to_string()))
        .collect();
    trail.extend_from_slice(&my_addrs);
    let node_set: HashSet<&String> = trail.iter().collect();
    ensure!(trail.len() == node_set.len(), "Loop detected");
    /////////////////////////////

    let ext_socket = match globals.external_addr {
        Some(x) => UdpSocket::bind(x).await?,
        None => match upstream_address {
            SocketAddr::V4(_) => {
                UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))).await?
            }
            SocketAddr::V6(s) => {
                UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    0,
                    s.flowinfo(),
                    s.scope_id(),
                )))
                .await?
            }
        },
    };
    ext_socket.connect(&upstream_address).await?;
    // TODO: V2分岐うざい
    if version == 1 || subsq_nodes_after_nexthop.is_empty() {
        ext_socket.send(encrypted_packet).await?;
    } else {
        let mut next = vec![0, 0];
        BigEndian::write_u16(&mut next, subsq_nodes_after_nexthop.len() as u16);
        let mut output = ANONYMIZED_DNSCRYPT_V2_QUERY_MAGIC.to_vec();
        output.extend_from_slice(&next);
        output.extend_from_slice(encrypted_packet);
        ext_socket.send(&output).await?;
    };
    //
    let mut response = vec![0u8; DNSCRYPT_UDP_RESPONSE_MAX_SIZE];
    let (response_len, is_certificate_response) = loop {
        let fut = ext_socket.recv_from(&mut response[..]);
        let (response_len, response_addr) = fut.await?;
        if response_addr != upstream_address {
            continue;
        }
        if is_encrypted_response(&response, response_len) {
            break (response_len, false);
        }
        if is_certificate_response(
            &response,
            encrypted_packet,
            &subsq_nodes_after_nexthop,
            version,
        ) {
            break (response_len, true);
        }
    };
    response.truncate(response_len);
    if is_certificate_response {
        let mut hasher = globals.hasher;
        let offset = ip_port_block_size * subsq_nodes_after_nexthop.len();
        hasher.write(&relayed_packet[offset..(offset + ANONYMIZED_DNSCRYPT_OVERHEAD)]); // target DNS server addr and port
        hasher.write(&dns::qname(&encrypted_packet[offset..])?); // target DNS server qname
        let packet_hash = hasher.finish128().as_u128();
        let cached_response = {
            match globals.cert_cache.lock().get(&packet_hash) {
                None => None,
                Some(response) if !(*response).has_expired() => {
                    trace!("Relayed certificate cached");
                    let mut cached_response = (*response).clone();
                    cached_response.set_tid(dns::tid(&encrypted_packet[offset..]));
                    Some(cached_response.into_response())
                }
                Some(_) => {
                    trace!("Relayed certificate expired");
                    None
                }
            }
        };
        match cached_response {
            None => {
                globals.cert_cache.lock().insert(
                    packet_hash,
                    CachedResponse::new(&globals.cert_cache, response.clone()),
                );
            }
            Some(cached_response) => response = cached_response,
        }
    }

    #[cfg(feature = "metrics")]
    globals.varz.anonymized_responses.inc();
    respond_to_query(client_ctx, response).await
}

#[inline]
fn is_encrypted_response(response: &[u8], response_len: usize) -> bool {
    (DNSCRYPT_UDP_RESPONSE_MIN_SIZE..=DNSCRYPT_UDP_RESPONSE_MAX_SIZE).contains(&response_len)
        && response[..DNSCRYPT_RESPONSE_MAGIC_SIZE] == DNSCRYPT_RESPONSE_MAGIC
}

// parse subsequent nodes that includes the target dns server if multiple relays used
fn parse_subsq_after_nexthop_v1(query: &[u8]) -> Result<Vec<std::net::SocketAddr>, Error> {
    let mut nodes = vec![];
    let magic_len = ANONYMIZED_DNSCRYPT_V1_QUERY_MAGIC.len();
    let mut raw_query_offset = 0;

    loop {
        ensure!(
            !(query[raw_query_offset..].len() < magic_len + ANONYMIZED_DNSCRYPT_OVERHEAD),
            "Invalid header for anonymized DNS"
        );
        let next_header = &query[raw_query_offset..(raw_query_offset + magic_len)];
        if next_header == ANONYMIZED_DNSCRYPT_V1_QUERY_MAGIC {
            let next_node = get_new_node(&query[(raw_query_offset + magic_len)..]);
            nodes.push(next_node);
            raw_query_offset += magic_len + ANONYMIZED_DNSCRYPT_OVERHEAD;
        } else {
            break;
        }
    }

    Ok(nodes)
}

fn parse_subsq_after_nexthop_v2(
    query: &[u8],
    num: u16,
) -> Result<Vec<std::net::SocketAddr>, Error> {
    let mut nodes = vec![];

    if num > 0 {
        ensure!(
            !(query.len() < (num as usize) * ANONYMIZED_DNSCRYPT_OVERHEAD),
            "Invalid header for anonymized DNS v2"
        );
        for i in 0..num - 1 {
            let next_node = get_new_node(&query[((i as usize) * ANONYMIZED_DNSCRYPT_OVERHEAD)..]);
            nodes.push(next_node);
        }
    }

    Ok(nodes)
}

fn is_certificate_response(
    response: &[u8],
    query: &[u8],
    subsequent_nodes: &[std::net::SocketAddr],
    version: usize,
) -> bool {
    let prefix = b"2.dnscrypt-cert.";
    let mut raw_query_offset = 0;
    //////
    // In case where multiple hop nodes exist after this relay.
    if !subsequent_nodes.is_empty() {
        if version == 1 {
            if query.len() > subsequent_nodes.len() * ANONYMIZED_DNSCRYPT_V1_HEADER_LEN {
                raw_query_offset += subsequent_nodes.len() * ANONYMIZED_DNSCRYPT_V1_HEADER_LEN;
            } else {
                error!("[FORK!] Unexpected size of query for multihop relays (version 1)");
                return false;
            }
        } else if query.len() > subsequent_nodes.len() * ANONYMIZED_DNSCRYPT_OVERHEAD {
            raw_query_offset += subsequent_nodes.len() * ANONYMIZED_DNSCRYPT_OVERHEAD;
        } else {
            error!("[FORK!] Unexpected size of query for multihop relays (version 2)");
            return false;
        }
    }
    //////
    if !((DNS_HEADER_SIZE + prefix.len() + 4..=DNS_MAX_PACKET_SIZE)
        .contains(&query[raw_query_offset..].len())
        && (DNS_HEADER_SIZE + prefix.len() + 4..=DNS_MAX_PACKET_SIZE).contains(&response.len())
        && dns::tid(response) == dns::tid(&query[raw_query_offset..])
        && dns::is_response(response)
        && !dns::is_response(&query[raw_query_offset..]))
    {
        /////////////////////
        // debug!("Cert response: {:?}", response);
        // debug!("Cert query: {:?}", &query[raw_query_offset..]);
        // debug!("Cert response TxID: {:?}", dns::tid(response));
        // debug!(
        //     "Cert query TxID: {:?}",
        //     dns::tid(&query[raw_query_offset..])
        // );
        /////////////////////
        error!("Unexpected relayed cert response");
        return false;
    }
    let qname = match (dns::qname(&query[raw_query_offset..]), dns::qname(response)) {
        (Ok(response_qname), Ok(query_qname)) if response_qname == query_qname => query_qname,
        _ => {
            debug!("Relayed cert qname response didn't match the query qname");
            return false;
        }
    };
    if qname.len() <= prefix.len() || &qname[..prefix.len()] != prefix {
        debug!("Relayed cert qname response didn't start with the standard prefix");
        return false;
    }
    true
}

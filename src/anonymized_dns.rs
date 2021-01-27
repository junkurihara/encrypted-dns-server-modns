use crate::errors::*;
use crate::*;

use byteorder::{BigEndian, ByteOrder};
use ipext::IpExt;
use siphasher::sip128::Hasher128;
use std::hash::Hasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use tokio::net::UdpSocket;

pub const ANONYMIZED_DNSCRYPT_QUERY_MAGIC: [u8; 10] =
    [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00];

pub const ANONYMIZED_DNSCRYPT_OVERHEAD: usize = 16 + 2;

pub const RELAYED_CERT_CACHE_SIZE: usize = 1000;
pub const RELAYED_CERT_CACHE_TTL: u32 = 600;

pub async fn handle_anonymized_dns(
    globals: Arc<Globals>,
    client_ctx: ClientCtx,
    relayed_packet: &[u8],
) -> Result<(), Error> {
    ensure!(
        relayed_packet.len() > ANONYMIZED_DNSCRYPT_OVERHEAD,
        "Short packet"
    );
    let ip_bin = &relayed_packet[..16];
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
    #[cfg(feature = "metrics")]
    globals.varz.anonymized_queries.inc();

    ensure!(IpExt::is_global(&ip), "Forbidden upstream address");
    ensure!(
        !globals.anonymized_dns_blacklisted_ips.contains(&ip),
        "Blacklisted upstream IP"
    );
    let port = BigEndian::read_u16(&relayed_packet[16..18]);
    ensure!(
        (globals.anonymized_dns_allow_non_reserved_ports && port >= 1024)
            || globals.anonymized_dns_allowed_ports.contains(&port),
        "Forbidden upstream port"
    );
    let upstream_address = SocketAddr::new(ip, port);
    ensure!(
        !globals.listen_addrs.contains(&upstream_address)
            && globals.external_addr != Some(upstream_address),
        "Would be relaying to self"
    );
    let encrypted_packet = &relayed_packet[ANONYMIZED_DNSCRYPT_OVERHEAD..];
    let encrypted_packet_len = encrypted_packet.len();
    ensure!(
        encrypted_packet_len >= ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len() + DNS_HEADER_SIZE
            && encrypted_packet_len <= DNSCRYPT_UDP_QUERY_MAX_SIZE,
        "Unexpected encapsulated query length"
    );
    ensure!(
        encrypted_packet_len > 8 && [0u8, 0, 0, 0, 0, 0, 0, 1] != encrypted_packet[..8],
        "Protocol confusion with QUIC"
    );
    debug_assert!(DNSCRYPT_UDP_QUERY_MIN_SIZE > ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len());
    /////////////////////////////
    // TODO: 安全のためにはここのループ判定の条件を難しくしないとダメ。一応コメントアウトで対処。
    // TODO: このとき、最大ホップ数とかで落としてあげるのが優しいと思われる。
    // TODO: ループディテクションはないとたしかに厳しいので、一旦バラしてどうの、というのを考えるほうが良さそう。
    // TODO: 本当はプロキシの方でもちゃんとやるほうが良いと思われる。
    let trailing_relays_num = count_trailing_relays(&encrypted_packet);
    debug!("num of trailing relays: {}", trailing_relays_num);
    // ensure!(
    //     encrypted_packet[..ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len()]
    //         != ANONYMIZED_DNSCRYPT_QUERY_MAGIC,
    //     "Loop detected"
    // );
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
    ext_socket.send(&encrypted_packet).await?;
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
        if is_certificate_response(&response, &encrypted_packet) {
            break (response_len, true);
        }
    };
    response.truncate(response_len);
    if is_certificate_response {
        debug!("certificate response {:?}", response);
        // TODO: キャッシュがうまくできていない
        // 以下で落ちてるっぽい。
        let mut hasher = globals.hasher;
        let offset = (ANONYMIZED_DNSCRYPT_OVERHEAD + ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len())
            * (trailing_relays_num as usize);
        hasher.write(&relayed_packet[offset..(offset + ANONYMIZED_DNSCRYPT_OVERHEAD)]); // target DNS server addr and port
        hasher.write(&dns::qname(&encrypted_packet[offset..])?); // target DNS server qname
        let packet_hash = hasher.finish128().as_u128();
        let cached_response = {
            match globals.cert_cache.lock().get(&packet_hash) {
                None => None,
                Some(response) if !(*response).has_expired() => {
                    trace!("Relayed certificate cached");
                    let mut cached_response = (*response).clone();
                    cached_response.set_tid(dns::tid(encrypted_packet));
                    Some(cached_response.into_response())
                }
                Some(_) => {
                    trace!("Relayed certificate expired");
                    None
                }
            }
        };
        debug!("if going well, this message is displayed {:?}", response);
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

fn count_trailing_relays(query: &[u8]) -> u8 {
    let magic_len = ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len();
    let mut cnt = 0;
    let mut raw_query_offset = 0;

    loop {
        if query[raw_query_offset..].len() < magic_len + ANONYMIZED_DNSCRYPT_OVERHEAD {
            break;
        }
        let next_header = &query[raw_query_offset..(raw_query_offset + magic_len)];
        if next_header == ANONYMIZED_DNSCRYPT_QUERY_MAGIC {
            cnt += 1;
            raw_query_offset += magic_len + ANONYMIZED_DNSCRYPT_OVERHEAD;
        } else {
            break;
        }
    }
    cnt
}

fn is_certificate_response(response: &[u8], query: &[u8]) -> bool {
    let prefix = b"2.dnscrypt-cert.";
    /////////////
    // TODO: 以下デバッグメモ
    // TODO: queryと比較するときちゃんと次のリレー分のヘッダも外して検証してあげないといけないよ！！！！！！！！！
    // TODO: TODO:TODO: TODO:TODO: TODO:TODO: TODO:TODO: TODO:TODO: TODO:
    // TODO: 再帰にする
    // TODO: 多分うまくレスポンス返せていない
    let magic_len = ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len();
    let mut raw_query_offset = 0;
    // check length first
    if query.len() > magic_len + ANONYMIZED_DNSCRYPT_OVERHEAD {
        let next_header = &query[..magic_len];
        let next_ip_port = &query[magic_len..(magic_len + ANONYMIZED_DNSCRYPT_OVERHEAD)];
        debug!("next header? {:?}", next_header);
        debug!("next ip and port? {:?}", next_ip_port);
        if next_header == ANONYMIZED_DNSCRYPT_QUERY_MAGIC {
            debug!("multi hop relayed cert query");
            raw_query_offset += magic_len + ANONYMIZED_DNSCRYPT_OVERHEAD;
        }
    }

    // debug!("{:?}, {:?}", response.len(), query.len());
    // debug!("{:?}", dns::is_response(response));
    // debug!("{:?}", !dns::is_response(query)); // ここがたまにfalseになる。このときは必ずtid(query)がクソでかい。
    // debug!("{:?}, {:?}", dns::tid(response), dns::tid(query));
    // debug!(
    //     "{:?}",
    //     (DNS_HEADER_SIZE + prefix.len() + 4..=DNS_MAX_PACKET_SIZE).contains(&response.len())
    // );
    // debug!(
    //     "{:?}",
    //     (DNS_HEADER_SIZE + prefix.len() + 4..=DNS_MAX_PACKET_SIZE).contains(&query.len())
    // );
    /////////////
    if !((DNS_HEADER_SIZE + prefix.len() + 4..=DNS_MAX_PACKET_SIZE)
        .contains(&query[raw_query_offset..].len())
        && (DNS_HEADER_SIZE + prefix.len() + 4..=DNS_MAX_PACKET_SIZE).contains(&response.len())
        && dns::tid(response) == dns::tid(&query[raw_query_offset..])
        && dns::is_response(response)
        && !dns::is_response(&query[raw_query_offset..]))
    {
        debug!("Unexpected relayed cert response");
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

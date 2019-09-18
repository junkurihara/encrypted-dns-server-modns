use crate::crypto::*;
use crate::dns::*;
use crate::dnscrypt_certs::*;
use crate::errors::*;

use libsodium_sys::*;
use rand::prelude::*;
use std::ffi::CStr;
use std::ptr;

pub const DNSCRYPT_FULL_NONCE_SIZE: usize =
    crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize;
pub const DNSCRYPT_MAC_SIZE: usize = crypto_box_curve25519xchacha20poly1305_MACBYTES as usize;

pub const DNSCRYPT_QUERY_MAGIC_SIZE: usize = 8;
pub const DNSCRYPT_QUERY_PK_SIZE: usize = 32;
pub const DNSCRYPT_QUERY_NONCE_SIZE: usize = DNSCRYPT_FULL_NONCE_SIZE / 2;
pub const DNSCRYPT_QUERY_HEADER_SIZE: usize =
    DNSCRYPT_QUERY_MAGIC_SIZE + DNSCRYPT_QUERY_PK_SIZE + DNSCRYPT_QUERY_NONCE_SIZE;
pub const DNSCRYPT_QUERY_MIN_PADDING_SIZE: usize = 1;
pub const DNSCRYPT_QUERY_MIN_OVERHEAD: usize =
    DNSCRYPT_QUERY_HEADER_SIZE + DNSCRYPT_MAC_SIZE + DNSCRYPT_QUERY_MIN_PADDING_SIZE;

pub const DNSCRYPT_RESPONSE_MAGIC_SIZE: usize = 8;
pub const DNSCRYPT_RESPONSE_NONCE_SIZE: usize = DNSCRYPT_FULL_NONCE_SIZE;
pub const DNSCRYPT_RESPONSE_HEADER_SIZE: usize =
    DNSCRYPT_RESPONSE_MAGIC_SIZE + DNSCRYPT_RESPONSE_NONCE_SIZE;
pub const DNSCRYPT_RESPONSE_MIN_PADDING_SIZE: usize = 1;
pub const DNSCRYPT_RESPONSE_MIN_OVERHEAD: usize =
    DNSCRYPT_RESPONSE_HEADER_SIZE + DNSCRYPT_MAC_SIZE + DNSCRYPT_RESPONSE_MIN_PADDING_SIZE;

pub const DNSCRYPT_UDP_QUERY_MIN_SIZE: usize = DNSCRYPT_QUERY_MIN_OVERHEAD + DNS_HEADER_SIZE;
pub const DNSCRYPT_UDP_QUERY_MAX_SIZE: usize = DNS_MAX_PACKET_SIZE;
pub const DNSCRYPT_TCP_QUERY_MIN_SIZE: usize = DNSCRYPT_QUERY_MIN_OVERHEAD + DNS_HEADER_SIZE;
pub const DNSCRYPT_TCP_QUERY_MAX_SIZE: usize = DNSCRYPT_QUERY_MIN_OVERHEAD + DNS_MAX_PACKET_SIZE;

pub const DNSCRYPT_UDP_RESPONSE_MIN_SIZE: usize = DNSCRYPT_RESPONSE_MIN_OVERHEAD + DNS_HEADER_SIZE;
pub const DNSCRYPT_UDP_RESPONSE_MAX_SIZE: usize = DNS_MAX_PACKET_SIZE;
pub const DNSCRYPT_TCP_RESPONSE_MIN_SIZE: usize = DNSCRYPT_RESPONSE_MIN_OVERHEAD + DNS_HEADER_SIZE;
pub const DNSCRYPT_TCP_RESPONSE_MAX_SIZE: usize =
    DNSCRYPT_RESPONSE_MIN_OVERHEAD + DNS_MAX_PACKET_SIZE;

pub fn decrypt(
    wrapped_packet: &[u8],
    dnscrypt_encryption_params_set: &[DNSCryptEncryptionParams],
) -> Result<(SharedKey, [u8; DNSCRYPT_FULL_NONCE_SIZE as usize], Vec<u8>), Error> {
    ensure!(
        wrapped_packet.len()
            >= DNSCRYPT_QUERY_MAGIC_SIZE
                + DNSCRYPT_QUERY_PK_SIZE
                + DNSCRYPT_QUERY_NONCE_SIZE
                + DNS_HEADER_SIZE,
        "Short packet"
    );
    let client_magic = &wrapped_packet[..DNSCRYPT_QUERY_MAGIC_SIZE];
    let client_pk = &wrapped_packet
        [DNSCRYPT_QUERY_MAGIC_SIZE..DNSCRYPT_QUERY_MAGIC_SIZE + DNSCRYPT_QUERY_PK_SIZE];
    let client_nonce = &wrapped_packet[DNSCRYPT_QUERY_MAGIC_SIZE + DNSCRYPT_QUERY_PK_SIZE
        ..DNSCRYPT_QUERY_MAGIC_SIZE + DNSCRYPT_QUERY_PK_SIZE + DNSCRYPT_QUERY_NONCE_SIZE];
    let encrypted_packet = &wrapped_packet[DNSCRYPT_QUERY_HEADER_SIZE..];
    let encrypted_packet_len = encrypted_packet.len();

    let dnscrypt_encryption_params = dnscrypt_encryption_params_set
        .iter()
        .find(|p| p.client_magic() == client_magic)
        .ok_or_else(|| format_err!("Client magic not found"))?;

    let mut nonce = [0u8; DNSCRYPT_FULL_NONCE_SIZE as usize];
    nonce[..DNSCRYPT_QUERY_NONCE_SIZE].copy_from_slice(client_nonce);
    let resolver_kp = dnscrypt_encryption_params.resolver_kp();
    let shared_key = resolver_kp.compute_shared_key(client_pk)?;
    let packet = shared_key.decrypt(&nonce, encrypted_packet)?;
    rand::thread_rng().fill_bytes(&mut nonce[DNSCRYPT_QUERY_NONCE_SIZE..]);

    Ok((shared_key, nonce, packet))
}

pub fn encrypt(
    packet: Vec<u8>,
    shared_key: &SharedKey,
    nonce: &[u8; DNSCRYPT_FULL_NONCE_SIZE as usize],
    max_packet_size: usize,
) -> Result<Vec<u8>, Error> {
    let mut wrapped_packet = Vec::with_capacity(DNS_MAX_PACKET_SIZE);
    wrapped_packet.extend_from_slice(&[0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38]);
    wrapped_packet.extend_from_slice(nonce);
    ensure!(
        max_packet_size >= wrapped_packet.len(),
        "Max packet size too short"
    );
    let max_encrypted_size = max_packet_size - wrapped_packet.len();
    shared_key.encrypt_into(
        &mut wrapped_packet,
        nonce,
        &nonce[..DNSCRYPT_QUERY_NONCE_SIZE],
        packet,
        max_encrypted_size,
    )?;
    Ok(wrapped_packet)
}
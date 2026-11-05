//! PRUDP transport.
//!
//! Ported from `nintendo/nex/prudp.py`, limited to UDP (the only transport the
//! 3DS and Wii U use):
//!
//! - PRUDP v0 (3DS, `Settings::load("3ds")`)
//! - PRUDP v1 (Wii U, `Settings::default()`)
//! - RC4 payload encryption and optional zlib compression
//! - reliability (acks, resends), fragmentation and substreams

use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use hmac::{Hmac, Mac};
use log::{debug, trace, warn};
use md5::{Digest, Md5};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;

use crate::nex::kerberos::{self, Credentials, KerberosEncryption, Rc4};
use crate::nex::settings::{Encryption, Settings};
use crate::nex::streams::{StreamError, StreamIn, StreamOut};

type HmacMd5 = Hmac<Md5>;

pub const TYPE_SYN: u8 = 0;
pub const TYPE_CONNECT: u8 = 1;
pub const TYPE_DATA: u8 = 2;
pub const TYPE_DISCONNECT: u8 = 3;
pub const TYPE_PING: u8 = 4;
pub const TYPE_USER: u8 = 5;
pub const TYPE_ROUTE: u8 = 6;
pub const TYPE_RAW: u8 = 7;

pub const FLAG_ACK: u8 = 1;
pub const FLAG_RELIABLE: u8 = 2;
pub const FLAG_NEED_ACK: u8 = 4;
pub const FLAG_HAS_SIZE: u8 = 8;
pub const FLAG_MULTI_ACK: u8 = 0x20;

const OPTION_SUPPORT: u8 = 0;
const OPTION_CONNECTION_SIG: u8 = 1;
const OPTION_FRAGMENT_ID: u8 = 2;
const OPTION_UNRELIABLE_SEQ_ID: u8 = 3;
const OPTION_MAX_SUBSTREAM_ID: u8 = 4;

const DEFAULT_LOCAL_PORT: u8 = 15;
const DEFAULT_LOCAL_TYPE: u8 = 10;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Error returned by the PRUDP layer.
#[derive(Debug, thiserror::Error)]
pub enum PrudpError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("stream error: {0}")]
    Stream(#[from] StreamError),
    #[error("kerberos error: {0}")]
    Kerberos(#[from] kerberos::KerberosError),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("handshake timed out")]
    Timeout,
    #[error("connection is closed")]
    Closed,
}

type Result<T> = std::result::Result<T, PrudpError>;

/// A PRUDP packet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Packet {
    pub kind: u8,
    pub flags: u8,
    pub version: u8,

    pub source_type: u8,
    pub source_port: u8,
    pub dest_type: u8,
    pub dest_port: u8,

    pub session_id: u8,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub substream_id: u8,

    pub connection_signature: Vec<u8>,
    pub initial_unreliable_id: u16,
    pub max_substream_id: u8,
    pub supported_functions: u32,
    pub minor_version: u8,

    pub signature: Vec<u8>,
    pub payload: Vec<u8>,
}

fn access_key(settings: &Settings) -> &[u8] {
    settings.access_key.as_bytes()
}

fn md5(data: &[u8]) -> Vec<u8> {
    let mut hash = Md5::new();
    hash.update(data);
    hash.finalize().to_vec()
}

fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn calc_checksum_v0(settings: &Settings, data: &[u8]) -> u32 {
    let access = access_key(settings);
    let checksum: u32 = access.iter().map(|&byte| u32::from(byte)).sum();

    if settings.checksum_version == 0 {
        let mut sum = checksum & 0xFF;
        for chunk in data.chunks(4) {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            sum = sum.wrapping_add(u32::from_le_bytes(word));
        }
        sum
    } else {
        let words = data.len() / 4;
        let mut temp = 0u32;
        for index in 0..words {
            let start = index * 4;
            temp = temp.wrapping_add(u32::from_le_bytes(
                data[start..start + 4].try_into().unwrap(),
            ));
        }

        let mut sum = checksum;
        sum = sum.wrapping_add(
            data[(data.len() & !3)..]
                .iter()
                .map(|&byte| u32::from(byte))
                .sum::<u32>(),
        );
        sum = sum.wrapping_add(
            temp.to_le_bytes()
                .iter()
                .map(|&byte| u32::from(byte))
                .sum::<u32>(),
        );
        sum & 0xFF
    }
}

fn signature_v0(
    settings: &Settings,
    packet: &Packet,
    session_key: &[u8],
    connection_signature: &[u8],
) -> Vec<u8> {
    if packet.kind == TYPE_DATA
        || (packet.kind == TYPE_DISCONNECT && settings.signature_version == 0)
    {
        let mut data = Vec::new();
        if settings.signature_version == 0 {
            data.extend_from_slice(session_key);
            data.extend_from_slice(&packet.packet_id.to_le_bytes());
            data.push(packet.fragment_id);
        }
        data.extend_from_slice(&packet.payload);

        if data.is_empty() {
            return 0x1234_5678u32.to_le_bytes().to_vec();
        }

        let key = md5(access_key(settings));
        return hmac_md5(&key, &data)[..4].to_vec();
    }

    if !connection_signature.is_empty() {
        return connection_signature.to_vec();
    }
    vec![0; 4]
}

fn signature_v1(
    settings: &Settings,
    packet: &Packet,
    session_key: &[u8],
    connection_signature: &[u8],
) -> Vec<u8> {
    let options = encode_options(packet);
    let header = encode_header_v1(packet, options.len());
    signature_v1_with(
        settings,
        packet,
        session_key,
        connection_signature,
        &options,
        &header,
    )
}

fn signature_v1_with(
    settings: &Settings,
    packet: &Packet,
    session_key: &[u8],
    connection_signature: &[u8],
    options: &[u8],
    header: &[u8],
) -> Vec<u8> {
    let access = access_key(settings);
    let key = md5(access);

    let mut mac = HmacMd5::new_from_slice(&key).expect("HMAC accepts keys of any length");
    mac.update(&header[4..]);
    mac.update(session_key);
    mac.update(&(access.iter().map(|&b| u32::from(b)).sum::<u32>()).to_le_bytes());
    mac.update(connection_signature);
    mac.update(options);
    mac.update(&packet.payload);
    mac.finalize().into_bytes().to_vec()
}

/// Computes the connection signature for the given address.
pub fn connection_signature(version: u8, addr: SocketAddr) -> Vec<u8> {
    let mut data = match addr {
        SocketAddr::V4(addr) => addr.ip().octets().to_vec(),
        SocketAddr::V6(addr) => addr.ip().octets().to_vec(),
    };
    data.extend_from_slice(&addr.port().to_be_bytes());

    if version == 0 {
        let digest = md5(&data);
        digest[..4].iter().rev().copied().collect()
    } else {
        const KEY: [u8; 15] = [
            0x26, 0xc3, 0x1f, 0x38, 0x1e, 0x46, 0xd6, 0xeb, 0x38, 0xe1, 0xaf, 0x6a, 0xb7, 0x0d,
            0x11,
        ];
        hmac_md5(&KEY, &data)
    }
}

fn encode_options(packet: &Packet) -> Vec<u8> {
    let mut data = Vec::new();
    match packet.kind {
        TYPE_SYN | TYPE_CONNECT => {
            push_option(
                &mut data,
                OPTION_SUPPORT,
                &(u32::from(packet.minor_version) | (packet.supported_functions << 8))
                    .to_le_bytes(),
            );

            let mut signature = packet.connection_signature.clone();
            signature.resize(16, 0);
            push_option(&mut data, OPTION_CONNECTION_SIG, &signature);

            if packet.kind == TYPE_CONNECT {
                push_option(
                    &mut data,
                    OPTION_UNRELIABLE_SEQ_ID,
                    &packet.initial_unreliable_id.to_le_bytes(),
                );
            }
            push_option(
                &mut data,
                OPTION_MAX_SUBSTREAM_ID,
                &[packet.max_substream_id],
            );
        }
        TYPE_DATA => {
            push_option(&mut data, OPTION_FRAGMENT_ID, &[packet.fragment_id]);
        }
        _ => {}
    }
    data
}

fn push_option(data: &mut Vec<u8>, kind: u8, value: &[u8]) {
    data.push(kind);
    data.push(value.len() as u8);
    data.extend_from_slice(value);
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Options {
    support: Option<u32>,
    connection_signature: Option<Vec<u8>>,
    fragment_id: Option<u8>,
    unreliable_seq_id: Option<u16>,
    max_substream_id: Option<u8>,
}

fn decode_options(settings: &Settings, data: &[u8]) -> Result<Options> {
    let mut options = Options::default();
    let mut stream = StreamIn::new(settings, data);

    while !stream.eof() {
        let kind = stream.u8()?;
        let length = stream.u8()?;

        match kind {
            OPTION_SUPPORT if length == 4 => {
                if options.support.is_some() {
                    return Err(PrudpError::Protocol("duplicate SUPPORT option".into()));
                }
                options.support = Some(stream.u32()?);
            }
            OPTION_CONNECTION_SIG if length == 16 => {
                if options.connection_signature.is_some() {
                    return Err(PrudpError::Protocol(
                        "duplicate CONNECTION_SIG option".into(),
                    ));
                }
                options.connection_signature = Some(stream.read(16)?.to_vec());
            }
            OPTION_FRAGMENT_ID if length == 1 => {
                if options.fragment_id.is_some() {
                    return Err(PrudpError::Protocol("duplicate FRAGMENT_ID option".into()));
                }
                options.fragment_id = Some(stream.u8()?);
            }
            OPTION_UNRELIABLE_SEQ_ID if length == 2 => {
                if options.unreliable_seq_id.is_some() {
                    return Err(PrudpError::Protocol(
                        "duplicate UNRELIABLE_SEQ_ID option".into(),
                    ));
                }
                options.unreliable_seq_id = Some(stream.u16()?);
            }
            OPTION_MAX_SUBSTREAM_ID if length == 1 => {
                if options.max_substream_id.is_some() {
                    return Err(PrudpError::Protocol(
                        "duplicate MAX_SUBSTREAM_ID option".into(),
                    ));
                }
                options.max_substream_id = Some(stream.u8()?);
            }
            _ => {
                return Err(PrudpError::Protocol(format!(
                    "invalid option {} with length {}",
                    kind, length
                )))
            }
        }
    }

    Ok(options)
}

fn encode_header_v1(packet: &Packet, option_size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(12);
    data.push(1);
    data.push(option_size as u8);
    data.extend_from_slice(&(packet.payload.len() as u16).to_le_bytes());
    data.push(packet.source_port | (packet.source_type << 4));
    data.push(packet.dest_port | (packet.dest_type << 4));
    data.extend_from_slice(
        &(u16::from(packet.kind) | (u16::from(packet.flags) << 4)).to_le_bytes(),
    );
    data.push(packet.session_id);
    data.push(packet.substream_id);
    data.extend_from_slice(&packet.packet_id.to_le_bytes());
    data
}

/// Encodes a packet with the format that belongs to `packet.version`.
pub fn encode(settings: &Settings, packet: &Packet) -> Result<Vec<u8>> {
    if packet.version == 0 {
        let mut data = Vec::new();
        data.push(packet.source_port | (packet.source_type << 4));
        data.push(packet.dest_port | (packet.dest_type << 4));
        if settings.flags_version == 0 {
            data.push(packet.kind | (packet.flags << 3));
        } else {
            data.extend_from_slice(
                &(u16::from(packet.kind) | (u16::from(packet.flags) << 4)).to_le_bytes(),
            );
        }
        data.push(packet.session_id);

        let mut signature = packet.signature.clone();
        signature.resize(4, 0);
        data.extend_from_slice(&signature);
        data.extend_from_slice(&packet.packet_id.to_le_bytes());

        if packet.kind == TYPE_SYN || packet.kind == TYPE_CONNECT {
            let mut connection = packet.connection_signature.clone();
            connection.resize(4, 0);
            data.extend_from_slice(&connection);
        }
        if packet.kind == TYPE_DATA {
            data.push(packet.fragment_id);
        }
        if packet.flags & FLAG_HAS_SIZE != 0 {
            data.extend_from_slice(&(packet.payload.len() as u16).to_le_bytes());
        }
        data.extend_from_slice(&packet.payload);

        let checksum = calc_checksum_v0(settings, &data);
        if settings.checksum_version == 0 {
            data.extend_from_slice(&checksum.to_le_bytes());
        } else {
            data.push(checksum as u8);
        }
        Ok(data)
    } else {
        let options = encode_options(packet);
        let header = encode_header_v1(packet, options.len());
        Ok(encode_v1(packet, &options, &header))
    }
}

fn encode_v1(packet: &Packet, options: &[u8], header: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(2 + header.len() + options.len() + packet.payload.len());
    data.extend_from_slice(b"\xEA\xD0");
    data.extend_from_slice(header);

    let mut signature = packet.signature.clone();
    signature.resize(16, 0);
    data.extend_from_slice(&signature);

    data.extend_from_slice(options);
    data.extend_from_slice(&packet.payload);
    data
}

fn encode_signed(
    version: u8,
    settings: &Settings,
    packet: &mut Packet,
    session_key: &[u8],
    connection_signature: &[u8],
) -> Result<Vec<u8>> {
    if version == 0 {
        packet.signature = signature_v0(settings, packet, session_key, connection_signature);
        return encode(settings, packet);
    }

    let options = encode_options(packet);
    let header = encode_header_v1(packet, options.len());
    packet.signature = signature_v1_with(
        settings,
        packet,
        session_key,
        connection_signature,
        &options,
        &header,
    );
    Ok(encode_v1(packet, &options, &header))
}

/// Decodes one or more packets from a datagram.
pub fn decode(settings: &Settings, data: &[u8]) -> Result<Vec<Packet>> {
    if data.len() >= 3 && data.starts_with(b"\xEA\xD0\x01") {
        decode_v1(settings, data)
    } else {
        decode_v0(settings, data)
    }
}

fn decode_v0(settings: &Settings, data: &[u8]) -> Result<Vec<Packet>> {
    let mut packets = Vec::new();
    let mut stream = StreamIn::new(settings, data);

    while !stream.eof() {
        let start = stream.position();

        let source = stream.u8()?;
        let dest = stream.u8()?;

        let mut packet = Packet {
            version: 0,
            source_type: source >> 4,
            source_port: source & 0xF,
            dest_type: dest >> 4,
            dest_port: dest & 0xF,
            ..Packet::default()
        };

        if settings.flags_version == 0 {
            let type_flags = stream.u8()?;
            packet.flags = type_flags >> 3;
            packet.kind = type_flags & 7;
        } else {
            let type_flags = stream.u16()?;
            packet.flags = (type_flags >> 4) as u8;
            packet.kind = (type_flags & 0xF) as u8;
        }

        packet.session_id = stream.u8()?;
        packet.signature = stream.read(4)?.to_vec();
        packet.packet_id = stream.u16()?;

        if packet.kind == TYPE_SYN || packet.kind == TYPE_CONNECT {
            packet.connection_signature = stream.read(4)?.to_vec();
        }
        if packet.kind == TYPE_DATA {
            packet.fragment_id = stream.u8()?;
        }

        let checksum_size = if settings.checksum_version == 0 { 4 } else { 1 };
        let payload_size = if packet.flags & FLAG_HAS_SIZE != 0 {
            usize::from(stream.u16()?)
        } else {
            stream
                .remaining()
                .checked_sub(checksum_size)
                .ok_or_else(|| PrudpError::Protocol("packet is too short".into()))?
        };
        packet.payload = stream.read(payload_size)?.to_vec();

        let end = stream.position();
        let expected = calc_checksum_v0(settings, &stream.data()[start..end]);
        let checksum = if settings.checksum_version == 0 {
            stream.u32()?
        } else {
            u32::from(stream.u8()?)
        };

        if checksum != expected {
            return Err(PrudpError::Protocol(format!(
                "invalid v0 checksum (expected {}, got {})",
                expected, checksum
            )));
        }

        packets.push(packet);
    }

    Ok(packets)
}

fn decode_v1(settings: &Settings, data: &[u8]) -> Result<Vec<Packet>> {
    let mut packets = Vec::new();
    let mut stream = StreamIn::new(settings, data);

    while !stream.eof() {
        if stream.read(2)? != b"\xEA\xD0" {
            return Err(PrudpError::Protocol("invalid v1 magic".into()));
        }

        if stream.u8()? != 1 {
            return Err(PrudpError::Protocol("invalid v1 version".into()));
        }

        let option_size = usize::from(stream.u8()?);
        let payload_size = usize::from(stream.u16()?);
        let source = stream.u8()?;
        let dest = stream.u8()?;
        let type_flags = stream.u16()?;

        let mut packet = Packet {
            version: 1,
            source_type: source >> 4,
            source_port: source & 0xF,
            dest_type: dest >> 4,
            dest_port: dest & 0xF,
            flags: (type_flags >> 4) as u8,
            kind: (type_flags & 0xF) as u8,
            session_id: stream.u8()?,
            substream_id: stream.u8()?,
            packet_id: stream.u16()?,
            ..Packet::default()
        };

        packet.signature = stream.read(16)?.to_vec();

        let option_data = stream.read(option_size)?;
        let options = decode_options(settings, option_data)?;

        let valid = match packet.kind {
            TYPE_SYN | TYPE_CONNECT => {
                let expected_support = packet.kind == TYPE_CONNECT;
                options.support.is_some()
                    && options.connection_signature.is_some()
                    && options.max_substream_id.is_some()
                    && options.unreliable_seq_id.is_some() == expected_support
                    && options.fragment_id.is_none()
            }
            TYPE_DATA => options.fragment_id.is_some(),
            _ => {
                options.support.is_none()
                    && options.connection_signature.is_none()
                    && options.fragment_id.is_none()
            }
        };
        if !valid {
            return Err(PrudpError::Protocol("unexpected set of v1 options".into()));
        }

        if packet.kind == TYPE_SYN || packet.kind == TYPE_CONNECT {
            let support = options.support.unwrap();
            packet.minor_version = (support & 0xFF) as u8;
            packet.supported_functions = support >> 8;
            packet.connection_signature = options.connection_signature.unwrap();
            packet.max_substream_id = options.max_substream_id.unwrap();
        }
        if packet.kind == TYPE_CONNECT {
            packet.initial_unreliable_id = options.unreliable_seq_id.unwrap();
        }
        if packet.kind == TYPE_DATA {
            packet.fragment_id = options.fragment_id.unwrap();
        }

        packet.payload = stream.read(payload_size)?.to_vec();
        packets.push(packet);
    }

    Ok(packets)
}

struct SequenceCounter {
    next: u16,
}

impl SequenceCounter {
    fn new(initial: u16) -> Self {
        SequenceCounter { next: initial }
    }

    fn next(&mut self) -> u16 {
        let current = self.next;
        self.next = self.next.wrapping_add(1);
        current
    }
}

struct SequenceManager {
    counters: Vec<SequenceCounter>,
    unreliable: SequenceCounter,
    ping: SequenceCounter,
}

impl SequenceManager {
    fn new(settings: &Settings, version: u8) -> Self {
        let initial_unreliable_id = if version == 0 { 1 } else { random_u16() };

        SequenceManager {
            counters: (0..=settings.max_substream_id)
                .map(|_| SequenceCounter::new(1))
                .collect(),
            unreliable: SequenceCounter::new(initial_unreliable_id),
            ping: SequenceCounter::new(1),
        }
    }

    fn assign(&mut self, packet: &Packet) -> u16 {
        if packet.flags & FLAG_RELIABLE != 0 {
            return self.counters[usize::from(packet.substream_id)].next();
        }
        match packet.kind {
            TYPE_DATA => self.unreliable.next(),
            TYPE_PING => self.ping.next(),
            _ => 0,
        }
    }

    fn initial_unreliable_id(&self) -> u16 {
        self.unreliable.next.wrapping_sub(1)
    }
}

fn random_u16() -> u16 {
    let mut bytes = [0u8; 2];
    let _ = getrandom::getrandom(&mut bytes);
    u16::from_le_bytes(bytes)
}

fn random_u8() -> u8 {
    let mut bytes = [0u8; 1];
    let _ = getrandom::getrandom(&mut bytes);
    bytes[0]
}

fn random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    let _ = getrandom::getrandom(&mut bytes);
    u32::from_le_bytes(bytes)
}

struct SlidingWindow {
    next: u16,
    packets: BTreeMap<u16, Packet>,
}

impl SlidingWindow {
    fn new() -> Self {
        SlidingWindow {
            next: 1,
            packets: BTreeMap::new(),
        }
    }

    fn skip(&mut self) {
        self.next = self.next.wrapping_add(1);
    }

    fn update(&mut self, packet: Packet) -> Vec<Packet> {
        let mut packets = Vec::new();

        if packet.packet_id < self.next || self.packets.contains_key(&packet.packet_id) {
            return packets;
        }

        self.packets.insert(packet.packet_id, packet);
        while let Some(packet) = self.packets.remove(&self.next) {
            packets.push(packet);
            self.skip();
        }
        packets
    }
}

struct Cipher {
    encrypt: Option<Rc4>,
    decrypt: Option<Rc4>,
}

impl Cipher {
    fn new(settings: &Settings, key: &[u8]) -> Self {
        if settings.transport == crate::nex::settings::Transport::Udp
            && settings.encryption == Encryption::Rc4
        {
            Cipher {
                encrypt: Some(Rc4::new(key)),
                decrypt: Some(Rc4::new(key)),
            }
        } else {
            Cipher {
                encrypt: None,
                decrypt: None,
            }
        }
    }

    fn set_key(&mut self, key: &[u8]) {
        if self.encrypt.is_some() {
            self.encrypt = Some(Rc4::new(key));
            self.decrypt = Some(Rc4::new(key));
        }
    }

    fn encrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        if let Some(cipher) = &mut self.encrypt {
            cipher.apply_keystream(&mut data);
        }
        data
    }

    fn decrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        if let Some(cipher) = &mut self.decrypt {
            cipher.apply_keystream(&mut data);
        }
        data
    }
}

struct PayloadEncoder {
    reliable: Vec<Cipher>,
    unreliable: Cipher,
    unreliable_key: [u8; 0x20],
    compression: bool,
}

impl PayloadEncoder {
    const DEFAULT_KEY: &'static [u8] = b"CD&ML";

    fn new(settings: &Settings) -> Self {
        let substreams = usize::from(settings.max_substream_id) + 1;

        PayloadEncoder {
            reliable: (0..substreams)
                .map(|_| Cipher::new(settings, Self::DEFAULT_KEY))
                .collect(),
            unreliable: Cipher::new(settings, Self::DEFAULT_KEY),
            unreliable_key: [0; 0x20],
            compression: settings.compression == crate::nex::settings::Compression::Zlib,
        }
    }

    fn set_session_key(&mut self, key: &[u8]) {
        self.reliable[0].set_key(key);

        let mut temp_key = key.to_vec();
        for cipher in self.reliable.iter_mut().skip(1) {
            temp_key = modify_key(&temp_key);
            cipher.set_key(&temp_key);
        }

        self.unreliable_key = init_unreliable_key(key);
    }

    fn encode(&mut self, packet: &mut Packet) -> Vec<u8> {
        let mut data = std::mem::take(&mut packet.payload);
        if packet.kind != TYPE_DATA || data.is_empty() {
            return data;
        }

        if self.compression {
            data = compress(&data);
        }

        if packet.flags & FLAG_RELIABLE != 0 {
            let cipher = &mut self.reliable[usize::from(packet.substream_id)];
            cipher.encrypt(data)
        } else {
            let key = make_unreliable_key(&self.unreliable_key, packet);
            self.unreliable.set_key(&key);
            self.unreliable.encrypt(data)
        }
    }

    fn decode(&mut self, packet: &mut Packet) -> Result<Vec<u8>> {
        let data = std::mem::take(&mut packet.payload);
        if packet.kind != TYPE_DATA || data.is_empty() {
            return Ok(data);
        }

        let data = if packet.flags & FLAG_RELIABLE != 0 {
            let cipher = &mut self.reliable[usize::from(packet.substream_id)];
            cipher.decrypt(data)
        } else {
            let key = make_unreliable_key(&self.unreliable_key, packet);
            self.unreliable.set_key(&key);
            self.unreliable.decrypt(data)
        };

        if self.compression {
            decompress(&data)
        } else {
            Ok(data)
        }
    }
}

fn modify_key(key: &[u8]) -> Vec<u8> {
    let mut chars = key.to_vec();
    let add = chars.len() / 2 + 1;
    for index in 0..chars.len() / 2 {
        chars[index] = chars[index].wrapping_add((add - index) as u8);
    }
    chars
}

fn combine_keys(key1: &[u8], key2: &[u8]) -> Vec<u8> {
    let mut data = key1.to_vec();
    data.extend_from_slice(key2);
    md5(&data)
}

fn init_unreliable_key(key: &[u8]) -> [u8; 0x20] {
    let part1 = combine_keys(key, &[0x18, 0xd8, 0x23, 0x34, 0x37, 0xe4, 0xe3, 0xfe]);
    let part2 = combine_keys(key, &[0x23, 0x3e, 0x60, 0x01, 0x23, 0xcd, 0xab, 0x80]);

    let mut output = [0u8; 0x20];
    output[..16].copy_from_slice(&part1);
    output[16..].copy_from_slice(&part2);
    output
}

fn make_unreliable_key(base: &[u8; 0x20], packet: &Packet) -> Vec<u8> {
    let mut key = *base;
    key[0] = key[0].wrapping_add(packet.packet_id as u8);
    key[1] = key[1].wrapping_add((packet.packet_id >> 8) as u8);
    key[31] = key[31].wrapping_add(packet.session_id);
    key.to_vec()
}

fn compress(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len() / 2 + 1);
    output.push(0);

    let mut encoder = ZlibEncoder::new(output, Compression::default());
    encoder
        .write_all(data)
        .expect("writing to memory cannot fail");
    let mut output = encoder
        .finish()
        .expect("finishing memory encoder cannot fail");

    let compressed_size = output.len() - 1;
    output[0] = (data.len() / compressed_size + 1) as u8;
    output
}

fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || data[0] == 0 {
        return Ok(data.get(1..).unwrap_or_default().to_vec());
    }

    let mut decoder = ZlibDecoder::new(&data[1..]);
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .map_err(|error| PrudpError::Protocol(format!("invalid compressed payload: {error}")))?;
    Ok(output)
}

struct State {
    session_key: Vec<u8>,
    local_session_id: u8,
    remote_session_id: u8,
    remote_signature: Vec<u8>,
    sequence: SequenceManager,
    windows: Vec<SlidingWindow>,
    fragments: Vec<Vec<u8>>,
    pending: HashSet<(u8, u8, u16)>,
    max_substream_id: u8,
    minor_version: u8,
    supported_functions: u32,
}

struct Inner {
    settings: Settings,
    socket: UdpSocket,
    remote: SocketAddr,
    version: u8,
    remote_port: u8,
    remote_type: u8,
    connection: Vec<u8>,
    payload: Mutex<PayloadEncoder>,
    state: Mutex<State>,
    reliable_tx: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    closed: AtomicBool,
    minor_version: AtomicU8,
    disconnect_ack: Notify,
}

impl Inner {
    async fn send_packet(self: &Arc<Self>, mut packet: Packet) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) && packet.kind != TYPE_DISCONNECT {
            return Err(PrudpError::Closed);
        }

        packet.version = self.version;
        packet.source_port = DEFAULT_LOCAL_PORT;
        packet.source_type = DEFAULT_LOCAL_TYPE;
        packet.dest_port = self.remote_port;
        packet.dest_type = self.remote_type;

        let (session_key, remote_signature) = {
            let mut state = self.state.lock().await;
            if packet.flags & (FLAG_ACK | FLAG_MULTI_ACK) == 0 {
                packet.packet_id = state.sequence.assign(&packet);
            }
            if packet.kind != TYPE_SYN {
                packet.session_id = state.local_session_id;
            }
            (state.session_key.clone(), state.remote_signature.clone())
        };

        if packet.kind == TYPE_DATA && packet.flags & (FLAG_ACK | FLAG_MULTI_ACK) == 0 {
            let mut payload = self.payload.lock().await;
            packet.payload = payload.encode(&mut packet);
        }

        trace!(
            "PRUDP send: kind={} flags=0x{:02X} packet_id={} substream={} payload={} bytes",
            packet.kind,
            packet.flags,
            packet.packet_id,
            packet.substream_id,
            packet.payload.len()
        );

        let (session_key, connection_signature) = match packet.kind {
            TYPE_SYN => (&[][..], &[][..]),
            TYPE_CONNECT => (&[][..], remote_signature.as_slice()),
            _ => (session_key.as_slice(), remote_signature.as_slice()),
        };
        let data = encode_signed(
            self.version,
            &self.settings,
            &mut packet,
            session_key,
            connection_signature,
        )?;

        let key = (packet.kind, packet.substream_id, packet.packet_id);
        let needs_ack = (packet.flags & FLAG_RELIABLE != 0 || packet.kind == TYPE_SYN)
            && packet.flags & FLAG_NEED_ACK != 0;

        if needs_ack {
            self.state.lock().await.pending.insert(key);
        }

        self.socket.send(&data).await?;

        if needs_ack {
            self.spawn_resend(key, data);
        }

        Ok(())
    }

    fn spawn_resend(self: &Arc<Self>, key: (u8, u8, u16), data: Vec<u8>) {
        let inner = Arc::clone(self);
        let timeout = Duration::from_secs_f32(self.settings.resend_timeout.max(0.001));
        let limit = self.settings.resend_limit;

        tokio::spawn(async move {
            let mut resends = 0;
            loop {
                tokio::time::sleep(timeout).await;
                if inner.closed.load(Ordering::SeqCst) {
                    return;
                }

                {
                    let mut state = inner.state.lock().await;
                    if !state.pending.contains(&key) {
                        return;
                    }
                    if resends >= limit {
                        state.pending.remove(&key);
                        drop(state);
                        inner.close().await;
                        return;
                    }
                }

                debug!(
                    "PRUDP resend: kind={} packet_id={} attempt={}",
                    key.0,
                    key.2,
                    resends + 1
                );
                if inner.socket.send(&data).await.is_err() {
                    inner.close().await;
                    return;
                }
                resends += 1;
            }
        });
    }

    async fn send_ack(self: &Arc<Self>, packet: &Packet) -> Result<()> {
        let ack = Packet {
            kind: packet.kind,
            flags: FLAG_ACK,
            packet_id: packet.packet_id,
            fragment_id: packet.fragment_id,
            substream_id: packet.substream_id,
            ..Packet::default()
        };
        self.send_packet(ack).await
    }

    fn build_connection_request(
        &self,
        credentials: &Credentials,
        connection_check: u32,
    ) -> Result<Vec<u8>> {
        let mut stream = StreamOut::new(&self.settings);
        stream.buffer(&credentials.ticket.internal)?;

        let mut substream = StreamOut::new(&self.settings);
        substream.pid(credentials.pid);
        substream.u32(credentials.cid as u32);
        substream.u32(connection_check);

        let encryption = KerberosEncryption::new(&credentials.ticket.session_key);
        stream.buffer(&encryption.encrypt(substream.as_bytes()))?;
        Ok(stream.into_bytes())
    }

    fn check_connection_response(
        credentials: Option<&Credentials>,
        data: &[u8],
        connection_check: u32,
    ) -> Result<()> {
        match credentials {
            Some(_) => {
                if data.len() != 8 {
                    return Err(PrudpError::Protocol(
                        "connection response has wrong size".into(),
                    ));
                }
                let length = u32::from_le_bytes(data[..4].try_into().unwrap());
                let check_value = u32::from_le_bytes(data[4..8].try_into().unwrap());
                if length != 4 {
                    return Err(PrudpError::Protocol(
                        "invalid connection response size".into(),
                    ));
                }
                if check_value != connection_check.wrapping_add(1) {
                    return Err(PrudpError::Protocol(
                        "connection response check failed".into(),
                    ));
                }
                Ok(())
            }
            None => {
                if data.is_empty() {
                    Ok(())
                } else {
                    Err(PrudpError::Protocol(
                        "expected empty connection response".into(),
                    ))
                }
            }
        }
    }

    async fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        *self.reliable_tx.lock().await = None;
        self.disconnect_ack.notify_one();
    }
}

/// Async PRUDP client.
pub struct PrudpClient {
    inner: Arc<Inner>,
    receiver: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    listener: Mutex<Option<JoinHandle<()>>>,
    ping_task: Mutex<Option<JoinHandle<()>>>,
    pid: Option<u64>,
}

impl PrudpClient {
    /// Connects to a PRUDP server and performs the handshake.
    pub async fn connect(
        settings: &Settings,
        host: &str,
        port: u16,
        vport: u8,
        credentials: Option<Credentials>,
    ) -> Result<Self> {
        let version = if settings.prudp_version == 0 { 0 } else { 1 };
        let connection_check = random_u32();
        debug!(
            "PRUDP connecting to {}:{} (vport={}, version={})",
            host, port, vport, version
        );

        let remote = tokio::net::lookup_host((host, port))
            .await?
            .find(SocketAddr::is_ipv4)
            .ok_or_else(|| {
                PrudpError::Protocol("host did not resolve to an IPv4 address".into())
            })?;

        let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
        socket.connect(remote).await?;

        let connection = connection_signature(version, remote);
        let (tx, rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            settings: settings.clone(),
            socket,
            remote,
            version,
            remote_port: vport,
            remote_type: DEFAULT_LOCAL_TYPE,
            connection: connection.clone(),
            payload: Mutex::new(PayloadEncoder::new(settings)),
            state: Mutex::new(State {
                session_key: Vec::new(),
                local_session_id: random_u8(),
                remote_session_id: 0,
                remote_signature: Vec::new(),
                sequence: SequenceManager::new(settings, version),
                windows: (0..=settings.max_substream_id)
                    .map(|_| SlidingWindow::new())
                    .collect(),
                fragments: vec![Vec::new(); usize::from(settings.max_substream_id) + 1],
                pending: HashSet::new(),
                max_substream_id: settings.max_substream_id,
                minor_version: settings.prudp_minor_version,
                supported_functions: settings.prudp_supported_functions,
            }),
            reliable_tx: Mutex::new(Some(tx)),
            closed: AtomicBool::new(false),
            minor_version: AtomicU8::new(settings.prudp_minor_version),
            disconnect_ack: Notify::new(),
        });

        let mut client = PrudpClient {
            inner,
            receiver: Mutex::new(rx),
            listener: Mutex::new(None),
            ping_task: Mutex::new(None),
            pid: credentials.as_ref().map(|credentials| credentials.pid),
        };

        // SYN
        let syn = Packet {
            kind: TYPE_SYN,
            flags: FLAG_NEED_ACK,
            connection_signature: vec![0; if version == 0 { 4 } else { 16 }],
            max_substream_id: settings.max_substream_id,
            supported_functions: settings.prudp_supported_functions,
            minor_version: settings.prudp_minor_version,
            ..Packet::default()
        };
        client.inner.send_packet(syn).await?;

        let synack = client.recv_handshake_packet().await?;
        client.process_syn_ack(&synack).await?;

        // CONNECT
        let credentials_ref = credentials.as_ref();
        let request = match credentials_ref {
            Some(credentials) => client
                .inner
                .build_connection_request(credentials, connection_check)?,
            None => Vec::new(),
        };

        let (initial_unreliable_id, max_substream_id, minor_version, supported_functions) = {
            let state = client.inner.state.lock().await;
            (
                state.sequence.initial_unreliable_id(),
                state.max_substream_id,
                state.minor_version,
                state.supported_functions,
            )
        };

        let connect = Packet {
            kind: TYPE_CONNECT,
            flags: FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE,
            connection_signature: connection,
            initial_unreliable_id,
            max_substream_id,
            minor_version,
            supported_functions,
            payload: request,
            ..Packet::default()
        };
        client.inner.send_packet(connect).await?;

        let connack = client.recv_handshake_packet().await?;
        client
            .process_connect_ack(&connack, credentials_ref, connection_check)
            .await?;

        if let Some(credentials) = credentials_ref {
            let mut state = client.inner.state.lock().await;
            state
                .session_key
                .clone_from(&credentials.ticket.session_key);
            drop(state);

            client
                .inner
                .payload
                .lock()
                .await
                .set_session_key(&credentials.ticket.session_key);
        }

        client.start_tasks().await;
        debug!("PRUDP connected to {}", remote);
        Ok(client)
    }

    async fn process_syn_ack(&self, packet: &Packet) -> Result<()> {
        let expected = signature_for(self.inner.version, &self.inner.settings, packet, b"", b"");
        if packet.signature != expected {
            return Err(PrudpError::Protocol(
                "received SYN packet with invalid signature".into(),
            ));
        }
        if packet.flags & FLAG_ACK == 0 {
            return Err(PrudpError::Protocol(
                "received unexpected SYN packet".into(),
            ));
        }
        if packet.session_id != 0
            || packet.packet_id != 0
            || packet.fragment_id != 0
            || packet.substream_id != 0
        {
            return Err(PrudpError::Protocol(
                "received invalid SYN/ACK packet".into(),
            ));
        }

        let mut state = self.inner.state.lock().await;
        if packet.max_substream_id > state.max_substream_id
            || packet.minor_version > state.minor_version
            || packet.supported_functions & !state.supported_functions != 0
        {
            return Err(PrudpError::Protocol(
                "received SYN/ACK with invalid negotiation parameters".into(),
            ));
        }

        state.max_substream_id = packet.max_substream_id;
        state.minor_version = packet.minor_version;
        state.supported_functions = packet.supported_functions;
        state
            .remote_signature
            .clone_from(&packet.connection_signature);
        state.windows = (0..=packet.max_substream_id)
            .map(|_| SlidingWindow::new())
            .collect();
        state.fragments = vec![Vec::new(); usize::from(packet.max_substream_id) + 1];
        state
            .pending
            .remove(&(TYPE_SYN, packet.substream_id, packet.packet_id));
        self.inner
            .minor_version
            .store(packet.minor_version, Ordering::SeqCst);
        Ok(())
    }

    async fn process_connect_ack(
        &self,
        packet: &Packet,
        credentials: Option<&Credentials>,
        connection_check: u32,
    ) -> Result<()> {
        let expected = signature_for(
            self.inner.version,
            &self.inner.settings,
            packet,
            b"",
            &self.inner.connection,
        );
        if packet.signature != expected {
            return Err(PrudpError::Protocol(
                "received CONNECT packet with invalid signature".into(),
            ));
        }
        if packet.flags & FLAG_ACK == 0 {
            return Err(PrudpError::Protocol(
                "received unexpected CONNECT packet".into(),
            ));
        }
        if packet.packet_id != 1
            || packet.fragment_id != 0
            || packet.substream_id != 0
            || packet.connection_signature.iter().any(|&byte| byte != 0)
        {
            return Err(PrudpError::Protocol(
                "received invalid CONNECT/ACK packet".into(),
            ));
        }

        {
            let state = self.inner.state.lock().await;
            if packet.max_substream_id != state.max_substream_id
                || packet.minor_version != state.minor_version
                || packet.supported_functions != state.supported_functions
            {
                return Err(PrudpError::Protocol(
                    "received CONNECT/ACK with invalid negotiation parameters".into(),
                ));
            }
        }

        Inner::check_connection_response(credentials, &packet.payload, connection_check)?;

        let mut state = self.inner.state.lock().await;
        state.remote_session_id = packet.session_id;
        state
            .pending
            .remove(&(TYPE_CONNECT, packet.substream_id, packet.packet_id));
        Ok(())
    }

    async fn recv_handshake_packet(&self) -> Result<Packet> {
        let mut buffer = vec![0u8; 0x10000];
        let length = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.inner.socket.recv(&mut buffer))
            .await
            .map_err(|_| PrudpError::Timeout)??;
        buffer.truncate(length);

        let mut packets = decode(&self.inner.settings, &buffer)?;
        if packets.is_empty() {
            return Err(PrudpError::Protocol("received empty datagram".into()));
        }
        Ok(packets.remove(0))
    }

    async fn start_tasks(&mut self) {
        let inner = Arc::clone(&self.inner);
        let listener = tokio::spawn(async move {
            let mut buffer = vec![0u8; 0x10000];
            loop {
                if inner.closed.load(Ordering::SeqCst) {
                    break;
                }
                let length = match inner.socket.recv(&mut buffer).await {
                    Ok(length) => length,
                    Err(_) => break,
                };

                let packets = match decode(&inner.settings, &buffer[..length]) {
                    Ok(packets) => packets,
                    Err(error) => {
                        debug!("PRUDP: dropping malformed datagram: {}", error);
                        continue;
                    }
                };
                for packet in packets {
                    if let Err(error) = inner.handle_packet(packet).await {
                        warn!("PRUDP: packet handling failed: {}", error);
                        inner.close().await;
                        return;
                    }
                }
            }
            inner.close().await;
        });

        let inner = Arc::clone(&self.inner);
        let interval = Duration::from_secs_f32(self.inner.settings.ping_timeout.max(0.001));
        let ping = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if inner.closed.load(Ordering::SeqCst) {
                    return;
                }
                let packet = Packet {
                    kind: TYPE_PING,
                    flags: FLAG_RELIABLE | FLAG_NEED_ACK,
                    ..Packet::default()
                };
                if inner.send_packet(packet).await.is_err() {
                    return;
                }
            }
        });

        *self.listener.lock().await = Some(listener);
        *self.ping_task.lock().await = Some(ping);
    }

    /// Sends a reliable message, splitting it into fragments if necessary.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(PrudpError::Closed);
        }

        let fragment_size = (self.inner.settings.fragment_size as usize).max(1);
        let mut offset = 0;
        let mut fragment_id = 1u8;

        while offset < data.len() {
            let end = (offset + fragment_size).min(data.len());
            if end == data.len() {
                fragment_id = 0;
            }

            let packet = Packet {
                kind: TYPE_DATA,
                flags: FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE,
                fragment_id,
                substream_id: 0,
                payload: data[offset..end].to_vec(),
                ..Packet::default()
            };
            self.inner.send_packet(packet).await?;

            offset = end;
            fragment_id = fragment_id.wrapping_add(1);
        }
        Ok(())
    }

    /// Receives the next reliable message. Returns `None` when the connection
    /// is closed.
    pub async fn recv(&self) -> Option<Vec<u8>> {
        self.receiver.lock().await.recv().await
    }

    pub fn pid(&self) -> Option<u64> {
        self.pid
    }

    pub fn minor_version(&self) -> u8 {
        self.inner.minor_version.load(Ordering::SeqCst)
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote
    }

    /// Sends a disconnect and closes the connection.
    pub async fn disconnect(&self) {
        if self.inner.closed.load(Ordering::SeqCst) {
            return;
        }

        debug!("PRUDP disconnect");
        let packet = Packet {
            kind: TYPE_DISCONNECT,
            flags: FLAG_RELIABLE | FLAG_NEED_ACK,
            ..Packet::default()
        };
        let _ = self.inner.send_packet(packet).await;

        let _ = tokio::time::timeout(Duration::from_secs(1), self.inner.disconnect_ack.notified())
            .await;
        self.close().await;
    }

    /// Closes the connection immediately.
    pub async fn close(&self) {
        debug!("PRUDP close");
        self.inner.close().await;
        if let Some(task) = self.listener.lock().await.take() {
            task.abort();
        }
        if let Some(task) = self.ping_task.lock().await.take() {
            task.abort();
        }
    }
}

impl Drop for PrudpClient {
    fn drop(&mut self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        if let Some(task) = self.listener.get_mut().take() {
            task.abort();
        }
        if let Some(task) = self.ping_task.get_mut().take() {
            task.abort();
        }
    }
}

impl Inner {
    async fn handle_packet(self: &Arc<Self>, packet: Packet) -> Result<()> {
        let expected = if packet.kind == TYPE_SYN {
            signature_for(self.version, &self.settings, &packet, b"", b"")
        } else if packet.kind == TYPE_CONNECT {
            signature_for(self.version, &self.settings, &packet, b"", &self.connection)
        } else {
            let state = self.state.lock().await;
            if packet.session_id != state.remote_session_id {
                return Err(PrudpError::Protocol("invalid session id".into()));
            }
            signature_for(
                self.version,
                &self.settings,
                &packet,
                &state.session_key,
                &self.connection,
            )
        };

        if packet.signature != expected {
            return Err(PrudpError::Protocol("invalid packet signature".into()));
        }

        if packet.flags & FLAG_MULTI_ACK != 0 {
            self.handle_multi_ack(&packet).await?;
            return Ok(());
        }

        if packet.flags & FLAG_ACK != 0 {
            let key = (packet.kind, packet.substream_id, packet.packet_id);
            self.state.lock().await.pending.remove(&key);
            if packet.kind == TYPE_DISCONNECT {
                self.disconnect_ack.notify_one();
            }
            return Ok(());
        }

        if packet.flags & FLAG_NEED_ACK != 0 {
            let _ = self.send_ack(&packet).await;
        }

        if packet.kind == TYPE_PING {
            return Ok(());
        }

        if packet.kind == TYPE_DISCONNECT {
            self.close().await;
            return Ok(());
        }

        if packet.kind != TYPE_DATA {
            return Ok(());
        }

        if packet.flags & FLAG_RELIABLE == 0 {
            return Ok(());
        }

        let ordered = {
            let mut state = self.state.lock().await;
            let substream = usize::from(packet.substream_id);
            if substream >= state.windows.len() {
                return Err(PrudpError::Protocol("invalid substream".into()));
            }
            state.windows[substream].update(packet)
        };

        for mut packet in ordered {
            let data = self.payload.lock().await.decode(&mut packet)?;
            let substream = usize::from(packet.substream_id);

            {
                let mut state = self.state.lock().await;
                state.fragments[substream].extend_from_slice(&data);
            }

            if packet.fragment_id == 0 {
                let message = {
                    let mut state = self.state.lock().await;
                    std::mem::take(&mut state.fragments[substream])
                };
                if let Some(tx) = self.reliable_tx.lock().await.as_ref() {
                    let _ = tx.send(message);
                }
            }
        }

        Ok(())
    }

    async fn handle_multi_ack(&self, packet: &Packet) -> Result<()> {
        if packet.kind != TYPE_DATA {
            return Err(PrudpError::Protocol(
                "multi-ack must be a DATA packet".into(),
            ));
        }

        let new_format = self.version == 1 && packet.substream_id == 1;
        if new_format {
            if packet.payload.len() < 4
                || packet.payload.len() != 4 + usize::from(packet.payload[1]) * 2
            {
                return Err(PrudpError::Protocol("invalid aggregate ack size".into()));
            }
        } else if packet.payload.len() < 4 {
            return Err(PrudpError::Protocol("aggregate ack is too small".into()));
        }

        let (substream, base_id, extra_ids) = if new_format {
            let substream = packet.payload[0];
            let base_id = u16::from_le_bytes(packet.payload[2..4].try_into().unwrap());
            let count = usize::from(packet.payload[1]);
            let mut ids = Vec::with_capacity(count);
            for index in 0..count {
                let start = 4 + index * 2;
                ids.push(u16::from_le_bytes(
                    packet.payload[start..start + 2].try_into().unwrap(),
                ));
            }
            (substream, base_id, ids)
        } else {
            let mut ids = Vec::with_capacity(packet.payload.len() / 2);
            for chunk in packet.payload.chunks_exact(2) {
                ids.push(u16::from_le_bytes(chunk.try_into().unwrap()));
            }
            (0, packet.packet_id, ids)
        };

        let mut state = self.state.lock().await;
        state.pending.retain(|&(kind, stream, id)| {
            !(kind == TYPE_DATA && stream == substream && id <= base_id)
        });
        for id in extra_ids {
            state.pending.remove(&(TYPE_DATA, substream, id));
        }
        Ok(())
    }
}

fn signature_for(
    version: u8,
    settings: &Settings,
    packet: &Packet,
    session_key: &[u8],
    connection_signature: &[u8],
) -> Vec<u8> {
    if version == 0 {
        signature_v0(settings, packet, session_key, connection_signature)
    } else {
        signature_v1(settings, packet, session_key, connection_signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_3ds() -> Settings {
        Settings {
            access_key: "ridfebb9".to_string(),
            ..Settings::load("3ds").unwrap()
        }
    }

    fn settings_wiiu() -> Settings {
        Settings {
            access_key: "ridfebb9".to_string(),
            ..Settings::default()
        }
    }

    #[test]
    fn v0_roundtrip() {
        let settings = settings_3ds();
        let mut packet = Packet {
            kind: TYPE_DATA,
            flags: FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE,
            version: 0,
            source_port: 15,
            source_type: 10,
            dest_port: 1,
            dest_type: 10,
            session_id: 0x12,
            packet_id: 0x1234,
            fragment_id: 0,
            payload: b"hello".to_vec(),
            ..Packet::default()
        };
        packet.signature = signature_v0(&settings, &packet, &[0xAA; 16], b"");

        let data = encode(&settings, &packet).unwrap();
        let packets = decode(&settings, &data).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], packet);
    }

    #[test]
    fn v1_roundtrip() {
        let settings = settings_wiiu();
        let mut packet = Packet {
            kind: TYPE_DATA,
            flags: FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE,
            version: 1,
            source_port: 15,
            source_type: 10,
            dest_port: 1,
            dest_type: 10,
            session_id: 0x12,
            substream_id: 0,
            packet_id: 0x1234,
            fragment_id: 0,
            payload: b"hello".to_vec(),
            ..Packet::default()
        };
        packet.signature = signature_v1(&settings, &packet, &[0xAA; 16], &[0xBB; 16]);

        let data = encode(&settings, &packet).unwrap();
        let packets = decode(&settings, &data).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], packet);
    }

    #[test]
    fn encode_signed_matches_manual_signature() {
        let session_key = [0xAA; 16];
        let connection_signature = [0xBB; 16];

        for (version, settings) in [(0, settings_3ds()), (1, settings_wiiu())] {
            let mut packet = Packet {
                kind: TYPE_DATA,
                flags: FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE,
                version,
                source_port: 15,
                source_type: 10,
                dest_port: 1,
                dest_type: 10,
                session_id: 0x12,
                substream_id: 0,
                packet_id: 0x1234,
                fragment_id: 0,
                payload: b"hello".to_vec(),
                ..Packet::default()
            };

            let signature = signature_for(
                version,
                &settings,
                &packet,
                &session_key,
                &connection_signature,
            );
            let mut expected_packet = packet.clone();
            expected_packet.signature = signature.clone();
            let expected = encode(&settings, &expected_packet).unwrap();

            let actual = encode_signed(
                version,
                &settings,
                &mut packet,
                &session_key,
                &connection_signature,
            )
            .unwrap();

            assert_eq!(packet.signature, signature);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn v1_syn_roundtrip() {
        let settings = settings_wiiu();
        let mut packet = Packet {
            kind: TYPE_SYN,
            flags: FLAG_NEED_ACK,
            version: 1,
            source_port: 15,
            source_type: 10,
            dest_port: 1,
            dest_type: 10,
            connection_signature: vec![0; 16],
            max_substream_id: 0,
            minor_version: 4,
            supported_functions: 0,
            ..Packet::default()
        };
        packet.signature = signature_v1(&settings, &packet, b"", b"");

        let data = encode(&settings, &packet).unwrap();
        let packets = decode(&settings, &data).unwrap();
        assert_eq!(packets[0], packet);
    }

    #[test]
    fn connection_signatures_match_reference() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        assert_eq!(connection_signature(0, addr), hex("42b48998"));

        assert_eq!(
            connection_signature(1, addr),
            hex("ea32ba60df0ebe0c9899d70a2afe510a")
        );
    }

    #[test]
    fn payload_roundtrip() {
        let settings = settings_3ds();
        let mut encoder = PayloadEncoder::new(&settings);
        let mut decoder = PayloadEncoder::new(&settings);
        let session_key = [0x42u8; 16];
        encoder.set_session_key(&session_key);
        decoder.set_session_key(&session_key);

        for fragment_id in [1u8, 0] {
            let mut packet = Packet {
                kind: TYPE_DATA,
                flags: FLAG_RELIABLE,
                substream_id: 0,
                session_id: 3,
                packet_id: 0x1234,
                fragment_id,
                payload: b"the quick brown fox".to_vec(),
                ..Packet::default()
            };
            let original = packet.payload.clone();

            let encoded = encoder.encode(&mut packet);
            let mut encoded_packet = packet;
            encoded_packet.payload = encoded;

            assert_eq!(decoder.decode(&mut encoded_packet).unwrap(), original);
        }
    }

    #[test]
    fn compression_roundtrip() {
        let settings = settings_3ds();
        let mut encoder = PayloadEncoder::new(&settings);
        encoder.set_session_key(&[0x42; 16]);
        encoder.compression = true;

        let mut packet = Packet {
            kind: TYPE_DATA,
            flags: FLAG_RELIABLE,
            substream_id: 0,
            packet_id: 1,
            fragment_id: 0,
            payload: b"hello hello hello hello".to_vec(),
            ..Packet::default()
        };
        let original = packet.payload.clone();

        let encoded = encoder.encode(&mut packet);
        let mut encoded_packet = packet;
        encoded_packet.payload = encoded;

        let mut decoder = PayloadEncoder::new(&settings);
        decoder.set_session_key(&[0x42; 16]);
        decoder.compression = true;
        assert_eq!(decoder.decode(&mut encoded_packet).unwrap(), original);
    }

    #[test]
    fn invalid_compressed_payload_is_an_error() {
        assert!(decompress(&[1, 0xff, 0xff]).is_err());
    }

    #[test]
    fn payload_matches_reference_sequence() {
        let settings = settings_3ds();
        let request = b"\x09\x00\x00\x00\xe6\x01\x00\x00\x00\x13\x00\x00\x00";

        let packet = |payload: Vec<u8>| Packet {
            kind: TYPE_DATA,
            flags: FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE,
            substream_id: 0,
            packet_id: 1,
            session_id: 5,
            fragment_id: 0,
            payload,
            ..Packet::default()
        };

        let mut client = PayloadEncoder::new(&settings);
        let mut request_packet = packet(request.to_vec());
        let encoded_request = client.encode(&mut request_packet);
        assert_eq!(encoded_request, hex("068744dbf5fe2c5005b161fd2a"));

        let mut server = PayloadEncoder::new(&settings);
        let mut request_packet = packet(encoded_request);
        assert_eq!(server.decode(&mut request_packet).unwrap(), request);

        let mut response_packet =
            packet(b"\x0b\x00\x00\x00\x66\x01\x01\x00\x00\x00\x13\x80\x00\x00\x2a".to_vec());
        let encoded_response = server.encode(&mut response_packet);
        assert_eq!(encoded_response, hex("048744db75fe2d5005a2727d2a16d8"));

        let mut response_packet = packet(encoded_response);
        assert_eq!(
            client.decode(&mut response_packet).unwrap(),
            b"\x0b\x00\x00\x00\x66\x01\x01\x00\x00\x00\x13\x80\x00\x00\x2a"
        );
    }

    #[test]
    fn sliding_window_orders_packets() {
        let mut window = SlidingWindow::new();
        let packet = |id: u16| Packet {
            packet_id: id,
            ..Packet::default()
        };

        assert!(window.update(packet(2)).is_empty());
        assert_eq!(window.update(packet(1)).len(), 2);
        assert_eq!(window.update(packet(3)).len(), 1);
        assert!(window.update(packet(3)).is_empty());
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }
}

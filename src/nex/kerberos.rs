//! Kerberos tickets.
//!
//! Ported from `nintendo/nex/kerberos.py`.
//!
//! The 3DS and Wii U friend servers use the old key derivation
//! ([`KeyDerivationOld`]). Ticket payloads are encrypted with RC4 and
//! authenticated with HMAC-MD5. The session key size comes from
//! [`crate::nex::settings::Settings`] (`16` for the friend server, `32`
//! otherwise).

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};

use crate::nex::common::DateTime;
use crate::nex::settings::Settings;
use crate::nex::streams::{StreamError, StreamIn, StreamOut};

type HmacMd5 = Hmac<Md5>;

/// Error returned while encrypting or decrypting a ticket.
#[derive(Debug, thiserror::Error)]
pub enum KerberosError {
    #[error("invalid kerberos checksum (incorrect password)")]
    InvalidChecksum,
    #[error("incorrect session key size")]
    IncorrectKeySize,
    #[error("failed to gather randomness")]
    Random,
    #[error(transparent)]
    Stream(#[from] StreamError),
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

/// RC4 stream cipher, as used by the old kerberos encryption.
pub struct Rc4 {
    state: [u8; 256],
    i: usize,
    j: usize,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "RC4 key must not be empty");

        let mut state = [0u8; 256];
        for (index, value) in state.iter_mut().enumerate() {
            *value = index as u8;
        }

        let mut j = 0usize;
        for i in 0..256 {
            j = (j + state[i] as usize + key[i % key.len()] as usize) & 0xFF;
            state.swap(i, j);
        }

        Rc4 { state, i: 0, j: 0 }
    }

    /// XORs the data with the RC4 keystream.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = (self.i + 1) & 0xFF;
            self.j = (self.j + self.state[self.i] as usize) & 0xFF;
            self.state.swap(self.i, self.j);

            let index = (self.state[self.i] as usize + self.state[self.j] as usize) & 0xFF;
            *byte ^= self.state[index];
        }
    }

    /// Encrypts (or decrypts) the data.
    pub fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = data.to_vec();
        self.apply_keystream(&mut output);
        output
    }
}

/// RC4 + HMAC-MD5 envelope around a ticket.
pub struct KerberosEncryption {
    key: Vec<u8>,
}

impl KerberosEncryption {
    pub fn new(key: &[u8]) -> Self {
        KerberosEncryption { key: key.to_vec() }
    }

    /// Verifies the checksum at the end of the buffer.
    pub fn check(&self, buffer: &[u8]) -> bool {
        if buffer.len() < 0x10 {
            return false;
        }

        let (data, checksum) = buffer.split_at(buffer.len() - 0x10);
        hmac_md5(&self.key, data) == checksum
    }

    /// Decrypts a buffer, rejecting a bad checksum.
    pub fn decrypt(&self, buffer: &[u8]) -> Result<Vec<u8>, KerberosError> {
        if !self.check(buffer) {
            return Err(KerberosError::InvalidChecksum);
        }

        let data = &buffer[..buffer.len() - 0x10];
        Ok(Rc4::new(&self.key).apply(data))
    }

    /// Encrypts a buffer and appends the checksum.
    pub fn encrypt(&self, buffer: &[u8]) -> Vec<u8> {
        let mut encrypted = Rc4::new(&self.key).apply(buffer);
        encrypted.extend_from_slice(&hmac_md5(&self.key, &encrypted));
        encrypted
    }
}

/// Old key derivation, used by 3DS and Wii U.
#[derive(Debug, Clone, Copy)]
pub struct KeyDerivationOld {
    pub base_count: u32,
    pub pid_count: u32,
}

impl KeyDerivationOld {
    pub fn new(base_count: u32, pid_count: u32) -> Self {
        KeyDerivationOld {
            base_count,
            pid_count,
        }
    }

    pub fn derive_key(&self, password: &[u8], pid: u32) -> Vec<u8> {
        let mut key = password.to_vec();
        let iterations = u64::from(self.base_count)
            + u64::from(pid)
                % u64::from(if self.pid_count == 0 {
                    1
                } else {
                    self.pid_count
                });
        for _ in 0..iterations {
            key = md5(&key);
        }
        key
    }
}

impl Default for KeyDerivationOld {
    fn default() -> Self {
        KeyDerivationOld::new(65000, 1024)
    }
}

/// New key derivation, used by Switch servers.
#[derive(Debug, Clone, Copy)]
pub struct KeyDerivationNew {
    pub base_count: u32,
    pub pid_count: u32,
}

impl KeyDerivationNew {
    pub fn new(base_count: u32, pid_count: u32) -> Self {
        KeyDerivationNew {
            base_count,
            pid_count,
        }
    }

    pub fn derive_key(&self, password: &[u8], pid: u64) -> Vec<u8> {
        let mut key = password.to_vec();
        for _ in 0..self.base_count {
            key = md5(&key);
        }

        key.extend_from_slice(&pid.to_le_bytes());
        for _ in 0..self.pid_count {
            key = md5(&key);
        }
        key
    }
}

impl Default for KeyDerivationNew {
    fn default() -> Self {
        KeyDerivationNew::new(1, 1)
    }
}

/// Ticket that a client receives from the authentication server and presents
/// to the secure server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientTicket {
    pub session_key: Vec<u8>,
    pub target: u64,
    pub internal: Vec<u8>,
}

impl ClientTicket {
    pub fn decrypt(data: &[u8], key: &[u8], settings: &Settings) -> Result<Self, KerberosError> {
        let decrypted = KerberosEncryption::new(key).decrypt(data)?;
        let mut stream = StreamIn::new(settings, &decrypted);

        Ok(ClientTicket {
            session_key: stream.read(settings.key_size)?.to_vec(),
            target: stream.pid()?,
            internal: stream.buffer()?.to_vec(),
        })
    }

    pub fn encrypt(&self, key: &[u8], settings: &Settings) -> Result<Vec<u8>, KerberosError> {
        if self.session_key.len() != settings.key_size {
            return Err(KerberosError::IncorrectKeySize);
        }

        let mut stream = StreamOut::new(settings);
        stream.write(&self.session_key);
        stream.pid(self.target);
        stream.buffer(&self.internal)?;
        Ok(KerberosEncryption::new(key).encrypt(stream.as_bytes()))
    }
}

/// Ticket that the secure server decrypts to find the client's session key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerTicket {
    pub timestamp: DateTime,
    pub source: u64,
    pub session_key: Vec<u8>,
}

impl ServerTicket {
    pub fn decrypt(data: &[u8], key: &[u8], settings: &Settings) -> Result<Self, KerberosError> {
        let mut key = key.to_vec();
        let mut data = data;

        if settings.ticket_version == 1 {
            let mut stream = StreamIn::new(settings, data);
            let ticket_key = stream.buffer()?;
            data = stream.buffer()?;

            let mut material = key.clone();
            material.extend_from_slice(ticket_key);
            key = md5(&material);
        }

        let decrypted = KerberosEncryption::new(&key).decrypt(data)?;
        let mut stream = StreamIn::new(settings, &decrypted);

        Ok(ServerTicket {
            timestamp: stream.datetime()?,
            source: stream.pid()?,
            session_key: stream.read(settings.key_size)?.to_vec(),
        })
    }

    pub fn encrypt(&self, key: &[u8], settings: &Settings) -> Result<Vec<u8>, KerberosError> {
        if self.session_key.len() != settings.key_size {
            return Err(KerberosError::IncorrectKeySize);
        }

        let mut stream = StreamOut::new(settings);
        stream.datetime(self.timestamp);
        stream.pid(self.source);
        stream.write(&self.session_key);

        if settings.ticket_version == 1 {
            let mut ticket_key = [0u8; 16];
            getrandom::getrandom(&mut ticket_key).map_err(|_| KerberosError::Random)?;

            let mut material = key.to_vec();
            material.extend_from_slice(&ticket_key);
            let final_key = md5(&material);

            let encrypted = KerberosEncryption::new(&final_key).encrypt(stream.as_bytes());

            let mut output = StreamOut::new(settings);
            output.buffer(&ticket_key)?;
            output.buffer(&encrypted)?;
            Ok(output.into_bytes())
        } else {
            Ok(KerberosEncryption::new(key).encrypt(stream.as_bytes()))
        }
    }
}

/// Credentials that are sent to a secure server when connecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub ticket: ClientTicket,
    pub pid: u64,
    pub cid: u64,
}

impl Credentials {
    pub fn new(ticket: ClientTicket, pid: u64, cid: u64) -> Self {
        Credentials { ticket, pid, cid }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_known_vector() {
        let mut cipher = Rc4::new(b"Key");
        assert_eq!(
            cipher.apply(b"Plaintext"),
            b"\xbb\xf3\x16\xe8\xd9\x40\xaf\x0a\xd3"
        );
    }

    #[test]
    fn old_key_derivation_matches_reference() {
        let derivation = KeyDerivationOld::default();
        assert_eq!(
            derivation.derive_key(b"password", 1000),
            hex("93cc081d39a8948344d8c62dac28908b")
        );
    }

    #[test]
    fn new_key_derivation_matches_reference() {
        let derivation = KeyDerivationNew::default();
        assert_eq!(
            derivation.derive_key(b"password", 1000),
            hex("a78dfa87e643f2c4b162d6d6c2bdb0e4")
        );
    }

    #[test]
    fn client_ticket_decrypts_reference_fixture() {
        let settings = Settings::load("friends").unwrap();
        let data = hex(
            "fff43a0d483bb2a96958a1773e46a1693502a6c9478b26011b224ff51904f93b372571019e82573d345a57b2dbc130b2",
        );
        let ticket = ClientTicket::decrypt(&data, b"password", &settings).unwrap();

        assert_eq!(ticket.session_key, (0..16).collect::<Vec<u8>>());
        assert_eq!(ticket.target, 1000);
        assert_eq!(ticket.internal, b"internal");
        assert_eq!(ticket.encrypt(b"password", &settings).unwrap(), data);
    }

    #[test]
    fn server_ticket_decrypts_reference_fixture() {
        let settings = Settings::load("friends").unwrap();
        let data = hex(
            "10000000000102030405060708090a0b0c0d0e0f2c000000aa9439fb76565068f9307a4613e69b5abf4564562ad769dec2527f55aa2c5be93498bd0a54afb9bc67d3e85d",
        );
        let ticket = ServerTicket::decrypt(&data, b"password", &settings).unwrap();

        assert_eq!(ticket.timestamp, DateTime::make(2020, 6, 15, 12, 34, 56));
        assert_eq!(ticket.source, 1000);
        assert_eq!(ticket.session_key, vec![0x11; 16]);
    }

    #[test]
    fn server_ticket_roundtrip() {
        for name in ["friends", "default"] {
            let settings = Settings::load(name).unwrap();
            let ticket = ServerTicket {
                timestamp: DateTime::make(2023, 1, 2, 3, 4, 5),
                source: 1234,
                session_key: vec![0x42; settings.key_size],
            };

            let data = ticket.encrypt(b"server key", &settings).unwrap();
            let decrypted = ServerTicket::decrypt(&data, b"server key", &settings).unwrap();
            assert_eq!(decrypted, ticket);
        }
    }

    #[test]
    fn wrong_password_is_rejected() {
        let settings = Settings::load("friends").unwrap();
        let data = hex(
            "fff43a0d483bb2a96958a1773e46a1693502a6c9478b26011b224ff51904f93b372571019e82573d345a57b2dbc130b2",
        );
        assert!(matches!(
            ClientTicket::decrypt(&data, b"wrong", &settings),
            Err(KerberosError::InvalidChecksum)
        ));
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }
}

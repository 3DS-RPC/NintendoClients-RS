//! NEX settings.
//!
//! Ported from `nintendo/nex/settings.py`. The bundled configuration files are
//! the same ones the Python package ships in `nintendo/files/config`.

use std::str::FromStr;
use std::sync::OnceLock;

/// `config/default.cfg`: defaults for Wii U applications.
pub const DEFAULT_CFG: &str = include_str!("../../config/default.cfg");
/// `config/3ds.cfg`: defaults for 3DS applications.
pub const THREE_DS_CFG: &str = include_str!("../../config/3ds.cfg");
/// `config/friends.cfg`: defaults for the 3DS / Wii U friend server.
pub const FRIENDS_CFG: &str = include_str!("../../config/friends.cfg");

/// Underlying transport for PRUDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Transport {
    Udp = 0,
    Tcp = 1,
    WebSocket = 2,
}

/// Compression algorithm for data packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Compression {
    None = 0,
    Zlib = 1,
}

/// Encryption algorithm for data packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Encryption {
    None = 0,
    Rc4 = 1,
}

impl TryFrom<u8> for Transport {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Transport::Udp),
            1 => Ok(Transport::Tcp),
            2 => Ok(Transport::WebSocket),
            other => Err(other),
        }
    }
}

impl TryFrom<u8> for Compression {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Compression::None),
            1 => Ok(Compression::Zlib),
            other => Err(other),
        }
    }
}

impl TryFrom<u8> for Encryption {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Encryption::None),
            1 => Ok(Encryption::Rc4),
            other => Err(other),
        }
    }
}

/// Holds the NEX/PRUDP/kerberos configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub nex_version: u32,
    pub nex_client_version: u32,
    pub struct_header: bool,
    pub pid_size: u8,

    pub access_key: String,

    pub prudp_version: u8,
    pub prudp_minor_version: u8,
    pub prudp_supported_functions: u32,
    pub transport: Transport,
    pub compression: Compression,
    pub encryption: Encryption,
    pub resend_timeout: f32,
    pub resend_limit: u32,
    pub ping_timeout: f32,
    pub fragment_size: u32,
    pub max_substream_id: u8,

    pub signature_version: u8,
    pub flags_version: u8,
    pub checksum_version: u8,

    pub key_size: usize,
    pub key_derivation: u8,
    pub ticket_version: u8,
}

/// Error returned while loading or updating [`Settings`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettingsError {
    #[error("syntax error at line {0}")]
    Syntax(usize),
    #[error("unknown setting: {0}")]
    UnknownField(String),
    #[error("unknown configuration: {0}")]
    UnknownConfig(String),
    #[error("invalid value for `{field}`: {value}")]
    InvalidValue { field: String, value: String },
    #[error("NEX 4.4.0 or later requires a client version")]
    ClientVersionRequired,
}

impl Settings {
    /// Creates a settings object from `config/default.cfg`.
    pub fn new() -> Self {
        static DEFAULT: OnceLock<Settings> = OnceLock::new();
        DEFAULT
            .get_or_init(|| {
                Self::from_cfg_text(DEFAULT_CFG).expect("bundled default.cfg must be valid")
            })
            .clone()
    }

    /// Parses a configuration file into a fresh settings object.
    pub fn from_cfg_text(text: &str) -> Result<Self, SettingsError> {
        let mut settings = Self::empty();
        settings.apply_cfg_text(text)?;
        Ok(settings)
    }

    /// Loads one of the bundled configurations (`default`, `3ds`, `friends`).
    pub fn load(name: &str) -> Result<Self, SettingsError> {
        let mut settings = Self::new();
        let text = match name {
            "default" => return Ok(settings),
            "3ds" => THREE_DS_CFG,
            "friends" => FRIENDS_CFG,
            other => return Err(SettingsError::UnknownConfig(other.to_string())),
        };
        settings.apply_cfg_text(text)?;
        Ok(settings)
    }

    /// Applies a configuration file on top of the current settings.
    ///
    /// Matches `Settings.load()` from the Python reference: only the fields
    /// present in the file are replaced.
    pub fn apply_cfg_text(&mut self, text: &str) -> Result<(), SettingsError> {
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let (field, value) = match line.split_once('=') {
                Some(pair) => pair,
                None => return Err(SettingsError::Syntax(index + 1)),
            };
            self.set(field.trim(), value.trim())?;
        }
        Ok(())
    }

    /// Configures `access_key`, `nex_version` and (for NEX 4.4.0+) the client
    /// version, mirroring `Settings.configure` in the Python reference.
    pub fn configure(
        &mut self,
        access_key: impl Into<String>,
        nex_version: u32,
        client_version: Option<u32>,
    ) -> Result<(), SettingsError> {
        self.access_key = access_key.into();
        self.nex_version = nex_version;
        if nex_version >= 40400 {
            match client_version {
                Some(version) => self.nex_client_version = version,
                None => return Err(SettingsError::ClientVersionRequired),
            }
        }
        Ok(())
    }

    fn empty() -> Self {
        Settings {
            nex_version: 0,
            nex_client_version: 0,
            struct_header: false,
            pid_size: 4,
            access_key: String::new(),
            prudp_version: 0,
            prudp_minor_version: 0,
            prudp_supported_functions: 0,
            transport: Transport::Udp,
            compression: Compression::None,
            encryption: Encryption::None,
            resend_timeout: 0.0,
            resend_limit: 0,
            ping_timeout: 0.0,
            fragment_size: 0,
            max_substream_id: 0,
            signature_version: 0,
            flags_version: 0,
            checksum_version: 0,
            key_size: 0,
            key_derivation: 0,
            ticket_version: 0,
        }
    }

    fn set(&mut self, field: &str, value: &str) -> Result<(), SettingsError> {
        match field {
            "nex.version" => self.nex_version = parse(field, value)?,
            "nex.client_version" => self.nex_client_version = parse(field, value)?,
            "nex.struct_header" => self.struct_header = parse::<u32>(field, value)? != 0,
            "nex.pid_size" => self.pid_size = parse(field, value)?,

            "prudp.access_key" => self.access_key = value.to_string(),
            "prudp.version" => self.prudp_version = parse(field, value)?,
            "prudp.minor_version" => self.prudp_minor_version = parse(field, value)?,
            "prudp.supported_functions" => self.prudp_supported_functions = parse(field, value)?,
            "prudp.transport" => {
                self.transport = Transport::try_from(parse::<u8>(field, value)?)
                    .map_err(|_| invalid(field, value))?
            }
            "prudp.compression" => {
                self.compression = Compression::try_from(parse::<u8>(field, value)?)
                    .map_err(|_| invalid(field, value))?
            }
            "prudp.encryption" => {
                self.encryption = Encryption::try_from(parse::<u8>(field, value)?)
                    .map_err(|_| invalid(field, value))?
            }
            "prudp.resend_timeout" => self.resend_timeout = parse(field, value)?,
            "prudp.resend_limit" => self.resend_limit = parse(field, value)?,
            "prudp.ping_timeout" => self.ping_timeout = parse(field, value)?,
            "prudp.fragment_size" => self.fragment_size = parse(field, value)?,
            "prudp.max_substream_id" => self.max_substream_id = parse(field, value)?,

            "prudp_v0.signature_version" => self.signature_version = parse(field, value)?,
            "prudp_v0.flags_version" => self.flags_version = parse(field, value)?,
            "prudp_v0.checksum_version" => self.checksum_version = parse(field, value)?,

            "kerberos.key_size" => self.key_size = parse(field, value)?,
            "kerberos.key_derivation" => self.key_derivation = parse(field, value)?,
            "kerberos.ticket_version" => self.ticket_version = parse(field, value)?,

            other => return Err(SettingsError::UnknownField(other.to_string())),
        }
        Ok(())
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new()
    }
}

fn parse<T: FromStr>(field: &str, value: &str) -> Result<T, SettingsError> {
    value.parse().map_err(|_| invalid(field, value))
}

fn invalid(field: &str, value: &str) -> SettingsError {
    SettingsError::InvalidValue {
        field: field.to_string(),
        value: value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_wiiu() {
        let settings = Settings::default();
        assert_eq!(settings.nex_version, 0);
        assert_eq!(settings.pid_size, 4);
        assert!(!settings.struct_header);
        assert_eq!(settings.prudp_version, 2);
        assert_eq!(settings.prudp_minor_version, 4);
        assert_eq!(settings.transport, Transport::Udp);
        assert_eq!(settings.encryption, Encryption::Rc4);
        assert_eq!(settings.fragment_size, 1300);
        assert_eq!(settings.key_size, 32);
        assert_eq!(settings.key_derivation, 0);
    }

    #[test]
    fn three_ds_overrides_defaults() {
        let settings = Settings::load("3ds").unwrap();
        assert_eq!(settings.prudp_version, 0);
        assert_eq!(settings.fragment_size, 962);
        assert_eq!(settings.key_size, 32);
    }

    #[test]
    fn friends_overrides_defaults() {
        let settings = Settings::load("friends").unwrap();
        assert_eq!(settings.prudp_version, 0);
        assert_eq!(settings.fragment_size, 962);
        assert_eq!(settings.signature_version, 1);
        assert_eq!(settings.key_size, 16);
    }

    #[test]
    fn load_is_cumulative() {
        let mut settings = Settings::load("3ds").unwrap();
        settings.apply_cfg_text(FRIENDS_CFG).unwrap();
        assert_eq!(settings.key_size, 16);
        assert_eq!(settings.prudp_version, 0);
    }

    #[test]
    fn configure_sets_access_key_and_version() {
        let mut settings = Settings::default();
        settings.configure("ridfebb9", 20000, None).unwrap();
        assert_eq!(settings.access_key, "ridfebb9");
        assert_eq!(settings.nex_version, 20000);
    }

    #[test]
    fn configure_requires_client_version_for_nex4() {
        let mut settings = Settings::default();
        assert_eq!(
            settings.configure("key", 40400, None),
            Err(SettingsError::ClientVersionRequired)
        );
        settings.configure("key", 40400, Some(100)).unwrap();
        assert_eq!(settings.nex_client_version, 100);
    }

    #[test]
    fn unknown_config_is_rejected() {
        assert_eq!(
            Settings::load("switch"),
            Err(SettingsError::UnknownConfig("switch".to_string()))
        );
    }

    #[test]
    fn unknown_field_is_rejected() {
        let mut settings = Settings::default();
        assert_eq!(
            settings.apply_cfg_text("prudp.nope = 1"),
            Err(SettingsError::UnknownField("prudp.nope".to_string()))
        );
    }

    #[test]
    fn syntax_error_reports_line() {
        let mut settings = Settings::default();
        assert_eq!(
            settings.apply_cfg_text("\n\noops"),
            Err(SettingsError::Syntax(3))
        );
    }
}

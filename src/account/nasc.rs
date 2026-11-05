//! 3DS account server (`nasc.nintendowifi.net`).
//!
//! Ported from `nintendo/nasc.py`.
//!
//! The 3DS does not send NEX credentials over NASC; they are stored on the
//! device. NASC only reports the game server address and a token.

use std::collections::HashMap;
use std::fmt::Write as _;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use log::{debug, info, warn};
use reqwest::Certificate;

use crate::nex::common::DateTime;

const CA_DER: &[u8] = include_bytes!("../../certs/Nintendo_CA_G3.der");
const CLIENT_CERT_DER: &[u8] = include_bytes!("../../certs/CTR_Common_Prod_1.der");
const CLIENT_KEY_DER: &[u8] = include_bytes!("../../certs/CTR_Common_Prod_1.key");

/// Host of the 3DS account server.
pub const HOST: &str = "nasc.nintendowifi.net";

pub const MEDIA_TYPE_SYSTEM: u8 = 0;
pub const MEDIA_TYPE_DIGITAL: u8 = 1;
pub const MEDIA_TYPE_CARTRIDGE: u8 = 2;

/// Error returned by the 3DS account server.
#[derive(Debug, thiserror::Error)]
pub enum NascError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("missing configuration: {0}")]
    Config(&'static str),
    #[error("NASC request failed with error code {return_code:?} (retry={retry})")]
    Server {
        return_code: Option<i32>,
        retry: bool,
    },
}

/// Response of a successful NASC login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginResponse {
    pub host: String,
    pub port: u16,
    /// Token in Nintendo's custom base64 encoding.
    pub token: String,
    pub datetime: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum User {
    None,
    Pid { pid: u64, hmac: String },
    Password(String),
}

/// Client for the 3DS account server.
pub struct NascClient {
    http: reqwest::Client,
    url: String,
    insecure: bool,

    sdk_version: (u32, u32),
    title_id: Option<u64>,
    title_version: Option<u16>,
    product_code: String,
    maker_code: String,
    media_type: u8,
    rom_id: Option<String>,

    serial_number: Option<String>,
    mac_address: Option<String>,
    device_cert: Option<Vec<u8>>,
    device_name: String,
    unit_code: String,

    bss_id: String,
    ap_info: String,

    region: u8,
    language: u8,
    user: User,

    fpd_version: u16,
    environment: String,
}

impl NascClient {
    pub fn new() -> Result<Self, NascError> {
        let http = build_http(false)?;

        Ok(NascClient {
            http,
            url: HOST.to_string(),
            insecure: false,

            sdk_version: (0, 0),
            title_id: None,
            title_version: None,
            product_code: "----".to_string(),
            maker_code: "00".to_string(),
            media_type: MEDIA_TYPE_SYSTEM,
            rom_id: None,

            serial_number: None,
            mac_address: None,
            device_cert: None,
            device_name: String::new(),
            unit_code: "2".to_string(),

            bss_id: random_hex(6),
            ap_info: "01:0000000000".to_string(),

            region: 3,
            language: 2,
            user: User::None,

            fpd_version: 16,
            environment: "L1".to_string(),
        })
    }

    pub fn set_url(&mut self, url: impl Into<String>) {
        self.url = url.into();
    }

    /// Disables certificate verification. Needed for Pretendo, whose account
    /// server does not use Nintendo's CA.
    pub fn set_insecure_tls(&mut self, insecure: bool) -> Result<(), NascError> {
        if insecure != self.insecure {
            self.http = build_http(insecure)?;
            self.insecure = insecure;
        }
        Ok(())
    }

    pub fn set_sdk_version(&mut self, major: u32, minor: u32) {
        self.sdk_version = (major, minor);
    }

    pub fn set_title(
        &mut self,
        title_id: u64,
        title_version: u16,
        product_code: &str,
        maker_code: &str,
        media_type: u8,
        rom_id: Option<&str>,
    ) {
        self.title_id = Some(title_id);
        self.title_version = Some(title_version);
        self.product_code = product_code.to_string();
        self.maker_code = maker_code.to_string();
        self.media_type = media_type;
        self.rom_id = rom_id.map(str::to_string);
    }

    pub fn set_device(
        &mut self,
        serial_number: impl Into<String>,
        mac_address: impl Into<String>,
        device_cert: impl Into<Vec<u8>>,
        name: impl Into<String>,
    ) {
        self.serial_number = Some(serial_number.into());
        self.mac_address = Some(mac_address.into());
        self.device_cert = Some(device_cert.into());
        self.device_name = name.into();
    }

    pub fn set_network(&mut self, bss_id: impl Into<String>, ap_info: impl Into<String>) {
        self.bss_id = bss_id.into();
        self.ap_info = ap_info.into();
    }

    pub fn set_unit_code(&mut self, unit_code: impl Into<String>) {
        self.unit_code = unit_code.into();
    }

    pub fn set_locale(&mut self, region: u8, language: u8) {
        self.region = region;
        self.language = language;
    }

    pub fn set_user(&mut self, pid: u64, pid_hmac: impl Into<String>) {
        self.user = User::Pid {
            pid,
            hmac: pid_hmac.into(),
        };
    }

    pub fn set_password(&mut self, password: impl Into<String>) {
        self.user = User::Password(password.into());
    }

    pub fn set_fpd_version(&mut self, version: u16) {
        self.fpd_version = version;
    }

    pub fn set_environment(&mut self, environment: impl Into<String>) {
        self.environment = environment.into();
    }

    /// Logs in and returns the game server address.
    pub async fn login(
        &self,
        game_server_id: u32,
        nickname: &str,
    ) -> Result<LoginResponse, NascError> {
        debug!("NASCClient.login()");
        let title_id = self.title_id.ok_or(NascError::Config("title"))?;
        let title_version = self.title_version.ok_or(NascError::Config("title"))?;
        let serial_number = self
            .serial_number
            .as_ref()
            .ok_or(NascError::Config("serial number"))?;
        let mac_address = self
            .mac_address
            .as_ref()
            .ok_or(NascError::Config("mac address"))?;
        let device_cert = self
            .device_cert
            .as_ref()
            .ok_or(NascError::Config("device certificate"))?;

        if self.media_type == MEDIA_TYPE_CARTRIDGE && self.rom_id.is_none() {
            return Err(NascError::Config("rom id"));
        }
        if matches!(self.user, User::None) {
            return Err(NascError::Config("user"));
        }

        let now = DateTime::now();
        let device_time = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}",
            now.year() % 100,
            now.month(),
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );

        let mut form: Vec<(String, Vec<u8>)> = Vec::new();
        form.push((
            "gameid".into(),
            format!("{:08X}", game_server_id).into_bytes(),
        ));
        form.push((
            "sdkver".into(),
            format!("{:03}{:03}", self.sdk_version.0, self.sdk_version.1).into_bytes(),
        ));
        form.push(("titleid".into(), format!("{:016X}", title_id).into_bytes()));
        form.push(("gamecd".into(), self.product_code.clone().into_bytes()));
        form.push((
            "gamever".into(),
            format!("{:04X}", title_version).into_bytes(),
        ));
        form.push(("mediatype".into(), self.media_type.to_string().into_bytes()));
        if self.media_type == MEDIA_TYPE_CARTRIDGE {
            form.push((
                "romid".into(),
                self.rom_id.clone().unwrap_or_default().into_bytes(),
            ));
        }
        form.push(("makercd".into(), self.maker_code.clone().into_bytes()));
        form.push(("unitcd".into(), self.unit_code.clone().into_bytes()));
        form.push(("macadr".into(), mac_address.clone().into_bytes()));
        form.push(("bssid".into(), self.bss_id.clone().into_bytes()));
        form.push(("apinfo".into(), self.ap_info.clone().into_bytes()));

        form.push(("fcdcert".into(), device_cert.clone()));

        let mut device_name = Vec::with_capacity(self.device_name.len() * 2);
        for unit in self.device_name.encode_utf16() {
            device_name.extend_from_slice(&unit.to_le_bytes());
        }
        form.push(("devname".into(), device_name));
        form.push(("servertype".into(), self.environment.clone().into_bytes()));
        form.push((
            "fpdver".into(),
            format!("{:04X}", self.fpd_version).into_bytes(),
        ));
        form.push(("devtime".into(), device_time.into_bytes()));
        form.push(("lang".into(), format!("{:02X}", self.language).into_bytes()));
        form.push(("region".into(), format!("{:02X}", self.region).into_bytes()));
        form.push(("csnum".into(), serial_number.clone().into_bytes()));

        match &self.user {
            User::Pid { pid, hmac } => {
                form.push(("uidhmac".into(), hmac.clone().into_bytes()));
                form.push(("userid".into(), pid.to_string().into_bytes()));
            }
            User::Password(password) => form.push(("passwd".into(), password.clone().into_bytes())),
            User::None => unreachable!(),
        }

        form.push(("action".into(), b"LOGIN".to_vec()));
        form.push(("ingamesn".into(), nickname.as_bytes().to_vec()));

        let body = encode_form(&form);
        info!("Performing HTTP request: POST /ac");
        let response = self
            .http
            .post(format!("https://{}/ac", self.url))
            .header("Host", &self.url)
            .header("X-GameId", format!("{:08X}", game_server_id))
            .header("User-Agent", format!("CTR FPD/{:04X}", self.fpd_version))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?;

        let status = response.status();
        info!("Received HTTP response: {}", status.as_u16());
        let response = response.text().await?;

        let keys = response
            .split('&')
            .map(|field| field.split('=').next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join(",");
        debug!(
            "NASC response: status={} length={} keys=[{}]",
            status,
            response.len(),
            keys
        );

        let form = decode_form(&response).map_err(|error| {
            NascError::InvalidResponse(format!(
                "{error} (status {}, {} bytes)",
                status,
                response.len()
            ))
        })?;

        let return_code = form
            .get("returncd")
            .map(|value| String::from_utf8_lossy(value).to_string())
            .unwrap_or_else(|| "null".to_string());
        let return_code_number = return_code.parse::<i32>().ok();

        if return_code == "null" || return_code_number != Some(1) {
            let retry = form
                .get("retry")
                .map(|value| String::from_utf8_lossy(value) == "1")
                .unwrap_or(false);
            warn!(
                "NASC login failed: return_code={:?} retry={}",
                return_code_number, retry
            );
            return Err(NascError::Server {
                return_code: return_code_number,
                retry,
            });
        }

        let locator = form
            .get("locator")
            .ok_or_else(|| NascError::InvalidResponse("missing locator".into()))?;
        let locator = String::from_utf8_lossy(locator);
        let (host, port) = locator
            .split_once(':')
            .ok_or_else(|| NascError::InvalidResponse("invalid locator".into()))?;

        let token = form
            .get("token")
            .map(|value| encode_base64(value))
            .unwrap_or_default();
        let datetime = form
            .get("datetime")
            .map(|value| String::from_utf8_lossy(value).to_string())
            .unwrap_or_default();

        debug!("NASCClient.login -> done");
        Ok(LoginResponse {
            host: host.to_string(),
            port: port
                .parse()
                .map_err(|_| NascError::InvalidResponse("invalid port".into()))?,
            token,
            datetime,
        })
    }
}

fn build_http(insecure: bool) -> Result<reqwest::Client, NascError> {
    let ca = Certificate::from_pem(pem("CERTIFICATE", CA_DER).as_bytes())?;
    let identity = reqwest::Identity::from_pem(
        format!(
            "{}{}",
            pem("CERTIFICATE", CLIENT_CERT_DER),
            pem("RSA PRIVATE KEY", CLIENT_KEY_DER)
        )
        .as_bytes(),
    )?;

    let mut builder = reqwest::Client::builder()
        .add_root_certificate(ca)
        .identity(identity);

    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }

    Ok(builder.build()?)
}

fn encode_form(form: &[(String, Vec<u8>)]) -> String {
    form.iter()
        .map(|(key, value)| format!("{}={}", key, encode_base64(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn decode_form(text: &str) -> Result<HashMap<String, Vec<u8>>, NascError> {
    let mut form = HashMap::new();
    for field in text.split('&') {
        if field.is_empty() {
            continue;
        }
        let (key, value) = field
            .split_once('=')
            .ok_or_else(|| NascError::InvalidResponse("malformed form field".into()))?;
        let key = percent_decode(key.trim());
        let value = value.trim();

        let decoded_value = percent_decode(value);
        let decoded = decode_base64(&decoded_value).map_err(|_| {
            NascError::InvalidResponse(format!(
                "invalid base64 in field `{}` ({} chars)",
                key,
                decoded_value.len()
            ))
        })?;
        form.insert(key, decoded);
    }
    Ok(form)
}

fn encode_base64(data: &[u8]) -> String {
    STANDARD
        .encode(data)
        .replace('+', ".")
        .replace('/', "-")
        .replace('=', "*")
}

fn decode_base64(text: &str) -> Result<Vec<u8>, NascError> {
    let text = text.replace('.', "+").replace('-', "/").replace('*', "=");
    STANDARD
        .decode(text)
        .map_err(|_| NascError::InvalidResponse("invalid base64".into()))
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(value) = u8::from_str_radix(&text[index + 1..index + 3], 16) {
                output.push(value);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).to_string()
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut output = format!("-----BEGIN {}-----\n", label);
    for chunk in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(chunk).unwrap());
        output.push('\n');
    }
    output.push_str(&format!("-----END {}-----\n", label));
    output
}

fn random_hex(bytes: usize) -> String {
    let mut data = vec![0u8; bytes];
    let _ = getrandom::getrandom(&mut data);

    let mut output = String::with_capacity(bytes * 2);
    for byte in data {
        let _ = write!(output, "{byte:02X}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_builds() {
        NascClient::new().expect("client should build");
    }

    #[test]
    fn base64_roundtrip() {
        for data in [
            Vec::new(),
            vec![0],
            vec![0, 1, 2, 250, 255],
            (0..200u8).collect::<Vec<_>>(),
        ] {
            let encoded = encode_base64(&data);
            assert!(!encoded.contains('+'));
            assert!(!encoded.contains('/'));
            assert_eq!(decode_base64(&encoded).unwrap(), data);
        }
    }

    #[test]
    fn base64_rejects_garbage() {
        assert!(decode_base64("!!!!").is_err());
    }

    #[test]
    fn percent_decode_handles_escapes() {
        assert_eq!(percent_decode("a%2Ab"), "a*b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("plain"), "plain");
    }

    #[test]
    fn form_roundtrip_and_trailing_whitespace() {
        let text = format!(
            "locator={}&retry={}&datetime={}\r\n",
            encode_base64(b"host:1234"),
            encode_base64(b"0"),
            encode_base64(b"20261026120000")
        );

        let form = decode_form(&text).unwrap();
        assert_eq!(form["locator"], b"host:1234");
        assert_eq!(form["retry"], b"0");
        assert_eq!(form["datetime"], b"20261026120000");
    }

    #[test]
    fn form_decodes_url_encoded_padding() {
        let encoded = encode_base64(b"abc").replace('*', "%2A");
        let form = decode_form(&format!("token={encoded}")).unwrap();
        assert_eq!(form["token"], b"abc");
    }

    #[test]
    fn form_rejects_malformed_fields() {
        assert!(decode_form("novalue").is_err());
        assert!(decode_form("key=!!!!").is_err());
    }

    #[test]
    fn pem_wraps_lines() {
        let pem = pem("CERTIFICATE", &[0xAB; 80]);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        for line in pem
            .lines()
            .skip(1)
            .take_while(|line| !line.starts_with("-----"))
        {
            assert!(line.len() <= 64);
        }
    }

    #[tokio::test]
    async fn login_validates_configuration() {
        let client = NascClient::new().unwrap();
        let error = client.login(0x3200, "").await.unwrap_err();
        assert!(matches!(error, NascError::Config("title")));
    }

    #[test]
    fn insecure_tls_can_be_toggled() {
        let mut client = NascClient::new().unwrap();
        client.set_insecure_tls(true).unwrap();
        client.set_insecure_tls(false).unwrap();
        client.set_url("nasc.pretendo.cc");
    }
}

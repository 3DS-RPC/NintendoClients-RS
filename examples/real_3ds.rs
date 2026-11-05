//! Real 3DS smoke test.
//!
//! Reads console credentials from the environment so they never end up in the
//! repository or on the command line. Pass `pretendo` to use the Pretendo
//! network (`nasc.pretendo.cc`, no certificate verification).
//!
//! Environment variables (prefix `NASC_`, or `PRETENDO_` for Pretendo):
//! `SERIAL`, `MAC`, `CERT` (hex), `DEVICE_NAME`, `PID`, `PID_HMAC`,
//! `NEX_PASSWORD`, `REGION`, `LANGUAGE`.
//!
//! It performs a NASC login and then reads the friend list (no writes). The
//! only things printed are the server address and the number of friends.
//!
//! ```text
//! cargo run --example real_3ds
//! cargo run --example real_3ds -- pretendo
//! ```

use std::sync::Arc;

use nintendoclients::account::nasc::{NascClient, MEDIA_TYPE_SYSTEM};
use nintendoclients::nex::backend::BackEndClient;
use nintendoclients::nex::friends::FriendsClientV1;
use nintendoclients::nex::settings::Settings;

const FRIENDS_TITLE_ID: u64 = 0x0004_0130_0000_3202;
const FRIENDS_TITLE_VERSION: u16 = 20;
const FRIENDS_GAME_SERVER_ID: u32 = 0x3200;

fn required(prefix: &str, name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = format!("{prefix}{name}");
    Ok(std::env::var(&key).map_err(|_| format!("missing environment variable {key}"))?)
}

fn parse_hex(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let digits: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if digits.len() % 2 != 0 {
        return Err("hex string has an odd length".into());
    }

    Ok(digits
        .as_bytes()
        .chunks(2)
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let pretendo = std::env::args().nth(1).as_deref() == Some("pretendo");
    let prefix = if pretendo { "PRETENDO_" } else { "NASC_" };

    let serial = required(prefix, "SERIAL")?;
    let mac = required(prefix, "MAC")?;
    let cert = parse_hex(&required(prefix, "CERT")?)?;
    let device_name = std::env::var(format!("{prefix}DEVICE_NAME")).unwrap_or_default();
    let pid: u64 = required(prefix, "PID")?.parse()?;
    let hmac = required(prefix, "PID_HMAC")?;
    let nex_password = required(prefix, "NEX_PASSWORD")?;
    let region: u8 = required(prefix, "REGION")?.parse()?;
    let language: u8 = required(prefix, "LANGUAGE")?.parse()?;

    let mut nasc = NascClient::new()?;
    if pretendo {
        nasc.set_url("nasc.pretendo.cc");
        nasc.set_insecure_tls(true)?;
    }

    nasc.set_title(
        FRIENDS_TITLE_ID,
        FRIENDS_TITLE_VERSION,
        "----",
        "00",
        MEDIA_TYPE_SYSTEM,
        None,
    );
    nasc.set_device(serial, mac, cert, device_name);
    nasc.set_locale(region, language);
    nasc.set_user(pid, hmac);

    let login = nasc.login(FRIENDS_GAME_SERVER_ID, "").await?;
    println!("NASC login ok: {}:{}", login.host, login.port);

    let mut settings = Settings::load("friends")?;
    settings.configure("ridfebb9", 20000, None)?;

    let backend = BackEndClient::connect(&settings, &login.host, login.port).await?;
    let client = Arc::new(backend.login(&pid.to_string(), &nex_password).await?);

    let friends = FriendsClientV1::new(Arc::clone(&client));
    let all = friends.get_all_friends().await?;
    println!("friend count: {}", all.len());

    client.disconnect().await;
    Ok(())
}

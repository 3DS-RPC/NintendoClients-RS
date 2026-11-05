//! Login smoke test against a local authentication + secure server.
//!
//! Expects the Python reference servers on `127.0.0.1:12345` (authentication)
//! and `127.0.0.1:12346` (secure, key `testkey`):
//!
//! ```text
//! cargo run --example local_login
//! ```

use std::sync::Arc;

use nintendoclients::nex::backend::BackEndClient;
use nintendoclients::nex::friends::FriendsClientV2;
use nintendoclients::nex::settings::Settings;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let mut settings = Settings::load("default")?;
    settings.configure("ridfebb9", 20000, None)?;

    let backend = BackEndClient::connect(&settings, "127.0.0.1", 12345).await?;
    let client = Arc::new(backend.login("username", "password").await?);
    println!("pid -> {:?}", client.pid());

    let friends = FriendsClientV2::new(Arc::clone(&client));
    println!(
        "check_setting_status -> {}",
        friends.check_setting_status().await?
    );

    client.disconnect().await;
    Ok(())
}

//! Smoke test against a local server.
//!
//! Expects a PRUDP/RMC server on `127.0.0.1:12345` that serves the friend
//! protocol. Pass `wiiu` to use the Wii U configuration (PRUDP v1,
//! `FriendsClientV2`) instead of the 3DS one (PRUDP v0, `FriendsClientV1`).
//!
//! ```text
//! cargo run --example local_friends
//! cargo run --example local_friends -- wiiu
//! ```

use std::sync::Arc;

use nintendoclients::nex::friends::{FriendsClientV1, FriendsClientV2, MyProfile};
use nintendoclients::nex::rmc::RmcClient;
use nintendoclients::nex::settings::Settings;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let wiiu = std::env::args().nth(1).as_deref() == Some("wiiu");
    let config = if wiiu { "default" } else { "friends" };

    let mut settings = Settings::load(config)?;
    settings.configure("ridfebb9", 20000, None)?;

    let client = Arc::new(RmcClient::connect(&settings, "127.0.0.1", 12345, 1, None).await?);

    if wiiu {
        let friends = FriendsClientV2::new(Arc::clone(&client));
        println!(
            "check_setting_status -> {}",
            friends.check_setting_status().await?
        );
        let info = friends.get_basic_info(&[1000]).await?;
        println!("get_basic_info -> {:?}", info);
    } else {
        let friends = FriendsClientV1::new(Arc::clone(&client));
        let profile = MyProfile {
            region: 1,
            country: 2,
            area: 3,
            language: 4,
            platform: 5,
            local_friend_code_seed: 0x1122_3344_5566_7788,
            mac_address: "aabbccddeeff".to_string(),
            serial_number: "123".to_string(),
        };

        friends.update_profile(&profile).await?;
        let relationships = friends.get_friend_relationships(&[1000]).await?;
        println!("get_friend_relationships -> {:?}", relationships);
    }

    client.disconnect().await;
    Ok(())
}

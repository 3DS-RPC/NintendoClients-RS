//! High-level login flow.
//!
//! Ported from `nintendo/nex/backend.py`, for the NEX < 4.0 path that the 3DS
//! and Wii U use:
//!
//! 1. connect to the authentication server over RMC
//! 2. `login` and decrypt the returned ticket
//! 3. derive the kerberos key from the NEX password
//! 4. connect to the secure server advertised in the connection data

use std::sync::Arc;

use log::debug;

use crate::nex::authentication::AuthenticationClient;
use crate::nex::common::RmcError as RemoteRmcError;
use crate::nex::kerberos::{
    ClientTicket, Credentials, KerberosError, KeyDerivationNew, KeyDerivationOld,
};
use crate::nex::rmc::{RmcClient, RmcClientError};
use crate::nex::settings::Settings;

/// Error returned while logging in.
#[derive(Debug, thiserror::Error)]
pub enum BackEndError {
    #[error(transparent)]
    Rmc(#[from] RmcClientError),
    #[error(transparent)]
    Remote(#[from] RemoteRmcError),
    #[error(transparent)]
    Kerberos(#[from] KerberosError),
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Authenticated connection to a game server.
pub struct BackEndClient {
    settings: Settings,
    auth: Arc<RmcClient>,
    auth_client: AuthenticationClient,
    auth_host: String,
    auth_port: u16,
}

impl BackEndClient {
    /// Connects to an authentication server.
    pub async fn connect(settings: &Settings, host: &str, port: u16) -> Result<Self, BackEndError> {
        debug!("BackEndClient.connect()");
        let auth = Arc::new(RmcClient::connect(settings, host, port, 1, None).await?);

        debug!("BackEndClient.connect -> done");
        Ok(BackEndClient {
            settings: settings.clone(),
            auth_client: AuthenticationClient::new(Arc::clone(&auth)),
            auth,
            auth_host: host.to_string(),
            auth_port: port,
        })
    }

    /// Logs in and returns a client for the secure server.
    pub async fn login(&self, username: &str, password: &str) -> Result<RmcClient, BackEndError> {
        debug!("BackEndClient.login()");
        let response = self.auth_client.login(username).await?;
        response.result.into_result()?;

        let key = self.derive_key(password, response.pid);
        let mut ticket = ClientTicket::decrypt(&response.ticket, &key, &self.settings)?;

        let station = &response.connection_data.main_station;
        let target = station.get_int("PID") as u64;

        if ticket.target != target {
            let response = self
                .auth_client
                .request_ticket(response.pid, target)
                .await?;
            response.result.into_result()?;
            ticket = ClientTicket::decrypt(&response.ticket, &key, &self.settings)?;
        }

        let cid = station.get_int("CID") as u64;
        let credentials = Credentials::new(ticket, response.pid, cid);

        let (mut host, mut port) = station.address();
        if host.is_empty() || host == "0.0.0.1" {
            host = self.auth_host.clone();
            port = i64::from(self.auth_port);
        }

        let vport = station.get_int("sid") as u8;
        let client =
            RmcClient::connect(&self.settings, &host, port as u16, vport, Some(credentials))
                .await?;
        debug!("BackEndClient.login -> done");
        Ok(client)
    }

    /// Logs in with the guest account.
    pub async fn login_guest(&self) -> Result<RmcClient, BackEndError> {
        debug!("BackEndClient.login_guest()");
        let client = self.login("guest", "MMQea3n!fsik").await?;
        debug!("BackEndClient.login_guest -> done");
        Ok(client)
    }

    /// The settings that this backend was configured with.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// The PID of the authenticated user, if the authentication client knows
    /// it.
    pub fn pid(&self) -> Option<u64> {
        self.auth.pid()
    }

    fn derive_key(&self, password: &str, pid: u64) -> Vec<u8> {
        if self.settings.key_derivation == 0 {
            KeyDerivationOld::new(65000, 1024).derive_key(password.as_bytes(), pid as u32)
        } else {
            KeyDerivationNew::new(1, 1).derive_key(password.as_bytes(), pid)
        }
    }
}

impl Drop for BackEndClient {
    fn drop(&mut self) {
        let auth = Arc::clone(&self.auth);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                auth.disconnect().await;
            });
        }
    }
}

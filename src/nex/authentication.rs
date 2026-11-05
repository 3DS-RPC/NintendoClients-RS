//! NEX authentication protocol.
//!
//! Ported from `nintendo/nex/authentication.py` (generated from
//! `authentication.proto` in the reference branch), limited to the legacy
//! NEX < 4.0 methods that the 3DS and Wii U use.

use std::sync::Arc;

use log::{info, warn};

use crate::nex::common::{DateTime, Result as NexResult, StationURL, Structure};
use crate::nex::rmc::{RmcClient, RmcClientError};
use crate::nex::streams::{StreamError, StreamIn, StreamOut};

/// Protocol id of the authentication protocol.
pub const PROTOCOL_ID: u8 = 0x0A;

const METHOD_LOGIN: u32 = 1;
const METHOD_REQUEST_TICKET: u32 = 3;
const METHOD_GET_PID: u32 = 4;
const METHOD_GET_NAME: u32 = 5;

/// Secure server connection data returned by `login`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RVConnectionData {
    pub main_station: StationURL,
    pub special_protocols: Vec<u8>,
    pub special_station: StationURL,
    pub server_time: DateTime,
}

impl Default for RVConnectionData {
    fn default() -> Self {
        RVConnectionData {
            main_station: StationURL::parse("prudp:/"),
            special_protocols: Vec::new(),
            special_station: StationURL::parse("prudp:/"),
            server_time: DateTime::never(),
        }
    }
}

impl Structure for RVConnectionData {
    fn save(&self, stream: &mut StreamOut, version: u8) -> Result<(), StreamError> {
        stream.stationurl(&self.main_station)?;
        stream.list(&self.special_protocols, |stream, value| {
            stream.u8(*value);
            Ok(())
        })?;
        stream.stationurl(&self.special_station)?;
        if stream.settings().nex_version >= 30500 && version >= 1 {
            stream.datetime(self.server_time);
        }
        Ok(())
    }

    fn load(&mut self, stream: &mut StreamIn, version: u8) -> Result<(), StreamError> {
        self.main_station = stream.stationurl()?;
        self.special_protocols = stream.list(|stream| stream.u8())?;
        self.special_station = stream.stationurl()?;
        if stream.settings().nex_version >= 30500 && version >= 1 {
            self.server_time = stream.datetime()?;
        }
        Ok(())
    }
}

/// Response of `login`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginResponse {
    pub result: NexResult,
    pub pid: u64,
    pub ticket: Vec<u8>,
    pub connection_data: RVConnectionData,
    pub server_name: Option<String>,
}

/// Response of `request_ticket`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketResponse {
    pub result: NexResult,
    pub ticket: Vec<u8>,
}

/// Client for the authentication protocol.
pub struct AuthenticationClient {
    client: Arc<RmcClient>,
}

impl AuthenticationClient {
    pub fn new(client: Arc<RmcClient>) -> Self {
        AuthenticationClient { client }
    }

    async fn request(
        &self,
        name: &str,
        method: u32,
        body: &[u8],
    ) -> Result<Vec<u8>, RmcClientError> {
        info!("AuthenticationClient.{}()", name);
        let result = self.client.request(PROTOCOL_ID.into(), method, body).await;
        match &result {
            Ok(_) => info!("AuthenticationClient.{} -> done", name),
            Err(error) => warn!("AuthenticationClient.{} -> failed: {}", name, error),
        }
        result
    }

    pub async fn login(&self, username: &str) -> Result<LoginResponse, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.string(username)?;

        let response = self
            .request("login", METHOD_LOGIN, stream.as_bytes())
            .await?;

        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(LoginResponse {
            result: stream.result()?,
            pid: stream.pid()?,
            ticket: stream.buffer()?.to_vec(),
            connection_data: stream.extract()?,
            server_name: stream.string()?,
        })
    }

    pub async fn request_ticket(
        &self,
        source: u64,
        target: u64,
    ) -> Result<TicketResponse, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.pid(source);
        stream.pid(target);

        let response = self
            .request("request_ticket", METHOD_REQUEST_TICKET, stream.as_bytes())
            .await?;

        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(TicketResponse {
            result: stream.result()?,
            ticket: stream.buffer()?.to_vec(),
        })
    }

    pub async fn get_pid(&self, username: &str) -> Result<u64, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.string(username)?;

        let response = self
            .request("get_pid", METHOD_GET_PID, stream.as_bytes())
            .await?;

        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(stream.pid()?)
    }

    pub async fn get_name(&self, pid: u64) -> Result<Option<String>, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.pid(pid);

        let response = self
            .request("get_name", METHOD_GET_NAME, stream.as_bytes())
            .await?;

        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(stream.string()?)
    }
}

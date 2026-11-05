//! RMC protocol.
//!
//! Ported from `nintendo/nex/rmc.py`, client side only.
//!
//! RMC runs on top of PRUDP and carries request/response pairs for the NEX
//! protocols. The client is used by the friend/authentication clients.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use log::{debug, warn};
use tokio::sync::{oneshot, Mutex};

use crate::nex::common::{Result as NexResult, RmcError as RemoteRmcError};
use crate::nex::kerberos::Credentials;
use crate::nex::prudp::{PrudpClient, PrudpError};
use crate::nex::settings::Settings;
use crate::nex::streams::{StreamError, StreamIn, StreamOut};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Error returned by the RMC client.
#[derive(Debug, thiserror::Error)]
pub enum RmcClientError {
    #[error(transparent)]
    Prudp(#[from] PrudpError),
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error("{0}")]
    Remote(#[from] RemoteRmcError),
    #[error("rmc protocol error: {0}")]
    Protocol(String),
    #[error("connection is closed")]
    Closed,
    #[error("request timed out")]
    Timeout,
}

type Result<T> = std::result::Result<T, RmcClientError>;

/// Direction of an RMC message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Request,
    Response,
}

/// A single RMC request or response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RmcMessage {
    pub mode: Mode,
    pub protocol: u16,
    pub method: u32,
    pub call_id: u32,
    pub error: Option<u32>,
    pub body: Vec<u8>,
}

impl RmcMessage {
    pub fn request(protocol: u16, method: u32, call_id: u32, body: Vec<u8>) -> Self {
        RmcMessage {
            mode: Mode::Request,
            protocol,
            method,
            call_id,
            error: None,
            body,
        }
    }

    pub fn response(protocol: u16, method: u32, call_id: u32, body: Vec<u8>) -> Self {
        RmcMessage {
            mode: Mode::Response,
            protocol,
            method,
            call_id,
            error: None,
            body,
        }
    }

    pub fn error(protocol: u16, _method: u32, call_id: u32, error: u32) -> Self {
        RmcMessage {
            mode: Mode::Response,
            protocol,
            method: 0,
            call_id,
            error: Some(error),
            body: Vec::new(),
        }
    }

    pub fn encode(&self, settings: &Settings) -> Vec<u8> {
        let mut stream = StreamOut::new(settings);
        stream.u32(0);

        let flag = if self.mode == Mode::Request {
            0x80
        } else {
            0x00
        };
        if self.protocol < 0x80 {
            stream.u8(self.protocol as u8 | flag);
        } else {
            stream.u8(0x7F | flag);
            stream.u16(self.protocol);
        }

        match self.mode {
            Mode::Request => {
                stream.u32(self.call_id);
                stream.u32(self.method);
                stream.write(&self.body);
            }
            Mode::Response => match self.error {
                Some(error) => {
                    stream.bool(false);
                    stream.u32(error);
                    stream.u32(self.call_id);
                }
                None => {
                    stream.bool(true);
                    stream.u32(self.call_id);
                    stream.u32(self.method | 0x8000);
                    stream.write(&self.body);
                }
            },
        }

        let body_length = (stream.len() - 4) as u32;
        stream.set_u32(0, body_length);
        stream.into_bytes()
    }

    pub fn parse(settings: &Settings, data: &[u8]) -> Result<Self> {
        let mut stream = StreamIn::new(settings, data);

        let length = stream.u32()?;
        if usize::try_from(length).ok() != Some(stream.size().saturating_sub(4)) {
            return Err(RmcClientError::Protocol(
                "RMC message has unexpected size".into(),
            ));
        }

        let protocol_byte = stream.u8()?;
        let mut protocol = u16::from(protocol_byte & !0x80);
        if protocol == 0x7F {
            protocol = stream.u16()?;
        }

        if protocol_byte & 0x80 != 0 {
            Ok(RmcMessage {
                mode: Mode::Request,
                protocol,
                call_id: stream.u32()?,
                method: stream.u32()?,
                error: None,
                body: stream.read_all()?.to_vec(),
            })
        } else if stream.bool()? {
            Ok(RmcMessage {
                mode: Mode::Response,
                protocol,
                call_id: stream.u32()?,
                method: stream.u32()? & !0x8000,
                error: None,
                body: stream.read_all()?.to_vec(),
            })
        } else {
            let error = stream.u32()?;
            let call_id = stream.u32()?;
            if !stream.eof() {
                return Err(RmcClientError::Protocol(
                    "RMC error message is bigger than expected".into(),
                ));
            }
            Ok(RmcMessage {
                mode: Mode::Response,
                protocol,
                method: 0,
                call_id,
                error: Some(error),
                body: Vec::new(),
            })
        }
    }
}

/// RMC client on top of a PRUDP connection.
pub struct RmcClient {
    settings: Settings,
    prudp: Arc<PrudpClient>,
    call_id: AtomicU32,
    pending: Arc<Mutex<HashMap<u32, oneshot::Sender<RmcMessage>>>>,
    closed: Arc<AtomicBool>,
}

impl RmcClient {
    /// Connects to an RMC server.
    pub async fn connect(
        settings: &Settings,
        host: &str,
        port: u16,
        vport: u8,
        credentials: Option<Credentials>,
    ) -> Result<Self> {
        debug!("RmcClient.connect({}:{}, vport={})", host, port, vport);
        let prudp = Arc::new(PrudpClient::connect(settings, host, port, vport, credentials).await?);

        let mut settings = settings.clone();
        if prudp.minor_version() >= 3 {
            settings.struct_header = true;
        }

        let pending: Arc<Mutex<HashMap<u32, oneshot::Sender<RmcMessage>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let closed = Arc::new(AtomicBool::new(false));

        let client = RmcClient {
            settings,
            prudp,
            call_id: AtomicU32::new(1),
            pending,
            closed,
        };

        client.spawn_reader();
        Ok(client)
    }

    fn spawn_reader(&self) {
        let settings = self.settings.clone();
        let prudp = Arc::clone(&self.prudp);
        let pending = Arc::clone(&self.pending);
        let closed = Arc::clone(&self.closed);

        tokio::spawn(async move {
            while let Some(data) = prudp.recv().await {
                let message = match RmcMessage::parse(&settings, &data) {
                    Ok(message) => message,
                    Err(error) => {
                        debug!("RMC: dropping malformed message: {}", error);
                        continue;
                    }
                };

                match message.mode {
                    Mode::Response => {
                        let sender = pending.lock().await.remove(&message.call_id);
                        if let Some(sender) = sender {
                            let _ = sender.send(message);
                        }
                    }
                    Mode::Request => {
                        let error = NexResult::error_named("Core::NotImplemented")
                            .unwrap_or_else(NexResult::error);
                        let response = RmcMessage::error(
                            message.protocol,
                            message.method,
                            message.call_id,
                            error.code(),
                        );
                        let _ = prudp.send(&response.encode(&settings)).await;
                    }
                }
            }

            closed.store(true, Ordering::SeqCst);
            pending.lock().await.clear();
        });
    }

    /// Calls a method on the remote server and returns the response body.
    pub async fn request(
        &self,
        protocol: u16,
        method: u32,
        body: impl Into<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(RmcClientError::Closed);
        }

        let call_id = self.next_call_id();
        let (sender, receiver) = oneshot::channel();
        self.pending.lock().await.insert(call_id, sender);

        let message = RmcMessage::request(protocol, method, call_id, body.into());
        debug!(
            "RMC request: protocol=0x{:02X} method={} call_id={} body={} bytes",
            protocol,
            method,
            call_id,
            message.body.len()
        );
        if let Err(error) = self.prudp.send(&message.encode(&self.settings)).await {
            warn!(
                "RMC request send failed: call_id={} error={}",
                call_id, error
            );
            self.pending.lock().await.remove(&call_id);
            return Err(error.into());
        }

        let response = match tokio::time::timeout(REQUEST_TIMEOUT, receiver).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => return Err(RmcClientError::Closed),
            Err(_) => {
                warn!("RMC request timed out: call_id={}", call_id);
                self.pending.lock().await.remove(&call_id);
                return Err(RmcClientError::Timeout);
            }
        };

        if let Some(error) = response.error {
            warn!(
                "RMC response error: call_id={} code=0x{:08X}",
                call_id, error
            );
            return Err(RemoteRmcError::new(NexResult::from_code(error)).into());
        }

        debug!(
            "RMC response: protocol=0x{:02X} method={} call_id={} body={} bytes",
            response.protocol,
            response.method,
            response.call_id,
            response.body.len()
        );
        Ok(response.body)
    }

    /// Calls a method that does not return a response.
    pub async fn request_no_response(
        &self,
        protocol: u16,
        method: u32,
        body: impl Into<Vec<u8>>,
    ) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(RmcClientError::Closed);
        }

        let call_id = self.next_call_id();
        let message = RmcMessage::request(protocol, method, call_id, body.into());
        debug!(
            "RMC request (no response): protocol=0x{:02X} method={} call_id={} body={} bytes",
            protocol,
            method,
            call_id,
            message.body.len()
        );
        self.prudp.send(&message.encode(&self.settings)).await?;
        Ok(())
    }

    /// Calls a method with a body that uses the client's settings.
    pub async fn request_stream(
        &self,
        protocol: u16,
        method: u32,
        body: &mut StreamOut<'_>,
    ) -> Result<Vec<u8>> {
        self.request(protocol, method, body.as_bytes()).await
    }

    fn next_call_id(&self) -> u32 {
        self.call_id.fetch_add(1, Ordering::SeqCst)
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn pid(&self) -> Option<u64> {
        self.prudp.pid()
    }

    /// Gracefully disconnects from the server.
    pub async fn disconnect(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.prudp.disconnect().await;
    }

    /// Closes the connection immediately.
    pub async fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.prudp.close().await;
    }
}

impl Drop for RmcClient {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        let prudp = Arc::clone(&self.prudp);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                prudp.close().await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_encoding_matches_reference() {
        let settings = Settings::load("friends").unwrap();
        let message = RmcMessage::request(101, 1, 5, b"\x01\x02".to_vec());
        assert_eq!(
            message.encode(&settings),
            hex("0b000000e505000000010000000102")
        );
    }

    #[test]
    fn response_encoding_matches_reference() {
        let settings = Settings::load("friends").unwrap();
        let message = RmcMessage::response(102, 3, 7, b"\x03\x04".to_vec());
        assert_eq!(
            message.encode(&settings),
            hex("0c000000660107000000038000000304")
        );
    }

    #[test]
    fn error_encoding_matches_reference() {
        let settings = Settings::load("friends").unwrap();
        let message = RmcMessage::error(102, 3, 7, 0x80010002);
        assert_eq!(
            message.encode(&settings),
            hex("0a00000066000200018007000000")
        );
    }

    #[test]
    fn large_protocol_id_encoding_matches_reference() {
        let settings = Settings::load("friends").unwrap();
        let message = RmcMessage::request(0x1234, 9, 1, Vec::new());
        assert_eq!(
            message.encode(&settings),
            hex("0b000000ff34120100000009000000")
        );
    }

    #[test]
    fn roundtrip_all_message_kinds() {
        let settings = Settings::load("friends").unwrap();
        let messages = [
            RmcMessage::request(101, 1, 5, b"body".to_vec()),
            RmcMessage::response(102, 3, 7, b"response".to_vec()),
            RmcMessage::error(102, 3, 7, 0x80010002),
            RmcMessage::request(0x1234, 9, 1, Vec::new()),
        ];

        for message in messages {
            let data = message.encode(&settings);
            let parsed = RmcMessage::parse(&settings, &data).unwrap();
            assert_eq!(parsed, message);
        }
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }
}

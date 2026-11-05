//! NEX notification protocol.
//!
//! Ported from `nintendo/nex/notification.py` (generated from
//! `notification.proto` in the reference branch).

use std::sync::Arc;

use log::{info, warn};

use crate::nex::common::Structure;
use crate::nex::rmc::{RmcClient, RmcClientError};
use crate::nex::streams::{StreamError, StreamIn, StreamOut};

/// Protocol id of the notification protocol.
pub const PROTOCOL_ID: u8 = 0x0E;
/// Method id of `process_notification_event`.
pub const METHOD_PROCESS_NOTIFICATION_EVENT: u32 = 1;

/// Event that the server pushes to the client.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NotificationEvent {
    pub pid: u64,
    pub type_: u32,
    pub param1: u64,
    pub param2: u64,
    pub text: String,
    pub param3: u64,
}

impl Structure for NotificationEvent {
    fn save(&self, stream: &mut StreamOut, _version: u8) -> Result<(), StreamError> {
        stream.pid(self.pid);
        stream.u32(self.type_);
        stream.pid(self.param1);
        stream.pid(self.param2);
        stream.string(&self.text)?;
        if stream.settings().nex_version >= 30500 {
            stream.pid(self.param3);
        }
        Ok(())
    }

    fn load(&mut self, stream: &mut StreamIn, _version: u8) -> Result<(), StreamError> {
        self.pid = stream.pid()?;
        self.type_ = stream.u32()?;
        self.param1 = stream.pid()?;
        self.param2 = stream.pid()?;
        self.text = stream.string()?.unwrap_or_default();
        if stream.settings().nex_version >= 30500 {
            self.param3 = stream.pid()?;
        }
        Ok(())
    }
}

/// Client for the notification protocol.
pub struct NotificationClient {
    client: Arc<RmcClient>,
}

impl NotificationClient {
    pub fn new(client: Arc<RmcClient>) -> Self {
        NotificationClient { client }
    }

    /// Sends a notification event to the server. The server does not respond.
    pub async fn process_notification_event(
        &self,
        event: &NotificationEvent,
    ) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.add(event)?;
        let body = stream.into_bytes();

        info!("NotificationClient.process_notification_event()");
        let result = self
            .client
            .request_no_response(PROTOCOL_ID.into(), METHOD_PROCESS_NOTIFICATION_EVENT, body)
            .await;
        match &result {
            Ok(()) => info!("NotificationClient.process_notification_event -> done"),
            Err(error) => warn!(
                "NotificationClient.process_notification_event -> failed: {}",
                error
            ),
        }
        result
    }
}

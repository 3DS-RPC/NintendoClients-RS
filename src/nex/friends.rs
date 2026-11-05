//! Friend protocol.
//!
//! Ported from `nintendo/nex/friends.py` (generated from `friends.proto` in
//! the reference branch).
//!
//! The 3DS uses [`FriendsClientV1`], the Wii U uses [`FriendsClientV2`].

use std::sync::Arc;

use log::{info, warn};

use crate::nex::common::{DateTime, Structure};
use crate::nex::rmc::{RmcClient, RmcClientError};
use crate::nex::streams::{StreamError, StreamIn, StreamOut};

/// Protocol id of the v1 friend protocol.
pub const PROTOCOL_ID_V1: u16 = 0x65;
/// Protocol id of the v2 friend protocol.
pub const PROTOCOL_ID_V2: u16 = 0x66;

macro_rules! write_value {
    ($stream:expr, $value:expr, u8) => {{
        $stream.u8(*$value);
        Ok(())
    }};
    ($stream:expr, $value:expr, u16) => {{
        $stream.u16(*$value);
        Ok(())
    }};
    ($stream:expr, $value:expr, u32) => {{
        $stream.u32(*$value);
        Ok(())
    }};
    ($stream:expr, $value:expr, u64) => {{
        $stream.u64(*$value);
        Ok(())
    }};
    ($stream:expr, $value:expr, bool) => {{
        $stream.bool(*$value);
        Ok(())
    }};
    ($stream:expr, $value:expr, pid) => {{
        $stream.pid(*$value);
        Ok(())
    }};
    ($stream:expr, $value:expr, string) => {
        $stream.string($value)
    };
    ($stream:expr, $value:expr, buffer) => {
        $stream.buffer($value)
    };
    ($stream:expr, $value:expr, datetime) => {{
        $stream.datetime(*$value);
        Ok(())
    }};
    ($stream:expr, $value:expr, struct($ty:ty)) => {
        $stream.add($value)
    };
}

macro_rules! read_value {
    ($stream:expr, u8) => {
        $stream.u8()
    };
    ($stream:expr, u16) => {
        $stream.u16()
    };
    ($stream:expr, u32) => {
        $stream.u32()
    };
    ($stream:expr, u64) => {
        $stream.u64()
    };
    ($stream:expr, bool) => {
        $stream.bool()
    };
    ($stream:expr, pid) => {
        $stream.pid()
    };
    ($stream:expr, string) => {
        Ok($stream.string()?.unwrap_or_default())
    };
    ($stream:expr, buffer) => {
        Ok($stream.buffer()?.to_vec())
    };
    ($stream:expr, datetime) => {
        $stream.datetime()
    };
    ($stream:expr, struct($ty:ty)) => {
        $stream.extract::<$ty>()
    };
}

macro_rules! save_fields {
    ($stream:expr, $this:expr,) => {};
    ($stream:expr, $this:expr, $field:ident : list($inner:ident), $($rest:tt)*) => {
        $stream.list(&$this.$field, |stream, value| write_value!(stream, value, $inner))?;
        save_fields!($stream, $this, $($rest)*);
    };
    ($stream:expr, $this:expr, $field:ident : liststruct($ty:ty), $($rest:tt)*) => {
        $stream.list(&$this.$field, |stream, value| stream.add(value))?;
        save_fields!($stream, $this, $($rest)*);
    };
    ($stream:expr, $this:expr, $field:ident : listbuffer, $($rest:tt)*) => {
        $stream.list(&$this.$field, |stream, value| stream.buffer(value))?;
        save_fields!($stream, $this, $($rest)*);
    };
    ($stream:expr, $this:expr, $field:ident : $kind:ident, $($rest:tt)*) => {
        write_value!($stream, &$this.$field, $kind)?;
        save_fields!($stream, $this, $($rest)*);
    };
    ($stream:expr, $this:expr, $field:ident : struct($ty:ty), $($rest:tt)*) => {
        write_value!($stream, &$this.$field, struct($ty))?;
        save_fields!($stream, $this, $($rest)*);
    };
}

macro_rules! load_fields {
    ($stream:expr, $this:expr,) => {};
    ($stream:expr, $this:expr, $field:ident : list($inner:ident), $($rest:tt)*) => {
        $this.$field = $stream.list(|stream| read_value!(stream, $inner))?;
        load_fields!($stream, $this, $($rest)*);
    };
    ($stream:expr, $this:expr, $field:ident : liststruct($ty:ty), $($rest:tt)*) => {
        $this.$field = $stream.list(|stream| stream.extract::<$ty>())?;
        load_fields!($stream, $this, $($rest)*);
    };
    ($stream:expr, $this:expr, $field:ident : listbuffer, $($rest:tt)*) => {
        $this.$field = $stream.list(|stream| Ok(stream.buffer()?.to_vec()))?;
        load_fields!($stream, $this, $($rest)*);
    };
    ($stream:expr, $this:expr, $field:ident : $kind:ident, $($rest:tt)*) => {
        $this.$field = read_value!($stream, $kind)?;
        load_fields!($stream, $this, $($rest)*);
    };
    ($stream:expr, $this:expr, $field:ident : struct($ty:ty), $($rest:tt)*) => {
        $this.$field = $stream.extract::<$ty>()?;
        load_fields!($stream, $this, $($rest)*);
    };
}

macro_rules! structure_impl {
    ($name:ident, { $($fields:tt)* }, $is_data:expr) => {
        impl Structure for $name {
            const IS_DATA: bool = $is_data;

            fn save(&self, stream: &mut StreamOut, _version: u8) -> Result<(), StreamError> {
                save_fields!(stream, self, $($fields)*);
                Ok(())
            }

            fn load(&mut self, stream: &mut StreamIn, _version: u8) -> Result<(), StreamError> {
                load_fields!(stream, self, $($fields)*);
                Ok(())
            }
        }
    };
}

macro_rules! structure {
    ($name:ident, { $($fields:tt)* }) => {
        structure_impl!($name, { $($fields)* }, false);
    };
}

macro_rules! data_structure {
    ($name:ident, { $($fields:tt)* }) => {
        structure_impl!($name, { $($fields)* }, true);
    };
}

// ---------------------------------------------------------------------------
// 3DS structures
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AccountExtraInfo {
    pub local_friend_code: u64,
    pub move_count: u32,
    pub token: String,
}

structure!(AccountExtraInfo, {
    local_friend_code: u64,
    move_count: u32,
    token: string,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FriendComment {
    pub pid: u64,
    pub comment: String,
    pub modified_at: DateTime,
}

data_structure!(FriendComment, {
    pid: pid,
    comment: string,
    modified_at: datetime,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FriendKey {
    pub unk1: u32,
    pub unk2: DateTime,
}

structure!(FriendKey, {
    unk1: u32,
    unk2: datetime,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Mii {
    pub name: String,
    pub unk1: bool,
    pub unk2: u8,
    pub mii_data: Vec<u8>,
}

data_structure!(Mii, {
    name: string,
    unk1: bool,
    unk2: u8,
    mii_data: buffer,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MiiList {
    pub unk1: String,
    pub unk2: bool,
    pub unk3: u8,
    pub mii_datas: Vec<Vec<u8>>,
}

data_structure!(MiiList, {
    unk1: string,
    unk2: bool,
    unk3: u8,
    mii_datas: listbuffer,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FriendMii {
    pub pid: u64,
    pub mii: Mii,
    pub modified_at: DateTime,
}

data_structure!(FriendMii, {
    pid: pid,
    mii: struct(Mii),
    modified_at: datetime,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FriendMiiList {
    pub unk1: u32,
    pub mii: MiiList,
    pub unk2: DateTime,
}

data_structure!(FriendMiiList, {
    unk1: u32,
    mii: struct(MiiList),
    unk2: datetime,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GameKey {
    pub title_id: u64,
    pub title_version: u16,
}

data_structure!(GameKey, {
    title_id: u64,
    title_version: u16,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FriendPersistentInfo {
    pub pid: u64,
    pub region: u8,
    pub country: u8,
    pub area: u8,
    pub language: u8,
    pub platform: u8,
    pub game_key: GameKey,
    pub message: String,
    pub message_updated: DateTime,
    pub friended: DateTime,
    pub last_online: DateTime,
}

data_structure!(FriendPersistentInfo, {
    pid: pid,
    region: u8,
    country: u8,
    area: u8,
    language: u8,
    platform: u8,
    game_key: struct(GameKey),
    message: string,
    message_updated: datetime,
    friended: datetime,
    last_online: datetime,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FriendPicture {
    pub unk: u32,
    pub data: Vec<u8>,
    pub datetime: DateTime,
}

data_structure!(FriendPicture, {
    unk: u32,
    data: buffer,
    datetime: datetime,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NintendoPresence {
    pub changed_bit_flag: u32,
    pub game_key: GameKey,
    pub game_mode_description: String,
    pub join_availability_flag: u32,
    pub matchmake_system_type: u8,
    pub join_game_id: u32,
    pub join_game_mode: u32,
    pub owner_pid: u64,
    pub join_group_id: u32,
    pub application_data: Vec<u8>,
}

data_structure!(NintendoPresence, {
    changed_bit_flag: u32,
    game_key: struct(GameKey),
    game_mode_description: string,
    join_availability_flag: u32,
    matchmake_system_type: u8,
    join_game_id: u32,
    join_game_mode: u32,
    owner_pid: pid,
    join_group_id: u32,
    application_data: buffer,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FriendPresence {
    pub pid: u64,
    pub presence: NintendoPresence,
}

data_structure!(FriendPresence, {
    pid: pid,
    presence: struct(NintendoPresence),
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FriendRelationship {
    pub pid: u64,
    pub friend_code: u64,
    pub is_complete: u8,
}

data_structure!(FriendRelationship, {
    pid: pid,
    friend_code: u64,
    is_complete: u8,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MyProfile {
    pub region: u8,
    pub country: u8,
    pub area: u8,
    pub language: u8,
    pub platform: u8,
    pub local_friend_code_seed: u64,
    pub mac_address: String,
    pub serial_number: String,
}

data_structure!(MyProfile, {
    region: u8,
    country: u8,
    area: u8,
    language: u8,
    platform: u8,
    local_friend_code_seed: u64,
    mac_address: string,
    serial_number: string,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PlayedGame {
    pub game_key: GameKey,
    pub datetime: DateTime,
}

data_structure!(PlayedGame, {
    game_key: struct(GameKey),
    datetime: datetime,
});

// ---------------------------------------------------------------------------
// Wii U structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalBasicInfo {
    pub pid: u64,
    pub nnid: String,
    pub mii: MiiV2,
    pub unk: u8,
}

impl Default for PrincipalBasicInfo {
    fn default() -> Self {
        PrincipalBasicInfo {
            pid: 0,
            nnid: String::new(),
            mii: MiiV2::default(),
            unk: 2,
        }
    }
}

data_structure!(PrincipalBasicInfo, {
    pid: pid,
    nnid: string,
    mii: struct(MiiV2),
    unk: u8,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MiiV2 {
    pub name: String,
    pub unk1: u8,
    pub unk2: u8,
    pub data: Vec<u8>,
    pub datetime: DateTime,
}

data_structure!(MiiV2, {
    name: string,
    unk1: u8,
    unk2: u8,
    data: buffer,
    datetime: datetime,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BlacklistedPrincipal {
    pub principal_info: PrincipalBasicInfo,
    pub game_key: GameKey,
    pub since: DateTime,
}

data_structure!(BlacklistedPrincipal, {
    principal_info: struct(PrincipalBasicInfo),
    game_key: struct(GameKey),
    since: datetime,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Comment {
    pub unk: u8,
    pub text: String,
    pub changed: DateTime,
}

data_structure!(Comment, {
    unk: u8,
    text: string,
    changed: datetime,
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NNAInfo {
    pub principal_info: PrincipalBasicInfo,
    pub unk1: u8,
    pub unk2: u8,
}

impl Default for NNAInfo {
    fn default() -> Self {
        NNAInfo {
            principal_info: PrincipalBasicInfo::default(),
            unk1: 94,
            unk2: 11,
        }
    }
}

data_structure!(NNAInfo, {
    principal_info: struct(PrincipalBasicInfo),
    unk1: u8,
    unk2: u8,
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NintendoPresenceV2 {
    pub flags: u32,
    pub is_online: bool,
    pub game_key: GameKey,
    pub unk1: u8,
    pub message: String,
    pub unk2: u32,
    pub unk3: u8,
    pub game_server_id: u32,
    pub unk4: u32,
    pub pid: u32,
    pub gathering_id: u32,
    pub application_data: Vec<u8>,
    pub unk5: u8,
    pub unk6: u8,
    pub unk7: u8,
}

impl Default for NintendoPresenceV2 {
    fn default() -> Self {
        NintendoPresenceV2 {
            flags: 0,
            is_online: false,
            game_key: GameKey::default(),
            unk1: 0,
            message: String::new(),
            unk2: 0,
            unk3: 0,
            game_server_id: 0,
            unk4: 0,
            pid: 0,
            gathering_id: 0,
            application_data: Vec::new(),
            unk5: 3,
            unk6: 3,
            unk7: 3,
        }
    }
}

data_structure!(NintendoPresenceV2, {
    flags: u32,
    is_online: bool,
    game_key: struct(GameKey),
    unk1: u8,
    message: string,
    unk2: u32,
    unk3: u8,
    game_server_id: u32,
    unk4: u32,
    pid: u32,
    gathering_id: u32,
    application_data: buffer,
    unk5: u8,
    unk6: u8,
    unk7: u8,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FriendInfo {
    pub nna_info: NNAInfo,
    pub presence: NintendoPresenceV2,
    pub comment: Comment,
    pub befriended: DateTime,
    pub last_online: DateTime,
    pub unk: u64,
}

data_structure!(FriendInfo, {
    nna_info: struct(NNAInfo),
    presence: struct(NintendoPresenceV2),
    comment: struct(Comment),
    befriended: datetime,
    last_online: datetime,
    unk: u64,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FriendRequestMessage {
    pub friend_request_id: u64,
    pub unk1: u8,
    pub unk2: u8,
    pub message: String,
    pub unk3: u8,
    pub string: String,
    pub game_key: GameKey,
    pub datetime: DateTime,
    pub expires: DateTime,
}

data_structure!(FriendRequestMessage, {
    friend_request_id: u64,
    unk1: u8,
    unk2: u8,
    message: string,
    unk3: u8,
    string: string,
    game_key: struct(GameKey),
    datetime: datetime,
    expires: datetime,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FriendRequest {
    pub principal_info: PrincipalBasicInfo,
    pub message: FriendRequestMessage,
    pub sent: DateTime,
}

data_structure!(FriendRequest, {
    principal_info: struct(PrincipalBasicInfo),
    message: struct(FriendRequestMessage),
    sent: datetime,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NintendoCreateAccountData {
    pub info: NNAInfo,
    pub token: String,
    pub birthday: DateTime,
    pub unk: u64,
}

data_structure!(NintendoCreateAccountData, {
    info: struct(NNAInfo),
    token: string,
    birthday: datetime,
    unk: u64,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PersistentNotification {
    pub unk1: u64,
    pub unk2: u32,
    pub unk3: u32,
    pub unk4: u32,
    pub string: String,
}

data_structure!(PersistentNotification, {
    unk1: u64,
    unk2: u32,
    unk3: u32,
    unk4: u32,
    string: string,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PrincipalPreference {
    pub show_online_status: bool,
    pub show_current_title: bool,
    pub block_friend_requests: bool,
}

data_structure!(PrincipalPreference, {
    show_online_status: bool,
    show_current_title: bool,
    block_friend_requests: bool,
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PrincipalRequestBlockSetting {
    pub pid: u32,
    pub blocked: bool,
}

data_structure!(PrincipalRequestBlockSetting, {
    pid: u32,
    blocked: bool,
});

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Result of `update_and_get_all_information` (Wii U).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AllFriendInformation {
    pub principal_preference: PrincipalPreference,
    pub comment: Comment,
    pub friends: Vec<FriendInfo>,
    pub sent_requests: Vec<FriendRequest>,
    pub received_requests: Vec<FriendRequest>,
    pub blacklist: Vec<BlacklistedPrincipal>,
    pub unk1: bool,
    pub notifications: Vec<PersistentNotification>,
    pub unk2: bool,
}

/// Result of `add_friend`/`add_friend_by_name`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FriendRequestResult {
    pub request: FriendRequest,
    pub info: FriendInfo,
}

fn method_name_v1(method: u32) -> &'static str {
    match method {
        1 => "update_profile",
        2 => "update_mii",
        3 => "update_mii_list",
        4 => "update_played_games",
        5 => "update_preference",
        6 => "get_friend_mii",
        7 => "get_friend_mii_list",
        8 => "is_active_game",
        9 => "get_principal_id_by_local_friend_code",
        10 => "get_friend_relationships",
        11 => "add_friend_by_principal_id",
        12 => "add_friend_by_principal_ids",
        13 => "remove_friend_by_local_friend_code",
        14 => "remove_friend_by_principal_id",
        15 => "get_all_friends",
        16 => "update_black_list",
        17 => "sync_friend",
        18 => "update_presence",
        19 => "update_favorite_game_key",
        20 => "update_comment",
        21 => "update_picture",
        22 => "get_friend_presence",
        23 => "get_friend_comment",
        24 => "get_friend_picture",
        25 => "get_friend_persistent_info",
        26 => "send_invitation",
        _ => "unknown",
    }
}

fn method_name_v2(method: u32) -> &'static str {
    match method {
        1 => "update_and_get_all_information",
        2 => "add_friend",
        3 => "add_friend_by_name",
        4 => "remove_friend",
        5 => "add_friend_request",
        6 => "cancel_friend_request",
        7 => "accept_friend_request",
        8 => "delete_friend_request",
        9 => "deny_friend_request",
        10 => "mark_friend_requests_as_received",
        11 => "add_black_list",
        12 => "remove_black_list",
        13 => "update_presence",
        14 => "update_mii",
        15 => "update_comment",
        16 => "update_preference",
        17 => "get_basic_info",
        18 => "delete_persistent_notification",
        19 => "check_setting_status",
        20 => "get_request_block_settings",
        _ => "unknown",
    }
}

/// Client for the 3DS friend protocol.
pub struct FriendsClientV1 {
    client: Arc<RmcClient>,
}

impl FriendsClientV1 {
    pub fn new(client: Arc<RmcClient>) -> Self {
        FriendsClientV1 { client }
    }

    async fn request(&self, method: u32, body: Vec<u8>) -> Result<Vec<u8>, RmcClientError> {
        let name = method_name_v1(method);
        info!("FriendsClientV1.{}()", name);
        let result = self.client.request(PROTOCOL_ID_V1, method, body).await;
        match &result {
            Ok(_) => info!("FriendsClientV1.{} -> done", name),
            Err(error) => warn!("FriendsClientV1.{} -> failed: {}", name, error),
        }
        result
    }

    pub async fn update_profile(&self, profile: &MyProfile) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.add(profile)?;
        self.request(1, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn update_mii(&self, mii: &Mii) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.add(mii)?;
        self.request(2, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn update_mii_list(&self, mii_list: &MiiList) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.add(mii_list)?;
        self.request(3, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn update_played_games(&self, games: &[PlayedGame]) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(games, |stream, game| stream.add(game))?;
        self.request(4, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn update_preference(
        &self,
        show_online_status: bool,
        show_current_title: bool,
        block_friend_requests: bool,
    ) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.bool(show_online_status);
        stream.bool(show_current_title);
        stream.bool(block_friend_requests);
        self.request(5, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn get_friend_mii(
        &self,
        friends: &[FriendKey],
    ) -> Result<Vec<FriendMii>, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(friends, |stream, friend| stream.add(friend))?;
        let response = self.request(6, stream.into_bytes()).await?;
        Self::read_list(&response, self.client.settings())
    }

    pub async fn get_friend_mii_list(
        &self,
        friends: &[FriendKey],
    ) -> Result<Vec<FriendMiiList>, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(friends, |stream, friend| stream.add(friend))?;
        let response = self.request(7, stream.into_bytes()).await?;
        Self::read_list(&response, self.client.settings())
    }

    pub async fn is_active_game(
        &self,
        unk1: &[u32],
        game_key: &GameKey,
    ) -> Result<Vec<u32>, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(unk1, |stream, value| {
            stream.u32(*value);
            Ok(())
        })?;
        stream.add(game_key)?;
        let response = self.request(8, stream.into_bytes()).await?;
        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(stream.list(|stream| stream.u32())?)
    }

    pub async fn get_principal_id_by_local_friend_code(
        &self,
        unk1: u64,
        unk2: &[u64],
    ) -> Result<Vec<FriendRelationship>, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.u64(unk1);
        stream.list(unk2, |stream, value| {
            stream.u64(*value);
            Ok(())
        })?;
        let response = self.request(9, stream.into_bytes()).await?;
        Self::read_list(&response, self.client.settings())
    }

    pub async fn get_friend_relationships(
        &self,
        principal_ids: &[u64],
    ) -> Result<Vec<FriendRelationship>, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(principal_ids, |stream, value| {
            stream.pid(*value);
            Ok(())
        })?;
        let response = self.request(10, stream.into_bytes()).await?;
        Self::read_list(&response, self.client.settings())
    }

    pub async fn add_friend_by_principal_id(
        &self,
        friend_seed: u64,
        pid: u64,
    ) -> Result<FriendRelationship, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.u64(friend_seed);
        stream.pid(pid);
        let response = self.request(11, stream.into_bytes()).await?;
        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(stream.extract()?)
    }

    pub async fn add_friend_by_principal_ids(
        &self,
        unk: u64,
        pids: &[u64],
    ) -> Result<Vec<FriendRelationship>, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.u64(unk);
        stream.list(pids, |stream, value| {
            stream.pid(*value);
            Ok(())
        })?;
        let response = self.request(12, stream.into_bytes()).await?;
        Self::read_list(&response, self.client.settings())
    }

    pub async fn remove_friend_by_local_friend_code(
        &self,
        friend_code: u64,
    ) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.u64(friend_code);
        self.request(13, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn remove_friend_by_principal_id(&self, pid: u64) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.pid(pid);
        self.request(14, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn get_all_friends(&self) -> Result<Vec<FriendRelationship>, RmcClientError> {
        let response = self.request(15, Vec::new()).await?;
        Self::read_list(&response, self.client.settings())
    }

    pub async fn update_black_list(&self, unk: &[u32]) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(unk, |stream, value| {
            stream.u32(*value);
            Ok(())
        })?;
        self.request(16, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn sync_friend(
        &self,
        friend_seed: u64,
        principal_ids: &[u64],
        unk: &[u64],
    ) -> Result<Vec<FriendRelationship>, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.u64(friend_seed);
        stream.list(principal_ids, |stream, value| {
            stream.pid(*value);
            Ok(())
        })?;
        stream.list(unk, |stream, value| {
            stream.u64(*value);
            Ok(())
        })?;
        let response = self.request(17, stream.into_bytes()).await?;
        Self::read_list(&response, self.client.settings())
    }

    pub async fn update_presence(
        &self,
        presence: &NintendoPresence,
        unk: bool,
    ) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.add(presence)?;
        stream.bool(unk);
        self.request(18, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn update_favorite_game_key(&self, game_key: &GameKey) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.add(game_key)?;
        self.request(19, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn update_comment(&self, comment: &str) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.string(comment)?;
        self.request(20, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn update_picture(&self, unk: u32, picture: &[u8]) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.u32(unk);
        stream.buffer(picture)?;
        self.request(21, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn get_friend_presence(
        &self,
        principal_ids: &[u64],
    ) -> Result<Vec<FriendPresence>, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(principal_ids, |stream, value| {
            stream.pid(*value);
            Ok(())
        })?;
        let response = self.request(22, stream.into_bytes()).await?;
        Self::read_list(&response, self.client.settings())
    }

    pub async fn get_friend_comment(
        &self,
        friends: &[FriendKey],
    ) -> Result<Vec<FriendComment>, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(friends, |stream, friend| stream.add(friend))?;
        let response = self.request(23, stream.into_bytes()).await?;
        Self::read_list(&response, self.client.settings())
    }

    pub async fn get_friend_picture(
        &self,
        principal_ids: &[u64],
    ) -> Result<Vec<FriendPicture>, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(principal_ids, |stream, value| {
            stream.pid(*value);
            Ok(())
        })?;
        let response = self.request(24, stream.into_bytes()).await?;
        Self::read_list(&response, self.client.settings())
    }

    pub async fn get_friend_persistent_info(
        &self,
        principal_ids: &[u64],
    ) -> Result<Vec<FriendPersistentInfo>, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(principal_ids, |stream, value| {
            stream.pid(*value);
            Ok(())
        })?;
        let response = self.request(25, stream.into_bytes()).await?;
        Self::read_list(&response, self.client.settings())
    }

    pub async fn send_invitation(&self, unk: &[u32]) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(unk, |stream, value| {
            stream.u32(*value);
            Ok(())
        })?;
        self.request(26, stream.into_bytes()).await?;
        Ok(())
    }

    fn read_list<T: Structure + Default>(
        data: &[u8],
        settings: &crate::nex::settings::Settings,
    ) -> Result<Vec<T>, RmcClientError> {
        let mut stream = StreamIn::new(settings, data);
        Ok(stream.list(|stream| stream.extract::<T>())?)
    }
}

/// Client for the Wii U friend protocol.
pub struct FriendsClientV2 {
    client: Arc<RmcClient>,
}

impl FriendsClientV2 {
    pub fn new(client: Arc<RmcClient>) -> Self {
        FriendsClientV2 { client }
    }

    async fn request(&self, method: u32, body: Vec<u8>) -> Result<Vec<u8>, RmcClientError> {
        let name = method_name_v2(method);
        info!("FriendsClientV2.{}()", name);
        let result = self.client.request(PROTOCOL_ID_V2, method, body).await;
        match &result {
            Ok(_) => info!("FriendsClientV2.{} -> done", name),
            Err(error) => warn!("FriendsClientV2.{} -> failed: {}", name, error),
        }
        result
    }

    pub async fn update_and_get_all_information(
        &self,
        nna_info: &NNAInfo,
        presence: &NintendoPresenceV2,
        birthday: DateTime,
    ) -> Result<AllFriendInformation, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.add(nna_info)?;
        stream.add(presence)?;
        stream.datetime(birthday);
        let response = self.request(1, stream.into_bytes()).await?;

        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(AllFriendInformation {
            principal_preference: stream.extract()?,
            comment: stream.extract()?,
            friends: stream.list(|stream| stream.extract())?,
            sent_requests: stream.list(|stream| stream.extract())?,
            received_requests: stream.list(|stream| stream.extract())?,
            blacklist: stream.list(|stream| stream.extract())?,
            unk1: stream.bool()?,
            notifications: stream.list(|stream| stream.extract())?,
            unk2: stream.bool()?,
        })
    }

    pub async fn add_friend(&self, pid: u64) -> Result<FriendRequestResult, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.pid(pid);
        self.read_request_result(2, stream.into_bytes()).await
    }

    pub async fn add_friend_by_name(
        &self,
        name: &str,
    ) -> Result<FriendRequestResult, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.string(name)?;
        self.read_request_result(3, stream.into_bytes()).await
    }

    pub async fn remove_friend(&self, pid: u64) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.pid(pid);
        self.request(4, stream.into_bytes()).await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn add_friend_request(
        &self,
        unk1: u32,
        unk2: u8,
        unk3: &str,
        unk4: u8,
        unk5: &str,
        game_key: &GameKey,
        unk6: DateTime,
    ) -> Result<FriendRequestResult, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.u32(unk1);
        stream.u8(unk2);
        stream.string(unk3)?;
        stream.u8(unk4);
        stream.string(unk5)?;
        stream.add(game_key)?;
        stream.datetime(unk6);
        self.read_request_result(5, stream.into_bytes()).await
    }

    pub async fn cancel_friend_request(&self, id: u64) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.u64(id);
        self.request(6, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn accept_friend_request(&self, id: u64) -> Result<FriendInfo, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.u64(id);
        let response = self.request(7, stream.into_bytes()).await?;
        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(stream.extract()?)
    }

    pub async fn delete_friend_request(&self, id: u64) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.u64(id);
        self.request(8, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn deny_friend_request(
        &self,
        id: u64,
    ) -> Result<BlacklistedPrincipal, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.u64(id);
        let response = self.request(9, stream.into_bytes()).await?;
        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(stream.extract()?)
    }

    pub async fn mark_friend_requests_as_received(
        &self,
        ids: &[u64],
    ) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(ids, |stream, value| {
            stream.u64(*value);
            Ok(())
        })?;
        self.request(10, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn add_black_list(
        &self,
        principal: &BlacklistedPrincipal,
    ) -> Result<BlacklistedPrincipal, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.add(principal)?;
        let response = self.request(11, stream.into_bytes()).await?;
        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(stream.extract()?)
    }

    pub async fn remove_black_list(&self, pid: u64) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.pid(pid);
        self.request(12, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn update_presence(
        &self,
        presence: &NintendoPresenceV2,
    ) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.add(presence)?;
        self.request(13, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn update_mii(&self, mii: &MiiV2) -> Result<DateTime, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.add(mii)?;
        let response = self.request(14, stream.into_bytes()).await?;
        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(stream.datetime()?)
    }

    pub async fn update_comment(&self, comment: &Comment) -> Result<DateTime, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.add(comment)?;
        let response = self.request(15, stream.into_bytes()).await?;
        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(stream.datetime()?)
    }

    pub async fn update_preference(
        &self,
        preference: &PrincipalPreference,
    ) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.add(preference)?;
        self.request(16, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn get_basic_info(
        &self,
        pids: &[u64],
    ) -> Result<Vec<PrincipalBasicInfo>, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(pids, |stream, value| {
            stream.pid(*value);
            Ok(())
        })?;
        let response = self.request(17, stream.into_bytes()).await?;
        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(stream.list(|stream| stream.extract())?)
    }

    pub async fn delete_persistent_notification(
        &self,
        notifications: &[PersistentNotification],
    ) -> Result<(), RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(notifications, |stream, value| stream.add(value))?;
        self.request(18, stream.into_bytes()).await?;
        Ok(())
    }

    pub async fn check_setting_status(&self) -> Result<u8, RmcClientError> {
        let response = self.request(19, Vec::new()).await?;
        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(stream.u8()?)
    }

    pub async fn get_request_block_settings(
        &self,
        unk: &[u32],
    ) -> Result<Vec<PrincipalRequestBlockSetting>, RmcClientError> {
        let mut stream = StreamOut::new(self.client.settings());
        stream.list(unk, |stream, value| {
            stream.u32(*value);
            Ok(())
        })?;
        let response = self.request(20, stream.into_bytes()).await?;
        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(stream.list(|stream| stream.extract())?)
    }

    async fn read_request_result(
        &self,
        method: u32,
        body: Vec<u8>,
    ) -> Result<FriendRequestResult, RmcClientError> {
        let response = self.request(method, body).await?;
        let mut stream = StreamIn::new(self.client.settings(), &response);
        Ok(FriendRequestResult {
            request: stream.extract()?,
            info: stream.extract()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structures_roundtrip() {
        let settings = crate::nex::settings::Settings::load("friends").unwrap();

        let relationship = FriendRelationship {
            pid: 1000,
            friend_code: 0x1234_5678_9ABC,
            is_complete: 1,
        };

        let mut stream = StreamOut::new(&settings);
        stream.add(&relationship).unwrap();
        let data = stream.into_bytes();

        let mut stream = StreamIn::new(&settings, &data);
        let parsed: FriendRelationship = stream.extract().unwrap();
        assert_eq!(parsed, relationship);
        assert!(stream.eof());
    }

    #[test]
    fn v2_defaults_match_reference() {
        let nna = NNAInfo::default();
        assert_eq!(nna.unk1, 94);
        assert_eq!(nna.unk2, 11);

        let presence = NintendoPresenceV2::default();
        assert_eq!(presence.unk5, 3);
        assert_eq!(presence.unk6, 3);
        assert_eq!(presence.unk7, 3);

        assert_eq!(PrincipalBasicInfo::default().unk, 2);
    }

    #[test]
    fn relationship_encoding_matches_reference() {
        let settings = crate::nex::settings::Settings::load("friends").unwrap();
        let relationship = FriendRelationship {
            pid: 1000,
            friend_code: 0x1234_5678_9ABC,
            is_complete: 1,
        };

        let mut stream = StreamOut::new(&settings);
        stream.add(&relationship).unwrap();
        assert_eq!(stream.into_bytes(), hex("e8030000bc9a78563412000001"));
    }

    #[test]
    fn presence_encoding_matches_reference() {
        let settings = crate::nex::settings::Settings::load("friends").unwrap();
        let mut stream = StreamOut::new(&settings);
        stream.add(&NintendoPresenceV2::default()).unwrap();
        assert_eq!(
            stream.into_bytes(),
            hex(
                "0000000000000000000000000000000001000000000000000000000000000000000000000000000000000000030303"
            )
        );
    }

    #[test]
    fn profile_encoding_matches_reference() {
        let settings = crate::nex::settings::Settings::load("friends").unwrap();
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

        let mut stream = StreamOut::new(&settings);
        stream.add(&profile).unwrap();
        assert_eq!(
            stream.into_bytes(),
            hex("010203040588776655443322110d0061616262636364646565666600040031323300")
        );
    }

    #[test]
    fn data_struct_header_matches_reference() {
        let mut settings = crate::nex::settings::Settings::load("default").unwrap();
        settings.struct_header = true;

        let info = PrincipalBasicInfo {
            pid: 1000,
            nnid: "test-nnid".to_string(),
            mii: MiiV2 {
                name: "mii".to_string(),
                data: b"mii-data".to_vec(),
                ..MiiV2::default()
            },
            unk: 2,
        };

        let mut stream = StreamOut::new(&settings);
        stream
            .list(std::slice::from_ref(&info), |stream, value| {
                stream.add(value)
            })
            .unwrap();
        let data = stream.into_bytes();
        assert_eq!(
            data,
            hex(
                "0100000000000000000037000000e80300000a00746573742d6e6e6964000000000000001c00000004006d6969000000080000006d69692d64617461000000000000000002"
            )
        );

        let mut stream = StreamIn::new(&settings, &data);
        let parsed: Vec<PrincipalBasicInfo> = stream.list(|stream| stream.extract()).unwrap();
        assert_eq!(parsed, vec![info]);
        assert!(stream.eof());
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }
}

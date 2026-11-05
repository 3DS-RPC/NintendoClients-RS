//! Common NEX types.
//!
//! Ported from `nintendo/nex/common.py`.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::nex::errors;
use crate::nex::streams::{StreamError, StreamIn, StreamOut};

/// Bit that marks a NEX result as an error.
pub const ERROR_MASK: u32 = 1 << 31;

/// Result of an RMC method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Result {
    code: u32,
}

impl Result {
    /// Creates a result from a raw code (with or without the error mask).
    pub fn from_code(code: u32) -> Self {
        Result { code }
    }

    /// Creates a success result. Without an explicit code this is
    /// `Core::Unknown`, mirroring the Python reference.
    pub fn success() -> Self {
        Result::success_code(0x00010001)
    }

    /// Creates an error result. Without an explicit code this is
    /// `Core::Unknown`, mirroring the Python reference.
    pub fn error() -> Self {
        Result::error_code(0x00010001)
    }

    /// Creates a success result from a code, clearing the error mask.
    pub fn success_code(code: u32) -> Self {
        Result {
            code: code & !ERROR_MASK,
        }
    }

    /// Creates an error result from a code, setting the error mask.
    pub fn error_code(code: u32) -> Self {
        Result {
            code: code | ERROR_MASK,
        }
    }

    /// Creates an error result from a name such as `Core::Unknown`.
    pub fn error_named(name: &str) -> Option<Self> {
        errors::error_code(name).map(Result::error_code)
    }

    pub fn is_success(self) -> bool {
        self.code & ERROR_MASK == 0
    }

    pub fn is_error(self) -> bool {
        !self.is_success()
    }

    pub fn code(self) -> u32 {
        self.code
    }

    /// Returns the name of this result, or `"unknown error"`.
    pub fn name(self) -> &'static str {
        if self.is_success() {
            "success"
        } else {
            errors::error_name(self.code & !ERROR_MASK).unwrap_or("unknown error")
        }
    }

    /// Converts the result into `Ok(())` or an [`RmcError`].
    pub fn into_result(self) -> std::result::Result<(), RmcError> {
        if self.is_error() {
            Err(RmcError::new(self))
        } else {
            Ok(())
        }
    }
}

impl Default for Result {
    fn default() -> Self {
        Result::success()
    }
}

impl fmt::Display for Result {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:08X})", self.name(), self.code())
    }
}

/// Error returned by an RMC method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RmcError {
    pub result: Result,
}

impl RmcError {
    pub fn new(result: Result) -> Self {
        RmcError { result }
    }

    pub fn unknown() -> Self {
        RmcError::new(Result::error())
    }

    pub fn code(self) -> u32 {
        self.result.code()
    }
}

impl fmt::Display for RmcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.result, f)
    }
}

impl std::error::Error for RmcError {}

/// A NEX structure that can be serialized to and from a stream.
///
/// The Python reference walks the class hierarchy to encode struct headers.
/// Rust has no inheritance, so each implementation is responsible for writing
/// its parent fields in `save`/`load`. `MAX_VERSION` is the highest version
/// that the structure understands.
pub trait Structure: Sized {
    const MAX_VERSION: u8 = 0;

    /// Whether this type inherits from `Data` in the Python reference. Data
    /// types carry an extra (empty) struct header when struct headers are
    /// enabled.
    const IS_DATA: bool = false;

    fn save(&self, stream: &mut StreamOut, version: u8) -> std::result::Result<(), StreamError>;
    fn load(&mut self, stream: &mut StreamIn, version: u8) -> std::result::Result<(), StreamError>;
}

/// Offset/size pair used by several NEX protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultRange {
    pub offset: u32,
    pub size: u32,
}

impl ResultRange {
    pub fn new(offset: u32, size: u32) -> Self {
        ResultRange { offset, size }
    }
}

impl Default for ResultRange {
    fn default() -> Self {
        ResultRange {
            offset: 0,
            size: 10,
        }
    }
}

impl Structure for ResultRange {
    fn save(&self, stream: &mut StreamOut, _version: u8) -> std::result::Result<(), StreamError> {
        stream.u32(self.offset);
        stream.u32(self.size);
        Ok(())
    }

    fn load(
        &mut self,
        stream: &mut StreamIn,
        _version: u8,
    ) -> std::result::Result<(), StreamError> {
        self.offset = stream.u32()?;
        self.size = stream.u32()?;
        Ok(())
    }
}

/// NEX date and time, packed into 64 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DateTime(u64);

impl DateTime {
    pub fn new(value: u64) -> Self {
        DateTime(value)
    }

    pub fn value(self) -> u64 {
        self.0
    }

    pub fn second(self) -> u32 {
        (self.0 & 63) as u32
    }

    pub fn minute(self) -> u32 {
        ((self.0 >> 6) & 63) as u32
    }

    pub fn hour(self) -> u32 {
        ((self.0 >> 12) & 31) as u32
    }

    pub fn day(self) -> u32 {
        ((self.0 >> 17) & 31) as u32
    }

    pub fn month(self) -> u32 {
        ((self.0 >> 22) & 15) as u32
    }

    pub fn year(self) -> u32 {
        (self.0 >> 26) as u32
    }

    /// Builds a date/time from its individual fields.
    pub fn make(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Self {
        DateTime(
            u64::from(second)
                | (u64::from(minute) << 6)
                | (u64::from(hour) << 12)
                | (u64::from(day) << 17)
                | (u64::from(month) << 22)
                | (u64::from(year) << 26),
        )
    }

    pub fn never() -> Self {
        DateTime(0)
    }

    pub fn future() -> Self {
        DateTime::make(9999, 12, 31, 23, 59, 59)
    }

    /// Converts a Unix timestamp (seconds since the epoch, UTC) into a
    /// [`DateTime`].
    pub fn from_unix_timestamp(timestamp: i64) -> Self {
        let days = timestamp.div_euclid(86_400);
        let seconds = timestamp.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        DateTime::make(
            year as u32,
            month,
            day,
            (seconds / 3_600) as u32,
            ((seconds % 3_600) / 60) as u32,
            (seconds % 60) as u32,
        )
    }

    /// Converts this date/time into a Unix timestamp (UTC).
    pub fn timestamp(self) -> i64 {
        let days = days_from_civil(i64::from(self.year()), self.month(), self.day());
        days * 86_400
            + i64::from(self.hour()) * 3_600
            + i64::from(self.minute()) * 60
            + i64::from(self.second())
    }

    pub fn now() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        DateTime::from_unix_timestamp(now)
    }
}

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{}-{} {}:{:02}:{:02}",
            self.day(),
            self.month(),
            self.year(),
            self.hour(),
            self.minute(),
            self.second()
        )
    }
}

// Howard Hinnant's civil calendar algorithms.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = (i64::from(month) + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u32, day as u32)
}

/// Station URL (`prudp:/address=...;port=...`).
///
/// Parameters are kept in insertion order because the order is preserved on
/// the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationURL {
    scheme: String,
    params: Vec<(String, String)>,
}

impl Default for StationURL {
    fn default() -> Self {
        StationURL::new("prudp")
    }
}

impl StationURL {
    pub fn new(scheme: &str) -> Self {
        StationURL {
            scheme: scheme.to_string(),
            params: Vec::new(),
        }
    }

    /// Parses a station URL such as `prudps:/PID=1;CID=100`.
    pub fn parse(text: &str) -> Self {
        if text.is_empty() {
            return StationURL::default();
        }

        if let Some((scheme, fields)) = text.split_once(":/") {
            let params = fields
                .split(';')
                .filter(|field| !field.is_empty())
                .filter_map(|field| field.split_once('='))
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect();
            StationURL {
                scheme: scheme.to_string(),
                params,
            }
        } else {
            StationURL {
                scheme: text.to_string(),
                params: Vec::new(),
            }
        }
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn get_str(&self, key: &str) -> String {
        self.params
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    }

    pub fn get_int(&self, key: &str) -> i64 {
        self.get_str(key).parse().unwrap_or(0)
    }

    pub fn set(&mut self, key: &str, value: impl ToString) {
        let value = value.to_string();
        if let Some((_, existing)) = self.params.iter_mut().find(|(name, _)| name == key) {
            *existing = value;
        } else {
            self.params.push((key.to_string(), value));
        }
    }

    pub fn address(&self) -> (String, i64) {
        (self.get_str("address"), self.get_int("port"))
    }

    pub fn is_public(&self) -> bool {
        self.get_int("type") & 2 != 0
    }

    pub fn is_behind_nat(&self) -> bool {
        self.get_int("type") & 1 != 0
    }

    pub fn is_global(&self) -> bool {
        self.is_public() && !self.is_behind_nat()
    }
}

impl fmt::Display for StationURL {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let params = self
            .params
            .iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect::<Vec<_>>()
            .join(";");

        if self.scheme.is_empty() {
            write!(f, "{}", params)
        } else {
            write!(f, "{}:/{}", self.scheme, params)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_success_and_error() {
        let success = Result::success();
        assert!(success.is_success());
        assert_eq!(success.code(), 0x00010001);
        assert_eq!(success.name(), "success");
        assert_eq!(success.to_string(), "success (0x00010001)");

        let error = Result::error_named("Core::NotImplemented").unwrap();
        assert!(error.is_error());
        assert_eq!(error.code(), 0x80010002);
        assert_eq!(error.name(), "Core::NotImplemented");
        assert!(error.into_result().is_err());
    }

    #[test]
    fn unknown_error_has_a_placeholder_name() {
        let result = Result::error_code(0x7FFF0001);
        assert_eq!(result.name(), "unknown error");
    }

    #[test]
    fn datetime_components() {
        let datetime = DateTime::make(2020, 6, 15, 12, 34, 56);
        assert_eq!(datetime.year(), 2020);
        assert_eq!(datetime.month(), 6);
        assert_eq!(datetime.day(), 15);
        assert_eq!(datetime.hour(), 12);
        assert_eq!(datetime.minute(), 34);
        assert_eq!(datetime.second(), 56);
        assert_eq!(DateTime::never().value(), 0);
        assert_eq!(DateTime::future().year(), 9999);
    }

    #[test]
    fn datetime_unix_roundtrip() {
        assert_eq!(
            DateTime::from_unix_timestamp(0).value(),
            DateTime::make(1970, 1, 1, 0, 0, 0).value()
        );
        assert_eq!(DateTime::make(1970, 1, 1, 0, 0, 0).timestamp(), 0);
        assert_eq!(
            DateTime::make(2021, 3, 4, 5, 6, 7).timestamp(),
            DateTime::from_unix_timestamp(1_614_834_367).timestamp()
        );
    }

    #[test]
    fn station_url_roundtrip() {
        let url = StationURL::parse("prudps:/PID=1;CID=100");
        assert_eq!(url.scheme(), "prudps");
        assert_eq!(url.get_int("PID"), 1);
        assert_eq!(url.get_int("CID"), 100);
        assert_eq!(url.to_string(), "prudps:/PID=1;CID=100");

        assert_eq!(StationURL::parse(""), StationURL::default());
        assert_eq!(StationURL::parse("").to_string(), "prudp:/");
        assert_eq!(StationURL::default().scheme(), "prudp");

        let mut url = StationURL::new("prudp");
        url.set("address", "127.0.0.1");
        url.set("port", 12345);
        url.set("type", 2);
        assert_eq!(url.address(), ("127.0.0.1".to_string(), 12345));
        assert!(url.is_public());
        assert!(!url.is_behind_nat());
        assert!(url.is_global());
        assert_eq!(
            url.to_string(),
            "prudp:/address=127.0.0.1;port=12345;type=2"
        );
    }

    #[test]
    fn result_range_encoding() {
        let settings = crate::nex::settings::Settings::default();
        let mut stream = StreamOut::new(&settings);
        stream.add(&ResultRange::default()).unwrap();
        assert_eq!(stream.into_bytes(), b"\x00\x00\x00\x00\x0a\x00\x00\x00");
    }

    #[test]
    fn struct_header_encoding() {
        let settings = crate::nex::settings::Settings {
            struct_header: true,
            ..crate::nex::settings::Settings::default()
        };

        let mut stream = StreamOut::new(&settings);
        stream.add(&ResultRange::default()).unwrap();
        assert_eq!(
            stream.into_bytes(),
            b"\x00\x08\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00"
        );

        let data = b"\x00\x08\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00";
        let mut stream = StreamIn::new(&settings, data);
        let range: ResultRange = stream.extract().unwrap();
        assert_eq!(range, ResultRange::default());
        assert!(stream.eof());
    }
}

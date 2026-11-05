//! NEX serialization.
//!
//! Ported from `nintendo/nex/streams.py`.

use std::fmt;

use crate::nex::common::{DateTime, Result as NexResult, StationURL, Structure};
use crate::nex::settings::Settings;

/// Error returned while reading or writing a NEX stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    /// The stream ended before the value could be read.
    UnexpectedEof,
    /// A length prefix did not fit in its field.
    LengthTooLarge,
    /// A string was not valid UTF-8.
    InvalidUtf8,
    /// A non-empty string was not null-terminated.
    MissingNullTerminator,
    /// A variant used an unknown type id.
    InvalidVariant(u8),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamError::UnexpectedEof => write!(f, "unexpected end of stream"),
            StreamError::LengthTooLarge => write!(f, "length does not fit in the length prefix"),
            StreamError::InvalidUtf8 => write!(f, "string is not valid UTF-8"),
            StreamError::MissingNullTerminator => write!(f, "string is not null-terminated"),
            StreamError::InvalidVariant(id) => write!(f, "variant has invalid type id {}", id),
        }
    }
}

impl std::error::Error for StreamError {}

/// A NEX variant value.
#[derive(Debug, Clone, PartialEq)]
pub enum Variant {
    None,
    Int(i64),
    Double(f64),
    Bool(bool),
    String(Option<String>),
    DateTime(DateTime),
    UInt(u64),
}

/// Writes NEX values to a byte buffer.
pub struct StreamOut<'a> {
    settings: &'a Settings,
    data: Vec<u8>,
}

impl<'a> StreamOut<'a> {
    pub fn new(settings: &'a Settings) -> Self {
        StreamOut {
            settings,
            data: Vec::new(),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the settings that are used to encode the stream.
    pub fn settings(&self) -> &'a Settings {
        self.settings
    }

    pub fn write(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    /// Overwrites a previously written 32-bit value, for length placeholders.
    pub fn set_u32(&mut self, offset: usize, value: u32) {
        self.data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    pub fn u8(&mut self, value: u8) {
        self.data.push(value);
    }

    pub fn u16(&mut self, value: u16) {
        self.data.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.data.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.data.extend_from_slice(&value.to_le_bytes());
    }

    pub fn s8(&mut self, value: i8) {
        self.u8(value as u8);
    }

    pub fn s16(&mut self, value: i16) {
        self.u16(value as u16);
    }

    pub fn s32(&mut self, value: i32) {
        self.u32(value as u32);
    }

    pub fn s64(&mut self, value: i64) {
        self.u64(value as u64);
    }

    pub fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub fn f32(&mut self, value: f32) {
        self.u32(value.to_bits());
    }

    pub fn f64(&mut self, value: f64) {
        self.u64(value.to_bits());
    }

    /// Writes a user id using the width from the settings.
    pub fn pid(&mut self, value: u64) {
        if self.settings.pid_size == 8 {
            self.u64(value);
        } else {
            self.u32(value as u32);
        }
    }

    /// Writes an RMC result.
    pub fn result(&mut self, result: NexResult) {
        self.u32(result.code());
    }

    /// Writes a `buffer`: a 32-bit length followed by the data.
    pub fn buffer(&mut self, data: &[u8]) -> Result<(), StreamError> {
        let length = u32::try_from(data.len()).map_err(|_| StreamError::LengthTooLarge)?;
        self.u32(length);
        self.write(data);
        Ok(())
    }

    /// Writes a `qbuffer`: a 16-bit length followed by the data.
    pub fn qbuffer(&mut self, data: &[u8]) -> Result<(), StreamError> {
        let length = u16::try_from(data.len()).map_err(|_| StreamError::LengthTooLarge)?;
        self.u16(length);
        self.write(data);
        Ok(())
    }

    /// Writes a null-terminated string with a 16-bit length prefix.
    pub fn string(&mut self, value: &str) -> Result<(), StreamError> {
        let length = u16::try_from(value.len() + 1).map_err(|_| StreamError::LengthTooLarge)?;
        self.u16(length);
        self.write(value.as_bytes());
        self.u8(0);
        Ok(())
    }

    /// Writes `None` as an empty string, matching the Python reference.
    pub fn string_opt(&mut self, value: Option<&str>) -> Result<(), StreamError> {
        match value {
            Some(value) => self.string(value),
            None => {
                self.u16(0);
                Ok(())
            }
        }
    }

    /// Writes a station URL.
    pub fn stationurl(&mut self, url: &StationURL) -> Result<(), StreamError> {
        self.string(&url.to_string())
    }

    /// Writes a date/time.
    pub fn datetime(&mut self, datetime: DateTime) {
        self.u64(datetime.value());
    }

    /// Writes a list: a 32-bit count followed by the elements.
    pub fn list<T>(
        &mut self,
        values: &[T],
        mut write: impl FnMut(&mut Self, &T) -> Result<(), StreamError>,
    ) -> Result<(), StreamError> {
        let length = u32::try_from(values.len()).map_err(|_| StreamError::LengthTooLarge)?;
        self.u32(length);
        for value in values {
            write(self, value)?;
        }
        Ok(())
    }

    /// Writes a map: a 32-bit count followed by key/value pairs.
    pub fn map<'b, K: 'b, V: 'b, I>(
        &mut self,
        values: I,
        mut write_key: impl FnMut(&mut Self, &K) -> Result<(), StreamError>,
        mut write_value: impl FnMut(&mut Self, &V) -> Result<(), StreamError>,
    ) -> Result<(), StreamError>
    where
        I: IntoIterator<Item = (&'b K, &'b V)>,
    {
        let values = values.into_iter().collect::<Vec<_>>();
        let length = u32::try_from(values.len()).map_err(|_| StreamError::LengthTooLarge)?;
        self.u32(length);
        for (key, value) in values {
            write_key(self, key)?;
            write_value(self, value)?;
        }
        Ok(())
    }

    /// Writes a structure, including its struct header when enabled.
    pub fn add<T: Structure>(&mut self, value: &T) -> Result<(), StreamError> {
        if !self.settings.struct_header {
            return value.save(self, 0);
        }

        let checkpoint = self.data.len();
        if T::IS_DATA {
            self.u8(0);
            self.buffer(&[])?;
        }

        self.u8(T::MAX_VERSION);
        let length_offset = self.data.len();
        self.u32(0);
        let body_offset = self.data.len();

        if let Err(error) = value.save(self, T::MAX_VERSION) {
            self.data.truncate(checkpoint);
            return Err(error);
        }

        let length = match u32::try_from(self.data.len() - body_offset) {
            Ok(length) => length,
            Err(_) => {
                self.data.truncate(checkpoint);
                return Err(StreamError::LengthTooLarge);
            }
        };
        self.set_u32(length_offset, length);
        Ok(())
    }

    /// Writes a variant value.
    pub fn variant(&mut self, value: &Variant) -> Result<(), StreamError> {
        match value {
            Variant::None => self.u8(0),
            Variant::Int(value) => {
                self.u8(1);
                self.s64(*value);
            }
            Variant::Double(value) => {
                self.u8(2);
                self.f64(*value);
            }
            Variant::Bool(value) => {
                self.u8(3);
                self.bool(*value);
            }
            Variant::String(value) => {
                self.u8(4);
                self.string_opt(value.as_deref())?;
            }
            Variant::DateTime(value) => {
                self.u8(5);
                self.datetime(*value);
            }
            Variant::UInt(value) => {
                self.u8(6);
                self.u64(*value);
            }
        }
        Ok(())
    }
}

/// Reads NEX values from a byte slice.
pub struct StreamIn<'a> {
    settings: &'a Settings,
    data: &'a [u8],
    position: usize,
}

impl<'a> StreamIn<'a> {
    pub fn new(settings: &'a Settings, data: &'a [u8]) -> Self {
        StreamIn {
            settings,
            data,
            position: 0,
        }
    }

    pub fn eof(&self) -> bool {
        self.position >= self.data.len()
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.position
    }

    /// Returns the complete underlying buffer.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Returns the settings that are used to decode the stream.
    pub fn settings(&self) -> &'a Settings {
        self.settings
    }

    pub fn read(&mut self, length: usize) -> Result<&'a [u8], StreamError> {
        if length > self.remaining() {
            return Err(StreamError::UnexpectedEof);
        }
        let start = self.position;
        self.position += length;
        Ok(&self.data[start..self.position])
    }

    pub fn u8(&mut self) -> Result<u8, StreamError> {
        Ok(self.read(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, StreamError> {
        let bytes: [u8; 2] = self.read(2)?.try_into().expect("slice has length 2");
        Ok(u16::from_le_bytes(bytes))
    }

    pub fn u32(&mut self) -> Result<u32, StreamError> {
        let bytes: [u8; 4] = self.read(4)?.try_into().expect("slice has length 4");
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn u64(&mut self) -> Result<u64, StreamError> {
        let bytes: [u8; 8] = self.read(8)?.try_into().expect("slice has length 8");
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn s8(&mut self) -> Result<i8, StreamError> {
        Ok(self.u8()? as i8)
    }

    pub fn s16(&mut self) -> Result<i16, StreamError> {
        Ok(self.u16()? as i16)
    }

    pub fn s32(&mut self) -> Result<i32, StreamError> {
        Ok(self.u32()? as i32)
    }

    pub fn s64(&mut self) -> Result<i64, StreamError> {
        Ok(self.u64()? as i64)
    }

    pub fn bool(&mut self) -> Result<bool, StreamError> {
        Ok(self.u8()? != 0)
    }

    pub fn f32(&mut self) -> Result<f32, StreamError> {
        Ok(f32::from_bits(self.u32()?))
    }

    pub fn f64(&mut self) -> Result<f64, StreamError> {
        Ok(f64::from_bits(self.u64()?))
    }

    /// Reads a user id using the width from the settings.
    pub fn pid(&mut self) -> Result<u64, StreamError> {
        if self.settings.pid_size == 8 {
            self.u64()
        } else {
            Ok(u64::from(self.u32()?))
        }
    }

    /// Reads an RMC result.
    pub fn result(&mut self) -> Result<NexResult, StreamError> {
        Ok(NexResult::from_code(self.u32()?))
    }

    /// Reads a `buffer`: a 32-bit length followed by the data.
    pub fn buffer(&mut self) -> Result<&'a [u8], StreamError> {
        let length = self.u32()? as usize;
        self.read(length)
    }

    /// Reads a `qbuffer`: a 16-bit length followed by the data.
    pub fn qbuffer(&mut self) -> Result<&'a [u8], StreamError> {
        let length = self.u16()? as usize;
        self.read(length)
    }

    /// Reads a null-terminated string, returning `None` for an empty string.
    pub fn string(&mut self) -> Result<Option<String>, StreamError> {
        let length = self.u16()? as usize;
        if length == 0 {
            return Ok(None);
        }

        let data = self.read(length)?;
        let (terminator, text) = data.split_last().expect("length is non-zero");
        if *terminator != 0 {
            return Err(StreamError::MissingNullTerminator);
        }

        let text = std::str::from_utf8(text).map_err(|_| StreamError::InvalidUtf8)?;
        Ok(Some(text.to_string()))
    }

    /// Reads a station URL.
    pub fn stationurl(&mut self) -> Result<StationURL, StreamError> {
        Ok(StationURL::parse(&self.string()?.unwrap_or_default()))
    }

    /// Reads a date/time.
    pub fn datetime(&mut self) -> Result<DateTime, StreamError> {
        Ok(DateTime::new(self.u64()?))
    }

    /// Reads a list: a 32-bit count followed by the elements.
    pub fn list<T>(
        &mut self,
        mut read: impl FnMut(&mut Self) -> Result<T, StreamError>,
    ) -> Result<Vec<T>, StreamError> {
        let count = self.u32()?;
        self.repeat(count, &mut read)
    }

    /// Reads a map: a 32-bit count followed by key/value pairs.
    pub fn map<K, V>(
        &mut self,
        mut read_key: impl FnMut(&mut Self) -> Result<K, StreamError>,
        mut read_value: impl FnMut(&mut Self) -> Result<V, StreamError>,
    ) -> Result<Vec<(K, V)>, StreamError> {
        let count = self.u32()?;
        let mut values = Vec::with_capacity(count.min(1024) as usize);
        for _ in 0..count {
            let key = read_key(self)?;
            let value = read_value(self)?;
            values.push((key, value));
        }
        Ok(values)
    }

    /// Reads `count` values with the given callback.
    pub fn repeat<T>(
        &mut self,
        count: u32,
        mut read: impl FnMut(&mut Self) -> Result<T, StreamError>,
    ) -> Result<Vec<T>, StreamError> {
        let mut values = Vec::with_capacity(count.min(1024) as usize);
        for _ in 0..count {
            values.push(read(self)?);
        }
        Ok(values)
    }

    /// Reads a substream: a `buffer` whose contents are read independently.
    pub fn substream(&mut self) -> Result<StreamIn<'a>, StreamError> {
        let data = self.buffer()?;
        Ok(StreamIn::new(self.settings, data))
    }

    /// Reads everything that is left.
    pub fn read_all(&mut self) -> Result<&'a [u8], StreamError> {
        self.read(self.remaining())
    }

    /// Reads a structure, including its struct header when enabled.
    pub fn extract<T: Structure + Default>(&mut self) -> Result<T, StreamError> {
        let mut value = T::default();
        if self.settings.struct_header {
            if T::IS_DATA {
                let _version = self.u8()?;
                let _substream = self.substream()?;
            }

            let version = self.u8()?;
            let mut substream = self.substream()?;
            value.load(&mut substream, version)?;
        } else {
            value.load(self, 0)?;
        }
        Ok(value)
    }

    /// Reads a variant value.
    pub fn variant(&mut self) -> Result<Variant, StreamError> {
        match self.u8()? {
            0 => Ok(Variant::None),
            1 => Ok(Variant::Int(self.s64()?)),
            2 => Ok(Variant::Double(self.f64()?)),
            3 => Ok(Variant::Bool(self.bool()?)),
            4 => Ok(Variant::String(self.string()?)),
            5 => Ok(Variant::DateTime(self.datetime()?)),
            6 => Ok(Variant::UInt(self.u64()?)),
            id => Err(StreamError::InvalidVariant(id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_uses_four_bytes_by_default() {
        let settings = Settings::default();
        let mut stream = StreamOut::new(&settings);
        stream.pid(12345);
        assert_eq!(stream.into_bytes(), b"\x39\x30\x00\x00");
    }

    #[test]
    fn pid_uses_eight_bytes_when_configured() {
        let settings = Settings {
            pid_size: 8,
            ..Settings::default()
        };

        let mut stream = StreamOut::new(&settings);
        stream.pid(12345);
        assert_eq!(stream.into_bytes(), b"\x39\x30\x00\x00\x00\x00\x00\x00");
    }

    #[test]
    fn string_matches_reference() {
        let settings = Settings::default();
        let mut stream = StreamOut::new(&settings);
        stream.string("test string").unwrap();
        assert_eq!(stream.into_bytes(), b"\x0c\x00test string\x00");
    }

    #[test]
    fn buffer_matches_reference() {
        let settings = Settings::default();
        let mut stream = StreamOut::new(&settings);
        stream.buffer(b"test buffer").unwrap();
        assert_eq!(stream.into_bytes(), b"\x0b\x00\x00\x00test buffer");
    }

    #[test]
    fn qbuffer_matches_reference() {
        let settings = Settings::default();
        let mut stream = StreamOut::new(&settings);
        stream.qbuffer(b"test qbuffer").unwrap();
        assert_eq!(stream.into_bytes(), b"\x0c\x00test qbuffer");
    }

    #[test]
    fn list_matches_reference() {
        let settings = Settings::default();
        let mut stream = StreamOut::new(&settings);
        stream
            .list(&[1u8, 2, 3, 4], |stream, value| {
                stream.u8(*value);
                Ok(())
            })
            .unwrap();
        assert_eq!(stream.into_bytes(), b"\x04\x00\x00\x00\x01\x02\x03\x04");
    }

    #[test]
    fn map_matches_reference() {
        let settings = Settings::default();
        let mut stream = StreamOut::new(&settings);
        stream
            .map(
                [(1u8, 10u16), (2, 11)].iter().map(|(k, v)| (k, v)),
                |stream, key| {
                    stream.u8(*key);
                    Ok(())
                },
                |stream, value| {
                    stream.u16(*value);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(
            stream.into_bytes(),
            b"\x02\x00\x00\x00\x01\x0a\x00\x02\x0b\x00"
        );
    }

    #[test]
    fn datetime_matches_reference() {
        let settings = Settings::default();
        let mut stream = StreamOut::new(&settings);
        stream.datetime(DateTime::new(135605968896));
        assert_eq!(stream.into_bytes(), b"\x00\xe0\xbe\x92\x1f\x00\x00\x00");
    }

    #[test]
    fn stationurl_matches_reference() {
        let settings = Settings::default();
        let mut url = StationURL::new("prudps");
        url.set("PID", 1);
        url.set("CID", 100);

        let mut stream = StreamOut::new(&settings);
        stream.stationurl(&url).unwrap();
        assert_eq!(stream.into_bytes(), b"\x16\x00prudps:/PID=1;CID=100\x00");
    }

    #[test]
    fn result_matches_reference() {
        let settings = Settings::default();
        let mut stream = StreamOut::new(&settings);
        stream.result(NexResult::success());
        assert_eq!(stream.into_bytes(), b"\x01\x00\x01\x00");
    }

    #[test]
    fn roundtrip_primitives() {
        let settings = Settings::load("friends").unwrap();
        let mut out = StreamOut::new(&settings);
        out.u8(1);
        out.u16(2);
        out.u32(3);
        out.u64(4);
        out.s8(-1);
        out.s16(-2);
        out.s32(-3);
        out.s64(-4);
        out.bool(true);
        out.f32(1.5);
        out.f64(-2.5);
        out.pid(1000);
        out.result(NexResult::success());
        out.string("hello").unwrap();
        out.qbuffer(b"raw").unwrap();

        let data = out.into_bytes();
        let mut input = StreamIn::new(&settings, &data);
        assert_eq!(input.u8().unwrap(), 1);
        assert_eq!(input.u16().unwrap(), 2);
        assert_eq!(input.u32().unwrap(), 3);
        assert_eq!(input.u64().unwrap(), 4);
        assert_eq!(input.s8().unwrap(), -1);
        assert_eq!(input.s16().unwrap(), -2);
        assert_eq!(input.s32().unwrap(), -3);
        assert_eq!(input.s64().unwrap(), -4);
        assert!(input.bool().unwrap());
        assert_eq!(input.f32().unwrap(), 1.5);
        assert_eq!(input.f64().unwrap(), -2.5);
        assert_eq!(input.pid().unwrap(), 1000);
        assert_eq!(input.result().unwrap(), NexResult::success());
        assert_eq!(input.string().unwrap().as_deref(), Some("hello"));
        assert_eq!(input.qbuffer().unwrap(), b"raw");
        assert!(input.eof());
    }

    #[test]
    fn roundtrip_lists_and_maps() {
        let settings = Settings::default();

        let mut out = StreamOut::new(&settings);
        out.list(&[1u16, 2, 3], |stream, value| {
            stream.u16(*value);
            Ok(())
        })
        .unwrap();
        let data = out.into_bytes();
        let mut input = StreamIn::new(&settings, &data);
        assert_eq!(input.list(|stream| stream.u16()).unwrap(), vec![1, 2, 3]);
        assert!(input.eof());

        let mut out = StreamOut::new(&settings);
        out.map(
            [(1u8, "one"), (2, "two")].iter().map(|(k, v)| (k, v)),
            |stream, key| {
                stream.u8(*key);
                Ok(())
            },
            |stream, value| stream.string(value),
        )
        .unwrap();
        let data = out.into_bytes();
        let mut input = StreamIn::new(&settings, &data);
        let entries = input
            .map(|stream| stream.u8(), |stream| stream.string())
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (1, Some("one".to_string())));
        assert_eq!(entries[1], (2, Some("two".to_string())));
    }

    #[test]
    fn roundtrip_variants() {
        let settings = Settings::default();
        let values = [
            Variant::None,
            Variant::Int(-12345),
            Variant::Double(123.45),
            Variant::Bool(true),
            Variant::String(Some("hello".to_string())),
            Variant::DateTime(DateTime::never()),
            Variant::UInt(12345),
        ];

        let mut out = StreamOut::new(&settings);
        for value in &values {
            out.variant(value).unwrap();
        }

        let data = out.into_bytes();
        let mut input = StreamIn::new(&settings, &data);
        for value in &values {
            assert_eq!(&input.variant().unwrap(), value);
        }
        assert!(input.eof());
    }

    #[test]
    fn variant_matches_reference() {
        let settings = Settings::default();
        let mut stream = StreamOut::new(&settings);
        stream.variant(&Variant::Int(-12345)).unwrap();
        assert_eq!(stream.into_bytes(), b"\x01\xc7\xcf\xff\xff\xff\xff\xff\xff");

        let mut stream = StreamOut::new(&settings);
        stream
            .variant(&Variant::String(Some("hello".to_string())))
            .unwrap();
        assert_eq!(stream.into_bytes(), b"\x04\x06\x00hello\x00");
    }

    #[test]
    fn invalid_variant_is_an_error() {
        let settings = Settings::default();
        let mut input = StreamIn::new(&settings, b"\x07");
        assert_eq!(input.variant(), Err(StreamError::InvalidVariant(7)));
    }

    #[test]
    fn empty_string_is_none() {
        let settings = Settings::default();
        let mut out = StreamOut::new(&settings);
        out.string_opt(None).unwrap();
        assert_eq!(out.as_bytes(), b"\x00\x00");

        let data = out.into_bytes();
        let mut input = StreamIn::new(&settings, &data);
        assert_eq!(input.string().unwrap(), None);
        assert!(input.eof());
    }

    #[test]
    fn truncated_input_is_an_error() {
        let settings = Settings::default();
        let mut input = StreamIn::new(&settings, b"\x01");
        assert_eq!(input.u32(), Err(StreamError::UnexpectedEof));
    }

    #[test]
    fn non_terminated_string_is_an_error() {
        let settings = Settings::default();
        let mut input = StreamIn::new(&settings, b"\x02\x00ab");
        assert_eq!(input.string(), Err(StreamError::MissingNullTerminator));
    }
}

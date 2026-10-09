//! Settings wire-format boundary, without transport or allocation.
use super::*;

/// Codec failure before any device I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// Response is incomplete or not this codec's format.
    Malformed,
    /// This codec has no established encoding for this operation.
    Unsupported,
    /// Request exceeds the bounded transport buffers.
    InvalidRequest,
}
/// A bounded wire command. Codecs own all command bytes and payload formats.
#[derive(Clone, Debug)]
pub struct Command {
    cdb: [u8; 16],
    cdb_len: usize,
    data: [u8; 256],
    data_len: usize,
    response_len: usize,
}
impl Command {
    /// Construct a no-data command; CDB length must be 1 through 16.
    pub fn new(cdb: &[u8]) -> Result<Self, CodecError> {
        if cdb.is_empty() || cdb.len() > 16 {
            return Err(CodecError::InvalidRequest);
        }
        let mut cmd = Self {
            cdb: [0; 16],
            cdb_len: cdb.len(),
            data: [0; 256],
            data_len: 0,
            response_len: 0,
        };
        cmd.cdb[..cdb.len()].copy_from_slice(cdb);
        Ok(cmd)
    }
    /// Construct a read command with a response bounded at 4096 bytes.
    pub fn read(cdb: &[u8], length: usize) -> Result<Self, CodecError> {
        if length == 0 || length > 4096 {
            return Err(CodecError::InvalidRequest);
        }
        let mut cmd = Self::new(cdb)?;
        cmd.response_len = length;
        Ok(cmd)
    }
    /// Construct a write command with at most 256 payload bytes.
    pub fn write(cdb: &[u8], payload: &[u8]) -> Result<Self, CodecError> {
        if payload.len() > 256 {
            return Err(CodecError::InvalidRequest);
        }
        let mut cmd = Self::new(cdb)?;
        cmd.data[..payload.len()].copy_from_slice(payload);
        cmd.data_len = payload.len();
        Ok(cmd)
    }
    /// Encoded command bytes.
    pub fn cdb(&self) -> &[u8] {
        &self.cdb[..self.cdb_len]
    }
    /// Encoded outgoing data; empty for no-data commands.
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
    /// Requested incoming byte count, zero for commands without incoming data.
    pub fn response_len(&self) -> usize {
        self.response_len
    }
}
/// Per-format settings decoder and command encoder. Implementations must not do I/O.
/// Envelope codecs do not imply a settings format: select using protocol evidence.
pub trait Codec {
    /// Read-only command used to obtain this format's settings response.
    fn query(&self) -> Result<Command, CodecError>;
    /// Normalize this format without inventing absent capability declarations.
    fn decode(&self, response: &[u8]) -> Result<Settings, CodecError>;
    /// Describe only controls with implemented write encodings; default is read-only.
    fn controls(&self, _settings: &Settings) -> Controls {
        Controls::default()
    }
    /// Encode Quiet Drive; default refuses unestablished writes.
    fn quiet_write(
        &self,
        _mode: QuietMode,
        _persistence: Persistence,
    ) -> Result<Command, CodecError> {
        Err(CodecError::Unsupported)
    }
    /// Encode PureRead; default refuses unestablished writes.
    fn pure_read_write(
        &self,
        _value: PureReadValue,
        _persistence: Persistence,
    ) -> Result<Command, CodecError> {
        Err(CodecError::Unsupported)
    }
}

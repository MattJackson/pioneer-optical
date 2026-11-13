//! Transport-independent settings codecs and normalized firmware-reported state.
mod codec {
    //! Settings wire-format boundary, without transport or allocation.
    use super::*;

    /// Codec failure before any device I/O.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
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
}
mod f4;
mod schema;
pub use codec::{Codec, CodecError, Command};
pub use f4::{F4Response, VendorF4};
pub use schema::{Control, Controls, Entry, PersistenceOptions, SettingId, Value};

/// Evidence supplied by the current firmware, not a model catalogue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Support {
    /// Explicit positive capability flag.
    Supported,
    /// Explicit negative capability flag.
    Unsupported,
    /// No recognized capability declaration.
    Unknown,
}
fn support(b: u8) -> Support {
    match b {
        0 => Support::Unsupported,
        1 => Support::Supported,
        _ => Support::Unknown,
    }
}
/// A feature's state exists only when the firmware declares support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability<T> {
    /// Supported feature and its state.
    Supported(T),
    /// Explicitly absent; child fields have no meaning.
    Unsupported,
    /// Firmware does not establish support.
    Unknown,
}
impl<T> Capability<T> {
    /// Borrow a supported feature's details.
    pub fn supported(&self) -> Option<&T> {
        match self {
            Self::Supported(v) => Some(v),
            _ => None,
        }
    }
}
/// Preserve undocumented values without making them legal setter inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed<V> {
    /// A decoded value.
    Known(V),
    /// Undocumented wire value.
    Unknown(u8),
    /// Firmware supplies the unavailable sentinel.
    NotReported,
}
/// Where a vendor setting should be applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Persistence {
    /// Runtime only; never falls back to nonvolatile storage.
    Volatile,
    /// Ask firmware to retain this setting across power cycles.
    Saved,
}
/// Region changes are inherently persistent and may consume a change count.
#[derive(Clone, Copy, Debug)]
pub struct Persistent;
/// Quiet Drive mode. Persistent quiet is a mode, independent of EEPROM saving.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum QuietMode {
    /// Standard drive behavior.
    Standard = 0,
    /// Performance priority.
    Performance = 1,
    /// Quiet priority.
    Quiet = 2,
    /// Maintain quiet operation.
    PersistentQuiet = 3,
}
/// PureRead mode; Standard disables PureRead processing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PureReadMode {
    /// Normal audio reading.
    Standard,
    /// PureRead master mode.
    Master,
    /// PureRead perfect mode.
    Perfect,
}
/// Complete PureRead write value; no hidden changes to real-time processing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PureReadValue {
    /// Requested reading mode.
    pub mode: PureReadMode,
    /// Real-time PureRead; requires its own positive support flag.
    pub real_time: bool,
}
/// Quiet mode and the independently advertised ability to change it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuietState {
    /// Current mode; does not imply write support.
    pub current: Observed<QuietMode>,
    /// Saved startup mode reported in F4 byte 3, independently of the live mode.
    pub saved: Observed<QuietMode>,
    /// Firmware-declared ability to select a mode.
    pub writable: Support,
}
/// PureRead state and per-feature capability evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PureReadState {
    /// Current processing mode.
    pub current: Observed<PureReadMode>,
    /// Real-time extension and its state, only when supported.
    pub real_time: Capability<Observed<bool>>,
    /// Reported version; zero/FF are not a usable version.
    pub version: Option<u8>,
}
/// Normalized settings, independent of command and response layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Active/saved Quiet Drive state and control support.
    pub quiet: QuietState,
    /// PureRead, including only applicable child fields.
    pub pure: Capability<PureReadState>,
    /// Control schema supplied by the selected protocol codec.
    pub controls: Controls,
}
impl Settings {
    /// Attach the selected codec's control schema to normalized state.
    pub fn with_controls(mut self, codec: &dyn Codec) -> Self {
        self.controls = codec.controls(&self);
        self
    }
    /// Quiet Drive state.
    pub fn quiet_drive(&self) -> QuietState {
        self.quiet
    }
    /// PureRead state.
    pub fn pure_read(&self) -> Capability<PureReadState> {
        self.pure
    }
}
impl QuietMode {
    /// Defined protocol modes, not a per-drive support declaration.
    pub const ALL: [Self; 4] = [
        Self::Standard,
        Self::Performance,
        Self::Quiet,
        Self::PersistentQuiet,
    ];
}
impl PureReadMode {
    /// Defined protocol modes, not a per-drive support declaration.
    pub const ALL: [Self; 3] = [Self::Standard, Self::Master, Self::Perfect];
}

/// Firmware-bound settings included in a prepared OEM update.
#[cfg(feature = "envelope")]
pub mod update;

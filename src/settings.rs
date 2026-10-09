//! Transport-independent settings codecs and normalized firmware-reported state.
mod codec;
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

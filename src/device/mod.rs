//! Typed, allocation-free live queries. No model allowlists or implicit writes.
//!
//! `Device` borrows a transport; snapshots retain independent query failures.
//! Vendor fields come from the firmware's F4 response, not product-name guesses.
use crate::drive::{Data, Transport};

pub mod info;
pub mod settings;
pub use settings::{DvdRegion, Persistence, PureRead, QuietDrive};

/// A query failure, retaining the transport error and reported sense.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error<E> {
    /// The command failed; an invalid field is not assumed to mean unsupported.
    Transport {
        /// Original transport error.
        source: E,
        /// Device sense, if available.
        sense: Option<(u8, u8, u8)>,
    },
    /// The protocol explicitly reports no support.
    Unsupported,
    /// The response does not establish a value or capability.
    NotReported,
    /// A response was truncated or structurally invalid.
    Malformed,
    /// The requested value or persistence is unavailable.
    InvalidValue,
    /// Region changes are exhausted or the drive is permanently locked.
    RegionLocked,
}
impl<E: core::fmt::Debug> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport { source, sense } => {
                write!(f, "command failed: {source:?} (sense {sense:?})")
            }
            Self::Unsupported => f.write_str("Unsupported"),
            Self::NotReported => f.write_str("Not reported"),
            Self::Malformed => f.write_str("Invalid or incomplete response"),
            Self::InvalidValue => f.write_str("Unsupported value or persistence"),
            Self::RegionLocked => f.write_str("DVD region changes unavailable"),
        }
    }
}
#[cfg(feature = "std")]
impl<E: core::fmt::Debug> std::error::Error for Error<E> {}

/// Read a typed value without changing the drive.
pub trait Readable {
    /// State returned by this query.
    type State;
    /// Execute this query.
    fn read<T: Transport>(
        &self,
        device: &mut Device<'_, T>,
    ) -> Result<Self::State, Error<T::Error>>;
}
/// A setting with a proven write encoding, distinct from informational queries.
pub trait Writable: Readable {
    /// Accepted input; unknown read values are intentionally not writable.
    type Value;
    /// Persistence options specific to this setting.
    type Policy;
    /// Validate, issue one write and verify by reading back.
    fn write<T: Transport>(
        &self,
        device: &mut Device<'_, T>,
        value: Self::Value,
        policy: Self::Policy,
    ) -> SetResult<Self::State, T::Error>;
}
/// Result of validating a write, with accepted writes carrying verification separately.
pub type SetResult<S, E> = Result<WriteOutcome<S, E>, Error<E>>;

/// A write was accepted, with a separate readback outcome. Never retry blindly.
#[derive(Debug)]
pub enum WriteOutcome<S, E> {
    /// Live state agrees; this does not verify retention across a power cycle.
    Verified(S),
    /// Write accepted, but returned state differs.
    Mismatch(S),
    /// Write accepted; verification could not complete.
    Unverified(Error<E>),
    /// The requested state was already active; no command was sent.
    Unchanged(S),
}

/// Borrowed live device; construction performs no I/O.
pub struct Device<'a, T: Transport> {
    transport: &'a mut T,
    settings_codec: &'a dyn settings::Codec,
}
impl<'a, T: Transport> Device<'a, T> {
    /// Use an existing SCSI transport.
    pub fn new(transport: &'a mut T) -> Self {
        Self {
            transport,
            settings_codec: &settings::VendorF4,
        }
    }
    /// Select a settings protocol codec using established format evidence.
    /// The codec affects settings commands only, not MMC queries or firmware updates.
    pub fn with_settings_codec(transport: &'a mut T, codec: &'a dyn settings::Codec) -> Self {
        Self {
            transport,
            settings_codec: codec,
        }
    }
    /// Read identity, a setting, or another typed query.
    pub fn get<Q: Readable>(&mut self, query: Q) -> Result<Q::State, Error<T::Error>> {
        query.read(self)
    }
    /// Write a typed setting, with explicit persistence and live verification.
    pub fn set<Q: Writable>(
        &mut self,
        query: Q,
        value: Q::Value,
        policy: Q::Policy,
    ) -> SetResult<Q::State, T::Error> {
        query.write(self, value, policy)
    }
    /// Collect independent read-only results for presentation.
    pub fn snapshot(&mut self) -> Snapshot<T::Error> {
        Snapshot {
            information: self.info(),
            settings: self.settings(),
            dvd_region: self.get(DvdRegion),
        }
    }
    /// Standard and Pioneer identity plus MMC information; failures are per field.
    pub fn info(&mut self) -> info::Information<T::Error> {
        info::read(self)
    }
    /// Read the parameters response for [`crate::production::parse`].
    pub fn parameters(
        &mut self,
        b: &mut [u8; crate::production::PARAMETERS_LEN],
    ) -> Result<usize, Error<T::Error>> {
        self.read(&crate::production::parameters(), b)
    }
    /// Read the vendor block once for a consistent Quiet Drive/PureRead view.
    pub fn settings(&mut self) -> Result<settings::Settings, Error<T::Error>> {
        let command = self.settings_codec.query().map_err(codec_error)?;
        if command.response_len() == 0 || !command.payload().is_empty() {
            return Err(Error::InvalidValue);
        }
        let mut b = [0; 4096];
        let n = self.read(command.cdb(), &mut b[..command.response_len()])?;
        self.settings_codec
            .decode(&b[..n])
            .map(|s| s.with_controls(self.settings_codec))
            .map_err(codec_error)
    }
    pub(super) fn write_setting(
        &mut self,
        command: &settings::Command,
    ) -> Result<bool, Error<T::Error>> {
        if command.response_len() != 0 {
            return Err(Error::InvalidValue);
        }
        let data = if command.payload().is_empty() {
            Data::None
        } else {
            Data::Out(command.payload())
        };
        let n = self.exec(command.cdb(), data)?;
        Ok(n == command.payload().len())
    }

    pub(super) fn read(&mut self, cdb: &[u8], b: &mut [u8]) -> Result<usize, Error<T::Error>> {
        let limit = b.len();
        let n = self.exec(cdb, Data::In(b))?;
        if n > limit {
            return Err(Error::Malformed);
        }
        Ok(n)
    }
    pub(super) fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, Error<T::Error>> {
        self.transport
            .exec(cdb, data)
            .map_err(|source| Error::Transport {
                source,
                sense: self.transport.sense(),
            })
    }
}
/// Independent results: an unavailable settings command does not hide identity.
#[derive(Debug)]
pub struct Snapshot<E> {
    /// Static identity and reported media capabilities.
    pub information: info::Information<E>,
    /// Quiet Drive and PureRead state from one vendor response.
    pub settings: Result<settings::Settings, Error<E>>,
    /// Standard DVD RPC state and remaining counters.
    pub dvd_region: Result<crate::rpc::State, Error<E>>,
}

fn codec_error<E>(error: settings::CodecError) -> Error<E> {
    match error {
        settings::CodecError::Malformed => Error::Malformed,
        settings::CodecError::Unsupported => Error::Unsupported,
        settings::CodecError::InvalidRequest => Error::InvalidValue,
    }
}

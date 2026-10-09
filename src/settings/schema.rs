//! Stable settings descriptors for data-driven consumers.
use super::*;

/// Stable semantic identifiers shared by codecs and user interfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingId {
    /// Spindle/noise policy.
    QuietDrive,
    /// Audio extraction policy.
    PureRead,
    /// Real-time audio processing extension.
    RealTimePureRead,
}
/// Typed choice value, independent of any wire encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    /// Quiet Drive policy.
    Quiet(QuietMode),
    /// Audio extraction policy.
    PureRead(PureReadMode),
    /// Toggle value.
    Boolean(bool),
}
/// Persistence encodings established by the selected codec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PersistenceOptions {
    /// Runtime-only writes are available.
    pub volatile: bool,
    /// Nonvolatile writes are available.
    pub saved: bool,
}
impl PersistenceOptions {
    /// Whether a requested persistence policy has an established encoding.
    pub fn allows(self, policy: Persistence) -> bool {
        match policy {
            Persistence::Volatile => self.volatile,
            Persistence::Saved => self.saved,
        }
    }
}
/// Codec-provided control metadata. Default is read-only with no assumed choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control {
    /// Defined choices; not proof of per-choice availability on the hardware.
    pub choices: &'static [Value],
    /// Both firmware support and a codec write implementation are required.
    pub writable: Support,
    /// Explicit persistence encodings; never silently fall back.
    pub persistence: PersistenceOptions,
}
impl Default for Control {
    fn default() -> Self {
        Self {
            choices: &[],
            writable: Support::Unsupported,
            persistence: PersistenceOptions::default(),
        }
    }
}
/// Settings codec's complete UI/control description.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Controls {
    /// Quiet Drive control.
    pub quiet: Control,
    /// PureRead mode control.
    pub pure: Control,
    /// Real-time extension control.
    pub real_time: Control,
}
/// One renderable setting. Unsupported settings are omitted by `Settings::entries`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Stable identity, suitable for localization and dispatch.
    pub id: SettingId,
    /// Current value, preserving unknown wire values.
    pub current: Observed<Value>,
    /// Saved startup value, when independently reported.
    pub saved: Observed<Value>,
    /// Current codec's choices and editability.
    pub control: Control,
    /// Feature generation when reported (PureRead only).
    pub version: Option<u8>,
}
impl<V> Observed<V> {
    /// Transform a decoded value without losing unknown or absent state.
    pub fn map<U>(self, map: impl FnOnce(V) -> U) -> Observed<U> {
        match self {
            Self::Known(v) => Observed::Known(map(v)),
            Self::Unknown(v) => Observed::Unknown(v),
            Self::NotReported => Observed::NotReported,
        }
    }
}
impl Settings {
    /// Generate the settings view without model names or display-string parsing.
    pub fn entries(&self) -> impl Iterator<Item = Entry> {
        let quiet = if self.quiet.writable == Support::Unsupported
            && self.quiet.current == Observed::NotReported
            && self.quiet.saved == Observed::NotReported
        {
            None
        } else {
            Some(Entry {
                id: SettingId::QuietDrive,
                current: self.quiet.current.map(Value::Quiet),
                saved: self.quiet.saved.map(Value::Quiet),
                control: self.controls.quiet,
                version: None,
            })
        };
        let (pure, real_time) = match self.pure {
            Capability::Supported(p) => (
                Some(Entry {
                    id: SettingId::PureRead,
                    current: p.current.map(Value::PureRead),
                    saved: Observed::NotReported,
                    control: self.controls.pure,
                    version: p.version,
                }),
                match p.real_time {
                    Capability::Supported(v) => Some(Entry {
                        id: SettingId::RealTimePureRead,
                        current: v.map(Value::Boolean),
                        saved: Observed::NotReported,
                        control: self.controls.real_time,
                        version: None,
                    }),
                    Capability::Unknown => Some(Entry {
                        id: SettingId::RealTimePureRead,
                        current: Observed::NotReported,
                        saved: Observed::NotReported,
                        control: Control::default(),
                        version: None,
                    }),
                    Capability::Unsupported => None,
                },
            ),
            Capability::Unknown => (
                Some(Entry {
                    id: SettingId::PureRead,
                    current: Observed::NotReported,
                    saved: Observed::NotReported,
                    control: Control::default(),
                    version: None,
                }),
                None,
            ),
            Capability::Unsupported => (None, None),
        };
        [quiet, pure, real_time].into_iter().flatten()
    }
}

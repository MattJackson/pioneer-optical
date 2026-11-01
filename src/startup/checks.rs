//! One set of receiver startup requirements and one transition planner.
use super::{bank, Ambiguous, Analysis, Setting};

/// One typed startup requirement recovered from the receiver's components.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// Native word comparison evidence; unknown is distinct from erased FFFF.
    ParameterWord(Result<Analysis, Ambiguous>),
    /// Persistent storage contract; missing evidence is unresolved.
    PersistentBanks(Option<bank::Storage>),
}

/// All supported startup checks belonging to a receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checks {
    word: Result<Analysis, Ambiguous>,
    banks: Option<bank::Storage>,
}
impl Checks {
    /// Inspect decoded components without device I/O or selecting writes.
    pub fn discover(normal: &[u8], kernel: Option<&[u8]>) -> Self {
        Self {
            word: super::analyze(normal),
            banks: bank::analyze_pair(normal, kernel),
        }
    }
    /// Stable reporting order, shared by planning and catalogue consumers.
    pub fn iter(self) -> impl Iterator<Item = Check> {
        [
            Check::ParameterWord(self.word),
            Check::PersistentBanks(self.banks),
        ]
        .into_iter()
    }
    /// Resolve the complete startup transition. Bank format conversion has no
    /// implicit writer; native word changes retain the existing verified path.
    pub fn plan_to(self, target: Self) -> Result<Plan, Error> {
        let word = target.word.map_err(|_| Error::AmbiguousWord)?;
        bank::check(self.banks, target.banks).map_err(Error::Banks)?;
        let setting = match word {
            Analysis::Required(r) => Setting {
                parameter: r.parameter,
                value: r.required,
                explicit: true,
            },
            // Existing neutral-word policy, explicitly separate from evidence.
            Analysis::Unknown => Setting {
                parameter: 0x9f,
                value: 0xffff,
                explicit: false,
            },
        };
        Ok(Plan { target, setting })
    }
}

/// All startup checks resolved before any settings or firmware write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    target: Checks,
    setting: Setting,
}
impl Plan {
    /// Evidence and selected policy remain separate in the prepared plan.
    pub fn target_checks(self) -> Checks {
        self.target
    }
    /// Read/change/verify action for the existing native word transaction.
    pub fn word_setting(self) -> Setting {
        self.setting
    }
}

/// A startup requirement prevented preparing the complete set of checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The target has conflicting native word comparisons.
    AmbiguousWord,
    /// Persistent storage requirements are unresolved or need conversion.
    Banks(bank::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AmbiguousWord => f.write_str(
                "target startup word checks are ambiguous; no startup plan can be prepared",
            ),
            Self::Banks(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Banks(e) => Some(e),
            _ => None,
        }
    }
}
impl crate::CodedError for Error {
    fn code(&self) -> &'static str {
        match self {
            Self::AmbiguousWord => "pioneer.preparation.ambiguous_startup",
            Self::Banks(e) => e.code(),
        }
    }
}

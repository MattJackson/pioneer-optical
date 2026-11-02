//! One set of receiver startup requirements and one transition planner.
use super::{bank, Ambiguous, Analysis, Setting};

/// Caller-selected startup policy, retained in each prepared transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Ordinary updates require compatible persistent-bank contracts.
    CompatibleBanks,
    /// Explicit family override; persistent-bank compatibility is still required.
    ExplicitCrossflash,
}

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
        self.plan_to_with_policy(target, Policy::CompatibleBanks)
    }
    /// Resolve target word requirements under an explicit transition policy.
    pub fn plan_to_with_policy(self, target: Self, policy: Policy) -> Result<Plan, Error> {
        target.word.map_err(|_| Error::AmbiguousWord)?;
        bank::check(self.banks, target.banks).map_err(Error::Banks)?;
        self.plan_verified_bank_transition(target, policy)
    }

    /// Receiver-only entry after an independently bound native conversion plan.
    pub(crate) fn plan_verified_bank_transition(
        self,
        target: Self,
        policy: Policy,
    ) -> Result<Plan, Error> {
        let word = target.word.map_err(|_| Error::AmbiguousWord)?;
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
        Ok(Plan {
            target,
            setting,
            policy,
        })
    }
}

/// Startup evidence and selected word action retained before any write.
/// Explicit crossflash policy does not resolve differing bank contracts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    target: Checks,
    setting: Setting,
    policy: Policy,
}
impl Plan {
    /// Explicit policy used while selecting this transition's startup word.
    pub fn policy(self) -> Policy {
        self.policy
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_crossflash_retains_both_banks_for_each_capacity_case() {
        let storage = |magic, when_one, otherwise| {
            Some(bank::Storage::Versioned(bank::Contract {
                magic,
                addresses: bank::Addresses::Capacity {
                    when_one,
                    otherwise,
                },
                validation: bank::Validation::RejectMismatch,
            }))
        };
        // Known-answer contracts extracted from the customer's 212U 1.01
        // and destination 213U 1.02. This exercises planning, not a simulated
        // native boot or a conversion of the underlying persistent records.
        let installed = Checks {
            word: Ok(Analysis::Unknown),
            banks: storage(0xfedc4321, [0x5efffa, 0x5ffffa], [0x7dfffa, 0x7efffa]),
        };
        let target = Checks {
            word: Ok(Analysis::Unknown),
            banks: storage(0xfedc4322, [0x5f3ffa, 0x5ffffa], [0x7dbffa, 0x7e7ffa]),
        };
        assert_eq!(
            installed.plan_to(target),
            Err(Error::Banks(bank::Error::ConversionRequired {
                installed: installed.banks.unwrap(),
                target: target.banks.unwrap(),
            }))
        );
        assert!(matches!(
            installed.plan_to_with_policy(target, Policy::ExplicitCrossflash),
            Err(Error::Banks(bank::Error::ConversionRequired { .. }))
        ));
        let plan = installed
            .plan_verified_bank_transition(target, Policy::ExplicitCrossflash)
            .unwrap();
        assert_eq!(plan.target_checks(), target);
        assert_eq!(
            plan.target_checks().iter().collect::<Vec<_>>(),
            vec![
                Check::ParameterWord(Ok(Analysis::Unknown)),
                Check::PersistentBanks(target.banks)
            ]
        );
        assert_eq!(plan.policy(), Policy::ExplicitCrossflash);
        assert_eq!(
            plan.word_setting(),
            Setting {
                parameter: 0x9f,
                value: 0xffff,
                explicit: false
            }
        );
        // Selecting the explicit policy does not mutate or relax the native
        // bank contracts used by a later ordinary preparation.
        assert!(matches!(
            installed.plan_to(target),
            Err(Error::Banks(bank::Error::ConversionRequired { .. }))
        ));
    }
}

#[cfg(test)]
mod error_api_tests {
    use super::*;
    use crate::CodedError;
    #[test]
    fn startup_refusals_preserve_their_public_code_and_cause() {
        use std::error::Error as _;
        let ambiguous = Error::AmbiguousWord;
        assert!(ambiguous.to_string().contains("ambiguous"));
        assert_eq!(ambiguous.code(), "pioneer.preparation.ambiguous_startup");
        assert!(ambiguous.source().is_none());
        for cause in [bank::Error::UnknownInstalled, bank::Error::UnknownTarget] {
            let error = Error::Banks(cause);
            assert_eq!(error.code(), cause.code());
            assert_eq!(error.to_string(), cause.to_string());
            assert_eq!(error.source().unwrap().to_string(), cause.to_string());
        }
    }
}

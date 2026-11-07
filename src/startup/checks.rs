//! One set of receiver startup requirements and one transition planner.
use super::{bank, capacity, Ambiguous, Analysis, Setting};

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
    capacity: capacity::Evidence,
}
impl Checks {
    /// Inspect decoded components without device I/O or selecting writes.
    pub fn discover(normal: &[u8], kernel: Option<&[u8]>) -> Self {
        Self {
            word: super::analyze(normal),
            banks: bank::analyze_pair(normal, kernel),
            capacity: capacity::Evidence::discover(normal, kernel),
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
    /// Resolve the complete startup transition. Differing persistent-bank
    /// contracts always refuse; native word changes retain the verified path.
    pub fn plan_to(self, target: Self) -> Result<Plan, Error> {
        self.plan_to_with_policy(target, Policy::CompatibleBanks)
    }
    /// Resolve target word requirements under an explicit transition policy.
    /// The policy never waives the persistent-bank comparison: there is no
    /// bank format conversion, so differing contracts refuse under every policy.
    pub fn plan_to_with_policy(self, target: Self, policy: Policy) -> Result<Plan, Error> {
        let word = target.word.map_err(|_| Error::AmbiguousWord)?;
        bank::check(self.banks, target.banks).map_err(Error::Banks)?;
        if !self.capacity.relates(target.capacity) {
            return Err(Error::CapacityRelationUnproved);
        }
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
    /// Equal bank address cases have no bound cross-image discriminator relation.
    CapacityRelationUnproved,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AmbiguousWord => f.write_str(
                "target startup word checks are ambiguous; no startup plan can be prepared",
            ),
            Self::Banks(e) => e.fmt(f),
            Self::CapacityRelationUnproved => f.write_str(
                "persistent bank capacity discriminator relation is unresolved; provide the complete installed and target Kernel/Normal pairs with supported native query evidence; no settings or firmware were written",
            ),
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
            Self::CapacityRelationUnproved => "pioneer.startup.capacity_relation_unproved",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage(magic: u32, when_one: [u32; 2], otherwise: [u32; 2]) -> Option<bank::Storage> {
        Some(bank::Storage::Versioned(bank::Contract {
            magic,
            addresses: bank::Addresses::Capacity {
                when_one,
                otherwise,
            },
            validation: bank::Validation::RejectMismatch,
        }))
    }
    // Contracts recovered from BDR-212U 1.01 and BDR-213U 1.02.
    fn bdr_212u() -> Checks {
        Checks {
            word: Ok(Analysis::Unknown),
            banks: storage(0xfedc4321, [0x5efffa, 0x5ffffa], [0x7dfffa, 0x7efffa]),
            capacity: capacity::Evidence::UNKNOWN,
        }
    }
    fn bdr_213u() -> Checks {
        Checks {
            word: Ok(Analysis::Unknown),
            banks: storage(0xfedc4322, [0x5f3ffa, 0x5ffffa], [0x7dbffa, 0x7e7ffa]),
            capacity: capacity::Evidence::UNKNOWN,
        }
    }

    #[test]
    fn bdr_212u_and_213u_banks_refuse_in_both_directions_under_every_policy() {
        for (installed, target) in [(bdr_212u(), bdr_213u()), (bdr_213u(), bdr_212u())] {
            let refused = Err(Error::Banks(bank::Error::ConversionRequired {
                installed: installed.banks.unwrap(),
                target: target.banks.unwrap(),
            }));
            assert_eq!(installed.plan_to(target), refused);
            for policy in [Policy::CompatibleBanks, Policy::ExplicitCrossflash] {
                assert_eq!(installed.plan_to_with_policy(target, policy), refused);
            }
        }
    }

    #[test]
    fn descriptive_bank_equality_does_not_manufacture_pairing_evidence() {
        for checks in [bdr_212u(), bdr_213u()] {
            for policy in [Policy::CompatibleBanks, Policy::ExplicitCrossflash] {
                assert_eq!(
                    checks.plan_to_with_policy(checks, policy),
                    Err(Error::CapacityRelationUnproved)
                );
                assert_eq!(
                    checks.iter().collect::<Vec<_>>(),
                    vec![
                        Check::ParameterWord(Ok(Analysis::Unknown)),
                        Check::PersistentBanks(checks.banks)
                    ]
                );
            }
        }
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

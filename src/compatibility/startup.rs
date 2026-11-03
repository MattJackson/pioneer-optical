//! Startup decisions and their native evidence, independent of device I/O.
use crate::startup::{BoundSelection, Setting};
use alloc::boxed::Box;

/// Evidence used to select a target startup word.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Evidence {
    /// A complete native getter establishes an accepted comparison value.
    /// This does not establish the absence of additional startup requirements.
    BoundComparison(BoundSelection),
    /// Neutral startup selection chooses word 009F = FFFF when no comparison
    /// is recognized. This selection is separate from native absence evidence.
    NeutralSelection {
        /// Incomplete native coverage remains visible alongside the policy.
        native: Box<crate::startup::coverage::assessment::Assessment>,
    },
    /// Internal transaction fixtures may select a word without native firmware.
    #[cfg(all(test, feature = "envelope"))]
    FixturePolicy,
}

/// How the startup word is selected. Native comparison evidence and neutral
/// startup selection retain separate provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupPolicy {
    /// Select only an accepted comparison value bound to its native getter.
    NativeEvidenceOnly,
    /// Select neutral FFFF when no comparison is recognized. Observed unbound
    /// or ambiguous comparisons still refuse.
    NeutralSelection,
}

/// Immutable startup decision consumed by the settings transaction.
#[derive(Clone, Debug)]
pub struct Plan {
    selected: Setting,
    evidence: Evidence,
}

impl Plan {
    /// Word to read, change if needed, and verify before transferring firmware.
    pub fn setting(&self) -> Setting {
        self.selected
    }

    /// Why this word was selected. Neutral startup selection is separate from
    /// proof that a firmware image accepts every value.
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    #[cfg(all(test, feature = "envelope"))]
    pub(crate) fn fixture(selected: Setting) -> Self {
        Self {
            selected,
            evidence: Evidence::FixturePolicy,
        }
    }
}

/// A target startup decision could not be established uniquely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Multiple recognized comparisons prevent an automatic selection.
    Ambiguous,
    /// Native acceptance is not established by a complete supported selection.
    Unresolved,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Ambiguous => "target startup comparisons are ambiguous",
            Self::Unresolved => {
                "native startup acceptance is unresolved; no automatic startup word is authorized"
            }
        })
    }
}

impl std::error::Error for Error {}

impl crate::CodedError for Error {
    fn code(&self) -> &'static str {
        match self {
            Self::Ambiguous => "pioneer.compatibility.ambiguous_startup",
            Self::Unresolved => "pioneer.compatibility.unresolved_startup",
        }
    }
}

/// Select an accepted word from a complete native comparison/getter binding.
/// A missing comparison is unresolved. Neutral startup selection is available
/// separately through [`plan_with_policy`]. Read-only coverage
/// diagnostics are available through [`crate::startup::native_selection`].
/// Execution separately preserves the actual before value and owns rollback.
pub fn plan(normal: &[u8]) -> Result<Plan, Error> {
    let bound = match crate::startup::bound_selection(normal) {
        crate::image::layout::Observation::Known(bound) => bound,
        crate::image::layout::Observation::Conflicting => return Err(Error::Ambiguous),
        crate::image::layout::Observation::Unresolved(_) => return Err(Error::Unresolved),
    };
    Ok(Plan {
        selected: Setting {
            parameter: bound.requirement.parameter,
            value: bound.requirement.required,
            explicit: true,
        },
        evidence: Evidence::BoundComparison(bound),
    })
}

/// Apply an explicit startup policy without confusing it with a native fact.
/// Neutral startup selection is available only for `discover == Ok(None)`.
/// A recognized comparison must bind to its actual native getter; ambiguous
/// comparisons refuse selection. This performs no I/O.
pub fn plan_with_policy(normal: &[u8], policy: StartupPolicy) -> Result<Plan, Error> {
    if policy == StartupPolicy::NativeEvidenceOnly {
        return plan(normal);
    }
    match crate::startup::discover(normal) {
        Err(_) => Err(Error::Ambiguous),
        Ok(Some(_)) => plan(normal),
        Ok(None) => Ok(Plan {
            selected: Setting {
                parameter: 0x9f,
                value: 0xffff,
                explicit: false,
            },
            evidence: Evidence::NeutralSelection {
                native: Box::new(crate::startup::coverage::assessment::assess(normal)),
            },
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn comparison_fixture() -> alloc::vec::Vec<u8> {
        let mut normal = alloc::vec![0xff; 0x2000];
        normal[0x20..0x34].copy_from_slice(&[
            0x79, 0, 0, 0x9f, 0x5e, 0x41, 1, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
            0x41, 1, 0x80,
        ]);
        normal[0x180..0x186].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        normal
    }

    #[test]
    fn strict_native_evidence_refuses_a_missing_comparison() {
        assert!(matches!(plan(&[]), Err(Error::Unresolved)));
        let mut normal = alloc::vec![0xff; 0x2000];
        crate::image::layout::install_test_layout(&mut normal, 0x1000);
        assert!(matches!(plan(&normal), Err(Error::Unresolved)));
        // The strict planner does not apply neutral startup selection.
        assert_eq!(crate::startup::setting(&normal).unwrap().value, 0xffff);
    }

    #[test]
    fn neutral_startup_selection_chooses_ffff_and_retains_native_assessment() {
        for normal in [&[][..], &[0xff; 32][..]] {
            assert!(matches!(
                plan_with_policy(normal, StartupPolicy::NativeEvidenceOnly),
                Err(Error::Unresolved)
            ));
            let selected = plan_with_policy(normal, StartupPolicy::NeutralSelection).unwrap();
            assert_eq!(
                selected.setting(),
                Setting {
                    parameter: 0x9f,
                    value: 0xffff,
                    explicit: false
                }
            );
            let Evidence::NeutralSelection { native } = selected.evidence() else {
                panic!("neutral startup selection must retain its provenance");
            };
            assert_eq!(
                native.scope,
                crate::startup::coverage::assessment::Scope::NormalStartupToKernelHandoff
            );
            assert!(!native.obligations.is_empty());
        }
    }

    #[test]
    fn neutral_startup_selection_refuses_unbound_and_ambiguous_comparisons() {
        let mut normal = comparison_fixture();
        assert!(matches!(crate::startup::discover(&normal), Ok(Some(_))));
        assert!(matches!(
            plan_with_policy(&normal, StartupPolicy::NeutralSelection),
            Err(Error::Unresolved)
        ));
        let comparison = normal[0x20..0x34].to_vec();
        normal[0x60..0x74].copy_from_slice(&comparison);
        assert!(matches!(
            plan_with_policy(&normal, StartupPolicy::NeutralSelection),
            Err(Error::Ambiguous)
        ));
    }

    #[test]
    fn either_policy_selects_the_same_native_accepted_word_when_bound() {
        let mut normal = comparison_fixture();
        crate::image::layout::install_test_layout(&mut normal, 0x1000);
        normal[0x25..0x28].copy_from_slice(&[0x41, 0x10, 0]);
        for policy in [
            StartupPolicy::NativeEvidenceOnly,
            StartupPolicy::NeutralSelection,
        ] {
            let selected = plan_with_policy(&normal, policy).unwrap();
            assert_eq!(
                selected.setting(),
                Setting {
                    parameter: 0x9f,
                    value: 0xfe24,
                    explicit: true
                }
            );
            assert!(matches!(selected.evidence(), Evidence::BoundComparison(_)));
        }
        // A comparison is still observed after corrupting the native reader;
        // the explicit compatibility policy must not hide that failure.
        normal[0x1000] ^= 1;
        assert!(matches!(
            plan_with_policy(&normal, StartupPolicy::NeutralSelection),
            Err(Error::Unresolved)
        ));
    }
}

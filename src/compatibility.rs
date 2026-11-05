//! Firmware compatibility planning and verified corrections.
//!
//! Native detection stays with each filter. This module compares requirements,
//! constructs a component-bound correction plan and verifies prepared firmware.
//! Execution and live setting transactions remain owned by the receiver.
#[cfg(feature = "envelope")]
mod kernel;
#[cfg(feature = "envelope")]
pub use kernel::{plan_kernel, KernelPlanningError, KernelStep, KernelTransitionPlan};
/// Target startup selection and the evidence retained with that decision.
pub mod startup;

#[cfg(feature = "envelope")]
mod representation;
#[cfg(feature = "envelope")]
pub(crate) use representation::rebuild_normal;

use crate::image::matrix::{discover, Key};
use crate::image::phase;
use alloc::vec::Vec;

// Prepared native firmware changes share one receiver handoff.
#[cfg(feature = "envelope")]
#[derive(Clone, Debug)]
pub(crate) struct PreparedCorrection {
    pub id: String,
    pub image: Vec<u8>,
    pub corrections: Vec<Correction>,
    pub required_words: Vec<crate::filters::prerequisites::OwnedWord>,
}

#[cfg(feature = "envelope")]
#[derive(Clone, Debug)]
pub(crate) struct CorrectionRequirements {
    pub id: String,
    pub corrections: Vec<Correction>,
    pub required_words: Vec<crate::filters::prerequisites::OwnedWord>,
}

#[cfg(feature = "envelope")]
impl From<PreparedCorrection> for CorrectionRequirements {
    fn from(a: PreparedCorrection) -> Self {
        Self {
            id: a.id,
            corrections: a.corrections,
            required_words: a.required_words,
        }
    }
}

#[cfg(feature = "envelope")]
impl PreparedCorrection {
    pub(crate) fn native(
        image: Vec<u8>,
        corrections: &[Correction],
        required_words: Vec<crate::filters::prerequisites::OwnedWord>,
    ) -> Self {
        Self {
            id: "pioneer.native-correction.v1".into(),
            image,
            corrections: corrections.to_vec(),
            required_words,
        }
    }
}

/// Firmware context from structured metadata and the exact associated Kernel.
#[derive(Clone, Copy)]
pub struct Firmware<'a> {
    /// Exact hardware tag; never inferred from a model name.
    pub hardware: &'a str,
    /// Decoded Normal bytes.
    pub normal: &'a [u8],
    /// Exact associated decoded Kernel, when available.
    pub kernel: Option<&'a [u8]>,
}

/// A required proof for a firmware correction failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A required identity input could not be established.
    UnresolvedIdentity,
    /// At least one noncorrectable filter differs.
    Incompatible,
    /// Target Normal occupies addresses needed for retained parameter records.
    /// A primary-address operand rewrite cannot preserve both byte contents.
    PersistentLayoutOverlap {
        /// Installed absolute record-region start, inclusive.
        start: u32,
        /// End of the traced installed record region, exclusive.
        end: u32,
    },
    /// No supported correction connects the established identities.
    Unsupported,
    /// Native phase correction or Normal checksum validation failed.
    Phase(phase::CorrectionError),
    /// Corrected firmware did not reproduce the installed identity.
    VerificationFailed,
    /// Envelope components differ from the firmware used to make the plan.
    ComponentMismatch,
    /// Corrected firmware could not be rebuilt and decoded exactly.
    Representation,
    /// Required envelope authentication could not be produced or verified.
    Authentication,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnresolvedIdentity => {
                f.write_str("required firmware identity evidence is unresolved")
            }
            Self::Incompatible => {
                f.write_str("a required hardware filter differs without a supported correction")
            }
            Self::PersistentLayoutOverlap { start, end } => write!(f,
                "target Normal occupies retained parameter-record addresses {start:#08x}..{end:#08x}; changing the primary address alone cannot preserve these records"),
            Self::Unsupported => f.write_str("this native firmware correction is unsupported"),
            Self::Phase(error) => write!(f, "native phase correction failed: {error:?}"),
            Self::VerificationFailed => {
                f.write_str("prepared firmware did not reproduce the required identity")
            }
            Self::ComponentMismatch => {
                f.write_str("firmware components do not match the correction plan")
            }
            Self::Representation => {
                f.write_str("prepared firmware could not be rebuilt and decoded exactly")
            }
            Self::Authentication => {
                f.write_str("prepared Normal does not satisfy Kernel authentication")
            }
        }
    }
}
impl std::error::Error for Error {}

impl crate::CodedError for Error {
    fn code(&self) -> &'static str {
        match self {
            Self::UnresolvedIdentity => "pioneer.compatibility.unresolved_identity",
            Self::Incompatible => "pioneer.compatibility.incompatible",
            Self::PersistentLayoutOverlap { .. } => {
                "pioneer.compatibility.persistent_layout_overlap"
            }
            Self::Unsupported => "pioneer.compatibility.unsupported_correction",
            Self::Phase(_) => "pioneer.compatibility.phase_correction",
            Self::VerificationFailed => "pioneer.compatibility.verification_failed",
            Self::ComponentMismatch => "pioneer.compatibility.component_mismatch",
            Self::Representation => "pioneer.compatibility.representation_failed",
            Self::Authentication => "pioneer.compatibility.authentication_failed",
        }
    }
}

/// A native firmware difference with a supported correction.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Correction {
    /// A correction supplied by a registered filter without central dispatch.
    Registered {
        /// Stable identifier of the owner authorizing the correction.
        filter: &'static str,
        /// Native facts in the requested firmware before correction.
        from: crate::filters::Finding,
        /// Required native facts after correction.
        to: crate::filters::Finding,
    },
    /// Change target output assignment to the installed hardware assignment.
    Phase {
        /// Assignment currently encoded in target Normal.
        from: phase::Assignment,
        /// Required installed assignment.
        to: phase::Assignment,
    },
}

/// Component-bound owner plan.
///
/// Planning never performs device I/O. This plan borrows the exact target bytes
/// used for detection; callers cannot substitute another image at application.
/// Envelope authentication and live setting prerequisites remain receiver gates.
/// Persistent parameter layout is never corrected; published candidate keys
/// retain it.
pub struct CorrectionPlan<'a> {
    target: Firmware<'a>,
    expected: Option<Key>,
    runner: crate::filters::runner::Plan<'a>,
    corrections: Vec<Correction>,
}
impl CorrectionPlan<'_> {
    /// Native corrections selected by their registered owners.
    pub fn corrections(&self) -> &[Correction] {
        &self.corrections
    }

    /// Read-only live requirements supplied by the selected correction owners.
    /// The receiver must verify these before transferring any firmware stage.
    pub fn required_words(&self) -> Result<Vec<crate::filters::prerequisites::OwnedWord>, Error> {
        self.runner.required_words()
    }

    /// Every registered owner result, including operational requirements and
    /// explicit family waivers. No platform-specific field list is applied.
    pub fn filters(&self) -> &[crate::filters::runner::Decision] {
        self.runner.decisions()
    }

    /// Prepare a complete corrected file using the original codec and Kernel.
    /// Authentication and live execution prerequisites remain independent gates.
    #[cfg(feature = "envelope")]
    pub fn prepare_file(
        &self,
        normal: &crate::envelope::Envelope,
        kernel: Option<&crate::envelope::Envelope>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let Some(image) = self.prepare_image(normal, kernel)? else {
            return Ok(None);
        };
        let bytes = rebuild_normal(normal, kernel, &image)?;
        Ok(Some(bytes))
    }

    /// Prepare exact decoded components with native codec authority. Each owner
    /// supplies its effect and verifier; the coordinator composes disjoint edits.
    #[cfg(feature = "envelope")]
    pub fn prepare_image(
        &self,
        normal: &crate::envelope::Envelope,
        kernel: Option<&crate::envelope::Envelope>,
    ) -> Result<Option<Vec<u8>>, Error> {
        if !representation::matching_components(normal, kernel)
            || normal.image != self.target.normal
            || self.target.kernel != kernel.map(|k| k.image.as_slice())
            || normal.info().hardware_version != self.target.hardware
        {
            return Err(Error::ComponentMismatch);
        }
        let context = crate::filters::Preparation {
            target: self.target,
            normal: Some(normal),
            kernel,
        };
        let result = self.runner.prepare(&context)?;
        self.verify_image(result.as_deref().unwrap_or(self.target.normal))?;
        Ok(result)
    }

    /// Apply supported decoded-image effects without inventing codec authority.
    /// A filter that needs a file or exact Kernel refuses this raw path.
    pub fn prepare_normal(&self) -> Result<Option<Vec<u8>>, Error> {
        let context = crate::filters::Preparation {
            target: self.target,
            #[cfg(feature = "envelope")]
            normal: None,
            #[cfg(feature = "envelope")]
            kernel: None,
        };
        let result = self.runner.prepare(&context)?;
        self.verify_image(result.as_deref().unwrap_or(self.target.normal))?;
        Ok(result)
    }

    fn verify_image(&self, image: &[u8]) -> Result<(), Error> {
        if let Some(expected) = &self.expected {
            let after = discover(self.target.hardware, image, self.target.kernel)
                .ok_or(Error::VerificationFailed)?;
            if &after.as_is != expected {
                return Err(Error::VerificationFailed);
            }
        }
        Ok(())
    }
}

/// Detect and compare full identities, then plan supported firmware corrections.
/// Every unrelated required filter must match. Unknown observations fail closed.
/// This is the firmware compatibility planner; it does not select live settings.
pub fn plan<'a>(
    installed: Firmware<'_>,
    target: Firmware<'a>,
) -> Result<CorrectionPlan<'a>, Error> {
    plan_with_policy(installed, target, crate::filters::runner::Policy::Strict)
}

/// Build the same complete owner plan under an explicit family override.
/// Operational requirements and selected correction proofs are never waived.
pub fn plan_with_policy<'a>(
    installed: Firmware<'_>,
    target: Firmware<'a>,
    policy: crate::filters::runner::Policy,
) -> Result<CorrectionPlan<'a>, Error> {
    use crate::filters::{Context, Finding};
    let source = Context::new(installed);
    let destination = Context::new(target);
    let runner = crate::filters::runner::plan(&source, &destination, policy)?;
    let expected = if policy == crate::filters::runner::Policy::Strict {
        Some(Key::Registered(
            crate::filters::identity::discover(&source)
                .ok_or(Error::UnresolvedIdentity)?
                .as_is,
        ))
    } else {
        None
    };
    let corrections = runner
        .decisions()
        .iter()
        .filter_map(|decision| {
            decision.operation().map(|operation| {
                operation
                    .description()
                    .unwrap_or_else(|| Correction::Registered {
                        filter: decision.id,
                        from: decision.target.finding.clone(),
                        to: match &decision.installed.finding {
                            Finding::Known(_) | Finding::NotApplicable { .. } => {
                                decision.installed.finding.clone()
                            }
                            _ => decision.target.finding.clone(),
                        },
                    })
            })
        })
        .collect();
    Ok(CorrectionPlan {
        target,
        expected,
        runner,
        corrections,
    })
}

/// Convenience entry point for the existing phase-only preparation API.
/// Uses the same compatibility planner and verification as receiver preparation.
pub fn prepare_phase(
    installed: Firmware<'_>,
    target: Firmware<'_>,
) -> Result<Option<Vec<u8>>, Error> {
    plan(installed, target)?.prepare_normal()
}

// Public enums stay non-exhaustive: downstream matches need a wildcard arm.
/// ```compile_fail
/// use pioneer_optical::compatibility;
/// fn f(e: compatibility::Error) -> u8 {
///     use compatibility::Error::*;
///     match e {
///         UnresolvedIdentity | Incompatible | PersistentLayoutOverlap { .. } | Unsupported => 0,
///         Phase(_) | PersistentLayout(_) | VerificationFailed | ComponentMismatch => 1,
///         Representation | Authentication => 2,
///     }
/// }
/// ```
/// ```compile_fail
/// use pioneer_optical::compatibility;
/// fn f(e: compatibility::KernelPlanningError) -> u8 {
///     use compatibility::KernelPlanningError::*;
///     match e {
///         UnknownInstalledPolicy | Handoff(_) | RejectedBridgeMarker | UnsupportedRestoration => 0,
///     }
/// }
/// ```
/// ```compile_fail
/// use pioneer_optical::compatibility;
/// fn f(e: compatibility::KernelStep) -> u8 {
///     use compatibility::KernelStep::*;
///     match e {
///         Handoff { .. } | ReceiverMarker { .. } | Target => 0,
///     }
/// }
/// ```
/// ```compile_fail
/// use pioneer_optical::compatibility;
/// fn f(e: compatibility::startup::Evidence) -> u8 {
///     use compatibility::startup::Evidence::*;
///     match e {
///         BoundComparison(_) | NeutralSelection { .. } => 0,
///     }
/// }
/// ```
/// ```compile_fail
/// use pioneer_optical::compatibility;
/// fn f(e: compatibility::startup::StartupPolicy) -> u8 {
///     use compatibility::startup::StartupPolicy::*;
///     match e {
///         NativeEvidenceOnly | NeutralSelection => 0,
///     }
/// }
/// ```
/// ```compile_fail
/// use pioneer_optical::compatibility;
/// fn f(e: compatibility::startup::Error) -> u8 {
///     use compatibility::startup::Error::*;
///     match e {
///         Ambiguous | Unresolved => 0,
///     }
/// }
/// ```
#[cfg(doctest)]
struct NonExhaustiveEnums;

#[cfg(test)]
mod tests {
    use super::*;

    fn normal(variant: u8) -> Vec<u8> {
        let mut bytes = alloc::vec![0xff; 0x2000];
        crate::image::matrix::install_test_contract(&mut bytes, variant);
        bytes[0x680..0x694].copy_from_slice(&[
            0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
            0x41, 0x06, 0xa0,
        ]);
        bytes[0x6a0..0x6a6].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        bytes[..16].copy_from_slice(b"PIONEER TEST    ");
        bytes[16..20].fill(0);
        bytes[20..24].copy_from_slice(&0x2000u32.to_be_bytes());
        bytes[24..28].copy_from_slice(b"ID01");
        let sum = bytes.chunks_exact(4).fold(0u32, |sum, w| {
            sum.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
        });
        bytes[16..20].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
        bytes
    }
    fn context(bytes: &[u8]) -> Firmware<'_> {
        Firmware {
            hardware: "SAT 8600",
            normal: bytes,
            kernel: None,
        }
    }

    #[test]
    fn phase_is_corrected_both_ways_only_with_matching_required_filters() {
        let direct = normal(0);
        let swapped = phase::correct_normal(&direct, phase::Assignment::Swapped).unwrap();
        let unchanged = plan(context(&direct), context(&direct)).unwrap();
        assert!(unchanged.corrections().iter().all(|effect| matches!(
            effect, Correction::Registered { filter: "startup-prerequisite", from, to } if from == to
        )));
        assert_eq!(
            unchanged.required_words().unwrap()[0].word,
            crate::filters::prerequisites::Word {
                parameter: 0x9f,
                value: 0xfe24
            }
        );
        assert_eq!(unchanged.prepare_normal(), Ok(None));
        let planned = plan(context(&direct), context(&swapped)).unwrap();
        assert!(planned.corrections().contains(&Correction::Phase {
            from: phase::Assignment::Swapped,
            to: phase::Assignment::Direct,
        }));
        assert_eq!(planned.prepare_normal(), Ok(Some(direct.clone())));
        assert_eq!(prepare_phase(context(&direct), context(&direct)), Ok(None));
        assert_eq!(
            prepare_phase(context(&direct), context(&swapped)),
            Ok(Some(direct.clone()))
        );
        assert_eq!(
            prepare_phase(context(&swapped), context(&direct)),
            Ok(Some(swapped.clone()))
        );
        // A different required IRQ filter cannot be repaired by phase changes.
        assert_eq!(
            prepare_phase(context(&normal(1)), context(&swapped)),
            Err(Error::Incompatible)
        );
        let mut different_layout = direct.clone();
        different_layout[0x1000..].fill(0xff);
        crate::image::layout::install_test_layout_variant(&mut different_layout, 0x1000, 5);
        crate::startup::bank::fixture(&mut different_layout);
        assert!(discover("SAT 8600", &different_layout, None).is_some());
        // Both native layouts are known and differ: layout is never corrected.
        assert_eq!(
            prepare_phase(context(&different_layout), context(&swapped)),
            Err(Error::Incompatible)
        );
        let mut missing = direct.clone();
        missing[0x1000..].fill(0xff);
        assert_eq!(
            prepare_phase(context(&missing), context(&swapped)),
            Err(Error::UnresolvedIdentity)
        );
        let mut corrupt = swapped.clone();
        corrupt[16] ^= 1;
        assert_eq!(
            prepare_phase(context(&direct), context(&corrupt)),
            Err(Error::Phase(phase::CorrectionError::InvalidNormal))
        );
    }

    #[test]
    fn verification_refuses_images_without_the_expected_identity() {
        let direct = normal(0);
        let swapped = phase::correct_normal(&direct, phase::Assignment::Swapped).unwrap();
        let planned = plan(context(&direct), context(&swapped)).unwrap();
        // Rediscovered identity differs from the expected one.
        assert_eq!(
            planned.verify_image(&normal(1)),
            Err(Error::VerificationFailed)
        );
        // No identity can be rediscovered at all.
        let mut garbage = direct.clone();
        garbage[0x1000..].fill(0xff);
        assert_eq!(
            planned.verify_image(&garbage),
            Err(Error::VerificationFailed)
        );
        assert_eq!(planned.verify_image(&direct), Ok(()));
    }
}

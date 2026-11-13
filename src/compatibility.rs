//! Firmware compatibility planning and verified corrections.
//!
//! Native detection stays with each filter. This module compares requirements,
//! constructs a component-bound correction plan and verifies prepared firmware.
//! Execution and live setting transactions remain owned by the receiver.
#[cfg(feature = "envelope")]
mod kernel;
#[cfg(feature = "envelope")]
pub use kernel::{plan_kernel, KernelPlanningError, KernelStep, KernelTransitionPlan};

#[cfg(feature = "envelope")]
mod representation;
#[cfg(feature = "envelope")]
pub(crate) use representation::rebuild_normal;

use crate::filters::family::{discover, Key};
#[cfg(test)]
use crate::filters::phase::native as phase;
use alloc::vec::Vec;

// Prepared native firmware changes share one receiver handoff.
#[cfg(feature = "envelope")]
#[derive(Clone, Debug)]
pub(crate) struct PreparedCorrection {
    pub id: String,
    pub image: Vec<u8>,
    pub corrections: Vec<Correction>,
    pub required_words: Vec<crate::filters::prerequisites::OwnedWord>,
    pub word_writes: Vec<crate::filters::prerequisites::OwnedWord>,
}

#[cfg(feature = "envelope")]
#[derive(Clone, Debug)]
pub(crate) struct CorrectionRequirements {
    pub id: String,
    pub corrections: Vec<Correction>,
    pub required_words: Vec<crate::filters::prerequisites::OwnedWord>,
    pub word_writes: Vec<crate::filters::prerequisites::OwnedWord>,
}

#[cfg(feature = "envelope")]
impl From<PreparedCorrection> for CorrectionRequirements {
    fn from(a: PreparedCorrection) -> Self {
        Self {
            id: a.id,
            corrections: a.corrections,
            required_words: a.required_words,
            word_writes: a.word_writes,
        }
    }
}

#[cfg(feature = "envelope")]
impl PreparedCorrection {
    pub(crate) fn native(
        image: Vec<u8>,
        corrections: &[Correction],
        required_words: Vec<crate::filters::prerequisites::OwnedWord>,
        word_writes: Vec<crate::filters::prerequisites::OwnedWord>,
    ) -> Self {
        Self {
            id: "pioneer.native-correction.v1".into(),
            image,
            corrections: corrections.to_vec(),
            required_words,
            word_writes,
        }
    }
}

pub use crate::filters::{Correction, Error, Firmware};

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

    /// Device words the selected corrections set before transfer.
    pub fn word_writes(&self) -> Result<Vec<crate::filters::prerequisites::OwnedWord>, Error> {
        self.runner.word_writes()
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

    /// Prepare decoded Normal bytes, refusing any changed Kernel component.
    /// Authentication and live prerequisites remain independent receiver gates.
    #[cfg(feature = "envelope")]
    pub fn prepare_image(
        &self,
        normal: &crate::envelope::Envelope,
        kernel: Option<&crate::envelope::Envelope>,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.normal_only(self.prepare_components(normal, kernel)?)
    }

    /// Prepare the complete decoded pair with original envelope authority.
    /// This does not authenticate rebuilt files or authorize an executable update.
    #[cfg(feature = "envelope")]
    pub fn prepare_components(
        &self,
        normal: &crate::envelope::Envelope,
        kernel: Option<&crate::envelope::Envelope>,
    ) -> Result<Option<crate::filters::PreparedComponents>, Error> {
        self.prepare_components_using(normal, kernel, |context| {
            self.runner.prepare_components(context)
        })
    }

    #[cfg(feature = "envelope")]
    fn prepare_components_using<F>(
        &self,
        normal: &crate::envelope::Envelope,
        kernel: Option<&crate::envelope::Envelope>,
        prepare: F,
    ) -> Result<Option<crate::filters::PreparedComponents>, Error>
    where
        F: FnOnce(
            &crate::filters::Preparation<'_>,
        ) -> Result<Option<crate::filters::PreparedComponents>, Error>,
    {
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
        self.prepare_pair_using(&context, prepare)
    }

    /// Apply decoded Normal effects without inventing codec authority.
    /// A changed Kernel cannot be represented by this legacy return type.
    pub fn prepare_normal(&self) -> Result<Option<Vec<u8>>, Error> {
        self.normal_only(self.prepare_decoded_components()?)
    }

    /// Prepare the complete decoded pair without inventing codec authority.
    /// Owners requiring original envelopes still refuse this raw path.
    pub fn prepare_decoded_components(
        &self,
    ) -> Result<Option<crate::filters::PreparedComponents>, Error> {
        self.prepare_decoded_components_using(|context| self.runner.prepare_components(context))
    }

    fn prepare_decoded_components_using<F>(
        &self,
        prepare: F,
    ) -> Result<Option<crate::filters::PreparedComponents>, Error>
    where
        F: FnOnce(
            &crate::filters::Preparation<'_>,
        ) -> Result<Option<crate::filters::PreparedComponents>, Error>,
    {
        let context = crate::filters::Preparation {
            target: self.target,
            #[cfg(feature = "envelope")]
            normal: None,
            #[cfg(feature = "envelope")]
            kernel: None,
        };
        self.prepare_pair_using(&context, prepare)
    }

    fn prepare_pair_using<F>(
        &self,
        context: &crate::filters::Preparation<'_>,
        prepare: F,
    ) -> Result<Option<crate::filters::PreparedComponents>, Error>
    where
        F: FnOnce(
            &crate::filters::Preparation<'_>,
        ) -> Result<Option<crate::filters::PreparedComponents>, Error>,
    {
        let result = prepare(context)?;
        let final_pair = match &result {
            Some(pair) => Firmware {
                hardware: self.target.hardware,
                normal: &pair.normal,
                kernel: pair.kernel.as_deref(),
            },
            None => self.target,
        };
        self.verify_pair(final_pair)?;
        Ok(result)
    }

    fn normal_only(
        &self,
        result: Option<crate::filters::PreparedComponents>,
    ) -> Result<Option<Vec<u8>>, Error> {
        match result {
            Some(pair) if pair.kernel.as_deref() != self.target.kernel => Err(Error::Unsupported),
            Some(pair) => Ok(Some(pair.normal)),
            None => Ok(None),
        }
    }

    #[cfg(test)]
    fn verify_image(&self, image: &[u8]) -> Result<(), Error> {
        self.verify_pair(Firmware {
            normal: image,
            ..self.target
        })
    }

    fn verify_pair(&self, final_pair: Firmware<'_>) -> Result<(), Error> {
        if let Some(expected) = &self.expected {
            let after = discover(final_pair.hardware, final_pair.normal, final_pair.kernel)
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

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn normal(variant: u8) -> Vec<u8> {
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
        // The installed fixed gate proves the drive's word: none read or set.
        assert!(unchanged.required_words().unwrap().is_empty());
        assert!(unchanged.word_writes().unwrap().is_empty());
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

#[cfg(test)]
#[path = "compatibility_pair_tests.rs"]
mod pair_tests;

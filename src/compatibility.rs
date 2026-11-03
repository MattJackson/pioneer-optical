//! Firmware compatibility planning and verified corrections.
//!
//! Native detection stays with each filter. This module compares requirements,
//! constructs a component-bound correction plan and verifies prepared firmware.
//! Execution and live setting transactions remain owned by the receiver.
/// Mechanism correction guards and live prerequisites.
#[cfg(feature = "envelope")]
pub mod mechanism;

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
#[cfg(feature = "envelope")]
mod preparation;
#[cfg(feature = "envelope")]
pub(crate) use preparation::{prepare as prepare_corrections, PreparationError};

use crate::image::matrix::{discover, Key};
#[cfg(test)]
use crate::image::matrix::{AtaInput, SatKey};
use crate::image::phase;
use alloc::vec::Vec;

/// A live parameter must have this value before any settings or firmware write.
#[cfg(feature = "envelope")]
#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ParameterPrerequisite {
    /// A0 word index, not a byte offset.
    pub parameter: u16,
    /// Required existing value; this is never a request to write that value.
    pub value: u16,
}

// Prepared firmware changes and live prerequisites share one receiver handoff.
#[cfg(feature = "envelope")]
#[derive(Clone, Debug)]
pub(crate) struct PreparedCorrection {
    pub verification: Verification,
    pub id: String,
    pub image: Vec<u8>,
    pub corrections: Vec<Correction>,
    pub requirements: Vec<ParameterPrerequisite>,
    pub(crate) requires_normal_runtime: bool,
    pub(crate) stock_return: bool,
    pub resolves_issue: String,
}

#[cfg(feature = "envelope")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verification {
    RegisteredFilters,
    ReviewedMechanism,
    ReviewedMechanismAndRegisteredFilters,
}

#[cfg(feature = "envelope")]
#[derive(Clone, Debug)]
pub(crate) struct CorrectionRequirements {
    pub id: String,
    pub corrections: Vec<Correction>,
    pub requirements: Vec<ParameterPrerequisite>,
    pub requires_normal_runtime: bool,
}

#[cfg(feature = "envelope")]
impl From<PreparedCorrection> for CorrectionRequirements {
    fn from(a: PreparedCorrection) -> Self {
        Self {
            id: a.id,
            corrections: a.corrections,
            requirements: a.requirements,
            requires_normal_runtime: a.requires_normal_runtime,
        }
    }
}

#[cfg(feature = "envelope")]
impl PreparedCorrection {
    pub(crate) fn native(image: Vec<u8>, corrections: &[Correction]) -> Self {
        Self {
            verification: Verification::RegisteredFilters,
            id: "pioneer.native-correction.v1".into(),
            image,
            corrections: corrections.to_vec(),
            requirements: Vec::new(),
            requires_normal_runtime: false,
            stock_return: false,
            resolves_issue: String::new(),
        }
    }
    pub(crate) fn stock_return(&self) -> bool {
        self.stock_return
    }
    pub(crate) fn verified_by_filters(&self) -> bool {
        matches!(
            self.verification,
            Verification::RegisteredFilters | Verification::ReviewedMechanismAndRegisteredFilters
        )
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
    /// Complete Normal-only persistent layout proof failed.
    PersistentLayout(crate::image::layout::H8RelocationError),
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
            Self::PersistentLayout(error) => write!(f, "persistent layout correction proof failed: {error:?}"),
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
            Self::PersistentLayout(_) => "pioneer.compatibility.persistent_layout_correction",
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
    /// Retain the installed primary location using a complete-program proof.
    PersistentParameterLayout {
        /// Primary location encoded in the target before correction.
        from: u32,
        /// Primary location required by installed retained records.
        to: u32,
    },
}

/// Immutable, component-bound firmware portion of a correction plan.
///
/// Planning never performs device I/O. This plan borrows the exact target bytes
/// used for detection; callers cannot substitute another image at application.
/// Envelope authentication and live setting prerequisites remain receiver gates.
/// Address relocation additionally requires complete Normal program equivalence
/// and the exact unchanged Kernel; published candidate keys retain layout.
struct InstalledFirmware {
    hardware: alloc::string::String,
    normal: Vec<u8>,
    kernel: Option<Vec<u8>>,
}
impl InstalledFirmware {
    fn as_firmware(&self) -> Firmware<'_> {
        Firmware {
            hardware: &self.hardware,
            normal: &self.normal,
            kernel: self.kernel.as_deref(),
        }
    }
}

/// Component-bound owner plan with an immutable installed-firmware snapshot.
pub struct CorrectionPlan<'a> {
    installed: InstalledFirmware,
    policy: crate::filters::runner::Policy,
    target: Firmware<'a>,
    expected: Option<Key>,
    runner: crate::filters::runner::Plan<'a>,
    corrections: Vec<Correction>,
}
impl CorrectionPlan<'_> {
    /// Re-evaluate every registered owner after a reviewed whole-program effect.
    /// The installed snapshot and explicit family policy remain unchanged.
    pub fn replan<'a>(&self, target: Firmware<'a>) -> Result<CorrectionPlan<'a>, Error> {
        plan_with_policy(self.installed.as_firmware(), target, self.policy)
    }

    /// Native corrections selected by their registered owners.
    pub fn corrections(&self) -> &[Correction] {
        &self.corrections
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
        let bytes = rebuild_normal(normal, kernel, &image, false)?;
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

// ATA transition support is checked per exact target by codec/checksum proof
// during preparation. Its published candidate identity still retains phase.
// Admit a potential plan only when every other typed field is exactly equal.
#[cfg(test)]
fn compatible_candidates(source: &Key, target: &Key) -> bool {
    if source == target {
        return true;
    }
    match (source, target) {
        (Key::Sat(SatKey::Sat1 { phase, .. }), Key::Sat(SatKey::Sat1 { .. })) => {
            let mut adjusted = target.clone();
            if let Key::Sat(SatKey::Sat1 {
                phase: ref mut value,
                ..
            }) = adjusted
            {
                *value = *phase;
            }
            *source == adjusted
        }
        (Key::Ata(a), Key::Ata(b)) => {
            let mut adjusted = b.clone();
            adjusted.phase.assignment = a.phase.assignment;
            *a == adjusted
        }
        _ => false,
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
        installed: InstalledFirmware {
            hardware: installed.hardware.into(),
            normal: installed.normal.to_vec(),
            kernel: installed.kernel.map(<[u8]>::to_vec),
        },
        policy,
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

    #[test]
    fn ata_phase_planning_cannot_waive_other_required_fields() {
        use crate::image::matrix::AtaKey;
        use crate::image::{geometry, layout, peripheral};
        let layout = layout::ParameterLayout::SerialRange {
            address_bits: 16,
            first_word: 0xc0,
            word_count: 160,
            encoding: layout::WordEncoding::SerialHighByteFirst,
        };
        let a = AtaKey {
            geometry: match geometry::peripheral_geometry(&layout) {
                layout::Observation::Known(v) => v,
                _ => panic!("fixture geometry"),
            },
            layout,
            host: peripheral::HostSignature {
                coordinate: 0x2000d2,
                signature_low: 0x2000d2,
                signature_high: 0x2000d3,
                initial_one: [0x2000d4, 0x2000d5],
            },
            input: AtaInput::V850(peripheral::KeyAlgorithm::CounterLow),
            phase: peripheral::Phase {
                assignment: phase::Assignment::Direct,
                interface: peripheral::Interface::Indexed16 {
                    window: 0x200100,
                    channels: [0x8e, 0x8f],
                },
            },
        };
        for input in [
            a.input,
            AtaInput::M32c(peripheral::Input::KeyEvent {
                address: 0x183,
                mask: 1,
                required: 1,
            }),
        ] {
            let mut a = a.clone();
            a.input = input;
            let source = Key::Ata(a.clone());
            let mut swapped = a.clone();
            swapped.phase.assignment = phase::Assignment::Swapped;
            assert!(compatible_candidates(&source, &Key::Ata(swapped.clone())));
            for field in 0..5 {
                let mut bad = swapped.clone();
                match field {
                    0 => {
                        if let layout::ParameterLayout::SerialRange {
                            ref mut word_count, ..
                        } = bad.layout
                        {
                            *word_count -= 1;
                        }
                    }
                    1 => {
                        bad.geometry = geometry::PeripheralGeometry::SerialWords {
                            first: 0xc1,
                            last: 0x15f,
                        }
                    }
                    2 => bad.host.signature_high += 1,
                    3 => {
                        bad.input = match a.input {
                            AtaInput::V850(_) => AtaInput::V850(peripheral::KeyAlgorithm::TimerLow),
                            AtaInput::M32c(_) => AtaInput::M32c(peripheral::Input::KeyEvent {
                                address: 0x183,
                                mask: 2,
                                required: 2,
                            }),
                        }
                    }
                    _ => {
                        bad.phase.interface = peripheral::Interface::Indexed16 {
                            window: 0x210100,
                            channels: [0x8e, 0x8f],
                        }
                    }
                }
                assert!(
                    !compatible_candidates(&source, &Key::Ata(bad)),
                    "required field {field}"
                );
            }
        }
    }
    fn normal(variant: u8) -> Vec<u8> {
        let mut bytes = alloc::vec![0xff; 0x2000];
        crate::image::matrix::install_test_contract(&mut bytes, variant);
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
        assert!(unchanged.corrections().is_empty());
        assert_eq!(unchanged.prepare_normal(), Ok(None));
        let planned = plan(context(&direct), context(&swapped)).unwrap();
        assert_eq!(
            planned.corrections(),
            &[Correction::Phase {
                from: phase::Assignment::Swapped,
                to: phase::Assignment::Direct,
            }]
        );
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
        // Both native layouts are known and differ, but these fixtures supply
        // no Kernel for the component-bound relocation proof. Refuse the
        // unresolved correction rather than claiming a proved format conflict.
        assert_eq!(
            prepare_phase(context(&different_layout), context(&swapped)),
            Err(Error::UnresolvedIdentity)
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

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
mod layout;
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

use crate::image::matrix::{discover, AtaInput, Key, SatKey};
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
    pub id: String,
    pub image: Vec<u8>,
    pub corrections: Vec<Correction>,
    pub requirements: Vec<ParameterPrerequisite>,
    requires_normal_runtime: bool,
    stock_return: bool,
    pub resolves_issue: String,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Correction {
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
pub struct CorrectionPlan<'a> {
    target: Firmware<'a>,
    expected: Key,
    candidate: Key,
    corrections: Vec<Correction>,
    prepared: Option<Vec<u8>>,
}
impl CorrectionPlan<'_> {
    /// Ordered native corrections; an empty list means the identities match.
    pub fn corrections(&self) -> &[Correction] {
        &self.corrections
    }

    /// Prepare a corrected Normal file bound to the plan's exact components.
    /// Rebuilds checksums, signs when required, decodes and verifies the result.
    /// A Kernel is optional only for codecs with sufficient standalone evidence.
    /// This proves file preparation only; live prerequisites, receiver protocol
    /// and transfer representation still gate flashing independently.
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
        self.verify_image(&image)?;
        Ok(Some(bytes))
    }

    /// Prepare decoded Normal bytes using the exact file codec and Kernel.
    /// Checks native sums and re-extracts every required identity field. The
    /// caller must still rebuild and authenticate the file before transfer.
    /// Receiver preparation uses this stage to compose corrections before the
    /// shared file rebuild, so authentication is performed only once.
    #[cfg(feature = "envelope")]
    pub fn prepare_image(
        &self,
        normal: &crate::envelope::Envelope,
        kernel: Option<&crate::envelope::Envelope>,
    ) -> Result<Option<Vec<u8>>, Error> {
        use crate::envelope::Layout;
        if !representation::matching_components(normal, kernel)
            || normal.image != self.target.normal
            || self.target.kernel != kernel.map(|k| k.image.as_slice())
            || normal.info().hardware_version != self.target.hardware
            || kernel.is_some_and(|k| {
                k.info().kind != crate::ComponentKind::Kernel
                    || k.info().hardware_version != self.target.hardware
            })
        {
            return Err(Error::ComponentMismatch);
        }
        let m32c = matches!(&self.expected,Key::Ata(k)if matches!(k.input,AtaInput::M32c(_)));
        let legacy_sat1 = matches!(&self.expected, Key::Sat(SatKey::Sat1 { .. }))
            && normal.info().layout == Layout::NormalScaledKey;
        let image = if let Some(prepared) = &self.prepared {
            prepared.clone()
        } else if m32c || legacy_sat1 {
            let [Correction::Phase { to, .. }] = self.corrections.as_slice() else {
                if self.corrections.is_empty() {
                    return Ok(None);
                }
                return Err(Error::Unsupported);
            };
            let modified = if m32c {
                let base = match normal.info().layout {
                    Layout::NormalTailKey => 0xf40000,
                    Layout::NormalBootKey if kernel.is_some() => 0xf80000,
                    _ => return Err(Error::Unsupported),
                };
                crate::image::peripheral::correct_m32c_phase_pair(self.target.normal, base, *to)
                    .map_err(Error::Phase)?
            } else {
                phase::correct_legacy(self.target.normal, *to).map_err(Error::Phase)?
            };
            let image = normal
                .repair_image_checksum(&modified)
                .ok_or(Error::Representation)?;
            self.verify_image(&image)?;
            image
        } else {
            let Some(image) = self.prepare_normal()? else {
                return Ok(None);
            };
            image
        };
        self.verify_image(&image)?;
        Ok(Some(image))
    }

    /// Apply supported firmware effects and re-extract the entire identity.
    /// None means no firmware changes are needed. This does not authorize flash.
    /// M32C checksum rules require codec evidence; use `prepare_file` instead.
    pub fn prepare_normal(&self) -> Result<Option<Vec<u8>>, Error> {
        if let Some(prepared) = &self.prepared {
            self.verify_image(prepared)?;
            return Ok(Some(prepared.clone()));
        }
        let corrected = match self.corrections.as_slice() {
            [] => return Ok(None),
            [Correction::Phase { to, .. }] => match &self.expected {
                Key::Ata(key) if matches!(key.input, AtaInput::V850(_)) => {
                    let kernel = self.target.kernel.ok_or(Error::UnresolvedIdentity)?;
                    crate::image::peripheral::correct_v850_normal_phase(
                        self.target.normal,
                        kernel,
                        *to,
                    )
                    .map_err(Error::Phase)?
                }
                Key::Ata(_) => return Err(Error::Unsupported),
                _ => phase::correct_normal(self.target.normal, *to).map_err(Error::Phase)?,
            },
            _ => return Err(Error::Unsupported),
        };
        self.verify_image(&corrected)?;
        Ok(Some(corrected))
    }

    fn verify_image(&self, image: &[u8]) -> Result<(), Error> {
        let after = discover(self.target.hardware, image, self.target.kernel)
            .ok_or(Error::VerificationFailed)?;
        if after.as_is != self.expected || !compatible_candidates(&after.candidate, &self.candidate)
        {
            return Err(Error::VerificationFailed);
        }
        Ok(())
    }
}

fn paired_assignment(key: &Key) -> Option<phase::Assignment> {
    match key {
        Key::Sat(
            SatKey::Sat8 {
                phase: Some(value), ..
            }
            | SatKey::Sat9 {
                phase: Some(value), ..
            },
        ) => Some(*value),
        Key::Sat(SatKey::Sat1 { phase, .. }) => Some(*phase),
        Key::Ata(key) => Some(key.phase.assignment),
        _ => None,
    }
}

// ATA transition support is checked per exact target by codec/checksum proof
// during preparation. Its published candidate identity still retains phase.
// Admit a potential plan only when every other typed field is exactly equal.
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
    let source = discover(installed.hardware, installed.normal, installed.kernel)
        .ok_or(Error::UnresolvedIdentity)?;
    let destination =
        discover(target.hardware, target.normal, target.kernel).ok_or(Error::UnresolvedIdentity)?;
    let mut address_change = None;
    if !compatible_candidates(&source.candidate, &destination.candidate) {
        if let Some((start, end)) =
            layout::relocation_overlap(&source.as_is, &destination.as_is, target.normal)
        {
            return Err(Error::PersistentLayoutOverlap { start, end });
        }
        let Some((adjusted, from, to)) =
            layout::address_only_candidate(&source.candidate, &destination.candidate)
        else {
            return Err(Error::Incompatible);
        };
        if !compatible_candidates(&source.candidate, &adjusted) {
            return Err(Error::Incompatible);
        }
        address_change = Some((from, to));
    }
    let mut corrections = Vec::new();
    let source_phase = paired_assignment(&source.as_is);
    let target_phase = paired_assignment(&destination.as_is);
    let phase_change = if source_phase != target_phase {
        let from = target_phase.ok_or(Error::Unsupported)?;
        let to = source_phase.ok_or(Error::Unsupported)?;
        if matches!(source.as_is, Key::Sat(SatKey::Sat1 { .. })) {
            use crate::image::layout::Observation;
            match (
                phase::discover(installed.normal),
                phase::discover(target.normal),
            ) {
                (Observation::Known(a), Observation::Known(b)) if a.interface == b.interface => {}
                (Observation::Known(_), Observation::Known(_)) => return Err(Error::Incompatible),
                _ => return Err(Error::UnresolvedIdentity),
            }
        }
        corrections.push(Correction::Phase { from, to });
        Some(to)
    } else {
        None
    };
    let prepared = if let Some((from, to)) = address_change {
        let native = crate::image::layout::plan_h8_relocation(
            installed.normal,
            installed.kernel.ok_or(Error::UnresolvedIdentity)?,
            target.normal,
            target.kernel.ok_or(Error::UnresolvedIdentity)?,
        )
        .map_err(Error::PersistentLayout)?;
        if (native.from(), native.to()) != (from, to) {
            return Err(Error::VerificationFailed);
        }
        let prepared = native
            .prepare_with_phase(phase_change)
            .map_err(Error::PersistentLayout)?;
        corrections.push(Correction::PersistentParameterLayout { from, to });
        Some(prepared)
    } else {
        None
    };
    let plan = CorrectionPlan {
        target,
        expected: source.as_is,
        candidate: source.candidate,
        corrections,
        prepared,
    };
    if let Some(prepared) = &plan.prepared {
        plan.verify_image(prepared)?;
    }
    Ok(plan)
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
        assert!(discover("SAT 8600", &different_layout, None).is_some());
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
}

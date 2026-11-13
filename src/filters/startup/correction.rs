//! Bound unchanged startup comparisons. The target image is never rewritten:
//! unless the installed firmware's own fixed gate already proves the drive
//! holds the target's word, the target's word is set on the drive
//! (`word_writes`) in the first stage's settings transaction. The live word is
//! read only to snapshot it for restore; it is never a prerequisite.
use super::ID;
use crate::startup::h8_conditional;
use crate::{
    compatibility::Error,
    filters::{prerequisites::Word, Finding, Integrity, Operation, Preparation, Transition},
    image::layout::{self, H8ReaderComponent, Observation},
    startup::{self, BoundSelection},
};
use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, Ea, Operand, Reg},
    Mode, Target,
};

const BASE: usize = 0x410000;

/// A complete local acceptance/rejection block, with its bound reader graph.
#[derive(Clone, Debug)]
struct Gate {
    bound: BoundSelection,
    comparison: Range<usize>,
    protected: Vec<Range<usize>>,
    conditional: Option<crate::filters::Value>,
}

impl Gate {
    fn bind(normal: &[u8]) -> Result<Self, Error> {
        let Observation::Known(bound) = startup::bound_selection(normal) else {
            return Err(Error::UnresolvedIdentity);
        };
        let start = bound.requirement.check_address as usize - BASE;
        let (_, compare) = startup::getter_call(normal, start).ok_or(Error::UnresolvedIdentity)?;
        let instruction = decode_insn(&normal[compare..], Target::H8S2000, Mode::Advanced)
            .map_err(|_| Error::UnresolvedIdentity)?;
        if instruction.len != 4
            || instruction.insn.mnemonic != "CMP"
            || instruction.insn.operands[0]
                != (Operand::Immediate {
                    value: u32::from(bound.requirement.required),
                    bits: 16,
                })
            || instruction.insn.operands[1] != Operand::Register(Reg::Word(0))
        {
            return Err(Error::UnresolvedIdentity);
        }
        let comparison = compare..compare + instruction.len;
        let branch = decode_insn(&normal[comparison.end..], Target::H8S2000, Mode::Advanced)
            .map_err(|_| Error::UnresolvedIdentity)?;
        let Operand::Address(Ea::PcRelative { value, .. }) = branch.insn.operands[0] else {
            return Err(Error::UnresolvedIdentity);
        };
        if branch.insn.mnemonic != "BEQ" || value <= 0 {
            return Err(Error::UnresolvedIdentity);
        }
        let end = (comparison.end + branch.len)
            .checked_add_signed(value as isize)
            .filter(|end| *end <= normal.len())
            .ok_or(Error::UnresolvedIdentity)?;
        // The indirect callee load can precede the parameter instruction.
        let begin = if normal.get(start + 4) == Some(&0x5d) {
            start.checked_sub(6).ok_or(Error::UnresolvedIdentity)?
        } else {
            start
        };
        let mut protected: Vec<_> = core::iter::once(begin..end).collect();
        let Observation::Known(reader) = layout::discover_h8_reader(normal, None) else {
            return Err(Error::UnresolvedIdentity);
        };
        if reader.component != H8ReaderComponent::Normal
            || reader.getter != bound.requirement.getter_address
            || reader.layout != bound.layout
        {
            return Err(Error::UnresolvedIdentity);
        }
        protected.extend(reader.functions.iter().map(|function| {
            let begin = function.address as usize - BASE;
            begin..begin + function.bytes
        }));
        let conditional = h8_conditional::discover(normal, &bound);
        if conditional.is_none()
            && !startup::calls_loader_flag(&normal[comparison.end + branch.len..end], normal)
        {
            return Err(Error::UnresolvedIdentity);
        }
        if let Some(evidence) = &conditional {
            protected.extend(
                evidence
                    .source_spans
                    .iter()
                    .map(|&(a, b)| a as usize - BASE..b as usize - BASE),
            );
        }
        // Protect every rejection-service wrapper as well as its call operand.
        // An unbound conditional predicate must never be treated as a simple
        // mismatch block merely because the primary accepted word was found.
        let mut at = comparison.end + branch.len;
        while at < end {
            let decoded = decode_insn(&normal[at..end], Target::H8S2000, Mode::Advanced)
                .map_err(|_| Error::UnresolvedIdentity)?;
            if decoded.insn.mnemonic == "JSR" {
                let Operand::Address(Ea::Absolute { value, bits: 24 }) = decoded.insn.operands[0]
                else {
                    return Err(Error::UnresolvedIdentity);
                };
                let offset = (value as usize)
                    .checked_sub(BASE)
                    .ok_or(Error::UnresolvedIdentity)?;
                let wrapper = normal
                    .get(offset..offset + 6)
                    .ok_or(Error::UnresolvedIdentity)?;
                if wrapper[..3] == [0x5e, 0x40, 0x0a] && wrapper[4..] == [0x54, 0x70] {
                    protected.push(offset..offset + 6);
                }
            }
            at += decoded.len;
        }
        if at != end {
            return Err(Error::UnresolvedIdentity);
        }
        Ok(Self {
            bound,
            comparison,
            protected,
            conditional: conditional.map(|value| value.predicate_value()),
        })
    }

    fn admits_unchanged(&self) -> Result<(), Error> {
        // FE09 must continue through its predicate, never be the equal branch
        // of a conditional gate. `h8_conditional::discover` already declines
        // that shape, so this restates its invariant rather than adding a rule.
        if self.conditional.is_some()
            && self.bound.requirement.required == h8_conditional::ALTERNATIVE
        {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
}

/// The value of a startup word no gate has set: the state of a unit that
/// shipped with gate-less firmware.
pub(super) const UNSET: u16 = crate::startup::UNSET_WORD;

/// Target with a proven-absent fixed startup gate: no image edit. An
/// independently bound preservation certificate is still enforced. Leaving a
/// gated installed firmware resets the word the installed gate relied on to
/// [`UNSET`], so the drive ends as a unit that shipped with the target; from a
/// gate-less installed firmware the word is left alone.
pub(super) fn plan_absent(
    transition: &Transition<'_, '_>,
    finding: &Finding,
) -> Result<Option<Box<dyn Operation>>, Error> {
    if transition.installed.sat.is_none() {
        return Err(Error::UnresolvedIdentity);
    }
    let preservation = PreservationOperation::bind(transition, finding)?
        .map(|op| Box::new(op) as Box<dyn Operation>);
    let Observation::Known(installed) = startup::bound_selection(transition.installed.firmware.normal)
    else {
        return Ok(preservation);
    };
    let target = transition.target.firmware;
    Ok(Some(Box::new(UnsetOperation {
        inner: preservation,
        word: Word {
            parameter: installed.requirement.parameter,
            value: UNSET,
        },
        hardware: target.hardware.into(),
        normal: target.normal.to_vec(),
        kernel: target.kernel.map(<[u8]>::to_vec),
        finding: finding.clone(),
    })))
}

/// Resets the installed gate's word for a proven gate-less target; image
/// effects and checks are those of the optional preservation certificate.
#[derive(Debug)]
struct UnsetOperation {
    inner: Option<Box<dyn Operation>>,
    word: Word,
    hardware: String,
    normal: Vec<u8>,
    kernel: Option<Vec<u8>>,
    finding: Finding,
}
impl Operation for UnsetOperation {
    fn filter_id(&self) -> &'static str {
        ID
    }
    fn description(&self) -> Option<crate::filters::Correction> {
        Some(unchanged(&self.finding))
    }
    fn word_writes(&self) -> Vec<Word> {
        vec![self.word]
    }
    fn integrity(&self) -> Option<Integrity> {
        self.inner.as_ref().and_then(|op| op.integrity())
    }
    fn prepare(&self, context: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
        bound_target(context, &self.hardware, &self.normal, self.kernel.as_deref())?;
        match &self.inner {
            Some(op) => op.prepare(context),
            None => Ok(None),
        }
    }
    fn verify(&self, context: &Preparation<'_>, normal: &[u8]) -> Result<(), Error> {
        if self.word.value != UNSET {
            return Err(Error::Unsupported);
        }
        bound_target(context, &self.hardware, &self.normal, self.kernel.as_deref())?;
        match &self.inner {
            Some(op) => op.verify(context, normal),
            None => Ok(()),
        }
    }
}

/// The operation was planned for exactly this target pair.
fn bound_target(
    context: &Preparation<'_>,
    hardware: &str,
    normal: &[u8],
    kernel: Option<&[u8]>,
) -> Result<(), Error> {
    if context.target.hardware != hardware
        || context.target.normal != normal
        || context.target.kernel != kernel
    {
        return Err(Error::ComponentMismatch);
    }
    #[cfg(feature = "envelope")]
    {
        if context.normal.is_some_and(|image| {
            image.image != normal
                || image.info().kind != crate::ComponentKind::Normal
                || image.info().hardware_version != hardware
        }) || context.kernel.is_some_and(|image| {
            Some(image.image.as_slice()) != kernel
                || image.info().kind != crate::ComponentKind::Kernel
                || image.info().hardware_version != hardware
        }) {
            return Err(Error::ComponentMismatch);
        }
    }
    Ok(())
}

/// `installed_absent` is the installed side's bounded gate-absent proof. With
/// it, a failed read-only target-word fallback is a definite refusal: B checks
/// a word A's firmware never maintains, it cannot be verified through a
/// differing or non-Normal reader, and a word is written only for a bound
/// installed comparison.
/// `finding` is the target's assessment, reported unchanged.
pub(super) fn plan(
    transition: &Transition<'_, '_>,
    installed_absent: bool,
    finding: &Finding,
) -> Result<Option<Box<dyn Operation>>, Error> {
    let installed = transition.installed.firmware;
    let target = transition.target.firmware;
    if transition.installed.sat.is_none() {
        return Err(Error::UnresolvedIdentity);
    }
    let gate = Gate::bind(target.normal);
    if gate.is_err() {
        if let Some(operation) = PreservationOperation::bind(transition, finding)? {
            return Ok(Some(Box::new(operation)));
        }
        // Exact component preservation proves no new startup requirement even
        // if this architecture's comparison is not recognized. This is not an
        // absence proof and supplies no guessed live word.
        if installed.normal == target.normal && installed.kernel == target.kernel {
            return Ok(None);
        }
    }
    let gate = gate?;
    let required = gate.bound.requirement.required;
    // Whether the drive already holds `required`: only an installed FIXED gate
    // proves it (the drive boots that firmware, so its word passes that gate).
    // An installed conditional gate may be satisfied by its alternative word.
    let proven_equal = match startup::bound_selection(installed.normal) {
        Observation::Known(donor) => {
            if donor.layout != gate.bound.layout {
                return Err(Error::Incompatible);
            }
            donor.requirement.required == required
                && Gate::bind(installed.normal).is_ok_and(|g| g.conditional.is_none())
        }
        Observation::Conflicting => return Err(Error::UnresolvedIdentity),
        Observation::Unresolved(_) => {
            // The installed requirement is unknown, so the drive's word is not
            // proven: set the target's own word. The installed Normal must still
            // read the word through the same layout, or the write would not land
            // where the target reads it. Missing installed evidence stays
            // unresolved; a proven-absent installed gate makes it a refusal.
            let refusal = if installed_absent {
                Error::Incompatible
            } else {
                Error::UnresolvedIdentity
            };
            let Observation::Known(reader) = layout::discover_h8_reader(installed.normal, None)
            else {
                return Err(refusal);
            };
            if reader.component != H8ReaderComponent::Normal || reader.layout != gate.bound.layout {
                return Err(refusal);
            }
            false
        }
    };
    // An unproven word is corrected on the drive, not in the image: the target
    // gate stays unchanged and the startup word is set to the target's own
    // primary value, the state of a unit that shipped with the target firmware,
    // whose own writer keeps that value. This holds for a conditional gate too:
    // its primary word is accepted unconditionally (the predicate only gates
    // the alternative), and the CMP operand is never rewritten here, so the
    // conditional predicate is preserved intact. `admits_unchanged` still
    // refuses the one unsafe shape (a conditional gate whose primary word is
    // the equal-branch alternative).
    let sets_word = !proven_equal;
    gate.admits_unchanged()?;
    Ok(Some(Box::new(StartupOperation {
        hardware: target.hardware.into(),
        normal: target.normal.to_vec(),
        kernel: target.kernel.map(<[u8]>::to_vec),
        gate,
        required,
        sets_word,
        finding: finding.clone(),
    })))
}

/// A native requirement-preservation certificate participates in the same
/// prepare/verify transaction as an unchanged comparison, including after phase edits.
/// Its theorem is target-local predicate/component invariance. Independent bank
/// selection and the automatic OEM parameter-writer lifecycle are not inferred
/// merely from equal reader layouts or from this certificate's presence.
#[derive(Debug)]
struct PreservationOperation {
    hardware: String,
    normal: Vec<u8>,
    kernel: Option<Vec<u8>>,
    certificate: startup::coverage::preservation::Certificate,
    finding: Finding,
}
impl PreservationOperation {
    fn bind(transition: &Transition<'_, '_>, finding: &Finding) -> Result<Option<Self>, Error> {
        let source = transition.installed.firmware;
        let target = transition.target.firmware;
        let Observation::Known(installed_reader) = layout::discover_h8_reader(source.normal, None)
        else {
            return Ok(None);
        };
        let Observation::Known(target_reader) = layout::discover_h8_reader(target.normal, None)
        else {
            return Ok(None);
        };
        if installed_reader.component != H8ReaderComponent::Normal
            || target_reader.component != H8ReaderComponent::Normal
            || installed_reader.layout != target_reader.layout
        {
            return Ok(None);
        }
        let installed_certificate =
            startup::coverage::preservation::discover_pair(source.normal, source.kernel);
        let certificate =
            startup::coverage::preservation::discover_pair(target.normal, target.kernel);
        // Positive native-integrity failure is a refusal, not missing evidence
        // which may fall through to the unknown exact-pair preservation path.
        if installed_certificate
            .as_ref()
            .is_some_and(|certificate| !certificate.final_integrity(source.normal, source.kernel))
            || certificate.as_ref().is_some_and(|certificate| {
                !certificate.final_integrity(target.normal, target.kernel)
            })
        {
            return Err(Error::VerificationFailed);
        }
        let (Some(_), Some(certificate)) = (installed_certificate, certificate) else {
            return Ok(None);
        };
        Ok(Some(Self {
            hardware: target.hardware.into(),
            normal: target.normal.to_vec(),
            kernel: target.kernel.map(<[u8]>::to_vec),
            certificate,
            finding: finding.clone(),
        }))
    }
    fn bound(&self, context: &Preparation<'_>) -> Result<(), Error> {
        bound_target(context, &self.hardware, &self.normal, self.kernel.as_deref())
    }
}
impl Operation for PreservationOperation {
    fn filter_id(&self) -> &'static str {
        ID
    }
    fn description(&self) -> Option<crate::filters::Correction> {
        Some(unchanged(&self.finding))
    }
    fn prepare(&self, context: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
        self.verify(context, &self.normal)?;
        Ok(None)
    }
    fn verify(&self, context: &Preparation<'_>, normal: &[u8]) -> Result<(), Error> {
        self.bound(context)?;
        if !self
            .certificate
            .preserves(&self.normal, normal, self.kernel.as_deref())
            || !self
                .certificate
                .final_integrity(normal, self.kernel.as_deref())
        {
            return Err(Error::VerificationFailed);
        }
        Ok(())
    }
}

struct StartupOperation {
    hardware: String,
    normal: Vec<u8>,
    kernel: Option<Vec<u8>>,
    gate: Gate,
    required: u16,
    /// The drive's word is not proven equal and is set to `required` before
    /// transfer (the old value is snapshotted for restore).
    sets_word: bool,
    finding: Finding,
}

/// The target comparison is never rewritten: its finding is unchanged.
fn unchanged(finding: &Finding) -> crate::filters::Correction {
    crate::filters::Correction::Registered {
        filter: ID,
        from: finding.clone(),
        to: finding.clone(),
    }
}
impl core::fmt::Debug for StartupOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StartupOperation")
            .field("hardware", &self.hardware)
            .field("comparison", &self.gate.comparison)
            .field("required", &self.required)
            .field("sets_word", &self.sets_word)
            .finish()
    }
}
impl StartupOperation {
    fn word(&self) -> Word {
        Word {
            parameter: self.gate.bound.requirement.parameter,
            value: self.required,
        }
    }
    fn bound(&self, context: &Preparation<'_>) -> Result<(), Error> {
        // Enforce the planning restriction again at prepare/final verification;
        // a stale or constructed operation cannot write a drive word other
        // than the target's own bound requirement.
        if self.required != self.gate.bound.requirement.required {
            return Err(Error::Unsupported);
        }
        if context.target.hardware != self.hardware
            || context.target.normal != self.normal
            || context.target.kernel != self.kernel.as_deref()
        {
            return Err(Error::ComponentMismatch);
        }
        #[cfg(feature = "envelope")]
        {
            use crate::{envelope::Layout, ComponentKind};
            if let Some(normal) = context.normal {
                if normal.image != self.normal
                    || normal.info().hardware_version != self.hardware
                    || normal.info().kind != ComponentKind::Normal
                {
                    return Err(Error::ComponentMismatch);
                }
                if !matches!(
                    normal.info().layout,
                    Layout::Normal | Layout::NormalReverse | Layout::NormalScaledKey
                ) {
                    return Err(Error::Representation);
                }
                if context.target.kernel.is_some() && context.kernel.is_none() {
                    return Err(Error::UnresolvedIdentity);
                }
            }
            if let Some(kernel) = context.kernel {
                if Some(kernel.image.as_slice()) != self.kernel.as_deref()
                    || kernel.info().hardware_version != self.hardware
                    || kernel.info().kind != ComponentKind::Kernel
                {
                    return Err(Error::ComponentMismatch);
                }
                if let Some(normal) = context.normal {
                    let n = normal.header_info();
                    let k = kernel.header_info();
                    for (a, b) in [
                        (&n.hardware_version, &k.hardware_version),
                        (&n.destination, &k.destination),
                        (&n.kernel_version, &k.kernel_version),
                        (&n.kernel_version2, &k.kernel_version2),
                    ] {
                        if a.is_empty() || a != b {
                            return Err(Error::ComponentMismatch);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
impl Operation for StartupOperation {
    fn filter_id(&self) -> &'static str {
        ID
    }
    fn description(&self) -> Option<crate::filters::Correction> {
        Some(unchanged(&self.finding))
    }
    fn word_writes(&self) -> Vec<Word> {
        if self.sets_word {
            vec![self.word()]
        } else {
            Vec::new()
        }
    }
    fn integrity(&self) -> Option<Integrity> {
        Some(crate::filters::be32_normal_integrity())
    }
    fn prepare(&self, context: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
        self.verify(context, &self.normal)?;
        Ok(None)
    }
    fn verify(&self, context: &Preparation<'_>, normal: &[u8]) -> Result<(), Error> {
        self.bound(context)?;
        if normal.len() != self.normal.len() {
            return Err(Error::VerificationFailed);
        }
        self.gate.admits_unchanged()?;
        for span in &self.gate.protected {
            if normal.get(span.clone()) != self.normal.get(span.clone()) {
                return Err(Error::VerificationFailed);
            }
        }
        let gate = Gate::bind(normal).map_err(|_| Error::VerificationFailed)?;
        if gate.bound.requirement.required != self.required
            || gate.bound.layout != self.gate.bound.layout
            || gate.comparison != self.gate.comparison
            || gate.conditional != self.gate.conditional
        {
            return Err(Error::VerificationFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compatibility::Firmware,
        filters::{Context, Filter},
    };

    fn fixture(required: u16, variant: usize) -> Vec<u8> {
        let mut normal = vec![0xff; 0x8000];
        crate::image::layout::install_test_layout_variant(&mut normal, 0x1000, variant);
        normal[0x80..0x94].copy_from_slice(&[
            0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
            0x41, 0x60, 0,
        ]);
        normal[0x8a..0x8c].copy_from_slice(&required.to_be_bytes());
        normal[0x6000..0x6006].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        normal
    }
    fn context(normal: &[u8]) -> Context<'_> {
        Context::new(Firmware {
            hardware: "SAT 8000",
            normal,
            kernel: None,
        })
    }
    fn operation(installed: &[u8], target: &[u8]) -> Result<Option<Box<dyn Operation>>, Error> {
        let installed = context(installed);
        let target = context(target);
        super::super::FILTER.plan(
            &Transition {
                installed: &installed,
                target: &target,
            },
            &super::super::inspect(&installed),
            &super::super::inspect(&target),
        )
    }
    fn preparation(normal: &[u8]) -> Preparation<'_> {
        Preparation {
            target: context(normal).firmware,
            #[cfg(feature = "envelope")]
            normal: None,
            #[cfg(feature = "envelope")]
            kernel: None,
        }
    }

    #[test]
    fn filter_preserves_unchanged_comparison_and_needs_no_word_when_proven() {
        let mut installed = fixture(0xfe24, 0);
        installed[0x7000] ^= 1;
        let target = fixture(0xfe24, 0);
        let operation = operation(&installed, &target).unwrap().unwrap();
        assert_eq!(operation.filter_id(), "startup-prerequisite");
        // The installed fixed gate proves the drive's word: no read, no write.
        assert!(operation.required_words().is_empty());
        assert!(operation.word_writes().is_empty());
        assert!(super::super::FILTER
            .parameters(&context(&target))
            .unwrap()
            .is_empty());
        let preparation = preparation(&target);
        assert!(operation.prepare(&preparation).unwrap().is_none());
        operation.verify(&preparation, &target).unwrap();
        for offset in [0x80, 0x84, 0x8a, 0x8c, 0x8e, 0x1000, 0x6000] {
            let mut bad = target.clone();
            bad[offset] ^= 1;
            assert!(
                operation.verify(&preparation, &bad).is_err(),
                "offset {offset:#x}"
            );
        }
        // Other owners may change disjoint image bytes during atomic composition.
        let mut composed = target.clone();
        composed[0x7000] ^= 1;
        operation.verify(&preparation, &composed).unwrap();
        assert!(operation.prepare(&self::preparation(&installed)).is_err());
    }

    #[test]
    fn equal_fixed_gate_needs_no_word_and_no_image_effect() {
        let normal = fixture(0xfe24, 0);
        let operation = operation(&normal, &normal).unwrap().unwrap();
        assert!(operation.required_words().is_empty());
        assert!(operation.word_writes().is_empty());
        assert!(operation.prepare(&preparation(&normal)).unwrap().is_none());
    }

    #[test]
    fn differing_fixed_comparisons_set_the_target_word_without_changing_the_image() {
        for (source, target) in [(0xfe25, 0xfe24), (0xfe24, 0xfe25)] {
            let target = fixture(target, 0);
            let operation = operation(&fixture(source, 0), &target).unwrap().unwrap();
            let word = Word {
                parameter: 0x9f,
                value: u16::from_be_bytes([target[0x8a], target[0x8b]]),
            };
            assert!(operation.required_words().is_empty());
            assert_eq!(operation.word_writes(), [word]);
            let preparation = preparation(&target);
            assert!(operation.prepare(&preparation).unwrap().is_none());
            operation.verify(&preparation, &target).unwrap();
            // The target comparison itself is never rewritten.
            let mut rewritten = target.clone();
            rewritten[0x8b] ^= 1;
            assert!(operation.verify(&preparation, &rewritten).is_err());
        }
        // Equal comparisons stay a read-only prerequisite with no write.
        let normal = fixture(0xfe24, 0);
        let equal = operation(&normal, &normal).unwrap().unwrap();
        assert!(equal.word_writes().is_empty());
    }

    #[test]
    fn startup_operations_report_the_target_comparison_as_unchanged() {
        // The generic description would claim the target adopts the installed
        // finding; these operations never change the comparison.
        use crate::filters::Correction;
        let mut no_gate = fixture(0xfe24, 0);
        no_gate[0x80..0x94].fill(0xff);
        for (installed, target) in [
            (fixture(0xfe24, 0), fixture(0xfe25, 0)),
            (no_gate, fixture(0xfe24, 0)),
        ] {
            let finding = super::super::inspect(&context(&target)).finding;
            assert_ne!(
                finding,
                super::super::inspect(&context(&installed)).finding,
                "fixture must distinguish the directions"
            );
            let operation = operation(&installed, &target).unwrap().unwrap();
            assert_eq!(
                operation.description(),
                Some(Correction::Registered {
                    filter: ID,
                    from: finding.clone(),
                    to: finding,
                })
            );
        }
    }

    #[test]
    fn operation_and_final_comparison_cannot_bypass_unchanged_operand_restriction() {
        let target = fixture(0xfe24, 0);
        let prepared = preparation(&target);
        let op = operation(&target, &target).unwrap().unwrap();
        let mut tampered = target.clone();
        tampered[0x8b] = 0x25;
        assert!(matches!(
            op.verify(&prepared, &tampered),
            Err(Error::VerificationFailed)
        ));
        // Even a stale/preconstructed operation carrying a different desired word
        // must refuse before preparation or final-output verification can approve it.
        let forged = StartupOperation {
            hardware: "SAT 8000".into(),
            normal: target.clone(),
            kernel: None,
            gate: Gate::bind(&target).unwrap(),
            required: 0xfe25,
            sets_word: false,
            finding: Finding::Unresolved("forged".into()),
        };
        assert!(matches!(forged.prepare(&prepared), Err(Error::Unsupported)));
        assert!(matches!(
            forged.verify(&prepared, &tampered),
            Err(Error::Unsupported)
        ));
    }

    #[test]
    fn unresolved_source_keeps_target_word_fallback_and_unknown_exact_pairs() {
        let normal = fixture(0xfe24, 0);
        let mut no_gate = normal.clone();
        no_gate[0x80..0x94].fill(0xff);
        // An unproven installed word is set, never required: the live word is
        // read only to snapshot it for restore.
        let condition = operation(&no_gate, &normal).unwrap().unwrap();
        assert!(condition.required_words().is_empty());
        assert_eq!(
            condition.word_writes(),
            [Word {
                parameter: 0x9f,
                value: 0xfe24
            }]
        );
        // An installed fixed gate with the same word proves the drive's word:
        // nothing is read or written.
        let proven = operation(&normal, &normal).unwrap().unwrap();
        assert!(proven.required_words().is_empty());
        assert!(proven.word_writes().is_empty());
        assert!(condition.prepare(&preparation(&normal)).unwrap().is_none());
        assert!(operation(&normal, &no_gate).is_err());
        assert!(operation(&no_gate, &no_gate).unwrap().is_none());
        let mut different = no_gate.clone();
        different[0x7000] ^= 1;
        assert!(operation(&no_gate, &different).is_err());
    }

    #[test]
    fn conditional_alternative_is_not_erased_or_promoted_to_unconditional_acceptance() {
        let target = h8_conditional::tests::fixture(0x1000, 0x4000, 0x5000);
        let installed = fixture(0xfe23, 5);
        let operation = operation(&installed, &target).unwrap().unwrap();
        let prepared = preparation(&target);
        assert!(operation.prepare(&prepared).unwrap().is_none());
        operation.verify(&prepared, &target).unwrap();
        let gate = Gate::bind(&target).unwrap();
        assert_eq!(gate.bound.requirement.required, 0xfe23);
        assert_eq!(gate.conditional, Gate::bind(&target).unwrap().conditional);
        for offset in [0x90, 0x94, 0x4000 + 253, 0x4000 + 279, 0x5000 + 10] {
            let mut bad = target.clone();
            bad[offset] ^= 1;
            assert!(operation.verify(&prepared, &bad).is_err(), "{offset:#x}");
        }
        // A differing fixed donor (whether the primary alternative FE09 or an
        // unrelated FE24) now sets the conditional target's primary word on the
        // drive and leaves the image and predicate unchanged: the primary is
        // accepted unconditionally, so this is as safe as the fixed-gate case.
        for donor in [0xfe09u16, 0xfe24] {
            let set = self::operation(&fixture(donor, 5), &target)
                .unwrap()
                .unwrap();
            assert!(set.prepare(&prepared).unwrap().is_none());
            assert!(set.required_words().is_empty());
            assert_eq!(
                set.word_writes(),
                [Word {
                    parameter: 0x9f,
                    value: 0xfe23
                }],
                "donor {donor:#06x}"
            );
            set.verify(&prepared, &target).unwrap();
        }
        // A conditional shape without its complete predicate cannot be admitted.
        let mut incomplete = target.clone();
        incomplete[0x4000 + 253] ^= 1;
        assert!(self::operation(&installed, &incomplete).is_err());
    }

    #[test]
    fn unchanged_indirect_getter_and_long_branch_keep_original_abi_and_call_address() {
        let installed = fixture(0xfe24, 0);
        for load_before in [false, true] {
            let mut target = fixture(0xfe24, 0);
            target[0x80..0xa0].fill(0xff);
            let load = [0x7a, 5, 0, 0x41, 0x10, 0];
            let param = [0x79, 0, 0, 0x9f];
            let mut code = vec![];
            if load_before {
                code.extend(load);
                code.extend(param);
            } else {
                code.extend(param);
                code.extend(load);
            }
            code.extend([
                0x5d, 0x50, 0x79, 0x20, 0xfe, 0x24, 0x58, 0x70, 0, 6, 0xf8, 1, 0x5e, 0x41, 0x60, 0,
            ]);
            target[0x80..0x80 + code.len()].copy_from_slice(&code);
            let op = operation(&installed, &target).unwrap().unwrap();
            assert!(op.required_words().is_empty());
            assert!(op.word_writes().is_empty());
            assert!(op.prepare(&preparation(&target)).unwrap().is_none());
            op.verify(&preparation(&target), &target).unwrap();
        }
    }

    /// Independent instruction execution of the complete native gate. Getter and
    /// predicate calls are explicit inputs; Kernel loader service calls are outputs.
    fn native_accepts(code: &[u8], word: u16, predicate: bool, saved_flag: bool) -> (bool, usize) {
        let mut registers = [0u32; 8];
        registers[4] = u32::from(saved_flag);
        let mut zero = false;
        let mut at = 0;
        let mut rejected = false;
        let mut predicate_calls = 0;
        let get = |registers: &[u32; 8], reg| match reg {
            Reg::Byte(n) => (registers[(n % 8) as usize] >> if n < 8 { 8 } else { 0 }) & 255,
            Reg::Word(n) => (registers[(n % 8) as usize] >> if n < 8 { 0 } else { 16 }) & 65535,
            Reg::Long(n) => registers[n as usize],
            _ => panic!("unsupported register {reg:?}"),
        };
        let value = |registers: &[u32; 8], operand| match operand {
            Operand::Register(reg) => get(registers, reg),
            Operand::Immediate { value, .. } => value,
            _ => panic!("unsupported operand {operand:?}"),
        };
        for _ in 0..64 {
            if at == code.len() {
                return (!rejected, predicate_calls);
            }
            let d = decode_insn(&code[at..], Target::H8S2000, Mode::Advanced).unwrap();
            let [a, b, _] = d.insn.operands;
            at += d.len;
            match (d.insn.mnemonic, a, b) {
                ("MOV" | "SUB", a, Operand::Register(reg)) => {
                    let result = if d.insn.mnemonic == "MOV" {
                        value(&registers, a)
                    } else {
                        get(&registers, reg).wrapping_sub(value(&registers, a))
                    };
                    let (n, shift, mask) = match reg {
                        Reg::Byte(n) => (n % 8, if n < 8 { 8 } else { 0 }, 255),
                        Reg::Word(n) => (n % 8, if n < 8 { 0 } else { 16 }, 65535),
                        Reg::Long(n) => (n, 0, u32::MAX),
                        _ => panic!("{reg:?}"),
                    };
                    let old = &mut registers[n as usize];
                    *old = (*old & !(mask << shift)) | ((result & mask) << shift);
                    zero = result & mask == 0;
                }
                ("CMP", a, b) => zero = value(&registers, a) == value(&registers, b),
                ("BEQ" | "BNE", Operand::Address(Ea::PcRelative { value, .. }), _) => {
                    if (d.insn.mnemonic == "BEQ") == zero {
                        at = at.checked_add_signed(value as isize).unwrap();
                    }
                }
                ("JSR", Operand::Address(Ea::Absolute { value, .. }), _) => match value {
                    0x411000 => {
                        assert_eq!(registers[0] & 65535, 0x9f);
                        registers[0] = u32::from(word);
                    }
                    0x414000 => {
                        registers[0] = u32::from(predicate);
                        predicate_calls += 1;
                    }
                    0x415110 | 0x416000 => {
                        assert_eq!(registers[0] & 255, 1);
                        rejected = true;
                    }
                    0x415100 | 0x415120 => {}
                    _ => panic!("unknown native service {value:#x}"),
                },
                other => panic!("unsupported native instruction {other:?}"),
            }
        }
        panic!("native gate did not terminate");
    }

    #[test]
    fn unchanged_conditional_gate_preserves_native_word_and_predicate_semantics() {
        let conditional = h8_conditional::tests::fixture(0x1000, 0x4000, 0x5000);
        let donor = fixture(0xfe23, 5);
        let op = operation(&donor, &conditional).unwrap().unwrap();
        assert!(op.prepare(&preparation(&conditional)).unwrap().is_none());
        for word in 0..=u16::MAX {
            for predicate in [false, true] {
                for saved_flag in [false, true] {
                    let (accepted, calls) =
                        native_accepts(&conditional[0x80..0xbc], word, predicate, saved_flag);
                    assert_eq!(
                        accepted,
                        word == 0xfe23 || (word == 0xfe09 && predicate),
                        "{word:04x}/{predicate}/{saved_flag}"
                    );
                    assert_eq!(calls, usize::from(word == 0xfe09));
                }
            }
        }
        let simple = fixture(0xfe25, 0);
        for word in 0..=u16::MAX {
            assert_eq!(
                native_accepts(&simple[0x80..0x94], word, false, false),
                (word == 0xfe25, 0)
            );
        }
    }

    #[test]
    fn native_oem_rejection_continuation_is_preserved_after_the_flag_service() {
        // Held SAT8801 OEM form. The final call follows the proven loader-flag
        // service; it must remain unchanged, not be mistaken for another gate.
        let mut target = fixture(0xfe13, 0);
        target[0x8c..0xa4].copy_from_slice(&[
            0x47, 0x16, 0x0c, 0xee, 0x47, 0x06, 0xf8, 1, 0x5e, 0x41, 0x60, 0x10, 0xf8, 1, 0x5e,
            0x41, 0x60, 0, 0x18, 0x88, 0x5e, 0x41, 0x61, 0,
        ]);
        target[0x6010..0x6016].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x14, 0x54, 0x70]);
        target[0x6100..0x6106].copy_from_slice(&[0x01, 0x10, 0x6d, 0xf4, 0x0c, 0x8c]);
        let donor = fixture(0xfe13, 0);
        let op = operation(&donor, &target).unwrap().unwrap();
        assert!(op.prepare(&preparation(&target)).unwrap().is_none());
        op.verify(&preparation(&target), &target).unwrap();
        // A differing fixed donor keeps this image and sets the target's word.
        let set = operation(&fixture(0xfe24, 0), &target).unwrap().unwrap();
        assert!(set.prepare(&preparation(&target)).unwrap().is_none());
        assert_eq!(
            set.word_writes(),
            [Word {
                parameter: 0x9f,
                value: 0xfe13
            }]
        );
    }
}

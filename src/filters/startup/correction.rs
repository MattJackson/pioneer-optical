//! Bound startup comparison edits. The existing device word is never changed.
use super::{h8_conditional, ID};
use crate::{
    compatibility::Error,
    filters::{prerequisites::Word, Integrity, Operation, Preparation, Transition},
    image::layout::{self, H8ReaderComponent, Observation},
    startup::{self, BoundSelection},
};
use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, encode_insn, Ea, Operand, Reg},
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

    fn emit(&self, normal: &[u8], required: u16) -> Result<Vec<u8>, Error> {
        // FE09 must continue through its predicate, never become the equal
        // branch of a conditional gate after an operand correction.
        if self.conditional.is_some() && required == 0xfe09 {
            return Err(Error::Unsupported);
        }
        let mut instruction = decode_insn(
            &normal[self.comparison.clone()],
            Target::H8S2000,
            Mode::Advanced,
        )
        .map_err(|_| Error::Representation)?
        .insn;
        instruction.operands[0] = Operand::Immediate {
            value: u32::from(required),
            bits: 16,
        };
        let encoded = encode_insn(instruction, Target::H8S2000, Mode::Advanced)
            .map_err(|_| Error::Representation)?;
        if encoded.len() != self.comparison.len() {
            return Err(Error::Representation);
        }
        let mut changed = normal.to_vec();
        changed[self.comparison.clone()].copy_from_slice(&encoded);
        Ok(changed)
    }
}

pub(super) fn plan(transition: &Transition<'_, '_>) -> Result<Option<Box<dyn Operation>>, Error> {
    let installed = transition.installed.firmware;
    let target = transition.target.firmware;
    if transition.installed.sat.is_none() {
        return Err(Error::UnresolvedIdentity);
    }
    if Gate::bind(target.normal).is_err() {
        if let Some(operation) = PreservationOperation::bind(transition)? {
            return Ok(Some(Box::new(operation)));
        }
    }
    // Exact component preservation proves no new startup requirement even if
    // this architecture's comparison is not recognized. This is not an absence
    // proof and supplies no guessed live word.
    if installed.normal == target.normal
        && installed.kernel == target.kernel
        && Gate::bind(target.normal).is_err()
    {
        return Ok(None);
    }
    let gate = Gate::bind(target.normal)?;
    let required = match startup::bound_selection(installed.normal) {
        Observation::Known(donor) => {
            if donor.layout != gate.bound.layout {
                return Err(Error::Incompatible);
            }
            donor.requirement.required
        }
        Observation::Conflicting => return Err(Error::UnresolvedIdentity),
        Observation::Unresolved(_) => {
            // A live read can establish the target's accepted branch without
            // guessing what the installed image requires. Keep the entire
            // target gate unchanged and require its already-stored value.
            let Observation::Known(reader) = layout::discover_h8_reader(installed.normal, None)
            else {
                return Err(Error::UnresolvedIdentity);
            };
            if reader.component != H8ReaderComponent::Normal || reader.layout != gate.bound.layout {
                return Err(Error::UnresolvedIdentity);
            }
            gate.bound.requirement.required
        }
    };
    let changed = gate.emit(target.normal, required)?;
    let corrected = Gate::bind(&changed)?;
    if corrected.bound.requirement.required != required || corrected.conditional != gate.conditional
    {
        return Err(Error::VerificationFailed);
    }
    Ok(Some(Box::new(StartupOperation {
        hardware: target.hardware.into(),
        normal: target.normal.to_vec(),
        kernel: target.kernel.map(<[u8]>::to_vec),
        gate,
        required,
    })))
}

/// A native requirement-preservation certificate participates in the same
/// prepare/verify transaction as a comparison edit, including after phase edits.
#[derive(Debug)]
struct PreservationOperation {
    hardware: String,
    normal: Vec<u8>,
    kernel: Option<Vec<u8>>,
    certificate: startup::coverage::preservation::Certificate,
}
impl PreservationOperation {
    fn bind(transition: &Transition<'_, '_>) -> Result<Option<Self>, Error> {
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
        }))
    }
    fn bound(&self, context: &Preparation<'_>) -> Result<(), Error> {
        if context.target.hardware != self.hardware
            || context.target.normal != self.normal
            || context.target.kernel != self.kernel.as_deref()
        {
            return Err(Error::ComponentMismatch);
        }
        #[cfg(feature = "envelope")]
        {
            if context.normal.is_some_and(|image| {
                image.image != self.normal
                    || image.info().kind != crate::ComponentKind::Normal
                    || image.info().hardware_version != self.hardware
            }) || context.kernel.is_some_and(|image| {
                Some(image.image.as_slice()) != self.kernel.as_deref()
                    || image.info().kind != crate::ComponentKind::Kernel
                    || image.info().hardware_version != self.hardware
            }) {
                return Err(Error::ComponentMismatch);
            }
        }
        Ok(())
    }
}
impl Operation for PreservationOperation {
    fn filter_id(&self) -> &'static str {
        ID
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
}
impl core::fmt::Debug for StartupOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StartupOperation")
            .field("hardware", &self.hardware)
            .field("comparison", &self.gate.comparison)
            .field("required", &self.required)
            .finish()
    }
}
impl StartupOperation {
    fn bound(&self, context: &Preparation<'_>) -> Result<(), Error> {
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
    fn required_words(&self) -> Vec<Word> {
        vec![Word {
            parameter: self.gate.bound.requirement.parameter,
            value: self.required,
        }]
    }
    fn integrity(&self) -> Option<Integrity> {
        Some(crate::filters::be32_normal_integrity())
    }
    fn prepare(&self, context: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
        self.bound(context)?;
        let changed = self.gate.emit(&self.normal, self.required)?;
        self.verify(context, &changed)?;
        if changed == self.normal {
            Ok(None)
        } else {
            Ok(Some(changed))
        }
    }
    fn verify(&self, context: &Preparation<'_>, normal: &[u8]) -> Result<(), Error> {
        self.bound(context)?;
        if normal.len() != self.normal.len() {
            return Err(Error::VerificationFailed);
        }
        let expected = self.gate.emit(&self.normal, self.required)?;
        for span in &self.gate.protected {
            if normal.get(span.clone()) != expected.get(span.clone()) {
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
mod tests;

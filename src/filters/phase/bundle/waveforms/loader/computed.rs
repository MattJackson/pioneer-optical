//! Computed DSP coefficients retain their native scaling graph. Raw signed
//! basis words are deliberately distinct from already scaled byte coefficients.
use super::*;
use crate::filters::phase::{bundle::waveforms::resources::evaluators, native};
use h8_asm::{
    isa::{decode_insn, encode_insn, Ea, Operand},
    Mode, Target,
};

/// All local resources consumed by the complete computed DSP loader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Complete loader and DSP helper wiring.
    pub loader: super::Binding,
    /// Raw signed basis, before native multiply/divide, clipping and extraction.
    pub basis: Range<usize>,
    /// Complete eight-mode calibration getter.
    pub calibration_program: Range<usize>,
    /// Constant or parameter-backed calibration source contract.
    pub calibration: evaluators::Calibration,
    /// Retained opaque native multiplication and division entry points.
    pub arithmetic: [u32; 2],
    /// Complete context-provider body used by the mode reader.
    pub mode_context: Range<usize>,
    /// Complete mode reader body.
    pub mode_reader: Range<usize>,
    /// Context RAM, initialization flag, and retained native initializer.
    pub mode_state: [u32; 3],
}
const CONTEXT: Template = t!(0x01 0x00 0x6d 0xf3 0x7a 0x03 _ _ _ _ 0x6b 0x20 _ _ _ _ 0x46 0x10 0x79 0x01 0x00 0x01 0x6b 0xa1 _ _ _ _ 0x0f 0xb0 0x5e _ _ _ 0x0f 0xb0 0x01 0x00 0x6d 0x73 0x54 0x70);
const MODE: Template = t!(0x6e 0x09 0x00 0x04 0x47 0x10 0xa9 0x01 0x47 0x0c 0xa9 0x02 0x46 0x04 0xf8 0x04 0x40 0x06 0x18 0x88 0x40 0x02 0xf8 0x03 0x54 0x70);

fn span(normal: &[u8], address: u32, length: usize) -> Result<Range<usize>, Error> {
    let start = address
        .checked_sub(0x410000)
        .ok_or(Error::ResourceMismatch)? as usize;
    let end = start.checked_add(length).ok_or(Error::ResourceMismatch)?;
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    if address & 1 != 0
        || !regions.stored.iter().any(|r| {
            let at = r.as_ptr() as usize - normal.as_ptr() as usize;
            start >= at && end <= at + r.len()
        })
    {
        return Err(Error::ResourceMismatch);
    }
    Ok(start..end)
}
fn body(normal: &[u8], address: u32, template: Template) -> Result<Range<usize>, Error> {
    let range = span(normal, address, template.len())?;
    if !normal[range.clone()]
        .iter()
        .zip(template)
        .all(|(b, t)| t.map_or(true, |t| t == *b))
    {
        return Err(Error::ResourceMismatch);
    }
    Ok(range)
}
fn word(bytes: &[u8], at: usize, length: usize) -> u32 {
    bytes[at..at + length]
        .iter()
        .fold(0, |v, b| v << 8 | u32::from(*b))
}
pub(super) fn validate_fold(normal: &[u8], getter: u32, folded: u16) -> Result<(), Error> {
    let (_, calibration) =
        evaluators::calibration_at(normal, getter).map_err(|_| Error::ResourceMismatch)?;
    let evaluators::Calibration::Constants(values) = calibration else {
        return Err(Error::ComputedUnsupported);
    };
    if (values[1] as u16).wrapping_sub((values[0] as u16).wrapping_mul(2)) != folded {
        return Err(Error::ResourceMismatch);
    }
    Ok(())
}

/// Bind scaling inputs, all shared call roles, mode state and complete DSP
/// writer/readback bodies. Arithmetic calls remain opaque target primitives:
/// transformations must preserve their symbolic arguments and call order.
pub fn observe(normal: &[u8]) -> Result<Binding, Error> {
    let (loader, shape, code) = super::bind(normal)?;
    if !loader.computed {
        return Err(Error::ComputedUnsupported);
    }
    readback::observe(normal, loader.readback, loader.writer)?;
    let calls = shape
        .fields
        .iter()
        .filter(|f| matches!(f.kind, FieldKind::Call))
        .map(|f| value(&code, 0, shape, f.at))
        .collect::<Result<Vec<_>, _>>()?;
    let (calibration_program, calibration) =
        evaluators::calibration_at(normal, calls[0]).map_err(|_| Error::ResourceMismatch)?;
    let basis = span(normal, value(&code, 0, shape, shape.tables[0])?, 72)?;
    let mode_context = body(normal, calls[11], CONTEXT)?;
    let mode_reader = body(normal, calls[12], MODE)?;
    let context = &normal[mode_context.clone()];
    let state = word(context, 6, 4);
    let flag = word(context, 12, 4);
    let initializer = word(context, 31, 3);
    if flag != word(context, 24, 4)
        || state == 0
        || state & 1 != 0
        || flag & 1 != 0
        || initializer & 1 != 0
        || initializer < 0x100000
        || initializer >= 0x410000 + normal.len() as u32
    {
        return Err(Error::ResourceMismatch);
    }
    let mut spans = alloc::vec![
        basis.clone(),
        calibration_program.clone(),
        mode_context.clone(),
        mode_reader.clone()
    ];
    spans.extend(loader.spans.iter().cloned());
    for (i, a) in spans.iter().enumerate() {
        for b in &spans[i + 1..] {
            if a.start < b.end && b.start < a.end {
                return Err(Error::ResourceMismatch);
            }
        }
    }
    Ok(Binding {
        loader,
        basis,
        calibration_program,
        calibration,
        arithmetic: [calls[2], calls[4]],
        mode_context,
        mode_reader,
        mode_state: [state, flag, initializer],
    })
}

fn instruction(code: &[u8], at: usize) -> Result<h8_asm::isa::Insn, Error> {
    Ok(decode_insn(&code[at..], Target::H8S2000, Mode::Advanced)
        .map_err(|_| Error::Unresolved)?
        .insn)
}
fn emit(insn: h8_asm::isa::Insn) -> Result<Vec<u8>, Error> {
    encode_insn(insn, Target::H8S2000, Mode::Advanced).map_err(|_| Error::Unresolved)
}

/// Change only the computed loader's DSP address direction using a complete
/// observed donor's native address arithmetic. The target raw basis, calibration,
/// clipping, mode scaling, call order, saved registers and stack ABI stay intact.
///
/// Space comes from constant-folding the target's native signed-word expression
/// cal[1]-2*cal[0]. Its next SUB.L ER1,ER1 kills temporary R1 and flags before the
/// unchanged opaque multiply. Both getter calls remain. No ROM arithmetic model
/// or calibration writes are introduced. Exact Normal+Kernel ownership is checked
/// before moving instructions. A parameter-backed getter cannot be folded.
pub fn specialize_direction(normal: &[u8], donor: &[u8], kernel: &[u8]) -> Result<Vec<u8>, Error> {
    let before = observe(normal)?;
    let (source, _, source_code) = super::bind(donor)?;
    let descending = match source.loader {
        Loader::Descending | Loader::DescendingNegated17 => true,
        Loader::Ascending | Loader::AscendingNegated17 => false,
    };
    let desired = if descending {
        Loader::DescendingNegated17
    } else {
        Loader::AscendingNegated17
    };
    if before.loader.loader == desired {
        return Ok(normal.to_vec());
    }
    if before.loader.spans.len() != 1 {
        return Err(Error::ComputedUnsupported);
    }
    let original = &before.loader.program;
    native::placement::retirement_loader_references_clear(
        normal,
        kernel,
        original,
        &(original.start + 2..original.end),
    )
    .ok_or(Error::InvalidSpace)?;
    let evaluators::Calibration::Constants(values) = before.calibration else {
        return Err(Error::ComputedUnsupported);
    };
    let folded = (values[1] as u16).wrapping_sub((values[0] as u16).wrapping_mul(2));
    let (_, shape, code) = super::bind(normal)?;
    let compact = shape
        .fields
        .iter()
        .any(|f| matches!(f.kind, FieldKind::Constant));
    let mut changed_code = if compact {
        code.clone()
    } else {
        // MOV.W immediate is taken from the native clipping limit, retargeted to
        // R0; EXTS.L is the original final instruction of the folded expression.
        let mut constant = instruction(&code, 126)?;
        constant.operands[0] = Operand::Immediate {
            value: u32::from(folded),
            bits: 16,
        };
        constant.operands[1] = instruction(&code, 40)?.operands[1];
        let mut out = code[..32].to_vec();
        out.extend(emit(constant)?);
        out.extend_from_slice(&code[42..44]);
        out.extend_from_slice(&code[44..252]);
        let mut padding = [0; 4];
        native::encoding::nops(&mut padding).ok_or(Error::Unresolved)?;
        out.extend_from_slice(&padding[..2]);
        out.extend_from_slice(&code[252..398]);
        out.extend_from_slice(&padding);
        out.extend_from_slice(&code[398..]);
        // The only branch crossing edited regions is the native BCS loop.
        let mut branch = instruction(&code, 280)?;
        let Operand::Address(Ea::PcRelative { value, bits }) = branch.operands[0] else {
            return Err(Error::Unresolved);
        };
        branch.operands[0] = Operand::Address(Ea::PcRelative {
            value: value - 2,
            bits,
        });
        out[276..280].copy_from_slice(&emit(branch)?);
        out
    };
    let (low, high) = if descending {
        if source.computed {
            (
                instruction(&source_code, 252)?,
                instruction(&source_code, 258)?,
            )
        } else {
            let positions = sites(
                &source_code,
                &[&source_code],
                crate::filters::phase::bundle::LOADER_DESCENDING,
            );
            let [at] = positions.as_slice() else {
                return Err(Error::Unresolved);
            };
            let mut low = instruction(&source_code, at + 4)?;
            let mut high = instruction(&source_code, at + 12)?;
            low.mnemonic = "ADD";
            high.mnemonic = "ADD";
            let Operand::Immediate { value, bits } = high.operands[0] else {
                return Err(Error::Unresolved);
            };
            let Operand::Immediate { value: adjust, .. } =
                instruction(&source_code, at + 18)?.operands[0]
            else {
                return Err(Error::Unresolved);
            };
            high.operands[0] = Operand::Immediate {
                value: value.wrapping_add(adjust),
                bits,
            };
            (low, high)
        }
    } else {
        let positions = sites(
            &source_code,
            &[&source_code],
            crate::filters::phase::bundle::LOADER_ASCENDING,
        );
        let [at] = positions.as_slice() else {
            return Err(Error::Unresolved);
        };
        (
            instruction(&source_code, at + 4)?,
            instruction(&source_code, at + 10)?,
        )
    };
    // Native negation is taken from the target's wrapped final coefficient fetch.
    // Changed C/H reach only the fully bound writer: STC saves them, its own
    // comparisons overwrite live flags, and LDC restores them without data use.
    // The retained INC.B; CMP.B #18 loop then kills C/H before its BCS.
    // Thus neither saved status nor a later opaque primitive observes the change.
    if descending {
        let mut neg = instruction(&code, if compact { 160 } else { 166 })?;
        neg.operands[0] = instruction(&changed_code, 244)?.operands[1];
        changed_code[246..248].copy_from_slice(&emit(neg)?);
    } else {
        native::encoding::nops(&mut changed_code[246..248]).ok_or(Error::Unresolved)?;
    }
    changed_code[252..256].copy_from_slice(&emit(low)?);
    changed_code[258..262].copy_from_slice(&emit(high)?);
    let mut changed = normal.to_vec();
    changed[original.clone()].copy_from_slice(&changed_code);
    let after = observe(&changed).map_err(|_| Error::VerificationFailed)?;
    let mut expected = before;
    expected.loader.loader = desired;
    if after != expected {
        return Err(Error::VerificationFailed);
    }
    Ok(changed)
}

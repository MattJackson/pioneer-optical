//! Bounded rewriting of the three native parameter-conversion programs.
//!
//! This is one stage of the mechanism correction, not a complete phase change.
//! It copies no installed call addresses or calibration values. Callers own code
//! space reservations and must compose the remaining bundle stages and checksum.
use super::*;
use core::ops::Range;

/// A conversion rewrite could not be proved without modifying its input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A required native program was absent or ambiguous.
    Unbound(Unbound),
    /// A growing program needs caller-reserved code space.
    SpaceRequired(Element),
    /// A reservation overlaps code, is unaligned, is not stored, or is not erased.
    InvalidSpace,
    /// Call relocation or the detour instruction boundary was not established.
    InvalidProgram,
    /// The output did not bind to the requested native conversions.
    VerificationFailed,
}

struct Program {
    element: Element,
    template: Vec<Option<u8>>,
    variant: u8,
    at: usize,
    body: native::placement::Body,
}
fn programs(normal: &[u8]) -> Result<Vec<Program>, Error> {
    let regions = crate::image::regions(normal).ok_or(Error::InvalidProgram)?;
    [
        (Element::CalibrationBase, BASE.as_slice()),
        (Element::CalibrationOffset, OFFSET.as_slice()),
        (Element::CalibrationStep, STEP.as_slice()),
    ]
    .into_iter()
    .map(|(element, templates)| {
        let (variant, at, body) =
            locate(normal, &regions.stored, templates, element).map_err(Error::Unbound)?;
        Ok(Program {
            element,
            template: matching_template(element, variant, &body.bytes)
                .ok_or(Error::InvalidProgram)?,
            variant,
            at,
            body,
        })
    })
    .collect()
}

/// One declared native JSR in a bound conversion's logical instruction stream.
#[derive(Clone, Debug)]
pub(crate) struct NativeCall {
    /// Offset of the JSR opcode, not its three-byte target operand.
    pub(crate) offset: usize,
    pub(crate) target: u32,
}

/// Complete OEM conversion grammar and its original physical placement.
#[derive(Clone, Debug)]
pub(crate) struct NativeProgram {
    pub(crate) element: Element,
    pub(crate) variant: u8,
    pub(crate) entry: u32,
    pub(crate) body: native::placement::Body,
    pub(crate) calls: Vec<NativeCall>,
}

/// Bind only recognized original/compact native conversion grammars. Every
/// instruction must decode and re-encode byte identically; calls are exposed
/// in their template-declared semantic order for a separate ABI proof.
pub(crate) fn bind_native(normal: &[u8]) -> Result<Vec<NativeProgram>, Error> {
    use h8_asm::{
        isa::{decode_insn, encode_insn},
        Mode, Target,
    };
    programs(normal)?
        .into_iter()
        .map(|program| {
            let mut at = 0;
            while at < program.body.bytes.len() {
                let decoded =
                    decode_insn(&program.body.bytes[at..], Target::H8S2000, Mode::Advanced)
                        .map_err(|_| Error::InvalidProgram)?;
                let encoded = encode_insn(decoded.insn, Target::H8S2000, Mode::Advanced)
                    .map_err(|_| Error::InvalidProgram)?;
                if program.body.bytes.get(at..at + decoded.len) != Some(encoded.as_slice()) {
                    return Err(Error::InvalidProgram);
                }
                at += decoded.len;
            }
            let bound_calls: Vec<_> = calls(&program.template)?
                .into_iter()
                .map(|field| NativeCall {
                    offset: field - 1,
                    target: u32::from_be_bytes([
                        0,
                        program.body.bytes[field],
                        program.body.bytes[field + 1],
                        program.body.bytes[field + 2],
                    ]),
                })
                .collect();
            if bound_calls.iter().any(|call| {
                call.target & 1 != 0
                    || call.target < 0x400000
                    || call.target >= 0x410000 + normal.len() as u32
            }) {
                return Err(Error::InvalidProgram);
            }
            Ok(NativeProgram {
                element: program.element,
                variant: program.variant,
                entry: u32::try_from(BASE_ADDRESS + program.at)
                    .map_err(|_| Error::InvalidProgram)?,
                body: program.body,
                calls: bound_calls,
            })
        })
        .collect()
}

/// Complete bound native conversion bodies, including any instruction spill.
pub(crate) fn protected_ranges(normal: &[u8]) -> Result<Vec<Range<usize>>, Error> {
    Ok(programs(normal)?
        .into_iter()
        .flat_map(|p| p.body.spans)
        .collect())
}

/// Bind contiguous or single-spill OEM conversions through h8-asm searches.
pub(super) fn locate(
    normal: &[u8],
    stored: &[&[u8]],
    templates: &[Template],
    element: Element,
) -> Result<(u8, usize, native::placement::Body), Unbound> {
    let mut found = None;
    let alternatives: Vec<_> = templates
        .iter()
        .enumerate()
        .flat_map(|(variant, template)| {
            let mut forms = alloc::vec![(variant, template.to_vec())];
            if let Some(compact) = compact_template(element, variant as u8) {
                forms.push((variant, compact));
            }
            forms
        })
        .collect();
    for (variant, template) in alternatives {
        // Search a complete first instruction, including any address holes.
        let concrete: Vec<_> = template.iter().map(|b| b.unwrap_or(0)).collect();
        let first =
            h8_asm::isa::decode_insn(&concrete, h8_asm::Target::H8S2000, h8_asm::Mode::Advanced)
                .map_err(|_| Unbound::Missing(element))?;
        for at in sites(normal, stored, &template[..first.len]) {
            if let Some(body) = native::placement::read(normal, stored, at, &template) {
                if found.is_some() {
                    return Err(Unbound::Ambiguous(element));
                }
                found = Some((variant as u8, at, body));
            }
        }
    }
    found.ok_or(Unbound::Missing(element))
}

// Compact forms are derived from the complete recognized OEM body. Only
// instruction operands, native arithmetic identities, and stack temporaries
// change; parameter-helper order and target addresses remain invariant.
fn compact_body(bytes: &[u8], element: Element, variant: u8) -> Option<Vec<u8>> {
    use h8_asm::isa::{decode_insn, encode_insn, Ea, Insn, Operand as O, Reg, Size};
    use h8_asm::{Mode, Target};
    let mut code = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let d = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced).ok()?;
        code.push(d.insn);
        at += d.len;
    }
    let reg = |n| O::Register(Reg::Word(n));
    let byte = |n| O::Register(Reg::Byte(n));
    let ins = |name, size, a, b| Insn::new(name, Some(size), [a, b, O::None]);
    let imm = |value, bits| O::Immediate { value, bits };
    let stack = |push, n| {
        if push {
            ins(
                "MOV",
                Size::Word,
                reg(n),
                O::Address(Ea::PreDecrement(Reg::Long(7))),
            )
        } else {
            ins(
                "MOV",
                Size::Word,
                O::Address(Ea::PostIncrement(Reg::Long(7))),
                reg(n),
            )
        }
    };
    let output = match (element, variant) {
        (Element::CalibrationBase, 1) => {
            if code.len() != 24 {
                return None;
            }
            // -(q + ((p128-1)<<6)) + arg == 64-q-(p128<<6)+arg
            // modulo 16 bits, including every overflow boundary. Two stack
            // words replace the OEM saved ER3 and its register shuffles.
            let mut divide_by = code[12];
            divide_by.operands[1] = reg(1);
            let mut divide = code[13];
            divide.operands[0] = reg(1);
            let mut shift = code[16];
            shift.operands[1] = reg(1);
            alloc::vec![
                stack(true, 1),
                code[2],
                code[3],
                stack(true, 0),
                code[5],
                code[6],
                code[9],
                code[10],
                code[11],
                divide_by,
                divide,
                stack(false, 1),
                ins("DEC", Size::Word, imm(1, 0), reg(1)),
                shift,
                shift,
                shift,
                ins("ADD", Size::Word, reg(1), reg(0)),
                ins("NEG", Size::Word, reg(0), O::None),
                stack(false, 1),
                ins("ADD", Size::Word, reg(1), reg(0)),
                code[23]
            ]
        }
        (Element::CalibrationOffset, 1 | 2) => {
            let multiply = code.iter().position(|i| i.mnemonic == "MULXU")?;
            // OEM mirrors compute (48 - byte) or (80 - byte), masked by 63.
            // Byte wrap is
            // removed by the following word mask before the exact native MUL.
            let mut output = code[..2].to_vec();
            output.push(ins(
                if variant == 1 { "NEG" } else { "NOT" },
                Size::Byte,
                byte(8),
                O::None,
            ));
            output.push(ins(
                "ADD",
                Size::Byte,
                imm(if variant == 1 { 48 } else { 81 }, 8),
                byte(8),
            ));
            output.push(ins("AND", Size::Word, imm(63, 16), reg(0)));
            output.extend_from_slice(&code[multiply.checked_sub(1)?..]);
            output
        }
        (Element::CalibrationStep, 1) => {
            let calls: Vec<_> = code
                .iter()
                .enumerate()
                .filter_map(|(n, i)| (i.mnemonic == "JSR").then_some(n))
                .collect();
            if calls.len() != 3 {
                return None;
            }
            let division = code.iter().position(|i| i.mnemonic == "DIVXU")?;
            let shift = code.iter().find(|i| i.mnemonic == "SHLL")?;
            let mut shift = *shift;
            shift.operands[1] = reg(0);
            let mut divisor = code[division - 1];
            divisor.operands[1] = reg(1);
            let mut divide = code[division];
            divide.operands[0] = reg(1);
            let mut constant = code
                .iter()
                .find(|i| i.mnemonic == "MOV" && i.operands[0] == imm(64, 8))
                .copied()?;
            constant.operands[0] = imm(48, 8);
            // Save the getter's result on the stack across the second helper,
            // rather than borrowing/restoring R3. Fold 64 + (-16) before SUB.
            alloc::vec![
                code[1],
                code[calls[0]],
                stack(true, 0),
                code[calls[1]],
                code[calls[1] + 1],
                stack(false, 0),
                shift,
                shift,
                code[division - 2],
                divisor,
                divide,
                constant,
                code[division + 1],
                code[division + 3],
                code[calls[2] - 1],
                code[calls[2]],
                *code.last()?
            ]
        }
        _ => return None,
    };
    let mut result = Vec::new();
    for instruction in output {
        result.extend_from_slice(&encode_insn(instruction, Target::H8S2000, Mode::Advanced).ok()?);
    }
    Some(result)
}

fn original_templates(element: Element) -> Option<&'static [Template]> {
    match element {
        Element::CalibrationBase => Some(&BASE),
        Element::CalibrationOffset => Some(&OFFSET),
        Element::CalibrationStep => Some(&STEP),
        _ => None,
    }
}
fn compact_template(element: Element, variant: u8) -> Option<Vec<Option<u8>>> {
    let original = *original_templates(element)?.get(usize::from(variant))?;
    let bytes: Vec<_> = original.iter().map(|b| b.unwrap_or(0)).collect();
    let bytes = compact_body(&bytes, element, variant)?;
    let mut template: Vec<_> = bytes.iter().copied().map(Some).collect();
    let mut at = 0;
    while at < bytes.len() {
        let d = h8_asm::isa::decode_insn(
            &bytes[at..],
            h8_asm::Target::H8S2000,
            h8_asm::Mode::Advanced,
        )
        .ok()?;
        if d.insn.mnemonic == "JSR" {
            template[at + 1..at + 4].fill(None);
        }
        at += d.len;
    }
    Some(template)
}
fn matching_template(element: Element, variant: u8, bytes: &[u8]) -> Option<Vec<Option<u8>>> {
    let original = original_templates(element)?
        .get(usize::from(variant))?
        .to_vec();
    core::iter::once(original)
        .chain(compact_template(element, variant))
        .find(|t| {
            t.len() == bytes.len()
                && t.iter()
                    .zip(bytes)
                    .all(|(a, b)| a.map_or(true, |a| a == *b))
        })
}

#[cfg(test)]
static PROOF_SPANS: std::sync::Mutex<std::collections::BTreeMap<usize, u8>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());
#[cfg(test)]
fn record_proof(address: usize, bytes: &[u8]) {
    if std::env::var_os("PIONEER_ARITHMETIC_EXPORT").is_some() {
        PROOF_SPANS
            .lock()
            .unwrap()
            .extend(bytes.iter().enumerate().map(|(i, b)| (address + i, *b)));
    }
}

// Prove scratch-register/condition-code death in the actual native users.
// Calls are followed, not assumed to follow a compiler ABI. Unknown operations,
// indirect transfers, excessive flow or escaping before overwrite fail closed.
fn scratch_dead(
    normal: &[u8],
    kernel: Option<&[u8]>,
    entry: usize,
    mask: u32,
    initial_flags: u8,
    return_to: Option<usize>,
) -> bool {
    use h8_asm::isa::{decode_insn, Ea, Operand as O, Reg, Size};
    use h8_asm::{Mode, Target};
    let reg_mask = |r: Reg| match r {
        Reg::Byte(1) => 0xff00,
        Reg::Byte(9) => 0xff,
        Reg::Word(1) => 0xffff,
        Reg::Word(9) => 0xffff0000,
        Reg::Long(1) => u32::MAX,
        _ => 0,
    };
    let reads = |o: O| match o {
        O::Register(r) => reg_mask(r),
        O::Address(Ea::Indirect(r) | Ea::PostIncrement(r) | Ea::PreDecrement(r)) => reg_mask(r),
        O::Address(Ea::Displacement { base, .. }) => reg_mask(base),
        _ => 0,
    };
    let coordinates = |r: Reg| match r {
        Reg::Byte(n) => Some(((n % 8) as usize, if n < 8 { 8 } else { 0 }, 255)),
        Reg::Word(n) => Some(((n % 8) as usize, if n < 8 { 0 } else { 16 }, 65535)),
        Reg::Long(n) => Some((n as usize, 0, u32::MAX)),
        _ => None,
    };
    let carried_read = |o: O, state: &[u32; 8]| -> u32 {
        let r = match o {
            O::Register(r) => r,
            O::Address(Ea::Indirect(r) | Ea::PostIncrement(r) | Ea::PreDecrement(r)) => r,
            O::Address(Ea::Displacement { base, .. }) => base,
            _ => return 0,
        };
        coordinates(r).map_or(0, |(n, shift, mask)| (state[n] >> shift) & mask)
    };
    let carried_write = |r: Reg, value: u32, state: &mut [u32; 8]| {
        if let Some((n, shift, mask)) = coordinates(r) {
            state[n] = (state[n] & !(mask << shift)) | ((value & mask) << shift);
        }
    };
    let regions = match crate::image::regions(normal) {
        Some(r) => r,
        None => return false,
    };
    let stored = |at: usize, len: usize| {
        regions.stored.iter().any(|r| {
            let start = r.as_ptr() as usize - normal.as_ptr() as usize;
            at >= start
                && at
                    .checked_add(len)
                    .is_some_and(|end| end <= start + r.len())
        })
    };
    let mut mapped = Vec::new();
    let (address_base, delta) = if let Some(kernel) = kernel {
        if kernel.len() != 0x10000 {
            return false;
        }
        mapped.extend_from_slice(kernel);
        mapped.extend_from_slice(normal);
        (0x400000, 0x10000)
    } else {
        (BASE_ADDRESS, 0)
    };
    let bytes = if kernel.is_some() {
        mapped.as_slice()
    } else {
        normal
    };
    let entry = entry + delta;
    let return_to = return_to.map(|r| r + delta);
    let mapped_stored = |at: usize, len: usize| {
        if delta != 0 && at < delta {
            at.checked_add(len).is_some_and(|end| end <= delta)
        } else {
            at.checked_sub(delta).is_some_and(|at| stored(at, len))
        }
    };
    // NZVC differences are tracked independently of the scratch word.
    let mut pending = alloc::vec![(
        entry,
        mask,
        initial_flags,
        [0u32; 8],
        return_to.into_iter().collect::<Vec<_>>()
    )];
    let mut visited = Vec::new();
    while let Some((at, mut dirty, mut flags, mut carried, mut returns)) = pending.pop() {
        if dirty == 0 && flags == 0 && carried.iter().all(|v| *v == 0) {
            continue;
        }
        let state = (at, dirty, flags, carried, returns.clone());
        if visited.contains(&state) {
            continue;
        }
        if visited.len() >= 4096 || returns.len() >= 12 {
            return false;
        }
        visited.push(state);
        let Some(bytes) = bytes.get(at..) else {
            return false;
        };
        let Ok(d) = decode_insn(bytes, Target::H8S2000, Mode::Advanced) else {
            return false;
        };
        if !mapped_stored(at, d.len) {
            return false;
        }
        #[cfg(test)]
        record_proof(address_base + at, &bytes[..d.len]);
        let [a, b, _] = d.insn.operands;
        let next = at + d.len;
        let jump = |o| match o {
            O::Address(Ea::Absolute { value, bits: 24 }) => {
                (value as usize).checked_sub(address_base)
            }
            O::Address(Ea::PcRelative { value, .. }) => next.checked_add_signed(value as isize),
            _ => None,
        };
        // STC/LDC may save and restore changed arithmetic flags solely while
        // masking interrupts. Track those bits through registers rather than
        // treating the saved CCR byte as an observable value or silently
        // discarding it. Any unsupported use or memory escape is refused.
        let loaded_flags = carried_read(a, &carried) as u8;
        match (d.insn.mnemonic, a, b) {
            ("STC", O::Register(Reg::Ccr), O::Register(r)) => {
                carried_write(r, u32::from(flags), &mut carried)
            }
            ("STC", O::Register(Reg::Ccr), _) if flags != 0 => return false,
            ("LDC", O::Register(_), O::Register(Reg::Ccr)) => {}
            ("MOV", source, O::Register(r)) => {
                if matches!(source, O::Address(_)) && carried_read(source, &carried) != 0 {
                    return false;
                }
                carried_write(
                    r,
                    if matches!(source, O::Register(_)) {
                        carried_read(source, &carried)
                    } else {
                        0
                    },
                    &mut carried,
                );
            }
            ("AND", O::Immediate { value, .. }, O::Register(r)) => {
                let v = carried_read(O::Register(r), &carried);
                carried_write(r, v & value, &mut carried);
            }
            ("OR", O::Immediate { value, .. }, O::Register(r)) => {
                let v = carried_read(O::Register(r), &carried);
                carried_write(r, v & !value, &mut carried);
            }
            ("SUB" | "XOR", O::Register(r), O::Register(to)) if r == to => {
                carried_write(r, 0, &mut carried)
            }
            ("STM", O::Registers { first, last }, _) => {
                if carried[first as usize..=last as usize]
                    .iter()
                    .any(|v| *v != 0)
                {
                    return false;
                }
            }
            ("LDM", _, O::Registers { first, last }) => {
                carried[first as usize..=last as usize].fill(0);
            }
            _ => {
                if carried_read(a, &carried) != 0 || carried_read(b, &carried) != 0 {
                    return false;
                }
            }
        }
        match d.insn.mnemonic {
            "JSR" | "BSR" => {
                let Some(to) = jump(a) else {
                    return false;
                };
                returns.push(next);
                pending.push((to, dirty, flags, carried, returns));
                continue;
            }
            "RTS" => {
                let Some(to) = returns.pop() else {
                    return false;
                };
                pending.push((to, dirty, flags, carried, returns));
                continue;
            }
            "JMP" | "BRA" => {
                let Some(to) = jump(a) else {
                    return false;
                };
                pending.push((to, dirty, flags, carried, returns));
                continue;
            }
            name if name.starts_with('B') && matches!(a, O::Address(Ea::PcRelative { .. })) => {
                let used = match name {
                    "BEQ" | "BNE" => 4,
                    "BCC" | "BCS" => 1,
                    "BPL" | "BMI" => 8,
                    "BVC" | "BVS" => 2,
                    "BHI" | "BLS" => 5,
                    "BGE" | "BLT" => 10,
                    "BGT" | "BLE" => 14,
                    _ => return false,
                };
                if flags & used != 0 {
                    return false;
                }
                let Some(to) = jump(a) else {
                    return false;
                };
                pending.push((to, dirty, flags, carried, returns.clone()));
            }
            "MOV" => {
                if reads(a) & dirty != 0 {
                    return false;
                }
                match b {
                    O::Register(r) => dirty &= !reg_mask(r),
                    _ if reads(b) & dirty != 0 => return false,
                    _ => {}
                }
                flags &= 0x21;
                if carried_read(b, &carried) != 0 {
                    flags |= 0x0c;
                }
            }
            "EXTU" => {
                let O::Register(r) = a else {
                    return false;
                };
                let input = match r {
                    Reg::Word(1) => 0xff,
                    Reg::Long(1) => 0xffff,
                    _ => reg_mask(r),
                };
                if input & dirty != 0 {
                    return false;
                }
                dirty &= !reg_mask(r);
                flags &= 0x21;
            }
            "SUB" | "XOR" if a == b => {
                let O::Register(r) = b else {
                    return false;
                };
                dirty &= !reg_mask(r);
                if d.insn.mnemonic == "SUB" {
                    flags = 0;
                } else {
                    flags &= 0x21;
                }
            }
            "ADD" | "SUB" | "CMP" | "NEG" => {
                if (reads(a) | reads(b)) & dirty != 0 {
                    return false;
                }
                flags = 0;
            }
            "SHLL" | "SHLR" | "SHAL" | "SHAR" => {
                if (reads(a) | reads(b)) & dirty != 0 {
                    return false;
                }
                flags &= 0x20;
            }
            "MULXU" | "MULXS" | "DIVXU" | "DIVXS" => {
                if (reads(a) | reads(b)) & dirty != 0 {
                    return false;
                }
            }
            "AND" | "OR" | "XOR" | "NOT" | "INC" | "DEC" => {
                if (reads(a) | reads(b)) & dirty != 0 {
                    return false;
                }
                flags &= 0x21;
                if carried_read(b, &carried) != 0 {
                    flags |= 0x0c;
                }
            }
            "BTST" => {
                if (reads(a) | reads(b)) & dirty != 0 {
                    return false;
                }
                flags &= !4;
            }
            "BSET" | "BCLR" | "BNOT" | "NOP" => {
                if (reads(a) | reads(b)) & dirty != 0 {
                    return false;
                }
            }
            "BLD" | "BILD" => {
                if (reads(a) | reads(b)) & dirty != 0 {
                    return false;
                }
                flags &= !1;
            }
            "BST" | "BIST" => {
                if flags & 1 != 0 || (reads(a) | reads(b)) & dirty != 0 {
                    return false;
                }
            }
            "LDC" => {
                if reads(a) & dirty != 0 {
                    return false;
                }
                flags = loaded_flags;
            }
            "STC" => {
                if a != O::Register(Reg::Ccr) {
                    return false;
                }
                match b {
                    O::Register(r) => dirty &= !reg_mask(r),
                    _ if reads(b) & dirty != 0 => return false,
                    _ => {}
                }
            }
            "ORC" | "ANDC" => {
                let O::Immediate { value, .. } = a else {
                    return false;
                };
                flags &= if d.insn.mnemonic == "ORC" {
                    !(value as u8)
                } else {
                    value as u8
                };
            }
            "STM" => {
                let O::Registers { first, last } = a else {
                    return false;
                };
                if first <= 1 && last >= 1 && dirty != 0 {
                    return false;
                }
                if reads(b) & dirty != 0 {
                    return false;
                }
            }
            "ADDS" | "SUBS" => {
                if (reads(a) | reads(b)) & dirty != 0 {
                    return false;
                }
            }
            "LDM" => {
                if reads(a) & dirty != 0 {
                    return false;
                }
                let O::Registers { first, last } = b else {
                    return false;
                };
                if first <= 1 && last >= 1 {
                    dirty = 0;
                }
                if d.insn.size != Some(Size::Long) {
                    return false;
                }
            }
            _ => return false,
        }
        pending.push((next, dirty, flags, carried, returns));
    }
    true
}

// Complete native transient-table initializer. This grammar establishes actual
// instruction boundaries for reference analysis; address fields remain local.
// In particular, its indexed store displacement is data, never a branch opcode.
const SCRATCH_INITIALIZER: Template = &[
    Some(0x01),
    Some(0x20),
    Some(0x6d),
    Some(0xf4),
    Some(0x1b),
    Some(0x97),
    Some(0x18),
    Some(0x88),
    Some(0x6a),
    Some(0xa8),
    None,
    None,
    None,
    None,
    Some(0x79),
    Some(0x00),
    Some(0x03),
    Some(0xe8),
    Some(0x6b),
    Some(0xa0),
    None,
    None,
    None,
    None,
    Some(0x18),
    Some(0xcc),
    Some(0x7a),
    Some(0x06),
    None,
    None,
    None,
    None,
    Some(0x0d),
    Some(0x05),
    Some(0x01),
    Some(0x00),
    Some(0x69),
    Some(0xf6),
    Some(0x1a),
    Some(0xa2),
    Some(0x0c),
    Some(0xca),
    Some(0x0f),
    Some(0xa1),
    Some(0x10),
    Some(0x31),
    Some(0x78),
    Some(0x10),
    Some(0x6b),
    Some(0xa5),
    None,
    None,
    None,
    None,
    Some(0x79),
    Some(0x00),
    Some(0xff),
    Some(0xff),
    Some(0x0a),
    Some(0xe1),
    Some(0x69),
    Some(0x90),
    Some(0x18),
    Some(0x88),
    Some(0x78),
    Some(0x20),
    Some(0x6a),
    Some(0xa8),
    None,
    None,
    None,
    None,
    Some(0x0a),
    Some(0x0c),
    Some(0xac),
    Some(0x05),
    Some(0x45),
    Some(0xd4),
    Some(0x7a),
    Some(0x01),
    None,
    None,
    None,
    None,
    Some(0x0f),
    Some(0xe0),
    Some(0x1a),
    Some(0xd5),
    Some(0xfd),
    Some(0x1c),
    Some(0x0f),
    Some(0xd2),
    Some(0x5e),
    None,
    None,
    None,
    Some(0x7a),
    Some(0x01),
    None,
    None,
    None,
    None,
    Some(0x0f),
    Some(0xe0),
    Some(0x0f),
    Some(0xd2),
    Some(0x5e),
    None,
    None,
    None,
    Some(0x7a),
    Some(0x01),
    None,
    None,
    None,
    None,
    Some(0x0f),
    Some(0xe0),
    Some(0x0f),
    Some(0xd2),
    Some(0x5e),
    None,
    None,
    None,
    Some(0x01),
    Some(0x00),
    Some(0x6b),
    Some(0xa6),
    None,
    None,
    None,
    None,
    Some(0x0b),
    Some(0x97),
    Some(0x01),
    Some(0x20),
    Some(0x6d),
    Some(0x76),
    Some(0x54),
    Some(0x70),
];

fn covered_routines(normal: &[u8]) -> Option<Vec<native::placement::Body>> {
    let regions = crate::image::regions(normal)?;
    let mut bodies = Vec::new();
    let mut templates: Vec<Vec<Option<u8>>> = OFFSET.iter().map(|t| t.to_vec()).collect();
    templates.extend([
        compact_template(Element::CalibrationOffset, 1)?,
        compact_template(Element::CalibrationOffset, 2)?,
    ]);
    templates.push(SCRATCH_INITIALIZER.to_vec());
    for template in templates {
        let concrete: Vec<_> = template.iter().map(|b| b.unwrap_or(0)).collect();
        let first =
            h8_asm::isa::decode_insn(&concrete, h8_asm::Target::H8S2000, h8_asm::Mode::Advanced)
                .ok()?;
        for at in sites(normal, &regions.stored, &template[..first.len]) {
            if let Some(body) = native::placement::read(normal, &regions.stored, at, &template) {
                #[cfg(test)]
                for span in &body.spans {
                    record_proof(BASE_ADDRESS + span.start, &normal[span.clone()]);
                }
                bodies.push(body);
            }
        }
    }
    Some(bodies)
}

fn scratch_callers(
    normal: &[u8],
    kernel: Option<&[u8]>,
    program: &Program,
    helper: Option<usize>,
    mask: u32,
) -> bool {
    use h8_asm::isa::{decode_insn, Ea, Operand as O};
    use h8_asm::{Mode, Target};
    if program.body.spans.len() != 1 {
        return false;
    }
    let original = &program.body.spans[0];
    let Some(covered) = covered_routines(normal) else {
        return false;
    };
    if native::placement::retirement_references_clear_bodies(
        normal,
        original,
        &(original.start + 2..original.end),
        &covered,
    )
    .is_none()
    {
        return false;
    }
    if let Some(kernel) = kernel {
        if native::placement::retirement_kernel_references_clear(kernel, original).is_none() {
            return false;
        }
        for at in (0..kernel.len()).step_by(2) {
            let Ok(d) = decode_insn(&kernel[at..], Target::H8S2000, Mode::Advanced) else {
                continue;
            };
            if !matches!(d.insn.mnemonic, "JSR" | "JMP" | "BSR" | "BRA") {
                continue;
            }
            let to = match d.insn.operands[0] {
                O::Address(Ea::Absolute { value, bits: 24 }) => Some(value as usize),
                O::Address(Ea::PcRelative { value, .. }) => {
                    (0x400000 + at + d.len).checked_add_signed(value as isize)
                }
                _ => None,
            };
            // No resident caller is guessed to share the Normal caller ABI.
            if to == Some(BASE_ADDRESS + program.at) {
                return false;
            }
        }
    }
    let Some(regions) = crate::image::regions(normal) else {
        return false;
    };
    let mut calls = 0;
    for region in &regions.stored {
        let offset = region.as_ptr() as usize - normal.as_ptr() as usize;
        for at in (offset % 2..region.len()).step_by(2) {
            let Ok(d) = decode_insn(&region[at..], Target::H8S2000, Mode::Advanced) else {
                continue;
            };
            if !matches!(d.insn.mnemonic, "JSR" | "JMP") && !d.insn.mnemonic.starts_with('B') {
                continue;
            }
            let next = offset + at + d.len;
            let to = match d.insn.operands[0] {
                O::Address(Ea::Absolute { value, bits: 24 }) => {
                    (value as usize).checked_sub(BASE_ADDRESS)
                }
                O::Address(Ea::PcRelative { value, .. }) => next.checked_add_signed(value as isize),
                _ => None,
            };
            if to != Some(program.at) {
                continue;
            }
            if !matches!(d.insn.mnemonic, "JSR" | "BSR") {
                return false;
            }
            #[cfg(test)]
            record_proof(BASE_ADDRESS + offset + at, &region[at..at + d.len]);
            calls += 1;
            if !scratch_dead(
                normal,
                kernel,
                helper.unwrap_or(next),
                mask,
                if helper.is_none() { 0x0e } else { 0x2f },
                helper.map(|_| next),
            ) {
                return false;
            }
        }
    }
    calls != 0
}

fn offset_flags_dead(normal: &[u8], kernel: Option<&[u8]>, program: &Program) -> bool {
    let Ok(fields) = calls(&program.template) else {
        return false;
    };
    let Some(field) = fields.get(2).copied() else {
        return false;
    };
    let address = u32::from_be_bytes([
        0,
        program.body.bytes[field],
        program.body.bytes[field + 1],
        program.body.bytes[field + 2],
    ]) as usize;
    let Some(helper) = address.checked_sub(BASE_ADDRESS) else {
        return false;
    };
    let continuation = program.at + field + 3;
    if continuation >= program.body.spans[0].end {
        return false;
    }
    // The identical native MUL/SHLR suffix overwrites NZVC. Only H can differ
    // after the byte-strength reduction; the following native NEG.W kills it.
    scratch_dead(normal, kernel, helper, 0, 0x20, Some(continuation))
}

// Every hole in these complete templates is a 24-bit absolute JSR operand.
// Bind those operands by semantic call order, never by arbitrary byte offsets.
fn calls(template: &[Option<u8>]) -> Result<Vec<usize>, Error> {
    let mut found = Vec::new();
    let mut at = 0;
    while at < template.len() {
        if template[at].is_none() {
            if at == 0
                || template[at - 1] != Some(0x5e)
                || template.get(at..at + 3) != Some(&[None, None, None])
            {
                return Err(Error::InvalidProgram);
            }
            found.push(at);
            at += 3;
        } else {
            at += 1;
        }
    }
    Ok(found)
}
fn transplant_program(normal: &[u8], from: &Program, desired: &Program) -> Result<Vec<u8>, Error> {
    let before = &from.template;
    if from.element != desired.element {
        return Err(Error::InvalidProgram);
    }
    let after = &desired.template;
    let old_calls = calls(before)?;
    let new_calls = calls(after)?;
    if old_calls.len() != new_calls.len() {
        return Err(Error::InvalidProgram);
    }
    // Transplant the actual recognized OEM body. Templates establish its
    // semantics; they are not a source of newly assembled replacement code.
    let mut bytes = desired.body.bytes.clone();
    for (old, new) in old_calls.into_iter().zip(new_calls) {
        let operand = from
            .body
            .bytes
            .get(old..old + 3)
            .ok_or(Error::InvalidProgram)?;
        let address = u32::from_be_bytes([0, operand[0], operand[1], operand[2]]);
        if address & 1 != 0 || address < 0x400000 || address >= 0x410000 + normal.len() as u32 {
            return Err(Error::InvalidProgram);
        }
        crate::filters::phase::native::encoding::retarget_call(&mut bytes, new - 1, address)
            .ok_or(Error::InvalidProgram)?;
    }
    Ok(bytes)
}
fn pad_nops(bytes: &mut Vec<u8>, length: usize) -> Result<(), Error> {
    use h8_asm::isa::{encode_insn, Insn, Operand};
    let nop = encode_insn(
        Insn::new("NOP", None, [Operand::None; 3]),
        h8_asm::Target::H8S2000,
        h8_asm::Mode::Advanced,
    )
    .map_err(|_| Error::InvalidProgram)?;
    if length < bytes.len() || (length - bytes.len()) % nop.len() != 0 {
        return Err(Error::InvalidProgram);
    }
    while bytes.len() < length {
        bytes.extend_from_slice(&nop);
    }
    Ok(())
}

fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

/// Transplant installed base/offset/step routines, retaining target helper calls.
///
/// A growing program requires its corresponding explicit reservation. The
/// reservation's complete range is checked and zero-padded; the original entry
/// becomes a JMP ending at a native instruction boundary. Shrinking programs
/// stay in place, with NOP padding. No checksum or persistent data is changed.
/// Reservations must be independently established as unused executable space;
/// erased bytes alone are not a code-space ownership proof.
pub fn rewrite(
    target: &[u8],
    installed: &[u8],
    reservations: [Option<Range<usize>>; 3],
) -> Result<Vec<u8>, Error> {
    rewrite_with_layout(target, installed, reservations, false, false, None)
}

/// Reuse the replaced routine's space and spill only whole-instruction overflow.
/// Reservations still require independent ownership and entry-point proof.
pub fn rewrite_compact(
    target: &[u8],
    installed: &[u8],
    reservations: [Option<Range<usize>>; 3],
) -> Result<Vec<u8>, Error> {
    rewrite_with_layout(target, installed, reservations, true, false, None)
}

/// Compact recognized native arithmetic when its complete helper/caller ABI is
/// proved. Remaining overflow still requires positively owned reservations.
pub fn rewrite_specialized(
    target: &[u8],
    installed: &[u8],
    reservations: [Option<Range<usize>>; 3],
) -> Result<Vec<u8>, Error> {
    rewrite_with_layout(target, installed, reservations, true, true, None)
}

/// Specialize with the exact resident Kernel when native callers cross the
/// Normal/Kernel boundary before discarding scratch values.
pub fn rewrite_specialized_with_kernel(
    target: &[u8],
    installed: &[u8],
    reservations: [Option<Range<usize>>; 3],
    kernel: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    rewrite_with_layout(target, installed, reservations, true, true, kernel)
}

/// Recheck all specialized scratch-register users against the final composed
/// image and its exact Kernel. Semantic template IDs alone cannot provide this
/// proof after another image operation changes a helper or caller.
pub fn verify_specialized_callers(normal: &[u8], kernel: Option<&[u8]>) -> Result<(), Error> {
    for p in programs(normal)? {
        let original =
            original_templates(p.element).ok_or(Error::InvalidProgram)?[usize::from(p.variant)];
        if original.len() == p.body.bytes.len()
            && original
                .iter()
                .zip(&p.body.bytes)
                .all(|(a, b)| a.map_or(true, |a| a == *b))
        {
            continue;
        }
        let proved = match p.element {
            Element::CalibrationBase => scratch_callers(normal, kernel, &p, None, u32::MAX),
            Element::CalibrationOffset => offset_flags_dead(normal, kernel, &p),
            Element::CalibrationStep => {
                let fields = calls(&p.template)?;
                let i = *fields.last().ok_or(Error::InvalidProgram)?;
                let address = u32::from_be_bytes([
                    0,
                    p.body.bytes[i],
                    p.body.bytes[i + 1],
                    p.body.bytes[i + 2],
                ]) as usize;
                address
                    .checked_sub(BASE_ADDRESS)
                    .is_some_and(|helper| scratch_callers(normal, kernel, &p, Some(helper), 0xff00))
            }
            _ => false,
        };
        if !proved {
            return Err(Error::VerificationFailed);
        }
    }
    Ok(())
}

fn transplanted_body(
    target: &[u8],
    program: &Program,
    desired: &Program,
    native_math: bool,
    kernel: Option<&[u8]>,
    compact_even_if_fits: bool,
) -> Result<Vec<u8>, Error> {
    let mut bytes = transplant_program(target, program, desired)?;
    if native_math && (compact_even_if_fits || bytes.len() > program.body.spans[0].len()) {
        if let Some(smaller) = compact_body(&bytes, desired.element, desired.variant) {
            let proved = match desired.element {
                Element::CalibrationBase => {
                    scratch_callers(target, kernel, program, None, u32::MAX)
                }
                Element::CalibrationOffset => true,
                Element::CalibrationStep => {
                    let fields = calls(&desired.template)?;
                    let field = *fields.last().ok_or(Error::InvalidProgram)?;
                    let address =
                        u32::from_be_bytes([0, bytes[field], bytes[field + 1], bytes[field + 2]])
                            as usize;
                    address.checked_sub(BASE_ADDRESS).is_some_and(|helper| {
                        scratch_callers(target, kernel, program, Some(helper), 0xff00)
                    })
                }
                _ => false,
            };
            if proved {
                bytes = smaller;
            }
        }
    }
    Ok(bytes)
}

/// Exact whole-instruction suffix sizes for all growing specialized conversions.
/// Callers still establish storage ownership and allocate disjoint reservations.
pub fn required_spills(
    target: &[u8],
    installed: &[u8],
    kernel: Option<&[u8]>,
) -> Result<[usize; 3], Error> {
    let from = programs(target)?;
    let required = programs(installed)?;
    let mut lengths = [0; 3];
    for (i, (program, desired)) in from.iter().zip(&required).enumerate() {
        if program.variant == desired.variant {
            continue;
        }
        let bytes = transplanted_body(target, program, desired, true, kernel, false)?;
        let original = &program.body.spans[0];
        if bytes.len() <= original.len() {
            continue;
        }
        let address =
            u32::try_from(BASE_ADDRESS + original.start).map_err(|_| Error::InvalidSpace)?;
        let (_, spill) =
            native::placement::split_closed(&bytes, address, original.len(), BASE_ADDRESS as u32)
                .ok_or(Error::InvalidProgram)?;
        if program
            .body
            .spans
            .get(1)
            .is_some_and(|range| range.len() >= spill.len())
        {
            continue;
        }
        lengths[i] = spill.len();
    }
    Ok(lengths)
}

/// Stage only complete conversions that fit their original native bodies.
/// The mechanism composer may subsequently prove ownership of their retired
/// suffixes; shrinking here is not by itself permission to reuse those bytes.
pub(crate) fn rewrite_shrinking(
    target: &[u8],
    installed: &[u8],
    kernel: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let from = programs(target)?;
    let required = programs(installed)?;
    let mut changed = target.to_vec();
    let mut expected = Vec::new();
    let mut written: Vec<Range<usize>> = Vec::new();
    for (program, desired) in from.iter().zip(&required) {
        let original = &program.body.spans[0];
        let mut bytes = transplanted_body(target, program, desired, true, kernel, true)?;
        if bytes.len() > original.len()
            || (program.variant == desired.variant && bytes.len() == original.len())
        {
            expected.push(program.variant);
            continue;
        }
        if program.body.spans.len() != 1 || written.iter().any(|range| overlaps(range, original)) {
            return Err(Error::InvalidSpace);
        }
        pad_nops(&mut bytes, original.len())?;
        changed[original.clone()].copy_from_slice(&bytes);
        written.push(original.clone());
        expected.push(desired.variant);
    }
    if programs(&changed)?.iter().map(|p| p.variant).ne(expected) {
        return Err(Error::VerificationFailed);
    }
    verify_specialized_callers(&changed, kernel)?;
    Ok(changed)
}

/// A complete shrinking body and its structurally retired suffix.
pub(crate) struct Retirement {
    pub(crate) program: Range<usize>,
    pub(crate) tail: Range<usize>,
}

/// Locate structurally retired suffixes. The allocator separately requires NOP
/// staging bytes and proves ownership; final verification also uses this after
/// those bytes contain another bound conversion's spill.
pub(crate) fn retired_tails(target: &[u8], changed: &[u8]) -> Result<Vec<Retirement>, Error> {
    let mut tails = Vec::new();
    for (before, after) in programs(target)?.iter().zip(programs(changed)?) {
        let original = &before.body.spans[0];
        let current = &after.body.spans[0];
        if before.body.spans.len() == 1
            && after.body.spans.len() == 1
            && original.start == current.start
            && current.end < original.end
        {
            let tail = current.end..original.end;
            tails.push(Retirement {
                program: original.clone(),
                tail,
            });
        }
    }
    Ok(tails)
}

fn rewrite_with_layout(
    target: &[u8],
    installed: &[u8],
    reservations: [Option<Range<usize>>; 3],
    compact: bool,
    native_math: bool,
    kernel: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let from = programs(target)?;
    let required = programs(installed)?;
    let regions = crate::image::regions(target).ok_or(Error::InvalidProgram)?;
    let contains = |range: &Range<usize>| {
        regions.stored.iter().any(|r| {
            let start = r.as_ptr() as usize - target.as_ptr() as usize;
            range.start >= start && range.end <= start + r.len()
        })
    };
    let mut writes = Vec::<(Range<usize>, Vec<u8>)>::new();
    for (i, (program, desired)) in from.iter().zip(&required).enumerate() {
        if program.variant == desired.variant {
            continue;
        }
        let bytes = transplanted_body(target, program, desired, native_math, kernel, false)?;
        if !compact && program.body.spans.len() != 1 {
            return Err(Error::InvalidProgram);
        }
        let original = program.body.spans[0].clone();
        let prior_spill = program.body.spans.get(1);
        if bytes.len() <= original.len() {
            let mut padded = bytes;
            pad_nops(&mut padded, original.len())?;
            writes.push((original, padded));
            if let Some(retired) = prior_spill {
                let mut padding = Vec::new();
                pad_nops(&mut padding, retired.len())?;
                writes.push((retired.clone(), padding));
            }
        } else {
            let space = reservations[i]
                .clone()
                .or_else(|| if compact { prior_spill.cloned() } else { None })
                .ok_or(Error::SpaceRequired(program.element))?;
            let reusing_spill = compact && prior_spill == Some(&space);
            if space.start & 1 != 0
                || space.end & 1 != 0
                || space.end < space.start
                || (!compact && space.len() < bytes.len())
                || !contains(&space)
                || (!reusing_spill
                    && !target
                        .get(space.clone())
                        .is_some_and(|b| b.iter().all(|b| *b == 0xff)))
                || from.iter().any(|p| {
                    p.body.spans.iter().any(|span| {
                        overlaps(&space, span)
                            && !(reusing_spill && p.at == program.at && Some(span) == prior_spill)
                    })
                })
            {
                return Err(Error::InvalidSpace);
            }
            if compact {
                let address = BASE_ADDRESS
                    .checked_add(space.start)
                    .and_then(|a| u32::try_from(a).ok())
                    .ok_or(Error::InvalidSpace)?;
                let original_address = BASE_ADDRESS
                    .checked_add(original.start)
                    .and_then(|a| u32::try_from(a).ok())
                    .ok_or(Error::InvalidSpace)?;
                let (prefix, mut spill) = native::placement::split_closed(
                    &bytes,
                    original_address,
                    original.len(),
                    address,
                )
                .ok_or(Error::InvalidProgram)?;
                if spill.len() > space.len() {
                    return Err(Error::InvalidSpace);
                }
                pad_nops(&mut spill, space.len())?;
                writes.push((original, prefix));
                writes.push((space, spill));
                if let Some(retired) = prior_spill.filter(|_| !reusing_spill) {
                    let mut padding = Vec::new();
                    pad_nops(&mut padding, retired.len())?;
                    writes.push((retired.clone(), padding));
                }
                continue;
            }
            let mut end = program.at;
            while end < program.at + 4 {
                let instruction = h8_asm::isa::decode_insn(
                    &target[end..original.end],
                    h8_asm::Target::H8S2000,
                    h8_asm::Mode::Advanced,
                )
                .map_err(|_| Error::InvalidProgram)?;
                if instruction.len == 0 {
                    return Err(Error::InvalidProgram);
                }
                end += instruction.len;
            }
            let address = BASE_ADDRESS
                .checked_add(space.start)
                .filter(|a| *a <= 0xffffff)
                .ok_or(Error::InvalidSpace)? as u32;
            use h8_asm::isa::{encode_insn, Ea, Insn, Operand};
            let mut detour = encode_insn(
                Insn::new(
                    "JMP",
                    None,
                    [
                        Operand::Address(Ea::Absolute {
                            value: address,
                            bits: 24,
                        }),
                        Operand::None,
                        Operand::None,
                    ],
                ),
                h8_asm::Target::H8S2000,
                h8_asm::Mode::Advanced,
            )
            .map_err(|_| Error::InvalidProgram)?;
            pad_nops(&mut detour, end - program.at)?;
            let mut relocated = bytes;
            pad_nops(&mut relocated, space.len())?;
            writes.push((program.at..end, detour));
            writes.push((space, relocated));
        }
    }
    for (i, (range, _)) in writes.iter().enumerate() {
        if writes[..i]
            .iter()
            .any(|(earlier, _)| overlaps(range, earlier))
        {
            return Err(Error::InvalidSpace);
        }
    }
    let mut output = target.to_vec();
    for (range, bytes) in writes {
        output[range].copy_from_slice(&bytes);
    }
    let after = programs(&output)?;
    if after
        .iter()
        .zip(&required)
        .any(|(a, b)| a.variant != b.variant)
    {
        return Err(Error::VerificationFailed);
    }
    if native_math {
        verify_specialized_callers(&output, kernel)?;
    }
    Ok(output)
}

/// Carry the effective mode-one sign and controller mode convention into target.
/// Both complete native mode branches are bound before the branch polarity can
/// change; the controller's complete ten-byte selection program is also bound.
/// Only these two programs change. Call operands and checksum remain untouched.
pub fn rewrite_controls(target: &[u8], installed: &[u8]) -> Result<Vec<u8>, Error> {
    type ConventionSite = (u8, usize);
    let bind = |normal: &[u8]| -> Result<(ConventionSite, ConventionSite), Error> {
        let regions = crate::image::regions(normal).ok_or(Error::InvalidProgram)?;
        Ok((
            mode_binding(normal, &regions.stored).map_err(Error::Unbound)?,
            one_of(
                normal,
                &regions.stored,
                &CONTROLLER,
                Element::ControllerMode,
            )
            .map_err(Error::Unbound)?,
        ))
    };
    let ((mode, at), (controller, control_at)) = bind(target)?;
    let ((required, _), (required_controller, donor_control)) = bind(installed)?;
    let mut changed = target.to_vec();
    if mode != required {
        use h8_asm::{
            isa::{decode_insn, encode_insn},
            Mode, Target,
        };
        let before = decode_insn(&target[at + 6..], Target::H8S2000, Mode::Advanced)
            .map_err(|_| Error::InvalidProgram)?;
        let mut instruction = before.insn;
        // The native NEG may live in either arm. Flip the target's bound
        // condition to select the donor's effective sign, retaining its arms.
        instruction.mnemonic = match instruction.mnemonic {
            "BEQ" => "BNE",
            "BNE" => "BEQ",
            _ => return Err(Error::InvalidProgram),
        };
        let bytes = encode_insn(instruction, Target::H8S2000, Mode::Advanced)
            .map_err(|_| Error::InvalidProgram)?;
        if bytes.len() != before.len {
            return Err(Error::InvalidProgram);
        }
        changed[at + 6..at + 6 + bytes.len()].copy_from_slice(&bytes);
    }
    if controller != required_controller {
        let template = CONTROLLER[required_controller as usize];
        changed[control_at..control_at + template.len()]
            .copy_from_slice(&installed[donor_control..donor_control + template.len()]);
    }
    let ((after, _), (controller_after, _)) = bind(&changed)?;
    if after != required || controller_after != required_controller {
        return Err(Error::VerificationFailed);
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(variants: [usize; 3], call_base: u32) -> Vec<u8> {
        let mut normal = alloc::vec![0xff; 0x800];
        for (n, templates) in [BASE.as_slice(), OFFSET.as_slice(), STEP.as_slice()]
            .into_iter()
            .enumerate()
        {
            let template = templates[variants[n]];
            let at = (n + 1) * 0x100;
            let mut bytes: Vec<_> = template.iter().map(|b| b.unwrap_or(0)).collect();
            for (i, operand) in calls(template).unwrap().into_iter().enumerate() {
                bytes[operand..operand + 3]
                    .copy_from_slice(&(call_base + i as u32 * 2).to_be_bytes()[1..]);
            }
            normal[at..at + bytes.len()].copy_from_slice(&bytes);
        }
        normal
    }
    fn spaces() -> [Option<Range<usize>>; 3] {
        [Some(0x500..0x580), Some(0x580..0x600), Some(0x600..0x680)]
    }

    #[test]
    fn native_binding_preserves_complete_programs_and_declared_call_roles() {
        for variants in [[0, 0, 0], [1, 1, 1], [1, 2, 2]] {
            let image = fixture(variants, 0x410700);
            let bound = bind_native(&image).unwrap();
            assert_eq!(bound.len(), 3);
            for (i, program) in bound.iter().enumerate() {
                assert_eq!(program.variant as usize, variants[i]);
                assert_eq!(program.entry, 0x410000 + ((i + 1) * 0x100) as u32);
                assert_eq!(program.body.spans.len(), 1);
                assert_eq!(program.body.bytes, image[program.body.spans[0].clone()]);
                assert_eq!(
                    program.element,
                    [
                        Element::CalibrationBase,
                        Element::CalibrationOffset,
                        Element::CalibrationStep
                    ][i]
                );
                for (role, call) in program.calls.iter().enumerate() {
                    assert_eq!(program.body.bytes[call.offset], 0x5e);
                    assert_eq!(call.target, 0x410700 + role as u32 * 2);
                }
            }
        }
    }

    #[test]
    fn compact_conversion_spills_only_overflow_and_preserves_oem_instruction_order() {
        for a in [[0, 0, 0], [1, 1, 1], [1, 2, 2]] {
            for b in [[0, 0, 0], [1, 1, 1], [1, 2, 2]] {
                let target = fixture(a, 0x410780);
                let donor = fixture(b, 0x410790);
                let reservations = [Some(0x500..0x518), Some(0x520..0x538), Some(0x540..0x558)];
                let changed = rewrite_compact(&target, &donor, reservations.clone()).unwrap();
                let actual = programs(&changed).unwrap();
                for (i, p) in actual.iter().enumerate() {
                    let template = [BASE.as_slice(), OFFSET.as_slice(), STEP.as_slice()][i][b[i]];
                    assert_eq!(p.variant as usize, b[i]);
                    assert_eq!(p.at, (i + 1) * 0x100);
                    let source = &donor[p.at..p.at + template.len()];
                    for (offset, byte) in template.iter().enumerate() {
                        if byte.is_some() {
                            assert_eq!(p.body.bytes[offset], source[offset]);
                        }
                    }
                    for (n, field) in calls(template).unwrap().into_iter().enumerate() {
                        assert_eq!(
                            p.body.bytes[field..field + 3],
                            (0x410780 + n as u32 * 2).to_be_bytes()[1..]
                        );
                    }
                    if template.len()
                        > [BASE.as_slice(), OFFSET.as_slice(), STEP.as_slice()][i][a[i]].len()
                    {
                        assert_eq!(p.body.spans.len(), 2);
                        assert!(
                            p.body.spans[0].len()
                                <= [BASE.as_slice(), OFFSET.as_slice(), STEP.as_slice()][i][a[i]]
                                    .len()
                        );
                        assert!(p.body.spans[1].len() <= reservations[i].as_ref().unwrap().len());
                        assert!(p.body.spans[1].len() < template.len());
                    }
                }
                assert_eq!(
                    rewrite_compact(&changed, &donor, [None, None, None]).unwrap(),
                    changed
                );
                let reverse = rewrite_compact(
                    &changed,
                    &target,
                    [Some(0x600..0x620), Some(0x620..0x640), Some(0x640..0x660)],
                )
                .unwrap();
                let restored = programs(&reverse).unwrap();
                for (i, p) in restored.iter().enumerate() {
                    assert_eq!(p.variant as usize, a[i]);
                    assert_eq!(p.body.bytes, programs(&target).unwrap()[i].body.bytes);
                }
                for (offset, (old, new)) in target.iter().zip(&changed).enumerate() {
                    if old != new {
                        assert!(
                            (0..3).any(|i| ((i + 1) * 0x100
                                ..(i + 1) * 0x100
                                    + [BASE.as_slice(), OFFSET.as_slice(), STEP.as_slice()][i]
                                        [a[i]]
                                        .len())
                                .contains(&offset))
                                || reservations.iter().flatten().any(|r| r.contains(&offset))
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn compact_reader_rejects_wrong_overflow_targets_and_corruption() {
        let target = fixture([0, 0, 0], 0x410780);
        let donor = fixture([1, 1, 1], 0x410790);
        let changed = rewrite_compact(&target, &donor, spaces()).unwrap();
        let bound = programs(&changed).unwrap();
        let jump_at = bound[0].body.spans[0].end - 4;
        for destination in [0x410100, 0x410501, 0x410800, 0x400000] {
            let mut bad = changed.clone();
            bad[jump_at..jump_at + 4]
                .copy_from_slice(&native::encoding::jump(destination).unwrap());
            assert!(programs(&bad).is_err());
        }
        let mut bad = changed;
        let at = bound[0].body.spans[1].start;
        bad[at] ^= 0x80;
        assert!(programs(&bad).is_err());
        assert!(rewrite_compact(&target, &donor, [Some(0x500..0x502), None, None]).is_err());
    }

    #[test]
    fn every_conversion_form_uses_target_calls_even_when_donor_calls_differ() {
        let conventions = [[0, 0, 0], [1, 1, 1], [1, 2, 2]];
        for a in conventions {
            for b in conventions {
                let target = fixture(a, 0x410600);
                let donor = fixture(b, 0x410700);
                let changed = rewrite(&target, &donor, spaces()).unwrap();
                let actual = programs(&changed).unwrap();
                for (n, p) in actual.iter().enumerate() {
                    assert_eq!(p.variant as usize, b[n], "{a:?} -> {b:?}");
                    for (i, call) in calls(&p.template).unwrap().into_iter().enumerate() {
                        assert_eq!(
                            changed[p.at + call..p.at + call + 3],
                            (0x410600 + i as u32 * 2).to_be_bytes()[1..]
                        );
                    }
                }
                let donor_programs = programs(&donor).unwrap();
                for (p, source) in actual.iter().zip(&donor_programs) {
                    let template = &source.template;
                    let relocations = calls(template).unwrap();
                    for offset in 0..template.len() {
                        if !relocations
                            .iter()
                            .any(|at| (*at..*at + 3).contains(&offset))
                        {
                            assert_eq!(
                                changed[p.at + offset],
                                donor[source.at + offset],
                                "non-relocation OEM byte {offset}, {a:?} -> {b:?}"
                            );
                        }
                    }
                }
                // The checksum/header bytes belong to the shared composer.
                assert_eq!(changed[..0x100], target[..0x100]);
            }
        }
    }

    #[test]
    fn growth_requires_valid_nonoverlapping_caller_reservations() {
        let target = fixture([0, 0, 0], 0x410600);
        let donor = fixture([1, 1, 1], 0x410700);
        assert_eq!(
            rewrite(&target, &donor, [None, None, None]),
            Err(Error::SpaceRequired(Element::CalibrationBase))
        );
        for bad in [
            [Some(0x501..0x541), Some(0x540..0x584), Some(0x584..0x5b8)],
            [Some(0x500..0x520), Some(0x540..0x584), Some(0x584..0x5b8)],
            [Some(0x500..0x580), Some(0x540..0x584), Some(0x584..0x5b8)],
            [Some(0x100..0x180), Some(0x540..0x584), Some(0x584..0x5b8)],
        ] {
            assert_eq!(rewrite(&target, &donor, bad), Err(Error::InvalidSpace));
        }
        let mut occupied = target.clone();
        occupied[0x510] = 0;
        assert_eq!(
            rewrite(&occupied, &donor, spaces()),
            Err(Error::InvalidSpace)
        );
    }

    #[test]
    fn equal_conversions_are_byte_identical_and_do_not_need_code_space() {
        let target = fixture([1, 2, 2], 0x410600);
        let donor = fixture([1, 2, 2], 0x410700);
        assert_eq!(
            rewrite(&target, &donor, [None, None, None]).unwrap(),
            target
        );
        let mut malformed = target.clone();
        malformed[0x100] ^= 0x80;
        assert!(matches!(
            rewrite(&malformed, &donor, spaces()),
            Err(Error::Unbound(Unbound::Missing(Element::CalibrationBase)))
        ));
        let mut odd_call = target.clone();
        odd_call[0x100 + calls(BASE[1]).unwrap()[0] + 2] |= 1;
        assert_eq!(
            rewrite(&odd_call, &fixture([0, 0, 0], 0x410700), spaces()),
            Err(Error::InvalidProgram)
        );
    }
}

#[cfg(test)]
#[test]
#[ignore = "requires PIONEER_NORMAL_CORPUS and its exact paired Kernels"]
fn compact_arithmetic_held_native_callers() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let mut fixtures = Vec::new();
    let mut images = std::collections::BTreeMap::new();
    for file in std::fs::read_dir(&root).unwrap() {
        let path = file.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        if name.len() != 68 || !name.ends_with(".bin") {
            continue;
        }
        let b = std::fs::read(&path).unwrap();
        let kernel = std::fs::read(path.with_extension("kernel.bin")).unwrap();
        let ps = programs(&b).unwrap();
        PROOF_SPANS.lock().unwrap().clear();
        for p in &ps {
            for span in &p.body.spans {
                record_proof(BASE_ADDRESS + span.start, &b[span.clone()]);
            }
            let cs = calls(&p.template).unwrap();
            let field = *cs.last().unwrap();
            let helper = u32::from_be_bytes([
                0,
                p.body.bytes[field],
                p.body.bytes[field + 1],
                p.body.bytes[field + 2],
            ]) as usize
                - BASE_ADDRESS;
            match p.element {
                Element::CalibrationBase => assert!(
                    scratch_callers(&b, Some(&kernel), p, None, u32::MAX),
                    "{name} BASE"
                ),
                Element::CalibrationStep => assert!(
                    scratch_callers(&b, Some(&kernel), p, Some(helper), 0xff00),
                    "{name} STEP"
                ),
                Element::CalibrationOffset => {
                    let proved = offset_flags_dead(&b, Some(&kernel), p);
                    if p.variant != 0 {
                        assert!(proved, "{name} OFFSET flags");
                    }
                }
                _ => {}
            }
        }
        let mut spans = Vec::<(usize, Vec<u8>)>::new();
        for (at, byte) in PROOF_SPANS.lock().unwrap().iter() {
            if let Some((start, bytes)) = spans
                .last_mut()
                .filter(|(start, bytes)| *start + bytes.len() == *at)
            {
                let _ = start;
                bytes.push(*byte);
            } else {
                spans.push((*at, alloc::vec![*byte]));
            }
        }
        let spans: Vec<_> = spans
            .into_iter()
            .map(|(at, bytes)| {
                serde_json::json!([
                    at,
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                ])
            })
            .collect();
        fixtures.push(serde_json::json!({"normal":&name[..64],"normal_len":b.len(),"spans":spans}));
        images.insert(name[..64].to_string(), (b, kernel));
    }
    if let Some(path) = std::env::var_os("PIONEER_ARITHMETIC_EXPORT") {
        std::fs::write(path, serde_json::to_string_pretty(&fixtures).unwrap()).unwrap();
    }
    for (target, donor) in [
        (
            "84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750",
            "87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1",
        ),
        (
            "84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750",
            "95664992a098ff6c3c8a9c4bae228209d956f4a1462c238fb37863b910b72149",
        ),
        (
            "84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750",
            "e6bdfa9bd0220f618d3e4bf722a590c2e1cf4216431869ab399561b94c71f515",
        ),
        (
            "3711cd5cdde5b5e7f288ccd7bc7fe1100eb6de5e40f3d0ffdcc528fb93ebeb46",
            "c93736b1fc66c7ada2d586044bf5d8a50a622b65e2f1fe6e74ad212f254adc1b",
        ),
    ] {
        let (b, k) = &images[target];
        let (d, _) = &images[donor];
        let changed =
            rewrite_specialized_with_kernel(b, d, [None, Some(0x400..0x40a), None], Some(k))
                .unwrap();
        verify_specialized_callers(&changed, Some(k)).unwrap();
        let actual = programs(&changed).unwrap();
        assert_eq!(actual[0].body.bytes.len(), 52);
        assert_eq!(actual[1].body.bytes.len(), 60);
        assert_eq!(actual[2].body.bytes.len(), 44);
        assert_eq!(actual[1].body.spans[1], 0x400..0x40a);
        assert_eq!(
            rewrite_specialized_with_kernel(&changed, d, [None, None, None], Some(k)).unwrap(),
            changed
        );
    }
}

#[cfg(test)]
#[path = "conversions/arithmetic_tests.rs"]
mod arithmetic_tests;

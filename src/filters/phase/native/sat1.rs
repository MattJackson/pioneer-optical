//! Complete SAT1 command, mode selection and native split-word output graphs.
use super::*;
pub mod phase_only;
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, encode_insn, Ea, Insn, Operand as O, Reg, Size},
    Mode, Target,
};
#[rustfmt::skip]
const DIRECT_CALLER: &[Option<u8>] = &[Some(0x01),Some(0x20),Some(0x6d),Some(0xf4),Some(0x0c),Some(0x1c),Some(0x0c),Some(0x9e),Some(0x0c),Some(0x86),Some(0x0c),Some(0x08),Some(0x17),Some(0xd0),Some(0x0d),Some(0x0e),Some(0x47),Some(0x10),Some(0x79),Some(0x2e),Some(0x00),Some(0x04),Some(0x4d),Some(0x06),Some(0x79),Some(0x2e),Some(0x00),Some(0x05),Some(0x4f),Some(0x04),Some(0x18),Some(0x00),Some(0x40),Some(0x02),Some(0xf0),Some(0x01),Some(0x7a),Some(0x05),None,None,None,None,Some(0x68),Some(0xd0),Some(0x5e),None,None,None,Some(0xa8),Some(0x01),Some(0x46),Some(0x04),Some(0x18),Some(0x00),Some(0x68),Some(0xd0),Some(0x68),Some(0x58),Some(0xa8),Some(0x01),Some(0x46),Some(0x04),Some(0x5e),None,None,None,Some(0x79),Some(0x2e),Some(0x00),Some(0x05),Some(0x42),Some(0x44),Some(0x0d),Some(0xe0),Some(0x17),Some(0x70),Some(0x0a),Some(0x80),Some(0x78),Some(0x00),Some(0x6b),Some(0x20),None,None,None,None,Some(0x17),Some(0x70),Some(0x7a),Some(0x10),None,None,None,None,Some(0x59),Some(0x00),Some(0x7a),Some(0x01),None,None,None,None,Some(0x40),Some(0x20),Some(0x7a),Some(0x01),None,None,None,None,Some(0x40),Some(0x18),Some(0x7a),Some(0x01),None,None,None,None,Some(0x0c),Some(0xcc),Some(0x46),Some(0x0e),Some(0x7a),Some(0x01),None,None,None,None,Some(0x40),Some(0x06),Some(0x7a),Some(0x01),None,None,None,None,Some(0x0d),Some(0x60),Some(0x55),Some(0x1a),Some(0x01),Some(0x20),Some(0x6d),Some(0x76),Some(0x54),Some(0x70)];
const COMMAND: &[Option<u8>] = &[
    Some(0x01),
    Some(0x10),
    Some(0x6d),
    Some(0xf4),
    Some(0x0c),
    Some(0x92),
    Some(0x0c),
    Some(0x04),
    Some(0x0c),
    Some(0x8a),
    Some(0x7a),
    Some(0x05),
    None,
    None,
    None,
    None,
    Some(0x6e),
    Some(0x50),
    Some(0x00),
    Some(0x0e),
    Some(0x18),
    Some(0x08),
    Some(0x6e),
    Some(0x50),
    Some(0x00),
    Some(0x10),
    Some(0x08),
    Some(0x08),
    Some(0x6e),
    Some(0xd8),
    Some(0x00),
    Some(0x10),
    Some(0x6e),
    Some(0x58),
    Some(0x00),
    Some(0x10),
    Some(0xa8),
    Some(0x80),
    Some(0x45),
    Some(0x08),
    Some(0x18),
    Some(0x11),
    Some(0x6e),
    Some(0xd1),
    Some(0x00),
    Some(0x10),
    Some(0x40),
    Some(0x14),
    Some(0x6e),
    Some(0x50),
    Some(0x00),
    Some(0x10),
    Some(0x6e),
    Some(0x58),
    Some(0x00),
    Some(0x11),
    Some(0x1c),
    Some(0x80),
    Some(0x45),
    Some(0x08),
    Some(0x6e),
    Some(0x58),
    Some(0x00),
    Some(0x11),
    Some(0x6e),
    Some(0xd8),
    Some(0x00),
    Some(0x10),
    Some(0xea),
    Some(0x3f),
    Some(0x0c),
    Some(0xac),
    Some(0x6e),
    Some(0x50),
    Some(0x00),
    Some(0x0e),
    Some(0x1c),
    Some(0xa0),
    Some(0x43),
    Some(0x14),
    Some(0x6e),
    Some(0x59),
    Some(0x00),
    Some(0x0e),
    Some(0x17),
    Some(0x51),
    Some(0x0c),
    Some(0xc8),
    Some(0x17),
    Some(0x50),
    Some(0x19),
    Some(0x01),
    Some(0x79),
    Some(0x21),
    Some(0x00),
    Some(0x10),
    Some(0x4e),
    Some(0x20),
    Some(0x40),
    Some(0x1a),
    Some(0x6e),
    Some(0x58),
    Some(0x00),
    Some(0x0e),
    Some(0x1c),
    Some(0xc8),
    Some(0x44),
    Some(0x1e),
    Some(0x0c),
    Some(0xc8),
    Some(0x17),
    Some(0x50),
    Some(0x6e),
    Some(0x59),
    Some(0x00),
    Some(0x0e),
    Some(0x17),
    Some(0x51),
    Some(0x19),
    Some(0x10),
    Some(0x79),
    Some(0x20),
    Some(0x00),
    Some(0x10),
    Some(0x4f),
    Some(0x04),
    Some(0x18),
    Some(0x99),
    Some(0x40),
    Some(0x02),
    Some(0xf9),
    Some(0x01),
    Some(0x6a),
    Some(0xa9),
    None,
    None,
    None,
    None,
    Some(0x0c),
    Some(0x44),
    Some(0x46),
    Some(0x08),
    Some(0x0c),
    Some(0x22),
    Some(0x46),
    Some(0x04),
    Some(0xf0),
    Some(0x04),
    Some(0x40),
    Some(0x02),
    Some(0x0c),
    Some(0x40),
    Some(0x0c),
    Some(0x29),
    Some(0x6a),
    Some(0x21),
    None,
    None,
    None,
    None,
    Some(0x0c),
    Some(0xc8),
    Some(0x55),
    Some(0x0c),
    Some(0x6e),
    Some(0xdc),
    Some(0x00),
    Some(0x0e),
    Some(0x01),
    Some(0x10),
    Some(0x6d),
    Some(0x75),
    Some(0x54),
    Some(0x70),
];
#[rustfmt::skip]
const SWAPPED_CALLER: &[Option<u8>] = &[Some(0x01),Some(0x20),Some(0x6d),Some(0xf4),Some(0x0c),Some(0x1c),Some(0x0c),Some(0x9e),Some(0x0c),Some(0x86),Some(0x0c),Some(0x08),Some(0x17),Some(0xd0),Some(0x0d),Some(0x0e),Some(0x47),Some(0x10),Some(0x79),Some(0x2e),Some(0x00),Some(0x04),Some(0x4d),Some(0x06),Some(0x79),Some(0x2e),Some(0x00),Some(0x05),Some(0x4f),Some(0x04),Some(0x18),Some(0x00),Some(0x40),Some(0x02),Some(0xf0),Some(0x01),Some(0x7a),Some(0x05),None,None,None,None,Some(0x68),Some(0xd0),Some(0x5e),None,None,None,Some(0xa8),Some(0x01),Some(0x46),Some(0x04),Some(0x18),Some(0x00),Some(0x68),Some(0xd0),Some(0x68),Some(0x58),Some(0xa8),Some(0x01),Some(0x46),Some(0x04),Some(0x5e),None,None,None,Some(0x79),Some(0x2e),Some(0x00),Some(0x05),Some(0x42),Some(0x4a),Some(0x0d),Some(0xe0),Some(0x17),Some(0x70),Some(0x0a),Some(0x80),Some(0x78),Some(0x00),Some(0x6b),Some(0x20),None,None,None,None,Some(0x17),Some(0x70),Some(0x7a),Some(0x10),None,None,None,None,Some(0x59),Some(0x00),Some(0x7a),Some(0x01),None,None,None,None,Some(0x40),Some(0x26),Some(0x0c),Some(0xcc),Some(0x46),Some(0x0c),Some(0x7a),Some(0x01),None,None,None,None,Some(0x40),Some(0x1a),Some(0x0c),Some(0xcc),Some(0x47),Some(0x08),Some(0x7a),Some(0x01),None,None,None,None,Some(0x40),Some(0x0e),Some(0x7a),Some(0x01),None,None,None,None,Some(0x40),Some(0x06),Some(0x7a),Some(0x01),None,None,None,None,Some(0x0d),Some(0x60),Some(0x55),Some(0x1a),Some(0x01),Some(0x20),Some(0x6d),Some(0x76),Some(0x54),Some(0x70)];
const ZERO: &[u8] = &[
    0x18, 0x88, 0x6a, 0x88, 0xf9, 0x12, 0x6a, 0x88, 0xf9, 0x13, 0x6a, 0x88, 0xf9, 0x10, 0x6a, 0x88,
    0xf9, 0x11, 0x54, 0x70,
];

/// Complete bounded SAT1 mechanism proof is unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A complete native grammar or resource was unavailable.
    Unresolved,
    /// Native resources or symbolic helper roles disagree.
    ResourceMismatch,
    /// Visible references prevent reclaiming native instructions.
    Ownership,
    /// Emitted code failed complete rebinding.
    Verification,
}
/// Complete command-relative source/table/output graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Native channel convention, including its mode-two phase selection.
    pub assignment: Assignment,
    /// Complete upstream phase command, including state update and direction inference.
    pub command: Range<usize>,
    /// Complete caller entry footprint; optional native epilogue resides in output tail.
    pub caller: Range<usize>,
    /// Full native output entry footprint, including positively retired tail.
    pub output: Range<usize>,
    /// Existing zero-output leaf, retained at its original entry.
    pub zero: Range<usize>,
    /// Six native selector destinations, relative to the bound jump base.
    pub jump_table: Range<usize>,
    /// Native ROM coefficient tables: normal, positive, negative, zero, auxiliary.
    pub tables: [Range<usize>; 5],
    /// Exact retained target Kernel identity and high-byte extractor entry points.
    pub encoders: [u32; 2],
    /// Upstream state, direction flag and mode flag RAM operands.
    pub state: [u32; 3],
    /// Target mode getter and conditional opaque auxiliary service.
    pub helpers: [u32; 2],
    /// Complete mode getter that kills comparison scratch flags before use.
    pub mode_getter: Range<usize>,
}
#[derive(Clone)]
struct Bound {
    facts: Binding,
    caller_code: Vec<u8>,
    output_code: Vec<u8>,
    compact: bool,
    selector_compact: bool,
}
fn read(bytes: &[u8], at: usize, n: usize) -> u32 {
    integer(&bytes[at..at + n])
}
fn stored(n: &[u8], a: u32, len: usize) -> Result<Range<usize>, Error> {
    let start = a.checked_sub(0x410000).ok_or(Error::ResourceMismatch)? as usize;
    let end = start.checked_add(len).ok_or(Error::ResourceMismatch)?;
    let r = crate::image::regions(n).ok_or(Error::Unresolved)?;
    if a & 1 != 0
        || !r.stored.iter().any(|r| {
            let o = r.as_ptr() as usize - n.as_ptr() as usize;
            start >= o && end <= o + r.len()
        })
    {
        return Err(Error::ResourceMismatch);
    }
    Ok(start..end)
}
fn fits(bytes: &[u8], shape: &[Option<u8>]) -> bool {
    bytes.len() == shape.len()
        && bytes
            .iter()
            .zip(shape)
            .all(|(b, t)| t.map_or(true, |t| *b == t))
}
fn decoded(code: &[u8]) -> Result<Vec<(usize, Insn, usize)>, Error> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < code.len() {
        let d = decode_insn(&code[at..], Target::H8S2000, Mode::Advanced)
            .map_err(|_| Error::Unresolved)?;
        out.push((at, d.insn, d.len));
        at += d.len;
    }
    Ok(out)
}
fn encode(i: Insn) -> Result<Vec<u8>, Error> {
    encode_insn(i, Target::H8S2000, Mode::Advanced).map_err(|_| Error::Unresolved)
}
// Derive transformations solely from the complete observed native instruction
// stream. The map relocates every internal relative branch through h8-asm.
fn transform(code: &[u8], selector: bool) -> Result<(Vec<u8>, Vec<usize>), Error> {
    let insns = decoded(code)?;
    let mut edited = Vec::new();
    let mut map = alloc::vec![usize::MAX;code.len()+1];
    let mut next = 0;
    let mut literals = 0;
    for (at, mut i, len) in insns {
        map[at] = next;
        let remove = if selector {
            false
        } else if i.mnemonic == "MOV"
            && matches!(i.operands[0], O::Immediate { bits: 32, .. })
            && i.operands[1] == O::Register(Reg::Long(4))
        {
            literals += 1;
            literals == 1
        } else {
            i.mnemonic == "JSR"
                && (matches!(i.operands[0], O::Address(Ea::Absolute { .. })) || literals == 1)
        };
        if remove {
            continue;
        }
        if selector && [18, 24].contains(&at) {
            if i.mnemonic != "CMP" || i.size != Some(Size::Word) {
                return Err(Error::Unresolved);
            }
            i.size = Some(Size::Byte);
            i.operands[0] = match i.operands[0] {
                O::Immediate { value, .. } => O::Immediate { value, bits: 8 },
                _ => return Err(Error::Unresolved),
            };
            i.operands[1] = O::Register(Reg::Byte(8));
        }
        let length = encode(i)?.len();
        edited.push((at, i, len, next));
        next += length;
    }
    map[code.len()] = next;
    let mut out = Vec::new();
    for (at, mut i, len, to) in edited {
        if let O::Address(Ea::PcRelative { value, bits }) = i.operands[0] {
            let target = (at + len)
                .checked_add_signed(value as isize)
                .ok_or(Error::Unresolved)?;
            if target < code.len() {
                let dest = *map.get(target).ok_or(Error::Unresolved)?;
                if dest == usize::MAX {
                    return Err(Error::Unresolved);
                }
                i.operands[0] = O::Address(Ea::PcRelative {
                    value: dest as i32 - (to + encode(i)?.len()) as i32,
                    bits,
                });
            }
        }
        out.extend(encode(i)?);
    }
    Ok((out, map))
}
fn derived(shape: &[Option<u8>], selector: bool) -> Result<Vec<Option<u8>>, Error> {
    // Wildcard operands are zero only while deriving recognition masks. No
    // replacement firmware is emitted from this recognition-only material.
    let concrete: Vec<_> = shape.iter().map(|x| x.unwrap_or(0)).collect();
    let (code, map) = transform(&concrete, selector)?;
    let mut result: Vec<_> = code.into_iter().map(Some).collect();
    for (at, _, len) in decoded(&concrete)? {
        if map[at] == usize::MAX {
            continue;
        }
        let next = map[at + len];
        if next == map[at] {
            continue;
        }
        // Every wildcard is an unchanged absolute address operand.
        if shape[at..at + len].iter().any(Option::is_none) {
            if next - map[at] != len {
                return Err(Error::Unresolved);
            }
            for j in 0..len {
                if shape[at + j].is_none() {
                    result[map[at] + j] = None;
                }
            }
        }
    }
    Ok(result)
}
fn consumer_shape(t: &Template, compact: bool) -> Result<Vec<Option<u8>>, Error> {
    let mut shape: Vec<_> = t.bytes.iter().copied().map(Some).collect();
    for r in t.relocations {
        shape[r.start..r.end].fill(None);
    }
    if compact {
        derived(&shape, false)
    } else {
        Ok(shape)
    }
}

fn bind(normal: &[u8]) -> Result<Bound, Error> {
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let mut found: Option<Bound> = None;
    for (assignment, original) in [
        (Assignment::Direct, DIRECT_CALLER),
        (Assignment::Swapped, SWAPPED_CALLER),
    ] {
        for selector_compact in [false, true] {
            let shape = if selector_compact {
                derived(original, true)?
            } else {
                original.to_vec()
            };
            for at in crate::filters::phase::bundle::sites(normal, &regions.stored, &shape[..16]) {
                // The zero leaf fixes the original entry footprint independent
                // of the requested donor convention and any epilogue split.
                for capacity in [146, 152] {
                    let zero = at + capacity..at + capacity + 20;
                    if normal.get(zero.clone()) != Some(ZERO) {
                        continue;
                    }
                    let mut caller = Vec::new();
                    let split = shape.len() > capacity;
                    let tail = zero.end + 156;
                    if split {
                        if shape.len() != 148
                            || capacity != 146
                            || normal.get(at + 142..at + 146)
                                != encoding::jump((0x410000 + tail) as u32).as_deref()
                        {
                            continue;
                        }
                        caller.extend_from_slice(&normal[at..at + 142]);
                        caller.extend_from_slice(
                            normal.get(tail..tail + 6).ok_or(Error::Unresolved)?,
                        );
                    } else {
                        let Some(code) = normal.get(at..at + shape.len()) else {
                            continue;
                        };
                        caller.extend_from_slice(code);
                        if !normal
                            .get(at + shape.len()..at + capacity)
                            .is_some_and(|b| b.iter().all(|x| *x == 0))
                        {
                            continue;
                        }
                    }
                    // BSR displacement follows the physical, retained output
                    // entry rather than the donor's original caller length.
                    let call = caller.len() - 8;
                    if caller.get(call..call + 1) != Some(&[0x55]) {
                        continue;
                    }
                    let expected = (zero.end - (at + call + 2)) as u8;
                    if caller[call + 1] != expected {
                        continue;
                    }
                    let mut matching = caller.clone();
                    matching[call + 1] = shape[call + 1].ok_or(Error::Unresolved)?;
                    if !fits(&matching, &shape) {
                        continue;
                    }
                    let shift = if selector_compact { 4 } else { 0 };
                    let field = |offset| {
                        read(
                            &caller,
                            if offset >= 28 { offset - shift } else { offset },
                            if [45, 63].contains(&offset) { 3 } else { 4 },
                        )
                    };
                    let flag = field(38);
                    let helpers = [field(45), field(63)];
                    let jt = stored(normal, field(82), 12)?;
                    let base = at + 96 - shift;
                    if field(90) != 0x410000 + base as u32 {
                        continue;
                    }
                    let jumps = if assignment == Assignment::Direct {
                        [0, 8, 34, 34, 16, 16]
                    } else {
                        [32, 0, 40, 40, 8, 20]
                    };
                    if !normal[jt.clone()]
                        .chunks_exact(2)
                        .zip(jumps)
                        .all(|(b, j)| u16::from_be_bytes([b[0], b[1]]) == j)
                    {
                        continue;
                    }
                    let table_offsets = if assignment == Assignment::Direct {
                        [98, 124, 114, 106, 132]
                    } else {
                        [130, 110, 122, 98, 138]
                    };
                    let mut tables = alloc::vec![];
                    for offset in table_offsets {
                        tables.push(stored(normal, read(&caller, offset - shift, 4), 256)?);
                    }
                    let tables: [Range<usize>; 5] =
                        tables.try_into().map_err(|_| Error::Unresolved)?;
                    let command_start = at.checked_sub(176).ok_or(Error::Unresolved)?;
                    let command = command_start..command_start + 174;
                    let c = normal.get(command.clone()).ok_or(Error::Unresolved)?;
                    if !fits(c, COMMAND) || read(c, 134, 4) != read(c, 156, 4) {
                        continue;
                    }
                    let state = read(c, 12, 4);
                    let direction = read(c, 134, 4);
                    let getter = stored(normal, helpers[0], 18)?;
                    let g = &normal[getter.clone()];
                    if g[..2] != [0x6a, 0x28]
                        || g[6..] != [0xa8, 3, 0x46, 4, 0xf8, 1, 0x40, 2, 0x18, 0x88, 0x54, 0x70]
                        || read(g, 2, 4) != state + 13
                        || flag + 2 != direction
                    {
                        continue;
                    }
                    if [state, direction, flag]
                        .iter()
                        .any(|v| *v == 0 || *v >= 0x410000)
                        || helpers[1] & 1 != 0
                        || helpers[1] < 0x400000
                    {
                        continue;
                    }
                    for t in templates::TEMPLATES.iter().filter(|t| {
                        t.bytes.len() == 174
                            && t.interface == Interface::SplitWord
                            && t.assignment == assignment
                    }) {
                        for compact in [false, true] {
                            let output_shape = consumer_shape(t, compact)?;
                            let output = zero.end..zero.end + 174;
                            let Some(code) =
                                normal.get(output.start..output.start + output_shape.len())
                            else {
                                continue;
                            };
                            if !fits(code, &output_shape) {
                                continue;
                            }
                            let mut high = None;
                            let mut low = None;
                            let mut literals = Vec::new();
                            for (_, i, _) in decoded(code)? {
                                match i.operands[0] {
                                    O::Address(Ea::Absolute { value, bits: 24 })
                                        if i.mnemonic == "JSR" =>
                                    {
                                        if high.replace(value).is_some_and(|v| v != value) {
                                            return Err(Error::ResourceMismatch);
                                        }
                                    }
                                    O::Immediate { value, bits: 32 }
                                        if i.mnemonic == "MOV"
                                            && i.operands[1] == O::Register(Reg::Long(4)) =>
                                    {
                                        literals.push(value);
                                        if compact || high != Some(value) {
                                            low = Some(value)
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            let low = low.ok_or(Error::ResourceMismatch)?;
                            let high =
                                high.unwrap_or(low.checked_sub(2).ok_or(Error::ResourceMismatch)?);
                            if low != high + 2
                                || (compact && literals != [low])
                                || (!compact && literals != [high, low])
                            {
                                return Err(Error::ResourceMismatch);
                            }
                            if compact {
                                let used = if split { 162 } else { 156 };
                                if normal
                                    .get(output.start + used..output.end)
                                    .map_or(true, |b| b.iter().any(|x| *x != 0))
                                {
                                    continue;
                                }
                            }
                            let mut all = alloc::vec![
                                command.clone(),
                                at..at + capacity,
                                zero.clone(),
                                output.clone(),
                                jt.clone(),
                                getter.clone()
                            ];
                            all.extend(tables.iter().cloned());
                            for (i, a) in all.iter().enumerate() {
                                for b in &all[i + 1..] {
                                    if a.start < b.end && b.start < a.end {
                                        return Err(Error::ResourceMismatch);
                                    }
                                }
                            }
                            let result = Bound {
                                facts: Binding {
                                    assignment,
                                    command: command.clone(),
                                    caller: at..at + capacity,
                                    output: output.clone(),
                                    zero: zero.clone(),
                                    jump_table: jt.clone(),
                                    tables: tables.clone(),
                                    encoders: [high, low],
                                    state: [state, direction, flag],
                                    helpers,
                                    mode_getter: getter.clone(),
                                },
                                caller_code: caller.clone(),
                                output_code: code.to_vec(),
                                compact,
                                selector_compact,
                            };
                            if let Some(previous) = &found {
                                if previous.facts != result.facts {
                                    return Err(Error::Unresolved);
                                }
                            } else {
                                found = Some(result)
                            }
                        }
                    }
                }
            }
        }
    }
    found.ok_or(Error::Unresolved)
}
/// Bind the complete Normal graph. Exact resident encoder validation remains
/// mandatory before an operation through [`observe`] or [`transplant`].
pub fn observe_normal(normal: &[u8]) -> Result<Binding, Error> {
    Ok(bind(normal)?.facts)
}
/// Bind complete phase command/mode/output routines and both exact Kernel leaves.
pub fn observe(normal: &[u8], kernel: &[u8]) -> Result<Binding, Error> {
    let b = bind(normal)?.facts;
    if kernel.len() != crate::image::KERNEL_LEN {
        return Err(Error::ResourceMismatch);
    }
    let at = b.encoders[0]
        .checked_sub(0x400000)
        .ok_or(Error::ResourceMismatch)? as usize;
    if kernel.get(at..at + 6) != Some(&[0x54, 0x70, 0x0c, 0x08, 0x54, 0x70]) {
        return Err(Error::ResourceMismatch);
    }
    Ok(b)
}

fn ownership(normal: &[u8], kernel: &[u8], b: &Binding) -> Result<(), Error> {
    if kernel.len() != crate::image::KERNEL_LEN {
        return Err(Error::Ownership);
    }
    // Reclaimed executable bytes need exclusive visible-entry ownership. ROM
    // tables and their six-way selector are existing positively bound native
    // resources, as in the other phase table owners; arbitrary numeric data is
    // not treated as a pointer proving a second consumer of those tables.
    let protected = |address: usize| {
        let Some(at) = address.checked_sub(0x410000) else {
            return false;
        };
        b.caller.contains(&at) || b.output.contains(&at)
    };
    for (bytes, base) in [(normal, 0x410000usize), (kernel, 0x400000)] {
        let regions = crate::image::regions(bytes).ok_or(Error::Ownership)?;
        for region in regions.stored {
            let start = region.as_ptr() as usize - bytes.as_ptr() as usize;
            for local in 0..region.len() {
                let at = start + local;
                // These complete native bodies establish both operand interiors
                // and every outgoing reference. No arbitrary enclosing decode is
                // used to waive references. Command contains one bound BSR entry.
                if base == 0x410000
                    && (b.caller.contains(&at) || b.output.contains(&at) || b.command.contains(&at))
                {
                    continue;
                }
                if local + 4 <= region.len() && protected(read(region, local, 4) as usize) {
                    return Err(Error::Ownership);
                }
                if at & 1 != 0 {
                    continue;
                }
                let Ok(d) = decode_insn(&region[local..], Target::H8S2000, Mode::Advanced) else {
                    continue;
                };
                for o in d.insn.operands {
                    let value = match o {
                        O::Immediate {
                            value,
                            bits: 24 | 32,
                        }
                        | O::Address(Ea::Absolute {
                            value,
                            bits: 24 | 32,
                        }) => Some(value as usize),
                        O::Address(Ea::PcRelative { value, .. }) => {
                            (base + at + d.len).checked_add_signed(value as isize)
                        }
                        O::Address(Ea::Displacement {
                            value, bits: 32, ..
                        }) => Some(value as usize),
                        _ => None,
                    };
                    if value.is_some_and(protected) {
                        return Err(Error::Ownership);
                    }
                }
            }
        }
    }
    Ok(())
}
fn field(code: &mut [u8], at: usize, width: usize, value: u32) -> Result<(), Error> {
    encoding::retarget_field(code, at, width, value).ok_or(Error::ResourceMismatch)
}
/// Carry the donor's complete mode-to-table and phase-to-output convention into
/// the target's existing native resources. Both exact Kernel encoders are bound.
/// Persistent state is never written: only Normal instructions and ROM tables
/// change, while all original RAM slots and opaque target services remain.
///
/// The native sign-extended mode comparisons are narrowed to their original byte
/// argument; signed branch outcomes agree for every 8-bit input. The complete
/// mode getter kills differing H before any use. Removing identity calls and
/// their dead literal frees18 bytes in the existing output body; a six-byte
/// caller epilogue can occupy that positively owned tail without moving entries.
pub fn transplant(
    target: &[u8],
    target_kernel: &[u8],
    donor: &[u8],
    donor_kernel: &[u8],
) -> Result<Vec<u8>, Error> {
    let a = observe(target, target_kernel)?;
    let b = observe(donor, donor_kernel)?;
    if a.assignment == b.assignment
        && a.tables
            .iter()
            .zip(&b.tables)
            .all(|(x, y)| target[x.clone()] == donor[y.clone()])
    {
        return Ok(target.to_vec());
    }
    ownership(target, target_kernel, &a)?;
    let original = bind(target)?;
    let source = bind(donor)?;
    let mut caller = if source.selector_compact {
        source.caller_code.clone()
    } else {
        transform(&source.caller_code, true)?.0
    };
    let mut output = if source.compact {
        source.output_code.clone()
    } else {
        transform(&source.output_code, false)?.0
    };
    if output.len() != 156 || !matches!(caller.len(), 142 | 148) {
        return Err(Error::ResourceMismatch);
    }
    // Both original callers share the same symbolic prefix and opaque calls.
    for (at, width, value) in [
        (34, 4, a.state[2]),
        (41, 3, a.helpers[0]),
        (59, 3, a.helpers[1]),
        (78, 4, (0x410000 + a.jump_table.start) as u32),
        (86, 4, (0x410000 + a.caller.start + 92) as u32),
    ] {
        field(&mut caller, at, width, value)?;
    }
    let slots = if b.assignment == Assignment::Direct {
        [98, 124, 114, 106, 132]
    } else {
        [130, 110, 122, 98, 138]
    };
    for (at, table) in slots.into_iter().zip(&a.tables) {
        field(&mut caller, at - 4, 4, (0x410000 + table.start) as u32)?;
    }
    for (at, i, _) in decoded(&output)? {
        if i.mnemonic == "MOV"
            && matches!(i.operands[0], O::Immediate { bits: 32, .. })
            && i.operands[1] == O::Register(Reg::Long(4))
        {
            field(&mut output, at + 2, 4, a.encoders[1])?;
        }
    }
    let call = caller.len() - 8;
    let mut i = decode_insn(&caller[call..], Target::H8S2000, Mode::Advanced)
        .map_err(|_| Error::Unresolved)?
        .insn;
    i.operands[0] = O::Address(Ea::PcRelative {
        value: a.output.start as i32 - (a.caller.start + call + 2) as i32,
        bits: 8,
    });
    caller[call..call + 2].copy_from_slice(&encode(i)?);
    let mut changed = target.to_vec();
    encoding::nops(&mut changed[a.caller.clone()]).ok_or(Error::Unresolved)?;
    encoding::nops(&mut changed[a.output.clone()]).ok_or(Error::Unresolved)?;
    changed[a.output.start..a.output.start + output.len()].copy_from_slice(&output);
    if caller.len() > a.caller.len() {
        if a.caller.len() != 146 || caller.len() != 148 {
            return Err(Error::ResourceMismatch);
        }
        // All native conditional edges and the internal table destinations stay
        // before142. Only the LDM/RTS epilogue crosses this typed terminal jump.
        changed[a.caller.start..a.caller.start + 142].copy_from_slice(&caller[..142]);
        let tail = a.output.start + 156;
        changed[a.caller.start + 142..a.caller.end]
            .copy_from_slice(&encoding::jump((0x410000 + tail) as u32).ok_or(Error::Unresolved)?);
        changed[tail..tail + 6].copy_from_slice(&caller[142..]);
    } else {
        changed[a.caller.start..a.caller.start + caller.len()].copy_from_slice(&caller);
    }
    changed[a.jump_table.clone()].copy_from_slice(&donor[b.jump_table.clone()]);
    for (x, y) in a.tables.iter().zip(&b.tables) {
        changed[x.clone()].copy_from_slice(&donor[y.clone()]);
    }
    let after = observe(&changed, target_kernel).map_err(|_| Error::Verification)?;
    let mut expected = a;
    expected.assignment = b.assignment;
    if after != expected {
        return Err(Error::Verification);
    }
    // Complete command and zero-output behavior, helper bodies and RAM sources
    // are target-owned and unmodified; caller/output/table edits are exhaustive.
    if changed[original.facts.command.clone()] != target[original.facts.command]
        || changed[expected.zero.clone()] != target[expected.zero]
    {
        return Err(Error::Verification);
    }
    Ok(changed)
}
/// Recompute the complete operation after shared composition. Other owners may
/// edit disjoint bytes, but every command, helper, selector, table and output
/// prerequisite remains exactly the bounded native contract.
pub fn verify(
    target: &[u8],
    target_kernel: &[u8],
    donor: &[u8],
    donor_kernel: &[u8],
    changed: &[u8],
) -> Result<(), Error> {
    let expected = transplant(target, target_kernel, donor, donor_kernel)?;
    let a = observe(&expected, target_kernel)?;
    let actual = observe(changed, target_kernel)?;
    if a != actual {
        return Err(Error::Verification);
    }
    for r in [
        &a.command,
        &a.caller,
        &a.output,
        &a.zero,
        &a.jump_table,
        &a.mode_getter,
    ]
    .into_iter()
    .chain(a.tables.iter())
    {
        if expected[r.clone()] != changed[r.clone()] {
            return Err(Error::Verification);
        }
    }
    Ok(())
}

//! Split placement for OEM routines with no branches crossing the split.
use super::encoding;
use alloc::vec::Vec;
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, Ea, Operand},
    Mode, Target,
};

const BASE: usize = 0x410000;

/// A complete logical OEM body and the physical spans containing it.
#[derive(Debug, Clone)]
pub(crate) struct Body {
    pub bytes: Vec<u8>,
    pub spans: Vec<Range<usize>>,
}

fn stored(normal: &[u8], regions: &[&[u8]], span: &Range<usize>) -> bool {
    regions.iter().any(|r| {
        let at = r.as_ptr() as usize - normal.as_ptr() as usize;
        span.start >= at && span.end <= at + r.len()
    })
}

/// Read a complete template, optionally crossing one absolute JMP between
/// instructions. All physical bytes must be stored, disjoint and recognized.
pub(crate) fn read(
    normal: &[u8],
    regions: &[&[u8]],
    start: usize,
    template: &[Option<u8>],
) -> Option<Body> {
    let mut bytes = Vec::new();
    let mut spans = Vec::new();
    let mut at = start;
    let mut begin = start;
    let mut cut = None;
    while bytes.len() < template.len() {
        let decoded = decode_insn(normal.get(at..)?, Target::H8S2000, Mode::Advanced).ok()?;
        let end = at.checked_add(decoded.len)?;
        if !stored(normal, regions, &(at..end)) {
            return None;
        }
        if decoded.insn.mnemonic == "JMP" {
            if bytes.is_empty() || !spans.is_empty() {
                return None;
            }
            let Operand::Address(Ea::Absolute { value, bits: 24 }) = decoded.insn.operands[0]
            else {
                return None;
            };
            let next = (value as usize).checked_sub(BASE)?;
            if next & 1 != 0 {
                return None;
            }
            spans.push(begin..end);
            cut = Some(bytes.len());
            begin = next;
            at = next;
            continue;
        }
        let logical_end = bytes.len().checked_add(decoded.len)?;
        if !normal[at..end]
            .iter()
            .zip(template.get(bytes.len()..logical_end)?)
            .all(|(b, t)| t.map_or(true, |t| t == *b))
        {
            return None;
        }
        bytes.extend_from_slice(&normal[at..end]);
        at = end;
    }
    spans.push(begin..at);
    if spans.len() == 2 && spans[0].start < spans[1].end && spans[1].start < spans[0].end {
        return None;
    }
    let Flow { edges, .. } = flow(&bytes)?;
    if cut.is_some_and(|cut| edges.iter().any(|(from, to)| (*from < cut) != (*to < cut))) {
        return None;
    }
    Some(Body { bytes, spans })
}

/// Decode every instruction and resolve every relative edge to an instruction
/// start inside the OEM routine. Computed branches and early returns are refused.
struct Flow {
    starts: Vec<usize>,
    edges: Vec<(usize, usize)>,
}
fn flow(bytes: &[u8]) -> Option<Flow> {
    let mut starts = Vec::new();
    let mut edges = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        starts.push(at);
        let d = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced).ok()?;
        if matches!(d.insn.mnemonic, "JMP" | "RTE" | "TRAPA" | "SLEEP")
            || (d.insn.mnemonic == "RTS" && at + d.len != bytes.len())
        {
            return None;
        }
        for operand in d.insn.operands {
            if let Operand::Address(Ea::PcRelative { value, .. }) = operand {
                let destination = (at + d.len).checked_add_signed(value as isize)?;
                edges.push((at, destination));
            }
        }
        at += d.len;
        if at == bytes.len() && d.insn.mnemonic != "RTS" {
            return None;
        }
    }
    if edges.iter().any(|(_, to)| !starts.contains(to)) {
        return None;
    }
    Some(Flow { starts, edges })
}

/// Relocate two branch-closed pieces through h8-asm, retaining OEM bytes.
/// The selected cut cannot redirect any conditional or subroutine branch.
pub(crate) fn split_closed(
    bytes: &[u8],
    original_address: u32,
    original_len: usize,
    spill_address: u32,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let jump = encoding::jump(spill_address)?;
    let capacity = original_len.checked_sub(jump.len())?;
    let Flow { starts, edges } = flow(bytes)?;
    let cut = starts.into_iter().rev().find(|cut| {
        *cut != 0
            && *cut <= capacity
            && edges
                .iter()
                .all(|(from, to)| (*from < *cut) == (*to < *cut))
    })?;
    let suffix_address = original_address.checked_add(u32::try_from(cut).ok()?)?;
    let prefix = h8_asm::relocate::relocate(
        &bytes[..cut],
        original_address,
        original_address,
        Target::H8S2000,
        Mode::Advanced,
    )
    .ok()?;
    let spill = h8_asm::relocate::relocate(
        &bytes[cut..],
        suffix_address,
        spill_address,
        Target::H8S2000,
        Mode::Advanced,
    )
    .ok()?;
    // All relative edges were internal to their piece, so no widening or operand
    // changes are needed. Refuse any deviation from the copied OEM stream.
    if prefix.bytes != bytes[..cut] || spill.bytes != bytes[cut..] {
        return None;
    }
    let mut prefix = prefix.bytes;
    prefix.extend_from_slice(&jump);
    let used = prefix.len();
    prefix.resize(original_len, 0);
    encoding::nops(&mut prefix[used..])?;
    Some((prefix, spill.bytes))
}

//! Split placement for OEM straight-line routines. No control logic is synthesized.
use super::encoding;
use alloc::vec::Vec;
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, Ea, Operand},
    Mode, Target,
};

const BASE: usize = 0x410000;

/// A complete logical OEM body and the physical spans containing it.
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
            begin = next;
            at = next;
            continue;
        }
        if decoded
            .insn
            .operands
            .iter()
            .any(|o| matches!(o, Operand::Address(Ea::PcRelative { .. })))
        {
            return None;
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
    Some(Body { bytes, spans })
}

/// Retain the largest whole-instruction prefix fitting beside a JMP; spill the
/// remaining OEM bytes unchanged. The caller proves ownership and entry points.
pub(crate) fn split(
    bytes: &[u8],
    original_len: usize,
    spill_address: u32,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let jump = encoding::jump(spill_address)?;
    let capacity = original_len.checked_sub(jump.len())?;
    let mut at = 0;
    let mut cut = 0;
    while at < bytes.len() {
        let d = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced).ok()?;
        if matches!(d.insn.mnemonic, "JMP" | "RTE" | "TRAPA" | "SLEEP")
            || d.insn
                .operands
                .iter()
                .any(|o| matches!(o, Operand::Address(Ea::PcRelative { .. })))
            || (d.insn.mnemonic == "RTS" && at + d.len != bytes.len())
        {
            return None;
        }
        at += d.len;
        if at <= capacity {
            cut = at;
        }
        if at == bytes.len() && d.insn.mnemonic != "RTS" {
            return None;
        }
    }
    if cut == 0 || cut >= bytes.len() || spill_address & 1 != 0 {
        return None;
    }
    let mut prefix = bytes[..cut].to_vec();
    prefix.extend_from_slice(&jump);
    let used = prefix.len();
    prefix.resize(original_len, 0);
    encoding::nops(&mut prefix[used..])?;
    Some((prefix, bytes[cut..].to_vec()))
}

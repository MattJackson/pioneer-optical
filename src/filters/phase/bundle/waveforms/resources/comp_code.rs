//! Complete native function grammars for COMP reference interpretation.
//!
//! This stage proves instruction boundaries and each function's own balanced
//! stack on normal-return paths. Calls have conditional normal-return edges;
//! it does not assert callee termination, effects or stack integrity. Its result
//! requires native caller/table/client linkage before excluding raw data views.
//! Captured bodies are full native CFGs, not prologue windows or image hashes.
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, Ea, Operand as O, Reg, Size},
    Mode, Target,
};

struct Spec {
    base: u32,
    entry: u32,
    end: u32,
    offset: usize,
}
include!("comp_code/specs.rs");
const BYTES: &[u8] = include_bytes!("comp_code/functions.bin");
const SWITCH: &[u8] = include_bytes!("comp_code/switch.bin");

/// One complete native function's structural evidence.
#[derive(Clone, Debug)]
pub struct Function {
    /// Component CPU base (Normal, Kernel or expanded stream five).
    pub base: u32,
    /// Exact CPU range including any unchanged unreachable bytes.
    pub span: Range<u32>,
    /// Decoded instruction CPU ranges; only these establish code boundaries.
    pub instructions: Vec<Range<u32>>,
    /// Direct native calls and tail transfers, for separate client linkage.
    pub calls: Vec<(u32, u32)>,
    /// Indirect calls retained as conditional normal-return edges.
    pub indirect_calls: Vec<u32>,
}
/// A whole set of native grammars, before caller/table/client linkage.
#[derive(Clone, Debug)]
pub struct Authority {
    /// Complete function bodies and decoded boundaries.
    pub functions: Vec<Function>,
}
impl Authority {
    /// Entries not yet linked to another complete native function by an actual
    /// decoded call/tail transfer. The two block primitive functions require
    /// their independent typed-state numerical contract instead.
    pub fn unlinked(&self) -> Vec<u32> {
        let mut linked = alloc::collections::BTreeSet::new();
        for f in &self.functions {
            for &(_, target) in &f.calls {
                if self
                    .functions
                    .iter()
                    .any(|callee| callee.span.start == target)
                {
                    linked.insert(f.span.start);
                    linked.insert(target);
                }
            }
        }
        self.functions
            .iter()
            .map(|f| f.span.start)
            .filter(|entry| !linked.contains(entry))
            .collect()
    }
    /// CPU byte window entirely covered by decoded instructions.
    pub fn instruction_bytes(&self, address: u32, length: usize) -> bool {
        (0..length).all(|i| {
            self.functions.iter().any(|f| {
                f.instructions
                    .iter()
                    .any(|r| r.contains(&(address + i as u32)))
            })
        })
    }
    /// A CPU location strictly inside a decoded instruction operand/encoding.
    pub fn instruction_interior(&self, address: u32) -> bool {
        self.functions.iter().any(|f| {
            f.instructions
                .iter()
                .any(|r| r.start < address && address < r.end)
        })
    }
}
fn branch(op: &str) -> bool {
    matches!(
        op,
        "BRA"
            | "BRN"
            | "BEQ"
            | "BNE"
            | "BHI"
            | "BLS"
            | "BCC"
            | "BCS"
            | "BGE"
            | "BLT"
            | "BGT"
            | "BLE"
            | "BPL"
            | "BMI"
            | "BVC"
            | "BVS"
    )
}
fn target(operand: O, next: u32) -> Option<u32> {
    match operand {
        O::Address(Ea::Absolute { value, .. }) => Some(value),
        O::Address(Ea::PcRelative { value, .. }) => next.checked_add_signed(value),
        _ => None,
    }
}
fn graph(bytes: &[u8], spec: &Spec) -> Option<Function> {
    let mut todo = vec![(spec.entry, 0i32)];
    let mut nodes = BTreeMap::new();
    let mut calls = Vec::new();
    let mut indirect_calls = Vec::new();
    let mut returned = false;
    while let Some((pc, depth)) = todo.pop() {
        if let Some((old, _)) = nodes.get(&pc) {
            if *old != depth {
                return None;
            }
            continue;
        }
        if pc < spec.entry || pc >= spec.end || nodes.len() > 8192 {
            return None;
        }
        let d = decode_insn(
            bytes.get((pc - spec.entry) as usize..)?,
            Target::H8S2000,
            Mode::Advanced,
        )
        .ok()?;
        let next = pc.checked_add(d.len as u32)?;
        if next > spec.end {
            return None;
        }
        let ins = d.insn;
        let op = ins.mnemonic;
        let mut changed = depth;
        let width = match ins.size {
            Some(Size::Long) => 4,
            Some(Size::Word) => 2,
            _ => 1,
        };
        for operand in ins.operands {
            let amount = ins
                .operands
                .iter()
                .find_map(|x| {
                    if let O::Registers { first, last } = x {
                        Some(i32::from(last - first + 1) * 4)
                    } else {
                        None
                    }
                })
                .unwrap_or(width);
            match operand {
                O::Address(Ea::PreDecrement(Reg::Long(7))) => changed -= amount,
                O::Address(Ea::PostIncrement(Reg::Long(7))) => changed += amount,
                O::Address(Ea::PreIncrement(Reg::Long(7)) | Ea::PostDecrement(Reg::Long(7))) => {
                    return None
                }
                O::Registers { last: 7, .. } => return None,
                _ => {}
            }
        }
        if matches!(
            ins.operands[1],
            O::Register(Reg::Long(7) | Reg::Word(7) | Reg::Word(15) | Reg::Byte(7) | Reg::Byte(15))
        ) {
            match (op, ins.operands[0]) {
                ("ADD" | "ADDS" | "INC", O::Immediate { value, .. }) => {
                    changed = changed.checked_add(i32::try_from(value).ok()?)?
                }
                ("SUB" | "SUBS" | "DEC", O::Immediate { value, .. }) => {
                    changed = changed.checked_sub(i32::try_from(value).ok()?)?
                }
                ("CMP", _) => {}
                _ => return None,
            }
        }
        if !(-65535..=0).contains(&changed) {
            return None;
        }
        nodes.insert(pc, (depth, d.len));
        if op == "RTS" {
            if changed != 0 {
                return None;
            }
            returned = true;
            continue;
        }
        if matches!(op, "RTE" | "SLEEP" | "TRAPA") {
            return None;
        }
        if op == "JMP" {
            if pc == 0x517f90 && spec.entry == 0x517f4a {
                for word in SWITCH.chunks_exact(2) {
                    todo.push((
                        0x517f92 + u32::from(u16::from_be_bytes([word[0], word[1]])),
                        changed,
                    ));
                }
            } else {
                let to = target(ins.operands[0], next)?;
                if to < spec.entry || to >= spec.end {
                    if changed != 0 {
                        return None;
                    }
                    returned = true;
                    calls.push((pc, to));
                } else {
                    todo.push((to, changed));
                }
            }
            continue;
        }
        if matches!(op, "JSR" | "BSR") {
            if let Some(to) = target(ins.operands[0], next) {
                calls.push((pc, to));
            } else {
                indirect_calls.push(pc);
            }
        }
        if branch(op) {
            if op != "BRN" {
                todo.push((target(ins.operands[0], next)?, changed));
            }
            if op == "BRA" {
                continue;
            }
        }
        todo.push((next, changed));
    }
    if !returned {
        return None;
    }
    let mut end = spec.entry;
    let mut instructions = Vec::new();
    for (at, (_, length)) in nodes {
        if at < end {
            return None;
        }
        end = at + length as u32;
        instructions.push(at..end);
    }
    Some(Function {
        base: spec.base,
        span: spec.entry..spec.end,
        instructions,
        calls,
        indirect_calls,
    })
}

/// Match complete native bodies and verify every branch/normal-return frame.
/// The expanded input must be stream five mapped by the bound native loader;
/// callers must additionally establish all graph entry/client relationships.
pub fn bind(normal: &[u8], kernel: &[u8], expanded: &[u8]) -> Option<Authority> {
    if kernel.len() != crate::image::KERNEL_LEN
        || normal.get(0x594c68 - 0x410000..0x594c7e - 0x410000)? != SWITCH
    {
        return None;
    }
    let regions = crate::image::regions(normal)?;
    let mut functions = Vec::new();
    for spec in SPECS {
        let component = match spec.base {
            0x410000 => normal,
            0x400000 => kernel,
            0xdac000 => expanded,
            _ => return None,
        };
        let range = (spec.entry - spec.base) as usize..(spec.end - spec.base) as usize;
        if spec.base == 0x410000
            && !regions.stored.iter().any(|b| {
                let at = b.as_ptr() as usize - normal.as_ptr() as usize;
                at <= range.start && range.end <= at + b.len()
            })
        {
            return None;
        }
        let bytes = component.get(range)?;
        let expected = BYTES.get(spec.offset..spec.offset + bytes.len())?;
        if bytes != expected {
            return None;
        }
        functions.push(graph(bytes, spec)?);
    }
    Some(Authority { functions })
}

/// Complete instruction authority: every routine is linked through decoded
/// native calls to another complete routine, except the initializer/compression
/// pair with its independent five-word-state/64-byte-block numerical contract.
/// The latter is executed from these exact same bytes by transform_tests:
/// 80 rounds, arbitrary context/block vectors, bounded reads/writes and preserved
/// ER3..ER6/SP. This is a primitive ABI proof, not a guessed incoming entry.
pub fn observe(normal: &[u8], kernel: &[u8], expanded: &[u8]) -> Option<Authority> {
    let authority = bind(normal, kernel, expanded)?;
    if authority.unlinked() != [0x56b4de, 0x56bb86] {
        return None;
    }
    Some(authority)
}

/// Exact primitive grammars shared with independent numerical tests.
#[cfg(test)]
pub(crate) fn primitive_bodies() -> [(u32, &'static [u8]); 2] {
    [0x56b4de, 0x56bb86].map(|entry| {
        let spec = SPECS.iter().find(|s| s.entry == entry).unwrap();
        (
            entry,
            &BYTES[spec.offset..spec.offset + (spec.end - spec.entry) as usize],
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_function_cfg_and_frame_grammars() {
        for spec in SPECS {
            let bytes = &BYTES[spec.offset..spec.offset + (spec.end - spec.entry) as usize];
            assert!(graph(bytes, spec).is_some(), "{:x}", spec.entry);
        }
    }
    #[test]
    fn complete_native_clients_link_to_bound_callees() {
        let functions = SPECS
            .iter()
            .map(|spec| {
                graph(
                    &BYTES[spec.offset..spec.offset + (spec.end - spec.entry) as usize],
                    spec,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(Authority { functions }.unlinked(), [0x56b4de, 0x56bb86]);
        assert_eq!(primitive_bodies().len(), 2);
    }
    #[test]
    fn changed_frame_and_branch_edges_refuse() {
        let spec = &SPECS[0];
        let bytes = &BYTES[spec.offset..spec.offset + (spec.end - spec.entry) as usize];
        let mut bad = bytes.to_vec();
        // Returning before the captured prologue has been unwound must refuse.
        let first = decode_insn(bytes, Target::H8S2000, Mode::Advanced).unwrap();
        bad[first.len..first.len + 2].copy_from_slice(&[0x54, 0x70]);
        assert!(graph(&bad, spec).is_none());
    }
}

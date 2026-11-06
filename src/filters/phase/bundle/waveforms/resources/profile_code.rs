//! Complete unchanged native instruction authority for retired profile data.
//!
//! Seven exact native function grammars establish full bounded CFGs and balanced
//! local stack frames on conditional normal-return edges. The first two clients
//! call the complete word getter 5257aa; the third tail-calls complete indexed
//! record getter 4da392. The fourth client calls the complete byte-to-length
//! helper 46ba52 (unsigned byte times two plus 30, returned as a signed long).
//! This establishes client/callee instruction linkage,
//! not callee effects, termination, or boot reachability.
//! Dispatcher 4d37f4 guards ER6 <= 96, doubles that index, reads a zero-extended
//! word from 59e498, adds 4d3c08, then jumps. All 97 switch edges are bound below.
//! Only decoded instruction bytes gain authority; data and unvisited bytes do not.
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
const BASE: u32 = 0x410000;
const SPECS: &[Spec] = &[
    Spec {
        base: BASE,
        entry: 0x46b4c8,
        end: 0x46ba52,
        offset: 2696,
    },
    Spec {
        base: BASE,
        entry: 0x46ba52,
        end: 0x46ba5e,
        offset: 4114,
    },
    Spec {
        base: BASE,
        entry: 0x4d37f4,
        end: 0x4d3f44,
        offset: 0,
    },
    Spec {
        base: BASE,
        entry: 0x4d7280,
        end: 0x4d7566,
        offset: 1872,
    },
    Spec {
        base: BASE,
        entry: 0x4dacea,
        end: 0x4dacfe,
        offset: 2614,
    },
    Spec {
        base: BASE,
        entry: 0x5257aa,
        end: 0x5257b2,
        offset: 2634,
    },
    Spec {
        base: BASE,
        entry: 0x4da392,
        end: 0x4da3c8,
        offset: 2642,
    },
];
const BYTES: &[u8] = include_bytes!("profile_code/functions.bin");
const SWITCH: &[u8] = include_bytes!("profile_code/switch.bin");

/// One complete native function's structural evidence.
#[derive(Clone, Debug)]
pub struct Function {
    /// Normal component CPU base.
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
    /// Entries without a complete native client/callee link.
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
            if pc == 0x4d3c06 && spec.entry == 0x4d37f4 {
                for word in SWITCH.chunks_exact(2) {
                    todo.push((
                        0x4d3c08 + u32::from(u16::from_be_bytes([word[0], word[1]])),
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

/// Bind exact unchanged bodies and switch data, with full local CFG/stack and
/// client/callee linkage. The caller must preserve all returned witnesses.
pub fn observe(normal: &[u8]) -> Option<Authority> {
    if normal.get(0x59e498 - BASE as usize..0x59e55a - BASE as usize)? != SWITCH {
        return None;
    }
    let regions = crate::image::regions(normal)?;
    let mut functions = Vec::new();
    for spec in SPECS {
        let range = (spec.entry - BASE) as usize..(spec.end - BASE) as usize;
        if !regions.stored.iter().any(|b| {
            let at = b.as_ptr() as usize - normal.as_ptr() as usize;
            at <= range.start && range.end <= at + b.len()
        }) {
            return None;
        }
        let bytes = normal.get(range)?;
        if bytes != BYTES.get(spec.offset..spec.offset + bytes.len())? {
            return None;
        }
        functions.push(graph(bytes, spec)?);
    }
    let authority = Authority { functions };
    authority.unlinked().is_empty().then_some(authority)
}
impl Authority {
    /// File spans of all unchanged classification witnesses, including switch.
    pub fn protected_normal(&self) -> Vec<Range<usize>> {
        let mut ranges: Vec<_> = self
            .functions
            .iter()
            .map(|f| (f.span.start - BASE) as usize..(f.span.end - BASE) as usize)
            .collect();
        ranges.push(0x59e498 - BASE as usize..0x59e55a - BASE as usize);
        ranges
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut n = vec![255; 0x200000];
        for s in SPECS {
            let len = (s.end - s.entry) as usize;
            n[(s.entry - BASE) as usize..(s.end - BASE) as usize]
                .copy_from_slice(&BYTES[s.offset..s.offset + len]);
        }
        n[0x59e498 - BASE as usize..0x59e55a - BASE as usize].copy_from_slice(SWITCH);
        n
    }
    #[test]
    fn complete_clients_bound_cross_instruction_windows() {
        let n = fixture();
        let a = observe(&n).unwrap();
        assert!(a.unlinked().is_empty());
        for at in [0x4d394f, 0x4d7445, 0x4dacf9, 0x46b532] {
            assert!(a.instruction_bytes(at, 4));
            assert!(!a.instruction_bytes(at, 4000));
        }
        for at in [
            0x4d37f4, 0x4d7288, 0x4dacfa, 0x5257aa, 0x4da392, 0x59e498, 0x46b4cc, 0x46ba52,
            0x4d3be2,
        ] {
            let mut bad = n.clone();
            bad[(at - BASE) as usize] ^= 1;
            assert!(observe(&bad).is_none());
        }
    }
    #[test]
    fn profile_storage_closure_keeps_real_typed_and_resident_references() {
        let n = fixture();
        let kernel = vec![255; crate::image::KERNEL_LEN];
        let retired = [
            0x5a4d0c - BASE as usize..0x5a4edc - BASE as usize,
            0x5b5704 - BASE as usize..0x5b5c04 - BASE as usize,
        ];
        let clear = |normal: &[u8], resident: &[u8]| {
            super::super::profile_ownership::prove(normal, resident, &retired, &retired, &[])
                .is_some()
        };
        assert!(clear(&n, &kernel));
        for bytes in [
            vec![0x5e, 0x5a, 0x4d, 0x40],
            vec![0x7a, 0x00, 0x00, 0x5a, 0x4d, 0x40],
            vec![0, 0x5a, 0x4d, 0x40],
        ] {
            let mut changed = n.clone();
            changed[0x400..0x400 + bytes.len()].copy_from_slice(&bytes);
            assert!(!clear(&changed, &kernel));
            let mut resident = kernel.clone();
            resident[0x400..0x400 + bytes.len()].copy_from_slice(&bytes);
            assert!(!clear(&n, &resident));
        }
        let mut invalid = n.clone();
        invalid[0x4d37f4 - BASE as usize] ^= 1;
        assert!(!clear(&invalid, &kernel));
    }
}

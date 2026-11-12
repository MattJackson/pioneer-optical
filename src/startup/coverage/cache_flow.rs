//! Bounded control-flow analysis of cache accessor consumers. Every branch is
//! explored without assuming condition flags. Function interiors reached from
//! elsewhere and computed aliases remain outside this observation's scope.
use crate::image::layout::Observation;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use h8_asm::{
    isa::{decode_insn, Ea, Operand as O, Reg as R},
    Mode, Target,
};
const CONVERTER: &[u8] = &[
    0x01, 0x10, 0x6d, 0xf4, 0x1b, 0x97, 0x0f, 0x94, 0x0c, 0x0d, 0x0f, 0xf1, 0x55, 0x2c, 0x0c, 0x88,
    0x47, 0x1e, 0x0f, 0xf1, 0x0b, 0xf1, 0x0c, 0xd8, 0x55, 0x20, 0x0c, 0x88, 0x47, 0x12, 0x68, 0x78,
    0x10, 0x48, 0x10, 0x48, 0x6e, 0x79, 0x00, 0x02, 0x14, 0x98, 0x68, 0xc8, 0xf8, 0x01, 0x40, 0x02,
    0x18, 0x88, 0x0b, 0x97, 0x01, 0x10, 0x6d, 0x75, 0x54, 0x70, 0x0c, 0x80, 0xa8, 0x30, 0x45, 0x08,
    0xa0, 0x39, 0x42, 0x04, 0x80, 0xd0, 0x40, 0x16, 0xa0, 0x41, 0x45, 0x08, 0xa0, 0x46, 0x42, 0x04,
    0x80, 0xc9, 0x40, 0x0a, 0xa0, 0x61, 0x45, 0x0c, 0xa0, 0x66, 0x42, 0x08, 0x80, 0xa9, 0x68, 0x90,
    0xf8, 0x01, 0x40, 0x02, 0x18, 0x88, 0x54, 0x70,
];
/// Reason a bounded function cannot establish complete local cache-call domains.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Issue {
    /// Instruction decoding failed or left the supplied function.
    Boundary(usize),
    /// Unsupported instruction semantics.
    Instruction(usize),
    /// Indirect call target could not be established.
    IndirectTarget(usize),
    /// Exploration reached its finite state limit.
    StateLimit,
}
/// Cache-byte indices reaching an accessor call across all explored branches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// Decoded Normal call offset.
    pub offset: usize,
    /// Possible byte indices; None explicitly retains an unknown value.
    pub indices: Vec<Option<u8>>,
}
/// Evidence for one bounded function; issues prevent treating it as complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    /// Decoded Normal entry offset.
    pub start: usize,
    /// Exclusive end offset.
    pub end: usize,
    /// Accessor call domains observed in reachable states.
    pub calls: Vec<Call>,
    /// Unresolved instructions, paths or targets.
    pub issues: Vec<Issue>,
    /// Instruction offsets visited from this entry.
    pub visited: Vec<usize>,
}
/// Address occurrence that still needs native interpretation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reference {
    /// Decoded Normal byte offset of a 24-bit address occurrence.
    Stored(usize),
    /// Byte offset in an expanded COMP stream, indexed in physical stream order.
    Expanded {
        /// Zero-based stream index in physical order.
        stream: usize,
        /// Byte offset within the expanded stream.
        offset: usize,
    },
}
/// Bounded consumer functions and address references without a proven boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// Accessor entry offset, bound through the complete bulk-cache graph.
    pub accessor: usize,
    /// Functions containing the selected native accessor references.
    pub functions: Vec<Function>,
    /// Literal references not covered by a recognized load and function.
    pub uncovered: Vec<Reference>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct State([Option<u8>; 32]);
impl State {
    fn span(reg: R) -> Option<(usize, usize)> {
        match reg {
            R::Byte(n) if n < 16 => Some(((n as usize & 7) * 4 + usize::from(n < 8), 1)),
            R::Word(n) if n < 16 => Some(((n as usize & 7) * 4 + if n < 8 { 0 } else { 2 }, 2)),
            R::Long(n) if n < 8 => Some((n as usize * 4, 4)),
            _ => None,
        }
    }
    fn get(&self, reg: R) -> Option<u32> {
        let (start, len) = Self::span(reg)?;
        let mut value = 0;
        for i in 0..len {
            value |= u32::from(self.0[start + i]?) << (i * 8);
        }
        Some(value)
    }
    fn set(&mut self, reg: R, value: Option<u32>) {
        if let Some((start, len)) = Self::span(reg) {
            for i in 0..len {
                self.0[start + i] = value.map(|v| (v >> (i * 8)) as u8);
            }
        }
    }
    fn operand(&self, op: O) -> Option<u32> {
        match op {
            O::Immediate { value, .. } => Some(value),
            O::Register(r) => self.get(r),
            _ => None,
        }
    }
}
fn stored(normal: &[u8], regions: &[&[u8]], start: usize, end: usize) -> bool {
    regions.iter().any(|b| {
        let at = b.as_ptr() as usize - normal.as_ptr() as usize;
        start >= at && end <= at + b.len()
    })
}
/// `regions` are the stored slices of `normal` from one `image::regions` decode.
fn analyse(
    normal: &[u8],
    regions: &[&[u8]],
    start: usize,
    end: usize,
    accessor: usize,
    register: u8,
) -> Function {
    let mut result = Function {
        start,
        end,
        calls: Vec::new(),
        issues: Vec::new(),
        visited: Vec::new(),
    };
    let mut instructions = BTreeMap::new();
    let mut at = start;
    while at < end {
        let Ok(decoded) = decode_insn(&normal[at..end], Target::H8S2000, Mode::Advanced) else {
            result.issues.push(Issue::Boundary(at));
            return result;
        };
        instructions.insert(at, decoded);
        at += decoded.len;
    }
    if at != end {
        result.issues.push(Issue::Boundary(at));
        return result;
    }
    let mut todo = alloc::vec![(start, State([None; 32]))];
    let mut seen = BTreeSet::new();
    let mut calls: BTreeMap<usize, BTreeSet<Option<u8>>> = BTreeMap::new();
    let mut issues = BTreeSet::new();
    while let Some((pc, mut state)) = todo.pop() {
        if !seen.insert((pc, state)) {
            continue;
        }
        if seen.len() > 10000 {
            issues.insert(Issue::StateLimit);
            break;
        }
        let Some(decoded) = instructions.get(&pc) else {
            issues.insert(Issue::Boundary(pc));
            continue;
        };
        let next = pc + decoded.len;
        let op = decoded.insn.mnemonic;
        let [a, b, c] = decoded.insn.operands;
        if c != O::None {
            issues.insert(Issue::Instruction(pc));
            continue;
        }
        if op == "RTS" {
            continue;
        }
        if matches!(
            op,
            "BRA"
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
        ) {
            let O::Address(Ea::PcRelative { value, .. }) = a else {
                issues.insert(Issue::Instruction(pc));
                continue;
            };
            if let Some(target) = next.checked_add_signed(value as isize) {
                todo.push((target, state));
            } else {
                issues.insert(Issue::Boundary(pc));
            }
            if op == "BRA" {
                continue;
            }
        } else if op == "JSR" {
            let target = match a {
                O::Address(Ea::Absolute { value, .. }) => Some(value),
                O::Address(Ea::Indirect(r)) => state.get(r),
                _ => None,
            };
            if target == Some(0x410000 + accessor as u32) {
                calls
                    .entry(pc)
                    .or_default()
                    .insert(state.get(R::Byte(register + 8)).map(|v| v as u8));
                state.set(R::Long(0), None);
                state.set(R::Long(1), None);
            } else if target
                .and_then(|v| v.checked_sub(0x410000))
                .is_some_and(|offset| {
                    let at = offset as usize;
                    normal.get(at..at.saturating_add(CONVERTER.len())) == Some(CONVERTER)
                        && stored(normal, regions, at, at + CONVERTER.len())
                })
            {
                for r in 0..3 {
                    state.set(R::Long(r), None);
                }
            } else {
                if target.is_none() {
                    issues.insert(Issue::IndirectTarget(pc));
                }
                state = State([None; 32]);
            }
        } else if op == "BSR" {
            let O::Address(Ea::PcRelative { value, .. }) = a else {
                issues.insert(Issue::Instruction(pc));
                continue;
            };
            if next.checked_add_signed(value as isize) == Some(accessor) {
                calls
                    .entry(pc)
                    .or_default()
                    .insert(state.get(R::Byte(register + 8)).map(|v| v as u8));
                state.set(R::Long(0), None);
                state.set(R::Long(1), None);
            } else {
                state = State([None; 32]);
            }
        } else if matches!(op, "CMP" | "BTST" | "NOP") {
        } else if op == "STM" {
            state.set(R::Long(7), None);
        } else if op == "LDM" {
            if let O::Registers { first, last } = b {
                for r in first..=last {
                    state.set(R::Long(r), None);
                }
            } else {
                issues.insert(Issue::Instruction(pc));
                continue;
            }
            state.set(R::Long(7), None);
        } else if let O::Register(R::Ccr | R::Exr) = b {
            // ORC/XORC/ANDC/LDC write only a control register; flags are not
            // modelled because both branch successors are always explored.
            if !matches!(op, "ORC" | "XORC" | "ANDC" | "LDC") {
                issues.insert(Issue::Instruction(pc));
                continue;
            }
        } else if let O::Register(dest) = if b == O::None { a } else { b } {
            if State::span(dest).is_none() {
                issues.insert(Issue::Instruction(pc));
                continue;
            }
            let value = match op {
                "MOV" => state.operand(a),
                "INC" | "ADD" | "ADDS" => state
                    .get(dest)
                    .zip(if b == O::None {
                        Some(1)
                    } else {
                        state.operand(a)
                    })
                    .map(|(v, n)| v.wrapping_add(n)),
                "SUB" | "XOR" if a == b => Some(0),
                "SUB" | "SUBS" => state
                    .get(dest)
                    .zip(state.operand(a))
                    .map(|(v, n)| v.wrapping_sub(n)),
                "AND" => state.get(dest).zip(state.operand(a)).map(|(v, n)| v & n),
                "OR" => state.get(dest).zip(state.operand(a)).map(|(v, n)| v | n),
                "DEC" | "EXTU" | "EXTS" | "NEG" | "NOT" | "SHAL" | "SHAR" | "SHLL" | "SHLR"
                | "ROTL" | "ROTR" | "ROTXL" | "ROTXR" | "MULXU" | "MULXS" | "DIVXU" | "DIVXS"
                | "STC" => None,
                _ => {
                    issues.insert(Issue::Instruction(pc));
                    continue;
                }
            };
            state.set(dest, value);
        } else if !matches!(op, "MOV" | "BSET" | "BCLR" | "STC") {
            issues.insert(Issue::Instruction(pc));
            continue;
        }
        // Address side effects also invalidate register knowledge.
        for operand in [a, b] {
            if let O::Address(
                Ea::PostIncrement(r)
                | Ea::PreDecrement(r)
                | Ea::PostDecrement(r)
                | Ea::PreIncrement(r),
            ) = operand
            {
                state.set(r, None);
            }
        }
        todo.push((next, state));
    }
    result.calls = calls
        .into_iter()
        .map(|(offset, indices)| Call {
            offset,
            indices: indices.into_iter().collect(),
        })
        .collect();
    result.issues = issues.into_iter().collect();
    result.visited = seen
        .into_iter()
        .map(|(pc, _)| pc)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    result
}
/// Find bounded consumer functions around literal loads of proven cache
/// accessors. Complete instruction decoding and branch containment are required;
/// unsupported dataflow and unmatched references stay explicit in the result.
/// This does not establish startup reachability or exclude interior entry points.
pub fn discover(normal: &[u8]) -> Observation<Vec<Evidence>> {
    discover_kind(normal, false)
}
/// Trace bounded functions containing direct absolute cache-accessor calls.
/// Unknown input arguments and missing function boundaries remain explicit.
/// Relative calls and computed aliases require separate inventories.
pub fn discover_direct(normal: &[u8]) -> Observation<Vec<Evidence>> {
    discover_kind(normal, true)
}
/// Function start and exclusive end in decoded Normal offsets.
type Span = (usize, usize);
fn discover_kind(normal: &[u8], direct: bool) -> Observation<Vec<Evidence>> {
    let (caches, regions) = match super::cache::discover_in(normal) {
        Observation::Known(v) => v,
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    let mut results = Vec::new();
    for cache in caches {
        // One pass over the image serves every accessor: each 24-bit address
        // occurrence is looked up, preserving each accessor's reference order.
        let mut by_address: BTreeMap<[u8; 3], Vec<usize>> = BTreeMap::new();
        for (k, accessor) in cache.accessors.iter().enumerate() {
            let address = (0x410000 + accessor.offset as u32).to_be_bytes();
            by_address
                .entry([address[1], address[2], address[3]])
                .or_default()
                .push(k);
        }
        // Per accessor: function boundaries with the (reference, call) offsets
        // they contain, and references without a function boundary.
        let mut boundaries: Vec<BTreeMap<Span, Vec<(usize, usize)>>> =
            alloc::vec![BTreeMap::new(); cache.accessors.len()];
        let mut uncovered: Vec<Vec<Reference>> = alloc::vec![Vec::new(); cache.accessors.len()];
        for region in &regions.stored {
            #[cfg(test)]
            tests::WINDOW_SCANS.with(|c| c.set(c.get() + 1));
            let base = region.as_ptr() as usize - normal.as_ptr() as usize;
            for (i, bytes) in region.windows(3).enumerate() {
                let Some(found) = by_address.get(bytes) else {
                    continue;
                };
                let direct_call = i > 0 && (base + i - 1) & 1 == 0 && region[i - 1] == 0x5e;
                if direct != direct_call {
                    continue;
                }
                if !direct
                    && (i < 3
                        || (base + i - 3) & 1 != 0
                        || region[i - 3] != 0x7a
                        || region[i - 2] > 7
                        || region[i - 1] != 0)
                {
                    for &k in found {
                        uncovered[k].push(Reference::Stored(base + i));
                    }
                    continue;
                }
                let load = i - if direct { 1 } else { 3 };
                let lo = load.saturating_sub(2048);
                let hi = region.len().min(load + 2048);
                let start = (lo..load.saturating_sub(1))
                    .rev()
                    .find(|&j| region[j..j + 2] == [0x54, 0x70])
                    .map(|j| j + 2);
                let end = start.and_then(|start| decoded_return(region, start, hi));
                let Some((start, end)) = start.zip(end) else {
                    for &k in found {
                        uncovered[k].push(Reference::Stored(base + i));
                    }
                    continue;
                };
                let saved_entry = matches!(
                    region.get(start..start + 4),
                    Some(
                        [0x01, 0x20, 0x6d, 0xf4] | [0x01, 0, 0x6d, 0xf3] | [0x01, 0x10, 0x6d, 0xf4]
                    )
                );
                // Direct readers also use a word-save prologue, or a leaf
                // beginning with a byte index followed by the accessor call.
                let direct_entry = direct
                    && (region.get(start..start + 2) == Some(&[0x6d, 0xf3])
                        || matches!(region.get(start..start + 3), Some([0xf8, _, 0x5e])));
                if (base + start) & 1 != 0 || !(saved_entry || direct_entry) {
                    for &k in found {
                        uncovered[k].push(Reference::Stored(base + i));
                    }
                    continue;
                }
                for &k in found {
                    boundaries[k]
                        .entry((base + start, base + end))
                        .or_default()
                        .push((base + i, base + load));
                }
            }
        }
        for (stream, bytes) in regions.expanded.iter().enumerate() {
            for (offset, value) in bytes.windows(3).enumerate() {
                for &k in by_address.get(value).map_or(&[][..], Vec::as_slice) {
                    uncovered[k].push(Reference::Expanded { stream, offset });
                }
            }
        }
        for ((accessor, boundaries), mut uncovered) in
            cache.accessors.iter().zip(boundaries).zip(uncovered)
        {
            let mut unreached = Vec::new();
            let functions = boundaries
                .into_iter()
                .map(|((start, end), references)| {
                    let function = analyse(
                        normal,
                        &regions.stored,
                        start,
                        end,
                        accessor.offset,
                        accessor.argument_register,
                    );
                    // A direct call the bounded walk never reached has no
                    // domain; it must not vanish from the evidence.
                    if direct {
                        unreached.extend(
                            references
                                .into_iter()
                                .filter(|&(_, call)| {
                                    !function.calls.iter().any(|c| c.offset == call)
                                })
                                .map(|(reference, _)| Reference::Stored(reference)),
                        );
                    }
                    function
                })
                .collect();
            uncovered.extend(unreached);
            results.push(Evidence {
                accessor: accessor.offset,
                functions,
                uncovered,
            });
        }
    }
    Observation::Known(results)
}
fn decoded_return(bytes: &[u8], start: usize, limit: usize) -> Option<usize> {
    let mut at = start;
    while at < limit {
        let decoded = decode_insn(bytes.get(at..limit)?, Target::H8S2000, Mode::Advanced).ok()?;
        at += decoded.len;
        if decoded.insn.mnemonic == "RTS" {
            return Some(at);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    std::thread_local! {
        pub(super) static WINDOW_SCANS: Cell<usize> = const { Cell::new(0) };
    }
    #[test]
    fn control_register_operations_leave_general_registers_traced() {
        let mut raw = alloc::vec![0xff;0x1000];
        // MOV.B #0x7E,R0L; ORC/XORC/ANDC/LDC #imm,CCR; LDC R1L,CCR; BSR accessor; RTS
        raw[0x100..0x10e].copy_from_slice(&[
            0xf8, 0x7e, 0x04, 0x80, 0x05, 0x01, 0x06, 0x7f, 0x07, 0x00, 0x03, 0x09, 0x55, 0x12,
        ]);
        raw[0x10e..0x110].copy_from_slice(&[0x54, 0x70]);
        let f = analyse(&raw, &[&raw[..]], 0x100, 0x110, 0x120, 0);
        assert!(f.issues.is_empty(), "{:?}", f.issues);
        assert_eq!(
            f.calls,
            alloc::vec![Call {
                offset: 0x10c,
                indices: alloc::vec![Some(0x7e)]
            }]
        );
        // STC CCR,R0L replaces the traced index with an unknown value.
        raw[0x10a..0x10c].copy_from_slice(&[0x02, 0x08]);
        let f = analyse(&raw, &[&raw[..]], 0x100, 0x110, 0x120, 0);
        assert!(f.issues.is_empty(), "{:?}", f.issues);
        assert_eq!(f.calls[0].indices, alloc::vec![None]);
    }
    /// Bulk loop at 0x2000 and R0 accessor leaves at each of `leaves`.
    fn bulk_fixture(leaves: &[usize]) -> Vec<u8> {
        let mut raw = alloc::vec![0xff; 0x5000];
        crate::image::layout::install_test_layout(&mut raw, 0x1000);
        let bulk = &super::super::cache_shapes::SHAPES[0];
        raw[0x2000..0x2000 + bulk.bytes.len()].copy_from_slice(bulk.bytes);
        raw[0x2000 + bulk.call + 1..0x2000 + bulk.call + 4].copy_from_slice(&[0x41, 0x10, 0]);
        for p in bulk.ram {
            raw[0x2000 + p..0x2000 + p + 4].copy_from_slice(&0xa01000u32.to_be_bytes());
        }
        let leaf = [
            0x0c, 0x89, 0x1a, 0x80, 0x0c, 0x98, 0x78, 0, 0x6a, 0x28, 0, 0xa0, 0x10, 0, 0x54, 0x70,
        ];
        for &at in leaves {
            raw[at..at + leaf.len()].copy_from_slice(&leaf);
        }
        raw
    }
    #[test]
    fn direct_calls_the_bounded_walk_never_reaches_stay_uncovered() {
        let mut raw = bulk_fixture(&[0x3000]);
        // RTS; MOV.L ER3,@-SP; SLEEP; MOV.B #0x7E,R0L; JSR @accessor; MOV.L @SP+,ER3; RTS
        raw[0x4000..0x4012].copy_from_slice(&[
            0x54, 0x70, 0x01, 0x00, 0x6d, 0xf3, 0x01, 0x80, 0xf8, 0x7e, 0x5e, 0x41, 0x30, 0, 0x01,
            0x00, 0x6d, 0x73,
        ]);
        raw[0x4012..0x4014].copy_from_slice(&[0x54, 0x70]);
        let Observation::Known(found) = discover_direct(&raw) else {
            panic!("fixture")
        };
        assert_eq!(found[0].functions.len(), 1);
        assert!(!found[0].functions[0].issues.is_empty());
        assert!(found[0].functions[0].calls.is_empty());
        assert_eq!(found[0].uncovered, alloc::vec![Reference::Stored(0x400b)]);
        // A reached call is recorded once and not also retained as uncovered.
        raw[0x4006..0x4008].copy_from_slice(&[0, 0]);
        let Observation::Known(found) = discover_direct(&raw) else {
            panic!("fixture")
        };
        assert_eq!(found[0].functions[0].calls.len(), 1);
        assert!(found[0].uncovered.is_empty());
    }
    #[test]
    fn accessor_references_are_collected_in_one_image_pass() {
        let mut raw = bulk_fixture(&[0x3000, 0x3100, 0x3200]);
        // RTS; MOV.B #5,R0L; JSR @accessor(0x3200); RTS. A JSR to the first
        // accessor without a function boundary stays uncovered.
        raw[0x4000..0x400a]
            .copy_from_slice(&[0x54, 0x70, 0xf8, 0x05, 0x5e, 0x41, 0x32, 0, 0x54, 0x70]);
        raw[0x4800..0x4804].copy_from_slice(&[0x5e, 0x41, 0x30, 0]);
        WINDOW_SCANS.with(|c| c.set(0));
        let Observation::Known(found) = discover_direct(&raw) else {
            panic!("fixture")
        };
        assert_eq!(
            found
                .iter()
                .map(|e| (e.accessor, e.functions.len(), e.uncovered.clone()))
                .collect::<Vec<_>>(),
            alloc::vec![
                (0x3000, 0, alloc::vec![Reference::Stored(0x4801)]),
                (0x3100, 0, Vec::new()),
                (0x3200, 1, Vec::new()),
            ]
        );
        assert_eq!(
            found[2].functions[0].calls,
            alloc::vec![Call {
                offset: 0x4004,
                indices: alloc::vec![Some(5)]
            }]
        );
        assert_eq!(WINDOW_SCANS.with(Cell::get), 1);
    }
    #[test]
    fn return_boundaries_skip_opcode_shaped_address_operands() {
        let bytes = [0x5e, 0x54, 0x70, 0xea, 0x54, 0x70];
        assert_eq!(decoded_return(&bytes, 0, bytes.len()), Some(6));
        assert_eq!(decoded_return(&bytes, 0, 3), None);
    }
    #[test]
    fn branches_preserve_both_domains_including_009f_cache_bytes() {
        let mut raw = alloc::vec![0xff;0x1000];
        raw[0x100..0x112].copy_from_slice(&[
            0x7a, 5, 0, 0x41, 3, 0, 0x47, 4, 0xf8, 0x78, 0x40, 2, 0xf8, 0x7e, 0x5d, 0x50, 0x54,
            0x70,
        ]);
        let f = analyse(&raw, &[&raw[..]], 0x100, 0x112, 0x300, 0);
        assert!(f.issues.is_empty(), "{:?}", f.issues);
        assert_eq!(
            f.calls,
            alloc::vec![Call {
                offset: 0x10e,
                indices: alloc::vec![Some(120), Some(126)]
            }]
        );
        raw[0x10c] = 0;
        raw[0x10d] = 0; // NOP leaves R0L unknown on this path.
        let f = analyse(&raw, &[&raw[..]], 0x100, 0x112, 0x300, 0);
        assert!(f.calls[0].indices.contains(&None));
        raw[0x107] = 1; // Branch into an instruction operand is never decoded as a new path.
        let f = analyse(&raw, &[&raw[..]], 0x100, 0x112, 0x300, 0);
        assert!(f
            .issues
            .iter()
            .any(|issue| matches!(issue, Issue::Boundary(_))));
    }
    #[test]
    fn converter_preservation_requires_its_entire_native_body_and_leaf() {
        let mut raw = alloc::vec![0xff;0x1000];
        raw[0x100..0x10e].copy_from_slice(&[
            0x7a, 5, 0, 0x41, 3, 0, 0x5e, 0x41, 4, 0, 0xf8, 0x78, 0x5d, 0x50,
        ]);
        raw[0x10e..0x110].copy_from_slice(&[0x54, 0x70]);
        raw[0x400..0x400 + CONVERTER.len()].copy_from_slice(CONVERTER);
        let f = analyse(&raw, &[&raw[..]], 0x100, 0x110, 0x300, 0);
        assert!(f.issues.is_empty());
        assert_eq!(f.calls[0].indices, alloc::vec![Some(120)]);
        for i in 0..CONVERTER.len() {
            raw[0x400 + i] ^= 1;
            let f = analyse(&raw, &[&raw[..]], 0x100, 0x110, 0x300, 0);
            assert!(
                f.issues.contains(&Issue::IndirectTarget(0x10c)),
                "converter byte {i}"
            );
            raw[0x400 + i] ^= 1;
        }
    }
    #[test]
    fn converter_checks_reuse_supplied_regions_for_every_state() {
        let mut raw = alloc::vec![0xff;0x1000];
        // MOV.B #0,R3L; loop: INC.B R3L; JSR @converter; BRA loop; RTS
        raw[0x100..0x10c].copy_from_slice(&[
            0xfb, 0, 0x0a, 0x0b, 0x5e, 0x41, 4, 0, 0x40, 0xf8, 0x54, 0x70,
        ]);
        raw[0x400..0x400 + CONVERTER.len()].copy_from_slice(CONVERTER);
        crate::comp_streams::READS.with(|reads| reads.set(0));
        let f = analyse(&raw, &[&raw[..]], 0x100, 0x10c, 0x300, 0);
        assert!(f.issues.is_empty(), "{:?}", f.issues);
        assert_eq!(crate::comp_streams::READS.with(|reads| reads.get()), 0);
    }
    #[test]
    fn relative_accessor_calls_record_their_index_domain() {
        let mut raw = alloc::vec![0xff;0x1000];
        // MOV.B #0x7E,R0L; BSR accessor; RTS
        raw[0x100..0x106].copy_from_slice(&[0xf8, 0x7e, 0x55, 0x1c, 0x54, 0x70]);
        let f = analyse(&raw, &[&raw[..]], 0x100, 0x106, 0x120, 0);
        assert!(f.issues.is_empty(), "{:?}", f.issues);
        assert_eq!(
            f.calls,
            alloc::vec![Call {
                offset: 0x102,
                indices: alloc::vec![Some(0x7e)]
            }]
        );
        // BSR.W reaches the same accessor.
        raw[0x102..0x108].copy_from_slice(&[0x5c, 0, 0, 0x18, 0x54, 0x70]);
        let f = analyse(&raw, &[&raw[..]], 0x100, 0x108, 0x11e, 0);
        assert_eq!(f.calls.len(), 1, "{:?}", f);
        assert_eq!(f.calls[0].offset, 0x102);
    }
    #[test]
    fn register_aliases_track_all_four_bytes_and_unknown_writes() {
        let mut state = State([None; 32]);
        state.set(R::Long(3), Some(0x12345678));
        assert_eq!(state.get(R::Word(3)), Some(0x5678));
        assert_eq!(state.get(R::Word(11)), Some(0x1234));
        assert_eq!(state.get(R::Byte(3)), Some(0x56));
        assert_eq!(state.get(R::Byte(11)), Some(0x78));
        state.set(R::Word(11), Some(0xabcd));
        assert_eq!(state.get(R::Long(3)), Some(0xabcd5678));
        state.set(R::Byte(11), None);
        assert_eq!(state.get(R::Long(3)), None);
        assert_eq!(state.get(R::Word(11)), Some(0xabcd));
    }
}

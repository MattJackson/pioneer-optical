//! Exact native facts retained when no startup comparison is recognized, and
//! the bounded proof that a target has no fixed 0x009F startup gate.
//!
//! `inspect` only explains a miss. `absent` is the single positive proof:
//! it requires the held Kernel and either the audited startup function with an
//! empty or dead-read gate slot, or no Normal loader-flag service and no 0x009F
//! getter read at all. Every Kernel 0x009F load must be the audited byte store.
//!
//! # Stated assumptions and model boundary
//!
//! The Kernel byte-store proof relies on the Renesas H8S C ABI: a called
//! routine preserves ER4-ER6 (callee-saved). Calls between the ER4 load and
//! the `JSR @ER4` site are therefore not decoded for ER4 effects. This
//! differs from `coverage::boot`, which binds an indirect call target only
//! from an immediately preceding load and assumes no callee-saved ABI. That
//! proof follows a call chain through arbitrary, possibly non-compiled stubs
//! whose register contract it must establish itself, whereas this proof
//! matches one compiler-generated routine shape whose callees are ordinary
//! C functions.
//!
//! These compatibility proofs are sound for compiler-generated vendor code
//! shapes and refuse shapes they do not recognise. They are not a defence
//! against deliberately crafted firmware, which can damage a drive directly
//! once flashed whatever any proof says. Outside the model, and not detected:
//! entries into the Kernel routine from computed jumps (`JMP @ERn` or pointers
//! built from 16-bit halves), cross-image transfers (Normal code calling into
//! the Kernel), and references that land in the middle of an instruction of a
//! neighbouring routine whose decode treats those bytes as an operand.
use crate::image::layout::{self, H8ReaderComponent, Observation, Unresolved};
use alloc::{borrow::Cow, vec::Vec};

/// Kernel load base: resident CPU addresses are this plus the byte offset.
const KERNEL_BASE: u32 = 0x400000;

/// Stable `NotApplicable` proof tag for a proven-absent startup word gate.
pub const GATE_ABSENT: u16 = 1;

/// Bound getter owner, entry and index register, or why it is unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Getter {
    /// Complete native reader graph bound in this component.
    Bound(H8ReaderComponent, u32, u8),
    /// No complete reader is bound.
    Unbound(Unresolved),
    /// Native reader candidates conflict.
    Conflicting,
}

/// Native observations behind a stored-code miss of the 0x009F comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Miss {
    /// Getter evidence from the Normal and its supplied Kernel.
    pub getter: Getter,
    /// A recognized loader-flag comparison of a different word, if any.
    pub other_parameter: Option<super::Requirement>,
    /// CPU addresses of stored immediate 0x009F loads bound to an explicit
    /// call of the getter (or of the required resident entry). These are reads
    /// only: no comparison with a loader-flag mismatch arm follows them.
    pub reads: Vec<u32>,
    /// CPU addresses of stored wrappers of Kernel loader-flag service 0x400A1A.
    pub loader_flag_wrappers: Vec<u32>,
}

/// Stored bytes with COMP spans erased to 0xFF; borrowed when nothing is erased.
fn stored(body: &[u8]) -> Option<Cow<'_, [u8]>> {
    let regions = crate::image::regions(body)?;
    if let [only] = regions.stored.as_slice() {
        if only.len() == body.len() {
            return Some(Cow::Borrowed(body));
        }
    }
    let mut stored = alloc::vec![0xff; body.len()];
    for region in regions.stored {
        let start = region.as_ptr() as usize - body.as_ptr() as usize;
        stored[start..start + region.len()].copy_from_slice(region);
    }
    Some(Cow::Owned(stored))
}

/// CPU target of a relative BSR.B/BSR.W at `call`.
fn relative_call(stored: &[u8], call: usize) -> Option<i64> {
    let pc = super::BASE as i64 + call as i64;
    match stored.get(call..)? {
        [0x55, delta, ..] => Some(pc + 2 + i64::from(*delta as i8)),
        [0x5c, 0, a, b, ..] => Some(pc + 4 + i64::from(i16::from_be_bytes([*a, *b]))),
        _ => None,
    }
}

/// Describe why stored Normal code has no recognized 0x009F comparison.
/// `None` when stored regions are unavailable or a 0x009F comparison (or a
/// conflict) was recognized, so the miss is elsewhere.
pub fn inspect(normal: &[u8], kernel: Option<&[u8]>) -> Option<Miss> {
    miss(normal, &stored(normal)?, kernel)
}

fn miss(normal: &[u8], stored: &[u8], kernel: Option<&[u8]>) -> Option<Miss> {
    let other_parameter = match super::discover(stored) {
        Ok(None) => None,
        Ok(Some(r)) if r.parameter != 0x9f => Some(r),
        _ => return None,
    };
    let getter = match layout::discover_h8_reader(normal, kernel) {
        Observation::Known(e) => Getter::Bound(e.component, e.getter, e.argument_register),
        Observation::Unresolved(reason) => Getter::Unbound(reason),
        Observation::Conflicting => Getter::Conflicting,
    };
    // A required resident entry is the exact paired A4/A5 call target.
    let entry = match getter {
        Getter::Bound(_, entry, register) => Some((entry, register)),
        Getter::Unbound(Unresolved::ResidentCodeRequired(entry)) => Some((entry, 0)),
        _ => None,
    };
    let mut reads = Vec::new();
    let mut loader_flag_wrappers = Vec::new();
    for at in (0..stored.len().saturating_sub(5)).step_by(2) {
        let w = &stored[at..at + 6];
        if w == [0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70] {
            loader_flag_wrappers.push(super::BASE as u32 + at as u32);
        }
        let Some((entry, register)) = entry else {
            continue;
        };
        // Every explicit call form: absolute/indirect, and relative BSR.
        if w[..4] == [0x79, register, 0, 0x9f]
            && (super::getter_call(stored, at).is_some_and(|(g, _)| g == entry as usize)
                || relative_call(stored, at + 4) == Some(i64::from(entry)))
        {
            reads.push(super::BASE as u32 + at as u32);
        }
    }
    Some(Miss {
        getter,
        other_parameter,
        reads,
        loader_flag_wrappers,
    })
}

/// How the absence of a fixed 0x009F startup gate was established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Basis {
    /// The audited startup function's gate slot holds no 0x009F read, and no
    /// stored getter call passes 0x009F anywhere.
    EmptySlot,
    /// The slot holds one getter read of the given word (the only 0x009F read
    /// when that word is 0x009F); its result is overwritten by the next callee
    /// before any use. No comparison or loader-flag arm.
    DeadRead {
        /// CPU address of the immediate index load.
        at: u32,
        /// Word index read and discarded.
        word: u16,
    },
    /// SAT1 only: no stored Normal call or wrapper of loader-flag service
    /// 0x400A1A and no 0x009F getter read anywhere in stored Normal code.
    NoLoaderFlagService,
}

/// Positive proof that the target cannot reject on a fixed 0x009F comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Absence {
    /// Bound getter owner, entry and index register.
    pub getter: (H8ReaderComponent, u32, u8),
    /// Proof form.
    pub basis: Basis,
    /// Startup-function anchor (handler install) for the slot forms.
    pub anchor: Option<u32>,
    /// Held-Kernel 0x009F loads, each proven a byte store at buffer offset 0x9F.
    pub kernel_stores: Vec<u32>,
}

fn masked(body: &[u8], at: usize, pattern: &[u8], masks: &[(usize, usize)]) -> bool {
    body.get(at..at + pattern.len()).is_some_and(|bytes| {
        bytes.iter().zip(pattern).enumerate().all(|(i, (a, b))| {
            a == b
                || masks
                    .iter()
                    .any(|&(start, len)| (start..start + len).contains(&i))
        })
    })
}

// Handler install that ends the audited startup function, directly after the
// gate slot. ER1 form (SAT 8xxx R0 / 9xxx / REC), as at 0x45de0c in the bound
// FE0B gate image: MOV.L #h,ER1; MOV.L ER1,@a; JSR; JSR; BSET #0/#4 FFFDFF2A/29.
const ANCHOR_ER1: (&[u8], &[(usize, usize)]) = (
    &[
        0x7a, 1, 0, 0, 0, 0, 1, 0, 0x6b, 0xa1, 0, 0, 0, 0, 0x5e, 0, 0, 0, 0x5e, 0, 0, 0, 0x6a,
        0x38, 0xff, 0xfd, 0xff, 0x2a, 0x70, 0, 0x6a, 0x38, 0xff, 0xfd, 0xff, 0x29, 0x70, 0x40,
    ],
    &[(3, 3), (12, 2), (15, 3), (19, 3)],
);
// ER2 form (SAT 8000 R1), as at 0x48b6b2 in the bound FF01 gate image.
const ANCHOR_ER2: (&[u8], &[(usize, usize)]) = (
    &[
        0x7a, 2, 0, 0, 0, 0, 1, 0, 0x6b, 0xa2, 0, 0, 0, 0, 0x5d, 0x50, 0x0f, 0x81, 0x47, 8, 0x0b,
        0x91, 0x0b, 0x91, 0x0f, 0x90, 0x40, 2, 0x1a, 0x80, 1, 0, 0x6b, 0xa0, 0, 0, 0, 0, 0x5d,
        0x50, 0x5e, 0, 0, 0, 0x5d, 0x50, 0x5e, 0, 0, 0, 0x5e, 0, 0, 0, 0x5e, 0, 0, 0, 0x6a, 0x38,
        0xff, 0xfd, 0xff, 0x2a, 0x70, 0, 0x6a, 0x38, 0xff, 0xfd, 0xff, 0x29, 0x70, 0x40,
    ],
    &[(3, 3), (12, 2), (36, 2), (41, 3), (47, 3), (51, 3), (55, 3)],
);
// Callee entry that overwrites R0 before any read: MOV.L ER3,@-ER7;
// MOV.L #a,ER3; MOV.W @a,R0.
const R0_OVERWRITE: (&[u8], &[(usize, usize)]) = (
    &[
        1, 0, 0x6d, 0xf3, 0x7a, 3, 0, 0, 0, 0, 0x6b, 0x20, 0, 0, 0, 0,
    ],
    &[(6, 4), (12, 4)],
);
// Kernel buffer byte store: STM.L (ER4-ER5); MOV.B R2L,R4L; MOV.W R1,R5;
// SUB.B R0L,R0L; JSR mapper; MOV.L ER0,ER1; MOV.W R5,R0; EXTU.L ER0;
// ADD.L ER1,ER0; MOV.B R4L,R1L; JSR store; LDM.L; RTS.
const BYTE_STORE: (&[u8], &[(usize, usize)]) = (
    &[
        1, 0x10, 0x6d, 0xf4, 0x0c, 0xac, 0x0d, 0x15, 0x18, 0x88, 0x5e, 0, 0, 0, 0x0f, 0x81, 0x0d,
        0x50, 0x17, 0x70, 0x0a, 0x90, 0x0c, 0xc9, 0x5e, 0, 0, 0, 1, 0x10, 0x6d, 0x75, 0x54, 0x70,
    ],
    &[(11, 3), (25, 3)],
);
// The final store: MOV.B R1L,@(d:32,ER0); RTS.
const STORE: (&[u8], &[(usize, usize)]) =
    (&[0x78, 0, 0x6a, 0xa9, 0, 0, 0, 0, 0x54, 0x70], &[(4, 4)]);

fn target(bytes: &[u8], base: u32) -> Option<usize> {
    let address = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
    address.checked_sub(base).map(|a| a as usize)
}

fn uses_register_4(insn: &h8_asm::isa::Insn) -> bool {
    use h8_asm::isa::{Ea, Operand, Reg};
    // Implicit operands the decoder does not list: EEPMOV.B/W counts down
    // R4L/R4 and advances ER5/ER6. Other H8S block/MAC/TAS forms decode their
    // registers explicitly.
    if insn.mnemonic == "EEPMOV" {
        return true;
    }
    let reg = |r: &Reg| matches!(r, Reg::Byte(4 | 12) | Reg::Word(4 | 12) | Reg::Long(4));
    let ea = |e: &Ea| match e {
        Ea::Indirect(r)
        | Ea::PostIncrement(r)
        | Ea::PreDecrement(r)
        | Ea::PostDecrement(r)
        | Ea::PreIncrement(r)
        | Ea::PcIndexed(r) => reg(r),
        Ea::Displacement { base, .. } => reg(base),
        Ea::Indexed { index, .. } => reg(index),
        _ => false,
    };
    insn.operands.iter().any(|o| match o {
        Operand::Register(r) => reg(r),
        Operand::Address(e) => ea(e),
        Operand::IndexedMemory { address, .. } => ea(address),
        Operand::Registers { first, last } => (*first..=*last).contains(&4),
        _ => false,
    })
}

/// Decoded instruction starts: length, successors and instruction.
type Routine = alloc::collections::BTreeMap<usize, (usize, Vec<usize>, h8_asm::isa::Insn)>;

/// Complete local control flow of one Kernel routine from `entry`: decoded
/// instruction starts with their lengths and successors. Calls continue at
/// their return address. Unresolved, indirect or non-returning control,
/// overlapping decodes or more than 4096 instructions refuse.
fn kernel_routine(kernel: &[u8], entry: usize) -> Option<Routine> {
    use h8_asm::{
        isa::{decode_insn, Ea, Operand},
        Mode, Target,
    };
    let mut nodes = alloc::collections::BTreeMap::new();
    let mut pending = alloc::vec![entry];
    while let Some(pc) = pending.pop() {
        if nodes.contains_key(&pc) {
            continue;
        }
        if nodes.len() >= 4096 || pc & 1 != 0 {
            return None;
        }
        let decoded = decode_insn(kernel.get(pc..)?, Target::H8S2000, Mode::Advanced).ok()?;
        let next = pc.checked_add(decoded.len)?;
        if decoded.len == 0 || next > kernel.len() {
            return None;
        }
        let insn = decoded.insn;
        let mut successors = Vec::new();
        match insn.mnemonic {
            "RTS" => {}
            "JSR" | "BSR" => successors.push(next),
            "JMP" => {
                let Operand::Address(Ea::Absolute { value, .. }) = insn.operands[0] else {
                    return None;
                };
                successors.push(target(&value.to_be_bytes()[1..], KERNEL_BASE)?);
            }
            name => match insn.operands.first() {
                Some(Operand::Address(Ea::PcRelative { value, .. })) => {
                    if !name.starts_with('B') {
                        return None;
                    }
                    if name != "BRN" {
                        successors.push(next.checked_add_signed(*value as isize)?);
                    }
                    if name != "BRA" {
                        successors.push(next);
                    }
                }
                _ if matches!(name, "RTE" | "TRAPA" | "SLEEP") => return None,
                _ => successors.push(next),
            },
        }
        pending.extend(successors.iter().copied());
        nodes.insert(pc, (decoded.len, successors, insn));
    }
    // Overlapping decodes mean some path executes another path's operands.
    let mut end = 0;
    for (&pc, (len, ..)) in &nodes {
        if pc < end {
            return None;
        }
        end = pc + len;
    }
    Some(nodes)
}

// One Kernel 0x009F load: MOV.B @(d,ER7),R2L; MOV.W #9F,R1; MOV.L ERn,ER0;
// JSR @ER4, where ER4 holds the byte-store routine. Proven on the complete
// control flow of the enclosing routine (entry: the 01 00 6D F3 prologue after
// the nearest preceding RTS): the ER4 load is on every path from the entry to
// the JSR @ER4, nothing on a path from the load to it touches register 4
// (other than JSR @ER4 calls; callees preserve ER4-ER6 per the Renesas H8S C
// ABI, a stated assumption in the module documentation), and no
// direct reference from outside the routine enters any instruction that can
// reach the call without passing the load.
fn kernel_byte_store(kernel: &[u8], at: usize) -> bool {
    let site = |b: &[u8]| b[..2] == [0x6e, 0x7a] && b[4..8] == [0x79, 1, 0, 0x9f];
    let call = |b: &[u8]| b[8] == 0x0f && matches!(b[9], 0xb0 | 0xe0) && b[10..12] == [0x5d, 0x40];
    let Some(bytes) = at.checked_sub(4).and_then(|s| kernel.get(s..s + 12)) else {
        return false;
    };
    if !site(bytes) || !call(bytes) {
        return false;
    }
    let Some(load) = (at.saturating_sub(0x400)..at)
        .step_by(2)
        .rev()
        .find(|&p| kernel[p..p + 2] == [0x7a, 4] && p % 2 == at % 2)
    else {
        return false;
    };
    let Some(routine) = target(&kernel[load + 3..load + 6], KERNEL_BASE) else {
        return false;
    };
    if kernel[load + 2] != 0
        || !masked(kernel, routine, BYTE_STORE.0, BYTE_STORE.1)
        || !target(&kernel[routine + 25..routine + 28], KERNEL_BASE)
            .is_some_and(|store| masked(kernel, store, STORE.0, STORE.1))
    {
        return false;
    }
    kernel_dominated_store(kernel, load, at + 6).unwrap_or_default()
}

fn kernel_dominated_store(kernel: &[u8], load: usize, call: usize) -> Option<bool> {
    use alloc::collections::{BTreeMap, BTreeSet};
    let entry = (load.saturating_sub(0x2000)..load)
        .step_by(2)
        .rev()
        .find(|&p| p % 2 == load % 2 && kernel[p..p + 2] == [0x54, 0x70])?
        + 2;
    if kernel.get(entry..entry + 4)? != [1, 0, 0x6d, 0xf3] {
        return Some(false);
    }
    let nodes = kernel_routine(kernel, entry)?;
    if !nodes.contains_key(&load) || !nodes.contains_key(&call) {
        return Some(false);
    }
    let mut predecessors: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (&pc, (_, successors, _)) in &nodes {
        for &s in successors {
            predecessors.entry(s).or_default().push(pc);
        }
    }
    // Dominance: the call is unreachable from the entry once the load is cut.
    let mut seen = BTreeSet::new();
    let mut todo = alloc::vec![entry];
    while let Some(pc) = todo.pop() {
        if pc == load || !seen.insert(pc) {
            continue;
        }
        if pc == call {
            return Some(false);
        }
        todo.extend(nodes.get(&pc).map_or(&[][..], |n| n.1.as_slice()));
    }
    // Instructions on some load-to-call path (not re-passing the load).
    let mut forward = BTreeSet::new();
    let mut todo: Vec<usize> = nodes[&load].1.clone();
    while let Some(pc) = todo.pop() {
        if pc == load || !forward.insert(pc) {
            continue;
        }
        todo.extend(nodes.get(&pc).map_or(&[][..], |n| n.1.as_slice()));
    }
    let mut backward = BTreeSet::new();
    let mut todo = alloc::vec![call];
    while let Some(pc) = todo.pop() {
        if pc == load || !backward.insert(pc) {
            continue;
        }
        todo.extend(predecessors.get(&pc).map_or(&[][..], Vec::as_slice));
    }
    for pc in forward.intersection(&backward) {
        let insn = &nodes[pc].2;
        let call_er4 = insn.mnemonic == "JSR" && kernel[*pc..*pc + 2] == [0x5d, 0x40];
        if !call_er4 && uses_register_4(insn) {
            return Some(false);
        }
    }
    // `backward` holds every instruction reaching the call without the load:
    // a direct entry into one of them from outside the routine bypasses it.
    let interior = |target: usize| backward.contains(&target);
    for at in (0..kernel.len()).step_by(2) {
        // The routine's own references are its decoded edges above.
        if nodes
            .range(..=at)
            .next_back()
            .is_some_and(|(&pc, n)| at < pc + n.0)
        {
            continue;
        }
        let pc = |len: usize, delta: isize| (at + len).checked_add_signed(delta);
        let entered = match &kernel[at..] {
            [0x5e | 0x5a, a, b, c, ..] => target(&[*a, *b, *c], KERNEL_BASE),
            [0, 0x40, a, b, ..] => target(&[0x40, *a, *b], KERNEL_BASE),
            [0x40..=0x4f | 0x55, delta, ..] => pc(2, *delta as i8 as isize),
            [0x58, cond, a, b, ..] if cond & 15 == 0 => {
                pc(4, i16::from_be_bytes([*a, *b]) as isize)
            }
            [0x5c, 0, a, b, ..] => pc(4, i16::from_be_bytes([*a, *b]) as isize),
            _ => None,
        };
        if entered.is_some_and(interior) && !neighbour_operand(kernel, at) {
            return Some(false);
        }
    }
    Some(true)
}

/// Exact native saved-register routine entries after an RTS (the same forms
/// `cache_flow` accepts): MOV.L ER3,@-ER7; STM (ER4-ER6); STM (ER4-ER5).
const NEIGHBOUR_PROLOGUES: [[u8; 4]; 3] = [
    [1, 0, 0x6d, 0xf3],
    [1, 0x20, 0x6d, 0xf4],
    [1, 0x10, 0x6d, 0xf4],
];

/// A raw byte hit at `at` is no instruction only when it lies strictly inside
/// an operand of a neighbouring routine that starts with an exact native
/// prologue after an RTS and decodes completely by bounded control flow.
fn neighbour_operand(kernel: &[u8], at: usize) -> bool {
    let Some(rts) = (at.saturating_sub(0x2000)..at)
        .step_by(2)
        .rev()
        .find(|&p| p % 2 == at % 2 && kernel[p..p + 2] == [0x54, 0x70])
    else {
        return false;
    };
    let entry = rts + 2;
    if !kernel
        .get(entry..entry + 4)
        .is_some_and(|head| NEIGHBOUR_PROLOGUES.iter().any(|p| head == p))
    {
        return false;
    }
    let Some(nodes) = kernel_routine(kernel, entry) else {
        return false;
    };
    nodes
        .range(..at)
        .next_back()
        .is_some_and(|(&pc, n)| pc < at && at < pc + n.0)
}

/// Prove that the target Normal and its held Kernel have no fixed 0x009F
/// startup comparison. `None` is not evidence of a gate; it only means this
/// bounded proof does not hold (including a missing Kernel). The global
/// no-loader-flag-service form is admitted only for SAT1 (`sat1`), the only
/// generation audited without the 0x400A00 Kernel service table.
pub fn absent(normal: &[u8], kernel: Option<&[u8]>, sat1: bool) -> Option<Absence> {
    let kernel = kernel?;
    let stored_normal = stored(normal)?;
    let miss = miss(normal, &stored_normal, Some(kernel))?;
    let Getter::Bound(component, getter, register) = miss.getter else {
        return None;
    };
    if miss.other_parameter.is_some() {
        return None;
    }
    let kernel = stored(kernel)?;
    let mut kernel_stores = Vec::new();
    for at in (0..kernel.len().saturating_sub(3)).step_by(2) {
        if kernel[at] == 0x79 && kernel[at + 1] <= 15 && kernel[at + 2..at + 4] == [0, 0x9f] {
            if !kernel_byte_store(&kernel, at) {
                return None;
            }
            kernel_stores.push(KERNEL_BASE + at as u32);
        }
    }
    let normal = &*stored_normal;
    let anchors: Vec<usize> = (0..normal.len())
        .step_by(2)
        .filter(|&at| {
            masked(normal, at, ANCHOR_ER1.0, ANCHOR_ER1.1)
                || masked(normal, at, ANCHOR_ER2.0, ANCHOR_ER2.1)
        })
        .collect();
    let base = super::BASE as u32;
    let (basis, anchor) = match anchors.as_slice() {
        [anchor] => {
            let at = *anchor;
            let slot = normal.get(at.checked_sub(12)?..at)?;
            let call = [
                0x5e,
                (getter >> 16) as u8,
                (getter >> 8) as u8,
                getter as u8,
            ];
            // Empty: exactly three JSRs, none to the getter, so the slot
            // itself loads no index (a 0x9F load passed to a wrapper is a read).
            let basis = if miss.reads.is_empty()
                && slot
                    .chunks_exact(4)
                    .all(|jsr| jsr[0] == 0x5e && jsr != call)
            {
                Basis::EmptySlot
            } else if slot[4..6] == [0x79, register]
                && slot[8..] == call
                && normal[at + 1] == 1
                && target(&normal[at + 15..at + 18], base)
                    .is_some_and(|callee| masked(normal, callee, R0_OVERWRITE.0, R0_OVERWRITE.1))
            {
                let read = base + at as u32 - 8;
                let word = u16::from_be_bytes([slot[6], slot[7]]);
                let only = if word == 0x9f {
                    alloc::vec![read]
                } else {
                    Vec::new()
                };
                if miss.reads != only {
                    return None;
                }
                Basis::DeadRead { at: read, word }
            } else {
                return None;
            };
            (basis, Some(base + at as u32))
        }
        [] => {
            // JSR/JMP @aa:24 or any aligned 32-bit literal (pointer or
            // MOV.L #imm immediate) naming the service is a reference.
            let service = (0..normal.len().saturating_sub(3)).step_by(2).any(|at| {
                matches!(normal[at], 0 | 0x5e | 0x5a)
                    && normal[at + 1..at + 4] == [0x40, 0x0a, 0x1a]
            });
            if !sat1 || service || !miss.reads.is_empty() {
                return None;
            }
            (Basis::NoLoaderFlagService, None)
        }
        _ => return None,
    };
    Some(Absence {
        getter: (component, getter, register),
        basis,
        anchor,
        kernel_stores,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // SAT 8600 BDW-PR1CPB-style startup slot (515b9fa7…, 0x45f66c): the word is
    // read and the next callee overwrites R0; no comparison or loader-flag arm.
    const READ_ONLY: &[u8] = &[
        0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x7a, 1, 0, 0x45, 0xf2, 0x4c, 1, 0, 0x6b, 0xa1, 0,
        0, 0x11, 0x46,
    ];
    // Cluster A, SAT 8600 515b9fa7… 0x45f668: slot (JSR; MOV.W #9F,R0; JSR
    // getter) and its ER1 handler-install anchor.
    const SLOT_DEAD_READ: &[u8] = &[
        0x5e, 0x45, 0xec, 0xf0, 0x79, 0x00, 0x00, 0x9f, 0x5e, 0x54, 0xb6, 0xf0, 0x7a, 0x01, 0x00,
        0x45, 0xf2, 0x4c, 0x01, 0x00, 0x6b, 0xa1, 0x00, 0x00, 0x11, 0x46, 0x5e, 0x53, 0x35, 0xfa,
        0x5e, 0x53, 0x3a, 0x32, 0x6a, 0x38, 0xff, 0xfd, 0xff, 0x2a, 0x70, 0x00, 0x6a, 0x38, 0xff,
        0xfd, 0xff, 0x29, 0x70, 0x40,
    ];
    // Its next callee 0x5335fa: MOV.L ER3,@-ER7; MOV.L #1F96,ER3; MOV.W @1F92,R0.
    const CALLEE: &[u8] = &[
        0x01, 0x00, 0x6d, 0xf3, 0x7a, 0x03, 0x00, 0x00, 0x1f, 0x96, 0x6b, 0x20, 0x00, 0x00, 0x1f,
        0x92,
    ];
    // SAT 8301 0cc2f51a… 0x47253c: dead read of word 0x8D in the same slot.
    const SLOT_OTHER_WORD: &[u8] = &[
        0x5e, 0x47, 0x15, 0xda, 0x79, 0x00, 0x00, 0x8d, 0x5e, 0x55, 0x5a, 0x2c, 0x7a, 0x01, 0x00,
        0x47, 0x21, 0x1a, 0x01, 0x00, 0x6b, 0xa1, 0x00, 0x00, 0x12, 0xf6, 0x5e, 0x54, 0x00, 0x18,
        0x5e, 0x54, 0x04, 0x44, 0x6a, 0x38, 0xff, 0xfd, 0xff, 0x2a, 0x70, 0x00, 0x6a, 0x38, 0xff,
        0xfd, 0xff, 0x29, 0x70, 0x40,
    ];
    // Cluster C, SAT 8000 BDR-207 0b524916… 0x48a1d6: three init JSRs and the
    // ER2 handler-install anchor; no 0x9F read.
    const SLOT_EMPTY_ER2: &[u8] = &[
        0x5e, 0x54, 0x2c, 0x12, 0x5e, 0x42, 0xfd, 0x02, 0x5e, 0x48, 0x8f, 0x7a, 0x7a, 0x02, 0x00,
        0x48, 0x9d, 0x06, 0x01, 0x00, 0x6b, 0xa2, 0x00, 0x00, 0x0f, 0x58, 0x5d, 0x50, 0x0f, 0x81,
        0x47, 0x08, 0x0b, 0x91, 0x0b, 0x91, 0x0f, 0x90, 0x40, 0x02, 0x1a, 0x80, 0x01, 0x00, 0x6b,
        0xa0, 0x00, 0x00, 0x0f, 0x5c, 0x5d, 0x50, 0x5e, 0x41, 0x5d, 0x08, 0x5d, 0x50, 0x5e, 0x41,
        0x5a, 0x84, 0x5e, 0x5d, 0x13, 0xe4, 0x5e, 0x5d, 0x18, 0x1c, 0x6a, 0x38, 0xff, 0xfd, 0xff,
        0x2a, 0x70, 0x00, 0x6a, 0x38, 0xff, 0xfd, 0xff, 0x29, 0x70, 0x40,
    ];
    // SAT 8600 Kernel ff8b12cc…: 0x402390 site, 0x4016c6 byte store, 0x404912 store.
    const KERNEL_SITE: &[u8] = &[
        0x6e, 0x7a, 0x00, 0x03, 0x79, 0x01, 0x00, 0x9f, 0x0f, 0xb0, 0x5d, 0x40,
    ];
    const KERNEL_ROUTINE: &[u8] = &[
        0x01, 0x10, 0x6d, 0xf4, 0x0c, 0xac, 0x0d, 0x15, 0x18, 0x88, 0x5e, 0x40, 0x4d, 0x98, 0x0f,
        0x81, 0x0d, 0x50, 0x17, 0x70, 0x0a, 0x90, 0x0c, 0xc9, 0x5e, 0x40, 0x11, 0x00, 0x01, 0x10,
        0x6d, 0x75, 0x54, 0x70,
    ];
    const KERNEL_STORE: &[u8] = &[0x78, 0x00, 0x6a, 0xa9, 0x00, 0xa0, 0x00, 0x00, 0x54, 0x70];

    fn normal() -> Vec<u8> {
        let mut normal = alloc::vec![0xff; 0x4000];
        layout::install_test_layout(&mut normal, 0x1000);
        normal
    }

    /// Held Kernel with the audited buffer byte store at offset 0x9F.
    pub(crate) fn kernel() -> Vec<u8> {
        let mut kernel = alloc::vec![0xff; 0x4000];
        kernel[0x1000..0x1000 + KERNEL_ROUTINE.len()].copy_from_slice(KERNEL_ROUTINE);
        kernel[0x1100..0x1100 + KERNEL_STORE.len()].copy_from_slice(KERNEL_STORE);
        // Enclosing routine: RTS of the previous one, then its prologue.
        kernel[0x1ffa..0x2000].copy_from_slice(&[0x54, 0x70, 1, 0, 0x6d, 0xf3]);
        kernel[0x2000..0x2006].copy_from_slice(&[0x7a, 4, 0, 0x40, 0x10, 0]);
        kernel[0x2006..0x2006 + KERNEL_SITE.len()].copy_from_slice(KERNEL_SITE);
        kernel[0x2020..0x2022].copy_from_slice(&[0x54, 0x70]);
        kernel
    }

    // Place a slot+anchor with the getter call and anchor callee relocated.
    fn place(normal: &mut [u8], slot: &[u8], getter_call: bool) {
        normal[0x100..0x100 + slot.len()].copy_from_slice(slot);
        if getter_call {
            normal[0x109..0x10c].copy_from_slice(&[0x41, 0x10, 0]);
        }
        if slot[13] == 1 {
            normal[0x11b..0x11e].copy_from_slice(&[0x41, 0x30, 0]);
            normal[0x3000..0x3000 + CALLEE.len()].copy_from_slice(CALLEE);
        }
        // A loader-flag wrapper is present in these generations.
        normal[0x1c00..0x1c06].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
    }

    /// Cluster B/D-shape target: audited startup function, empty gate slot.
    pub(crate) fn empty_slot_normal() -> Vec<u8> {
        let mut normal = normal();
        let mut slot = SLOT_DEAD_READ.to_vec();
        slot[4..8].copy_from_slice(&[0x5e, 0x45, 0xec, 0xf4]);
        place(&mut normal, &slot, false);
        normal
    }

    #[test]
    fn read_without_comparison_is_retained_as_a_read_only_fact() {
        let mut normal = normal();
        normal[0x80..0x80 + READ_ONLY.len()].copy_from_slice(READ_ONLY);
        normal[0x1800..0x1806].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        let miss = inspect(&normal, None).unwrap();
        assert_eq!(
            miss.getter,
            Getter::Bound(H8ReaderComponent::Normal, 0x411000, 0)
        );
        assert_eq!(miss.reads, alloc::vec![0x410080]);
        assert_eq!(miss.loader_flag_wrappers, alloc::vec![0x411800]);
        assert_eq!(miss.other_parameter, None);
        assert!(!matches!(
            super::super::bound_selection(&normal),
            Observation::Known(_)
        ));
        // A bare read outside the audited slot is never an absence proof.
        assert_eq!(absent(&normal, Some(&kernel()), true), None);
        normal[0x81] = 1;
        assert!(inspect(&normal, None).unwrap().reads.is_empty());
        normal[0x81] = 0;
        normal[0x86] = 0x20;
        assert!(inspect(&normal, None).unwrap().reads.is_empty());
    }

    #[test]
    fn dead_read_slot_proves_absence_only_with_its_r0_overwrite() {
        let mut normal = normal();
        place(&mut normal, SLOT_DEAD_READ, true);
        let proof = absent(&normal, Some(&kernel()), false).unwrap();
        assert_eq!(
            proof.basis,
            Basis::DeadRead {
                at: 0x410104,
                word: 0x9f
            }
        );
        assert_eq!(proof.anchor, Some(0x41010c));
        assert_eq!(proof.kernel_stores, alloc::vec![0x40200a]);
        // The next callee reads R0 first: the result may be consumed.
        normal[0x300a] = 0x6b;
        normal[0x300b] = 0xa0;
        assert_eq!(absent(&normal, Some(&kernel()), true), None);
        let mut other = self::normal();
        place(&mut other, SLOT_OTHER_WORD, true);
        assert_eq!(
            absent(&other, Some(&kernel()), false).unwrap().basis,
            Basis::DeadRead {
                at: 0x410104,
                word: 0x8d
            }
        );
        // A second 0x9F read elsewhere defeats the slot-local proof.
        other[0x80..0x88].copy_from_slice(&READ_ONLY[..8]);
        assert_eq!(absent(&other, Some(&kernel()), true), None);
    }

    #[test]
    fn empty_slot_proves_absence_for_both_anchor_forms() {
        let normal = empty_slot_normal();
        let proof = absent(&normal, Some(&kernel()), false).unwrap();
        assert_eq!(proof.basis, Basis::EmptySlot);
        let mut er2 = self::normal();
        place(&mut er2, SLOT_EMPTY_ER2, false);
        assert_eq!(
            absent(&er2, Some(&kernel()), false).unwrap().anchor,
            Some(0x41010c)
        );
        // Two anchors leave the startup function unbound.
        let mut twice = er2.clone();
        twice[0x200..0x200 + SLOT_EMPTY_ER2.len()].copy_from_slice(SLOT_EMPTY_ER2);
        assert_eq!(absent(&twice, Some(&kernel()), true), None);
        // Any 0x9F getter read with an empty slot is not absence.
        er2[0x80..0x88].copy_from_slice(&READ_ONLY[..8]);
        assert_eq!(absent(&er2, Some(&kernel()), true), None);
    }

    #[test]
    fn global_absence_requires_held_kernel_and_no_loader_flag_service() {
        let normal = normal();
        let proof = absent(&normal, Some(&kernel()), true).unwrap();
        assert_eq!(proof.basis, Basis::NoLoaderFlagService);
        assert_eq!(proof.anchor, None);
        // Outside SAT1 a gate-less image without the audited function is unproven.
        assert_eq!(absent(&normal, Some(&kernel()), false), None);
        assert_eq!(absent(&normal, None, true), None);
        assert!(absent(&normal, Some(&[0xff; 64]), true).is_some());
        let mut flag = normal.clone();
        flag[0x200..0x204].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a]);
        assert_eq!(absent(&flag, Some(&kernel()), true), None);
        let mut read = normal.clone();
        read[0x80..0x88].copy_from_slice(&READ_ONLY[..8]);
        assert_eq!(absent(&read, Some(&kernel()), true), None);
    }

    #[test]
    fn kernel_009f_loads_must_be_the_audited_byte_store() {
        let normal = normal();
        for (at, value) in [(0x2001, 5), (0x1001, 0x11), (0x1103, 0xa8), (0x2010, 0x0f)] {
            let mut kernel = kernel();
            kernel[at] = value;
            assert_eq!(
                absent(&normal, Some(&kernel), true),
                None,
                "kernel byte {at:#x}"
            );
        }
        // An intervening ER4 write between load and call refuses.
        let mut kernel = kernel();
        kernel.copy_within(0x2000..0x2012, 0x2002);
        kernel[0x2000..0x2002].copy_from_slice(&[0x0f, 0x84]);
        kernel[0x2008..0x200a].copy_from_slice(&[0x0f, 0x84]);
        assert_eq!(absent(&normal, Some(&kernel), true), None);
    }

    #[test]
    fn a_native_gate_is_never_classified_absent() {
        let mut gated = empty_slot_normal();
        gated[0x80..0x94].copy_from_slice(&[
            0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
            0x41, 0x1c, 0,
        ]);
        assert_eq!(inspect(&gated, None), None);
        assert_eq!(absent(&gated, Some(&kernel()), true), None);
        // Unrecognized compare in the slot itself: not empty, not a dead read.
        let mut slot = SLOT_DEAD_READ.to_vec();
        slot[0..4].copy_from_slice(&[0x79, 0, 0, 0x9f]);
        slot[4..8].copy_from_slice(&[0x5e, 0x41, 0x10, 0]);
        slot[8..12].copy_from_slice(&[0x79, 0x20, 0xfe, 0x24]);
        let mut normal = normal();
        place(&mut normal, &slot, false);
        assert_eq!(absent(&normal, Some(&kernel()), true), None);
    }

    #[test]
    fn empty_slot_and_recognized_comparison_are_distinguished() {
        let normal = normal();
        let miss = inspect(&normal, None).unwrap();
        assert!(miss.reads.is_empty() && miss.loader_flag_wrappers.is_empty());
        let mut gated = normal;
        gated[0x80..0x94].copy_from_slice(&[
            0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
            0x41, 0x18, 0,
        ]);
        gated[0x1800..0x1806].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        assert_eq!(inspect(&gated, None), None);
    }

    #[test]
    fn slot_index_load_into_a_non_getter_call_is_not_an_empty_slot() {
        // JSR; MOV.W #9F,R0; JSR wrapper: the slot passes 0x009F onward.
        let mut normal = empty_slot_normal();
        normal[0x104..0x108].copy_from_slice(&[0x79, 0, 0, 0x9f]);
        assert_eq!(absent(&normal, Some(&kernel()), false), None);
    }

    #[test]
    fn relative_getter_calls_are_reads() {
        let mut normal = empty_slot_normal();
        // MOV.W #9F,R0; BSR.W getter (0x410088 + 0xf78 = 0x411000).
        normal[0x80..0x88].copy_from_slice(&[0x79, 0, 0, 0x9f, 0x5c, 0, 0x0f, 0x78]);
        assert_eq!(inspect(&normal, None).unwrap().reads, alloc::vec![0x410080]);
        assert_eq!(absent(&normal, Some(&kernel()), false), None);
        // BSR.B form, with the getter in reach.
        let mut near = self::normal();
        near[0xf80..0xf86].copy_from_slice(&[0x79, 0, 0, 0x9f, 0x55, 0x7a]);
        assert_eq!(inspect(&near, None).unwrap().reads, alloc::vec![0x410f80]);
        assert_eq!(absent(&near, Some(&kernel()), true), None);
    }

    #[test]
    fn branch_between_er4_load_and_site_is_not_straight_line() {
        let normal = normal();
        let mut kernel = kernel();
        // BRA past the site directly after the ER4 load.
        kernel.copy_within(0x2006..0x2012, 0x2008);
        kernel[0x2006..0x2008].copy_from_slice(&[0x40, 0x0c]);
        assert_eq!(absent(&normal, Some(&kernel), true), None);
        // An arm join inside the range (BRA to the site start) still holds.
        kernel[0x2007] = 0;
        assert!(absent(&normal, Some(&kernel), true).is_some());
    }

    #[test]
    fn branch_into_an_instruction_operand_is_not_straight_line() {
        let normal = normal();
        let mut kernel = kernel();
        // ER4 load; BRA +2; MOV.W #0x0B74,R0; site. The BRA lands on the
        // immediate 0B 74 = INC.L #1,ER4, which is never decoded.
        kernel.copy_within(0x2006..0x2012, 0x200c);
        kernel[0x2006..0x200c].copy_from_slice(&[0x40, 0x02, 0x79, 0x00, 0x0b, 0x74]);
        assert_eq!(absent(&normal, Some(&kernel), true), None);
        // The same BRA to the MOV's own start still holds.
        kernel[0x2007] = 0;
        assert!(absent(&normal, Some(&kernel), true).is_some());
    }

    #[test]
    fn branch_into_the_er4_load_operand_is_not_straight_line() {
        let normal = normal();
        let mut kernel = kernel();
        // Byte-store routine at 0x0B74: the load MOV.L #0x400B74,ER4 ends in
        // 0B 74 (INC.L #1,ER4). A backward BNE -4 lands on that operand.
        kernel[0xb74..0xb74 + KERNEL_ROUTINE.len()].copy_from_slice(KERNEL_ROUTINE);
        kernel[0x2004..0x2006].copy_from_slice(&[0x0b, 0x74]);
        kernel.copy_within(0x2006..0x2012, 0x2008);
        kernel[0x2006..0x2008].copy_from_slice(&[0x46, 0xfc]);
        assert_eq!(absent(&normal, Some(&kernel), true), None);
        // A backward branch to the load instruction itself still holds.
        kernel[0x2007] = 0xf8;
        assert!(absent(&normal, Some(&kernel), true).is_some());
    }

    #[test]
    fn er4_load_straddled_by_a_preceding_instruction_is_not_executed() {
        let normal = normal();
        let mut kernel = kernel();
        // Prologue, then 7A 00 = MOV.L #imm32,ER0 swallowing the load's first
        // four bytes: the ER4 load is never decoded or executed.
        kernel[0x1ff8..0x2000].copy_from_slice(&[0x54, 0x70, 1, 0, 0x6d, 0xf3, 0x7a, 0]);
        assert_eq!(absent(&normal, Some(&kernel), true), None);
    }

    #[test]
    fn branch_from_before_the_er4_load_into_the_range_skips_it() {
        let normal = normal();
        let mut kernel = kernel();
        // Prologue, then BRA to the site start, skipping the ER4 load.
        kernel[0x1ff8..0x2000].copy_from_slice(&[0x54, 0x70, 1, 0, 0x6d, 0xf3, 0x40, 0x06]);
        assert_eq!(absent(&normal, Some(&kernel), true), None);
    }

    #[test]
    fn back_edge_after_the_site_that_writes_er4_refuses() {
        let normal = normal();
        let mut kernel = kernel();
        // After JSR @ER4: INC.L #1,ER4; BNE back to the site start.
        kernel[0x2012..0x2016].copy_from_slice(&[0x0b, 0x74, 0x46, 0xf0]);
        assert_eq!(absent(&normal, Some(&kernel), true), None);
    }

    #[test]
    fn neighbour_operand_bytes_are_not_branches_but_its_branches_are() {
        let normal = normal();
        let mut kernel = kernel();
        // Neighbouring routine: prologue; MOV.L #0x580000FC,ER0; RTS. Its
        // operand bytes 58 00 00 FC read raw as BRA.W to the site start.
        kernel[0x1efe..0x1f0c].copy_from_slice(&[
            0x54, 0x70, 1, 0, 0x6d, 0xf3, 0x7a, 0, 0x58, 0, 0, 0xfc, 0x54, 0x70,
        ]);
        assert!(absent(&normal, Some(&kernel), true).is_some());
        // The same bytes as a decoded BRA.W of that neighbour enter the routine.
        kernel[0x1f04..0x1f0a].copy_from_slice(&[0x58, 0, 0x00, 0xfe, 0x54, 0x70]);
        assert_eq!(absent(&normal, Some(&kernel), true), None);
        // An STM (ER4-ER6) neighbour, as in the SAT 8D30 Kernel, is decoded.
        let mut stm = self::kernel();
        stm[0x1efe..0x1f0c].copy_from_slice(&[
            0x54, 0x70, 1, 0x20, 0x6d, 0xf4, 0x7a, 0, 0x58, 0, 0, 0xfc, 0x54, 0x70,
        ]);
        assert!(absent(&normal, Some(&stm), true).is_some());
        // A neighbour without an exact native prologue is not decoded: refuse.
        let mut other = self::kernel();
        other[0x1efe..0x1f0c].copy_from_slice(&[
            0x54, 0x70, 1, 0x30, 0x6d, 0xf4, 0x7a, 0, 0x58, 0, 0, 0xfc, 0x54, 0x70,
        ]);
        assert_eq!(absent(&normal, Some(&other), true), None);
    }

    #[test]
    fn eepmov_between_er4_load_and_site_writes_r4() {
        let normal = normal();
        let mut kernel = kernel();
        // RTS; prologue; MOV.L #0x401000,ER4; EEPMOV.W; NOP x3; site at 0x2006.
        kernel[0x1ff0..0x2006].copy_from_slice(&[
            0x54, 0x70, 1, 0, 0x6d, 0xf3, 0x7a, 4, 0, 0x40, 0x10, 0, 0x7b, 0xd4, 0x59, 0x8f, 0, 0,
            0, 0, 0, 0,
        ]);
        assert_eq!(absent(&normal, Some(&kernel), true), None);
        // Control: the same layout with NOPs in place of EEPMOV holds.
        kernel[0x1ffc..0x2000].fill(0);
        assert!(absent(&normal, Some(&kernel), true).is_some());
    }

    #[test]
    fn literal_service_address_defeats_the_no_service_proof() {
        let mut normal = normal();
        // MOV.L #0x400A1A,ER1; JSR @ER1.
        normal[0x200..0x208].copy_from_slice(&[0x7a, 1, 0, 0x40, 0x0a, 0x1a, 0x5d, 0x10]);
        assert_eq!(absent(&normal, Some(&kernel()), true), None);
    }
}

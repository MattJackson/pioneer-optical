//! V850 tray loading-arrival predicates, bound by the native `[LOADIN]` and
//! `[LOADOUT]` motor state machines in the bus-decoded Normal.
//!
//! Each role is the pin the state machine waits on after its diagnostic: an
//! arrival test `tst1 b, disp16[r0]; be ARRIVED`, where ARRIVED loads the
//! settle timer and enters state N, immediately followed by state N's
//! confirmation reread of the same pin (`be` keeps the arrival, otherwise the
//! state falls back to N-1). The waited-for level is therefore bit == 0.
//! Code offsets, RAM slots and state numbers are evidence, never values.
//!
//! Slim solenoid-eject drives run different `[LOADIN]`/`[LOADOUT]` programs
//! with no arrival/confirmation pair. For those, [`slim`] binds the exact
//! direct peripheral bit I/O each referenced state machine performs.
//!
//! Memory accesses through a base register are classified by bounded
//! constant propagation over the walked instructions (`mov`/`movea`/
//! `movhi`/`mov imm32`, `addi`, `add`/`sub` of known values, a few logic
//! ops; anything else makes the written register unknown; joins keep only
//! equal values). Edges come from the walk's own branches and `switch`
//! tables; the walk's start, positions with no edge inside the walk and
//! positions that branches or bounded `switch` tables outside the walk may
//! enter all start from nothing known. A known peripheral address counts
//! exactly like `disp16[r0]`; a known address inside the Normal image is
//! not I/O; any other known address (external bus, an alias of the I/O
//! region) and an unknown base refuse. By the calling convention sp
//! addresses the stack and gp the small data area within the disp16[gp]
//! window (gp is set before the Normal runs, so its value is not known
//! here), both RAM; a call (`jarl`, `callt`, `jarl [reg]`) preserves only
//! r20-r29, sp and gp.
use crate::image::layout::{Observation, Unresolved};
use alloc::{format, string::String, vec::Vec};

/// CPU address of Normal offset zero.
const BASE: usize = 0x10000;
/// Bytes after the diagnostic reference searched for the confirmation state.
const WINDOW: usize = 0x200;
const CLOSED: &[u8] = b"[LOADIN]\n\r\0";
const OPENED: &[u8] = b"[LOADOUT]\n\r\0";

/// One physical pin a role waits on. The required level is bit == 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Pin {
    /// Peripheral address: sign-extended `disp16[r0]`, or a tracked base
    /// register plus its displacement.
    pub address: u32,
    /// Bit index within the byte.
    pub bit: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Role {
    pub pin: Pin,
    /// Normal offsets of the arrival test and the confirmation state.
    pub arrival: usize,
    pub confirmation: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Predicates {
    pub closed: Role,
    pub opened: Role,
}

fn half(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]))
}
/// `tst1 bit, disp16[r0]` with a negative (peripheral) displacement.
fn test(b: &[u8], at: usize) -> Option<Pin> {
    let w = half(b, at)?;
    let disp = half(b, at + 2)?;
    (w & 0xc7ff == 0xc7c0 && disp >= 0x8000).then(|| Pin {
        address: 0xffff_0000 | u32::from(disp),
        bit: (w >> 11) as u8 & 7,
    })
}
/// Format III conditional branch: (condition, target).
fn branch(b: &[u8], at: usize) -> Option<(u16, usize)> {
    let w = half(b, at)?;
    if w & 0x0780 != 0x0580 {
        return None;
    }
    let disp = (((w >> 11) << 4) | (((w >> 4) & 7) << 1)) as i16;
    let disp = (disp << 7) >> 7; // sign-extend the 9-bit displacement
    Some((w & 15, at.checked_add_signed(isize::from(disp))?))
}
const BE: u16 = 2;
const BR: u16 = 5;
const BNE: u16 = 10;
/// `mov imm5, reg`: (reg, unsigned imm).
fn mov5(b: &[u8], at: usize) -> Option<(u16, u16)> {
    let w = half(b, at)?;
    (w & 0x07e0 == 0x0200).then_some((w >> 11, w & 31))
}
/// `st.b reg, disp16[gp]`: (reg, disp).
fn store(b: &[u8], at: usize) -> Option<(u16, u16)> {
    let w = half(b, at)?;
    (w & 0x07ff == 0x0744).then_some((w >> 11, half(b, at + 2)?))
}
/// `mov N, rB; st.b rB, s[gp]` with a nonzero register: (N, s).
fn state(b: &[u8], at: usize) -> Option<(u16, u16)> {
    let (reg, value) = mov5(b, at)?;
    let (stored, slot) = store(b, at + 2)?;
    (reg != 0 && reg == stored).then_some((value, slot))
}

/// Confirmation state at `c`: timer == 0, reread the pin, keep the arrival
/// on bit == 0 or fall back to state N-1. Returns (pin, N-1, state slot).
fn confirmation(b: &[u8], c: usize) -> Option<(Pin, u16, u16)> {
    let w = half(b, c)?;
    let timer = w >> 11;
    // ld.b / ld.h disp16[gp], timer; cmp r0, timer; bne exit
    if timer == 0
        || !(w & 0x07ff == 0x0704 || (w & 0x07ff == 0x0724 && half(b, c + 2)? & 1 == 0))
        || half(b, c + 4)? != (timer << 11) | 0x01e0
        || branch(b, c + 6)?.0 != BNE
    {
        return None;
    }
    let pin = test(b, c + 8)?;
    if branch(b, c + 12)? != (BE, c + 24) {
        return None;
    }
    let (fallback, slot) = state(b, c + 14)?;
    (branch(b, c + 20)?.0 == BR).then_some((pin, fallback, slot))
}

fn unique(b: &[u8], needle: &[u8]) -> Option<usize> {
    let mut found = b
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle);
    let (at, _) = found.next()?;
    found.next().is_none().then_some(at)
}

/// The unique `mov imm32, r7` loading the diagnostic at `label` for its print.
fn referenced(b: &[u8], label: usize) -> Option<usize> {
    let address = u32::try_from(label + BASE).ok()?;
    let mut reference = [0x27, 0x06, 0, 0, 0, 0];
    reference[2..].copy_from_slice(&address.to_le_bytes());
    unique(b, &reference).filter(|at| at & 1 == 0)
}

/// Each diagnostic's unique offset and its unique reference, located once.
struct Anchors {
    labels: [Option<usize>; 2],
    starts: [Option<usize>; 2],
}
fn anchors(b: &[u8]) -> Anchors {
    let labels = [unique(b, CLOSED), unique(b, OPENED)];
    Anchors {
        labels,
        starts: labels.map(|label| label.and_then(|at| referenced(b, at))),
    }
}

fn role(b: &[u8], start: Option<usize>) -> Observation<Role> {
    let Some(start) = start else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    let mut found: Option<Role> = None;
    for c in (start + 6..start + WINDOW).step_by(2) {
        let Some((pin, fallback, slot)) = confirmation(b, c) else {
            continue;
        };
        // ARRIVED: ...; mov N, rB; st.b rB, s[gp]; br exit — directly before c.
        if c < start + 30
            || state(b, c - 8) != Some((fallback + 1, slot))
            || branch(b, c - 2).map(|x| x.0) != Some(BR)
        {
            continue;
        }
        // The arrival test is the first peripheral bit test after the
        // diagnostic, on the same pin, branching into the ARRIVED block.
        let Some(arrival) = (start + 6..c).step_by(2).find(|&at| test(b, at).is_some()) else {
            continue;
        };
        match branch(b, arrival + 4) {
            Some((BE, target))
                if test(b, arrival) == Some(pin) && (c - 22..=c - 8).contains(&target) => {}
            _ => continue,
        }
        let next = Role {
            pin,
            arrival,
            confirmation: c,
        };
        if found.is_some_and(|old| old != next) {
            return Observation::Unresolved(Unresolved::AmbiguousReader);
        }
        found = Some(next);
    }
    found.map_or(
        Observation::Unresolved(Unresolved::ReaderNotRecognized),
        Observation::Known,
    )
}

/// Native-order (bus-decoded) Normal. Both roles must bind.
fn predicates(normal: &[u8], starts: [Option<usize>; 2]) -> Observation<Predicates> {
    match (role(normal, starts[0]), role(normal, starts[1])) {
        (Observation::Known(closed), Observation::Known(opened)) => {
            Observation::Known(Predicates { closed, opened })
        }
        (Observation::Unresolved(Unresolved::AmbiguousReader), _)
        | (_, Observation::Unresolved(Unresolved::AmbiguousReader)) => {
            Observation::Unresolved(Unresolved::AmbiguousReader)
        }
        _ => Observation::Unresolved(Unresolved::ReaderNotRecognized),
    }
}

#[cfg(test)]
fn native(normal: &[u8]) -> Observation<Predicates> {
    predicates(normal, anchors(normal).starts)
}

/// Whether both loading diagnostics exist, so a miss is a recognizer gap.
#[cfg(test)]
fn diagnostics(normal: &[u8]) -> bool {
    anchors(normal).labels.iter().all(Option::is_some)
}

/// One direct peripheral bit access of a slim loading program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Io {
    /// `tst1`: the program branches on this input.
    Input(Pin),
    /// `set1` (true) or `clr1` (false): the program drives this level.
    Output(Pin, bool),
}
/// The complete direct bit I/O of one referenced state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Program {
    /// Sorted, deduplicated physical I/O set. This is the value.
    pub io: Vec<Io>,
    /// Normal offsets of the diagnostic reference and the closing `dispose`.
    pub start: usize,
    pub end: usize,
    /// gp-relative RAM bit operations (mnemonic, displacement, bit): evidence.
    pub gates: Vec<(&'static str, u16, u8)>,
    /// Whether the direct set was incomplete, so one helper level was followed.
    pub followed: bool,
    /// Helper paths not bound (failed closed or deeper calls): evidence only.
    /// Empty unless a helper level was followed.
    pub unbound: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Slim {
    pub closed: Program,
    pub opened: Program,
}

/// reg2 == r0 forms under opcode 0x3c/0x3d whose second halfword has bit 0
/// set (jr disp22 has it clear).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Extended {
    /// prepare list, imm5 (00001) or prepare list, imm5, sp | imm16 |
    /// imm16 << 16 | imm32 (ff011): its length.
    Prepare(usize),
    /// V850E2 format XIV ld.b/bu/h/hu/w and st.b/h/w disp23[reg1] (6 bytes):
    /// sub-opcodes 0101, 1101, 00111, 01001, 01111.
    Disp23,
    /// No instruction this walker can decode.
    Unknown,
}
fn extended(b: &[u8], at: usize) -> Option<Option<Extended>> {
    let w = half(b, at)?;
    let sub = half(b, at + 2)?;
    if w >> 11 != 0 || !matches!((w >> 5) & 0x3f, 0x3c | 0x3d) || sub & 1 == 0 {
        return Some(None);
    }
    Some(Some(if sub & 0x1f == 1 {
        Extended::Prepare(4)
    } else if sub & 7 == 3 {
        Extended::Prepare([4, 6, 6, 8][usize::from((sub >> 3) & 3)])
    } else if matches!(sub & 0xf, 0b0101 | 0b1101)
        || matches!(sub & 0x1f, 0b00111 | 0b01001 | 0b01111)
    {
        Extended::Disp23
    } else {
        Extended::Unknown
    }))
}

/// V850E2 instruction length from its leading halfwords.
fn length(b: &[u8], at: usize) -> Option<usize> {
    let w = half(b, at)?;
    let (op, reg2) = ((w >> 5) & 0x3f, w >> 11);
    Some(match op {
        // jr/jarl disp32
        0x17 if reg2 == 0 => 6,
        0..=0x2f => 2,
        // mov imm32, reg / jmp disp32[reg]
        0x31 | 0x37 if reg2 == 0 => 6,
        0x3c | 0x3d if reg2 == 0 => match extended(b, at)? {
            Some(Extended::Prepare(len)) => len,
            Some(Extended::Disp23) => 6,
            Some(Extended::Unknown) | None => 4,
        },
        _ => 4,
    })
}
/// Longest referenced state machine walked before giving up.
const PROGRAM: usize = 0x1000;
/// Most `switch` table entries decoded for one table.
const CASES: usize = 0x400;
/// How far before a walk a `switch` may sit whose table enters the walk.
const SWITCH_REACH: usize = 0x1_0000;

/// Abstract register value of the bounded constant propagation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Val {
    Unknown,
    Known(u32),
    /// The stack pointer plus an offset: RAM by the calling convention.
    Stack,
    /// gp plus a known offset: the small data area, RAM by the calling
    /// convention when the offset stays within [`GP_REACH`].
    Gp(u32),
}
type Regs = [Val; 32];
const SP: usize = 3;
const GP: usize = 4;
const EP: usize = 30;
/// Offsets from gp inside its data area: the disp16[gp] window.
const GP_REACH: u32 = 0x8000;

/// Register state where nothing is known: r0 is zero, sp is the stack.
fn unknown() -> Regs {
    let mut regs = [Val::Unknown; 32];
    regs[0] = Val::Known(0);
    regs[SP] = Val::Stack;
    regs[GP] = Val::Gp(0);
    regs
}
/// Merge at a join: equal values survive, differing ones become unknown.
fn join(into: &mut Option<Regs>, from: &Regs) -> bool {
    let Some(into) = into else {
        *into = Some(*from);
        return true;
    };
    let mut changed = false;
    for (a, b) in into.iter_mut().zip(from) {
        if *a != *b && *a != Val::Unknown {
            *a = Val::Unknown;
            changed = true;
        }
    }
    changed
}
fn plus(a: Val, d: u32) -> Val {
    match a {
        Val::Known(v) => Val::Known(v.wrapping_add(d)),
        Val::Stack => Val::Stack,
        Val::Gp(v) => Val::Gp(v.wrapping_add(d)),
        Val::Unknown => Val::Unknown,
    }
}
fn known(a: Val, b: Val, f: impl Fn(u32, u32) -> u32) -> Val {
    match (a, b) {
        (Val::Known(a), Val::Known(b)) => Val::Known(f(a, b)),
        _ => Val::Unknown,
    }
}
fn sext16(v: u16) -> u32 {
    v as i16 as i32 as u32
}
fn word(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from(half(b, at)?) | u32::from(half(b, at + 2)?) << 16)
}

/// Control flow leaving one instruction.
enum Flow {
    /// Falls through only.
    Next,
    /// Conditional branch: falls through and may take the target.
    Branch(usize),
    /// Unconditional transfer to a target (inside or outside the walk).
    Jump(usize),
    /// `switch`: an inline table of entries follows the instruction.
    Switch,
    /// Leaves with no known successor (`jmp [reg]`, `jmp disp32[reg]`,
    /// `dispose ..., [reg]`).
    Exit,
}
/// `dispose imm5, list, [reg]`: returns (without [reg] it falls through).
fn returning_dispose(b: &[u8], at: usize) -> bool {
    half(b, at).is_some_and(|w| w & 0xffc0 == 0x0640)
        && half(b, at + 2).is_some_and(|sub| sub & 31 != 0)
}
/// A computed jump: `jmp [reg]` other than the `jmp [lp]` return, or
/// `jmp disp32[reg]`.
fn computed(w: u16) -> bool {
    (w & 0xffe0 == 0x0060 && w != 0x007f) || w & 0xffe0 == 0x06e0
}
fn flow(b: &[u8], at: usize) -> Flow {
    let Some(w) = half(b, at) else {
        return Flow::Exit;
    };
    let (op, reg1, reg2) = ((w >> 5) & 0x3f, w & 31, w >> 11);
    let sub = half(b, at + 2).unwrap_or(0);
    if returning_dispose(b, at) {
        return Flow::Exit;
    }
    match op {
        0x2c..=0x2f => match branch(b, at) {
            Some((BR, target)) => Flow::Jump(target),
            Some((_, target)) => Flow::Branch(target),
            None => Flow::Exit,
        },
        0x02 if reg2 == 0 && reg1 != 0 => Flow::Switch,
        0x03 if reg2 == 0 => Flow::Exit,
        0x37 if reg2 == 0 => Flow::Exit,
        // jr disp22
        0x3c | 0x3d if reg2 == 0 && sub & 1 == 0 => {
            let d = ((u32::from(w & 0x3f) << 16) | u32::from(sub)) as i32;
            at.checked_add_signed(((d << 10) >> 10) as isize)
                .map_or(Flow::Exit, Flow::Jump)
        }
        // jr disp32
        0x17 if reg2 == 0 && reg1 == 0 => word(b, at + 2)
            .and_then(|d| at.checked_add_signed(d as i32 as isize))
            .map_or(Flow::Exit, Flow::Jump),
        _ => Flow::Next,
    }
}
/// Targets of the inline table of a `switch` at `at`: halfword entries,
/// each a signed halfword offset from the table, ending where the lowest
/// forward target begins. `None` when no bound is found within [`CASES`].
fn table(b: &[u8], at: usize) -> Option<(Vec<usize>, usize)> {
    let base = at + 2;
    let (mut targets, mut lowest) = (Vec::new(), usize::MAX);
    for i in 0..CASES {
        let entry = base + 2 * i;
        if entry >= lowest {
            return Some((targets, entry));
        }
        let e = half(b, entry)? as i16;
        let target = base.checked_add_signed(isize::from(e) * 2)?;
        if target > entry {
            lowest = lowest.min(target);
        }
        targets.push(target);
    }
    (base + 2 * CASES >= lowest).then_some((targets, base + 2 * CASES))
}

/// Register effect of one instruction. Anything not modelled makes the
/// registers it may write unknown.
fn effect(b: &[u8], at: usize, len: usize, regs: &mut Regs) {
    let Some(w) = half(b, at) else { return };
    let (op, r1, r2) = ((w >> 5) & 0x3f, usize::from(w & 31), usize::from(w >> 11));
    let sub = if len >= 4 {
        half(b, at + 2).unwrap_or(0)
    } else {
        0
    };
    let r3 = usize::from(sub >> 11);
    let imm5 = (((w & 31) as i8) << 3 >> 3) as i32 as u32;
    let call = |regs: &mut Regs| {
        // Calling convention: r20-r29, sp and gp survive a call.
        for (r, v) in regs.iter_mut().enumerate() {
            if !matches!(r, 0 | SP | GP | 20..=29) {
                *v = Val::Unknown;
            }
        }
    };
    let clobber_all = |regs: &mut Regs| *regs = unknown();
    let set = |regs: &mut Regs, r: usize, v: Val| {
        if r != 0 {
            regs[r] = if r == SP { Val::Stack } else { v };
        }
    };
    if w & 0xffc0 == 0x0640 {
        // dispose: sp moves within the stack; listed r20-r31 are restored.
        for v in &mut regs[20..32] {
            *v = Val::Unknown;
        }
        return;
    }
    match op {
        // mov reg1, reg2
        0x00 if r2 != 0 => set(regs, r2, regs[r1]),
        0x00 if r1 == 0 => {}
        // add / sub / subr reg1, reg2
        0x0e => set(
            regs,
            r2,
            match (regs[r2], regs[r1]) {
                (Val::Stack, Val::Known(_)) | (Val::Known(_), Val::Stack) => Val::Stack,
                (Val::Gp(g), Val::Known(k)) | (Val::Known(k), Val::Gp(g)) => {
                    Val::Gp(g.wrapping_add(k))
                }
                (a, b) => known(a, b, u32::wrapping_add),
            },
        ),
        0x0d => set(
            regs,
            r2,
            match (regs[r2], regs[r1]) {
                (Val::Stack, Val::Known(_)) => Val::Stack,
                (Val::Gp(g), Val::Known(k)) => Val::Gp(g.wrapping_sub(k)),
                (a, b) => known(a, b, u32::wrapping_sub),
            },
        ),
        0x0c => set(regs, r2, known(regs[r1], regs[r2], u32::wrapping_sub)),
        0x08 => set(regs, r2, known(regs[r2], regs[r1], |a, b| a | b)),
        0x0a => set(regs, r2, known(regs[r2], regs[r1], |a, b| a & b)),
        // tst, cmp, cmp imm5, Format III branches: flags only.
        0x0b | 0x0f | 0x13 | 0x2c..=0x2f => {}
        // jmp [reg1], switch: no register written.
        0x02 | 0x03 if r2 == 0 => {}
        // callt
        // callt imm6: imm6 bit 5 is opcode bit 0, so callt 32..63 is 0x11.
        0x10 | 0x11 if r2 == 0 => call(regs),
        0x10 => set(regs, r2, Val::Known(imm5)),
        0x12 => set(regs, r2, plus(regs[r2], imm5)),
        0x14 => set(
            regs,
            r2,
            known(regs[r2], Val::Known(0), |a, _| a >> (w & 31)),
        ),
        0x16 => set(
            regs,
            r2,
            known(regs[r2], Val::Known(0), |a, _| a << (w & 31)),
        ),
        // jr / jarl disp32
        0x17 if r2 == 0 => {
            if r1 != 0 {
                call(regs);
                regs[r1] = Val::Unknown;
            }
        }
        // sst.b, sst.h, sst.w: memory only.
        0x1c..=0x1f | 0x24..=0x27 => {}
        0x28..=0x2b if w & 1 == 1 => {}
        // sld.b, sld.h, sld.w, sld.bu, sld.hu
        0x18..=0x1b | 0x20..=0x23 | 0x28..=0x2b | 0x03 => set(regs, r2, Val::Unknown),
        0x30 => set(regs, r2, plus(regs[r1], sext16(sub))),
        // mov imm32, reg1
        0x31 if r2 == 0 => set(regs, r1, word(b, at + 2).map_or(Val::Unknown, Val::Known)),
        0x31 => set(regs, r2, plus(regs[r1], sext16(sub))),
        0x32 if r2 != 0 => set(regs, r2, plus(regs[r1], u32::from(sub) << 16)),
        0x34 => set(
            regs,
            r2,
            known(regs[r1], Val::Known(sub.into()), |a, b| a | b),
        ),
        0x35 => set(
            regs,
            r2,
            known(regs[r1], Val::Known(sub.into()), |a, b| a ^ b),
        ),
        0x36 => set(
            regs,
            r2,
            known(regs[r1], Val::Known(sub.into()), |a, b| a & b),
        ),
        // ld.b, ld.h/ld.w
        0x38 | 0x39 => set(regs, r2, Val::Unknown),
        // st.b, st.h/st.w, bit operations: memory and flags only.
        0x3a | 0x3b | 0x3e => {}
        // ld.bu
        0x3c | 0x3d if r2 != 0 && sub & 1 == 1 => set(regs, r2, Val::Unknown),
        // jarl disp22
        0x3c | 0x3d if r2 != 0 => {
            call(regs);
            regs[r2] = Val::Unknown;
        }
        // jr disp22
        0x3c | 0x3d if r2 == 0 && sub & 1 == 0 => {}
        0x3c | 0x3d => match extended(b, at).flatten() {
            // prepare: sp moves within the stack; the ff form also sets ep.
            Some(Extended::Prepare(_)) if sub & 0x1f == 1 => {}
            Some(Extended::Prepare(_)) => {
                regs[EP] = match (sub >> 3) & 3 {
                    0 => Val::Stack,
                    1 => half(b, at + 4).map_or(Val::Unknown, |v| Val::Known(sext16(v))),
                    2 => half(b, at + 4).map_or(Val::Unknown, |v| Val::Known(u32::from(v) << 16)),
                    _ => word(b, at + 4).map_or(Val::Unknown, Val::Known),
                }
            }
            // disp23 loads write reg3; stores write nothing.
            Some(Extended::Disp23) if matches!(sub & 0xf, 0b1101) || sub & 0x1f == 0b01111 => {}
            Some(Extended::Disp23) => set(regs, r3, Val::Unknown),
            _ => clobber_all(regs),
        },
        // ld.hu
        0x3f if sub & 1 == 1 => set(regs, r2, Val::Unknown),
        0x3f => match sub & 0x07ff {
            // set1/not1/clr1/tst1 reg2, [reg1]; ldsr; di/ei, halt, trap, reti
            // di, ei exactly; E2V3 `jarl [reg1], reg3` shares their second
            // halfword and is an indirect call.
            0x0160 if sub == 0x0160 && matches!(w, 0x07e0 | 0x87e0) => {}
            0x0160 => {
                call(regs);
                set(regs, r3, Val::Unknown);
            }
            0x00e0 | 0x00e2 | 0x00e4 | 0x00e6 | 0x0020 | 0x0120 | 0x0100 | 0x0140 => {}
            // setf, stsr, shr/sar/shl, sasf, mul/mulu, divh(u), div(u), mul
            // imm9, cmov, bsw/bsh/hsw: reg2 and/or reg3.
            0x0000 | 0x0040 | 0x0080 | 0x00a0 | 0x00c0 | 0x0082 | 0x00a2 | 0x00c2 | 0x0200
            | 0x0220 | 0x0222 | 0x0280 | 0x0282 | 0x02c0 | 0x02c2 | 0x0340 | 0x0342 | 0x0344 => {
                set(regs, r2, Val::Unknown);
                set(regs, r3, Val::Unknown);
            }
            s if s & 0x07c3 == 0x0240 || s & 0x07c1 == 0x0300 => {
                set(regs, r2, Val::Unknown);
                set(regs, r3, Val::Unknown);
            }
            _ => clobber_all(regs),
        },
        // Every other Format I/II/VI instruction writes reg2 (reg1 when
        // reg2 is r0: zxb, sxb, zxh, sxh).
        0x00..=0x17 | 0x30..=0x37 => {
            if r2 != 0 {
                set(regs, r2, Val::Unknown)
            } else {
                set(regs, r1, Val::Unknown)
            }
        }
        _ => clobber_all(regs),
    }
}

/// Where one memory access goes, from the propagated base register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Base {
    /// The effective address is known.
    Address(u32),
    /// Stack-pointer or gp data-area relative: RAM by the calling convention.
    Ram,
    /// The base register's value is not known here.
    Unknown,
}
/// One memory access of a walked instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    /// Bit operation (kind: set1, not1, clr1, tst1) on a bit; `None` when
    /// the bit number is a register whose value is not known.
    Bit(Base, u8, Option<u8>),
    /// Byte, halfword or word load or store (or caxi).
    Transfer(Base),
}
/// Peripheral I/O region, as reached by negative `disp16[r0]`.
fn peripheral(address: u32) -> bool {
    address >= 0xffff_8000
}
fn base(regs: &Regs, reg: usize, disp: u32) -> Base {
    match regs[reg] {
        Val::Known(v) => Base::Address(v.wrapping_add(disp)),
        Val::Stack => Base::Ram,
        Val::Gp(v) => match v.wrapping_add(disp).wrapping_add(GP_REACH) {
            0..=0xffff => Base::Ram,
            _ => Base::Unknown,
        },
        Val::Unknown => Base::Unknown,
    }
}
/// The memory access of the instruction at `at`, if it has one, with its
/// base register.
fn access(b: &[u8], at: usize, len: usize, regs: &Regs) -> Option<(usize, Access)> {
    let w = half(b, at)?;
    let (op, r1, r2) = ((w >> 5) & 0x3f, usize::from(w & 31), usize::from(w >> 11));
    let sub = if len >= 4 { half(b, at + 2)? } else { 0 };
    let short = |disp: u16| Some((EP, Access::Transfer(base(regs, EP, disp.into()))));
    match op {
        0x03 if r2 != 0 && w & 0x10 == 0 => short(w & 0xf),
        0x03 if r2 != 0 => short((w & 0xf) << 1),
        0x18..=0x1f => short(w & 0x7f),
        0x20..=0x27 => short((w & 0x7f) << 1),
        0x28..=0x2b => short((w & 0x7e) << 1),
        // ld.b, st.b: disp16; ld.h/ld.w, st.h/st.w: bit 0 selects the width.
        0x38 | 0x3a => Some((r1, Access::Transfer(base(regs, r1, sext16(sub))))),
        0x39 | 0x3b => Some((r1, Access::Transfer(base(regs, r1, sext16(sub & !1))))),
        0x3c | 0x3d if r2 != 0 && sub & 1 == 1 => {
            // ld.bu: displacement bit 0 is bit 5 of the first halfword.
            let disp = (sub & !1) | ((w >> 5) & 1);
            Some((r1, Access::Transfer(base(regs, r1, sext16(disp)))))
        }
        0x3c | 0x3d if r2 == 0 && extended(b, at).flatten() == Some(Extended::Disp23) => {
            let high = u32::from(half(b, at + 4)?);
            let disp = (high << 7) | u32::from((sub >> 4) & 0x7f);
            let disp = ((disp << 9) as i32 >> 9) as u32;
            Some((r1, Access::Transfer(base(regs, r1, disp))))
        }
        0x3e => Some((
            r1,
            Access::Bit(
                base(regs, r1, sext16(sub)),
                (w >> 14) as u8,
                Some((w >> 11) as u8 & 7),
            ),
        )),
        0x3f if sub & 1 == 1 => Some((r1, Access::Transfer(base(regs, r1, sext16(sub & !1))))),
        0x3f if matches!(sub & 0x07ff, 0x00e0 | 0x00e2 | 0x00e4 | 0x00e6) => {
            let bit = match regs[r2] {
                Val::Known(v) => Some(v as u8 & 7),
                _ => None,
            };
            Some((
                r1,
                Access::Bit(base(regs, r1, 0), (sub >> 1) as u8 & 3, bit),
            ))
        }
        // caxi [reg1], reg2, reg3
        0x3f if sub & 0x07ff == 0x00ee => Some((r1, Access::Transfer(base(regs, r1, 0)))),
        _ => None,
    }
}

/// Direct bit I/O, RAM gates, direct call (`jarl disp22`/`jarl disp32`)
/// targets and indirect calls (`callt`, `jarl [reg]`) of one walked routine.
struct Walk {
    io: Vec<Io>,
    gates: Vec<(&'static str, u16, u8)>,
    calls: Vec<usize>,
    /// Offsets of indirect calls, whose callees are not known here.
    indirect: Vec<usize>,
    end: usize,
}

/// Instruction offsets from `start` to the closing returning `dispose ...,
/// [reg]` (or, for a called helper, also `jmp [lp]`; a `dispose` without
/// [reg] falls through and is walked), with inline `switch` tables skipped.
/// The closing return is the first one no walked branch or `switch` case
/// jumps past, so every path of a routine with early returns is walked; a
/// target before `start` or beyond [`PROGRAM`] leaves the walk and refuses.
fn decode(b: &[u8], name: &str, start: usize, helper: bool) -> Result<(Vec<usize>, usize), String> {
    let mut ats = Vec::new();
    let mut at = start;
    let mut furthest = start;
    let end = loop {
        let w = half(b, at).ok_or_else(|| format!("{name} code is truncated"))?;
        if (returning_dispose(b, at) || (helper && w == 0x007f)) && furthest <= at {
            break at;
        }
        // An early `jmp [lp]` return is walked past, never a dispatch.
        if helper
            && w != 0x007f
            && (w & 0xffe0 == 0x0040 || w & 0xffe0 == 0x0060 || w & 0xffe0 == 0x06e0)
        {
            return Err(format!(
                "{name} dispatches indirectly at Normal+{at:#x}; its reached pins are not fixed"
            ));
        }
        let len = length(b, at).ok_or_else(|| format!("{name} code is truncated"))?;
        if extended(b, at).flatten() == Some(Extended::Unknown) {
            return Err(format!(
                "{name} has an undecoded instruction at Normal+{at:#x}"
            ));
        }
        ats.push(at);
        let (targets, next) = match flow(b, at) {
            Flow::Switch => table(b, at)
                .ok_or_else(|| format!("{name} has an unbounded switch table at Normal+{at:#x}"))?,
            Flow::Branch(t) | Flow::Jump(t) => (alloc::vec![t], at + len),
            Flow::Next | Flow::Exit => (Vec::new(), at + len),
        };
        for t in targets {
            if t < start || t - start > PROGRAM {
                return Err(format!(
                    "{name} branches outside its walk to Normal+{t:#x} at Normal+{at:#x}"
                ));
            }
            furthest = furthest.max(t);
        }
        at = next;
        if at - start > PROGRAM {
            return Err(format!(
                "{name} has no closing dispose within {PROGRAM:#x} bytes"
            ));
        }
    };
    Ok((ats, end))
}

/// Positions of the walk that code outside it may enter: direct branches
/// (Format III, `jr`) anywhere in the scanned window ([`PROGRAM`] after
/// the walk and, before it, [`PROGRAM`] for a helper or [`SWITCH_REACH`]
/// for a state machine) and, for a state
/// machine (a case inside a larger routine), the bounded tables of `switch`
/// instructions within [`SWITCH_REACH`] before it; a computed jump in the
/// instruction stream before a state machine may enter every position.
/// For direct branches and `switch` tables every halfword is tried,
/// so this over-approximates; such a position merges the unknown state. A
/// helper starts at its routine's entry, so no other routine's `switch`
/// enters it.
fn outside(b: &[u8], start: usize, end: usize, ats: &[usize], helper: bool) -> Vec<usize> {
    let mut marks = Vec::new();
    let mut mark = |target: usize| {
        if let Ok(i) = ats.binary_search(&target) {
            marks.push(i);
        }
    };
    let reach = if helper { PROGRAM } else { SWITCH_REACH };
    let from = start.saturating_sub(reach) & !1;
    let to = (end + PROGRAM).min(b.len());
    for at in (from..to).step_by(2) {
        if (start..=end).contains(&at) {
            continue;
        }
        match flow(b, at) {
            Flow::Branch(t) | Flow::Jump(t) => mark(t),
            // A table is bounded by its lowest forward case and, being
            // data, cannot run into the walk.
            Flow::Switch if !helper => match table(b, at) {
                Some((targets, table_end)) if table_end <= start => {
                    targets.into_iter().for_each(&mut mark)
                }
                _ => {}
            },
            _ => {}
        }
    }
    // The enclosing routine's jump table may enter any case: a computed
    // jump in the instruction stream before a state machine marks every
    // position. Operand halfwords are skipped by following instruction
    // lengths (and inline `switch` tables) from the window start.
    if !helper {
        let mut at = from;
        while at < start {
            let Some(w) = half(b, at) else { break };
            if computed(w) {
                marks.extend(0..ats.len());
                break;
            }
            at = match flow(b, at) {
                Flow::Switch => table(b, at).map_or(at + 2, |t| t.1),
                _ => at + length(b, at).unwrap_or(2),
            };
        }
    }
    marks
}

/// Register state on entry to each walked instruction: constant
/// propagation over the walk's own control flow. The walk's first
/// instruction, every instruction with no edge inside the walk and every
/// position code outside the walk may enter start from [`unknown`], as does
/// every position of a state machine with a computed jump in or around it.
fn states(
    b: &[u8],
    name: &str,
    ats: &[usize],
    end: usize,
    helper: bool,
) -> Result<Vec<Regs>, String> {
    let n = ats.len();
    let mut succ: Vec<Vec<usize>> = Vec::with_capacity(n);
    let mut entered = alloc::vec![false; n];
    let start = ats.first().copied().unwrap_or(end);
    for (i, &at) in ats.iter().enumerate() {
        let targets = match flow(b, at) {
            Flow::Next => alloc::vec![],
            Flow::Branch(t) | Flow::Jump(t) => alloc::vec![t],
            Flow::Switch => table(b, at).map(|t| t.0).unwrap_or_default(),
            Flow::Exit => alloc::vec![],
        };
        let mut next = Vec::new();
        if matches!(flow(b, at), Flow::Next | Flow::Branch(_)) && i + 1 < n {
            next.push(i + 1);
        }
        for t in targets {
            // [`decode`] keeps every target within the walk or at its
            // closing return, which has no successor.
            if t == end {
                continue;
            }
            let j = ats
                .binary_search(&t)
                .map_err(|_| format!("{name} branches into an instruction at Normal+{t:#x}"))?;
            next.push(j);
        }
        for &j in &next {
            entered[j] = true;
        }
        succ.push(next);
    }
    // A computed jump (`jmp [reg]` other than the `jmp [lp]` return,
    // `jmp disp32[reg]`) may enter any position: every one starts unknown.
    let computed = ats.iter().any(|&at| half(b, at).is_some_and(computed));
    let mut state: Vec<Option<Regs>> = alloc::vec![None; n];
    let mut work = Vec::new();
    let seeds = (0..n)
        .filter(|&i| computed || i == 0 || !entered[i])
        .chain(outside(b, start, end, ats, helper));
    for i in seeds {
        if join(&mut state[i], &unknown()) {
            work.push(i);
        }
    }
    loop {
        while let Some(i) = work.pop() {
            let Some(mut regs) = state[i] else { continue };
            effect(b, ats[i], length(b, ats[i]).unwrap_or(2), &mut regs);
            for &j in &succ[i] {
                if join(&mut state[j], &regs) {
                    work.push(j);
                }
            }
        }
        // Positions reached only from unreached cycles start unknown.
        match state.iter().position(Option::is_none) {
            Some(i) => {
                state[i] = Some(unknown());
                work.push(i);
            }
            None => break,
        }
    }
    Ok(state
        .into_iter()
        .map(|s| s.unwrap_or_else(unknown))
        .collect())
}

/// Walk instruction by instruction from `start` to the closing `dispose`
/// (or, for a called helper, also `jmp [lp]`), including every path past
/// an early return. A helper has no switch table and no indirect jump.
fn walk(b: &[u8], name: &str, start: usize, helper: bool) -> Result<Walk, String> {
    let (mut io, mut gates, mut calls, mut indirect) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let (ats, end) = decode(b, name, start, helper)?;
    let states = states(b, name, &ats, end, helper)?;
    for (&at, regs) in ats.iter().zip(&states) {
        let w = half(b, at).ok_or_else(|| format!("{name} code is truncated"))?;
        let len = length(b, at).ok_or_else(|| format!("{name} code is truncated"))?;
        let disp = half(b, at + 2).unwrap_or(0);
        let reg1 = w & 31;
        let access = access(b, at, len, regs);
        // disp23 sign is bit 15 of the third halfword.
        if extended(b, at).flatten() == Some(Extended::Disp23)
            && reg1 == 0
            && half(b, at + 4).is_some_and(|h| h >= 0x8000)
        {
            return Err(format!(
                "{name} transfers peripheral data at Normal+{at:#x}; not a fixed bit I/O set"
            ));
        }
        let (reg, base) = match access {
            Some((reg, Access::Bit(base, ..) | Access::Transfer(base))) => (reg, base),
            None => (0, Base::Ram),
        };
        match (base, access) {
            (Base::Unknown, _) => {
                return Err(format!(
                    "{name} accesses memory through r{reg} of unknown value at Normal+{at:#x}; whether it is peripheral I/O is not known"
                ))
            }
            (Base::Address(address), Some((_, Access::Bit(_, kind, bit)))) if peripheral(address) => {
                let Some(bit) = bit else {
                    return Err(format!(
                        "{name} operates on {address:#010x} with a register bit number of unknown value at Normal+{at:#x}"
                    ));
                };
                let pin = Pin { address, bit };
                match kind {
                    3 => io.push(Io::Input(pin)),
                    0 => io.push(Io::Output(pin, true)),
                    2 => io.push(Io::Output(pin, false)),
                    _ => {
                        return Err(format!("{name} toggles {:#010x}.b{} at Normal+{at:#x}; a toggle has no fixed driven level", pin.address, pin.bit))
                    }
                }
            }
            (Base::Address(address), Some((_, Access::Transfer(_)))) if peripheral(address) => {
                // A byte/halfword/word peripheral transfer is not a bit set.
                return Err(format!(
                    "{name} transfers peripheral data at Normal+{at:#x}; not a fixed bit I/O set"
                ));
            }
            // Only the Normal image itself is known not to be I/O: an
            // external bus device or an alias of the I/O region may not be.
            (Base::Address(address), Some(_))
                if !peripheral(address)
                    && !(BASE..BASE + b.len()).contains(&(address as usize)) =>
            {
                return Err(format!(
                    "{name} accesses {address:#010x} at Normal+{at:#x}, neither peripheral I/O nor the Normal image"
                ));
            }
            (_, Some((_, Access::Bit(_, kind, Some(bit))))) if reg1 == 4 && w & 0x07e0 == 0x07c0 => {
                gates.push((["set1", "not1", "clr1", "tst1"][usize::from(kind)], disp, bit))
            }
            _ => {}
        }
        let (op, reg2) = ((w >> 5) & 0x3f, w >> 11);
        if len == 4 && reg2 != 0 && matches!(op, 0x3c | 0x3d) && disp & 1 == 0 {
            // jarl disp22, reg2
            let d = ((u32::from(w & 0x3f) << 16) | u32::from(disp)) as i32;
            let d = (d << 10) >> 10;
            if let Some(target) = at.checked_add_signed(d as isize) {
                calls.push(target);
            }
        } else if op == 0x17 && reg2 == 0 && reg1 != 0 {
            // jarl disp32, reg1
            if let Some(target) =
                word(b, at + 2).and_then(|d| at.checked_add_signed(d as i32 as isize))
            {
                calls.push(target);
            }
        } else if (matches!(op, 0x10 | 0x11) && reg2 == 0)
            || (op == 0x3f
                && disp & 0x07ff == 0x0160
                && !(disp == 0x0160 && matches!(w, 0x07e0 | 0x87e0)))
        {
            // callt imm6, jarl [reg1], reg3
            indirect.push(at);
        }
    }
    Ok(Walk {
        io,
        gates,
        calls,
        indirect,
        end,
    })
}
fn complete(io: &[Io]) -> bool {
    io.iter().any(|x| matches!(x, Io::Input(_))) && io.iter().any(|x| matches!(x, Io::Output(..)))
}
fn io_text(io: &[Io]) -> String {
    io.iter()
        .map(|x| match x {
            Io::Input(p) => format!("{:#010x}.b{}", p.address, p.bit),
            Io::Output(p, l) => format!("{:#010x}.b{}<-{}", p.address, p.bit, u8::from(*l)),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn program(b: &[u8], label: &[u8], start: Option<usize>) -> Result<Program, String> {
    let name = core::str::from_utf8(&label[..label.len() - 3]).unwrap_or("?");
    let start =
        start.ok_or_else(|| format!("{name} has no unique diagnostic and unique reference"))?;
    // From the diagnostic case to the state machine's single closing dispose.
    let program = walk(b, &format!("{name} state machine"), start, false)?;
    let Walk {
        mut io,
        mut gates,
        mut calls,
        indirect,
        end,
    } = program;
    io.sort();
    io.dedup();
    let mut unbound = Vec::new();
    let followed = !complete(&io);
    if followed {
        // Follow exactly one level into each directly called helper and take
        // only the fixed outputs it drives itself. A helper that fails closed
        // contributes nothing; its own further calls are not followed. Both
        // are named as unbound paths.
        let direct = io_text(&io);
        calls.sort();
        calls.dedup();
        unbound.extend(indirect.iter().map(|at| {
            format!("{name} state machine calls indirectly at Normal+{at:#x}, not followed")
        }));
        let mut reached = Vec::new();
        for &target in &calls {
            match walk(b, &format!("helper Normal+{target:#x}"), target, true) {
                Err(e) => unbound.push(e),
                Ok(helper) => {
                    let outputs: Vec<Io> = helper
                        .io
                        .into_iter()
                        .filter(|x| matches!(x, Io::Output(..)))
                        .collect();
                    if !helper.calls.is_empty() {
                        let mut deeper = helper.calls;
                        deeper.sort();
                        deeper.dedup();
                        let deeper: Vec<String> =
                            deeper.iter().map(|t| format!("Normal+{t:#x}")).collect();
                        unbound.push(format!(
                            "helper Normal+{target:#x} calls {} further, not followed",
                            deeper.join(", ")
                        ));
                    }
                    unbound.extend(helper.indirect.iter().map(|at| {
                        format!("helper Normal+{target:#x} calls indirectly at Normal+{at:#x}, not followed")
                    }));
                    reached.extend(outputs);
                }
            }
        }
        if reached.is_empty() {
            return Err(format!(
                "{name} state machine Normal+{start:#x}..{end:#x} directly accesses only [{direct}] and none of its {} directly called helpers drives a fixed output at one level{}",
                calls.len(),
                if unbound.is_empty() { String::new() } else { format!("; unbound: {}", unbound.join("; ")) }
            ));
        }
        io.extend(reached);
        io.sort();
        io.dedup();
        if !complete(&io) {
            return Err(format!(
                "{name} state machine Normal+{start:#x}..{end:#x} and one helper level access only [{}]; no complete bound input and output set",
                io_text(&io)
            ));
        }
    }
    gates.sort();
    gates.dedup();
    Ok(Program {
        io,
        start,
        end,
        gates,
        followed,
        unbound,
    })
}

/// Slim-mechanism I/O for both roles of a native-order Normal.
fn slim_at(normal: &[u8], starts: [Option<usize>; 2]) -> Result<Slim, String> {
    Ok(Slim {
        closed: program(normal, CLOSED, starts[0])?,
        opened: program(normal, OPENED, starts[1])?,
    })
}
#[cfg(test)]
fn slim(normal: &[u8]) -> Result<Slim, String> {
    slim_at(normal, anchors(normal).starts)
}

/// V850 observations of a stored bus-order Normal, as held in the context.
pub(super) struct Bus {
    pub arrival: Observation<Predicates>,
    /// Both loading diagnostics exist, so a miss is a recognizer gap.
    pub diagnostics: bool,
    /// Only examined when the diagnostics exist and no arrival pair binds.
    pub slim: Option<Result<Slim, String>>,
}
pub(super) fn bus(normal: &[u8]) -> Bus {
    let Some(native_order) = crate::image::layout::decode_v850_bus(normal) else {
        return Bus {
            arrival: Observation::Unresolved(Unresolved::ReaderNotRecognized),
            diagnostics: false,
            slim: None,
        };
    };
    let anchors = anchors(&native_order);
    let arrival = predicates(&native_order, anchors.starts);
    let diagnostics = anchors.labels.iter().all(Option::is_some);
    let slim = (diagnostics
        && matches!(
            arrival,
            Observation::Unresolved(Unresolved::ReaderNotRecognized)
        ))
    .then(|| slim_at(&native_order, anchors.starts));
    Bus {
        arrival,
        diagnostics,
        slim,
    }
}

#[cfg(test)]
#[path = "v850_k06.rs"]
mod k06;

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// DVR-109 1.40 `[LOADIN]` state machine: diagnostic reference at +0x00,
    /// arrival `tst1 6, -3053[r0]` at +0x14a, confirmation state 15 at +0x1a8
    /// (native bytes from Normal 0xb3328.., call/branch operands unchanged).
    const DVR109_LOADIN: &[(usize, &[u8])] = &[
        (0x000, &[0x27, 0x06, 0, 0, 0, 0]),
        (
            0x14a,
            &[
                0xc0, 0xf7, 0x13, 0xf4, // tst1 6, -3053[r0]
                0xd2, 0x25, // be +0x4a
                0x24, 0x77, 0x42, 0x27, // ld.h 10050[gp], r14
                0xe0, 0x71, // cmp r0, r14
                0xb2, 0x05, // be +6
                0x80, 0x07, 0x02, 0x01, // jr exit
            ],
        ),
        (
            0x198,
            &[
                0x24, 0x7f, 0x88, 0x1b, // ld.h 7048[gp], r15
                0x44, 0x7f, 0x40, 0x27, // st.b r15, 10048[gp]
                0x0f, 0x6a, // mov 15, r13
                0x44, 0x6f, 0x3d, 0x27, // st.b r13, 10045[gp]
                0xa5, 0x5d, // br exit
                0x04, 0x57, 0x40, 0x27, // ld.b 10048[gp], r10
                0xe0, 0x51, // cmp r0, r10
                0xea, 0x55, // bne exit
                0xc0, 0xf7, 0x13, 0xf4, // tst1 6, -3053[r0]
                0xe2, 0x05, // be +0xc
                0x0e, 0x82, // mov 14, r16
                0x44, 0x87, 0x3d, 0x27, // st.b r16, 10045[gp]
                0xf5, 0x4d, // br exit
                0x00, 0x00,
            ],
        ),
    ];
    /// DVR-110 1.37 `[LOADOUT]`: arrival `tst1 1, -3054[r0]` at +0x150,
    /// ARRIVED block (with its motor-flag clear) and confirmation state 11.
    const DVR110_LOADOUT: &[(usize, &[u8])] = &[
        (0x000, &[0x27, 0x06, 0, 0, 0, 0]),
        (
            0x150,
            &[
                0xc0, 0xcf, 0x12, 0xf4, // tst1 1, -3054[r0]
                0xa2, 0x25, // be +0x44
                0x24, 0x87, 0x90, 0x22, // ld.h 8848[gp], r16
                0xe0, 0x81, // cmp r0, r16
                0xb2, 0x05, // be +6
            ],
        ),
        (
            0x198,
            &[
                0xc4, 0xbf, 0x90, 0x54, // clr1 7, 21648[gp]
                0x84, 0x67, 0xcd, 0x13, // ld.bu 5068[gp], r12
                0x64, 0x67, 0x8e, 0x22, // st.h r12, 8846[gp]
                0x0b, 0x6a, // mov 11, r13
                0x44, 0x6f, 0x89, 0x22, // st.b r13, 8841[gp]
                0x95, 0x65, // br exit
                0x24, 0x7f, 0x8e, 0x22, // ld.h 8846[gp], r15
                0xe0, 0x79, // cmp r0, r15
                0xda, 0x5d, // bne exit
                0xc0, 0xcf, 0x12, 0xf4, // tst1 1, -3054[r0]
                0xe2, 0x05, // be +0xc
                0x0a, 0x52, // mov 10, r10
                0x44, 0x57, 0x89, 0x22, // st.b r10, 8841[gp]
                0xe5, 0x55, // br exit
                0x00, 0x00,
            ],
        ),
    ];

    fn place(raw: &mut [u8], at: usize, text: usize, parts: &[(usize, &[u8])]) {
        for &(offset, bytes) in parts {
            raw[at + offset..at + offset + bytes.len()].copy_from_slice(bytes);
        }
        raw[at + 2..at + 6].copy_from_slice(&((text + BASE) as u32).to_le_bytes());
    }
    /// Native-order image: closed from DVR-109, open from DVR-110.
    pub(crate) fn fixture() -> Vec<u8> {
        let mut raw = alloc::vec![0xff; 0x4000];
        raw[0x100..0x100 + CLOSED.len()].copy_from_slice(CLOSED);
        raw[0x120..0x120 + OPENED.len()].copy_from_slice(OPENED);
        place(&mut raw, 0x1000, 0x100, DVR109_LOADIN);
        place(&mut raw, 0x2000, 0x120, DVR110_LOADOUT);
        raw
    }

    #[test]
    fn diagnostic_state_machines_bind_both_roles_and_levels() {
        let Observation::Known(p) = native(&fixture()) else {
            panic!();
        };
        assert_eq!(
            p.closed.pin,
            Pin {
                address: 0xffff_f413,
                bit: 6
            }
        );
        assert_eq!(
            p.opened.pin,
            Pin {
                address: 0xffff_f412,
                bit: 1
            }
        );
        assert_eq!((p.closed.arrival, p.closed.confirmation), (0x114a, 0x11a8));
        assert_eq!((p.opened.arrival, p.opened.confirmation), (0x2150, 0x21ac));
        let stored = crate::image::layout::encode_v850_bus(&fixture()).unwrap();
        let observed = bus(&stored);
        assert!(observed.diagnostics && observed.slim.is_none());
        assert!(matches!(observed.arrival, Observation::Known(q) if q == p));
    }

    #[test]
    fn every_bound_instruction_field_is_required() {
        let raw = fixture();
        // Arrival pin/bit/branch, ARRIVED state store, confirmation timer
        // compare, reread pin/bit, keep-branch, fallback state and branch.
        for at in [
            0x114a, 0x114b, 0x114c, 0x114e, 0x11a0, 0x11a2, 0x11ac, 0x11ae, 0x11b0, 0x11b1, 0x11b2,
            0x11b4, 0x11b6, 0x11b8, 0x11bc, 0x21ae, 0x21b0, 0x2002,
        ] {
            let mut bad = raw.clone();
            bad[at] ^= 1;
            assert!(!matches!(native(&bad), Observation::Known(_)), "{at:x}");
        }
        // The confirmation must reread the arrival pin.
        let mut bad = raw.clone();
        bad[0x11b2] = 0x12;
        assert!(!matches!(native(&bad), Observation::Known(_)));
        // A missing role never yields a partial value.
        let mut bad = raw.clone();
        bad[0x120] = b'x';
        assert!(!diagnostics(&bad));
        assert!(matches!(native(&bad), Observation::Unresolved(_)));
    }

    #[test]
    fn duplicated_diagnostic_or_reference_is_not_selected_by_order() {
        let mut raw = fixture();
        raw[0x3000..0x3000 + CLOSED.len()].copy_from_slice(CLOSED);
        assert!(!matches!(native(&raw), Observation::Known(_)));
        let mut raw = fixture();
        let reference = raw[0x1000..0x1006].to_vec();
        raw[0x3000..0x3006].copy_from_slice(&reference);
        assert!(!matches!(native(&raw), Observation::Known(_)));
    }
    /// DVR-K15 1.11 `[LOADIN]` program: Normal+0xb3f68..=0xb4003, native bytes
    /// from the diagnostic reference through the closing `dispose`.
    const K15_LOADIN: &str = concat!(
        "2706a1cc0200b7fffee7036244673b25c0af06f4026a247643276e6f0000047f3d27417a447f3d27245643272a870000",
        "e081ba350332b8ffda48c02f06f480ffc611bdffae2f2066e803247643276e670000046f3d27416a446f3d27e51d0000",
        "24864327307f0000e079fa15c0ef13f4820d043282ff28d6045244573b25d50d013282ff1ad62076880044773f27a437",
        "3f27003882ff1cd640063f00",
    );
    /// DVR-K15 1.11 `[LOADOUT]` program: Normal+0xb403c..=0xb4225, native bytes
    /// from the diagnostic reference through the closing `dispose`.
    const K15_LOADOUT: &str = concat!(
        "27064ccc0200b7ff2ae701724477fc1f027a447f3b2582ff5aef440779540132203efe00bdffa82e2487e81de0819a0d",
        "2036f100203e10000048004082ffb0ee04673d27416244673d2780079c010000246f7129616aba0580078e012036e400",
        "204ef0000040003882ff84ee04573d27415244573d27800770010000247771296172ba05800762010030b8ffaa4c047f",
        "3d27417a447f3d2780074e01c0ff13f4e205058244873d2780073e01036264674027046f3d27416a446f3d2780072a01",
        "24574027e051b20580071e01c0ff13f4820d04773d27417244773d2780070a0140360008270658cc0200b7ff46e6c08f",
        "06f4c4af7c2c013282ffd0d4046244673e27a575207ec80024864327707f000004673d27416244673d27247643272e6f",
        "0000e0699a65c40f4808c00f06f4205664002486432770570000047f3d27417a447f3d2795550000c0ff13f4e20d2476",
        "43272e670000e061fa45c08f06f4096a446f3d279545000003826487402704573d27415244573d27f5350000247f4027",
        "e079aa35c0ff13f4b2b5077244773d27b52d0000a45f7954415a8b00625af715445f795440360010270669cc0200b7ff",
        "82e5043282ff14d42086880044873f27a4373f27003882ff16d4e50d40360010270686cc0200445f79540b40b7ff94e4",
        "057a447f3d2740063f00",
    );
    /// DVR-K16 1.42 `[LOADIN]` program: Normal+0xec958..=0xec9e3, native bytes
    /// from the diagnostic reference through the closing `dispose`.
    const K16_LOADIN: &str = concat!(
        "270691a10300b5ff3a91036244671323c08f12f4026a646f282204772122417244772122247f2822e079fa2d0332b6ff",
        "e219c00f12f480ff1a15bcff1a0c2086e8036487282204672122416244672122c51d0000246f2822e069fa15c0ef13f4",
        "820d043283ffb854047244771323d50d013283ffaa54207e8800447f2322a4372322003883ffac5440063f00",
    );
    /// DVR-K16 1.42 `[LOADOUT]` program: Normal+0xeca1c..=0xecc51, native bytes
    /// from the diagnostic reference through the closing `dispose`.
    const K16_LOADOUT: &str = concat!(
        "27061ca10300b5ff7690017244770019027a447f132383ff166e4407874d0132203efe00bcff1c0b24871416e0819a0d",
        "2036f100203e10000048004083ffa86d046721224162446721228007e8010000246f6122616aba058007da012036e400",
        "204ef0000040003883ff7c6d045721224152445721228007bc010000247761226172ba058007ae010030b6ffb21d047f",
        "2122417a447f212280079a01c4f7884de20dc0f700f4ba0d036264672622046f2122416a446f212280077a0105524457",
        "212280077001000024772622e071b20580076201c0f700f4820d047f2122417a447f212280074e0140360008270628a1",
        "0300b5ff8a8fc0b712f4c4b7894dc437884d4036001027064aa10300b5ffe08e013283ff465304824487222280071601",
        "2086c8006487282204672122416244672122246f2822e069b2058007f800c40f4008c03712f42076640064772822047f",
        "2122417a447f2122d56d0000c4f7884dea0d24872822e081da65036264672622046f2122416a446f2122c55dc0f700f4",
        "c20d24772822e071da55c0b712f4097a447f2122f54d000040360010270639a10300b5ffda8e03826487262204672122",
        "416244672122e53d246f2622e069aa3dc0f700f4929dc4f7884dfa05c0b712f4097a447f2122e52d075244572122a52d",
        "a45f874d415a8b00625af715445f874d40360010270659a10300b5ff828e043283ff5852206e8800446f2322a4372322",
        "003883ff5a52e50d40360010270676a10300445f874d0b40b5ffc48d05724477212240063f00",
    );

    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
    /// Native-order slim image: both programs placed with their diagnostics.
    pub(crate) fn slim_fixture(closed: &str, opened: &str) -> Vec<u8> {
        let mut raw = alloc::vec![0xff; 0x4000];
        raw[0x100..0x100 + CLOSED.len()].copy_from_slice(CLOSED);
        raw[0x120..0x120 + OPENED.len()].copy_from_slice(OPENED);
        for (at, text, program) in [(0x1000, 0x100, closed), (0x2000, 0x120, opened)] {
            let program = bytes(program);
            raw[at..at + program.len()].copy_from_slice(&program);
            raw[at + 2..at + 6].copy_from_slice(&((text + BASE) as u32).to_le_bytes());
        }
        raw
    }
    pub(crate) fn k15() -> Vec<u8> {
        slim_fixture(K15_LOADIN, K15_LOADOUT)
    }
    pub(crate) fn k16() -> Vec<u8> {
        slim_fixture(K16_LOADIN, K16_LOADOUT)
    }
    fn pin(address: u32, bit: u8) -> Pin {
        Pin { address, bit }
    }

    #[test]
    fn slim_programs_bind_their_exact_direct_io_sets() {
        use Io::{Input, Output};
        let raw = k15();
        assert!(matches!(
            native(&raw),
            Observation::Unresolved(Unresolved::ReaderNotRecognized)
        ));
        let k15 = slim(&raw).unwrap();
        assert_eq!(
            k15.closed.io,
            [
                Input(pin(0xffff_f413, 5)),
                Output(pin(0xffff_f406, 5), false),
                Output(pin(0xffff_f406, 5), true)
            ]
        );
        assert_eq!(
            k15.opened.io,
            [
                Input(pin(0xffff_f413, 7)),
                Output(pin(0xffff_f406, 1), false),
                Output(pin(0xffff_f406, 1), true)
            ]
        );
        assert_eq!((k15.closed.start, k15.closed.end), (0x1000, 0x1098));
        assert_eq!(k15.opened.gates, [("clr1", 11388, 5), ("set1", 2120, 1)]);
        let k16 = slim(&k16()).unwrap();
        assert_eq!(
            k16.closed.io,
            [
                Input(pin(0xffff_f413, 5)),
                Output(pin(0xffff_f412, 1), false),
                Output(pin(0xffff_f412, 1), true)
            ]
        );
        assert_eq!(
            k16.opened.io,
            [
                Input(pin(0xffff_f400, 6)),
                Output(pin(0xffff_f412, 6), false),
                Output(pin(0xffff_f412, 6), true)
            ]
        );
        assert!(k16.opened.gates.contains(&("tst1", 19848, 6)));
        assert_ne!(k15.opened.io, k16.opened.io);
        // From stored bus order, examined only because no arrival pair binds.
        let observed = bus(&crate::image::layout::encode_v850_bus(&raw).unwrap());
        assert!(matches!(observed.slim, Some(Ok(s)) if s == k15));
    }

    #[test]
    fn slim_io_requires_anchors_closed_programs_and_fixed_levels() {
        let raw = k15();
        // clr1 5, -3066[r0] at +0x10: another pin changes the set.
        let mut other = raw.clone();
        other[0x1012] = 0x07;
        assert_ne!(
            slim(&other).unwrap().closed.io,
            slim(&raw).unwrap().closed.io
        );
        // The same access as not1 has no fixed driven level.
        let mut toggle = raw.clone();
        toggle[0x1011] = (toggle[0x1011] & 0x3f) | 0x40;
        assert!(slim(&toggle).unwrap_err().contains("toggles"));
        // Without its closing dispose the program is not bounded.
        let mut open = raw.clone();
        open[0x1098] = 0;
        assert!(slim(&open).is_err());
        // Duplicate diagnostic or duplicate reference is not selected by order.
        let mut twice = raw.clone();
        twice[0x3000..0x3000 + CLOSED.len()].copy_from_slice(CLOSED);
        assert!(slim(&twice).is_err());
        let mut twice = raw.clone();
        let reference = twice[0x2000..0x2006].to_vec();
        twice[0x3000..0x3006].copy_from_slice(&reference);
        assert!(slim(&twice).is_err());
        // Inputs only: the actuator is unbound, so no value.
        let reads = slim_fixture(K15_LOADIN, "2706000000000000c0ff13f440063f00");
        assert!(slim(&reads).unwrap_err().contains("drives a fixed output"));
    }

    /// `[LOADOUT]` reading 0xFFFFF413.b7 and calling one helper at +0x400.
    pub(crate) fn with_helper(helper: &[u8]) -> Vec<u8> {
        // ref; tst1 7, -3053[r0]; jarl +0x3f6, lp; dispose 0, {lp}, lp
        let mut raw = slim_fixture(K15_LOADIN, "270600000000c0ff13f480fff60340063f00");
        raw[0x2400..0x2400 + helper.len()].copy_from_slice(helper);
        raw
    }
    #[test]
    fn one_helper_level_adds_only_fixed_outputs_of_closed_helpers() {
        use Io::{Input, Output};
        // set1 6, -3054[r0]; jmp [lp]
        let raw = with_helper(&[0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00]);
        let opened = slim(&raw).unwrap().opened;
        assert_eq!(
            opened.io,
            [
                Input(pin(0xffff_f413, 7)),
                Output(pin(0xffff_f412, 6), true)
            ]
        );
        assert!(opened.unbound.is_empty());
        // Its own output still counts; the further call is named, not followed.
        let deeper = with_helper(&[0xc0, 0x37, 0x12, 0xf4, 0x80, 0xff, 0x10, 0x00, 0x7f, 0x00]);
        let opened = slim(&deeper).unwrap().opened;
        assert_eq!(opened.io.len(), 2);
        assert!(opened.unbound[0].contains("not followed"));
        // A helper failing closed (switch, byte-wide store) adds no pins.
        for bad in [
            &[0x4a, 0x00, 0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00][..],
            &[0x40, 0x5f, 0x12, 0xf4, 0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00],
        ] {
            let error = slim(&with_helper(bad)).unwrap_err();
            assert!(
                error.contains("none of its 1 directly called helpers"),
                "{error}"
            );
        }
        // Helper inputs are not taken: a tst1-only helper binds no output.
        assert!(slim(&with_helper(&[0xc0, 0x37 | 0xc0, 0x12, 0xf4, 0x7f, 0x00])).is_err());
    }

    #[test]
    fn a_followed_helper_that_only_calls_further_is_named_unbound() {
        // [LOADOUT]: tst1 7, -3053[r0]; jarl A (+0x400); jarl B (+0x500).
        // A drives set1 6, -3054[r0]; B drives nothing itself and calls C.
        let mut raw = slim_fixture(K15_LOADIN, "270600000000c0ff13f480fff60380fff20440063f00");
        raw[0x2400..0x2406].copy_from_slice(&[0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00]);
        raw[0x2500..0x2506].copy_from_slice(&[0x80, 0xff, 0x00, 0x01, 0x7f, 0x00]);
        raw[0x2600..0x2606].copy_from_slice(&[0xc0, 0x0f, 0x12, 0xf4, 0x7f, 0x00]);
        let opened = slim(&raw).unwrap().opened;
        assert_eq!(opened.io.len(), 2);
        assert_eq!(
            opened.unbound,
            ["helper Normal+0x2500 calls Normal+0x2600 further, not followed"]
        );
    }

    #[test]
    fn unsigned_byte_peripheral_reads_fail_closed() {
        // ld.bu -3053[r0], r10 (format VII 11110b, disp bit 0 in the first
        // halfword, second halfword bit 0 set) in the state machine itself.
        let direct = slim_fixture(K15_LOADIN, "270600000000a05713f4c0ff13f4c03712f440063f00");
        let error = slim(&direct).unwrap_err();
        assert!(error.contains("transfers peripheral data"), "{error}");
        // The same read in the one followed helper level adds no pins.
        let helper = with_helper(&[0xa0, 0x57, 0x13, 0xf4, 0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00]);
        let error = slim(&helper).unwrap_err();
        assert!(
            error.contains("none of its 1 directly called helpers"),
            "{error}"
        );
        // ld.bu disp16[gp] is a RAM read, not peripheral I/O.
        let ram = with_helper(&[0xa4, 0x57, 0x13, 0x74, 0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00]);
        assert_eq!(slim(&ram).unwrap().opened.io.len(), 2);
    }

    #[test]
    fn extended_prepare_operands_are_not_walked_as_instructions() {
        use Io::{Input, Output};
        // prepare {}, 0, imm32 whose operand bytes encode `set1 6, -3054[r0]`,
        // then the helper's real `set1 1, -3054[r0]; jmp [lp]`.
        let raw = with_helper(&[
            0x80, 0x07, 0x1b, 0x00, 0xc0, 0x37, 0x12, 0xf4, 0xc0, 0x0f, 0x12, 0xf4, 0x7f, 0x00,
        ]);
        assert_eq!(
            slim(&raw).unwrap().opened.io,
            [
                Input(pin(0xffff_f413, 7)),
                Output(pin(0xffff_f412, 1), true)
            ]
        );
        // prepare {}, 0, imm16 whose operand is `jmp [lp]` does not end the helper.
        let raw = with_helper(&[
            0x80, 0x07, 0x0b, 0x00, 0x7f, 0x00, 0xc0, 0x0f, 0x12, 0xf4, 0x7f, 0x00,
        ]);
        assert_eq!(slim(&raw).unwrap().opened.io.len(), 2);
    }

    #[test]
    fn v850e2_disp23_transfers_are_walked_whole_and_r0_ones_fail_closed() {
        // set1 6, -3054[r0]; ld.b -3053[r0], r10 (format XIV, disp23); nop;
        // nop; jmp [lp].
        let raw = with_helper(&[
            0xc0, 0x37, 0x12, 0xf4, 0x80, 0x07, 0x35, 0x51, 0xe8, 0xff, 0, 0, 0, 0, 0x7f, 0x00,
        ]);
        let error = slim(&raw).unwrap_err();
        assert!(
            error.contains("none of its 1 directly called helpers"),
            "{error}"
        );
        // ld.b disp23[gp], r10 whose high displacement halfword reads as
        // `jmp [lp]` is one 6-byte instruction, not the end of the helper.
        let raw = with_helper(&[
            0x84, 0x07, 0x35, 0x51, 0x7f, 0x00, 0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00,
        ]);
        assert_eq!(slim(&raw).unwrap().opened.io.len(), 2);
    }

    #[test]
    fn register_format_instructions_under_opcode_3f_are_not_transfers() {
        // bsw r10, r20 (reg1 field 0, second halfword 0xa340, bit 0 clear).
        let raw = with_helper(&[0xe0, 0x57, 0x40, 0xa3, 0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00]);
        assert_eq!(slim(&raw).unwrap().opened.io.len(), 2);
        // ld.hu -3054[r0], r10 (bit 0 set) is still a peripheral transfer.
        let raw = with_helper(&[0xe0, 0x57, 0x13, 0xf4, 0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00]);
        assert!(slim(&raw).is_err());
    }

    /// `[LOADOUT]`: reference; `tst1 7, -3053[r0]`; `body`; closing dispose.
    fn opened_with(body: &str) -> Result<Slim, String> {
        slim(&slim_fixture(
            K15_LOADIN,
            &format!("270600000000c0ff13f4{body}40063f00"),
        ))
    }
    // movea -3054, r0, r14 (r14 = 0xFFFFF412)
    const R14_F412: &str = "207612f4";
    // movea 0x100, gp, r14 (a gp data-area pointer)
    const R14_GP: &str = "24760001";

    #[test]
    fn base_register_peripheral_bit_io_is_bound_like_absolute_io() {
        use Io::{Input, Output};
        // set1 6, 0[r14] with r14 = 0xFFFFF412
        let opened = opened_with(&format!("{R14_F412}ce370000")).unwrap().opened;
        assert_eq!(
            opened.io,
            [
                Input(pin(0xffff_f413, 7)),
                Output(pin(0xffff_f412, 6), true)
            ]
        );
        assert!(!opened.followed);
        // Another vendor build driving bit 1 through the same base differs.
        let other = opened_with(&format!("{R14_F412}ce0f0000")).unwrap().opened;
        assert_ne!(other.io, opened.io);
        // movhi 0xffff, r0, r14; clr1 6, -3054[r14] reaches 0xFFFEF412:
        // neither the peripheral region nor the Normal image.
        let low = opened_with("4076ffffce b712f4c03712f4".replace(' ', "").as_str());
        assert!(low
            .unwrap_err()
            .contains("neither peripheral I/O nor the Normal"));
        // not1 through the base has no fixed level.
        let toggle = opened_with(&format!("{R14_F412}ce770000")).unwrap_err();
        assert!(toggle.contains("toggles"), "{toggle}");
        // ld.b 0[r14], r10: a peripheral data transfer.
        let read = opened_with(&format!("{R14_F412}c03712f40e570000")).unwrap_err();
        assert!(read.contains("transfers peripheral data"), "{read}");
    }

    #[test]
    fn unknown_base_registers_refuse_and_known_ram_is_ignored() {
        // set1 6, -3054[r0] makes the direct set complete.
        let set = "c03712f4";
        // ld.b 0[r14], r10 with r14 never set in the walk.
        let error = opened_with(&format!("{set}0e570000")).unwrap_err();
        assert!(error.contains("unknown value"), "{error}");
        // sld.b 0[ep], r10 with ep never set.
        let error = opened_with(&format!("{set}0053")).unwrap_err();
        assert!(error.contains("unknown value"), "{error}");
        // mov 0x03FFF412, r14; ld.b 0[r14]: a mirror of the peripheral region.
        let error = opened_with(&format!("{set}2e0612f4ff030e570000")).unwrap_err();
        assert!(error.contains("neither peripheral I/O"), "{error}");
        // gp data area, the stack and ROM are not I/O.
        for body in [
            format!("{R14_GP}4e570000"),          // st.b r10, 0[r14]
            "63570500".into(),                    // st.w r10, 4[sp]
            "40760100 0e570000".replace(' ', ""), // movhi 1, r0, r14; ld.b 0[r14]
        ] {
            let opened = opened_with(&format!("{set}{body}")).unwrap().opened;
            assert_eq!(opened.io.len(), 2, "{body}");
        }
        // Paths joining with a peripheral and a RAM base: unknown.
        // movea -3054, r0, r14; bne +6; movea 0x100, gp, r14; ld.b 0[r14], r10
        let error = opened_with(&format!("{set}{R14_F412}ba05{R14_GP}0e570000")).unwrap_err();
        assert!(error.contains("unknown value"), "{error}");
        // A call clobbers r14 but preserves r20.
        // movea -3054, r0, rN; jarl +0x3f0, lp; set1 6, 0[rN]
        let call = |reg: u16| {
            let movea = (reg << 11) | 0x0620;
            let set1 = (6 << 11) | 0x07c0 | reg;
            format!(
                "{:02x}{:02x}12f480fff003{:02x}{:02x}0000",
                movea & 0xff,
                movea >> 8,
                set1 & 0xff,
                set1 >> 8
            )
        };
        assert!(opened_with(&call(14))
            .unwrap_err()
            .contains("unknown value"));
        assert_eq!(opened_with(&call(20)).unwrap().opened.io.len(), 2);
        // In a followed helper an unknown base fails the helper closed.
        let helper = with_helper(&[0x0e, 0x57, 0, 0, 0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00]);
        let error = slim(&helper).unwrap_err();
        assert!(
            error.contains("none of its 1 directly called helpers")
                && error.contains("unknown value"),
            "{error}"
        );
    }

    #[test]
    fn calls_clobber_and_unbound_addresses_refuse() {
        let set = "c03712f4";
        for body in [
            // movea 0x100, gp, r10; callt 40; set1 6, 0[r10]
            "24560001 2802 ca370000",
            // movea 0x100, gp, r12; jarl [r11], r10; set1 6, 0[r12]
            "24660001 ebc76051 cc370000",
            // movhi 0x10, r0, r14; ld.b 0[r14], r10: neither Normal nor I/O
            "40761000 0e570000",
            // movea 0x7fff, gp, r14; st.b r10, 0x10[r14]: beyond disp16[gp]
            "2476ff7f 4e571000",
        ] {
            let body = body.replace(' ', "");
            assert!(opened_with(&format!("{set}{body}")).is_err(), "{body}");
        }
        // di and ei keep every register.
        let body = format!("{set}{R14_GP}e0076001e0876001 4e570000").replace(' ', "");
        assert_eq!(opened_with(&body).unwrap().opened.io.len(), 2);
    }

    #[test]
    fn edges_from_outside_the_walk_enter_with_nothing_known() {
        // set1 6, -3054[r0]; movea 0x100, gp, r14; st.b r10, 0[r14] at +0x12.
        let program = format!("270600000000c0ff13f4c03712f4{R14_GP}4e57000040063f00");
        let raw = slim_fixture(K15_LOADIN, &program);
        assert_eq!(slim(&raw).unwrap().opened.io.len(), 2);
        // br +0x22 from 0x1ff0 enters at the store with r14 unknown.
        let mut branched = raw.clone();
        branched[0x1ff0..0x1ff2].copy_from_slice(&[0x95, 0x15]);
        let error = slim(&branched).unwrap_err();
        assert!(error.contains("unknown value"), "{error}");
        // switch r10 at 0x1f00 whose bounded table [0x2012, 0x1f06] ends
        // before the walk: its case 0 enters at the store.
        let mut switched = raw.clone();
        switched[0x1f00..0x1f06].copy_from_slice(&[0x4a, 0x00, 0x88, 0x00, 0x02, 0x00]);
        let error = slim(&switched).unwrap_err();
        assert!(error.contains("unknown value"), "{error}");
    }

    #[test]
    fn far_branches_from_the_scanned_window_enter_with_nothing_known() {
        let program = format!("270600000000c0ff13f4c03712f4{R14_GP}4e57000040063f00");
        let mut far = slim_fixture(K15_LOADIN, &program);
        // jr +0x1812 from 0x800 (0x1800 before the walk) enters at the store.
        far[0x800..0x804].copy_from_slice(&[0x80, 0x07, 0x12, 0x18]);
        let error = slim(&far).unwrap_err();
        assert!(error.contains("unknown value"), "{error}");
    }

    #[test]
    fn branches_past_a_return_are_walked_and_branches_out_refuse() {
        use Io::{Input, Output};
        // Helper: bne L; set1 6, -3054[r0]; jmp [lp]; L: clr1 7, -3054[r0];
        // jmp [lp]. Both returns' paths are walked.
        let raw = with_helper(&[
            0xca, 0x05, 0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00, 0xc0, 0xbf, 0x12, 0xf4, 0x7f, 0x00,
        ]);
        assert_eq!(
            slim(&raw).unwrap().opened.io,
            [
                Input(pin(0xffff_f413, 7)),
                Output(pin(0xffff_f412, 6), true),
                Output(pin(0xffff_f412, 7), false)
            ]
        );
        // State machine: bne L; set1 6, -3054[r0]; dispose; L: clr1 7,
        // -3054[r0]; dispose.
        let opened = opened_with("da05c03712f440063f00c0bf12f4").unwrap().opened;
        assert!(opened.io.contains(&Output(pin(0xffff_f412, 7), false)));
        assert_eq!(opened.end, 0x2018);
        // A branch before the walk's start leaves the walk: refused.
        let error = opened_with("c03712f485f5").unwrap_err();
        assert!(error.contains("branches outside"), "{error}");
    }

    #[test]
    fn computed_jumps_in_a_state_machine_enter_every_position_unknown() {
        // set1 6, -3054[r0]; movea 0x100, gp, r14; st.b r10, 0[r14];
        // jmp [r11]: the table may enter the store with r14 unknown.
        let error = opened_with(&format!("c03712f4{R14_GP}4e5700006b00")).unwrap_err();
        assert!(error.contains("unknown value"), "{error}");
        assert!(opened_with(&format!("c03712f4{R14_GP}4e570000")).is_ok());
    }

    #[test]
    fn a_computed_jump_before_a_state_machine_enters_every_position_unknown() {
        let program = format!("270600000000c0ff13f4c03712f4{R14_GP}4e57000040063f00");
        let raw = slim_fixture(K15_LOADIN, &program);
        assert!(slim(&raw).is_ok());
        // jmp [r11] at 0x1f00: the enclosing routine's jump table may
        // enter the store with r14 unknown.
        let mut table = raw.clone();
        table[0x1f00..0x1f02].copy_from_slice(&[0x6b, 0x00]);
        let error = slim(&table).unwrap_err();
        assert!(error.contains("unknown value"), "{error}");
        // A `jmp [lp]` return there is not a dispatch.
        let mut ret = raw.clone();
        ret[0x1f00..0x1f02].copy_from_slice(&[0x7f, 0x00]);
        assert!(slim(&ret).is_ok());
    }

    #[test]
    fn only_returning_disposes_close_a_walk() {
        use Io::Output;
        // dispose 0, {lp} without [reg] does not return: the set1 after it
        // is walked up to the returning dispose.
        let opened = opened_with("40062000c03712f4").unwrap().opened;
        assert!(opened.io.contains(&Output(pin(0xffff_f412, 6), true)));
        // movea -3054, r0, r20; bne L; dispose 0, {lp}, [lp]; L: set1 6,
        // 0[r20]. The returning dispose (which restores r20-r31) has no
        // fallthrough edge, so L keeps r20 from the branch alone.
        let opened = opened_with("20a612f4ba0540063f00d4370000").unwrap().opened;
        assert!(opened.io.contains(&Output(pin(0xffff_f412, 6), true)));
    }

    #[test]
    fn every_direct_call_form_is_followed_and_indirect_calls_are_named() {
        use Io::{Input, Output};
        // [LOADOUT]: tst1 7, -3053[r0]; jarl disp32 +0x3f6, lp; dispose.
        let mut raw = slim_fixture(K15_LOADIN, "270600000000c0ff13f4ff02f603000040063f00");
        raw[0x2400..0x2406].copy_from_slice(&[0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00]);
        assert_eq!(
            slim(&raw).unwrap().opened.io,
            [
                Input(pin(0xffff_f413, 7)),
                Output(pin(0xffff_f412, 6), true)
            ]
        );
        // tst1; jarl disp22 +0x3f6, lp; callt 40; dispose: the callt is named.
        let mut raw = slim_fixture(
            K15_LOADIN,
            "270600000000c0ff13f480fff6032802 40063f00"
                .replace(' ', "")
                .as_str(),
        );
        raw[0x2400..0x2406].copy_from_slice(&[0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00]);
        let opened = slim(&raw).unwrap().opened;
        assert_eq!(opened.io.len(), 2);
        assert!(
            opened
                .unbound
                .iter()
                .any(|u| u.contains("indirectly at Normal+0x200e")),
            "{:?}",
            opened.unbound
        );
        // jarl disp22 with r10 as the link register is a direct call too.
        let mut raw = slim_fixture(K15_LOADIN, "270600000000c0ff13f48057f60340063f00");
        raw[0x2400..0x2406].copy_from_slice(&[0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00]);
        assert_eq!(slim(&raw).unwrap().opened.io.len(), 2);
        // jarl [r11], lp and callt 5 in the state machine, and callt 40 in
        // the followed helper, are each named.
        let mut raw = slim_fixture(
            K15_LOADIN,
            "270600000000c0ff13f480fff603ebc760f9050240063f00",
        );
        raw[0x2400..0x2408].copy_from_slice(&[0x28, 0x02, 0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00]);
        let opened = slim(&raw).unwrap().opened;
        assert_eq!(opened.io.len(), 2);
        for at in ["0x200e", "0x2012"] {
            let text = format!("state machine calls indirectly at Normal+{at}, not followed");
            assert!(
                opened.unbound.iter().any(|u| u.contains(&text)),
                "{:?}",
                opened.unbound
            );
        }
        assert!(opened
            .unbound
            .iter()
            .any(|u| u == "helper Normal+0x2400 calls indirectly at Normal+0x2400, not followed"));
        // A forward jr beyond the walk bound refuses.
        let error = opened_with("c03712f480070011").unwrap_err();
        assert!(error.contains("branches outside"), "{error}");
    }

    #[test]
    fn disp23_lengths_effects_and_undecoded_forms_are_exact() {
        // A sub-opcode under 0x0780 this walker cannot decode fails closed.
        let error = slim(&with_helper(&[
            0x84, 0x07, 0x11, 0x00, 0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00,
        ]))
        .unwrap_err();
        assert!(error.contains("undecoded instruction"), "{error}");
        // st.w r10, disp23[gp] whose high halfword reads as `jmp [lp]` is
        // one 6-byte instruction.
        let raw = with_helper(&[
            0x84, 0x07, 0x0f, 0x50, 0x7f, 0x00, 0xc0, 0x37, 0x12, 0xf4, 0x7f, 0x00,
        ]);
        assert_eq!(slim(&raw).unwrap().opened.io.len(), 2);
        // movea -3054, r0, r10; st.w / ld.w r10, 0[gp] (disp23); set1 6,
        // 0[r10]: the store keeps r10, the load makes it unknown.
        let through = |sub: u8| {
            with_helper(&[
                0x20, 0x56, 0x12, 0xf4, 0x84, 0x07, sub, 0x50, 0, 0, 0xca, 0x37, 0, 0, 0x7f, 0x00,
            ])
        };
        assert_eq!(slim(&through(0x0f)).unwrap().opened.io.len(), 2);
        let error = slim(&through(0x09)).unwrap_err();
        assert!(error.contains("unknown value"), "{error}");
    }

    fn k06(ranges: &[(usize, &str)]) -> Vec<u8> {
        let mut raw = alloc::vec![0xff; 0x198000];
        for &(at, hex) in ranges {
            let data = bytes(hex);
            raw[at..at + data.len()].copy_from_slice(&data);
        }
        raw
    }
    #[test]
    fn k06_revisions_bind_equal_direct_and_one_level_io() {
        use Io::{Input, Output};
        let a = slim(&k06(k06::K06_100)).unwrap();
        let b = slim(&k06(k06::K06_105)).unwrap();
        let motor = [
            Output(pin(0xffff_f412, 6), false),
            Output(pin(0xffff_f412, 6), true),
            Output(pin(0xffff_f412, 7), false),
            Output(pin(0xffff_f412, 7), true),
        ];
        let mut closed = alloc::vec![
            Input(pin(0xffff_f400, 6)),
            Input(pin(0xffff_f412, 4)),
            Input(pin(0xffff_f413, 5)),
        ];
        closed.extend(motor);
        let mut opened = alloc::vec![
            Input(pin(0xffff_f400, 6)),
            Input(pin(0xffff_f412, 2)),
            Input(pin(0xffff_f412, 4)),
            Input(pin(0xffff_f413, 5)),
        ];
        opened.extend(motor);
        assert_eq!(a.closed.io, closed);
        assert_eq!(a.opened.io, opened);
        assert_eq!((&b.closed.io, &b.opened.io), (&a.closed.io, &a.opened.io));
        // The mode dispatch's F400.b2 store and the motor-voltage call are
        // named as unbound, never added to the value.
        for program in [&a.closed, &a.opened] {
            assert!(!program
                .io
                .iter()
                .any(|x| matches!(x, Output(p, _) if p.address == 0xffff_f400)));
            let unbound = program.unbound.join("; ");
            assert!(
                unbound.contains("helper Normal+0x4df20 dispatches indirectly"),
                "{unbound}"
            );
            assert!(
                unbound.contains("helper Normal+0xed300 calls Normal+0x458c0, Normal+0xae16c"),
                "{unbound}"
            );
        }
    }
}

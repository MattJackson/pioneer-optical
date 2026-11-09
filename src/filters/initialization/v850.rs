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
    /// Sign-extended `disp16[r0]` peripheral address.
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

/// The unique `mov imm32, r7` loading the unique diagnostic for its print.
fn reference(b: &[u8], label: &[u8]) -> Option<usize> {
    let address = u32::try_from(unique(b, label)? + BASE).ok()?;
    let mut reference = [0x27, 0x06, 0, 0, 0, 0];
    reference[2..].copy_from_slice(&address.to_le_bytes());
    unique(b, &reference).filter(|at| at & 1 == 0)
}

fn role(b: &[u8], label: &[u8]) -> Observation<Role> {
    let Some(start) = reference(b, label) else {
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
pub(super) fn native(normal: &[u8]) -> Observation<Predicates> {
    match (role(normal, CLOSED), role(normal, OPENED)) {
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

/// Whether both loading diagnostics exist, so a miss is a recognizer gap.
pub(super) fn diagnostics(normal: &[u8]) -> bool {
    unique(normal, CLOSED).is_some() && unique(normal, OPENED).is_some()
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
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Slim {
    pub closed: Program,
    pub opened: Program,
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
        // prepare list, imm5 [, imm16 | imm32]; jr disp22 has an even disp.
        0x3c | 0x3d if reg2 == 0 && half(b, at + 2)? & 7 == 1 => {
            [4, 6, 6, 8][usize::from((half(b, at + 2)? >> 3) & 3)]
        }
        _ => 4,
    })
}
/// Longest referenced state machine walked before giving up.
const PROGRAM: usize = 0x1000;

fn program(b: &[u8], label: &[u8]) -> Result<Program, String> {
    let name = core::str::from_utf8(&label[..label.len() - 3]).unwrap_or("?");
    let start = reference(b, label)
        .ok_or_else(|| format!("{name} has no unique diagnostic and unique reference"))?;
    let (mut io, mut gates) = (Vec::new(), Vec::new());
    let mut at = start;
    // Walk instruction by instruction from the diagnostic case to the state
    // machine's single closing dispose; called helpers are not followed.
    let end = loop {
        let w = half(b, at).ok_or_else(|| format!("{name} program is truncated"))?;
        if w & 0xffc0 == 0x0640 {
            break at;
        }
        let len = length(b, at).ok_or_else(|| format!("{name} program is truncated"))?;
        let disp = half(b, at + 2).unwrap_or(0);
        let reg1 = w & 31;
        if len == 4 && w & 0x07e0 == 0x07c0 {
            let pin = Pin {
                address: 0xffff_0000 | u32::from(disp),
                bit: (w >> 11) as u8 & 7,
            };
            match (reg1, disp >= 0x8000, w >> 14) {
                (0, true, 3) => io.push(Io::Input(pin)),
                (0, true, 0) => io.push(Io::Output(pin, true)),
                (0, true, 2) => io.push(Io::Output(pin, false)),
                (0, true, _) => {
                    return Err(format!("{name} toggles {:#010x}.b{} at Normal+{at:#x}; a toggle has no fixed driven level", pin.address, pin.bit))
                }
                (4, _, kind) => gates.push((["set1", "not1", "clr1", "tst1"][usize::from(kind)], disp, pin.bit)),
                _ => {}
            }
        } else if len == 4
            && reg1 == 0
            && disp >= 0x8000
            && matches!((w >> 5) & 0x3f, 0x38..=0x3b | 0x3f)
        {
            // A byte/halfword/word peripheral transfer is not a bit set.
            return Err(format!(
                "{name} transfers peripheral data at Normal+{at:#x}; not a fixed bit I/O set"
            ));
        }
        at += len;
        if at - start > PROGRAM {
            return Err(format!(
                "{name} state machine has no closing dispose within {PROGRAM:#x} bytes"
            ));
        }
    };
    io.sort();
    io.dedup();
    gates.sort();
    gates.dedup();
    if !io.iter().any(|x| matches!(x, Io::Input(_)))
        || !io.iter().any(|x| matches!(x, Io::Output(..)))
    {
        let read: Vec<String> = io
            .iter()
            .map(|x| match x {
                Io::Input(p) => format!("{:#010x}.b{}", p.address, p.bit),
                Io::Output(p, l) => format!("{:#010x}.b{}<-{}", p.address, p.bit, u8::from(*l)),
            })
            .collect();
        return Err(format!(
            "{name} state machine Normal+{start:#x}..{end:#x} directly accesses only [{}]; its actuator (solenoid/motor) is driven only through called helpers, so the program has no complete bound input and output set",
            read.join(", ")
        ));
    }
    Ok(Program {
        io,
        start,
        end,
        gates,
    })
}

/// Slim-mechanism I/O for both roles of a native-order Normal.
pub(super) fn slim(normal: &[u8]) -> Result<Slim, String> {
    Ok(Slim {
        closed: program(normal, CLOSED)?,
        opened: program(normal, OPENED)?,
    })
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
    let arrival = native(&native_order);
    let diagnostics = diagnostics(&native_order);
    let slim = (diagnostics
        && matches!(
            arrival,
            Observation::Unresolved(Unresolved::ReaderNotRecognized)
        ))
    .then(|| slim(&native_order));
    Bus {
        arrival,
        diagnostics,
        slim,
    }
}

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
        assert!(slim(&reads).unwrap_err().contains("actuator"));
    }
}

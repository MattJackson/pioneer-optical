//! V850 tray loading-arrival predicates, bound by the native `[LOADIN]` and
//! `[LOADOUT]` motor state machines in the bus-decoded Normal.
//!
//! Each role is the pin the state machine waits on after its diagnostic: an
//! arrival test `tst1 b, disp16[r0]; be ARRIVED`, where ARRIVED loads the
//! settle timer and enters state N, immediately followed by state N's
//! confirmation reread of the same pin (`be` keeps the arrival, otherwise the
//! state falls back to N-1). The waited-for level is therefore bit == 0.
//! Code offsets, RAM slots and state numbers are evidence, never values.
use crate::image::layout::{Observation, Unresolved};

/// CPU address of Normal offset zero.
const BASE: usize = 0x10000;
/// Bytes after the diagnostic reference searched for the confirmation state.
const WINDOW: usize = 0x200;
const CLOSED: &[u8] = b"[LOADIN]\n\r\0";
const OPENED: &[u8] = b"[LOADOUT]\n\r\0";

/// One physical pin a role waits on. The required level is bit == 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    let mut found = b.windows(needle.len()).enumerate().filter(|(_, w)| *w == needle);
    let (at, _) = found.next()?;
    found.next().is_none().then_some(at)
}

fn role(b: &[u8], label: &[u8]) -> Observation<Role> {
    let Some(text) = unique(b, label) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    let Some(address) = u32::try_from(text + BASE).ok() else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    // mov imm32, r7 loading the diagnostic for the print call.
    let mut reference = [0x27, 0x06, 0, 0, 0, 0];
    reference[2..].copy_from_slice(&address.to_le_bytes());
    let Some(start) = unique(b, &reference).filter(|at| at & 1 == 0) else {
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
            Some((BE, target)) if test(b, arrival) == Some(pin) && (c - 22..=c - 8).contains(&target) => {}
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

/// Stored bus-order Normal, as held in the firmware context.
pub(super) fn bus(normal: &[u8]) -> (Observation<Predicates>, bool) {
    match crate::image::layout::decode_v850_bus(normal) {
        Some(native_order) => (native(&native_order), diagnostics(&native_order)),
        None => (Observation::Unresolved(Unresolved::ReaderNotRecognized), false),
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// DVR-109 1.40 `[LOADIN]` state machine: diagnostic reference at +0x00,
    /// arrival `tst1 6, -3053[r0]` at +0x14a, confirmation state 15 at +0x1a8
    /// (native bytes from Normal 0xb3328.., call/branch operands unchanged).
    const DVR109_LOADIN: &[(usize, &[u8])] = &[
        (0x000, &[0x27, 0x06, 0, 0, 0, 0]),
        (0x14a, &[
            0xc0, 0xf7, 0x13, 0xf4, // tst1 6, -3053[r0]
            0xd2, 0x25, // be +0x4a
            0x24, 0x77, 0x42, 0x27, // ld.h 10050[gp], r14
            0xe0, 0x71, // cmp r0, r14
            0xb2, 0x05, // be +6
            0x80, 0x07, 0x02, 0x01, // jr exit
        ]),
        (0x198, &[
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
        ]),
    ];
    /// DVR-110 1.37 `[LOADOUT]`: arrival `tst1 1, -3054[r0]` at +0x150,
    /// ARRIVED block (with its motor-flag clear) and confirmation state 11.
    const DVR110_LOADOUT: &[(usize, &[u8])] = &[
        (0x000, &[0x27, 0x06, 0, 0, 0, 0]),
        (0x150, &[
            0xc0, 0xcf, 0x12, 0xf4, // tst1 1, -3054[r0]
            0xa2, 0x25, // be +0x44
            0x24, 0x87, 0x90, 0x22, // ld.h 8848[gp], r16
            0xe0, 0x81, // cmp r0, r16
            0xb2, 0x05, // be +6
        ]),
        (0x198, &[
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
        ]),
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
        assert_eq!(p.closed.pin, Pin { address: 0xffff_f413, bit: 6 });
        assert_eq!(p.opened.pin, Pin { address: 0xffff_f412, bit: 1 });
        assert_eq!((p.closed.arrival, p.closed.confirmation), (0x114a, 0x11a8));
        assert_eq!((p.opened.arrival, p.opened.confirmation), (0x2150, 0x21ac));
        let stored = crate::image::layout::encode_v850_bus(&fixture()).unwrap();
        assert!(matches!(bus(&stored), (Observation::Known(q), true) if q == p));
    }

    #[test]
    fn every_bound_instruction_field_is_required() {
        let raw = fixture();
        // Arrival pin/bit/branch, ARRIVED state store, confirmation timer
        // compare, reread pin/bit, keep-branch, fallback state and branch.
        for at in [
            0x114a, 0x114b, 0x114c, 0x114e, 0x11a0, 0x11a2, 0x11ac, 0x11ae, 0x11b0, 0x11b1,
            0x11b2, 0x11b4, 0x11b6, 0x11b8, 0x11bc, 0x21ae, 0x21b0, 0x2002,
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
}

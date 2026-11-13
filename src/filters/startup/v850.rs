//! Native eight-byte Kernel/Normal acceptance requirement, rooted in Normal entry.
//! This is an operational requirement, not a hardware platform identity. The
//! Kernel transfer is proved as an address; its implementation is outside scope.
use super::Span;
use crate::shape::matches;
use crate::image::layout::{Observation, Unresolved};
use shapes::*;

const BASE: usize = 0x10000;
const KERNEL_OFFSET: usize = 0x1008;
/// Kernel address the bound rejection path transfers to.
const REJECT_TRANSFER: usize = 0x900;

/// Coordinates and verification status must be excluded from semantic values.
#[derive(Clone, Debug)]
pub(super) struct Evidence {
    pub expected: [u8; 8],
    pub kernel_offset: usize,
    pub entry: Span,
    pub body: Span,
    pub comparison: Span,
    pub literal: Span,
    pub reject: Span,
    pub reject_transfer: u32,
    /// None retains the obligation to verify the exact associated Kernel. A
    /// supplied foreign Kernel may establish false; it never changes expected.
    pub paired_kernel_matches: Option<bool>,
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn span(at: usize, bytes: usize) -> Option<Span> {
    Some(Span {
        offset: at,
        bytes,
        address: u32::try_from(BASE.checked_add(at)?).ok()?,
    })
}
/// Decode a native JR/JARL displacement, preserving both opcode and link register.
fn transfer(b: &[u8], at: usize, opcode: u16) -> Option<usize> {
    let word = le16(b, at)?;
    if word & 0xffc0 != opcode {
        return None;
    }
    let raw = (u32::from(word & 63) << 16) | u32::from(le16(b, at + 2)?);
    let displacement = if raw & (1 << 21) != 0 {
        i64::from(raw) - (1 << 22)
    } else {
        i64::from(raw)
    };
    let address = i64::try_from(BASE.checked_add(at)?)
        .ok()?
        .checked_add(displacement)?;
    let address = usize::try_from(address).ok()?;
    (address & 1 == 0).then_some(address)
}
fn normal_target(b: &[u8], at: usize, opcode: u16) -> Option<usize> {
    let offset = transfer(b, at, opcode)?.checked_sub(BASE)?;
    (offset < b.len()).then_some(offset)
}

fn entry(b: &[u8], new: bool) -> Option<(Span, usize)> {
    let (at, shape) = if new {
        (0x138, ENTRY_NEW)
    } else {
        (0x134, ENTRY_OLD)
    };
    // Two zeroing loops, the native initializer call, and a direct jump to main.
    if !matches(
        b,
        at,
        shape,
        &[
            (2, 4),
            (8, 4),
            (28, 4),
            (34, 4),
            (54, 4),
            (60, 4),
            (shape.len() - 4, 4),
        ],
    ) {
        return None;
    }
    for (lo, hi) in [(2, 8), (28, 34)] {
        let lo = le32(b, at + lo)?;
        let hi = le32(b, at + hi)?;
        if lo >= hi
            || lo & 3 != 0
            || !((0x200000..0x210000).contains(&lo) && hi <= 0x210000
                || (0x03ff0000..0x04000000).contains(&lo) && hi <= 0x04000000)
        {
            return None;
        }
    }
    let table = usize::try_from(le32(b, at + 54)?).ok()?.checked_sub(BASE)?;
    if b.get(table..table.checked_add(8)?)? != [0x52, 0x4d, 0x50, 0, 1, 0, 0, 0] {
        return None;
    }
    let initializer = normal_target(b, at + 60, 0xff80)?;
    // The startup initializer must be an actual native function, not an arbitrary
    // in-range target. This is its argument-preserving entry, not its closure.
    if table != initializer.checked_add(180)?
        || b.get(initializer..initializer.checked_add(10)?)?
            != [0x58, 0x1a, 0x63, 0xe7, 1, 0, 0x63, 0xdf, 5, 0]
    {
        return None;
    }
    let main = normal_target(b, at + shape.len() - 4, 0x0780)?;
    Some((span(at, shape.len())?, main))
}

fn reject(b: &[u8], at: usize, new: bool) -> Option<Span> {
    let (shape, reads) = if new {
        (REJECT_NEW, [6, 50, 70])
    } else {
        (REJECT_OLD, [10, 42, 62])
    };
    let call = shape.len() - 8;
    if !matches(
        b,
        at,
        shape,
        &[(reads[0], 2), (reads[1], 2), (reads[2], 2), (call, 4)],
    ) || transfer(b, at + call, 0xff80)? != REJECT_TRANSFER
    {
        return None;
    }
    // The three status bytes remain adjacent even when their GP coordinates move.
    if reads
        .iter()
        .any(|&read| le16(b, at + read).map_or(true, |word| word & 1 == 0))
    {
        return None;
    }
    let first = le16(b, at + reads[0])? & !1;
    let second = (le16(b, at + reads[1])? & !1) | 1;
    let third = le16(b, at + reads[2])? & !1;
    if second.checked_add(1)? != first || third.checked_add(1)? != second {
        return None;
    }
    span(at, shape.len())
}

fn native(normal: &[u8], kernel: Option<&[u8]>) -> Observation<Evidence> {
    let mut found = None;
    for new in [false, true] {
        let Some((entry, body)) = entry(normal, new) else {
            continue;
        };
        let prologue: &[u8] = if new {
            &[0x86, 7, 0xe1, 0]
        } else {
            &[0x80, 7, 0xe1, 0]
        };
        if normal.get(body..body + 4) != Some(prologue) {
            continue;
        }
        let Some(at) = body.checked_add(4) else {
            continue;
        };
        if !matches(normal, at, COMPARISON, &[(2, 4), (24, 4)]) {
            continue;
        }
        let Some(literal) = le32(normal, at + 2).and_then(|p| (p as usize).checked_sub(BASE))
        else {
            continue;
        };
        let Some(expected) = literal
            .checked_add(8)
            .and_then(|end| normal.get(literal..end))
            .and_then(|v| <[u8; 8]>::try_from(v).ok())
        else {
            continue;
        };
        let Some(reject_at) = normal_target(normal, at + 24, 0xff80) else {
            continue;
        };
        let Some(reject) = reject(normal, reject_at, new) else {
            continue;
        };
        let Some(comparison) = span(at, COMPARISON.len()) else {
            continue;
        };
        let Some(body) = span(body, 4 + COMPARISON.len()) else {
            continue;
        };
        let Some(literal) = span(literal, 8) else {
            continue;
        };
        let evidence = Evidence {
            expected,
            kernel_offset: KERNEL_OFFSET,
            entry,
            body,
            comparison,
            literal,
            reject,
            reject_transfer: REJECT_TRANSFER as u32,
            paired_kernel_matches: kernel
                .and_then(|k| k.get(KERNEL_OFFSET..KERNEL_OFFSET + 8))
                .map(|v| v == expected),
        };
        if found.is_some() {
            return Observation::Unresolved(Unresolved::AmbiguousReader);
        }
        found = Some(evidence);
    }
    found
        .map(Observation::Known)
        .unwrap_or(Observation::Unresolved(Unresolved::ReaderNotRecognized))
}

/// Decode the stored bus representation and bind the rooted native requirement.
/// Missing or malformed Kernel does not erase a requirement proved by Normal;
/// it leaves paired verification pending. Detector misses never prove absence.
pub(super) fn discover(normal_bus: &[u8], kernel_bus: Option<&[u8]>) -> Observation<Evidence> {
    let Some(normal) = crate::image::layout::decode_v850_bus(normal_bus) else {
        return Observation::Unresolved(Unresolved::TruncatedEvidence);
    };
    let kernel = kernel_bus.and_then(crate::image::layout::decode_v850_bus);
    native(&normal, kernel.as_deref())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    fn put32(b: &mut [u8], at: usize, value: u32) {
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn branch(b: &mut [u8], at: usize, address: usize, opcode: u16) {
        let displacement = (address as i64 - (BASE + at) as i64) as u32 & 0x3fffff;
        b[at..at + 2].copy_from_slice(&(opcode | ((displacement >> 16) as u16)).to_le_bytes());
        b[at + 2..at + 4].copy_from_slice(&(displacement as u16).to_le_bytes());
    }
    pub(crate) fn fixture(new: bool) -> (Vec<u8>, Vec<u8>) {
        let mut b = vec![0xff; 8192];
        let mut k = vec![0xff; 8192];
        let (at, shape) = if new {
            (0x138, ENTRY_NEW)
        } else {
            (0x134, ENTRY_OLD)
        };
        b[at..at + shape.len()].copy_from_slice(shape);
        for (offset, value) in [
            (2, 0x03ff9000),
            (8, 0x03ffd000),
            (28, 0x204d00),
            (34, 0x207000),
            (54, (BASE + 0x10b4) as u32),
        ] {
            put32(&mut b, at + offset, value);
        }
        branch(&mut b, at + 60, BASE + 0x1000, 0xff80);
        branch(&mut b, at + shape.len() - 4, BASE + 0x400, 0x0780);
        b[0x1000..0x100a].copy_from_slice(&[0x58, 0x1a, 0x63, 0xe7, 1, 0, 0x63, 0xdf, 5, 0]);
        b[0x10b4..0x10bc].copy_from_slice(&[0x52, 0x4d, 0x50, 0, 1, 0, 0, 0]);
        b[0x400..0x404].copy_from_slice(if new {
            &[0x86, 7, 0xe1, 0]
        } else {
            &[0x80, 7, 0xe1, 0]
        });
        b[0x404..0x404 + COMPARISON.len()].copy_from_slice(COMPARISON);
        put32(&mut b, 0x406, (BASE + 0x900) as u32);
        branch(&mut b, 0x404 + 24, BASE + 0x600, 0xff80);
        let rejection = if new { REJECT_NEW } else { REJECT_OLD };
        b[0x600..0x600 + rejection.len()].copy_from_slice(rejection);
        branch(&mut b, 0x600 + rejection.len() - 8, 0x900, 0xff80);
        // An arbitrary literal intentionally avoids an OEM string allowlist.
        b[0x900..0x908].copy_from_slice(&[0, 1, 0x80, 0xff, 4, 5, 6, 7]);
        k[KERNEL_OFFSET..KERNEL_OFFSET + 8].copy_from_slice(&b[0x900..0x908]);
        (b, k)
    }
    fn known(b: &[u8], k: Option<&[u8]>) -> Evidence {
        match native(b, k) {
            Observation::Known(e) => e,
            other => panic!("unbound comparator: {other:?}"),
        }
    }
    #[test]
    fn both_native_entry_forms_extract_all_eight_bytes_and_retain_kernel_obligation() {
        for new in [false, true] {
            let (b, k) = fixture(new);
            let e = known(&b, Some(&k));
            assert_eq!(e.expected, [0, 1, 0x80, 0xff, 4, 5, 6, 7]);
            assert_eq!(e.kernel_offset, 0x1008);
            assert_eq!(e.body.address, 0x10400);
            assert_eq!(e.comparison.offset, 0x404);
            assert_eq!(e.literal.offset, 0x900);
            assert_eq!(e.reject_transfer, 0x900);
            assert_eq!(e.paired_kernel_matches, Some(true));
            assert_eq!(known(&b, None).paired_kernel_matches, None);
            assert_eq!(
                known(&b, Some(&k[..KERNEL_OFFSET + 7])).paired_kernel_matches,
                None
            );
            for index in 0..8 {
                let mut foreign = k.clone();
                foreign[KERNEL_OFFSET + index] ^= 1;
                let foreign = known(&b, Some(&foreign));
                assert_eq!(foreign.expected, e.expected);
                assert_eq!(foreign.paired_kernel_matches, Some(false));
                let mut changed = b.clone();
                changed[0x900 + index] ^= 1;
                let changed = known(&changed, Some(&k));
                assert_ne!(changed.expected, e.expected);
                assert_eq!(changed.paired_kernel_matches, Some(false));
            }
        }
    }
    #[test]
    fn every_fixed_instruction_byte_is_required() {
        for new in [false, true] {
            let (b, _) = fixture(new);
            let e = known(&b, None);
            let reads = if new { [6, 50, 70] } else { [10, 42, 62] };
            for (span, operands) in [
                (
                    &e.entry,
                    vec![
                        (2, 4),
                        (8, 4),
                        (28, 4),
                        (34, 4),
                        (54, 4),
                        (60, 4),
                        (e.entry.bytes - 4, 4),
                    ],
                ),
                (&e.comparison, vec![(2, 4), (24, 4)]),
                (
                    &e.reject,
                    vec![
                        (reads[0], 2),
                        (reads[1], 2),
                        (reads[2], 2),
                        (e.reject.bytes - 8, 4),
                    ],
                ),
                (
                    &Span {
                        offset: 0x400,
                        bytes: 4,
                        address: 0x10400,
                    },
                    vec![],
                ),
            ] {
                for byte in 0..span.bytes {
                    if operands
                        .iter()
                        .any(|&(at, len)| (at..at + len).contains(&byte))
                    {
                        continue;
                    }
                    let mut changed = b.clone();
                    changed[span.offset + byte] ^= 1;
                    assert!(
                        !matches!(native(&changed, None), Observation::Known(_)),
                        "new={new}, fixed native byte {:#x}",
                        span.offset + byte
                    );
                }
            }
        }
    }
    #[test]
    fn disconnected_edges_scalars_and_native_boundaries_fail_closed() {
        for new in [false, true] {
            let (b, _) = fixture(new);
            let e = known(&b, None);
            let read = if new { 6 } else { 10 };
            for at in [
                e.entry.offset + 60,
                e.entry.offset + e.entry.bytes - 4,
                0x404 + 10,
                0x404 + 22,
                0x404 + 24,
                0x404 + 32,
                0x404 + 34,
                0x600 + read,
                0x600 + e.reject.bytes - 8,
                0x1000,
                0x10b4,
            ] {
                let mut changed = b.clone();
                changed[at] ^= 1;
                assert!(
                    !matches!(native(&changed, None), Observation::Known(_)),
                    "native scalar/edge {at:#x}"
                );
            }
            for at in [e.entry.offset + 2, 0x406] {
                let mut changed = b.clone();
                put32(&mut changed, at, u32::MAX);
                assert!(!matches!(native(&changed, None), Observation::Known(_)));
            }
            let mut orphan = b.clone();
            orphan[e.entry.offset..e.entry.offset + e.entry.bytes].fill(0xff);
            assert!(!matches!(native(&orphan, None), Observation::Known(_)));
            for end in [
                e.entry.offset + e.entry.bytes - 1,
                0x404 + COMPARISON.len() - 1,
                0x600 + e.reject.bytes - 1,
                0x907,
                0x10bb,
            ] {
                assert!(!matches!(native(&b[..end], None), Observation::Known(_)));
            }
            // The local D9 getter gate contributes no rooted requirement.
            assert!(!matches!(
                native(&[0x20, 0x36, 0xd9, 0, 0x21, 6, 0xff, 0xff, 0, 0], None),
                Observation::Known(_)
            ));
        }
    }
    #[test]
    fn stored_bus_api_preserves_native_proof_and_rejects_partial_bus_blocks() {
        let (b, k) = fixture(false);
        let bus = crate::image::layout::encode_v850_bus(&b).unwrap();
        let kernel = crate::image::layout::encode_v850_bus(&k).unwrap();
        assert!(matches!(
            discover(&bus, Some(&kernel)),
            Observation::Known(Evidence {
                paired_kernel_matches: Some(true),
                ..
            })
        ));
        assert!(matches!(
            discover(&bus[..bus.len() - 2], None),
            Observation::Unresolved(Unresolved::TruncatedEvidence)
        ));
        assert!(matches!(
            discover(&bus, Some(&kernel[..kernel.len() - 2])),
            Observation::Known(Evidence {
                paired_kernel_matches: None,
                ..
            })
        ));
    }
}

mod shapes {
    // Bounded native V850 entry, byte comparator and rejection control flow.
    pub(super) const ENTRY_OLD: &[u8] = &[
        45, 6, 28, 145, 255, 3, 44, 6, 220, 212, 255, 3, 236, 105, 233, 5, 109, 7, 1, 0, 68, 106,
        236, 105, 193, 253, 45, 6, 0, 77, 32, 0, 44, 6, 228, 114, 32, 0, 236, 105, 233, 5, 109, 7,
        1, 0, 68, 106, 236, 105, 193, 253, 38, 6, 240, 120, 18, 0, 31, 58, 145, 255, 204, 118, 131,
        7, 76, 2,
    ];
    pub(super) const ENTRY_NEW: &[u8] = &[
        45, 6, 100, 154, 255, 3, 44, 6, 224, 212, 255, 3, 236, 105, 233, 5, 109, 7, 1, 0, 68, 106,
        236, 105, 193, 253, 45, 6, 0, 77, 255, 3, 44, 6, 25, 123, 255, 3, 236, 105, 233, 5, 109, 7,
        1, 0, 68, 106, 236, 105, 193, 253, 38, 6, 244, 255, 24, 0, 31, 58, 151, 255, 204, 253, 6,
        82, 64, 87, 193, 246, 32, 86, 144, 0, 64, 87, 252, 241, 64, 87, 194, 246, 131, 7, 246, 246,
    ];
    pub(super) const REJECT_OLD: &[u8] = &[
        128, 7, 33, 0, 32, 94, 255, 0, 132, 55, 33, 7, 68, 7, 2, 0, 1, 82, 68, 87, 3, 0, 68, 87, 0,
        0, 235, 49, 226, 5, 134, 102, 32, 0, 68, 103, 4, 0, 149, 21, 164, 55, 31, 7, 230, 89, 242,
        5, 134, 110, 16, 0, 68, 111, 4, 0, 133, 13, 0, 0, 132, 55, 31, 7, 230, 89, 178, 5, 68, 55,
        4, 0, 11, 112, 94, 119, 193, 0, 224, 7, 96, 1, 188, 255, 130, 5, 64, 6, 63, 0,
    ];
    pub(super) const REJECT_NEW: &[u8] = &[
        128, 7, 33, 0, 132, 55, 25, 7, 68, 7, 2, 0, 1, 82, 68, 87, 3, 0, 68, 87, 0, 0, 32, 94, 255,
        0, 30, 103, 136, 1, 235, 49, 68, 103, 5, 0, 226, 5, 134, 110, 32, 0, 68, 111, 4, 0, 149,
        21, 164, 55, 23, 7, 230, 89, 242, 5, 134, 118, 16, 0, 68, 119, 4, 0, 133, 13, 0, 0, 132,
        55, 23, 7, 230, 89, 178, 5, 68, 55, 4, 0, 11, 120, 94, 127, 193, 0, 224, 7, 96, 1, 187,
        255, 106, 17, 64, 6, 63, 0,
    ];
    pub(super) const COMPARISON: &[u8] = &[
        61, 6, 248, 2, 4, 0, 0, 224, 156, 103, 9, 16, 29, 112, 220, 113, 142, 119, 1, 0, 238, 97,
        178, 5, 191, 255, 80, 255, 65, 226, 252, 0, 104, 226, 182, 245,
    ];
}

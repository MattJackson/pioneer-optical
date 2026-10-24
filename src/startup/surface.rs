//! Bind the audited direct R0 native word access to an A0 write selector.
//! Recognition is read-only: writer/default semantics and live receiver binding
//! remain required before a caller may authorize a settings migration.

use alloc::{collections::BTreeMap, vec::Vec};

const BASE: usize = 0x410000;
const GETTER_PREFIX: &[u8] = &[
    1, 0x10, 0x6d, 0xf4, 0x79, 0x37, 0, 8, 0x0d, 0x0d, 0x19, 0x55, 0x1a, 0x91, 1, 0, 0x69, 0xf1, 1,
    0, 0x6f, 0xf1, 0, 4, 2, 0x0c, 4, 0x80, 0x0f, 0xf1, 0x0f, 0xf2, 0x0b, 0x92, 0x19, 0x88,
];
const SETTER_PREFIX: &[u8] = &[
    1, 0, 0x6d, 0xf3, 1, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0, 0x38, 0x0d, 0x86, 0x6f, 0xf0, 0, 0x18,
    0x19, 0x11, 0x6f, 0xf1, 0, 0x1a, 2, 9, 0x6e, 0xf9, 0, 0x1c, 4, 0x80,
];

/// Addresses establishing the observed direct native word-command binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeWordAccess {
    /// A0 selector comparison in the command handler.
    pub selector: u32,
    /// Shared group access routine.
    pub access: u32,
    /// Persistent word getter, with R0=index.
    pub getter: u32,
    /// Persistent word setter, with R0=index and E0=value.
    pub setter: u32,
}

fn offset(bytes: &[u8]) -> Option<usize> {
    let a = u32::from_be_bytes(bytes.try_into().ok()?) as usize;
    a.checked_sub(BASE)
}

fn direct_call(bytes: &[u8]) -> Option<usize> {
    (bytes.first() == Some(&0x5e))
        .then(|| offset(&[0, bytes[1], bytes[2], bytes[3]]))
        .flatten()
}

fn write_branch_target(bytes: &[u8], start: usize) -> Option<usize> {
    use h8_asm::{isa::decode_insn, Mode, Target};
    let entry = bytes.get(start..start + 4)?;
    if entry != [0xf1, 2, 0x40, 6] {
        return None;
    }
    let mut at = start + 10;
    let mut write = false;
    for _ in 0..8 {
        let tail = bytes.get(at..)?;
        let Ok(insn) = decode_insn(tail, Target::H8S2000, Mode::Advanced) else {
            return None;
        };
        let op = tail.get(..insn.len)?;
        if op.len() == 4 && op[0] == 0x5e {
            return if write { direct_call(op) } else { None };
        }
        if op == [0xf9, 1] && !write {
            write = true;
        } else if !(op.len() == 6
            && op[..3] == [1, 0, 0x6f]
            && (0x70..=0x77).contains(&op[3])
            && op[3] != 0x71
            || op.len() == 4
                && op[..3] == [1, 0, 0x69]
                && (0xf0..=0xf7).contains(&op[3])
                && op[3] != 0xf1
            || op.len() == 2 && op[0] == 0x0f && op[1] & 0xf != 1)
        {
            return None;
        }
        at += insn.len;
    }
    None
}

/// Recognize the direct R0 native word surface in decoded Normal firmware.
/// A missing or non-unique binding is unknown, not permission to try an A0 write.
pub fn discover(bytes: &[u8]) -> Option<NativeWordAccess> {
    const PREFIX: &[u8] = &[
        1, 0, 0x6d, 0xf3, 1, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0, 8, 0x0c, 0x1e, 0x0c, 0x96, 1, 0,
        0x6f, 0xf0, 0, 4, 0x1a, 0x91, 0x0c, 0xe9, 0x10, 0x71, 0x0f, 0x95, 1, 0, 0x6f, 0x73, 0,
        0x1c, 0x0a, 0xa3, 0x7a, 4,
    ];
    #[cfg(test)]
    tests::SELECTOR_SCANS.with(|c| c.set(c.get() + 1));
    let mut writers: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (selector, op) in bytes.windows(6).enumerate().step_by(2) {
        if !(0xa0..=0xaf).contains(&op[0]) || op[1..4] != [0xa0, 0x58, 0x70] {
            continue;
        }
        let dest = selector as isize + 6 + i16::from_be_bytes([op[4], op[5]]) as isize;
        if dest < 0 {
            continue;
        }
        if let Some(access) = write_branch_target(bytes, dest as usize) {
            writers.entry(access).or_default().push(selector);
        }
    }
    let mut result = None;
    for access in (0..bytes.len().saturating_sub(0x156)).step_by(2) {
        if bytes.get(access..access + PREFIX.len()) != Some(PREFIX) {
            continue;
        }
        let Some(table) = bytes.get(access + 0x28..access + 0x2c).and_then(offset) else {
            continue;
        };
        if bytes.get(table + 8..table + 12) != Some(&[0x80, 2, 8, 0][..]) {
            continue;
        }
        if bytes.get(access + 0x48..access + 0x4e) != Some(&[0x0f, 0xa0, 0x11, 0x30, 0x0d, 3][..]) {
            continue;
        }
        let p = access + 0x136;
        let Some(w) = bytes.get(p..p + 32) else {
            continue;
        };
        if w[..7] != [0x0c, 0x66, 0x46, 8, 0x0d, 0x30, 0x5e]
            || w[10..12] != [0x40, 0x2e]
            || w[18..21] != [0x0d, 0xb1, 0x5e]
            || w[24..29] != [0x0d, 8, 0x0d, 0x30, 0x5e]
        {
            continue;
        }
        let (Some(getter), Some(setter)) = (direct_call(&w[6..10]), direct_call(&w[28..32])) else {
            continue;
        };
        if getter >= bytes.len() || setter >= bytes.len() {
            continue;
        }
        if bytes.get(getter..getter + GETTER_PREFIX.len()) != Some(GETTER_PREFIX)
            || bytes.get(setter..setter + SETTER_PREFIX.len()) != Some(SETTER_PREFIX)
        {
            continue;
        }
        let Some(lookup) = bytes
            .get(getter + 0x24..getter + 0x28)
            .and_then(direct_call)
        else {
            continue;
        };
        if lookup >= bytes.len()
            || bytes
                .get(setter + 0x42..setter + 0x46)
                .and_then(direct_call)
                != Some(lookup)
            || bytes
                .get(setter + 0x60..setter + 0x64)
                .and_then(direct_call)
                != Some(lookup)
        {
            continue;
        }
        for &selector in writers.get(&access).into_iter().flatten() {
            let candidate = NativeWordAccess {
                selector: (BASE + selector) as u32,
                access: (BASE + access) as u32,
                getter: (BASE + getter) as u32,
                setter: (BASE + setter) as u32,
            };
            if result.replace(candidate).is_some() {
                return None;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    std::thread_local! {
        pub(super) static SELECTOR_SCANS: Cell<usize> = const { Cell::new(0) };
    }

    fn fixture() -> Vec<u8> {
        let mut b = vec![0; 0xa00];
        b[0x100..0x12c].copy_from_slice(&[
            1, 0, 0x6d, 0xf3, 1, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0, 8, 0x0c, 0x1e, 0x0c, 0x96, 1, 0,
            0x6f, 0xf0, 0, 4, 0x1a, 0x91, 0x0c, 0xe9, 0x10, 0x71, 0x0f, 0x95, 1, 0, 0x6f, 0x73, 0,
            0x1c, 0x0a, 0xa3, 0x7a, 4, 0, 0x41, 8, 0,
        ]);
        b[0x148..0x14e].copy_from_slice(&[0x0f, 0xa0, 0x11, 0x30, 0x0d, 3]);
        b[0x236..0x256].copy_from_slice(&[
            0x0c, 0x66, 0x46, 8, 0x0d, 0x30, 0x5e, 0x41, 9, 0, 0x40, 0x2e, 1, 0, 0x6f, 0x70, 0, 4,
            0x0d, 0xb1, 0x5e, 0x41, 7, 0, 0x0d, 8, 0x0d, 0x30, 0x5e, 0x41, 6, 0,
        ]);
        b[0x480..0x486].copy_from_slice(&[0xa1, 0xa0, 0x58, 0x70, 0, 0x7a]);
        b[0x500..0x504].copy_from_slice(&[0xf1, 2, 0x40, 6]);
        b[0x50a..0x51c].copy_from_slice(&[
            1, 0, 0x69, 0xf4, 0xf9, 1, 1, 0, 0x6f, 0x70, 0, 0x88, 0x0f, 0xe2, 0x5e, 0x41, 1, 0,
        ]);
        b[0x808..0x80c].copy_from_slice(&[0x80, 2, 8, 0]);
        b[0x600..0x600 + SETTER_PREFIX.len()].copy_from_slice(SETTER_PREFIX);
        b[0x900..0x900 + GETTER_PREFIX.len()].copy_from_slice(GETTER_PREFIX);
        for at in [0x642, 0x660, 0x924] {
            b[at..at + 4].copy_from_slice(&[0x5e, 0x41, 9, 0x80]);
        }
        b
    }

    #[test]
    fn binds_the_selector_descriptor_and_native_calls() {
        assert_eq!(
            discover(&fixture()),
            Some(NativeWordAccess {
                selector: 0x410480,
                access: 0x410100,
                getter: 0x410900,
                setter: 0x410600,
            })
        );
    }

    #[test]
    fn broken_word_or_write_contract_is_unknown() {
        for at in [
            0x148, 0x808, 0x809, 0x80a, 0x481, 0x50f, 0x51b, 0x253, 0x600, 0x900, 0x645, 0x663,
        ] {
            let mut b = fixture();
            b[at] ^= 0x80;
            assert_eq!(discover(&b), None, "mutation at {at:x}");
        }
        let b = fixture();
        for end in 0..=0x980 {
            assert_eq!(discover(&b[..end]), None, "truncation {end:x}");
        }
    }

    #[test]
    fn two_a0_bindings_are_not_silently_selected() {
        let mut b = fixture();
        b[0x460..0x466].copy_from_slice(&[0xa1, 0xa0, 0x58, 0x70, 0, 0x9a]);
        assert_eq!(discover(&b), None);
    }

    #[test]
    fn decoy_candidate_with_bad_operand_does_not_hide_the_binding() {
        let mut b = fixture();
        let prefix = fixture()[0x100..0x128].to_vec();
        b[0..40].copy_from_slice(&prefix[..40]);
        assert_eq!(
            discover(&b),
            Some(NativeWordAccess {
                selector: 0x410480,
                access: 0x410100,
                getter: 0x410900,
                setter: 0x410600,
            })
        );
    }

    #[test]
    fn many_access_candidates_scan_selectors_once() {
        let mut b = fixture();
        let block = fixture();
        b[0x700..0x72c].copy_from_slice(&block[0x100..0x12c]);
        b[0x748..0x74e].copy_from_slice(&block[0x148..0x14e]);
        b[0x836..0x856].copy_from_slice(&block[0x236..0x256]);
        SELECTOR_SCANS.with(|c| c.set(0));
        assert_eq!(discover(&b).map(|r| r.access), Some(0x410100));
        assert_eq!(SELECTOR_SCANS.with(Cell::get), 1);
    }
}

//! Normal <-> Kernel ABI analysis.
//!
//! On Pioneer BD firmware (H8S/2000, big-endian) the 64 KiB **Kernel**
//! component is loaded at `0x400000` and the **Normal** component (~1.8 MiB) at
//! `0x410000`. The Normal reaches the Kernel only through absolute
//! `JSR @aa:24` (`5E xx xx xx`) / `JMP @aa:24` (`5A xx xx xx`) instructions whose
//! target lies in `0x400000..=0x40FFFF`. Those targets are the **ABI entries**.
//!
//! * [`abi_required`] extracts the set of Kernel entry addresses a Normal body
//!   calls (found by an instruction-synchronised sweep, so data bytes that merely
//!   look like `5E 40 xx xx` are rejected).
//! * [`abi_provided`] extracts the set of addresses a Kernel body exposes as
//!   callable entries: function starts (instruction boundaries following a
//!   terminator / padding), jump-table records and internal call targets.
//! * [`abi_compatible`] is the set test `required` is a subset of `provided`.
//!
//! Both sets also carry an FNV-1a id of the sorted entry list for coarse
//! grouping (equal id == equal set).

use alloc::vec::Vec;

/// First address of the Kernel component.
pub const KERNEL_BASE: u32 = 0x40_0000;
/// Last address of the Kernel component.
pub const KERNEL_END: u32 = 0x40_FFFF;
/// Size of a Kernel body in bytes.
const KERNEL_LEN: usize = 0x1_0000;
/// Offset in a Normal body where code begins (after the `COMP` directory).
const NORMAL_CODE_START: usize = 0x1100;
/// Number of consecutive well-formed instructions required before a call is
/// accepted. Rejects `5E 40 xx xx` byte patterns inside data tables and
/// desynchronised sweeps. Chosen empirically over the 721-body corpus: at 8 the
/// sweep admits ~300 spurious entries; at 128 every Normal that has a same-SAT
/// Kernel is subset-compatible with one, while only ~0.14% of genuine call
/// targets are dropped (and the reset address `0x400000` is the main one).
const SYNC_RUN: u32 = 128;

fn fnv1a_entries(entries: &[u32]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for e in entries {
        for b in e.to_be_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

/// The set of Kernel entry addresses a Normal body calls.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AbiRequired {
    entries: Vec<u32>,
    id: u64,
}

/// The set of entry addresses a Kernel body provides.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AbiProvided {
    entries: Vec<u32>,
    id: u64,
}

impl AbiRequired {
    /// Required entries that `provided` does **not** supply (empty iff
    /// [`abi_compatible`]).
    pub fn missing_from(&self, provided: &AbiProvided) -> Vec<u32> {
        self.entries
            .iter()
            .copied()
            .filter(|e| provided.entries.binary_search(e).is_err())
            .collect()
    }
}

macro_rules! abi_set_impl {
    ($t:ident) => {
        impl $t {
            fn from_sorted(entries: Vec<u32>) -> Self {
                let id = fnv1a_entries(&entries);
                Self { entries, id }
            }
            /// Sorted, de-duplicated entry addresses (all in `0x400000..=0x40FFFF`).
            pub fn entries(&self) -> &[u32] {
                &self.entries
            }
            /// FNV-1a id of the sorted entry list; equal ids mean equal sets.
            pub fn id(&self) -> u64 {
                self.id
            }
        }
        impl core::fmt::Display for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{:016x}", self.id)
            }
        }
    };
}
abi_set_impl!(AbiRequired);
abi_set_impl!(AbiProvided);

/// Instruction length in bytes at `i` (H8S/2000 big-endian).
fn ilen(c: &[u8], i: usize) -> usize {
    let g = |k: usize| c.get(i + k).copied().unwrap_or(0);
    let (b0, b1) = (g(0), g(1));
    match b0 {
        0x01 => match b1 & 0xF0 {
            0x00 | 0x40 => match g(2) {
                0x6B => {
                    if g(3) & 0x70 == 0 {
                        6
                    } else {
                        8
                    }
                }
                0x6F => 6,
                0x78 => 10,
                _ => 4,
            },
            0x10 | 0x20 | 0x30 | 0xC0 | 0xD0 | 0xF0 => 4,
            _ => 2,
        },
        0x58 | 0x5A | 0x5C | 0x5E => 4,
        0x6A => match b1 & 0xF0 {
            0x10 | 0x20 | 0x90 | 0xA0 => 6,
            0x30 | 0xB0 => 8,
            _ => 4,
        },
        0x6B => match b1 & 0xF0 {
            0x00 | 0x80 => 4,
            _ => 6,
        },
        0x6E | 0x6F | 0x79 | 0x7B | 0x7C | 0x7D | 0x7E | 0x7F => 4,
        0x78 => 8,
        0x7A => 6,
        _ => 2,
    }
}

/// Is the instruction at `i` a defined H8S/2000 encoding (coarse check)?
fn valid(c: &[u8], i: usize) -> bool {
    if i + 2 > c.len() {
        return false;
    }
    let g = |k: usize| c.get(i + k).copied().unwrap_or(0);
    let (b0, b1) = (g(0), g(1));
    match b0 {
        0x01 => match b1 & 0xF0 {
            h @ (0x00 | 0x40) => {
                if h == 0x00 && b1 != 0x00 {
                    return false;
                }
                match g(2) {
                    0x69 | 0x6D | 0x6F => true,
                    0x6B => matches!(g(3) & 0x70, 0x00 | 0x20),
                    0x78 => matches!(g(4), 0x6A | 0x6B),
                    _ => false,
                }
            }
            0x10 | 0x20 | 0x30 => b1 & 0x0F == 0 && g(2) == 0x6D && g(3) >= 0x70,
            0x80 => b1 == 0x80,
            0xC0 => g(2) == 0x50,
            0xD0 => g(2) == 0x51,
            0xF0 => matches!(g(2), 0x64..=0x66),
            _ => false,
        },
        0x54 | 0x56 => b1 == 0x70,
        0x58 => b1 & 0x0F == 0,
        0x59 | 0x5D => b1 & 0x8F == 0,
        0x5A | 0x5E => b1 <= 0x7F,
        0x5C => b1 == 0,
        0x7C | 0x7D => b1 & 0x8F == 0 && matches!(g(2), 0x60..=0x77),
        0x7E | 0x7F => matches!(g(2), 0x60..=0x77),
        0x7B => b1 == 0x5C && g(2) == 0x59,
        0x78 => b1 & 0x8F == 0 && matches!(g(2), 0x6A | 0x6B),
        0x79 | 0x7A => b1 & 0xF0 <= 0x60,
        0x6A => matches!(
            b1 & 0xF0,
            0x00 | 0x10 | 0x20 | 0x30 | 0x80 | 0x90 | 0xA0 | 0xB0
        ),
        0x6B => matches!(b1 & 0xF0, 0x00 | 0x20 | 0x80 | 0xA0),
        _ => true,
    }
}

/// Kernel-range absolute target of a `JSR/JMP @aa:24` at `i`, if it is one.
fn abs24_target(c: &[u8], i: usize) -> Option<u32> {
    if matches!(c.get(i), Some(0x5A) | Some(0x5E)) && i + 4 <= c.len() {
        Some(u32::from_be_bytes([0, c[i + 1], c[i + 2], c[i + 3]]))
    } else {
        None
    }
}

fn sorted_dedup(mut v: Vec<u32>) -> Vec<u32> {
    v.sort_unstable();
    v.dedup();
    v
}

/// Entry addresses a Normal body calls: targets of `JSR/JMP @aa:24` in
/// `0x400000..=0x40FFFF` (even), seen in the synchronised instruction stream.
fn required_entries(body: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    let (mut i, mut run) = (NORMAL_CODE_START, 0u32);
    while i + 4 <= body.len() {
        let v = valid(body, i);
        if v && run >= SYNC_RUN {
            if let Some(t) = abs24_target(body, i) {
                if (KERNEL_BASE..=KERNEL_END).contains(&t) && t & 1 == 0 {
                    out.push(t);
                }
            }
        }
        run = if v { run + 1 } else { 0 };
        i += ilen(body, i);
    }
    sorted_dedup(out)
}

/// Entry addresses a Kernel body provides (see module docs).
fn provided_entries(k: &[u8]) -> Vec<u32> {
    // Instruction starts by linear sweep from offset 0.
    let mut starts = Vec::new();
    let mut i = 0usize;
    while i < k.len() {
        starts.push(i);
        i += ilen(k, i);
    }
    let mut out: Vec<u32> = Vec::new();
    let mut add = |off: usize| out.push(KERNEL_BASE + off as u32);
    add(0);
    for w in starts.windows(2) {
        let (p, a) = (w[0], w[1]);
        let (b0, b1) = (k[p], k.get(p + 1).copied().unwrap_or(0));
        let word_term = matches!(
            (b0, b1),
            (0x54, 0x70) | (0x56, 0x70) | (0x00, 0x00) | (0xFF, 0xFF)
        );
        // after RTS/RTE/padding, JMP forms, or an unconditional BRA
        if word_term || matches!(b0, 0x5A | 0x59 | 0x5B | 0x40) || (b0 == 0x58 && b1 == 0x00) {
            add(a);
        }
    }
    for &a in &starts {
        let t = match k[a] {
            0x5A | 0x5E => abs24_target(k, a)
                .and_then(|t| t.checked_sub(KERNEL_BASE))
                .map(|t| t as usize),
            0x5C if a + 4 <= k.len() => {
                let d = i16::from_be_bytes([k[a + 2], k[a + 3]]) as isize;
                (a as isize + 4 + d).try_into().ok()
            }
            0x55 => {
                let d = k[a + 1] as i8 as isize;
                (a as isize + 2 + d).try_into().ok()
            }
            _ => None,
        };
        if let Some(t) = t {
            if t < k.len() {
                add(t);
            }
        }
    }
    sorted_dedup(out)
}

/// Set of Kernel entry addresses a **Normal** body calls (`JSR/JMP @aa:24` into
/// `0x400000..=0x40FFFF`). `None` if `body` is too small to be a Normal (or is
/// the size of a Kernel), or if it makes no Kernel calls at all (e.g. the
/// monolithic `SAT 8291` image).
pub fn abi_required(body: &[u8]) -> Option<AbiRequired> {
    if body.len() <= KERNEL_LEN {
        return None;
    }
    let e = required_entries(body);
    if e.is_empty() {
        return None;
    }
    Some(AbiRequired::from_sorted(e))
}

/// Set of entry addresses a **Kernel** body provides. `None` unless `body` is a
/// 64 KiB Kernel image.
pub fn abi_provided(body: &[u8]) -> Option<AbiProvided> {
    if body.len() != KERNEL_LEN {
        return None;
    }
    Some(AbiProvided::from_sorted(provided_entries(body)))
}

/// `required` is a subset of `provided`: every Kernel entry the Normal calls is
/// a callable entry of the Kernel.
pub fn abi_compatible(required: &AbiRequired, provided: &AbiProvided) -> bool {
    required
        .entries
        .iter()
        .all(|e| provided.entries.binary_search(e).is_ok())
}

/// Convenience: can this Normal body pair with this Kernel body? `false` if
/// either body is not recognised.
pub fn get_abi_match(normal_body: &[u8], kernel_body: &[u8]) -> bool {
    match (abi_required(normal_body), abi_provided(kernel_body)) {
        (Some(r), Some(p)) => abi_compatible(&r, &p),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// `0A 01` (INC.B R1H): a valid, non-terminating 2-byte filler instruction.
    fn fill(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| if i & 1 == 0 { 0x0A } else { 0x01 })
            .collect()
    }

    /// Kernel with one RTS at 0x100: the only entries are 0x400000 and 0x400102.
    fn kernel() -> Vec<u8> {
        let mut k = fill(KERNEL_LEN);
        k[0x100..0x102].copy_from_slice(&[0x54, 0x70]);
        k
    }

    fn normal_calling(target: u32, preceded_by_junk: bool) -> Vec<u8> {
        // 0x20000 > KERNEL_LEN so this is classified as a Normal
        let mut n = fill(0x2_0000);
        let at = 0x3000;
        if preceded_by_junk {
            n[at - 2..at].copy_from_slice(&[0x01, 0x90]); // undefined encoding
        }
        let t = target.to_be_bytes();
        n[at..at + 4].copy_from_slice(&[0x5E, t[1], t[2], t[3]]);
        n
    }

    #[test]
    fn provided_entries_of_synthetic_kernel() {
        let p = abi_provided(&kernel()).unwrap();
        assert_eq!(p.entries(), &[0x40_0000, 0x40_0102]);
        assert_eq!(p.id(), fnv1a_entries(&[0x40_0000, 0x40_0102]));
    }

    #[test]
    fn required_extracts_kernel_calls() {
        let r = abi_required(&normal_calling(0x40_0102, false)).unwrap();
        assert_eq!(r.entries(), &[0x40_0102]);
        assert_eq!(r.id(), fnv1a_entries(&[0x40_0102]));
    }

    #[test]
    fn subset_semantics() {
        let k = kernel();
        assert!(get_abi_match(&normal_calling(0x40_0102, false), &k));
        // 0x400104 is mid-stream filler, not an entry
        let bad = normal_calling(0x40_0104, false);
        assert!(!get_abi_match(&bad, &k));
        let r = abi_required(&bad).unwrap();
        assert_eq!(r.missing_from(&abi_provided(&k).unwrap()), vec![0x40_0104]);
    }

    #[test]
    fn data_lookalikes_are_rejected() {
        // JSR preceded by an undefined encoding is not trusted: no calls found.
        assert!(abi_required(&normal_calling(0x40_0104, true)).is_none());
    }

    #[test]
    fn odd_and_out_of_range_targets_ignored() {
        assert!(abi_required(&normal_calling(0x40_0103, false)).is_none());
        assert!(abi_required(&normal_calling(0x41_0000, false)).is_none());
    }

    #[test]
    fn wrong_sized_bodies_rejected() {
        assert!(abi_provided(&[0u8; 100]).is_none());
        assert!(abi_required(&kernel()).is_none());
        assert!(abi_required(&[]).is_none());
        assert!(!get_abi_match(&[], &[]));
    }
}

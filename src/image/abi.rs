//! Kernel ABI: the Kernel entry points a Normal body calls and a Kernel body
//! provides.
//!
//! The Kernel loads at [`KERNEL_BASE`] and the Normal reaches it only through
//! absolute `JSR @aa:24` (`5E`) / `JMP @aa:24` (`5A`) into the Kernel range.

use super::{fnv1a, KERNEL_BASE, KERNEL_LEN};
use alloc::vec::Vec;

/// Last address of the Kernel range.
const KERNEL_END: u32 = KERNEL_BASE + KERNEL_LEN as u32 - 1;
/// Offset in a Normal body where code begins (after the `COMP` directory).
const NORMAL_CODE_START: usize = crate::comp::COMP_OFFSET + 0x100;
/// Consecutive well-formed instructions required before a call is accepted;
/// rejects call-shaped bytes inside data.
const SYNC_RUN: u32 = 128;

/// A set of Kernel entry addresses, sorted and de-duplicated.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Abi {
    entries: Vec<u32>,
}

impl Abi {
    fn new(mut entries: Vec<u32>) -> Self {
        entries.sort_unstable();
        entries.dedup();
        Self { entries }
    }
    /// The entry addresses, ascending.
    pub fn entries(&self) -> &[u32] {
        &self.entries
    }
    /// A hash of the entry set; equal ids mean equal sets.
    pub fn id(&self) -> u64 {
        let bytes: Vec<u8> = self.entries.iter().flat_map(|e| e.to_be_bytes()).collect();
        fnv1a(&bytes)
    }
    /// Entries of `self` missing from `provided`.
    pub fn missing_from(&self, provided: &Abi) -> Vec<u32> {
        self.entries
            .iter()
            .copied()
            .filter(|e| provided.entries.binary_search(e).is_err())
            .collect()
    }
    /// Whether every entry of `self` is in `provided`: a Normal with this
    /// required ABI runs on a Kernel with that provided ABI.
    pub fn is_satisfied_by(&self, provided: &Abi) -> bool {
        self.entries
            .iter()
            .all(|e| provided.entries.binary_search(e).is_ok())
    }
}

impl core::fmt::Display for Abi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:016x}", self.id())
    }
}

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
    out
}

/// Entry addresses a Kernel body provides: its start, instruction boundaries
/// after a return, jump or padding, and internal call and branch targets.
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
    out
}

/// The Kernel entries a Normal body calls. `None` if `body` is not larger than
/// a Kernel or calls no Kernel entry.
pub fn required_abi(body: &[u8]) -> Option<Abi> {
    if body.len() <= KERNEL_LEN {
        return None;
    }
    let e = required_entries(body);
    (!e.is_empty()).then(|| Abi::new(e))
}

/// The entries a Kernel body provides. `None` unless `body` is exactly
/// [`KERNEL_LEN`] bytes.
pub fn provided_abi(body: &[u8]) -> Option<Abi> {
    (body.len() == KERNEL_LEN).then(|| Abi::new(provided_entries(body)))
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

    /// Kernel with one RTS at 0x100: entries are 0x400000 and 0x400102.
    fn kernel() -> Vec<u8> {
        let mut k = fill(KERNEL_LEN);
        k[0x100..0x102].copy_from_slice(&[0x54, 0x70]);
        k
    }

    fn normal_calling(target: u32, preceded_by_junk: bool) -> Vec<u8> {
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
    fn provided_entries_of_a_kernel() {
        let p = provided_abi(&kernel()).unwrap();
        assert_eq!(p.entries(), &[0x40_0000, 0x40_0102]);
    }

    #[test]
    fn required_entries_of_a_normal() {
        let r = required_abi(&normal_calling(0x40_0102, false)).unwrap();
        assert_eq!(r.entries(), &[0x40_0102]);
        assert_eq!(r.id(), Abi::new(vec![0x40_0102]).id());
    }

    #[test]
    fn subset_semantics() {
        let p = provided_abi(&kernel()).unwrap();
        assert!(required_abi(&normal_calling(0x40_0102, false))
            .unwrap()
            .is_satisfied_by(&p));
        let bad = required_abi(&normal_calling(0x40_0104, false)).unwrap();
        assert!(!bad.is_satisfied_by(&p));
        assert_eq!(bad.missing_from(&p), vec![0x40_0104]);
    }

    #[test]
    fn rejected_inputs() {
        assert!(required_abi(&normal_calling(0x40_0104, true)).is_none());
        assert!(required_abi(&normal_calling(0x40_0103, false)).is_none());
        assert!(required_abi(&normal_calling(0x41_0000, false)).is_none());
        assert!(provided_abi(&[0u8; 100]).is_none());
        assert!(required_abi(&kernel()).is_none());
        assert!(required_abi(&[]).is_none());
    }

    /// `ilen` of `bytes` placed at offset 2 behind a 2-byte prefix, zero-padded.
    fn il(bytes: &[u8]) -> usize {
        let mut v = vec![0xEEu8, 0xEE];
        v.extend_from_slice(bytes);
        v.extend_from_slice(&[0u8; 12]);
        ilen(&v, 2)
    }

    /// `valid` of `bytes` at offset 2 behind a junk prefix, zero-padded.
    fn va(bytes: &[u8]) -> bool {
        let mut v = vec![0x01u8, 0x90];
        v.extend_from_slice(bytes);
        v.extend_from_slice(&[0u8; 12]);
        valid(&v, 2)
    }

    #[test]
    fn ilen_table() {
        // 0x01 with 0x00/0x40 high nibble, keyed on the third byte
        for b1 in [0x00u8, 0x0F, 0x40, 0x4F] {
            assert_eq!(il(&[0x01, b1, 0x6B, 0x00]), 6);
            assert_eq!(il(&[0x01, b1, 0x6B, 0x0F]), 6);
            assert_eq!(il(&[0x01, b1, 0x6B, 0x70]), 8);
            assert_eq!(il(&[0x01, b1, 0x6B, 0x10]), 8);
            assert_eq!(il(&[0x01, b1, 0x6B, 0x20]), 8);
            assert_eq!(il(&[0x01, b1, 0x6B, 0x80]), 6);
            assert_eq!(il(&[0x01, b1, 0x6F]), 6);
            assert_eq!(il(&[0x01, b1, 0x78]), 10);
            assert_eq!(il(&[0x01, b1, 0x69]), 4);
        }
        for b1 in [0x10u8, 0x1F, 0x20, 0x30, 0xC0, 0xD0, 0xF0, 0xFF] {
            assert_eq!(il(&[0x01, b1]), 4, "{b1:#x}");
        }
        for b1 in [0x50u8, 0x5F, 0x60, 0x70, 0x80, 0x8F, 0x90, 0xA0, 0xB0, 0xE0] {
            assert_eq!(il(&[0x01, b1]), 2, "{b1:#x}");
        }
        for b0 in [0x58u8, 0x5A, 0x5C, 0x5E] {
            assert_eq!(il(&[b0, 0x00]), 4);
        }
        for b1 in [0x10u8, 0x1F, 0x20, 0x90, 0xA0, 0xAF] {
            assert_eq!(il(&[0x6A, b1]), 6, "{b1:#x}");
        }
        for b1 in [0x30u8, 0x3F, 0xB0, 0xBF] {
            assert_eq!(il(&[0x6A, b1]), 8, "{b1:#x}");
        }
        for b1 in [0x00u8, 0x0F, 0x40, 0x80, 0x8F, 0xC0] {
            assert_eq!(il(&[0x6A, b1]), 4, "{b1:#x}");
        }
        for b1 in [0x00u8, 0x0F, 0x80, 0x8F] {
            assert_eq!(il(&[0x6B, b1]), 4, "{b1:#x}");
        }
        for b1 in [0x10u8, 0x1F, 0x20, 0x40, 0x90, 0xA0] {
            assert_eq!(il(&[0x6B, b1]), 6, "{b1:#x}");
        }
        for b0 in [0x6Eu8, 0x6F, 0x79, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F] {
            assert_eq!(il(&[b0, 0x00]), 4, "{b0:#x}");
        }
        assert_eq!(il(&[0x78, 0x00]), 8);
        assert_eq!(il(&[0x7A, 0x00]), 6);
        assert_eq!(il(&[0x0A, 0x01]), 2);
        assert_eq!(il(&[0x6D, 0x00]), 2);
        assert_eq!(il(&[0x77, 0x00]), 2);
    }

    #[test]
    fn valid_bounds() {
        let v = [0x0Au8, 0x01];
        assert!(valid(&v, 0));
        assert!(!valid(&v, 1));
        assert!(!valid(&v, 2));
        assert!(!valid(&[0x0A], 0));
        assert!(valid(&[0x0A, 0x0A, 0x0A], 1));
        assert!(!valid(&[0x0A, 0x0A, 0x0A], 2));
        assert!(valid(&[0, 0, 0x0A, 0x01], 2));
        assert!(!valid(&[0, 0, 0x0A, 0x01], 3));
        assert!(!valid(&[0, 0, 0x0A], 2));
    }

    #[test]
    fn valid_table() {
        // 0x01 0x00 / 0x40 family
        for b0 in [0x69u8, 0x6D, 0x6F] {
            assert!(va(&[0x01, 0x00, b0]), "{b0:#x}");
            assert!(va(&[0x01, 0x40, b0]));
            assert!(va(&[0x01, 0x4F, b0]));
            assert!(!va(&[0x01, 0x01, b0]));
            assert!(!va(&[0x01, 0x0F, b0]));
        }
        assert!(!va(&[0x01, 0x00, 0x68]));
        assert!(!va(&[0x01, 0x00, 0x00]));
        assert!(va(&[0x01, 0x00, 0x6B, 0x00]));
        assert!(va(&[0x01, 0x40, 0x6B, 0x20]));
        assert!(va(&[0x01, 0x40, 0x6B, 0x2F]));
        assert!(!va(&[0x01, 0x00, 0x6B, 0x10]));
        assert!(!va(&[0x01, 0x00, 0x6B, 0x70]));
        assert!(!va(&[0x01, 0x00, 0x6B, 0x30]));
        assert!(va(&[0x01, 0x00, 0x78, 0x00, 0x6A]));
        assert!(va(&[0x01, 0x40, 0x78, 0x00, 0x6B]));
        assert!(!va(&[0x01, 0x00, 0x78, 0x00, 0x6C]));
        assert!(!va(&[0x01, 0x00, 0x78, 0x00, 0x00]));
        // 0x01 1x/2x/3x
        for h in [0x10u8, 0x20, 0x30] {
            assert!(va(&[0x01, h, 0x6D, 0x70]));
            assert!(va(&[0x01, h, 0x6D, 0xFF]));
            assert!(!va(&[0x01, h, 0x6D, 0x6F]));
            assert!(!va(&[0x01, h, 0x6C, 0x70]));
            assert!(!va(&[0x01, h, 0x6E, 0x70]));
            assert!(!va(&[0x01, h | 1, 0x6D, 0x70]));
            assert!(!va(&[0x01, h | 0x0F, 0x6D, 0x70]));
        }
        assert!(va(&[0x01, 0x80]));
        assert!(!va(&[0x01, 0x81]));
        assert!(!va(&[0x01, 0x8F]));
        assert!(va(&[0x01, 0xC0, 0x50]));
        assert!(!va(&[0x01, 0xC0, 0x51]));
        assert!(va(&[0x01, 0xD0, 0x51]));
        assert!(!va(&[0x01, 0xD0, 0x50]));
        for g in [0x64u8, 0x65, 0x66] {
            assert!(va(&[0x01, 0xF0, g]));
        }
        assert!(!va(&[0x01, 0xF0, 0x63]));
        assert!(!va(&[0x01, 0xF0, 0x67]));
        for h in [0x50u8, 0x60, 0x70, 0x90, 0xA0, 0xB0, 0xE0] {
            assert!(!va(&[0x01, h, 0x50]), "{h:#x}");
        }
        // single-opcode families
        for b0 in [0x54u8, 0x56] {
            assert!(va(&[b0, 0x70]));
            assert!(!va(&[b0, 0x71]));
            assert!(!va(&[b0, 0x00]));
        }
        assert!(va(&[0x58, 0x00]));
        assert!(va(&[0x58, 0x70]));
        assert!(!va(&[0x58, 0x01]));
        for b0 in [0x59u8, 0x5D] {
            assert!(va(&[b0, 0x00]));
            assert!(va(&[b0, 0x70]));
            assert!(!va(&[b0, 0x80]));
            assert!(!va(&[b0, 0x01]));
        }
        for b0 in [0x5Au8, 0x5E] {
            assert!(va(&[b0, 0x00]));
            assert!(va(&[b0, 0x7F]));
            assert!(!va(&[b0, 0x80]));
        }
        assert!(va(&[0x5C, 0x00]));
        assert!(!va(&[0x5C, 0x01]));
        assert!(!va(&[0x5C, 0x80]));
        for b0 in [0x7Cu8, 0x7D] {
            assert!(va(&[b0, 0x00, 0x60]));
            assert!(va(&[b0, 0x70, 0x77]));
            assert!(!va(&[b0, 0x80, 0x60]));
            assert!(!va(&[b0, 0x01, 0x60]));
            assert!(!va(&[b0, 0x00, 0x78]));
            assert!(!va(&[b0, 0x00, 0x5F]));
        }
        for b0 in [0x7Eu8, 0x7F] {
            assert!(va(&[b0, 0x00, 0x60]));
            assert!(va(&[b0, 0xFF, 0x77]));
            assert!(!va(&[b0, 0x00, 0x78]));
            assert!(!va(&[b0, 0x00, 0x5F]));
        }
        assert!(va(&[0x7B, 0x5C, 0x59]));
        assert!(!va(&[0x7B, 0x5C, 0x58]));
        assert!(!va(&[0x7B, 0x5D, 0x59]));
        assert!(va(&[0x78, 0x00, 0x6A]));
        assert!(va(&[0x78, 0x70, 0x6B]));
        assert!(!va(&[0x78, 0x80, 0x6A]));
        assert!(!va(&[0x78, 0x01, 0x6A]));
        assert!(!va(&[0x78, 0x00, 0x6C]));
        for b0 in [0x79u8, 0x7A] {
            assert!(va(&[b0, 0x00]));
            assert!(va(&[b0, 0x6F]));
            assert!(va(&[b0, 0x60]));
            assert!(!va(&[b0, 0x70]));
            assert!(!va(&[b0, 0xF0]));
        }
        for h in [0x00u8, 0x10, 0x20, 0x30, 0x80, 0x90, 0xA0, 0xB0] {
            assert!(va(&[0x6A, h]));
            assert!(va(&[0x6A, h | 0x0F]));
        }
        for h in [0x40u8, 0x50, 0x60, 0x70, 0xC0, 0xD0, 0xE0, 0xF0] {
            assert!(!va(&[0x6A, h]), "{h:#x}");
        }
        for h in [0x00u8, 0x20, 0x80, 0xA0] {
            assert!(va(&[0x6B, h]));
            assert!(va(&[0x6B, h | 0x0F]));
        }
        for h in [0x10u8, 0x30, 0x40, 0x90, 0xB0, 0xC0] {
            assert!(!va(&[0x6B, h]), "{h:#x}");
        }
        assert!(va(&[0x0A, 0x01]));
        assert!(va(&[0x00, 0x00]));
    }

    #[test]
    fn abi_id_and_display() {
        let a = Abi::new(vec![0x40_0102, 0x40_0000]);
        let want = fnv1a(&[0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x01, 0x02]);
        assert_eq!(a.id(), want);
        assert_ne!(a.id(), 0);
        assert_ne!(a.id(), 1);
        assert_ne!(a.id(), Abi::new(vec![0x40_0000]).id());
        assert_eq!(alloc::format!("{a}"), alloc::format!("{want:016x}"));
        assert_eq!(alloc::format!("{a}").len(), 16);
    }

    fn call_at(at: usize, bytes: &[u8]) -> Vec<u8> {
        let mut n = fill(0x2_0000);
        n[at..at + bytes.len()].copy_from_slice(bytes);
        n
    }

    #[test]
    fn required_entries_positions() {
        // call far into the body (guards the `i + 4 <= len` loop bound)
        let n = call_at(0x9000, &[0x5E, 0x40, 0x01, 0x00]);
        assert_eq!(required_entries(&n), vec![0x40_0100]);
        // call as the very last instruction
        let n = call_at(0x2_0000 - 4, &[0x5A, 0x40, 0x01, 0x00]);
        assert_eq!(required_entries(&n), vec![0x40_0100]);
        // JMP and JSR, multiple, kernel range bounds
        let mut n = call_at(0x3000, &[0x5A, 0x40, 0x02, 0x00]);
        n[0x3010..0x3014].copy_from_slice(&[0x5E, 0x40, 0xFF, 0xFE]);
        n[0x3020..0x3024].copy_from_slice(&[0x5E, 0x40, 0x00, 0x00]);
        n[0x3030..0x3034].copy_from_slice(&[0x5E, 0x3F, 0xFF, 0xFE]);
        n[0x3040..0x3044].copy_from_slice(&[0x5E, 0x41, 0x00, 0x00]);
        assert_eq!(required_entries(&n), vec![0x40_0200, 0x40_FFFE, 0x40_0000]);
        // non-call instruction whose following bytes look like a kernel address
        let n = call_at(0x3000, &[0x0A, 0x40, 0x08, 0x00]);
        assert!(required_entries(&n).is_empty());
        let n = call_at(0x3000, &[0x5C, 0x40, 0x08, 0x00]);
        assert!(required_entries(&n).is_empty());
    }

    fn prov(patches: &[(usize, &[u8])]) -> Vec<u32> {
        let mut k = fill(KERNEL_LEN);
        for (o, b) in patches {
            k[*o..*o + b.len()].copy_from_slice(b);
        }
        let mut v: Vec<u32> = provided_abi(&k).unwrap().entries().to_vec();
        for e in &mut v {
            *e -= KERNEL_BASE;
        }
        v
    }

    #[test]
    fn provided_terminators() {
        assert_eq!(prov(&[]), vec![0]);
        for t in [[0x54u8, 0x70], [0x56, 0x70], [0x00, 0x00], [0xFF, 0xFF]] {
            assert_eq!(prov(&[(0x100, &t)]), vec![0, 0x102], "{t:?}");
        }
        for t in [[0x54u8, 0x71], [0x56, 0x00], [0x00, 0x01], [0xFF, 0x00]] {
            assert_eq!(prov(&[(0x100, &t)]), vec![0], "{t:?}");
        }
        for b0 in [0x59u8, 0x5B, 0x40] {
            assert_eq!(prov(&[(0x100, &[b0, 0x00])]), vec![0, 0x102], "{b0:#x}");
        }
        assert_eq!(prov(&[(0x100, &[0x58, 0x00, 0x0A, 0x01])]), vec![0, 0x104]);
        assert_eq!(prov(&[(0x100, &[0x58, 0x01, 0x0A, 0x01])]), vec![0]);
        assert_eq!(prov(&[(0x100, &[0x5A, 0x00, 0x00, 0x00])]), vec![0, 0x104]);
        assert_eq!(prov(&[(0x100, &[0x5E, 0x00, 0x00, 0x00])]), vec![0]);
    }

    #[test]
    fn provided_call_and_branch_targets() {
        // JMP / JSR abs24 into the kernel
        assert_eq!(prov(&[(0x100, &[0x5E, 0x40, 0x08, 0x00])]), vec![0, 0x800]);
        assert_eq!(
            prov(&[(0x100, &[0x5A, 0x40, 0x08, 0x00])]),
            vec![0, 0x104, 0x800]
        );
        // target range edges
        assert_eq!(prov(&[(0x100, &[0x5E, 0x40, 0xFF, 0xFE])]), vec![0, 0xFFFE]);
        assert_eq!(prov(&[(0x100, &[0x5E, 0x41, 0x00, 0x00])]), vec![0]);
        assert_eq!(prov(&[(0x100, &[0x5E, 0x3F, 0xFF, 0xFE])]), vec![0]);
        // BSR 16-bit: target = a + 4 + d
        assert_eq!(prov(&[(0x100, &[0x5C, 0x00, 0x00, 0x10])]), vec![0, 0x114]);
        assert_eq!(prov(&[(0x100, &[0x5C, 0x00, 0xFF, 0xF0])]), vec![0, 0xF4]);
        // BSR as the final instruction: guard must stop the read past the end
        assert_eq!(
            prov(&[(KERNEL_LEN - 4, &[0x5C, 0x00, 0xFF, 0xF0])]),
            vec![0, (KERNEL_LEN - 16) as u32]
        );
        assert_eq!(prov(&[(KERNEL_LEN - 2, &[0x5C, 0x00])]), vec![0]);
        assert_eq!(prov(&[(KERNEL_LEN - 2, &[0x5A, 0x40])]), vec![0]);
        // BRA 8-bit: target = a + 2 + d
        assert_eq!(prov(&[(0x100, &[0x55, 0x10])]), vec![0, 0x112]);
        assert_eq!(prov(&[(0x100, &[0x55, 0xF0])]), vec![0, 0xF2]);
        assert_eq!(prov(&[(0x10, &[0x55, 0x80])]), vec![0]);
        // target at/after the kernel end is dropped, last byte kept
        assert_eq!(prov(&[(0x100, &[0x5E, 0x41, 0x00, 0x00])]), vec![0]);
        assert_eq!(prov(&[(KERNEL_LEN - 2, &[0x55, 0x00])]), vec![0]);
        assert_eq!(
            prov(&[(KERNEL_LEN - 4, &[0x55, 0x01])]),
            vec![0, (KERNEL_LEN - 4 + 3) as u32]
        );
    }
}

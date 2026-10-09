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

use super::h8::{ilen, valid};

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
        if word_term
            || (valid(k, p)
                && (matches!(b0, 0x5A | 0x59 | 0x5B | 0x40) || (b0 == 0x58 && b1 == 0x00)))
        {
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
#[path = "abi_tests.rs"]
mod tests;

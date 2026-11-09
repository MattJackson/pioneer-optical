//! Exact native facts retained when no startup comparison is recognized, and
//! the bounded proof that a target has no fixed 0x009F startup gate.
//!
//! `inspect` only explains a miss. `absent` is the single positive proof:
//! it requires the held Kernel and either the audited startup function with an
//! empty or dead-read gate slot, or no Normal loader-flag service and no 0x009F
//! getter read at all. Every Kernel 0x009F load must be the audited byte store.
use crate::image::layout::{self, H8ReaderComponent, Observation, Unresolved};
use alloc::vec::Vec;

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

fn stored(body: &[u8]) -> Option<Vec<u8>> {
    let regions = crate::image::regions(body)?;
    let mut stored = alloc::vec![0xff; body.len()];
    for region in regions.stored {
        let start = region.as_ptr() as usize - body.as_ptr() as usize;
        stored[start..start + region.len()].copy_from_slice(region);
    }
    Some(stored)
}

/// Describe why stored Normal code has no recognized 0x009F comparison.
/// `None` when stored regions are unavailable or a 0x009F comparison (or a
/// conflict) was recognized, so the miss is elsewhere.
pub fn inspect(normal: &[u8], kernel: Option<&[u8]>) -> Option<Miss> {
    let stored = stored(normal)?;
    let other_parameter = match super::discover(&stored) {
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
        if w[..4] == [0x79, register, 0, 0x9f]
            && super::getter_call(&stored, at).is_some_and(|(g, _)| g == entry as usize)
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

// One Kernel 0x009F load: MOV.B @(d,ER7),R2L; MOV.W #9F,R1; MOV.L ERn,ER0;
// JSR @ER4, where ER4 was loaded with the byte-store routine and every
// straight-line instruction since that load leaves register 4 untouched
// (other than JSR @ER4 calls; callees preserve ER4-ER6 by convention).
fn kernel_byte_store(kernel: &[u8], at: usize) -> bool {
    use h8_asm::{isa::decode_insn, Mode, Target};
    const BASE: u32 = 0x400000;
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
    let Some(routine) = target(&kernel[load + 3..load + 6], BASE) else {
        return false;
    };
    if kernel[load + 2] != 0
        || !masked(kernel, routine, BYTE_STORE.0, BYTE_STORE.1)
        || !target(&kernel[routine + 25..routine + 28], BASE)
            .is_some_and(|store| masked(kernel, store, STORE.0, STORE.1))
    {
        return false;
    }
    let mut p = load + 6;
    while p < at + 8 {
        let Ok(decoded) = decode_insn(&kernel[p..], Target::H8S2000, Mode::Advanced) else {
            return false;
        };
        let insn = decoded.insn;
        let call_er4 = insn.mnemonic == "JSR" && kernel[p..p + 2] == [0x5d, 0x40];
        if !call_er4 && (uses_register_4(&insn) || matches!(insn.mnemonic, "RTS" | "RTE" | "JMP")) {
            return false;
        }
        p += decoded.len;
    }
    p == at + 8
}

/// Prove that the target Normal and its held Kernel have no fixed 0x009F
/// startup comparison. `None` is not evidence of a gate; it only means this
/// bounded proof does not hold (including a missing Kernel). The global
/// no-loader-flag-service form is admitted only for SAT1 (`sat1`), the only
/// generation audited without the 0x400A00 Kernel service table.
pub fn absent(normal: &[u8], kernel: Option<&[u8]>, sat1: bool) -> Option<Absence> {
    let kernel = kernel?;
    let miss = inspect(normal, Some(kernel))?;
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
            kernel_stores.push(0x400000 + at as u32);
        }
    }
    let normal = stored(normal)?;
    let anchors: Vec<usize> = (0..normal.len())
        .step_by(2)
        .filter(|&at| {
            masked(&normal, at, ANCHOR_ER1.0, ANCHOR_ER1.1)
                || masked(&normal, at, ANCHOR_ER2.0, ANCHOR_ER2.1)
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
            let basis = if miss.reads.is_empty() && slot[8] == 0x5e && slot[8..] != call {
                Basis::EmptySlot
            } else if slot[4..6] == [0x79, register]
                && slot[8..] == call
                && normal[at + 1] == 1
                && target(&normal[at + 15..at + 18], base)
                    .is_some_and(|callee| masked(&normal, callee, R0_OVERWRITE.0, R0_OVERWRITE.1))
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
            let service = (0..normal.len().saturating_sub(3)).step_by(2).any(|at| {
                matches!(normal[at], 0x5e | 0x5a) && normal[at + 1..at + 4] == [0x40, 0x0a, 0x1a]
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
        kernel[0x2000..0x2006].copy_from_slice(&[0x7a, 4, 0, 0x40, 0x10, 0]);
        kernel[0x2006..0x2006 + KERNEL_SITE.len()].copy_from_slice(KERNEL_SITE);
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
}

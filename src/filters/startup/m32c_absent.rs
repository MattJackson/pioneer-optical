//! Bounded proof that an M32C ATA target has no native 0x00D9 startup gate.
//!
//! Where the gate exists (ATA 0006 and later), main calls it in the slot directly
//! before the OS task-install anchor and it reads word 0x00D9 through the
//! word-ID getter (`MOV.W #0xD9,R0; JSR.A getter`). This proof roots the startup
//! path in the held Kernel: its reset vector and its unique acceptance gate, which
//! transfers to the Normal entry. It then binds the entry prefix and main up to
//! the anchor instruction by instruction, from a closed set of data writes and
//! direct calls, with a direct `JSR.A` in the gate slot. Neither Normal nor the
//! Kernel may hold an immediate 0x00D9 index load or a native word getter.
//! Callees are not executed, the same standard as the H8 empty-slot proof.
use super::shape_matches as matches;

const KERNEL_BASE: u32 = 0xffc000;
const KERNEL_BYTES: usize = 0x4000;
const NORMAL_BASE: u32 = 0xf80000;

/// Held Kernel reset acceptance gate: reset-cleared RAM flag 0x3000, word sum of
/// 0x1000..0x2000 and 0xF80010..0xFFC000, then the 16-byte header at
/// 0xF80000 against the Kernel copy (operand 50) and `JMP.A` entry (operand 68).
/// Every failure branch reaches the end of this gate, the Kernel's own loop.
const KERNEL_GATE: (&[u8], &[(usize, usize)]) = (
    &[
        0xe6, 0x91, 0x00, 0x30, 0x00, 0xda, 0x41, 0xf9, 0xe0, 0xbc, 0x00, 0x10, 0x00, 0x89, 0xc8,
        0xac, 0xa0, 0xb1, 0x00, 0x20, 0x00, 0x00, 0x9a, 0xf6, 0xbc, 0x10, 0x00, 0xf8, 0x89, 0xc8,
        0xac, 0xa0, 0xb1, 0x00, 0xc0, 0xff, 0x00, 0x9a, 0xf6, 0xe9, 0xd0, 0x9a, 0x1d, 0xd7, 0x9a,
        0x00, 0x00, 0xf8, 0xd7, 0x9b, 0x00, 0x00, 0x00, 0x03, 0x80, 0x46, 0x9a, 0x0e, 0x8c, 0x8d,
        0xa9, 0x8e, 0x47, 0x10, 0x00, 0x9a, 0xf4, 0xcc, 0x00, 0x00, 0x00,
    ],
    &[(50, 3), (68, 3)],
);
/// OS task-install anchor ending main's startup prefix: `MOV.L #sp,abs16;
/// FSET I; PUSH.B #0x250; PUSH.L #task; JSR.A create` (Kernel service).
const ANCHOR: (&[u8], &[(usize, usize)]) = (
    &[
        0xb6, 0xf1, 0, 0, 0, 0, 0, 0, 0xd1, 0xee, 0xaf, 0x50, 0x02, 0xb6, 0x53, 0, 0, 0, 0, 0xcd,
        0, 0, 0,
    ],
    &[(2, 6), (15, 4), (20, 3)],
);
/// Native index load of the startup word into the getter argument register.
const D9_INDEX: &[u8] = &[0x05, 0xd9, 0x00];

/// Anchored coordinates of the proof; evidence only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Absence {
    pub kernel_gate: u32,
    pub header: u32,
    pub entry: u32,
    pub main: u32,
    pub anchor: u32,
    pub slot: u32,
    pub slot_target: u32,
    pub task: u32,
    pub create: u32,
}

fn le24(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], 0])
}

fn in_normal(normal: &[u8], address: u32) -> Option<usize> {
    let at = usize::try_from(address.checked_sub(NORMAL_BASE)?).ok()?;
    (address < KERNEL_BASE && at < normal.len()).then_some(at)
}

/// Length of one entry-prefix instruction: memory clear/copy setup only.
fn entry_step(b: &[u8]) -> Option<usize> {
    match *b.get(..2)? {
        [0x02, _] => Some(1),                   // MOV.B:Z #0,R0L
        [0xb0, 0xb1 | 0xf1] => Some(6),         // MOV.L:G #imm32,A0/A1
        [0x99, 0x6f] => Some(4),                // MOV.W:G #imm16,R3
        [0xb8, 0x03] | [0xb0, 0x83] => Some(2), // SSTR.B / SMOVF.B
        [0xf6, 0xa0] | [0xd5, 0x28] => Some(5), // MOV.B:Q #0,abs24 / LDC #,INTB
        _ => None,
    }
}

/// Length of one main-prefix instruction: data writes, flag reads and direct
/// calls. The only branch is `JEQ` over exactly one following `JSR.A`.
fn main_step(b: &[u8]) -> Option<usize> {
    match *b.get(..3)? {
        [0x8f, _, _] => Some(2),                                    // PUSHM
        [0xcf, _, _] => Some(3),                                    // JSR.W
        [0xcd, _, _] | [0x14, _, _] => Some(4),                     // JSR.A / MOV.B:S #,abs16
        [0x12 | 0x18 | 0x10, _, _] => Some(3),                      // MOV.B:Z/S abs16
        [0xf6, 0xe0..=0xef, _] | [0xd6, 0xf0..=0xff, _] => Some(4), // MOV.B:Q / BSET/BCLR abs16
        [0x15, _, _] => Some(5),                                    // MOV.W:S #,abs16
        [0x4c | 0x44, _, _] | [0xd1, 0xee, _] => Some(2),           // AND/OR.B:S #,R0L / FSET I
        [0xda, 0x05, 0xcd] => Some(2),                              // JEQ over one JSR.A
        _ => None,
    }
}

/// Prove that the target Normal and its held Kernel have no native 0x00D9
/// startup gate. `None` is not evidence of a gate (including a missing Kernel).
pub(super) fn absent(normal: &[u8], kernel: Option<&[u8]>) -> Option<Absence> {
    let kernel = kernel?;
    if kernel.len() != KERNEL_BYTES || kernel[KERNEL_BYTES - 4..] != [0x00, 0xc0, 0xff, 0x00] {
        return None;
    }
    let mut gates =
        (0..kernel.len()).filter(|&at| matches(kernel, at, KERNEL_GATE.0, KERNEL_GATE.1));
    let (Some(gate), None) = (gates.next(), gates.next()) else {
        return None;
    };
    let header = le24(&kernel[gate + 50..]);
    let header_at = usize::try_from(header.checked_sub(KERNEL_BASE)?).ok()?;
    kernel.get(header_at..header_at.checked_add(16)?)?;
    let entry = le24(&kernel[gate + 68..]);
    let mut at = in_normal(normal, entry)?;
    for _ in 0..64 {
        if normal.get(at) == Some(&0xcd) {
            break;
        }
        at += entry_step(normal.get(at..)?)?;
    }
    let main = le24(normal.get(at + 1..at + 4)?);
    let mut at = in_normal(normal, main)?;
    let mut slot = None;
    for _ in 0..96 {
        if matches(normal, at, ANCHOR.0, ANCHOR.1) {
            break;
        }
        let step = main_step(normal.get(at..)?)?;
        slot = Some(at);
        at += step;
    }
    if !matches(normal, at, ANCHOR.0, ANCHOR.1) {
        return None;
    }
    // The gate slot must be a direct JSR.A to Normal code, never a JSR.W gate.
    let slot = slot.filter(|&s| normal[s] == 0xcd && s + 4 == at)?;
    let slot_target = le24(&normal[slot + 1..]);
    in_normal(normal, slot_target)?;
    let task = u32::from_le_bytes(normal[at + 15..at + 19].try_into().ok()?);
    let create = le24(&normal[at + 20..]);
    in_normal(normal, task)?;
    if create < KERNEL_BASE || usize::try_from(create - KERNEL_BASE).ok()? >= kernel.len() {
        return None;
    }
    let index = |b: &[u8]| b.windows(D9_INDEX.len()).any(|w| w == D9_INDEX);
    if index(normal) || index(kernel) || super::m32c::has_word_getter(normal) {
        return None;
    }
    let address = |offset: usize| NORMAL_BASE + offset as u32;
    Some(Absence {
        kernel_gate: KERNEL_BASE + gate as u32,
        header,
        entry,
        main,
        anchor: address(at),
        slot: address(slot),
        slot_target,
        task,
        create,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec::Vec;

    // DVR-105 1.21 (0ac7b4a3…) Normal entry 0xf80012..0xf8009c.
    const ENTRY: &[u8] = &[
        0x02, 0xb0, 0xf1, 0x09, 0x36, 0x00, 0x00, 0x99, 0x6f, 0x72, 0x09, 0xb8, 0x03, 0x02, 0xb0,
        0xf1, 0x7b, 0x3f, 0x00, 0x00, 0x99, 0x6f, 0x8d, 0x03, 0xb8, 0x03, 0xf6, 0xa0, 0x0e, 0x00,
        0x00, 0xb0, 0xb1, 0x00, 0x10, 0x00, 0x00, 0xb0, 0xf1, 0xde, 0x34, 0x00, 0x00, 0x99, 0x6f,
        0xe4, 0x00, 0xb0, 0x83, 0xb0, 0xb1, 0xe4, 0x10, 0x00, 0x00, 0xb0, 0xf1, 0xc2, 0x35, 0x00,
        0x00, 0x99, 0x6f, 0x47, 0x00, 0xb0, 0x83, 0x02, 0xb0, 0xf1, 0xd4, 0x8e, 0x10, 0x00, 0x99,
        0x6f, 0x44, 0x25, 0xb8, 0x03, 0x02, 0xb0, 0xf1, 0x18, 0xb4, 0x10, 0x00, 0x99, 0x6f, 0x49,
        0x03, 0xb8, 0x03, 0xb0, 0xb1, 0xcd, 0x9f, 0xff, 0x00, 0xb0, 0xf1, 0xcb, 0x8d, 0x10, 0x00,
        0x99, 0x6f, 0xf4, 0x00, 0xb0, 0x83, 0xb0, 0xb1, 0xc1, 0xa0, 0xff, 0x00, 0xb0, 0xf1, 0xbf,
        0x8e, 0x10, 0x00, 0x99, 0x6f, 0x15, 0x00, 0xb0, 0x83, 0xd5, 0x28, 0xb0, 0xbe, 0xff, 0xcd,
        0x00, 0x13, 0xf8,
    ];
    // Its main 0xf81300 through the task-install anchor at 0xf8138c; the gate
    // slot 0xf81388 is JSR.A 0xfbe77a.
    const MAIN: &[u8] = &[
        0x8f, 0x20, 0xcf, 0xe3, 0xff, 0x14, 0x9e, 0x00, 0x32, 0x12, 0x90, 0x00, 0x12, 0x72, 0x00,
        0xf6, 0xe1, 0x48, 0x01, 0x14, 0x4c, 0x01, 0x90, 0x14, 0x49, 0x01, 0x09, 0x12, 0x90, 0x00,
        0x12, 0x72, 0x00, 0x14, 0x37, 0x01, 0x40, 0x15, 0x28, 0x01, 0x97, 0x06, 0x12, 0x8c, 0x00,
        0x12, 0x38, 0x01, 0x15, 0x2a, 0x01, 0x4b, 0x84, 0xf6, 0xe7, 0x6e, 0x00, 0xd6, 0xfa, 0x20,
        0x01, 0x14, 0x3c, 0x01, 0x86, 0x14, 0x3b, 0x01, 0x42, 0x12, 0x94, 0x00, 0xf6, 0xe2, 0x3d,
        0x01, 0x12, 0x96, 0x00, 0x14, 0x17, 0x01, 0x2b, 0x14, 0x14, 0x01, 0x21, 0x18, 0x16, 0x01,
        0x4c, 0x87, 0x44, 0x58, 0x10, 0x16, 0x01, 0xcd, 0xdc, 0x05, 0xf8, 0xcd, 0x32, 0x38, 0xf8,
        0x18, 0x03, 0x30, 0xda, 0x05, 0xcd, 0x9c, 0x37, 0xf8, 0xf6, 0xe1, 0xbf, 0x34, 0xd1, 0xee,
        0xcd, 0xee, 0x66, 0xfb, 0xcd, 0x1a, 0xe0, 0xfc, 0xcd, 0x16, 0x06, 0xfa, 0xcd, 0xac, 0x90,
        0xfc, 0xcd, 0x7a, 0xe7, 0xfb, 0xb6, 0xf1, 0x0a, 0x30, 0x92, 0x34, 0x00, 0x00, 0xd1, 0xee,
        0xaf, 0x50, 0x02, 0xb6, 0x53, 0xa2, 0x1c, 0xf8, 0x00, 0xcd, 0x1c, 0xeb, 0xff,
    ];
    pub(crate) const HEADER: &[u8; 16] = b"PIONEER  DVR-105";

    /// DVR-105 1.21 Kernel c3508327… shape: reset vector, gate at 0xffc1da
    /// (header copy 0xffc23e, entry 0xf80012).
    pub(crate) fn kernel() -> Vec<u8> {
        let mut k = alloc::vec![0xff; KERNEL_BYTES];
        k[0x1da..0x1da + KERNEL_GATE.0.len()].copy_from_slice(KERNEL_GATE.0);
        k[0x1da + 50..0x1da + 53].copy_from_slice(&[0x3e, 0xc2, 0xff]);
        k[0x1da + 68..0x1da + 71].copy_from_slice(&[0x12, 0x00, 0xf8]);
        k[0x23e..0x24e].copy_from_slice(HEADER);
        k[KERNEL_BYTES - 4..].copy_from_slice(&[0x00, 0xc0, 0xff, 0x00]);
        k
    }

    pub(crate) fn normal() -> Vec<u8> {
        // Every image byte outside the bound entry and main paths is 0x00.
        let mut n = alloc::vec![0x00; 0x40000];
        n[..16].copy_from_slice(HEADER);
        n[0x12..0x12 + ENTRY.len()].copy_from_slice(ENTRY);
        n[0x1300..0x1300 + MAIN.len()].copy_from_slice(MAIN);
        n
    }

    #[test]
    fn held_kernel_rooted_startup_without_d9_gate_is_absent() {
        let proof = absent(&normal(), Some(&kernel())).unwrap();
        assert_eq!(
            proof,
            Absence {
                kernel_gate: 0xffc1da,
                header: 0xffc23e,
                entry: 0xf80012,
                main: 0xf81300,
                anchor: 0xf8138c,
                slot: 0xf81388,
                slot_target: 0xfbe77a,
                task: 0xf81ca2,
                create: 0xffeb1c,
            }
        );
        // The exact Kernel is required.
        assert_eq!(absent(&normal(), None), None);
    }

    #[test]
    fn a_d9_index_load_or_word_getter_anywhere_defeats_the_proof() {
        let mut n = normal();
        n[0x1800..0x1803].copy_from_slice(D9_INDEX);
        assert_eq!(absent(&n, Some(&kernel())), None);
        let mut k = kernel();
        k[0x3000..0x3003].copy_from_slice(D9_INDEX);
        assert_eq!(absent(&normal(), Some(&k)), None);
        let getter = super::super::m32c::tests::fixture(false, false, 0, 0xf40000);
        let mut n = normal();
        n.extend_from_slice(&getter[0x1000..0x1000 + 0x62]);
        assert!(super::super::m32c::has_word_getter(&n));
        assert_eq!(absent(&n, Some(&kernel())), None);
    }

    #[test]
    fn a_gate_call_or_unbound_instruction_in_main_defeats_the_proof() {
        // A JSR.W gate inserted in the slot before the anchor.
        let mut n = normal();
        let anchor = 0x1300 + MAIN.len() - ANCHOR.0.len();
        n.copy_within(anchor..0x1300 + MAIN.len(), anchor + 3);
        n[anchor..anchor + 3].copy_from_slice(&[0xcf, 0x00, 0x01]);
        assert_eq!(absent(&n, Some(&kernel())), None);
        // A comparison or conditional branch not in the closed set.
        for (at, byte) in [
            (0x1300 + 5, 0xe6u8),
            (0x1300 + 0x6c, 0x9a),
            (0x1300 + 0x6d, 0x06),
        ] {
            let mut n = normal();
            n[at] = byte;
            assert_eq!(absent(&n, Some(&kernel())), None, "main byte {at:#x}");
        }
        // The slot target must be Normal code; the create service Kernel code.
        let mut n = normal();
        n[anchor - 1] = 0xff;
        assert_eq!(absent(&n, Some(&kernel())), None);
        let mut n = normal();
        n[0x1300 + MAIN.len() - 1] = 0xf8;
        assert_eq!(absent(&n, Some(&kernel())), None);
        // No anchor: the startup function is unbound.
        let mut n = normal();
        n[anchor + 9] = 0x00;
        assert_eq!(absent(&n, Some(&kernel())), None);
    }

    #[test]
    fn the_entry_prefix_admits_only_memory_initialization() {
        for at in [0x12usize, 0x12 + 0x0b, 0x12 + 0x81] {
            let mut n = normal();
            n[at] = 0xda;
            assert_eq!(absent(&n, Some(&kernel())), None, "entry byte {at:#x}");
        }
        let mut n = normal();
        n[0x12 + ENTRY.len() - 1] = 0xff;
        assert_eq!(absent(&n, Some(&kernel())), None);
    }

    #[test]
    fn every_fixed_kernel_gate_byte_and_the_reset_vector_are_required() {
        let operands = [(50usize, 3usize), (68, 3)];
        for byte in 0..KERNEL_GATE.0.len() {
            if operands.iter().any(|&(a, l)| (a..a + l).contains(&byte)) {
                continue;
            }
            let mut k = kernel();
            k[0x1da + byte] ^= 1;
            assert_eq!(absent(&normal(), Some(&k)), None, "gate byte {byte}");
        }
        let mut k = kernel();
        k[KERNEL_BYTES - 3] = 0xc1;
        assert_eq!(absent(&normal(), Some(&k)), None);
        // A second gate leaves the startup root ambiguous.
        let mut k = kernel();
        k.copy_within(0x1da..0x1da + KERNEL_GATE.0.len(), 0x2000);
        assert_eq!(absent(&normal(), Some(&k)), None);
        // Entry outside Normal, header outside the Kernel, wrong Kernel size.
        let mut k = kernel();
        k[0x1da + 70] = 0xff;
        assert_eq!(absent(&normal(), Some(&k)), None);
        let mut k = kernel();
        k[0x1da + 51] = 0xbf;
        assert_eq!(absent(&normal(), Some(&k)), None);
        assert_eq!(absent(&normal(), Some(&kernel()[..0x3ffc])), None);
    }
}

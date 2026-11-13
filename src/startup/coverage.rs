//! Stored-code getter-reference inventory. An inventory is not an absence proof.
//! Every dynamic caller and literal-pointer lifetime still needs a bound consumer
//! contract before a no-fixed-requirement observation can authorize a policy.
//!
//! Instruction boundaries (index loads before a call, argument suffixes, the
//! JSR/JMP operand-word test) come from one linear forward decode per stored
//! region, not a control-flow walk from proven routine entries. Inline data
//! that decodes cleanly can keep that decode misaligned until a byte fails to
//! decode; the analysis relies only on the resulting spurious refusals. A false
//! boundary needs an operand tail matching a load pattern while the decode is
//! misaligned, which compiler-generated vendor code does not produce: this is
//! a limit against deliberately crafted firmware only, outside the analysis's
//! threat model. The audited corpus shows no such boundary.
use crate::image::layout::{self, Observation, Unresolved};
use alloc::vec::Vec;

/// Typed Normal-startup scope and remaining native obligations.
pub mod assessment;
/// Native Normal boot-chain bodies and opaque handoff dependencies.
pub mod boot;
mod boot_shapes;
/// Native copied checksum routine used by startup rejection predicates.
pub mod copied_checksum;
/// Fixed-bank predicates whose paired resident owns image validation.
pub mod fixed_bank_resident;
mod legacy_aliases;
mod legacy_kernel {
    //! Immutable SAT1 paired authority. The held native boundary includes the
    //! resident copy/clear implementations, formatter and rejection transfer.
    use super::legacy_sinks::Profile;
    use sha2::{Digest, Sha256};

    /// Exact resident component and the Normal operands consumed by its native gates.
    /// This is a local boundary receipt, not a cold-start or host READY theorem.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct KernelBoundary {
        identity: [u8; 32],
        normal_length: usize,
        descriptor: usize,
        normal_root_call: core::ops::Range<usize>,
        descriptor_compare: core::ops::Range<usize>,
        destination_compare: core::ops::Range<usize>,
        length_gate: core::ops::Range<usize>,
        image_sum: core::ops::Range<usize>,
        copied_ram: core::ops::Range<u32>,
        rejection_entry: core::ops::Range<usize>,
    }

    impl KernelBoundary {
        pub(super) fn bind(normal: &[u8], kernel: &[u8], profile: &Profile) -> Option<Self> {
            let identity: [u8; 32] = Sha256::digest(kernel).into();
            if kernel.len() != 0x10000 || identity != profile.kernel_hash {
                return None;
            }
            let result = Self {
                identity,
                normal_length: profile.length,
                descriptor: profile.descriptor,
                normal_root_call: 0x1a4..0x1a8,
                descriptor_compare: 0x11a..0x142,
                destination_compare: 0x142..0x174,
                length_gate: 0x174..0x1a4,
                image_sum: if profile.name == "w26" {
                    0x555a..0x5588
                } else {
                    0x555e..0x558c
                },
                copied_ram: 0x670..0xa72,
                rejection_entry: 0x1d8..0x220,
            };
            result.accepts(normal, kernel).then_some(result)
        }

        /// Check the actual final descriptor/destination and bounded checksum extent.
        /// Normal's checksum may still await the existing integrity repair owner.
        pub fn accepts(&self, normal: &[u8], kernel: &[u8]) -> bool {
            let identity: [u8; 32] = Sha256::digest(kernel).into();
            if kernel.len() != 0x10000
                || identity != self.identity
                || normal.len() != self.normal_length
                || normal.len() & 3 != 0
                || normal.len() > 0x3c0000
            {
                return false;
            }
            let Some(length) = normal.get(0x14..0x18) else {
                return false;
            };
            if u32::from_be_bytes(length.try_into().unwrap()) as usize != normal.len() {
                return false;
            }
            // Native Normal bytes are sign extended, resident bytes zero extended.
            // High-bit bytes must not acquire equality from a byte-only comparison.
            let equal = |a: &[u8], b: &[u8]| {
                a.len() == b.len()
                    && a.iter()
                        .zip(b)
                        .all(|(&x, &y)| i32::from(x as i8) == i32::from(y))
            };
            equal(
                &normal[..16],
                &kernel[self.descriptor..self.descriptor + 16],
            ) && equal(&normal[0x18..0x20], &kernel[0x1008..0x1010])
                && kernel[0x1a4..0x1a8] == [0x5e, 0x41, 0, 0x28]
        }

        /// Required after established checksum repair and authenticated paired decode.
        /// Authentication itself belongs to the actual envelope receiver authority.
        pub fn final_integrity(&self, normal: &[u8], kernel: &[u8]) -> bool {
            self.accepts(normal, kernel) && zero_sum(kernel) && zero_sum(normal)
        }
    }

    fn zero_sum(bytes: &[u8]) -> bool {
        bytes.len() & 3 == 0
            && bytes.chunks_exact(4).fold(0u32, |sum, word| {
                sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
            }) == 0
    }
}
mod legacy_shapes;
/// Exact paired SAT1 local predicate preservation.
pub mod legacy_sinks;
/// Native Normal control-flow graph with conditional call-return frontiers.
pub mod native_flow;
/// Pair-bound local predicate preservation, separate from rooted acceptance.
pub mod preservation;
mod sink_boundaries;
mod sink_boundary_shapes;
mod sink_declarations;
#[cfg(all(test, feature = "envelope"))]
pub(crate) mod sink_fixture;
/// Native rejection sink ownership and independently owned predicates.
pub mod sinks;

/// Bounded local parameter-index dataflow.
pub mod argument;
/// Bulk parameter cache and exact byte accessor bindings.
pub mod cache;
/// Bounded control flow for indirect cache consumers.
pub mod cache_flow;
/// Caller inputs to byte and paired-byte cache helpers.
pub mod cache_helpers;
/// Combined local direct-cache index coverage.
pub mod cache_indices;
/// ROM cache index tables and their caller mode selectors.
pub mod cache_rom;
mod cache_rom_shapes;
mod cache_shapes {
    // Generated from independently traced complete bulk-cache loops.
    use super::cache::Shape;
    pub(super) const SHAPES: &[Shape] = &[
        Shape {
            bytes: &[
                0x18, 0xdd, 0x0c, 0xde, 0x17, 0x56, 0x0d, 0x60, 0x79, 0x10, 0x00, 0x60, 0x5e, 0x00,
                0x00, 0x00, 0x0d, 0x04, 0x10, 0x16, 0x0d, 0x60, 0x17, 0xf0, 0x78, 0x00, 0x6a, 0xa4,
                0x00, 0x00, 0x00, 0x00, 0x0d, 0x60, 0x0b, 0x50, 0x17, 0xf0, 0x78, 0x00, 0x6a, 0xac,
                0x00, 0x00, 0x00, 0x00, 0x0a, 0x0d, 0xad, 0x40, 0x45, 0xce,
            ],
            call: 12,
            ram: [28, 42],
            argument_register: 0,
        },
        Shape {
            bytes: &[
                0x18, 0xdd, 0x0c, 0xdb, 0x17, 0x53, 0x0d, 0x31, 0x79, 0x11, 0x00, 0x60, 0x0f, 0xe0,
                0x5e, 0x00, 0x00, 0x00, 0x0d, 0x04, 0x10, 0x13, 0x0d, 0x31, 0x17, 0xf1, 0x78, 0x10,
                0x6a, 0xa4, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x31, 0x0b, 0x51, 0x17, 0xf1, 0x78, 0x10,
                0x6a, 0xac, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0d, 0xad, 0x40, 0x45, 0xcc,
            ],
            call: 14,
            ram: [30, 44],
            argument_register: 1,
        },
    ];
}
/// Native cache writers and retained aliases.
pub mod cache_writers;
/// Audited direct-consumer block bindings and explicit uncovered references.
pub mod direct;
mod direct_shapes;
/// Packed high-word getter arguments.
pub mod packed;
/// Complete getter-pointer lifetimes and required tails/callers.
pub mod pointer;
mod pointer_shapes;
/// Native parameter-comparison queue and cold-start clearing.
pub mod queue;
/// R1 paired-cache initializer and saved-register graph.
pub mod r1_pair;
mod r1_pair_shapes {
    // Generated from complete native R1 pair/initializer/constructor evidence.
    use super::r1_pair::Pattern;
    #[rustfmt::skip]
    pub(super) const PAIR: Pattern = Pattern {
        bytes: &[
            0x6d, 0xf3, 0x01, 0x20, 0x6d, 0xf4, 0x0f, 0xa5, 0x0d, 0x13, 0x0f, 0x86, 0x5e, 0x00, 0x00,
            0x00, 0x0c, 0xbc, 0x0c, 0xb9, 0x5e, 0x00, 0x00, 0x00, 0x0c, 0x8b, 0x0c, 0x83, 0x5e, 0x00,
            0x00, 0x00, 0x0a, 0x0c, 0x0c, 0xc9, 0x5e, 0x00, 0x00, 0x00, 0x0c, 0x81, 0xab, 0xff, 0x46,
            0x04, 0xa1, 0xff, 0x47, 0x10, 0x0f, 0xe0, 0x0f, 0xd2, 0x0c, 0x39, 0x55, 0x14, 0x0c, 0x88,
            0x47, 0x04, 0xf8, 0x01, 0x40, 0x04, 0x18, 0x88, 0x68, 0xd8, 0x01, 0x20, 0x6d, 0x76, 0x6d,
            0x73, 0x54, 0x70,
        ],
        masks: &[(13, 3), (21, 3), (29, 3), (37, 3)],
    };
    #[rustfmt::skip]
    pub(super) const INITIALIZER: Pattern = Pattern {
        bytes: &[
            0x01, 0x00, 0x6d, 0xf3, 0x7a, 0x03, 0x00, 0x00, 0x00, 0x00, 0x6b, 0x20, 0x00, 0x00, 0x00,
            0x00, 0x46, 0x10, 0x79, 0x01, 0x00, 0x01, 0x6b, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xb0,
            0x5e, 0x00, 0x00, 0x00, 0x0f, 0xb0, 0x01, 0x00, 0x6d, 0x73, 0x54, 0x70,
        ],
        masks: &[(6, 4), (12, 4), (24, 4), (31, 3)],
    };
    #[rustfmt::skip]
    pub(super) const CONSTRUCTOR: Pattern = Pattern {
        bytes: &[
            0x01, 0x00, 0x6d, 0xf3, 0x01, 0x20, 0x6d, 0xf4, 0x0f, 0x84, 0x46, 0x0e, 0x1a, 0x80, 0xf8,
            0x06, 0x5e, 0x00, 0x00, 0x00, 0x0f, 0x84, 0x58, 0x70, 0x00, 0xa2, 0x7a, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x69, 0xc1, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x11, 0x7a,
            0x03, 0x00, 0x00, 0x00, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x01, 0x40, 0x5d, 0x30, 0x7a, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x7a, 0x05, 0x00, 0x00, 0x01, 0xc0, 0x0f, 0xd2, 0x19, 0x11, 0x5d,
            0x30, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x11, 0x1a, 0xe6, 0xfe, 0x20, 0x0f, 0xe2,
            0x5d, 0x30, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x11, 0x7a, 0x02, 0x00, 0x00, 0x01,
            0x14, 0x5d, 0x30, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x11, 0x1a, 0xa2, 0xfa, 0x10,
            0x5d, 0x30, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xd2, 0x19, 0x11, 0x5d, 0x30, 0x7a,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xd2, 0x19, 0x11, 0x5d, 0x30, 0x7a, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x19, 0x11, 0x0f, 0xe2, 0x5d, 0x30, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19,
            0x11, 0x1a, 0xa2, 0xfa, 0x80, 0x5d, 0x30, 0x18, 0x99, 0x6e, 0xc9, 0x00, 0x04, 0x5e, 0x00,
            0x00, 0x00, 0x18, 0x99, 0x6e, 0xc9, 0x00, 0x05, 0x0f, 0xc0, 0x01, 0x20, 0x6d, 0x76, 0x01,
            0x00, 0x6d, 0x73, 0x54, 0x70,
        ],
        masks: &[
            (17, 3), (28, 4), (38, 4), (46, 4), (60, 4), (78, 4), (94, 4), (110, 4), (124, 4), (136, 4),
            (148, 4), (160, 4), (179, 3),
        ],
    };
    #[rustfmt::skip]
    pub(super) const FILL: &[u8] = &[
        0x6d, 0xf3, 0x0f, 0xa2, 0x47, 0x28, 0x0a, 0xa0, 0x73, 0x08, 0x47, 0x06, 0x6c, 0x89, 0x1b, 0x72,
        0x47, 0x1c, 0x0c, 0x91, 0x0d, 0x19, 0x0d, 0x23, 0x11, 0x72, 0x47, 0x08, 0x01, 0x00, 0x6d, 0x81,
        0x1b, 0x72, 0x46, 0xf8, 0xeb, 0x03, 0x47, 0x06, 0x6c, 0x89, 0x1a, 0x0b, 0x46, 0xfa, 0x6d, 0x73,
        0x54, 0x70,
    ];
}
/// Native ROM-index loop with its complete seven-word source table.
pub mod table;
mod table_shape {
    // Generated from independently traced native table-loop evidence.
    pub(super) const BYTES: &[u8] = &[
        0x01, 0x10, 0x6d, 0xf4, 0x79, 0x37, 0x00, 0x0e, 0x79, 0x00, 0x00, 0xb1, 0x5e, 0x54, 0xdc, 0xf2,
        0x79, 0x20, 0xff, 0xff, 0x47, 0x46, 0x79, 0x20, 0x00, 0x01, 0x47, 0x40, 0x0f, 0xf1, 0x7a, 0x00,
        0x00, 0x5a, 0x20, 0x7a, 0x1a, 0xa2, 0xfa, 0x0e, 0x5e, 0x10, 0x58, 0xdc, 0x18, 0xcc, 0x1a, 0xd5,
        0x0c, 0xcd, 0x10, 0x35, 0x0f, 0xf0, 0x0a, 0xd0, 0x69, 0x00, 0x5e, 0x54, 0xdc, 0xf2, 0x78, 0x50,
        0x6b, 0xa0, 0x00, 0xa0, 0x41, 0xba, 0x0a, 0x0c, 0xac, 0x07, 0x45, 0xe2, 0xf8, 0x01, 0x6a, 0xa8,
        0x00, 0xa0, 0xce, 0xdd, 0x7a, 0x00, 0x00, 0x91, 0x01, 0xa8, 0x40, 0x46, 0x79, 0x00, 0x00, 0x15,
        0x7a, 0x01, 0x00, 0xa0, 0x41, 0xba, 0x69, 0x90, 0xf8, 0x52, 0x6f, 0x90, 0x00, 0x02, 0x79, 0x00,
        0x01, 0x00, 0x6f, 0x90, 0x00, 0x04, 0x79, 0x00, 0x00, 0x26, 0x6f, 0x90, 0x00, 0x06, 0xf8, 0xa7,
        0x6f, 0x90, 0x00, 0x08, 0x79, 0x00, 0x01, 0xe6, 0x6f, 0x90, 0x00, 0x0a, 0x79, 0x00, 0x00, 0x15,
        0x6f, 0x90, 0x00, 0x0c, 0x18, 0x88, 0x6a, 0xa8, 0x00, 0xa0, 0xce, 0xdd, 0x7a, 0x00, 0x00, 0x91,
        0x01, 0x93, 0x5e, 0x54, 0xbd, 0xa8, 0x5e, 0x4f, 0x50, 0x58, 0x79, 0x17, 0x00, 0x0e, 0x01, 0x10,
        0x6d, 0x75, 0x54, 0x70,
    ];
    pub(super) const RELOCATIONS: &[(usize, usize, usize)] = &[
        (13, 3, 0),
        (32, 4, 1),
        (59, 3, 0),
        (66, 4, 2),
        (80, 4, 3),
        (86, 4, 4),
        (98, 4, 2),
        (152, 4, 3),
        (158, 4, 5),
        (163, 3, 6),
        (167, 3, 7),
    ];
}
/// Two-word parameter formatting functions and their caller arguments.
pub mod word_pair;

/// Native direct or relative call encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallKind {
    /// Absolute 24-bit JSR.
    Absolute,
    /// Signed eight-bit BSR.
    Relative8,
    /// Signed sixteen-bit BSR.
    Relative16,
}
/// An aligned native call-site reference to the proven getter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Call {
    /// Decoded Normal byte offset.
    pub offset: usize,
    /// Native instruction encoding.
    pub kind: CallKind,
    /// Immediate index load decoded directly before the call, if present. This
    /// is not a CFG proof that every incoming path executes that load.
    pub preceding_index_load: Option<u16>,
}
/// A literal getter address loaded into an extended register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pointer {
    /// Decoded Normal byte offset of MOV.L.
    pub offset: usize,
    /// Extended register number, zero through seven.
    pub register: u8,
}
/// Bounded references; does not cover arbitrary computed pointers or aliases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct References {
    /// Getter CPU address established by its complete native reader graph.
    pub getter: u32,
    /// Native parameter-index word register, R0 or R1.
    pub argument_register: u8,
    /// Absolute and relative calls in stored regions, in offset order.
    pub calls: Vec<Call>,
    /// Immediate pointer loads in stored regions, in offset order.
    pub pointers: Vec<Pointer>,
}

/// Instruction boundaries of one stored region from a single forward decode
/// that starts at the region's first aligned byte. After undecodable bytes the
/// decode resumes only at the next aligned RTS; an RTS-shaped word inside a
/// decoded instruction is an operand and never restarts it. A byte pattern
/// ending at a call is an instruction only when this decode places the call
/// directly after it. The sweep is extended lazily and runs at most once.
pub(super) struct Anchors<'a> {
    region: &'a [u8],
    /// Decoded instruction starts, ascending.
    starts: Vec<u32>,
    /// Starts at which the decode resumed after undecodable bytes.
    resumed: alloc::collections::BTreeSet<u32>,
    cursor: usize,
}
impl<'a> Anchors<'a> {
    /// `base` is the region's offset in decoded Normal, fixing its alignment.
    pub(super) fn new(region: &'a [u8], base: usize) -> Self {
        Self {
            region,
            starts: Vec::new(),
            resumed: alloc::collections::BTreeSet::new(),
            cursor: base & 1,
        }
    }
    fn extend(&mut self, to: usize) {
        while self.cursor <= to && self.cursor < self.region.len() {
            let at = self.cursor;
            // The shared decoder's length recognizer; operands are not needed.
            match h8_asm::isa::insn_len(
                &self.region[at..],
                h8_asm::Target::H8S2000,
                h8_asm::Mode::Advanced,
            ) {
                Some(len) if len > 0 => {
                    self.starts.push(at as u32);
                    self.cursor = at + len;
                }
                _ => {
                    let resume = (at + 2..self.region.len().saturating_sub(1))
                        .step_by(2)
                        .find(|&j| self.region[j..j + 2] == [0x54, 0x70]);
                    let Some(resume) = resume else {
                        self.cursor = self.region.len();
                        break;
                    };
                    self.resumed.insert(resume as u32);
                    self.cursor = resume;
                }
            }
        }
    }
    /// Whether `local` starts a decoded instruction.
    pub(super) fn starts_at(&mut self, local: usize) -> bool {
        self.extend(local);
        u32::try_from(local).is_ok_and(|l| self.starts.binary_search(&l).is_ok())
    }
    /// Region offset of the decoded instruction ending exactly at `local`, or
    /// None when `local` is not on the decoded boundary chain.
    pub(super) fn previous(&mut self, local: usize) -> Option<usize> {
        self.extend(local);
        let local = u32::try_from(local).ok()?;
        let k = self.starts.binary_search(&local).ok()?;
        if self.resumed.contains(&local) {
            return None;
        }
        self.starts.get(k.checked_sub(1)?).map(|&p| p as usize)
    }
    /// Whether `local` is the address word of a decoded absolute JSR/JMP.
    pub(super) fn call_operand(&mut self, local: usize) -> bool {
        local >= 2
            && matches!(self.region[local - 2], 0x5a | 0x5e)
            && self.starts_at(local - 2)
            && !self.starts_at(local)
    }
}

/// CPU target of an aligned BRA/BRN/Bcc (eight- or sixteen-bit displacement)
/// starting at decoded Normal offset `at`, if `bytes` begins with one. Callers
/// drop it only when [`Anchors::call_operand`] proves it is a JSR/JMP operand.
pub(super) fn branch_target(bytes: &[u8], at: usize) -> Option<i64> {
    match bytes {
        [0x40..=0x4f, disp, ..] => Some(0x410000 + at as i64 + 2 + i64::from(*disp as i8)),
        [0x58, condition, high, low, ..] if condition & 15 == 0 => {
            Some(0x410000 + at as i64 + 4 + i64::from(i16::from_be_bytes([*high, *low])))
        }
        _ => None,
    }
}

/// Enumerate instruction-shaped references to the exact proven Normal getter.
/// Compressed payload bytes are excluded. This makes no claim about complete
/// function reachability, pointer use, cached data or startup acceptance.
pub fn references(normal: &[u8]) -> Observation<References> {
    match references_in(normal) {
        Observation::Known((references, _)) => Observation::Known(references),
        Observation::Unresolved(reason) => Observation::Unresolved(reason),
        Observation::Conflicting => Observation::Conflicting,
    }
}

/// [`references`] with the regions it decoded, so callers need not inflate the
/// COMP streams a second time.
pub(super) fn references_in(normal: &[u8]) -> Observation<(References, crate::image::Regions<'_>)> {
    let (getter, argument_register) = match layout::normal_reader(normal) {
        Observation::Known((entry, register, _)) => (entry, register),
        Observation::Unresolved(reason) => return Observation::Unresolved(reason),
        Observation::Conflicting => return Observation::Conflicting,
    };
    let Some(regions) = crate::image::regions(normal) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    let mut result = References {
        getter,
        argument_register,
        calls: Vec::new(),
        pointers: Vec::new(),
    };
    for region in &regions.stored {
        let start = region.as_ptr() as usize - normal.as_ptr() as usize;
        let mut anchors = Anchors::new(region, start);
        for local in (start & 1..region.len()).step_by(2) {
            let at = start + local;
            let bytes = &region[local..];
            let call = if bytes.len() >= 4 && bytes[0] == 0x5e {
                Some((
                    CallKind::Absolute,
                    u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as i64,
                ))
            } else if bytes.len() >= 2 && bytes[0] == 0x55 {
                Some((
                    CallKind::Relative8,
                    0x410000 + at as i64 + 2 + i64::from(bytes[1] as i8),
                ))
            } else if bytes.len() >= 4 && bytes[..2] == [0x5c, 0] {
                Some((
                    CallKind::Relative16,
                    0x410000 + at as i64 + 4 + i64::from(i16::from_be_bytes([bytes[2], bytes[3]])),
                ))
            } else {
                None
            };
            if let Some((kind, _)) = call.filter(|(_, target)| *target == i64::from(getter)) {
                let preceding_index_load = local
                    .checked_sub(4)
                    .filter(|&p| anchors.previous(local) == Some(p))
                    .and_then(|p| {
                        (region[p..p + 2] == [0x79, argument_register])
                            .then(|| u16::from_be_bytes([region[p + 2], region[p + 3]]))
                    });
                result.calls.push(Call {
                    offset: at,
                    kind,
                    preceding_index_load,
                });
            }
            if bytes.len() >= 6
                && bytes[0] == 0x7a
                && bytes[1] <= 7
                && u32::from_be_bytes(bytes[2..6].try_into().unwrap()) == getter
            {
                result.pointers.push(Pointer {
                    offset: at,
                    register: bytes[1],
                });
            }
        }
    }
    Observation::Known((result, regions))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absolute_relative_and_pointer_forms_preserve_native_coordinates() {
        let mut raw = alloc::vec![0xff; 0x2000];
        layout::install_test_layout(&mut raw, 0x1000);
        raw[0x80..0x88].copy_from_slice(&[0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0]);
        raw[0x90..0x94].copy_from_slice(&[0x5c, 0, 0x0f, 0x6c]);
        raw[0xa0..0xa6].copy_from_slice(&[0x7a, 5, 0, 0x41, 0x10, 0]);
        raw[0xfd0..0xfd2].copy_from_slice(&[0x55, 0x2e]);
        let Observation::Known(found) = references(&raw) else {
            panic!("fixture");
        };
        assert_eq!(
            found.calls,
            alloc::vec![
                Call {
                    offset: 0x84,
                    kind: CallKind::Absolute,
                    preceding_index_load: Some(0x9f)
                },
                Call {
                    offset: 0x90,
                    kind: CallKind::Relative16,
                    preceding_index_load: None
                },
                Call {
                    offset: 0xfd0,
                    kind: CallKind::Relative8,
                    preceding_index_load: None
                },
            ]
        );
        assert_eq!(
            found.pointers,
            alloc::vec![Pointer {
                offset: 0xa0,
                register: 5
            }]
        );
        raw[0x81] = 1;
        let Observation::Known(found) = references(&raw) else {
            panic!("fixture");
        };
        assert_eq!(found.calls[0].preceding_index_load, None);
        // MOV.L #H'7900009F,ER0 holds the load bytes as its operand.
        raw[0x7e..0x82].copy_from_slice(&[0x7a, 0, 0x79, 0]);
        let Observation::Known(found) = references(&raw) else {
            panic!("fixture");
        };
        assert_eq!(found.calls[0].offset, 0x84);
        assert_eq!(found.calls[0].preceding_index_load, None);
        raw[0x1000] ^= 1;
        assert!(!matches!(references(&raw), Observation::Known(_)));
    }
}

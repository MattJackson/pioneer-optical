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
mod legacy_kernel;
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
mod cache_shapes;
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
mod r1_pair_shapes;
/// Native ROM-index loop with its complete seven-word source table.
pub mod table;
mod table_shape;
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

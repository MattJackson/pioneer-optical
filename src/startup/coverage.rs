//! Stored-code getter-reference inventory. An inventory is not an absence proof.
//! Every dynamic caller and literal-pointer lifetime still needs a bound consumer
//! contract before a no-fixed-requirement observation can authorize a policy.
use crate::image::layout::{self, Observation, Unresolved};
use alloc::vec::Vec;

/// Typed Normal-startup scope and remaining native obligations.
pub mod assessment;
/// Native Normal boot-chain bodies and opaque handoff dependencies.
pub mod boot;
mod boot_shapes;
/// Native Normal control-flow graph with conditional call-return frontiers.
pub mod native_flow;

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
    /// Contiguous immediate index load, if present. This is not a CFG proof
    /// that every incoming path executes that load.
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

/// Enumerate instruction-shaped references to the exact proven Normal getter.
/// Compressed payload bytes are excluded. This makes no claim about complete
/// function reachability, pointer use, cached data or startup acceptance.
pub fn references(normal: &[u8]) -> Observation<References> {
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
    for region in regions.stored {
        let start = region.as_ptr() as usize - normal.as_ptr() as usize;
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
            if let Some((kind, target)) = call.filter(|(_, target)| *target == i64::from(getter)) {
                debug_assert_eq!(target, i64::from(getter));
                let preceding_index_load = local.checked_sub(4).and_then(|p| {
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
    Observation::Known(result)
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
        raw[0x1000] ^= 1;
        assert!(!matches!(references(&raw), Observation::Known(_)));
    }
}

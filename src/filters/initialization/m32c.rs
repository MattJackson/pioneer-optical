//! Complete observed M32C initialization blocks, with ordered native writes.
//! This contract concerns this block, not every later reset or resident action.
use crate::image::layout::{Observation, Unresolved};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Op {
    Write8(u32, u8),
    Write16(u32, u16),
    SetBit(u32, u8),
    Update8(u32, u8, u8),
}
pub(super) struct Shape {
    pub bytes: &'static [u8],
    pub operations: &'static [Op],
}
#[path = "m32c_shapes.rs"]
mod shapes;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Evidence {
    pub offset: usize,
    pub bytes: usize,
    pub operations: Vec<Op>,
}
/// Bind one complete observed initialization block. Duplicated or incompatible
/// blocks retain ambiguity; a missing pattern never supplies an empty program.
pub(super) fn discover(normal: &[u8]) -> Observation<Evidence> {
    let mut found = None;
    for shape in shapes::SHAPES {
        for (offset, bytes) in normal.windows(shape.bytes.len()).enumerate() {
            if bytes != shape.bytes {
                continue;
            }
            if found.is_some() {
                return Observation::Unresolved(Unresolved::AmbiguousReader);
            }
            found = Some(Evidence {
                offset,
                bytes: bytes.len(),
                operations: shape.operations.to_vec(),
            });
        }
    }
    match found {
        Some(value) => Observation::Known(value),
        None => Observation::Unresolved(Unresolved::ReaderNotRecognized),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_instruction_and_scalar_is_bound_and_offsets_are_not_values() {
        for shape in shapes::SHAPES {
            let mut normal = alloc::vec![0xff; 0x2000];
            normal[0x100..0x100 + shape.bytes.len()].copy_from_slice(shape.bytes);
            let Observation::Known(a) = discover(&normal) else {
                panic!("program");
            };
            normal[0x100..0x100 + shape.bytes.len()].fill(0xff);
            normal[0x400..0x400 + shape.bytes.len()].copy_from_slice(shape.bytes);
            let Observation::Known(b) = discover(&normal) else {
                panic!("relocated program");
            };
            assert_eq!(a.operations, b.operations);
            assert_ne!(a.offset, b.offset);
            for i in 0..shape.bytes.len() {
                normal[0x400 + i] ^= 1;
                assert!(
                    !matches!(discover(&normal), Observation::Known(_)),
                    "byte {i}"
                );
                normal[0x400 + i] ^= 1;
            }
            normal[0x800..0x800 + shape.bytes.len()].copy_from_slice(shape.bytes);
            assert!(!matches!(discover(&normal), Observation::Known(_)));
        }
    }
    #[test]
    fn three_programs_retain_their_actual_register_differences() {
        let programs: Vec<_> = shapes::SHAPES.iter().map(|s| s.operations).collect();
        assert_eq!(programs.len(), 3);
        for i in 0..programs.len() {
            for j in i + 1..programs.len() {
                assert_ne!(programs[i], programs[j]);
            }
        }
    }
}

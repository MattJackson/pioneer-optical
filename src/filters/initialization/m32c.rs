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
mod shapes {
    // Complete observed M32C initialization blocks. Native instruction offsets
    // identify evidence and never become semantic identity values.
    use super::{Op, Shape};
    pub(super) const SHAPES: &[Shape] = &[
        Shape {
            bytes: &[
                0x12, 0x90, 0x0, 0x12, 0x72, 0x0, 0xf6, 0xe1, 0x48, 0x1, 0x14, 0x4c, 0x1, 0x90,
                0xf6, 0xe4, 0x49, 0x1, 0x12, 0x90, 0x0, 0x12, 0x72, 0x0, 0x14, 0x37, 0x1, 0x40,
                0x15, 0x28, 0x1, 0x7b, 0x2, 0x12, 0x8c, 0x0, 0x14, 0x38, 0x1, 0x40, 0x15, 0x2a,
                0x1, 0x33, 0x6, 0xf6, 0xe7, 0x6e, 0x0, 0xd6, 0xfa, 0x20, 0x1, 0x14, 0x3c, 0x1,
                0x46, 0x14, 0x3b, 0x1, 0x42, 0x12, 0x94, 0x0, 0xf6, 0xe2, 0x3d, 0x1, 0x12, 0x96,
                0x0, 0x14, 0x17, 0x1, 0x2b, 0x14, 0x14, 0x1, 0x11, 0x18, 0x16, 0x1, 0x4c, 0x87,
                0x44, 0x58, 0x10, 0x16, 0x1,
            ],
            operations: &[
                Op::Write8(0x90, 0x0),
                Op::Write8(0x72, 0x0),
                Op::Write8(0x148, 0x1),
                Op::Write8(0x14c, 0x90),
                Op::Write8(0x149, 0x4),
                Op::Write8(0x90, 0x0),
                Op::Write8(0x72, 0x0),
                Op::Write8(0x137, 0x40),
                Op::Write16(0x128, 0x27b),
                Op::Write8(0x8c, 0x0),
                Op::Write8(0x138, 0x40),
                Op::Write16(0x12a, 0x633),
                Op::Write8(0x6e, 0x7),
                Op::SetBit(0x120, 2),
                Op::Write8(0x13c, 0x46),
                Op::Write8(0x13b, 0x42),
                Op::Write8(0x94, 0x0),
                Op::Write8(0x13d, 0x2),
                Op::Write8(0x96, 0x0),
                Op::Write8(0x117, 0x2b),
                Op::Write8(0x114, 0x11),
                Op::Update8(0x116, 0x87, 0x58),
            ],
        },
        Shape {
            bytes: &[
                0x12, 0x90, 0x0, 0x12, 0x72, 0x0, 0xf6, 0xe1, 0x48, 0x1, 0x14, 0x4c, 0x1, 0x90,
                0xf6, 0xe4, 0x49, 0x1, 0x12, 0x90, 0x0, 0x12, 0x72, 0x0, 0x14, 0x37, 0x1, 0x40,
                0x15, 0x28, 0x1, 0x7b, 0x2, 0x12, 0x8c, 0x0, 0x14, 0x38, 0x1, 0x40, 0x15, 0x2a,
                0x1, 0x33, 0x6, 0xf6, 0xe7, 0x6e, 0x0, 0xd6, 0xfa, 0x20, 0x1, 0x14, 0x3c, 0x1,
                0x86, 0xf6, 0xe2, 0x76, 0x0, 0x14, 0x3b, 0x1, 0x42, 0x12, 0x94, 0x0, 0xf6, 0xe2,
                0x3d, 0x1, 0x12, 0x96, 0x0, 0x14, 0x17, 0x1, 0x2b, 0x14, 0x14, 0x1, 0x11, 0x18,
                0x16, 0x1, 0x4c, 0x87, 0x44, 0x58, 0x10, 0x16, 0x1,
            ],
            operations: &[
                Op::Write8(0x90, 0x0),
                Op::Write8(0x72, 0x0),
                Op::Write8(0x148, 0x1),
                Op::Write8(0x14c, 0x90),
                Op::Write8(0x149, 0x4),
                Op::Write8(0x90, 0x0),
                Op::Write8(0x72, 0x0),
                Op::Write8(0x137, 0x40),
                Op::Write16(0x128, 0x27b),
                Op::Write8(0x8c, 0x0),
                Op::Write8(0x138, 0x40),
                Op::Write16(0x12a, 0x633),
                Op::Write8(0x6e, 0x7),
                Op::SetBit(0x120, 2),
                Op::Write8(0x13c, 0x86),
                Op::Write8(0x76, 0x2),
                Op::Write8(0x13b, 0x42),
                Op::Write8(0x94, 0x0),
                Op::Write8(0x13d, 0x2),
                Op::Write8(0x96, 0x0),
                Op::Write8(0x117, 0x2b),
                Op::Write8(0x114, 0x11),
                Op::Update8(0x116, 0x87, 0x58),
            ],
        },
        Shape {
            bytes: &[
                0x12, 0x90, 0x0, 0x12, 0x72, 0x0, 0xf6, 0xe1, 0x48, 0x1, 0x14, 0x4c, 0x1, 0x90,
                0x14, 0x49, 0x1, 0x9, 0x12, 0x90, 0x0, 0x12, 0x72, 0x0, 0x14, 0x37, 0x1, 0x40,
                0x15, 0x28, 0x1, 0x97, 0x6, 0x12, 0x8c, 0x0, 0x12, 0x38, 0x1, 0x15, 0x2a, 0x1,
                0x4b, 0x84, 0xf6, 0xe7, 0x6e, 0x0, 0xd6, 0xfa, 0x20, 0x1, 0x14, 0x3c, 0x1, 0x86,
                0x14, 0x3b, 0x1, 0x42, 0x12, 0x94, 0x0, 0xf6, 0xe2, 0x3d, 0x1, 0x12, 0x96, 0x0,
                0x14, 0x17, 0x1, 0x2b, 0x14, 0x14, 0x1, 0x21, 0x18, 0x16, 0x1, 0x4c, 0x87, 0x44,
                0x58, 0x10, 0x16, 0x1,
            ],
            operations: &[
                Op::Write8(0x90, 0x0),
                Op::Write8(0x72, 0x0),
                Op::Write8(0x148, 0x1),
                Op::Write8(0x14c, 0x90),
                Op::Write8(0x149, 0x9),
                Op::Write8(0x90, 0x0),
                Op::Write8(0x72, 0x0),
                Op::Write8(0x137, 0x40),
                Op::Write16(0x128, 0x697),
                Op::Write8(0x8c, 0x0),
                Op::Write8(0x138, 0x0),
                Op::Write16(0x12a, 0x844b),
                Op::Write8(0x6e, 0x7),
                Op::SetBit(0x120, 2),
                Op::Write8(0x13c, 0x86),
                Op::Write8(0x13b, 0x42),
                Op::Write8(0x94, 0x0),
                Op::Write8(0x13d, 0x2),
                Op::Write8(0x96, 0x0),
                Op::Write8(0x117, 0x2b),
                Op::Write8(0x114, 0x21),
                Op::Update8(0x116, 0x87, 0x58),
            ],
        },
    ];
}
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

/// First reviewed initialization block shape.
#[cfg(test)]
pub(super) fn fixture() -> &'static Shape {
    &shapes::SHAPES[0]
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

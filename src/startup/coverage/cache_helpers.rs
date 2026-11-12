//! R0 byte and paired-byte cache consumers, with exact native bodies and local
//! caller inputs. Conversion calls occur after the cache reads; their effects
//! and arbitrary computed aliases remain separate coverage obligations.
use super::{cache_flow::Reference, CallKind};
use crate::image::layout::Observation;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
/// Number of cache bytes read from the caller-supplied low-byte index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// One byte.
    Byte,
    /// The input byte and the following byte, wrapping at 256.
    Pair,
}
/// Native caller and its contiguous argument definition, if recognized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    /// Decoded Normal call offset.
    pub offset: usize,
    /// Absolute or relative native encoding.
    pub kind: CallKind,
    /// Byte indices from the index load decoded directly before the call;
    /// None means the input still needs dataflow analysis.
    pub indices: Option<Vec<u8>>,
}
/// Exact wrapper and its incoming-reference observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Helper {
    /// Decoded Normal entry offset.
    pub offset: usize,
    /// Native cache-read operation.
    pub kind: Kind,
    /// Exact cache-accessor call offsets.
    pub reads: Vec<usize>,
    /// Helper called after all cache reads; its own behavior is a separate audit.
    pub converter: usize,
    /// Incoming call observations; absence does not establish unreachability.
    pub callers: Vec<Caller>,
    /// Literal pointers and absolute jumps still requiring interpretation.
    pub other_references: Vec<Reference>,
}
struct Shape {
    kind: Kind,
    bytes: &'static [u8],
    reads: &'static [usize],
    converter: usize,
}
const SHAPES: &[Shape] = &[
    Shape {
        kind: Kind::Byte,
        bytes: &[
            0x01, 0x00, 0x6d, 0xf3, 0x0f, 0x93, 0x5e, 0x54, 0xde, 0x38, 0xa8, 0xff, 0x47, 0x0e,
            0x0f, 0xb1, 0x5e, 0x54, 0xeb, 0x0e, 0x0c, 0x88, 0x47, 0x04, 0xf8, 0x01, 0x40, 0x04,
            0x18, 0x88, 0x68, 0xb8, 0x01, 0x00, 0x6d, 0x73, 0x54, 0x70,
        ],
        reads: &[6],
        converter: 16,
    },
    Shape {
        kind: Kind::Pair,
        bytes: &[
            0x01, 0x20, 0x6d, 0xf4, 0x0f, 0x95, 0x0c, 0x8e, 0x5e, 0x54, 0xde, 0x38, 0x0c, 0x86,
            0x0c, 0x8c, 0x0a, 0x0e, 0x0c, 0xe8, 0x5e, 0x54, 0xde, 0x38, 0x0c, 0x80, 0xa6, 0xff,
            0x46, 0x04, 0xa0, 0xff, 0x47, 0x0e, 0x0f, 0xd1, 0x0c, 0xc8, 0x55, 0x36, 0x0c, 0x88,
            0x47, 0x04, 0xf8, 0x01, 0x40, 0x04, 0x18, 0x88, 0x68, 0xd8, 0x01, 0x20, 0x6d, 0x76,
            0x54, 0x70,
        ],
        reads: &[8, 20],
        converter: 38,
    },
];
impl Shape {
    fn bind(&self, bytes: &[u8], accessor: u32, at: usize) -> Option<usize> {
        if bytes.len() != self.bytes.len() {
            return None;
        }
        if bytes[..4] != self.bytes[..4] {
            return None;
        }
        if !bytes.iter().zip(self.bytes).enumerate().all(|(i, (a, b))| {
            if let Some(&call) = self.reads.iter().find(|&&c| (c + 1..c + 4).contains(&i)) {
                *a == accessor.to_be_bytes()[i - call]
            } else if (self.kind == Kind::Byte
                && (self.converter + 1..self.converter + 4).contains(&i))
                || (self.kind == Kind::Pair && i == self.converter + 1)
            {
                true
            } else {
                a == b
            }
        }) {
            return None;
        }
        if self.kind == Kind::Byte {
            let c = self.converter;
            let target = u32::from_be_bytes([0, bytes[c + 1], bytes[c + 2], bytes[c + 3]]);
            if target & 1 != 0 {
                return None;
            }
            (target as usize).checked_sub(0x410000)
        } else {
            let target = at.checked_add_signed(
                self.converter as isize + 2 + bytes[self.converter + 1] as i8 as isize,
            )?;
            (target & 1 == 0).then_some(target)
        }
    }
}
/// Bind R0 byte/pair helper inputs through complete stored bodies and the exact
/// proven cache accessor. R1 helpers require additional initializer contracts.
pub fn discover(normal: &[u8]) -> Observation<Vec<Helper>> {
    let (caches, regions) = match super::cache::discover_in(normal) {
        Observation::Known(v) => v,
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    let mut helpers = Vec::new();
    for cache in caches {
        // One pass binds every R0 accessor: each candidate body's first read
        // operand selects the accessor, ordered as one pass per accessor was.
        let accessors: BTreeMap<u32, usize> = cache
            .accessors
            .iter()
            .filter(|a| a.argument_register == 0)
            .enumerate()
            .map(|(rank, a)| (0x410000 + a.offset as u32, rank))
            .collect();
        let mut bound = Vec::new();
        for region in &regions.stored {
            #[cfg(test)]
            tests::BIND_SCANS.with(|c| c.set(c.get() + 1));
            let base = region.as_ptr() as usize - normal.as_ptr() as usize;
            for local in (base & 1..region.len()).step_by(2) {
                for shape in SHAPES {
                    let Some(bytes) = region.get(local..local + shape.bytes.len()) else {
                        continue;
                    };
                    let read = shape.reads[0];
                    let accessor =
                        u32::from_be_bytes([0, bytes[read + 1], bytes[read + 2], bytes[read + 3]]);
                    let Some(&rank) = accessors.get(&accessor) else {
                        continue;
                    };
                    let Some(converter) = shape.bind(bytes, accessor, base + local) else {
                        continue;
                    };
                    if converter >= normal.len() {
                        continue;
                    }
                    bound.push((
                        rank,
                        Helper {
                            offset: base + local,
                            kind: shape.kind,
                            reads: shape.reads.iter().map(|o| base + local + o).collect(),
                            converter,
                            callers: Vec::new(),
                            other_references: Vec::new(),
                        },
                    ));
                }
            }
        }
        bound.sort_by_key(|&(rank, _)| rank);
        helpers.extend(bound.into_iter().map(|(_, helper)| helper));
    }
    if helpers.is_empty() {
        return Observation::Known(helpers);
    }
    #[cfg(test)]
    tests::REFERENCE_SCANS.with(|c| c.set(c.get() + 1));
    // One pass over the image; each decoded target is looked up among helper
    // entries, preserving each helper's per-region reference order.
    let mut by_target: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (i, helper) in helpers.iter().enumerate() {
        by_target
            .entry(0x410000 + helper.offset as u32)
            .or_default()
            .push(i);
    }
    let lookup = |target: i64| {
        u32::try_from(target)
            .ok()
            .and_then(|t| by_target.get(&t))
            .map_or(&[][..], Vec::as_slice)
    };
    for region in &regions.stored {
        let base = region.as_ptr() as usize - normal.as_ptr() as usize;
        let mut anchors = super::Anchors::new(region, base);
        for local in (base & 1..region.len()).step_by(2) {
            let b = &region[local..];
            let at = base + local;
            let absolute = |b: &[u8]| u32::from_be_bytes([0, b[1], b[2], b[3]]) as i64;
            let call = if b.len() >= 4 && b[0] == 0x5e {
                Some((CallKind::Absolute, absolute(b)))
            } else if b.len() >= 2 && b[0] == 0x55 {
                Some((
                    CallKind::Relative8,
                    0x410000 + at as i64 + 2 + i64::from(b[1] as i8),
                ))
            } else if b.len() >= 4 && b[..2] == [0x5c, 0] {
                Some((
                    CallKind::Relative16,
                    0x410000 + at as i64 + 4 + i64::from(i16::from_be_bytes([b[2], b[3]])),
                ))
            } else {
                None
            };
            if let Some((kind, target)) = call.filter(|&(_, t)| !lookup(t).is_empty()) {
                // The index load must be the decoded instruction ending at the
                // call, never operand bytes of a longer earlier instruction.
                let index = anchors
                    .previous(local)
                    .and_then(|p| match region[p..local] {
                        [0x79, 0, _, i] | [0xf8, i] => Some(i),
                        _ => None,
                    });
                for &h in lookup(target) {
                    let helper = &mut helpers[h];
                    let indices = index.map(|i| {
                        if helper.kind == Kind::Pair {
                            alloc::vec![i, i.wrapping_add(1)]
                        } else {
                            alloc::vec![i]
                        }
                    });
                    helper.callers.push(Caller {
                        offset: at,
                        kind,
                        indices,
                    });
                }
            }
            if b.len() >= 4 && b[0] == 0x5a {
                for &h in lookup(absolute(b)) {
                    helpers[h].other_references.push(Reference::Stored(at));
                }
            }
            // Branch tail transfers enter with an unrecorded caller input.
            if let Some(target) = super::branch_target(b, at)
                .filter(|&t| !lookup(t).is_empty() && !anchors.call_operand(local))
            {
                for &h in lookup(target) {
                    helpers[h].other_references.push(Reference::Stored(at));
                }
            }
        }
        for (i, b) in region.windows(4).enumerate() {
            for &h in lookup(i64::from(u32::from_be_bytes(b.try_into().unwrap()))) {
                helpers[h]
                    .other_references
                    .push(Reference::Stored(base + i));
            }
        }
    }
    for (stream, bytes) in regions.expanded.iter().enumerate() {
        for (offset, b) in bytes.windows(4).enumerate() {
            for &h in lookup(i64::from(u32::from_be_bytes(b.try_into().unwrap()))) {
                helpers[h]
                    .other_references
                    .push(Reference::Expanded { stream, offset });
            }
        }
    }
    Observation::Known(helpers)
}
#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use core::cell::Cell;
    std::thread_local! {
        pub(super) static REFERENCE_SCANS: Cell<usize> = const { Cell::new(0) };
        pub(super) static BIND_SCANS: Cell<usize> = const { Cell::new(0) };
    }
    #[test]
    fn branch_transfers_to_a_helper_entry_stay_visible() {
        for (at, branch) in [
            (0x3f80, &[0x40, 0x7e][..]),
            (0x3f80, &[0x47, 0x7e]),
            (0x100, &[0x58, 0x60, 0x3e, 0xfc]),
        ] {
            let mut raw = fixture(&SHAPES[0]);
            raw[at..at + branch.len()].copy_from_slice(branch);
            let Observation::Known(found) = discover(&raw) else {
                panic!("fixture")
            };
            assert_eq!(
                found[0].other_references,
                alloc::vec![Reference::Stored(at)],
                "branch {branch:02x?}"
            );
        }
    }
    #[test]
    fn helper_binding_scans_the_image_once_for_every_accessor() {
        let mut raw = fixture(&SHAPES[0]);
        let leaf = raw[0x3000..0x3010].to_vec();
        for at in [0x3100, 0x3200, 0x3300] {
            raw[at..at + leaf.len()].copy_from_slice(&leaf);
        }
        install(&mut raw, &SHAPES[1], 0x5000);
        // The earlier helper reads a later accessor.
        raw[0x4000 + 7..0x4000 + 10].copy_from_slice(&[0x41, 0x32, 0]);
        BIND_SCANS.with(|c| c.set(0));
        let Observation::Known(found) = discover(&raw) else {
            panic!("fixture")
        };
        // Order follows the accessor, then the image position.
        assert_eq!(
            found.iter().map(|h| h.offset).collect::<Vec<_>>(),
            alloc::vec![0x5000, 0x4000]
        );
        assert_eq!(BIND_SCANS.with(Cell::get), 1);
    }
    /// Bulk loop, R0 accessor at 0x3000 and `shape` at 0x4000 reading it.
    fn fixture(shape: &Shape) -> Vec<u8> {
        let mut raw = alloc::vec![0xff;0x8000];
        crate::image::layout::install_test_layout(&mut raw, 0x1000);
        // RTS anchoring the decoded caller code that tests place from 0x72.
        raw[0x70..0x72].copy_from_slice(&[0x54, 0x70]);
        let bulk = &super::super::cache_shapes::SHAPES[0];
        raw[0x2000..0x2000 + bulk.bytes.len()].copy_from_slice(bulk.bytes);
        raw[0x2000 + bulk.call + 1..0x2000 + bulk.call + 4].copy_from_slice(&[0x41, 0x10, 0]);
        for p in bulk.ram {
            raw[0x2000 + p..0x2000 + p + 4].copy_from_slice(&0xa01000u32.to_be_bytes());
        }
        raw[0x3000..0x3010].copy_from_slice(&[
            0x0c, 0x89, 0x1a, 0x80, 0x0c, 0x98, 0x78, 0, 0x6a, 0x28, 0, 0xa0, 0x10, 0, 0x54, 0x70,
        ]);
        install(&mut raw, shape, 0x4000);
        raw
    }
    /// Byte-helper fixture whose caller at 0x84 loads `index` with MOV.W. A
    /// preceding RTS bounds the helper as a direct accessor-reading function.
    pub(in super::super) fn byte_helper_fixture(index: u8) -> Vec<u8> {
        let mut raw = fixture(&SHAPES[0]);
        raw[0x3ffe..0x4000].copy_from_slice(&[0x54, 0x70]);
        raw[0x80..0x88].copy_from_slice(&[0x79, 0, 0, index, 0x5e, 0x41, 0x40, 0]);
        raw
    }
    fn install(raw: &mut [u8], shape: &Shape, at: usize) {
        raw[at..at + shape.bytes.len()].copy_from_slice(shape.bytes);
        for &call in shape.reads {
            raw[at + call + 1..at + call + 4].copy_from_slice(&[0x41, 0x30, 0]);
        }
        if shape.kind == Kind::Byte {
            raw[at + 0x11..at + 0x14].copy_from_slice(&[0x41, 0x60, 0]);
        }
    }
    #[test]
    fn helper_references_are_collected_in_one_image_pass() {
        let mut raw = fixture(&SHAPES[0]);
        install(&mut raw, &SHAPES[0], 0x4800);
        install(&mut raw, &SHAPES[1], 0x5000);
        raw[0x80..0x88].copy_from_slice(&[0x79, 0, 0, 126, 0x5e, 0x41, 0x40, 0]);
        raw[0x88..0x8a].copy_from_slice(&[0x55, 0x76]); // BSR 0x4800 is out of range
        raw[0x90..0x94].copy_from_slice(&[0x5a, 0x41, 0x48, 0]);
        raw[0x94..0x98].copy_from_slice(&[0x5c, 0, 0x4f, 0x68]); // BSR.W 0x5000
        raw[0x98..0x9c].copy_from_slice(&0x414000u32.to_be_bytes());
        REFERENCE_SCANS.with(|c| c.set(0));
        let Observation::Known(found) = discover(&raw) else {
            panic!("fixture")
        };
        assert_eq!(
            found
                .iter()
                .map(|h| (h.offset, h.callers.clone(), h.other_references.clone()))
                .collect::<Vec<_>>(),
            alloc::vec![
                (
                    0x4000,
                    alloc::vec![Caller {
                        offset: 0x84,
                        kind: CallKind::Absolute,
                        indices: Some(alloc::vec![126])
                    }],
                    alloc::vec![Reference::Stored(0x98)]
                ),
                (0x4800, Vec::new(), alloc::vec![Reference::Stored(0x90)]),
                (
                    0x5000,
                    alloc::vec![Caller {
                        offset: 0x94,
                        kind: CallKind::Relative16,
                        indices: None
                    }],
                    Vec::new()
                ),
            ]
        );
        assert!(REFERENCE_SCANS.with(Cell::get) <= 1);
    }
    #[test]
    fn index_loads_after_longer_instructions_resolve() {
        // Genuine streams whose preceding operand bytes happen to begin a
        // longer instruction; the index load itself is a real boundary.
        for prefix in [
            &[0x5e, 0x41, 0x6e, 0x12, 0xf8, 0x05][..], // JSR @0x416e12; MOV.B #5,R0L
            &[0x5e, 0x41, 0x5e, 0, 0x79, 0, 0, 0x05],  // JSR @0x415e00; MOV.W #5,R0
            &[0x7a, 0x01, 0, 0xa0, 0x7a, 0, 0xf8, 0x05], // MOV.L #0xa07a00,ER1; MOV.B #5,R0L
        ] {
            let mut raw = fixture(&SHAPES[0]);
            let call = 0x84;
            raw[call - prefix.len()..call].copy_from_slice(prefix);
            raw[call..call + 4].copy_from_slice(&[0x5e, 0x41, 0x40, 0]);
            let Observation::Known(found) = discover(&raw) else {
                panic!("fixture")
            };
            assert_eq!(found[0].callers[0].offset, call);
            assert_eq!(
                found[0].callers[0].indices,
                Some(alloc::vec![5]),
                "{prefix:02x?}"
            );
        }
    }
    #[test]
    fn operand_tails_of_earlier_instructions_are_not_index_loads() {
        for prefix in [
            &[0x6a, 0x08, 0xf8, 0x05][..],      // MOV.B @H'F805:16,R0L
            &[0x6b, 0x00, 0x79, 0x00, 0, 0x05], // MOV.W @H'7900:16,R0; data word
        ] {
            let mut raw = fixture(&SHAPES[0]);
            let call = 0x84;
            raw[call - prefix.len()..call].copy_from_slice(prefix);
            raw[call..call + 4].copy_from_slice(&[0x5e, 0x41, 0x40, 0]);
            let Observation::Known(found) = discover(&raw) else {
                panic!("fixture")
            };
            assert_eq!(found[0].callers[0].offset, call);
            assert_eq!(found[0].callers[0].indices, None, "{prefix:02x?}");
        }
        // An RTS-shaped operand word does not restart the decode:
        // MOV.W @H'5470F805:32,R0 is one instruction.
        let mut raw = fixture(&SHAPES[0]);
        raw[0x7e..0x88].copy_from_slice(&[0x6b, 0x20, 0x54, 0x70, 0xf8, 0x05, 0x5e, 0x41, 0x40, 0]);
        let Observation::Known(found) = discover(&raw) else {
            panic!("fixture")
        };
        assert_eq!(found[0].callers[0].offset, 0x84);
        assert_eq!(found[0].callers[0].indices, None);
    }
    #[test]
    fn converter_offsets_follow_each_native_call_encoding() {
        for (shape, expected) in SHAPES.iter().zip([0x6000, 0x4000 + 38 + 2 + 0x36]) {
            let mut raw = fixture(shape);
            let Observation::Known(found) = discover(&raw) else {
                panic!("fixture")
            };
            assert_eq!(found[0].converter, expected);
            if shape.kind == Kind::Byte {
                // Odd and out-of-image absolute targets bind no helper.
                for target in [0x416001u32, 0x410000 + raw.len() as u32] {
                    raw[0x4011..0x4014].copy_from_slice(&target.to_be_bytes()[1..]);
                    let Observation::Known(found) = discover(&raw) else {
                        panic!("fixture")
                    };
                    assert!(found.is_empty(), "{target:x}");
                }
            } else {
                raw[0x4000 + 39] = 0x37;
                let Observation::Known(found) = discover(&raw) else {
                    panic!("fixture")
                };
                assert!(found.is_empty());
            }
        }
    }
    #[test]
    fn relative_callers_resolve_their_targets_and_index_loads() {
        let mut raw = fixture(&SHAPES[0]);
        // RTS; MOV.B #126,R0L; BSR 0x4000
        raw[0x3f9e..0x3fa0].copy_from_slice(&[0x54, 0x70]);
        raw[0x3fa0..0x3fa4].copy_from_slice(&[0xf8, 0x7e, 0x55, 0x5c]);
        // MOV.W #126,R0; BSR.W 0x4000
        raw[0x100..0x108].copy_from_slice(&[0x79, 0, 0, 0x7e, 0x5c, 0, 0x3e, 0xf8]);
        let Observation::Known(found) = discover(&raw) else {
            panic!("fixture")
        };
        assert_eq!(
            found[0].callers,
            alloc::vec![
                Caller {
                    offset: 0x104,
                    kind: CallKind::Relative16,
                    indices: Some(alloc::vec![126])
                },
                Caller {
                    offset: 0x3fa2,
                    kind: CallKind::Relative8,
                    indices: Some(alloc::vec![126])
                },
            ]
        );
    }
    #[test]
    fn caller_changes_cache_009f_bytes_wraparound_and_aliases_stay_visible() {
        for shape in SHAPES {
            let mut raw = alloc::vec![0xff;0x8000];
            crate::image::layout::install_test_layout(&mut raw, 0x1000);
            raw[0x70..0x72].copy_from_slice(&[0x54, 0x70]);
            let bulk = &super::super::cache_shapes::SHAPES[0];
            raw[0x2000..0x2000 + bulk.bytes.len()].copy_from_slice(bulk.bytes);
            raw[0x2000 + bulk.call + 1..0x2000 + bulk.call + 4].copy_from_slice(&[0x41, 0x10, 0]);
            for p in bulk.ram {
                raw[0x2000 + p..0x2000 + p + 4].copy_from_slice(&0xa01000u32.to_be_bytes());
            }
            raw[0x3000..0x3010].copy_from_slice(&[
                0x0c, 0x89, 0x1a, 0x80, 0x0c, 0x98, 0x78, 0, 0x6a, 0x28, 0, 0xa0, 0x10, 0, 0x54,
                0x70,
            ]);
            raw[0x4000..0x4000 + shape.bytes.len()].copy_from_slice(shape.bytes);
            for &call in shape.reads {
                raw[0x4000 + call + 1..0x4000 + call + 4].copy_from_slice(&[0x41, 0x30, 0]);
            }
            if shape.kind == Kind::Byte {
                raw[0x4011..0x4014].copy_from_slice(&[0x41, 0x60, 0]);
            }
            raw[0x80..0x88].copy_from_slice(&[0x79, 0, 1, 126, 0x5e, 0x41, 0x40, 0]);
            for index in [126, 127, 255] {
                raw[0x83] = index;
                let Observation::Known(found) = discover(&raw) else {
                    panic!("fixture")
                };
                assert_eq!(found.len(), 1);
                let expected = if shape.kind == Kind::Pair {
                    alloc::vec![index, index.wrapping_add(1)]
                } else {
                    alloc::vec![index]
                };
                assert_eq!(found[0].callers[0].indices, Some(expected));
            }
            raw[0x81] = 1;
            raw[0x91..0x95].copy_from_slice(&0x414000u32.to_be_bytes());
            let Observation::Known(found) = discover(&raw) else {
                panic!("fixture")
            };
            assert_eq!(found[0].callers[0].indices, None);
            assert_eq!(
                found[0].other_references,
                alloc::vec![Reference::Stored(0x91)]
            );
        }
    }
    #[test]
    fn every_body_byte_except_relocated_converter_is_bound() {
        for shape in SHAPES {
            let mut b = shape.bytes.to_vec();
            let accessor = 0x411000u32;
            for &c in shape.reads {
                b[c + 1..c + 4].copy_from_slice(&accessor.to_be_bytes()[1..]);
            }
            assert!(shape.bind(&b, accessor, 0x2000).is_some());
            for i in 0..b.len() {
                if (shape.kind == Kind::Byte
                    && (shape.converter + 1..shape.converter + 4).contains(&i))
                    || (shape.kind == Kind::Pair && i == shape.converter + 1)
                {
                    continue;
                }
                b[i] ^= 1;
                assert!(shape.bind(&b, accessor, 0x2000).is_none(), "{i}");
                b[i] ^= 1;
            }
        }
    }
}

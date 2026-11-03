//! Native cache RAM aliases. Complete write-only blocks are bound to the actual
//! bulk-cache RAM base. Unrecognized occurrences remain explicit obligations;
//! absence of a matching block never establishes startup acceptance.
use super::{cache, cache_flow::Reference};
use crate::image::layout::Observation;
use alloc::vec::Vec;

/// Semantics of a completely bound native cache address occurrence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A byte store in the complete 0x60..0x9f bulk loop.
    BulkStore,
    /// A complete byte accessor leaf; consumers are a separate obligation.
    Accessor,
    /// Guarded pair of byte writes from the requested word, with no cache read.
    Update,
    /// Zero exactly 128 cache bytes through the bound native memset leaf.
    Zero,
}
/// An actual 24-bit cache-address occurrence, including interior byte aliases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alias {
    /// Native location; expanded streams retain their own coordinate space.
    pub reference: Reference,
    /// Offset from the bound RAM base, zero through 127.
    pub cache_offset: u8,
    /// None retains the address occurrence as an uncovered obligation.
    pub kind: Option<Kind>,
}
/// A complete recognized update or zero block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Writer {
    /// Decoded Normal entry offset.
    pub offset: usize,
    /// Exclusive end of the complete bound instruction sequence.
    pub end: usize,
    /// Established write behavior.
    pub kind: Kind,
    /// Actual memset CPU entry for Zero; no external callee for Update.
    pub memset: Option<u32>,
    /// Branch destinations outside the local write block, requiring path analysis.
    pub continuation_targets: Vec<u32>,
}
/// Cache alias inventory, with no whole-program computed-alias claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// RAM base established by the native bulk-reader graph.
    pub ram_base: u32,
    /// Complete native write blocks.
    pub writers: Vec<Writer>,
    /// Every literal address in the 128-byte cache in stored and expanded regions.
    pub aliases: Vec<Alias>,
}
struct Shape {
    bytes: &'static [u8],
    // Equal source addresses share a group. Only these address operands relocate.
    relocations: &'static [(usize, usize, usize)],
    cache_group: usize,
    memset_group: Option<usize>,
    branches: &'static [(usize, usize)],
    kind: Kind,
}
pub(super) const MEMSET: &[u8] = &[
    0x6d, 0xf3, 0x0f, 0xa2, 0x47, 0x28, 0x0a, 0xa0, 0x73, 0x08, 0x47, 0x06, 0x6c, 0x89, 0x1b, 0x72,
    0x47, 0x1c, 0x0c, 0x91, 0x0d, 0x19, 0x0d, 0x23, 0x11, 0x72, 0x47, 0x08, 0x01, 0x00, 0x6d, 0x81,
    0x1b, 0x72, 0x46, 0xf8, 0xeb, 0x03, 0x47, 0x06, 0x6c, 0x89, 0x1a, 0x0b, 0x46, 0xfa, 0x6d, 0x73,
    0x54, 0x70,
];
/// `stored` must be `image::regions(normal)?.stored`, decoded once by the caller.
pub(super) fn stored_at<'a>(
    normal: &'a [u8],
    stored: &[&[u8]],
    address: u32,
    len: usize,
) -> Option<&'a [u8]> {
    let at = address.checked_sub(0x410000)? as usize;
    let end = at.checked_add(len)?;
    stored
        .iter()
        .any(|r| {
            let start = r.as_ptr() as usize - normal.as_ptr() as usize;
            at >= start && end <= start + r.len()
        })
        .then(|| &normal[at..end])
}
/// Bind the entire native memset routine, including its register-save contract.
pub(super) fn is_memset(normal: &[u8], stored: &[&[u8]], address: u32) -> bool {
    stored_at(normal, stored, address, MEMSET.len()) == Some(MEMSET)
}
impl Shape {
    fn bind(&self, bytes: &[u8], at: usize, ram: u32) -> Option<(Option<u32>, Vec<u32>)> {
        if bytes.len() != self.bytes.len() {
            return None;
        }
        let mut groups: Vec<Option<u32>> =
            alloc::vec![None; self.relocations.iter().map(|r| r.2 + 1).max().unwrap_or(0)];
        for &(p, n, g) in self.relocations {
            let value = bytes[p..p + n]
                .iter()
                .fold(0, |a, &b| a * 256 + u32::from(b));
            if groups[g].is_some_and(|old| old != value) {
                return None;
            }
            groups[g] = Some(value);
        }
        if groups[self.cache_group] != Some(ram) {
            return None;
        }
        let mut targets = Vec::new();
        for &(p, n) in self.branches {
            let displacement = if n == 1 {
                i32::from(bytes[p] as i8)
            } else {
                i32::from(i16::from_be_bytes(bytes[p..p + 2].try_into().ok()?))
            };
            let target =
                (0x410000i64 + at as i64 + (p + n) as i64 + i64::from(displacement)) as u32;
            targets.push(target);
        }
        for (i, (&actual, &expected)) in bytes.iter().zip(self.bytes).enumerate() {
            if !self
                .relocations
                .iter()
                .any(|&(p, n, _)| (p..p + n).contains(&i))
                && !self.branches.iter().any(|&(p, n)| (p..p + n).contains(&i))
                && actual != expected
            {
                return None;
            }
        }
        // R1's two guards and final jump all return to the same queue loop.
        if !targets.is_empty() {
            let jump = self
                .relocations
                .iter()
                .find(|&&(p, n, _)| n == 3 && bytes[p - 1] == 0x5a)?;
            let target = groups[jump.2]?;
            if targets.iter().any(|&v| v != target) {
                return None;
            }
            targets.push(target);
        }
        Some((self.memset_group.and_then(|g| groups[g]), targets))
    }
}
const SHAPES: &[Shape] = &[
    Shape {
        bytes: &[
            0x79, 0x21, 0x00, 0x60, 0x45, 0x28, 0x79, 0x31, 0x00, 0x60, 0x0d, 0x18, 0x79, 0x21,
            0x00, 0x40, 0x44, 0x1c, 0x0d, 0x20, 0x10, 0x18, 0x0d, 0x81, 0x17, 0x71, 0x7a, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x0a, 0xa1, 0x68, 0x90, 0x0b, 0x58, 0x0d, 0x81, 0x17, 0x71,
            0x0a, 0xa1, 0x68, 0x98, 0x54, 0x70,
        ],
        relocations: &[(28, 4, 0)],
        cache_group: 0,
        memset_group: None,
        branches: &[],
        kind: Kind::Update,
    },
    Shape {
        bytes: &[
            0x7a, 0x03, 0x00, 0x00, 0x00, 0x00, 0x1a, 0xa2, 0xfa, 0x10, 0x5d, 0x30, 0x7a, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x19, 0x11, 0x7a, 0x02, 0x00, 0x00, 0x01, 0xc0, 0x5d, 0x30,
            0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x11, 0x1a, 0xa2, 0xfa, 0xe0, 0x5d, 0x30,
            0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x11, 0x1a, 0xa2, 0xfa, 0x20, 0x5d, 0x30,
            0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x11, 0x1a, 0xa2, 0xfa, 0x80, 0x5d, 0x30,
        ],
        relocations: &[(2, 4, 0), (14, 4, 1), (30, 4, 2), (44, 4, 3), (58, 4, 4)],
        cache_group: 4,
        memset_group: Some(0),
        branches: &[],
        kind: Kind::Zero,
    },
    Shape {
        bytes: &[
            0x79, 0x24, 0x00, 0x60, 0x58, 0x50, 0x00, 0x00, 0x79, 0x34, 0x00, 0x60, 0x0d, 0x48,
            0x79, 0x24, 0x00, 0x40, 0x58, 0x40, 0x00, 0x00, 0x0d, 0xc0, 0x10, 0x18, 0x0d, 0x81,
            0x17, 0x71, 0x7a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xa1, 0x68, 0x90, 0x0d, 0x81,
            0x0b, 0x51, 0x17, 0x71, 0x0a, 0xa1, 0x68, 0x98, 0x5a, 0x00, 0x00, 0x00,
        ],
        relocations: &[(32, 4, 0), (51, 3, 1)],
        cache_group: 0,
        memset_group: None,
        branches: &[(6, 2), (20, 2)],
        kind: Kind::Update,
    },
    Shape {
        bytes: &[
            0x7a, 0x03, 0x00, 0x00, 0x00, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x01, 0x40, 0x5d, 0x30,
            0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7a, 0x05, 0x00, 0x00, 0x01, 0xc0, 0x0f, 0xd2,
            0x19, 0x11, 0x5d, 0x30, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x11, 0x1a, 0xe6,
            0xfe, 0x20, 0x0f, 0xe2, 0x5d, 0x30, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x11,
            0x7a, 0x02, 0x00, 0x00, 0x01, 0x14, 0x5d, 0x30, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x19, 0x11, 0x1a, 0xa2, 0xfa, 0x10, 0x5d, 0x30, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0f, 0xd2, 0x19, 0x11, 0x5d, 0x30, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xd2,
            0x19, 0x11, 0x5d, 0x30, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x11, 0x0f, 0xe2,
            0x5d, 0x30, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x11, 0x1a, 0xa2, 0xfa, 0x80,
            0x5d, 0x30,
        ],
        relocations: &[
            (2, 4, 0),
            (16, 4, 1),
            (34, 4, 2),
            (50, 4, 3),
            (66, 4, 4),
            (80, 4, 5),
            (92, 4, 6),
            (104, 4, 7),
            (116, 4, 8),
        ],
        cache_group: 8,
        memset_group: Some(0),
        branches: &[],
        kind: Kind::Zero,
    },
];
/// Discover complete cache write contracts and classify all literal cache RAM
/// occurrences. Other computed aliases and accessor value consumers remain
/// separate obligations even when every literal occurrence is classified.
pub fn discover(normal: &[u8]) -> Observation<Vec<Evidence>> {
    let blocks = match cache::discover(normal) {
        Observation::Known(v) => v,
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    let regions = crate::image::regions(normal).expect("cache regions checked");
    let mut result = Vec::new();
    for block in blocks {
        let mut writers = Vec::new();
        for region in &regions.stored {
            let start = region.as_ptr() as usize - normal.as_ptr() as usize;
            for local in (start & 1..region.len()).step_by(2) {
                for shape in SHAPES {
                    let Some(bytes) = region.get(local..local + shape.bytes.len()) else {
                        continue;
                    };
                    if bytes[..2] != shape.bytes[..2] {
                        continue;
                    }
                    let Some((memset, continuation_targets)) =
                        shape.bind(bytes, start + local, block.ram_base)
                    else {
                        continue;
                    };
                    if memset.is_some_and(|target| !is_memset(normal, &regions.stored, target)) {
                        continue;
                    }
                    writers.push(Writer {
                        offset: start + local,
                        end: start + local + bytes.len(),
                        kind: shape.kind,
                        memset,
                        continuation_targets,
                    });
                }
            }
        }
        let mut aliases = Vec::new();
        // The bulk graph was already matched by cache::discover. Its two RAM
        // operand offsets are fixed by the register convention and loop length.
        let bulk_operands: [usize; 2] = if block.getter_call - block.offset == 12 {
            [28, 42]
        } else {
            [30, 44]
        };
        for region in &regions.stored {
            let start = region.as_ptr() as usize - normal.as_ptr() as usize;
            for (local, bytes) in region.windows(3).enumerate() {
                let value = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
                let Some(delta) = value.checked_sub(block.ram_base).filter(|&n| n < 128) else {
                    continue;
                };
                let at = start + local;
                let kind = if bulk_operands.iter().any(|&p| at == block.offset + p + 1) {
                    Some(Kind::BulkStore)
                } else if block
                    .accessors
                    .iter()
                    .any(|a| at == a.offset + if a.argument_register == 0 { 11 } else { 9 })
                {
                    Some(Kind::Accessor)
                } else {
                    writers
                        .iter()
                        .find(|w| at >= w.offset && at + 3 <= w.end)
                        .and_then(|w| {
                            let shape = SHAPES
                                .iter()
                                .find(|s| s.kind == w.kind && s.bytes.len() == w.end - w.offset)?;
                            shape
                                .relocations
                                .iter()
                                .any(|&(p, n, g)| {
                                    g == shape.cache_group && n == 4 && at == w.offset + p + 1
                                })
                                .then_some(w.kind)
                        })
                };
                aliases.push(Alias {
                    reference: Reference::Stored(at),
                    cache_offset: delta as u8,
                    kind,
                });
            }
        }
        for (stream, region) in regions.expanded.iter().enumerate() {
            for (offset, bytes) in region.windows(3).enumerate() {
                let value = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
                if let Some(delta) = value.checked_sub(block.ram_base).filter(|&n| n < 128) {
                    aliases.push(Alias {
                        reference: Reference::Expanded { stream, offset },
                        cache_offset: delta as u8,
                        kind: None,
                    });
                }
            }
        }
        result.push(Evidence {
            ram_base: block.ram_base,
            writers,
            aliases,
        });
    }
    Observation::Known(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn instantiated(shape: &Shape, at: usize, ram: u32) -> Vec<u8> {
        let mut bytes = shape.bytes.to_vec();
        for &(p, n, g) in shape.relocations {
            let value = if g == shape.cache_group {
                ram
            } else {
                0x500000 + g as u32 * 0x100
            };
            bytes[p..p + n].copy_from_slice(&value.to_be_bytes()[4 - n..]);
        }
        if !shape.branches.is_empty() {
            let jump = shape
                .relocations
                .iter()
                .find(|&&(p, n, _)| n == 3 && bytes[p - 1] == 0x5a)
                .unwrap();
            let target = (0x410000 + at - 20) as u32;
            bytes[jump.0..jump.0 + 3].copy_from_slice(&target.to_be_bytes()[1..]);
            for &(p, n) in shape.branches {
                assert_eq!(n, 2);
                let d = (i64::from(target) - 0x410000 - at as i64 - (p + n) as i64) as i16;
                bytes[p..p + n].copy_from_slice(&d.to_be_bytes());
            }
        }
        bytes
    }
    #[test]
    fn scalar_mutations_and_repeated_pointer_disagreement_fail() {
        for shape in SHAPES {
            let mut bytes = instantiated(shape, 0x1000, 0xa01000);
            assert!(shape.bind(&bytes, 0x1000, 0xa01000).is_some());
            for i in 0..bytes.len() {
                if shape
                    .relocations
                    .iter()
                    .any(|&(p, n, _)| (p..p + n).contains(&i))
                {
                    continue;
                }
                bytes[i] ^= 1;
                assert!(
                    shape.bind(&bytes, 0x1000, 0xa01000).is_none(),
                    "scalar/branch {i}"
                );
                bytes[i] ^= 1;
            }
            let p = shape
                .relocations
                .iter()
                .find(|r| r.2 == shape.cache_group)
                .unwrap()
                .0;
            bytes[p + 3] ^= 1;
            assert!(shape.bind(&bytes, 0x1000, 0xa01000).is_none());
        }
    }
    const RAM: u32 = 0xa01000;
    fn zero_writer(shape: &Shape, at: usize, memset: u32) -> Vec<u8> {
        let mut bytes = instantiated(shape, at, RAM);
        let g = shape.memset_group.unwrap();
        for &(p, n, _) in shape.relocations.iter().filter(|r| r.2 == g) {
            bytes[p..p + n].copy_from_slice(&memset.to_be_bytes()[4 - n..]);
        }
        bytes
    }
    /// Bulk loop at 0x2000, Update at 0x3000, branched Update at 0x3100,
    /// R0 accessor at 0x3800, MEMSET at 0x5000 and `zeros` Zero writers from 0x6000.
    fn writers_fixture(zeros: usize) -> Vec<u8> {
        let mut raw = alloc::vec![0xff; 0x8000];
        crate::image::layout::install_test_layout(&mut raw, 0x1000);
        let bulk = &super::super::cache_shapes::SHAPES[0];
        let at = 0x2000;
        raw[at..at + bulk.bytes.len()].copy_from_slice(bulk.bytes);
        raw[at + bulk.call + 1..at + bulk.call + 4].copy_from_slice(&[0x41, 0x10, 0]);
        for p in bulk.ram {
            raw[at + p..at + p + 4].copy_from_slice(&RAM.to_be_bytes());
        }
        for (shape, at) in [(&SHAPES[0], 0x3000), (&SHAPES[2], 0x3100)] {
            let code = instantiated(shape, at, RAM);
            raw[at..at + code.len()].copy_from_slice(&code);
        }
        // Native R0 byte accessor leaf (cache.rs R0 head, RAM base, RTS).
        let mut leaf = alloc::vec![0x0c, 0x89, 0x1a, 0x80, 0x0c, 0x98, 0x78, 0, 0x6a, 0x28];
        leaf.extend_from_slice(&RAM.to_be_bytes());
        leaf.extend_from_slice(&[0x54, 0x70]);
        raw[0x3800..0x3800 + leaf.len()].copy_from_slice(&leaf);
        raw[0x5000..0x5000 + MEMSET.len()].copy_from_slice(MEMSET);
        for k in 0..zeros {
            let at = 0x6000 + k * 0x50;
            let code = zero_writer(&SHAPES[1], at, 0x415000);
            raw[at..at + code.len()].copy_from_slice(&code);
        }
        raw
    }
    fn evidence(raw: &[u8]) -> Evidence {
        let Observation::Known(mut found) = discover(raw) else {
            panic!("fixture")
        };
        assert_eq!(found.len(), 1);
        found.remove(0)
    }
    fn alias_kind(evidence: &Evidence, at: usize) -> Option<Kind> {
        evidence
            .aliases
            .iter()
            .find(|a| a.reference == Reference::Stored(at))
            .unwrap_or_else(|| panic!("alias at {at:#x}"))
            .kind
    }
    #[test]
    fn repeated_zero_writers_decode_the_image_regions_a_fixed_number_of_times() {
        let reads = |zeros| {
            let raw = writers_fixture(zeros);
            crate::comp_streams::READS.with(|reads| reads.set(0));
            assert_eq!(
                evidence(&raw)
                    .writers
                    .iter()
                    .filter(|w| w.kind == Kind::Zero)
                    .count(),
                zeros
            );
            crate::comp_streams::READS.with(|reads| reads.get())
        };
        assert_eq!(reads(40), reads(1));
    }
    #[test]
    fn zero_writer_requires_the_exact_memset_callee() {
        let mut raw = writers_fixture(1);
        let found = evidence(&raw);
        let zero: Vec<_> = found
            .writers
            .iter()
            .filter(|w| w.kind == Kind::Zero)
            .collect();
        assert_eq!(zero.len(), 1);
        assert_eq!((zero[0].offset, zero[0].memset), (0x6000, Some(0x415000)));
        assert_eq!(alias_kind(&found, 0x6000 + 59), Some(Kind::Zero));
        let branched = found.writers.iter().find(|w| w.offset == 0x3100).unwrap();
        assert_eq!(branched.kind, Kind::Update);
        assert_eq!(branched.memset, None);
        assert_eq!(
            branched.continuation_targets,
            alloc::vec![0x410000 + 0x3100 - 20; 3]
        );
        for i in 0..MEMSET.len() {
            raw[0x5000 + i] ^= 1;
            let found = evidence(&raw);
            assert!(
                !found.writers.iter().any(|w| w.kind == Kind::Zero),
                "memset byte {i}"
            );
            assert_eq!(alias_kind(&found, 0x6000 + 59), None);
            raw[0x5000 + i] ^= 1;
        }
    }
    #[test]
    fn alias_kinds_follow_the_bound_operand_and_cache_range_is_exact() {
        let mut raw = writers_fixture(0);
        raw[0x4000..0x4006].copy_from_slice(&[0xa0, 0x10, 0x7f, 0xa0, 0x10, 0x00]);
        raw[0x4010..0x4013].copy_from_slice(&[0xa0, 0x10, 0x80]);
        raw[0x4020..0x4023].copy_from_slice(&[0xa0, 0x0f, 0xff]);
        let found = evidence(&raw);
        assert_eq!(alias_kind(&found, 0x2000 + 29), Some(Kind::BulkStore));
        assert_eq!(alias_kind(&found, 0x2000 + 43), Some(Kind::BulkStore));
        assert_eq!(alias_kind(&found, 0x3000 + 29), Some(Kind::Update));
        assert_eq!(alias_kind(&found, 0x3100 + 33), Some(Kind::Update));
        assert_eq!(alias_kind(&found, 0x3800 + 11), Some(Kind::Accessor));
        assert_eq!(alias_kind(&found, 0x4000), None);
        assert_eq!(alias_kind(&found, 0x4003), None);
        let a = |at| {
            found
                .aliases
                .iter()
                .find(|a| a.reference == Reference::Stored(at))
        };
        assert_eq!(a(0x4000).unwrap().cache_offset, 127);
        assert_eq!(a(0x4003).unwrap().cache_offset, 0);
        assert!(a(0x4010).is_none(), "ram_base + 128 is outside the cache");
        assert!(a(0x4020).is_none(), "ram_base - 1 is outside the cache");
    }
    #[test]
    fn all_cache_byte_aliases_stay_visible_and_memset_body_is_required() {
        let mut raw = alloc::vec![0xff;0x8000];
        crate::image::layout::install_test_layout(&mut raw, 0x1000);
        let bulk = &super::super::cache_shapes::SHAPES[0];
        let at = 0x2000;
        raw[at..at + bulk.bytes.len()].copy_from_slice(bulk.bytes);
        raw[at + bulk.call + 1..at + bulk.call + 4].copy_from_slice(&[0x41, 0x10, 0]);
        for p in bulk.ram {
            raw[at + p..at + p + 4].copy_from_slice(&0xa01000u32.to_be_bytes());
        }
        let update = &SHAPES[0];
        let code = instantiated(update, 0x3000, 0xa01000);
        raw[0x3000..0x3000 + code.len()].copy_from_slice(&code);
        raw[0x4000..0x4006].copy_from_slice(&[0xa0, 0x10, 0x7e, 0xa0, 0x10, 0x7f]);
        let Observation::Known(found) = discover(&raw) else {
            panic!("fixture")
        };
        assert_eq!(found[0].writers.len(), 1);
        assert!(found[0]
            .aliases
            .iter()
            .any(|a| a.cache_offset == 126 && a.kind.is_none()));
        assert!(found[0]
            .aliases
            .iter()
            .any(|a| a.cache_offset == 127 && a.kind.is_none()));
        raw[0x5000..0x5000 + MEMSET.len()].copy_from_slice(MEMSET);
        assert!(is_memset(&raw, &[&raw], 0x415000));
        for i in 0..MEMSET.len() {
            raw[0x5000 + i] ^= 1;
            assert!(!is_memset(&raw, &[&raw], 0x415000));
            raw[0x5000 + i] ^= 1;
        }
    }
}

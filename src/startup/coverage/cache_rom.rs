//! ROM-indexed cache readers. Only callers with a bound mode selector receive
//! an index set. Every other caller and pointer route remains explicit.
use super::{cache_flow::Reference, CallKind};
use crate::image::layout::Observation;
use alloc::vec::Vec;
pub(super) struct Pattern {
    pub bytes: &'static [u8],
    pub masks: &'static [(usize, usize)],
}
impl Pattern {
    fn matches(&self, b: &[u8]) -> bool {
        b.len() == self.bytes.len()
            && b[..self
                .masks
                .iter()
                .map(|&(at, _)| at)
                .min()
                .unwrap_or(b.len())]
                == self.bytes[..self
                    .masks
                    .iter()
                    .map(|&(at, _)| at)
                    .min()
                    .unwrap_or(b.len())]
            && b.iter().zip(self.bytes).enumerate().all(|(i, (a, c))| {
                a == c || self.masks.iter().any(|&(at, n)| (at..at + n).contains(&i))
            })
    }
}
pub(super) struct HelperShape {
    pub pattern: Pattern,
    pub table: usize,
    pub reads: &'static [usize],
    pub register: u8,
}
pub(super) struct SelectorShape {
    pub pattern: Pattern,
    pub validator: usize,
    pub helper: usize,
    pub register: u8,
}
pub(super) struct ValidatorShape {
    pub pattern: Pattern,
    pub pointers: &'static [usize],
}
/// An incoming call and the selector domain established by contiguous code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    /// Decoded Normal call offset.
    pub offset: usize,
    /// Native call encoding.
    pub kind: CallKind,
    /// Possible table slots; None retains unsupported incoming dataflow.
    pub modes: Option<Vec<u8>>,
    /// Entry of the exact validator preserving the saved mode, if used.
    pub validator: Option<usize>,
}
/// One native table reader, bound through its cache accessor and ROM bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Helper {
    /// Decoded Normal helper entry.
    pub offset: usize,
    /// Caller index register, R0L or R1L.
    pub argument_register: u8,
    /// Byte offset of the three native ROM table values.
    pub table_offset: usize,
    /// Actual first cache-byte indices, in table order.
    pub first_indices: [u8; 3],
    /// Both bound cache call offsets.
    pub reads: Vec<usize>,
    /// Whether the entire function or only its pre-read prefix is recognized.
    pub complete_body: bool,
    /// Incoming call observations; all must be resolved before claiming coverage.
    pub callers: Vec<Caller>,
    /// Uninterpreted literal pointers and jumps into the helper.
    pub other_references: Vec<Reference>,
    /// Literal words spanning a complete bound stack read/modify/write sequence,
    /// optionally followed by register zeroing. These paths do not load a pointer.
    pub instruction_overlaps: Vec<usize>,
}
impl Helper {
    /// Actual cache-byte indices selected by this helper's own recorded caller.
    /// Unknown modes, foreign callers and out-of-range slots stay unresolved.
    /// Each second byte wraps at 256, following the native byte increment.
    pub fn indices_for(&self, caller: &Caller) -> Option<Vec<u8>> {
        if !self.callers.contains(caller) {
            return None;
        }
        let mut indices = Vec::new();
        for &mode in caller.modes.as_ref()? {
            let first = *self.first_indices.get(usize::from(mode))?;
            indices.extend_from_slice(&[first, first.wrapping_add(1)]);
        }
        indices.sort_unstable();
        indices.dedup();
        Some(indices)
    }
}
fn word(b: &[u8]) -> u32 {
    b.iter().fold(0, |v, b| (v << 8) | u32::from(*b))
}
fn stored(normal: &[u8], at: usize, len: usize) -> bool {
    crate::image::regions(normal).is_some_and(|r| {
        r.stored.iter().any(|s| {
            let start = s.as_ptr() as usize - normal.as_ptr() as usize;
            at >= start && at.saturating_add(len) <= start + s.len()
        })
    })
}
fn validator(normal: &[u8], target: u32, accessor: u32) -> Option<usize> {
    let at = (target as usize).checked_sub(0x410000)?;
    for shape in super::cache_rom_shapes::VALIDATORS {
        let Some(b) = normal.get(at..at.checked_add(shape.pattern.bytes.len())?) else {
            continue;
        };
        if shape.pattern.matches(b)
            && stored(normal, at, b.len())
            && shape
                .pointers
                .iter()
                .all(|&p| word(&b[p..p + 4]) == accessor)
        {
            return Some(at);
        }
    }
    None
}
fn selector(
    normal: &[u8],
    region: &[u8],
    local: usize,
    register: u8,
    accessor: u32,
) -> (Option<Vec<u8>>, Option<usize>) {
    if local >= 2 && region[local - 2..local] == [0xf8 + register, 2] {
        return (Some(alloc::vec![2]), None);
    }
    for shape in super::cache_rom_shapes::SELECTORS
        .iter()
        .filter(|s| s.register == register)
    {
        let Some(start) = local.checked_sub(shape.helper) else {
            continue;
        };
        let Some(b) = region.get(start..start + shape.pattern.bytes.len()) else {
            continue;
        };
        if !shape.pattern.matches(b) {
            continue;
        }
        let target = word(&b[shape.validator + 1..shape.validator + 4]);
        if let Some(at) = validator(normal, target, accessor) {
            // Full selector has fixed branches and mode constants 0,1,2. Its
            // validator saves/restores ER4/5 and never writes ER3.
            return (Some(alloc::vec![0, 1, 2]), Some(at));
        }
    }
    (None, None)
}
/// Bind all held ROM-reader compiler forms, preserving changed ROM values and
/// unknown callers. Special long helpers expose a prefix contract only. This
/// establishes local cache indices, not startup reachability or global aliases.
pub fn discover(normal: &[u8]) -> Observation<Vec<Helper>> {
    let caches = match super::cache::discover(normal) {
        Observation::Known(v) => v,
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    let regions = crate::image::regions(normal).expect("bound cache regions");
    let mut helpers = Vec::new();
    for cache in caches {
        for accessor in cache.accessors.iter().filter(|a| a.argument_register == 0) {
            let target = 0x410000 + accessor.offset as u32;
            for region in &regions.stored {
                let base = region.as_ptr() as usize - normal.as_ptr() as usize;
                for local in (base & 1..region.len()).step_by(2) {
                    for shape in super::cache_rom_shapes::HELPERS {
                        let Some(b) = region.get(local..local + shape.pattern.bytes.len()) else {
                            continue;
                        };
                        if !shape.pattern.matches(b)
                            || !shape
                                .reads
                                .iter()
                                .all(|&p| word(&b[p + 1..p + 4]) == target)
                        {
                            continue;
                        }
                        let Some(table) =
                            (word(&b[shape.table..shape.table + 4]) as usize).checked_sub(0x410000)
                        else {
                            continue;
                        };
                        if !stored(normal, table, 3) {
                            continue;
                        }
                        let Some(values) = normal.get(table..table + 3) else {
                            continue;
                        };
                        helpers.push(Helper {
                            offset: base + local,
                            argument_register: shape.register,
                            table_offset: table,
                            first_indices: values.try_into().unwrap(),
                            reads: shape.reads.iter().map(|p| base + local + p).collect(),
                            complete_body: b.ends_with(&[0x54, 0x70]),
                            callers: Vec::new(),
                            other_references: Vec::new(),
                            instruction_overlaps: Vec::new(),
                        });
                    }
                }
            }
            for h in helpers.iter_mut().filter(|h| h.callers.is_empty()) {
                let entry = 0x410000 + h.offset as i64;
                for region in &regions.stored {
                    let base = region.as_ptr() as usize - normal.as_ptr() as usize;
                    for local in (base & 1..region.len()).step_by(2) {
                        let b = &region[local..];
                        let at = base + local;
                        let absolute = |b: &[u8]| word(&b[1..4]) as i64;
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
                                0x410000
                                    + at as i64
                                    + 4
                                    + i64::from(i16::from_be_bytes([b[2], b[3]])),
                            ))
                        } else {
                            None
                        };
                        if let Some((kind, _)) = call.filter(|(_, t)| *t == entry) {
                            let (modes, validator) =
                                selector(normal, region, local, h.argument_register, target);
                            h.callers.push(Caller {
                                offset: at,
                                kind,
                                modes,
                                validator,
                            });
                        }
                        if b.len() >= 4 && b[0] == 0x5a && absolute(b) == entry {
                            h.other_references.push(Reference::Stored(at));
                        }
                    }
                    for (i, b) in region.windows(4).enumerate() {
                        if b == (entry as u32).to_be_bytes() {
                            let stack_increment = i >= 2
                                && region.get(i - 2..i + 8)
                                    == Some(&[0x6e, 0x70, 0, 0x54, 0x0a, 0, 0x6e, 0xf0, 0, 0x54]);
                            if (base + i) & 1 == 0
                                && (stack_increment
                                    || (i >= 8
                                        && region.get(i - 8..i + 4)
                                            == Some(&[
                                                0x6e, 0x7a, 0, 0x54, 0x70, 0x1a, 0x6e, 0xfa, 0,
                                                0x54, 0x1a, 0xc4,
                                            ])))
                            {
                                h.instruction_overlaps.push(base + i);
                            } else {
                                h.other_references.push(Reference::Stored(base + i));
                            }
                        }
                    }
                }
                for (stream, b) in regions.expanded.iter().enumerate() {
                    for (offset, b) in b.windows(4).enumerate() {
                        if b == (entry as u32).to_be_bytes() {
                            h.other_references
                                .push(Reference::Expanded { stream, offset });
                        }
                    }
                }
            }
        }
    }
    Observation::Known(helpers)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_fixed_instruction_in_each_native_form_is_required() {
        for p in super::super::cache_rom_shapes::HELPERS
            .iter()
            .map(|s| &s.pattern)
            .chain(
                super::super::cache_rom_shapes::SELECTORS
                    .iter()
                    .map(|s| &s.pattern),
            )
            .chain(
                super::super::cache_rom_shapes::VALIDATORS
                    .iter()
                    .map(|s| &s.pattern),
            )
        {
            let mut b = p.bytes.to_vec();
            assert!(p.matches(&b));
            for i in 0..b.len() {
                if p.masks.iter().any(|&(a, n)| (a..a + n).contains(&i)) {
                    continue;
                }
                b[i] ^= 1;
                assert!(!p.matches(&b), "byte {i}");
                b[i] ^= 1;
            }
        }
    }
    fn fixture() -> Vec<u8> {
        let mut raw = alloc::vec![0xff;0x8000];
        crate::image::layout::install_test_layout(&mut raw, 0x1000);
        let bulk = &super::super::cache_shapes::SHAPES[0];
        raw[0x2000..0x2000 + bulk.bytes.len()].copy_from_slice(bulk.bytes);
        raw[0x2000 + bulk.call + 1..0x2000 + bulk.call + 4].copy_from_slice(&[0x41, 0x10, 0]);
        for at in bulk.ram {
            raw[0x2000 + at..0x2000 + at + 4].copy_from_slice(&0xa01000u32.to_be_bytes());
        }
        raw[0x2800..0x2810].copy_from_slice(&[
            0x0c, 0x89, 0x1a, 0x80, 0x0c, 0x98, 0x78, 0, 0x6a, 0x28, 0, 0xa0, 0x10, 0, 0x54, 0x70,
        ]);
        let h = &super::super::cache_rom_shapes::HELPERS[0];
        raw[0x4000..0x4000 + h.pattern.bytes.len()].copy_from_slice(h.pattern.bytes);
        raw[0x4000 + h.table..0x4004 + h.table].copy_from_slice(&0x415000u32.to_be_bytes());
        for &c in h.reads {
            raw[0x4001 + c..0x4004 + c].copy_from_slice(&[0x41, 0x28, 0]);
        }
        raw[0x5000..0x5003].copy_from_slice(&[116, 114, 112]);
        let v = &super::super::cache_rom_shapes::VALIDATORS[0];
        raw[0x6000..0x6000 + v.pattern.bytes.len()].copy_from_slice(v.pattern.bytes);
        for &p in v.pointers {
            raw[0x6000 + p..0x6004 + p].copy_from_slice(&0x412800u32.to_be_bytes());
        }
        let s = &super::super::cache_rom_shapes::SELECTORS[0];
        raw[0x800..0x800 + s.pattern.bytes.len()].copy_from_slice(s.pattern.bytes);
        raw[0x801 + s.validator..0x804 + s.validator].copy_from_slice(&[0x41, 0x60, 0]);
        raw[0x801 + s.helper..0x804 + s.helper].copy_from_slice(&[0x41, 0x40, 0]);
        raw
    }
    #[test]
    fn changed_tables_are_visible_and_broken_dependencies_leave_modes_unknown() {
        let mut raw = fixture();
        let Observation::Known(found) = discover(&raw) else {
            panic!("fixture")
        };
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].callers[0].modes, Some(alloc::vec![0, 1, 2]));
        for i in 0..3 {
            let old = raw[0x5000 + i];
            raw[0x5000 + i] = 126;
            let Observation::Known(found) = discover(&raw) else {
                panic!("fixture")
            };
            assert_eq!(found[0].first_indices[i], 126);
            let indices = found[0].indices_for(&found[0].callers[0]).unwrap();
            assert!(indices.contains(&126) && indices.contains(&127));
            raw[0x5000 + i] = old;
        }
        let v = &super::super::cache_rom_shapes::VALIDATORS[0];
        for i in 0..v.pattern.bytes.len() {
            if v.pattern
                .masks
                .iter()
                .any(|&(a, n)| (a..a + n).contains(&i))
            {
                continue;
            }
            raw[0x6000 + i] ^= 1;
            let Observation::Known(found) = discover(&raw) else {
                panic!("fixture")
            };
            assert_eq!(found[0].callers[0].modes, None, "validator byte {i}");
            raw[0x6000 + i] ^= 1;
        }
        raw[0x4000 + 17] ^= 1;
        let Observation::Known(found) = discover(&raw) else {
            panic!("fixture")
        };
        assert!(found.is_empty());
    }
    #[test]
    fn index_resolution_preserves_wrap_and_rejects_unknown_or_foreign_callers() {
        let Observation::Known(mut helpers) = discover(&fixture()) else {
            panic!("fixture")
        };
        let h = &mut helpers[0];
        h.first_indices = [255, 126, 112];
        assert_eq!(
            h.indices_for(&h.callers[0]),
            Some(alloc::vec![0, 112, 113, 126, 127, 255])
        );
        let mut caller = h.callers[0].clone();
        caller.offset += 2;
        assert_eq!(h.indices_for(&caller), None);
        h.callers[0].modes = None;
        assert_eq!(h.indices_for(&h.callers[0]), None);
        h.callers[0].modes = Some(alloc::vec![3]);
        assert_eq!(h.indices_for(&h.callers[0]), None);
    }
}

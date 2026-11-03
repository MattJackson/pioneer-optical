//! Bounded getter-pointer lifetimes. These observations do not prove global
//! startup acceptance; cache, queue and boot coverage remain separate.
use super::References;
use crate::image::layout::{Observation, Unresolved};
use alloc::{collections::BTreeSet, vec::Vec};

/// Native use of a loaded getter pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Reads diagnostic fields or ranges for output.
    DiagnosticOutput,
    /// Reads A7/A6/AB flag words.
    FlagWords,
    /// Reads the audited 8F..93 calibration selections.
    CalibrationWords,
    /// Reads the 228..22B calibration fields.
    CalibrationValidation,
    /// Reads calibration fields then branches to a bound register-restoration tail.
    CalibrationComputation,
    /// Selects C8/CD or C9/CF.
    ConditionalWords,
    /// Reads 9B/95/8E; numeric proximity is not a read of 9F.
    Near9fWords,
    /// Reads 10C/10D default fields.
    Defaults,
    /// Formats the 120..18F and 210..28F ranges.
    DumpRanges,
    /// Formats four words; all observed callers must select indices above 9F.
    FourWordOutput,
    /// Reads the 100..102 range and selected C8/CD or C9/CF fields.
    ByteLoop100,
}
/// An observed caller to the four-word formatter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caller {
    /// Decoded Normal offset of the call instruction.
    pub offset: usize,
    /// Adjacent R1 immediate index, checked to exclude 9F from the four words.
    pub index: u16,
}
/// A complete audited pointer-use block and its required external tail/callers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// Decoded Normal offset of the block.
    pub offset: usize,
    /// Native compiler form, for evidence reporting only.
    pub form: &'static str,
    /// Audited use of the getter pointer.
    pub kind: Kind,
    /// Every getter-pointer load covered by this block.
    pub pointers: Vec<usize>,
    /// Register-restoration tail when the block branches to one.
    pub lifetime_tail: Option<usize>,
    /// Four-word formatter callers; empty for other forms.
    pub callers: Vec<Caller>,
}
/// Explicit pointer coverage without inferring startup acceptance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// Matched blocks; audited forms may intentionally overlap.
    pub blocks: Vec<Block>,
    /// Getter-pointer loads that have no complete bound block.
    pub uncovered: Vec<usize>,
}
pub(super) struct Shape {
    pub form: &'static str,
    pub kind: Kind,
    pub bytes: &'static [u8],
    pub relocations: &'static [(usize, usize, usize)],
    pub pointers: &'static [usize],
    pub local_targets: &'static [(usize, usize, usize)],
}
fn word(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0, |v, b| (v << 8) | u32::from(*b))
}
fn control_target(target: u32, len: usize) -> bool {
    target & 1 == 0 && target >= 0x400000 && (target as usize) < 0x410000usize.saturating_add(len)
}
fn stored(normal: &[u8], regions: &[&[u8]], at: usize, len: usize) -> bool {
    regions.iter().any(|r| {
        let origin = r.as_ptr() as usize - normal.as_ptr() as usize;
        at >= origin && at.saturating_add(len) <= origin + r.len()
    })
}
impl Shape {
    fn matches(&self, normal: &[u8], at: usize, getter: u32) -> bool {
        let Some(bytes) = normal.get(at..at.saturating_add(self.bytes.len())) else {
            return false;
        };
        if !bytes.iter().zip(self.bytes).enumerate().all(|(i, (a, b))| {
            a == b
                || self
                    .relocations
                    .iter()
                    .any(|&(p, n, _)| (p..p + n).contains(&i))
        }) {
            return false;
        }
        for (i, &(offset, width, group)) in self.relocations.iter().enumerate() {
            let value = word(&bytes[offset..offset + width]);
            if self.relocations[..i]
                .iter()
                .any(|&(p, n, g)| g == group && word(&bytes[p..p + n]) != value)
            {
                return false;
            }
            if width == 3
                && offset > 0
                && matches!(bytes[offset - 1], 0x5e | 0x5a)
                && !control_target(value, normal.len())
            {
                return false;
            }
        }
        if self
            .local_targets
            .iter()
            .any(|&(p, n, delta)| word(&bytes[p..p + n]) as usize != 0x410000 + at + delta)
        {
            return false;
        }
        self.pointers
            .iter()
            .all(|&p| bytes[p] == 0x7a && bytes[p + 1] <= 7 && word(&bytes[p + 2..p + 6]) == getter)
    }
}
const TAIL: &[u8] = &[
    0x5e, 0x10, 0x55, 0x88, 0x0f, 0x81, 0x7a, 0x20, 0, 0, 0xff, 0xff, 0x4f, 6, 0x7a, 1, 0, 0, 0xff,
    0xff, 1, 0, 0x6f, 0x74, 0, 0x1c,
];
fn lifetime_tail(normal: &[u8], regions: &[&[u8]], end: usize) -> Option<usize> {
    let jump = normal.get(end.checked_sub(4)?..end)?;
    if jump[0] != 0x5a {
        return None;
    }
    let at = word(&jump[1..]).checked_sub(0x410000)? as usize;
    if !stored(normal, regions, at, TAIL.len()) {
        return None;
    }
    let bytes = normal.get(at..at.checked_add(TAIL.len())?)?;
    if bytes != TAIL {
        return None;
    }
    Some(at)
}
const ERROR_TAIL: &[u8] = &[
    0x79, 0, 0xfd, 0, 0xf9, 0x7f, 0x0c, 0x81, 0x5e, 0, 0, 0, 0x18, 0, 0x5e, 0, 0, 0, 0x7a, 0, 0, 0,
    0, 0, 1, 0, 0x69, 0xf0, 0x79, 2, 0xff, 0xfd, 0x6f, 0xf2, 0, 4, 0xf8, 2, 0x7a, 6, 0, 0, 0, 0,
    0x5d, 0x60, 0x79, 0x17, 0, 0x14, 1, 0x20, 0x6d, 0x76, 1, 0, 0x6d, 0x73, 0x54, 0x70,
];
fn near9f_tail(normal: &[u8], regions: &[&[u8]], start: usize) -> Option<usize> {
    let mut target = None;
    for offset in [0x22, 0x2a, 0x32] {
        let at = start.checked_add(offset)?;
        let branch = normal.get(at..at.checked_add(4)?)?;
        if branch[..2] != [0x58, 0x70] {
            return None;
        }
        let destination =
            usize::try_from(at as i64 + 4 + i64::from(i16::from_be_bytes([branch[2], branch[3]])))
                .ok()?;
        if target.is_some_and(|old| old != destination) {
            return None;
        }
        target = Some(destination);
    }
    let target = target?;
    if !stored(normal, regions, target, ERROR_TAIL.len()) {
        return None;
    }
    let bytes = normal.get(target..target.checked_add(ERROR_TAIL.len())?)?;
    if !matches!(bytes[2], 0xfd | 0xf5 | 0xf9) || bytes[31] != bytes[2] {
        return None;
    }
    if !bytes.iter().zip(ERROR_TAIL).enumerate().all(|(i, (a, b))| {
        a == b
            || [2, 31].contains(&i)
            || (9..12).contains(&i)
            || (15..18).contains(&i)
            || (20..24).contains(&i)
            || (40..44).contains(&i)
    }) {
        return None;
    }
    if ![
        word(&bytes[9..12]),
        word(&bytes[15..18]),
        word(&bytes[40..44]),
    ]
    .iter()
    .all(|&value| control_target(value, normal.len()))
    {
        return None;
    }
    Some(target)
}

fn callers(normal: &[u8], regions: &[&[u8]], entry: usize) -> Option<Vec<Caller>> {
    let target = 0x410000usize.checked_add(entry)? as u32;
    let mut result = Vec::new();
    for region in regions {
        let origin = region.as_ptr() as usize - normal.as_ptr() as usize;
        for local in (origin & 1..region.len()).step_by(2) {
            let bytes = &region[local..];
            if bytes.len() >= 6 && bytes[0] == 0x7a && bytes[1] <= 7 && word(&bytes[2..6]) == target
            {
                return None;
            }
            if bytes.len() >= 4 && bytes[0] == 0x5a && word(&bytes[1..4]) == target {
                return None;
            }
            let destination = if bytes.len() >= 4 && bytes[0] == 0x5e {
                Some(i64::from(word(&bytes[1..4])))
            } else if bytes.len() >= 2 && bytes[0] == 0x55 {
                Some(0x410000 + (origin + local) as i64 + 2 + i64::from(bytes[1] as i8))
            } else if bytes.len() >= 4 && bytes[..2] == [0x5c, 0] {
                Some(
                    0x410000
                        + (origin + local) as i64
                        + 4
                        + i64::from(i16::from_be_bytes([bytes[2], bytes[3]])),
                )
            } else {
                None
            };
            if destination != Some(i64::from(target)) {
                continue;
            }
            let load = local.checked_sub(4)?;
            if region[load..load + 2] != [0x79, 1] {
                return None;
            }
            let index = u16::from_be_bytes([region[load + 2], region[load + 3]]);
            if index <= 0x9f {
                return None;
            }
            result.push(Caller {
                offset: origin + local,
                index,
            });
        }
    }
    (!result.is_empty()).then_some(result)
}
/// Bind complete pointer-use blocks, retaining every uncovered pointer load.
/// This does not substitute for cache, boot, queue or arbitrary-alias analysis.
pub fn discover(normal: &[u8]) -> Observation<Evidence> {
    match super::references(normal) {
        Observation::Known(references) => bind(normal, &references),
        Observation::Unresolved(reason) => Observation::Unresolved(reason),
        Observation::Conflicting => Observation::Conflicting,
    }
}
fn bind(normal: &[u8], references: &References) -> Observation<Evidence> {
    if references.argument_register != 0 {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    }
    let Some(regions) = crate::image::regions(normal) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    let mut blocks = Vec::new();
    let mut seen = BTreeSet::new();
    let mut covered = BTreeSet::new();
    for pointer in &references.pointers {
        for (shape_index, shape) in super::pointer_shapes::SHAPES.iter().enumerate() {
            for &relative in shape.pointers {
                let Some(at) = pointer.offset.checked_sub(relative) else {
                    continue;
                };
                if seen.contains(&(at, shape_index))
                    || !stored(normal, &regions.stored, at, shape.bytes.len())
                    || !shape.matches(normal, at, references.getter)
                {
                    continue;
                }
                let tail = if shape.kind == Kind::CalibrationComputation {
                    let Some(tail) = lifetime_tail(normal, &regions.stored, at + shape.bytes.len())
                    else {
                        continue;
                    };
                    Some(tail)
                } else if shape.kind == Kind::Near9fWords {
                    let Some(tail) = near9f_tail(normal, &regions.stored, at) else {
                        continue;
                    };
                    Some(tail)
                } else {
                    None
                };
                let clients = if shape.kind == Kind::FourWordOutput {
                    let Some(clients) = callers(normal, &regions.stored, at) else {
                        continue;
                    };
                    clients
                } else {
                    Vec::new()
                };
                let pointers: Vec<_> = shape.pointers.iter().map(|offset| at + offset).collect();
                covered.extend(pointers.iter().copied());
                seen.insert((at, shape_index));
                blocks.push(Block {
                    offset: at,
                    form: shape.form,
                    kind: shape.kind,
                    pointers,
                    lifetime_tail: tail,
                    callers: clients,
                });
            }
        }
    }
    blocks.sort_by_key(|b| (b.offset, b.form));
    Observation::Known(Evidence {
        blocks,
        uncovered: references
            .pointers
            .iter()
            .filter(|p| !covered.contains(&p.offset))
            .map(|p| p.offset)
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(shape: &Shape) -> Vec<u8> {
        let mut raw = alloc::vec![0xff;0x10000];
        let at = 0x200;
        raw[at..at + shape.bytes.len()].copy_from_slice(shape.bytes);
        for &(p, n, group) in shape.relocations {
            let getter = shape
                .relocations
                .iter()
                .any(|&(off, _, g)| g == group && shape.pointers.iter().any(|&ptr| off == ptr + 2));
            let short = shape
                .relocations
                .iter()
                .any(|&(_, len, g)| g == group && len == 2);
            let local = shape.relocations.iter().find_map(|&(off, _, g)| {
                (g == group)
                    .then(|| {
                        shape
                            .local_targets
                            .iter()
                            .find(|&&(start, _, _)| start == off)
                            .map(|&(_, _, delta)| delta)
                    })
                    .flatten()
            });
            let value = if getter {
                0x410100u32
            } else if let Some(delta) = local {
                0x410000 + at as u32 + delta as u32
            } else if short {
                0x2800 + group as u32 * 2
            } else {
                0x418000 + group as u32 * 16
            };
            raw[at + p..at + p + n].copy_from_slice(&value.to_be_bytes()[4 - n..]);
        }
        raw
    }
    #[test]
    fn all_pointer_forms_bind_fixed_bytes_repeated_operands_and_local_targets() {
        for shape in super::super::pointer_shapes::SHAPES {
            let mut raw = fixture(shape);
            let at = 0x200;
            assert!(shape.matches(&raw, at, 0x410100), "{}", shape.form);
            for i in 0..shape.bytes.len() {
                if shape
                    .relocations
                    .iter()
                    .any(|&(p, n, _)| (p..p + n).contains(&i))
                {
                    continue;
                }
                raw[at + i] ^= 1;
                assert!(
                    !shape.matches(&raw, at, 0x410100),
                    "{} fixed byte {i}",
                    shape.form
                );
                raw[at + i] ^= 1;
            }
            for (i, &(p, n, group)) in shape.relocations.iter().enumerate() {
                if shape.relocations[..i].iter().any(|&(_, _, g)| g == group)
                    || shape.local_targets.iter().any(|&(off, _, _)| off == p)
                    || shape.pointers.iter().any(|&off| off + 2 == p)
                {
                    raw[at + p + n - 1] ^= 2;
                    assert!(
                        !shape.matches(&raw, at, 0x410100),
                        "{} bound operand {p}",
                        shape.form
                    );
                    raw[at + p + n - 1] ^= 2;
                }
            }
        }
    }
    #[test]
    fn near9f_early_errors_must_share_a_complete_restoring_return_tail() {
        let mut raw = alloc::vec![0xff;0x600];
        let start = 0x100;
        let tail = 0x300;
        for offset in [0x22, 0x2a, 0x32] {
            let at = start + offset;
            raw[at..at + 2].copy_from_slice(&[0x58, 0x70]);
            raw[at + 2..at + 4].copy_from_slice(&((tail - at - 4) as i16).to_be_bytes());
        }
        raw[tail..tail + ERROR_TAIL.len()].copy_from_slice(ERROR_TAIL);
        for (p, n, v) in [
            (9, 3, 0x410400u32),
            (15, 3, 0x410420),
            (20, 4, 0x900000),
            (40, 4, 0x410440),
        ] {
            raw[tail + p..tail + p + n].copy_from_slice(&v.to_be_bytes()[4 - n..]);
        }
        for code in [0xfd, 0xf5, 0xf9] {
            raw[tail + 2] = code;
            raw[tail + 31] = code;
            assert_eq!(near9f_tail(&raw, &[&raw], start), Some(tail));
        }
        raw[tail + 58..tail + 60].copy_from_slice(&[0x5d, 0x30]);
        assert_eq!(near9f_tail(&raw, &[&raw], start), None);
        raw[tail + 58..tail + 60].copy_from_slice(&[0x54, 0x70]);
        raw[start + 0x25] ^= 2;
        assert_eq!(near9f_tail(&raw, &[&raw], start), None);
    }
    #[test]
    fn calibration_exit_requires_the_exact_arithmetic_and_register_restore_tail() {
        let mut raw = alloc::vec![0xff;0x600];
        raw[0x200..0x204].copy_from_slice(&[0x5a, 0x41, 3, 0]);
        raw[0x300..0x300 + TAIL.len()].copy_from_slice(TAIL);
        assert_eq!(lifetime_tail(&raw, &[&raw], 0x204), Some(0x300));
        for i in 0..TAIL.len() {
            raw[0x300 + i] ^= 1;
            assert_eq!(lifetime_tail(&raw, &[&raw], 0x204), None, "tail byte {i}");
            raw[0x300 + i] ^= 1;
        }
    }

    #[test]
    fn formatter_callers_require_known_excluding_indices_and_no_pointer_alias() {
        let mut raw = alloc::vec![0xff;0x600];
        raw[0x40..0x48].copy_from_slice(&[0x79, 1, 1, 0x20, 0x5e, 0x41, 3, 0]);
        assert_eq!(
            callers(&raw, &[&raw], 0x300),
            Some(alloc::vec![Caller {
                offset: 0x44,
                index: 0x120
            }])
        );
        raw[0x42..0x44].copy_from_slice(&[0, 0x9f]);
        assert_eq!(callers(&raw, &[&raw], 0x300), None);
        raw[0x42..0x44].copy_from_slice(&[1, 0x20]);
        raw[0x80..0x86].copy_from_slice(&[0x7a, 5, 0, 0x41, 3, 0]);
        assert_eq!(callers(&raw, &[&raw], 0x300), None);
    }
}

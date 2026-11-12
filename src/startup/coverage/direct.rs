//! Complete native blocks around direct getter calls. These are coverage
//! observations; caller, helper, pointer, queue and boot proofs remain separate.
use super::{CallKind, References};
use crate::image::layout::{Observation, Unresolved};
use alloc::{collections::BTreeSet, vec::Vec};

/// Audited consumer block, retaining distinctions needed by later coverage checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// Selects one of A6, A7 and AB.
    SelectorFlags,
    /// Forwards an R1 index; every caller still needs analysis.
    WordForward,
    /// Reads a requested table index.
    TableQuery,
    /// Reads a requested command index.
    CommandRead,
    /// Alternate command-read compiler form.
    CommandReadAlternate,
    /// Selects a read or write request.
    CommandReadWrite,
    /// Transfers a word through a caller buffer.
    GenericBuffer,
    /// Compares against a queued expected value, not an OEM fixed value.
    QueuedComparison,
    /// Alternate queued-comparison compiler form.
    QueuedComparisonAlternate,
}
impl Kind {
    /// Stable evidence label from the independent native audit.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelectorFlags => "selector_flags",
            Self::WordForward => "word_forward",
            Self::TableQuery => "table_query",
            Self::CommandRead => "command_read_a",
            Self::CommandReadAlternate => "command_read_a_alt",
            Self::CommandReadWrite => "command_read_b",
            Self::GenericBuffer => "generic_buffer",
            Self::QueuedComparison => "record_compare",
            Self::QueuedComparisonAlternate => "record_compare_alt",
        }
    }
}
/// A complete matched block, with every enclosed getter call bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// Decoded Normal offset of the complete block.
    pub offset: usize,
    /// Audited block role; this does not establish its callers or helper effects.
    pub kind: Kind,
    /// Exact getter call offsets within this block.
    pub calls: Vec<usize>,
}
/// Partial coverage without converting unmatched references into absence claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// Complete independently bound blocks, in native offset order.
    pub blocks: Vec<Block>,
    /// Absolute getter calls not covered by these block forms.
    pub uncovered: Vec<usize>,
}

pub(super) struct Shape {
    pub kind: Kind,
    pub bytes: &'static [u8],
    // Operand offset, width and equality group. Only native addresses relocate.
    pub relocations: &'static [(usize, usize, usize)],
    pub getter_calls: &'static [usize],
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
                    .any(|&(start, len, _)| (start..start + len).contains(&i))
        }) {
            return false;
        }
        let value = |start: usize, len: usize| {
            bytes[start..start + len]
                .iter()
                .fold(0u32, |v, b| (v << 8) | u32::from(*b))
        };
        for (i, &(offset, width, group)) in self.relocations.iter().enumerate() {
            let actual = value(offset, width);
            if self.relocations[..i]
                .iter()
                .any(|&(other, len, g)| g == group && value(other, len) != actual)
            {
                return false;
            }
            if width == 3
                && offset > 0
                && matches!(bytes[offset - 1], 0x5e | 0x5a)
                && (actual & 1 != 0
                    || actual < 0x400000
                    || actual as usize >= 0x410000usize.saturating_add(normal.len()))
            {
                return false;
            }
        }
        self.getter_calls
            .iter()
            .all(|&call| bytes[call] == 0x5e && value(call + 1, 3) == getter)
    }
}

/// Recognize direct consumer blocks against the exact proven getter.
/// Uncovered calls are retained. No startup setting is selected by this API.
pub fn discover(normal: &[u8]) -> Observation<Evidence> {
    match super::references_in(normal) {
        Observation::Known((references, regions)) => bind(normal, &references, &regions),
        Observation::Unresolved(reason) => Observation::Unresolved(reason),
        Observation::Conflicting => Observation::Conflicting,
    }
}
fn bind(
    normal: &[u8],
    references: &References,
    regions: &crate::image::Regions<'_>,
) -> Observation<Evidence> {
    if references.argument_register != 0 {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    }
    let mut evidence = Evidence {
        blocks: Vec::new(),
        uncovered: Vec::new(),
    };
    let mut seen = BTreeSet::new();
    for call in references
        .calls
        .iter()
        .filter(|c| c.kind == CallKind::Absolute)
    {
        let mut matched = None;
        for shape in super::direct_shapes::SHAPES {
            for &relative in shape.getter_calls {
                let Some(at) = call.offset.checked_sub(relative) else {
                    continue;
                };
                // The byte match is cheap and rejects nearly every candidate.
                if !shape.matches(normal, at, references.getter)
                    || !regions.stored.iter().any(|r| {
                        let start = r.as_ptr() as usize - normal.as_ptr() as usize;
                        at >= start && at.saturating_add(shape.bytes.len()) <= start + r.len()
                    })
                {
                    continue;
                }
                let block = Block {
                    offset: at,
                    kind: shape.kind,
                    calls: shape.getter_calls.iter().map(|off| at + off).collect(),
                };
                if matched.as_ref().is_some_and(|old| old != &block) {
                    return Observation::Conflicting;
                }
                matched = Some(block);
            }
        }
        if let Some(block) = matched {
            if seen.insert((block.offset, block.kind, block.calls.clone())) {
                evidence.blocks.push(block);
            }
        } else {
            evidence.uncovered.push(call.offset);
        }
    }
    evidence.blocks.sort_by_key(|b| b.offset);
    Observation::Known(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn install(shape: &Shape, raw: &mut [u8], at: usize) {
        raw[at..at + shape.bytes.len()].copy_from_slice(shape.bytes);
        for &(offset, width, group) in shape.relocations {
            let value = relocated(shape, group);
            raw[at + offset..at + offset + width]
                .copy_from_slice(&value.to_be_bytes()[4 - width..]);
        }
    }
    fn getter_group(shape: &Shape, group: usize) -> bool {
        shape.relocations.iter().any(|&(off, _, g)| {
            g == group && shape.getter_calls.iter().any(|&call| off == call + 1)
        })
    }
    fn relocated(shape: &Shape, group: usize) -> u32 {
        let short_group = shape
            .relocations
            .iter()
            .any(|&(_, w, g)| g == group && w == 2);
        if getter_group(shape, group) {
            0x411000u32
        } else if short_group {
            0x2800 + group as u32 * 2
        } else {
            0x414000 + group as u32 * 32
        }
    }
    #[test]
    fn control_transfer_operands_must_be_even_and_inside_the_image() {
        let mut checked = 0;
        for shape in super::super::direct_shapes::SHAPES {
            let mut raw = alloc::vec![0xff; 0x6000];
            crate::image::layout::install_test_layout(&mut raw, 0x1000);
            let at = 0x2000;
            install(shape, &mut raw, at);
            assert!(shape.matches(&raw, at, 0x411000), "{:?}", shape.kind);
            for &(offset, width, group) in shape.relocations {
                if width != 3
                    || !matches!(shape.bytes[offset - 1], 0x5e | 0x5a)
                    || getter_group(shape, group)
                {
                    continue;
                }
                let past = 0x410000 + raw.len() as u32;
                for bad in [0x414001u32, 0x3ffffe, past] {
                    for &(o, w, _) in shape.relocations.iter().filter(|r| r.2 == group) {
                        raw[at + o..at + o + w].copy_from_slice(&bad.to_be_bytes()[4 - w..]);
                    }
                    assert!(
                        !shape.matches(&raw, at, 0x411000),
                        "{:?} operand {offset} = {bad:#x}",
                        shape.kind
                    );
                    checked += 1;
                }
                let good = relocated(shape, group);
                for &(o, w, _) in shape.relocations.iter().filter(|r| r.2 == group) {
                    raw[at + o..at + o + w].copy_from_slice(&good.to_be_bytes()[4 - w..]);
                }
                assert!(shape.matches(&raw, at, 0x411000));
            }
        }
        assert!(checked > 0);
    }
    #[test]
    fn getter_calls_outside_every_block_stay_uncovered() {
        let shape = &super::super::direct_shapes::SHAPES[0];
        let mut raw = alloc::vec![0xff; 0x6000];
        crate::image::layout::install_test_layout(&mut raw, 0x1000);
        install(shape, &mut raw, 0x2000);
        raw[0x5000..0x5004].copy_from_slice(&[0x5e, 0x41, 0x10, 0x00]);
        let Observation::Known(evidence) = discover(&raw) else {
            panic!("fixture");
        };
        assert_eq!(evidence.uncovered, alloc::vec![0x5000]);
        assert_eq!(evidence.blocks.len(), 1);
        assert_eq!(evidence.blocks[0].offset, 0x2000);
        assert!(!evidence.blocks.iter().any(|b| b.calls.contains(&0x5000)));
    }
    #[test]
    fn r1_index_getters_are_not_bound_by_r0_block_forms() {
        let mut r1 = 0;
        // The ten native reader graph forms of the test layout.
        for variant in 0..10 {
            let mut raw = alloc::vec![0xff; 0x6000];
            crate::image::layout::install_test_layout_variant(&mut raw, 0x1000, variant);
            let Observation::Known(references) = super::super::references(&raw) else {
                continue;
            };
            if references.argument_register == 0 {
                continue;
            }
            raw[0x5000..0x5004].copy_from_slice(&[0x5e, 0x41, 0x10, 0x00]);
            assert!(matches!(
                discover(&raw),
                Observation::Unresolved(Unresolved::ReaderNotRecognized)
            ));
            r1 += 1;
        }
        assert!(r1 > 0, "no R1 test layout");
    }
    #[test]
    fn every_fixed_instruction_and_repeated_operand_is_bound() {
        for shape in super::super::direct_shapes::SHAPES {
            let mut raw = alloc::vec![0xff;0x6000];
            crate::image::layout::install_test_layout(&mut raw, 0x1000);
            let at = 0x2000;
            raw[at..at + shape.bytes.len()].copy_from_slice(shape.bytes);
            for &(offset, width, group) in shape.relocations {
                let getter_group = shape.relocations.iter().any(|&(off, _, g)| {
                    g == group && shape.getter_calls.iter().any(|&call| off == call + 1)
                });
                let short_group = shape
                    .relocations
                    .iter()
                    .any(|&(_, w, g)| g == group && w == 2);
                let value = if getter_group {
                    0x411000u32
                } else if short_group {
                    0x2800 + group as u32 * 2
                } else {
                    0x414000 + group as u32 * 32
                };
                raw[at + offset..at + offset + width]
                    .copy_from_slice(&value.to_be_bytes()[4 - width..]);
            }
            assert!(shape.matches(&raw, at, 0x411000), "{:?}", shape.kind);
            let Observation::Known(evidence) = discover(&raw) else {
                panic!("fixture");
            };
            assert!(evidence
                .blocks
                .iter()
                .any(|b| b.offset == at && b.kind == shape.kind));
            for offset in 0..shape.bytes.len() {
                if shape
                    .relocations
                    .iter()
                    .any(|&(start, len, _)| (start..start + len).contains(&offset))
                {
                    continue;
                }
                raw[at + offset] ^= 1;
                assert!(
                    !shape.matches(&raw, at, 0x411000),
                    "{:?} offset {offset}",
                    shape.kind
                );
                raw[at + offset] ^= 1;
            }
            for (i, &(offset, width, group)) in shape.relocations.iter().enumerate() {
                if shape.relocations[..i].iter().any(|&(_, _, g)| g == group) {
                    raw[at + offset + width - 1] ^= 2;
                    assert!(!shape.matches(&raw, at, 0x411000));
                    raw[at + offset + width - 1] ^= 2;
                }
            }
            for &call in shape.getter_calls {
                raw[at + call + 3] ^= 2;
                assert!(!shape.matches(&raw, at, 0x411000));
                raw[at + call + 3] ^= 2;
            }
        }
    }
}

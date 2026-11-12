//! Packed ER0 caller arguments: E0 supplies the parameter index and R0 is
//! retained for arithmetic. This is local dataflow, not a boot acceptance proof.
use super::CallKind;
use crate::image::layout::{Observation, Unresolved};
use alloc::{collections::BTreeMap, vec::Vec};
/// A caller whose contiguous MOV.L may establish the packed argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    /// Decoded Normal call offset.
    pub offset: usize,
    /// Native call form.
    pub kind: CallKind,
    /// High index word and low arithmetic word; None means an unknown definition.
    pub words: Option<(u16, u16)>,
}
/// A bound prologue and all enumerated direct/relative incoming calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// Prologue offset in decoded Normal.
    pub offset: usize,
    /// Getter call supplied by the high word.
    pub getter_call: usize,
    /// Caller observations; empty does not prove the helper unreachable.
    pub callers: Vec<Caller>,
    /// Literal 32-bit address occurrences and absolute jumps need further analysis.
    pub other_references: Vec<usize>,
}
/// Bind the six-byte save/copy prologue and its exact native getter call.
/// A changed or unknown caller is preserved, never treated as excluding 0x009F.
/// Does not prove absence of computed aliases or incoming edges into the prologue.
pub fn discover(normal: &[u8]) -> Observation<Vec<Block>> {
    let (refs, regions) = match super::references_in(normal) {
        Observation::Known(r) => r,
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    if refs.argument_register != 0 {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    }
    let mut blocks = Vec::new();
    for call in refs.calls.iter().filter(|c| c.kind == CallKind::Absolute) {
        let Some(at) = call.offset.checked_sub(6) else {
            continue;
        };
        if normal.get(at..call.offset) != Some(&[0x6d, 0xf3, 0x0d, 3, 0x0d, 0x80][..]) {
            continue;
        }
        if !regions.stored.iter().any(|r| {
            let start = r.as_ptr() as usize - normal.as_ptr() as usize;
            at >= start && call.offset + 4 <= start + r.len()
        }) {
            continue;
        }
        blocks.push(Block {
            offset: at,
            getter_call: call.offset,
            callers: Vec::new(),
            other_references: Vec::new(),
        });
    }
    // One scan over stored code for all blocks: each target is looked up, so
    // a crafted image with many prologues costs O(image log blocks).
    let targets: BTreeMap<i64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(i, block)| (0x410000 + block.offset as i64, i))
        .collect();
    for region in &regions.stored {
        #[cfg(test)]
        tests::REGION_SCANS.with(|c| c.set(c.get() + 1));
        let base = region.as_ptr() as usize - normal.as_ptr() as usize;
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
            if let Some((kind, &i)) = call.and_then(|(kind, v)| Some((kind, targets.get(&v)?))) {
                let words = local.checked_sub(6).and_then(|p| {
                    (region[p..p + 2] == [0x7a, 0]).then(|| {
                        (
                            u16::from_be_bytes([region[p + 2], region[p + 3]]),
                            u16::from_be_bytes([region[p + 4], region[p + 5]]),
                        )
                    })
                });
                blocks[i].callers.push(Caller {
                    offset: at,
                    kind,
                    words,
                });
            }
            if b.len() >= 4 && b[0] == 0x5a {
                if let Some(&i) = targets.get(&absolute(b)) {
                    blocks[i].other_references.push(at);
                }
            }
        }
        for (i, word) in region.windows(4).enumerate() {
            let literal = i64::from(u32::from_be_bytes(word.try_into().unwrap()));
            if let Some(&block) = targets.get(&literal) {
                blocks[block].other_references.push(base + i);
            }
        }
    }
    for block in &mut blocks {
        block.other_references.sort_unstable();
        block.other_references.dedup();
    }
    Observation::Known(blocks)
}
#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    std::thread_local! {
        pub(super) static REGION_SCANS: Cell<usize> = const { Cell::new(0) };
    }
    fn fixture() -> Vec<u8> {
        let mut raw = alloc::vec![0xff;0x4000];
        crate::image::layout::install_test_layout(&mut raw, 0x1000);
        raw[0x2000..0x200a]
            .copy_from_slice(&[0x6d, 0xf3, 0x0d, 3, 0x0d, 0x80, 0x5e, 0x41, 0x10, 0]);
        raw[0x80..0x8a].copy_from_slice(&[0x7a, 0, 2, 0x22, 0, 0x8c, 0x5e, 0x41, 0x20, 0]);
        raw
    }
    #[test]
    fn prologue_and_exact_getter_target_are_required() {
        let mut raw = fixture();
        for i in 0..10 {
            raw[0x2000 + i] ^= 1;
            let Observation::Known(found) = discover(&raw) else {
                panic!("getter remains valid")
            };
            assert!(found.is_empty(), "byte {i}");
            raw[0x2000 + i] ^= 1;
        }
    }
    #[test]
    fn high_word_changes_unknown_callers_and_aliases_remain_visible() {
        let mut raw = fixture();
        for (word, expected) in [
            (0x0222, Some((0x0222, 0x8c))),
            (0x009f, Some((0x009f, 0x8c))),
        ] {
            raw[0x82..0x84].copy_from_slice(&(word as u16).to_be_bytes());
            let Observation::Known(found) = discover(&raw) else {
                panic!("fixture")
            };
            assert_eq!(found[0].callers[0].words, expected);
        }
        raw[0x81] = 1;
        raw[0x91..0x95].copy_from_slice(&0x412000u32.to_be_bytes());
        let Observation::Known(found) = discover(&raw) else {
            panic!("fixture")
        };
        assert_eq!(found[0].callers[0].words, None);
        assert_eq!(found[0].other_references, alloc::vec![0x91]);
    }
    #[test]
    fn many_prologues_share_one_reference_scan_with_unchanged_callers() {
        let mut raw = fixture();
        let copies = [0x2100usize, 0x2200, 0x2300];
        for &at in &copies {
            raw[at..at + 10]
                .copy_from_slice(&[0x6d, 0xf3, 0x0d, 3, 0x0d, 0x80, 0x5e, 0x41, 0x10, 0]);
        }
        // Relative8, Relative16, absolute JMP and an odd literal for 0x412200.
        raw[0x21f0..0x21f2].copy_from_slice(&[0x55, 0x0e]);
        raw[0x2400..0x2404].copy_from_slice(&[0x5c, 0, 0xfd, 0xfc]);
        raw[0x2410..0x2414].copy_from_slice(&[0x5a, 0x41, 0x22, 0]);
        raw[0x2421..0x2425].copy_from_slice(&0x412200u32.to_be_bytes());
        REGION_SCANS.with(|c| c.set(0));
        let Observation::Known(found) = discover(&raw) else {
            panic!("fixture")
        };
        assert_eq!(REGION_SCANS.with(Cell::get), 1, "one scan for all blocks");
        assert_eq!(
            found.iter().map(|b| b.offset).collect::<Vec<_>>(),
            alloc::vec![0x2000, 0x2100, 0x2200, 0x2300]
        );
        assert_eq!(
            found[0].callers,
            alloc::vec![Caller {
                offset: 0x86,
                kind: CallKind::Absolute,
                words: Some((0x0222, 0x8c))
            }]
        );
        assert_eq!(
            found[2].callers,
            alloc::vec![
                Caller {
                    offset: 0x21f0,
                    kind: CallKind::Relative8,
                    words: None
                },
                Caller {
                    offset: 0x2400,
                    kind: CallKind::Relative16,
                    words: None
                },
            ]
        );
        assert_eq!(found[2].other_references, alloc::vec![0x2410, 0x2421]);
        assert!(found[1].callers.is_empty() && found[1].other_references.is_empty());
        assert!(found[3].callers.is_empty() && found[3].other_references.is_empty());
    }
}

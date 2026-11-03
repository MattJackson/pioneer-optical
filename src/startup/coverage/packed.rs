//! Packed ER0 caller arguments: E0 supplies the parameter index and R0 is
//! retained for arithmetic. This is local dataflow, not a boot acceptance proof.
use super::CallKind;
use crate::image::layout::{Observation, Unresolved};
use alloc::vec::Vec;
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
    let refs = match super::references(normal) {
        Observation::Known(r) => r,
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    if refs.argument_register != 0 {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    }
    let regions = crate::image::regions(normal).expect("stored references");
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
    for block in &mut blocks {
        let target = 0x410000 + block.offset as i64;
        for region in &regions.stored {
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
                if let Some((kind, _)) = call.filter(|(_, v)| *v == target) {
                    let words = local.checked_sub(6).and_then(|p| {
                        (region[p..p + 2] == [0x7a, 0]).then(|| {
                            (
                                u16::from_be_bytes([region[p + 2], region[p + 3]]),
                                u16::from_be_bytes([region[p + 4], region[p + 5]]),
                            )
                        })
                    });
                    block.callers.push(Caller {
                        offset: at,
                        kind,
                        words,
                    });
                }
                if b.len() >= 4 && b[0] == 0x5a && absolute(b) == target {
                    block.other_references.push(at);
                }
            }
            let literal = (target as u32).to_be_bytes();
            for (i, word) in region.windows(4).enumerate() {
                if word == literal {
                    block.other_references.push(base + i);
                }
            }
        }
        block.other_references.sort_unstable();
        block.other_references.dedup();
    }
    Observation::Known(blocks)
}
#[cfg(test)]
mod tests {
    use super::*;
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
}

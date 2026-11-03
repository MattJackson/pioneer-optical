//! Complete native seven-index loop and its ROM data. This establishes only
//! these getter arguments, not startup reachability or global absence of gates.
use super::{
    table_shape::{BYTES, RELOCATIONS},
    CallKind,
};
use crate::image::layout::{Observation, Unresolved};
use alloc::vec::Vec;

/// A matched loop with exact decoded Normal coordinates and source indices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// Start of the complete 180-byte function.
    pub offset: usize,
    /// Getter call supplied by the table loop.
    pub dynamic_call: usize,
    /// Start of the seven big-endian words in stored Normal.
    pub table_offset: usize,
    /// Actual source indices, not inferred from a model name.
    pub indices: [u16; 7],
}
fn stored(normal: &[u8], offset: usize, len: usize) -> bool {
    crate::image::regions(normal).is_some_and(|r| {
        r.stored.iter().any(|region| {
            let start = region.as_ptr() as usize - normal.as_ptr() as usize;
            offset >= start && offset.saturating_add(len) <= start + region.len()
        })
    })
}
fn bind(normal: &[u8], offset: usize, getter: u32) -> Option<Block> {
    let bytes = normal.get(offset..offset.checked_add(BYTES.len())?)?;
    if !bytes
        .iter()
        .zip(BYTES)
        .enumerate()
        .all(|(k, (a, b))| a == b || RELOCATIONS.iter().any(|&(i, n, _)| (i..i + n).contains(&k)))
        || !stored(normal, offset, BYTES.len())
    {
        return None;
    }
    let value = |i: usize, n: usize| {
        bytes[i..i + n]
            .iter()
            .fold(0u32, |v, b| (v << 8) | u32::from(*b))
    };
    for &(i, n, g) in RELOCATIONS {
        if RELOCATIONS
            .iter()
            .any(|&(j, m, h)| g == h && value(i, n) != value(j, m))
        {
            return None;
        }
        if n == 3 && matches!(bytes[i - 1], 0x5e | 0x5a) {
            let target = value(i, n) as usize;
            if target & 1 != 0
                || target < 0x400000
                || target >= 0x410000usize.saturating_add(normal.len())
            {
                return None;
            }
        }
    }
    if value(13, 3) != getter || value(59, 3) != getter {
        return None;
    }
    let table_offset = (value(32, 4) as usize).checked_sub(0x410000)?;
    if table_offset & 1 != 0 || !stored(normal, table_offset, 14) {
        return None;
    }
    let table = normal.get(table_offset..table_offset.checked_add(14)?)?;
    let mut indices = [0; 7];
    for (i, word) in table.chunks_exact(2).enumerate() {
        indices[i] = u16::from_be_bytes([word[0], word[1]]);
    }
    Some(Block {
        offset,
        dynamic_call: offset + 58,
        table_offset,
        indices,
    })
}
/// Bind all matching seven-word loops to the proven R0 getter. Empty results
/// mean no recognized loop; callers must retain uncovered getter references.
/// Changed table words remain visible, including a newly introduced 0x009F.
pub fn discover(normal: &[u8]) -> Observation<Vec<Block>> {
    let references = match super::references(normal) {
        Observation::Known(r) => r,
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    if references.argument_register != 0 {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    }
    let mut blocks = Vec::new();
    for call in references
        .calls
        .iter()
        .filter(|c| c.kind == CallKind::Absolute)
    {
        if let Some(block) = call
            .offset
            .checked_sub(58)
            .and_then(|at| bind(normal, at, references.getter))
        {
            blocks.push(block);
        }
    }
    Observation::Known(blocks)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut raw = alloc::vec![0xff;0x6000];
        crate::image::layout::install_test_layout(&mut raw, 0x1000);
        raw[0x2000..0x2000 + BYTES.len()].copy_from_slice(BYTES);
        for &(i, n, g) in RELOCATIONS {
            let v = if i == 13 || i == 59 {
                0x411000u32
            } else if i == 32 {
                0x414000
            } else {
                0x415000 + g as u32 * 32
            };
            raw[0x2000 + i..0x2000 + i + n].copy_from_slice(&v.to_be_bytes()[4 - n..]);
        }
        raw[0x4000..0x400e].copy_from_slice(&[
            0, 0x50, 0, 0x51, 0, 0x52, 0, 0x54, 0, 0x53, 0, 0x55, 1, 0x10,
        ]);
        raw
    }
    #[test]
    fn complete_code_and_operand_relationships_are_required() {
        let mut raw = fixture();
        assert!(bind(&raw, 0x2000, 0x411000).is_some());
        for k in 0..BYTES.len() {
            if RELOCATIONS.iter().any(|&(i, n, _)| (i..i + n).contains(&k)) {
                continue;
            }
            raw[0x2000 + k] ^= 1;
            assert!(bind(&raw, 0x2000, 0x411000).is_none(), "byte {k}");
            raw[0x2000 + k] ^= 1;
        }
        for &(i, n, g) in RELOCATIONS {
            if RELOCATIONS.iter().filter(|&&(_, _, h)| h == g).count() > 1 {
                raw[0x2000 + i + n - 1] ^= 2;
                assert!(bind(&raw, 0x2000, 0x411000).is_none());
                raw[0x2000 + i + n - 1] ^= 2;
            }
        }
        raw[0x2020..0x2024].copy_from_slice(&0x40fff0u32.to_be_bytes());
        assert!(bind(&raw, 0x2000, 0x411000).is_none());
    }
    #[test]
    fn every_source_word_is_read_including_a_new_009f() {
        let mut raw = fixture();
        for i in 0..7 {
            let old = [raw[0x4000 + 2 * i], raw[0x4001 + 2 * i]];
            raw[0x4000 + 2 * i..0x4002 + 2 * i].copy_from_slice(&0x9fu16.to_be_bytes());
            let Observation::Known(blocks) = discover(&raw) else {
                panic!("fixture")
            };
            assert_eq!(blocks.len(), 1);
            assert_eq!(blocks[0].indices[i], 0x9f);
            raw[0x4000 + 2 * i..0x4002 + 2 * i].copy_from_slice(&old);
        }
    }
}

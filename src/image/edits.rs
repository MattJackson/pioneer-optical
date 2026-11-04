//! Atomic edits to a complete H8 Normal. Native provers supply exact operands;
//! this module does not establish that any operand is safe to change.
use alloc::vec::Vec;

pub(crate) struct Edit {
    pub offset: usize,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    InvalidNormal,
    InvalidEdit,
    Overlap,
}

fn checksum(bytes: &[u8]) -> u32 {
    bytes.chunks_exact(4).fold(0u32, |sum, word| {
        sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
    })
}

pub(crate) fn valid_normal(normal: &[u8]) -> bool {
    normal.len() >= 32
        && normal.len() % 4 == 0
        && u32::from_be_bytes(normal[20..24].try_into().unwrap()) as usize == normal.len()
        && normal[..16].iter().any(u8::is_ascii_graphic)
        && normal[..16]
            .iter()
            .all(|b| b.is_ascii_graphic() || *b == b' ')
        && checksum(normal) == 0
}

pub(crate) fn apply_normal(normal: &[u8], edits: &[Edit]) -> Result<Vec<u8>, Error> {
    if !valid_normal(normal) {
        return Err(Error::InvalidNormal);
    }
    let mut spans = Vec::with_capacity(edits.len());
    for edit in edits {
        let end = edit
            .offset
            .checked_add(edit.before.len())
            .ok_or(Error::InvalidEdit)?;
        if edit.offset < 32
            || edit.before.is_empty()
            || edit.before.len() != edit.after.len()
            || normal.get(edit.offset..end) != Some(edit.before.as_slice())
        {
            return Err(Error::InvalidEdit);
        }
        spans.push((edit.offset, end));
    }
    spans.sort_unstable();
    if spans.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(Error::Overlap);
    }
    let mut result = normal.to_vec();
    for edit in edits {
        result[edit.offset..edit.offset + edit.after.len()].copy_from_slice(&edit.after);
    }
    let old = u32::from_be_bytes(normal[16..20].try_into().unwrap());
    let replacement = old.wrapping_sub(checksum(&result));
    result[16..20].copy_from_slice(&replacement.to_be_bytes());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn fixture() -> Vec<u8> {
        let mut b = vec![0; 64];
        b[..16].copy_from_slice(b"PIONEER TEST    ");
        b[20..24].copy_from_slice(&64u32.to_be_bytes());
        let sum = checksum(&b);
        b[16..20].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
        b
    }
    fn edit(offset: usize, before: &[u8], after: &[u8]) -> Edit {
        Edit {
            offset,
            before: before.to_vec(),
            after: after.to_vec(),
        }
    }
    #[test]
    fn composition_is_order_independent_and_reversible() {
        let original = fixture();
        let forward = apply_normal(
            &original,
            &[edit(33, &[0, 0], &[4, 5]), edit(40, &[0], &[9])],
        )
        .unwrap();
        assert!(valid_normal(&forward));
        assert_eq!(
            forward,
            apply_normal(
                &original,
                &[edit(40, &[0], &[9]), edit(33, &[0, 0], &[4, 5])]
            )
            .unwrap()
        );
        assert_eq!(
            apply_normal(
                &forward,
                &[edit(33, &[4, 5], &[0, 0]), edit(40, &[9], &[0])]
            )
            .unwrap(),
            original
        );
        assert_eq!(apply_normal(&original, &[]).unwrap(), original);
    }
    #[test]
    fn rejects_conflicts_stale_bytes_and_header_edits() {
        let original = fixture();
        assert_eq!(
            apply_normal(
                &original,
                &[edit(33, &[0, 0], &[1, 2]), edit(34, &[0], &[2])]
            ),
            Err(Error::Overlap)
        );
        for e in [
            edit(33, &[1], &[2]),
            edit(16, &[0], &[1]),
            edit(64, &[0], &[1]),
            edit(32, &[], &[]),
            edit(32, &[0], &[1, 2]),
            edit(usize::MAX, &[0], &[1]),
        ] {
            assert_eq!(
                apply_normal(&original, &[edit(40, &[0], &[9]), e]),
                Err(Error::InvalidEdit)
            );
        }
        let mut bad = original.clone();
        bad[63] ^= 1;
        assert_eq!(apply_normal(&bad, &[]), Err(Error::InvalidNormal));
        assert!(valid_normal(&original));
    }
    fn recompensate(b: &mut [u8]) {
        b[16..20].fill(0);
        let sum = checksum(b);
        b[16..20].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
    }
    fn sized(len: usize) -> Vec<u8> {
        let mut b = vec![0; len];
        b[..16].copy_from_slice(b"PIONEER TEST    ");
        b[20..24].copy_from_slice(&(len as u32).to_be_bytes());
        recompensate(&mut b);
        b
    }
    #[test]
    fn each_normal_condition_is_required_with_a_valid_checksum() {
        assert!(valid_normal(&sized(32)));
        let mut spaces = fixture();
        spaces[..16].fill(b' ');
        recompensate(&mut spaces);
        assert!(!valid_normal(&spaces));
        let mut control = fixture();
        control[3] = 1;
        recompensate(&mut control);
        assert!(!valid_normal(&control));
        let mut short_word = fixture();
        short_word[20..24].copy_from_slice(&60u32.to_be_bytes());
        recompensate(&mut short_word);
        assert!(!valid_normal(&short_word));
        // The additive sum ignores a two-byte tail, so only alignment rejects it.
        let mut unaligned = fixture();
        unaligned.extend_from_slice(&[0, 0]);
        unaligned[20..24].copy_from_slice(&66u32.to_be_bytes());
        recompensate(&mut unaligned);
        assert!(!valid_normal(&unaligned));
        assert!(!valid_normal(&sized(28)));
    }
    #[test]
    fn edits_inside_the_32_byte_header_are_rejected() {
        let original = fixture();
        for offset in [20, 24, 31] {
            assert_eq!(
                apply_normal(&original, &[edit(offset, &[original[offset]], &[1])]),
                Err(Error::InvalidEdit),
                "{offset}"
            );
        }
        assert!(apply_normal(&original, &[edit(32, &[0], &[1])]).is_ok());
    }
}

use super::{m32c_serial_shapes::*, *};

fn unique(body: &[u8], pattern: &[u8]) -> Option<usize> {
    let mut positions = body
        .windows(pattern.len())
        .enumerate()
        .filter_map(|(at, bytes)| (bytes == pattern).then_some(at));
    let first = positions.next()?;
    positions.next().is_none().then_some(first)
}

fn u24(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
}

/// Recognize a native M32C serial mechanical-parameter reader.
///
/// `normal_base` is the CPU load address of `body`, established by the component
/// mapping (the audited legacy images use `0xF80000`). The consumer's absolute
/// call must resolve to the exact native word reader. Read, write, enable and
/// disable routines must all have their traced serial protocol implementation.
/// This is read-only recognition, not permission to invoke those operations.
pub fn discover_m32c_serial(body: &[u8], normal_base: u32) -> Observation<ParameterLayout> {
    let missing = || Observation::Unresolved(Unresolved::ReaderNotRecognized);
    let Some(reader) = unique(body, WORD_READ) else {
        return missing();
    };
    if [WORD_WRITE, WRITE_ENABLE, WRITE_DISABLE]
        .iter()
        .any(|pattern| unique(body, pattern).is_none())
    {
        return missing();
    }
    let Some(reader_address) = u32::try_from(reader)
        .ok()
        .and_then(|at| normal_base.checked_add(at))
    else {
        return missing();
    };
    let mut found = None;
    for code in body.windows(MECHANICAL_CACHE_LOADER.len()) {
        // The range, native call and destination RAM pointer are operands;
        // branches, arithmetic, access width and loop structure are fixed.
        if !code
            .iter()
            .zip(MECHANICAL_CACHE_LOADER)
            .enumerate()
            .all(|(i, (a, b))| a == b || matches!(i, 6..=7 | 9..=11 | 16..=18 | 23))
        {
            continue;
        }
        if u24(&code[9..12]) != reader_address {
            return missing();
        }
        let first_word = u16::from_le_bytes([code[6], code[7]]);
        let word_count = u16::from(code[23]);
        if word_count == 0 || u32::from(first_word) + u32::from(word_count) > 1024 {
            return missing();
        }
        if found.is_some() {
            return Observation::Unresolved(Unresolved::AmbiguousReader);
        }
        found = Some(ParameterLayout::SerialRange {
            address_bits: 10,
            first_word,
            word_count,
            encoding: WordEncoding::SerialHighByteFirst,
        });
    }
    found.map(Observation::Known).unwrap_or_else(missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn fixture() -> Vec<u8> {
        let mut b = vec![0; 512];
        for (at, bytes) in [
            (0, WORD_READ),
            (100, WORD_WRITE),
            (190, WRITE_ENABLE),
            (240, WRITE_DISABLE),
            (300, MECHANICAL_CACHE_LOADER),
        ] {
            b[at..at + bytes.len()].copy_from_slice(bytes);
        }
        b[309..312].copy_from_slice(&[0, 0, 0xf8]);
        b
    }

    #[test]
    fn native_serial_range_and_mapping_are_bound() {
        let body = fixture();
        let expected = ParameterLayout::SerialRange {
            address_bits: 10,
            first_word: 0xc0,
            word_count: 160,
            encoding: WordEncoding::SerialHighByteFirst,
        };
        assert_eq!(
            discover_m32c_serial(&body, 0xf80000).compare(&Observation::Known(expected)),
            Some(true)
        );
        assert!(matches!(
            discover_m32c_serial(&body, 0xf40000),
            Observation::Unresolved(_)
        ));
        let mut moved = vec![0; 41];
        moved.extend_from_slice(&body);
        moved[350..353].copy_from_slice(&[41, 0, 0xf8]);
        assert_eq!(
            discover_m32c_serial(&body, 0xf80000).compare(&discover_m32c_serial(&moved, 0xf80000)),
            Some(true)
        );
    }

    #[test]
    fn changed_range_is_a_different_layout_not_a_model_lookup() {
        let body = fixture();
        let mut changed = body.clone();
        changed[306] = 0xc1;
        assert_eq!(
            discover_m32c_serial(&body, 0xf80000)
                .compare(&discover_m32c_serial(&changed, 0xf80000)),
            Some(false)
        );
        changed[306..308].copy_from_slice(&1023u16.to_le_bytes());
        assert!(matches!(
            discover_m32c_serial(&changed, 0xf80000),
            Observation::Unresolved(_)
        ));
    }

    #[test]
    fn altered_serial_protocol_never_claims_the_original_layout() {
        let body = fixture();
        for at in 0..290 {
            for bit in 0..8 {
                let mut changed = body.clone();
                changed[at] ^= 1 << bit;
                assert!(
                    matches!(
                        discover_m32c_serial(&changed, 0xf80000),
                        Observation::Unresolved(_)
                    ),
                    "protocol mutation at {at}, bit {bit}"
                );
            }
        }
        let mut duplicate = body.clone();
        duplicate.extend_from_slice(WORD_READ);
        assert!(matches!(
            discover_m32c_serial(&duplicate, 0xf80000),
            Observation::Unresolved(_)
        ));
    }
}

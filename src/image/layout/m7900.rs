use super::{m7900_shapes::*, *};

fn u24(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
}

fn resolve(body: &[u8], address_bias: u32, address: u32, len: usize) -> Option<&[u8]> {
    let start = usize::try_from(address.checked_sub(address_bias)?).ok()?;
    body.get(start..start.checked_add(len)?)
}

/// Recognize the M7900 ATA paired serial-record consumer and fallback selector.
/// Uses the same native address mapping as [`discover_m7900_scsi`].
pub fn discover_m7900_ata(body: &[u8], address_bias: u32) -> Observation<ParameterLayout> {
    let missing = || Observation::Unresolved(Unresolved::ReaderNotRecognized);
    let mut result = None;
    for (at, code) in body.windows(ATA_LOOP.len()).enumerate() {
        if !code
            .iter()
            .zip(ATA_LOOP)
            .enumerate()
            .all(|(i, (a, b))| a == b || matches!(i,3..=4|6..=8|17..=18|22..=23|25..=27|38..=39))
        {
            continue;
        }
        let Some(prefix) = at
            .checked_sub(ATA_PREFIX.len())
            .and_then(|start| body.get(start..at))
        else {
            return missing();
        };
        if !prefix
            .iter()
            .zip(ATA_PREFIX)
            .enumerate()
            .all(|(i, (a, b))| a == b || matches!(i, 12..=14))
        {
            return missing();
        }
        let reader = u24(&code[6..9]);
        if u24(&code[25..28]) != reader
            || resolve(body, address_bias, reader, WORD_READ.len()) != Some(WORD_READ)
        {
            return missing();
        }
        let Some(selector) = resolve(body, address_bias, u24(&prefix[12..15]), 7) else {
            return missing();
        };
        if selector[..3] != [0x34, 0xc4, 0x0d] || selector[6] != 0x94 {
            return missing();
        }
        let Some(table) = resolve(body, address_bias, u24(&selector[3..6]), 8) else {
            return missing();
        };
        let Some(fallback) =
            body.get(at + ATA_LOOP.len()..at + ATA_LOOP.len() + ATA_SELECTION.len())
        else {
            return missing();
        };
        let word_offsets = [0usize, 10, 20, 35, 50, 68, 81, 94];
        let calls = [3usize, 13, 23, 38, 53, 71, 84, 97];
        let ram = [8usize, 18, 28, 43, 102];
        if !fallback
            .iter()
            .zip(ATA_SELECTION)
            .enumerate()
            .all(|(i, (a, b))| {
                a == b
                    || word_offsets.iter().any(|p| (p + 1..p + 3).contains(&i))
                    || calls.iter().any(|p| (p + 1..p + 4).contains(&i))
                    || ram.iter().any(|p| (*p..p + 2).contains(&i))
            })
        {
            return missing();
        }
        if calls.iter().any(|p| u24(&fallback[p + 1..p + 4]) != reader) {
            return missing();
        }
        let words = word_offsets.map(|p| u16::from_le_bytes([fallback[p + 1], fallback[p + 2]]));
        let slots: [u8; 8] = table.try_into().expect("bounded eight-byte table");
        let bases = [
            u16::from_le_bytes([code[3], code[4]]),
            u16::from_le_bytes([code[22], code[23]]),
        ];
        if words.iter().any(|w| *w >= 1024)
            || bases.iter().any(|base| {
                slots
                    .iter()
                    .any(|slot| u32::from(*base) + u32::from(*slot) >= 1024)
            })
        {
            return missing();
        }
        if result.is_some() {
            return Observation::Unresolved(Unresolved::AmbiguousReader);
        }
        result = Some(ParameterLayout::SerialSelected {
            address_bits: 10,
            bases,
            slots,
            selection: SerialSelection::FallbackWords(words),
            encoding: WordEncoding::SerialHighByteFirst,
        });
    }
    result.map(Observation::Known).unwrap_or_else(missing)
}

/// Recognize the M7900 SCSI selected serial-parameter record consumer.
///
/// `address_bias` maps native encoded addresses to offsets in `body`: an encoded
/// address minus this bias is its slice offset. The audited decoded Normal
/// payloads omit a `0x3800` prefix. All reader, selector and table references must
/// resolve inside the supplied bytes; a sibling component cannot supply them.
pub fn discover_m7900_scsi(body: &[u8], address_bias: u32) -> Observation<ParameterLayout> {
    let missing = || Observation::Unresolved(Unresolved::ReaderNotRecognized);
    let mut result = None;
    for code in body.windows(SCSI_LOOP.len()) {
        if !code.iter().zip(SCSI_LOOP).enumerate().all(|(i, (a, b))| {
            a == b || matches!(i, 7..=8 | 10..=12 | 22..=24 | 30..=31 | 33..=35 | 49..=50 | 52..=54)
        }) {
            continue;
        }
        let reader = u24(&code[10..13]);
        if u24(&code[33..36]) != reader
            || u24(&code[52..55]) != reader
            || resolve(body, address_bias, reader, WORD_READ.len()) != Some(WORD_READ)
        {
            return missing();
        }
        let Some(selector) = resolve(body, address_bias, u24(&code[22..25]), 7) else {
            return missing();
        };
        if selector[..3] != [0x34, 0xc4, 0x0d] || selector[6] != 0x94 {
            return missing();
        }
        let Some(table) = resolve(body, address_bias, u24(&selector[3..6]), 8) else {
            return missing();
        };
        let slots: [u8; 8] = table.try_into().expect("bounded eight-byte selector");
        let bases = [
            u16::from_le_bytes([code[30], code[31]]),
            u16::from_le_bytes([code[49], code[50]]),
        ];
        let header = u16::from_le_bytes([code[7], code[8]]);
        if header >= 1024
            || bases.iter().any(|base| {
                slots
                    .iter()
                    .any(|slot| u32::from(*base) + u32::from(*slot) >= 1024)
            })
        {
            return missing();
        }
        if result.is_some() {
            return Observation::Unresolved(Unresolved::AmbiguousReader);
        }
        result = Some(ParameterLayout::SerialSelected {
            address_bits: 10,
            bases,
            slots,
            selection: SerialSelection::Header(header),
            encoding: WordEncoding::SerialHighByteFirst,
        });
    }
    result.map(Observation::Known).unwrap_or_else(missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn fixture() -> Vec<u8> {
        let mut body = vec![0; 512];
        body[..WORD_READ.len()].copy_from_slice(WORD_READ);
        body[160..167].copy_from_slice(&[0x34, 0xc4, 0x0d, 0xb0, 0x38, 0, 0x94]);
        body[176..184].copy_from_slice(&[8, 10, 11, 9, 12, 0, 1, 2]);
        body[200..200 + SCSI_LOOP.len()].copy_from_slice(SCSI_LOOP);
        for at in [210, 233, 252] {
            body[at..at + 3].copy_from_slice(&[0, 0x38, 0]);
        }
        body[222..225].copy_from_slice(&[0xa0, 0x38, 0]);
        body
    }

    fn ata_fixture() -> Vec<u8> {
        let mut body = fixture();
        body[200..].fill(0);
        body[200..217].copy_from_slice(ATA_PREFIX);
        body[212..215].copy_from_slice(&[0xa0, 0x38, 0]);
        body[217..267].copy_from_slice(ATA_LOOP);
        for at in [223, 242] {
            body[at..at + 3].copy_from_slice(&[0, 0x38, 0]);
        }
        body[267..371].copy_from_slice(ATA_SELECTION);
        for call in [3, 13, 23, 38, 53, 71, 84, 97] {
            body[268 + call..271 + call].copy_from_slice(&[0, 0x38, 0]);
        }
        body
    }

    #[test]
    fn ata_fallback_words_are_not_scsi_header_metadata() {
        let body = ata_fixture();
        let expected = ParameterLayout::SerialSelected {
            address_bits: 10,
            bases: [0x220, 0x260],
            slots: [8, 10, 11, 9, 12, 0, 1, 2],
            selection: SerialSelection::FallbackWords([
                0x240, 0x242, 0x243, 0x241, 0x246, 0x247, 0x245, 0x244,
            ]),
            encoding: WordEncoding::SerialHighByteFirst,
        };
        assert_eq!(
            discover_m7900_ata(&body, 0x3800).compare(&Observation::Known(expected)),
            Some(true)
        );
        assert!(matches!(
            discover_m7900_scsi(&body, 0x3800),
            Observation::Unresolved(_)
        ));
        let mut changed = body.clone();
        changed[268] ^= 1;
        assert_eq!(
            discover_m7900_ata(&body, 0x3800).compare(&discover_m7900_ata(&changed, 0x3800)),
            Some(false)
        );
    }

    #[test]
    fn ata_fallback_compare_and_calls_must_be_bound() {
        let body = ata_fixture();
        for at in [223, 242, 271, 281, 291, 306, 321, 339, 352, 365] {
            let mut changed = body.clone();
            changed[at..at + 3].fill(0xff);
            assert!(matches!(
                discover_m7900_ata(&changed, 0x3800),
                Observation::Unresolved(_)
            ));
        }
        for end in 0..371 {
            assert!(!matches!(
                discover_m7900_ata(&body[..end], 0x3800),
                Observation::Known(_)
            ));
        }
        let mut changed = body.clone();
        changed[267 + 58] = 0;
        assert!(matches!(
            discover_m7900_ata(&changed, 0x3800),
            Observation::Unresolved(_)
        ));
    }

    #[test]
    fn native_selector_table_is_part_of_identity() {
        let body = fixture();
        let expected = ParameterLayout::SerialSelected {
            address_bits: 10,
            bases: [0x220, 0x260],
            slots: [8, 10, 11, 9, 12, 0, 1, 2],
            selection: SerialSelection::Header(0x256),
            encoding: WordEncoding::SerialHighByteFirst,
        };
        assert_eq!(
            discover_m7900_scsi(&body, 0x3800).compare(&Observation::Known(expected)),
            Some(true)
        );
        let mut changed = body.clone();
        changed.swap(176, 177);
        assert_eq!(
            discover_m7900_scsi(&body, 0x3800).compare(&discover_m7900_scsi(&changed, 0x3800)),
            Some(false)
        );
        assert!(matches!(
            discover_m7900_scsi(&body, 0),
            Observation::Unresolved(_)
        ));
    }

    #[test]
    fn broken_native_targets_and_incomplete_loops_fail_closed() {
        let body = fixture();
        for at in [210, 222, 233, 252, 163] {
            let mut changed = body.clone();
            changed[at..at + 3].fill(0xff);
            assert!(matches!(
                discover_m7900_scsi(&changed, 0x3800),
                Observation::Unresolved(_)
            ));
        }
        for end in 0..200 + SCSI_LOOP.len() {
            assert!(!matches!(
                discover_m7900_scsi(&body[..end], 0x3800),
                Observation::Known(_)
            ));
        }
        let mut duplicate = body.clone();
        duplicate.extend_from_slice(&body[200..200 + SCSI_LOOP.len()]);
        assert!(matches!(
            discover_m7900_scsi(&duplicate, 0x3800),
            Observation::Unresolved(Unresolved::AmbiguousReader)
        ));
    }

    fn known(o: Observation<ParameterLayout>) -> bool {
        matches!(o, Observation::Known(_))
    }
    fn put(body: &[u8], at: usize, value: u16) -> Vec<u8> {
        let mut changed = body.to_vec();
        changed[at..at + 2].copy_from_slice(&value.to_le_bytes());
        changed
    }

    #[test]
    fn scsi_serial_word_addresses_stop_at_1024() {
        let body = fixture();
        // Header word operand.
        assert!(known(discover_m7900_scsi(&put(&body, 207, 1023), 0x3800)));
        assert!(!known(discover_m7900_scsi(&put(&body, 207, 1024), 0x3800)));
        // First base plus the largest slot (12).
        assert!(known(discover_m7900_scsi(&put(&body, 230, 1011), 0x3800)));
        assert!(!known(discover_m7900_scsi(&put(&body, 230, 1012), 0x3800)));
    }

    #[test]
    fn ata_serial_word_addresses_stop_at_1024_and_duplicates_are_ambiguous() {
        let body = ata_fixture();
        // First fallback word operand.
        assert!(known(discover_m7900_ata(&put(&body, 268, 1023), 0x3800)));
        assert!(!known(discover_m7900_ata(&put(&body, 268, 1024), 0x3800)));
        // First base plus the largest slot (12).
        assert!(known(discover_m7900_ata(&put(&body, 220, 1011), 0x3800)));
        assert!(!known(discover_m7900_ata(&put(&body, 220, 1012), 0x3800)));
        let mut duplicate = body.clone();
        duplicate.extend_from_slice(&body[200..371]);
        assert!(matches!(
            discover_m7900_ata(&duplicate, 0x3800),
            Observation::Unresolved(Unresolved::AmbiguousReader)
        ));
    }
}

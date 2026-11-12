use super::{v850_shapes::*, *};
use alloc::vec;

const BASE: usize = 0x10000;

// Both directions share physical wiring coordinates; only data bit direction differs.
const DATA_BITS: [usize; 16] = [0, 1, 3, 2, 5, 4, 6, 7, 9, 8, 11, 10, 14, 12, 13, 15];
/// Swaps address bits 1/2, 3/4, 7/8, 9/10 and 11/12; `0x1f9e` is the set of
/// those ten permuted bits, every other bit is kept.
fn bus_address(at: usize) -> usize {
    (at & !0x1f9e)
        | ((at & 2) << 1)
        | ((at & 4) >> 1)
        | ((at & 8) << 1)
        | ((at & 16) >> 1)
        | ((at & 128) << 1)
        | ((at & 256) >> 1)
        | ((at & 512) << 1)
        | ((at & 1024) >> 1)
        | ((at & 2048) << 1)
        | ((at & 4096) >> 1)
}

pub(crate) fn decode_bus(bytes: &[u8]) -> Option<Vec<u8>> {
    // Every address permutation stays within an 8 KiB block. Reject a partial
    // block instead of truncating, growing or zero-padding the component.
    if bytes.is_empty() || bytes.len() % 8192 != 0 {
        return None;
    }
    let mut out = vec![0; bytes.len()];
    for at in (0..bytes.len()).step_by(2) {
        let address = bus_address(at);
        let word = u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        let decoded = DATA_BITS
            .iter()
            .enumerate()
            .fold(0u16, |v, (to, from)| v | (((word >> from) & 1) << to));
        out[address..address + 2].copy_from_slice(&decoded.to_le_bytes());
    }
    Some(out)
}

/// Invert the physical address/data wiring. The data permutation includes a
/// three-cycle, so applying the decoder twice is not an encoder.
pub(crate) fn encode_bus(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() || bytes.len() % 8192 != 0 {
        return None;
    }
    let mut out = vec![0; bytes.len()];
    for stored in (0..bytes.len()).step_by(2) {
        let native = bus_address(stored);
        let word = u16::from_le_bytes([bytes[native], bytes[native + 1]]);
        let encoded = DATA_BITS
            .iter()
            .enumerate()
            .fold(0u16, |v, (from, to)| v | (((word >> from) & 1) << to));
        out[stored..stored + 2].copy_from_slice(&encoded.to_le_bytes());
    }
    Some(out)
}

/// Recognize V850 records from the stored address/data bus representation.
///
/// Decodes copies of the supplied components, then applies
/// [`discover_v850_native`]. This does not modify firmware or authorize a bus
/// representation change in an update. Partial permutation blocks are rejected.
pub fn discover_v850_bus(normal: &[u8], kernel: Option<&[u8]>) -> Observation<ParameterLayout> {
    let Some(normal) = decode_bus(normal) else {
        return Observation::Unresolved(Unresolved::TruncatedEvidence);
    };
    let kernel = match kernel {
        Some(bytes) => match decode_bus(bytes) {
            Some(bytes) => Some(bytes),
            None => return Observation::Unresolved(Unresolved::TruncatedEvidence),
        },
        None => None,
    };
    discover_v850_native(&normal, kernel.as_deref())
}
fn le16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn pointer(bytes: &[u8], hi: usize, lo: usize) -> u32 {
    u32::from(le16(bytes, hi))
        .wrapping_mul(65536)
        .wrapping_add(i32::from(le16(bytes, lo) as i16) as u32)
}
fn masked(actual: &[u8], expected: &[u8], ranges: &[(usize, usize)]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).enumerate().all(|(i, (a, b))| {
            a == b
                || ranges
                    .iter()
                    .any(|(start, len)| (*start..start + len).contains(&i))
        })
}
fn jarl(code: &[u8], offset: usize, address: usize) -> Option<usize> {
    let lo = le16(code, offset);
    if lo & 0xffc0 != 0xff80 {
        return None;
    }
    let raw = (u32::from(lo & 0x3f) << 16) | u32::from(le16(code, offset + 2));
    let delta = if raw & (1 << 21) != 0 {
        i64::from(raw) - (1 << 22)
    } else {
        i64::from(raw)
    };
    usize::try_from(i64::try_from(address.checked_add(offset)?).ok()? + delta).ok()
}
fn bytes_at(body: &[u8], address: usize, len: usize) -> Option<&[u8]> {
    let at = address.checked_sub(BASE)?;
    body.get(at..at.checked_add(len)?)
}

/// Recognize V850 fixed parameter records from native bus-order bytes.
///
/// Normal starts at CPU `0x10000`, Kernel at zero. Inputs must already have the
/// firmware's address/data bus permutation decoded. Both runtime-selectable
/// readers are bound; an unavailable Kernel returns its required native entry
/// address rather than treating the direct-reader branch as sufficient.
/// This validates the traced read format, not writes or layout migration.
pub fn discover_v850_native(normal: &[u8], kernel: Option<&[u8]>) -> Observation<ParameterLayout> {
    let missing = || Observation::Unresolved(Unresolved::ReaderNotRecognized);
    let mut found = None;
    for (at, code) in normal.windows(PRIMARY.len()).enumerate().step_by(2) {
        if code[..24] != PRIMARY[..24] {
            continue;
        }
        let mut ordered = code.to_vec();
        if ordered[44..50] == [0xe0, 0xd1, 0x63, 0x57, 2, 0] {
            ordered[44..50].copy_from_slice(&[0x63, 0x57, 2, 0, 0xe0, 0xd1]);
        }
        if !masked(
            &ordered,
            PRIMARY,
            &[(24, 4), (32, 4), (40, 4), (58, 4), (90, 2)],
        ) {
            return missing();
        }
        let address = at + BASE;
        let mut targets = [0; 4];
        for (index, offset) in [24, 32, 40, 58].into_iter().enumerate() {
            let Some(target) = jarl(code, offset, address) else {
                return missing();
            };
            targets[index] = target;
        }
        if bytes_at(normal, targets[0], RECORD_WIDTH.len()) != Some(RECORD_WIDTH)
            || bytes_at(normal, targets[1], REGION_SIZE.len()) != Some(REGION_SIZE)
            || bytes_at(normal, targets[2], HEADER_SIZE.len()) != Some(HEADER_SIZE)
        {
            return missing();
        }
        let branch = le16(code, 90);
        // Format III Bcond: opcode 1011 in bits 10..7 and condition BR (0101).
        if branch & 0x078f != 0x0585 {
            return missing();
        }
        let raw = ((branch >> 4) & 7) * 2 + ((branch >> 11) & 31) * 16;
        let delta = if raw & 256 != 0 {
            i32::from(raw) - 512
        } else {
            i32::from(raw)
        };
        let Some(end) = address
            .checked_add(90)
            .and_then(|a| a.checked_add_signed(delta as isize))
        else {
            return missing();
        };
        if bytes_at(normal, end, 6) != Some(&[0x19, 0x50, 0x44, 6, 0xff, 0xf1][..]) {
            return missing();
        }
        let Some(scanner) = bytes_at(normal, targets[3], SCANNER.len()) else {
            return missing();
        };
        if !masked(scanner, SCANNER, &[(24, 2), (30, 2), (34, 2)])
            || pointer(scanner, 24, 34) as usize != targets[3] + 38
        {
            return missing();
        }
        let slot = &scanner[30..32];
        let mut callback = None;
        for (shape, ranges, slot1, slot2, khi, klo, dhi, dlo) in [
            (
                SELECTOR_A,
                &[(8, 2), (12, 2), (16, 2), (22, 2), (26, 2), (30, 2)][..],
                16,
                30,
                8,
                12,
                22,
                26,
            ),
            (
                SELECTOR_B,
                &[(14, 2), (18, 2), (22, 2), (30, 2), (34, 2), (38, 2)][..],
                22,
                38,
                14,
                18,
                30,
                34,
            ),
        ] {
            for candidate in normal.windows(shape.len()).step_by(2) {
                if candidate[..8] != shape[..8] {
                    continue;
                }
                if !masked(candidate, shape, ranges)
                    || &candidate[slot1..slot1 + 2] != slot
                    || &candidate[slot2..slot2 + 2] != slot
                {
                    continue;
                }
                if callback.is_some() {
                    return Observation::Unresolved(Unresolved::AmbiguousReader);
                }
                callback = Some((pointer(candidate, khi, klo), pointer(candidate, dhi, dlo)));
            }
        }
        let Some((resident, direct)) = callback else {
            return missing();
        };
        if bytes_at(normal, direct as usize, DIRECT_READER.len()) != Some(DIRECT_READER) {
            return missing();
        }
        let Some(kernel) = kernel else {
            return Observation::Unresolved(Unresolved::ResidentCodeRequired(resident));
        };
        let start = resident as usize;
        if start
            .checked_add(KERNEL_READER.len())
            .and_then(|end| kernel.get(start..end))
            != Some(KERNEL_READER)
        {
            return missing();
        }
        if found.is_some() {
            return Observation::Unresolved(Unresolved::AmbiguousReader);
        }
        found = Some(ParameterLayout::FlashRecords {
            regions: [
                (0x1fa000, 0xa20, 320, 8),
                (0x1faa20, 0x5e0, 160, 9),
                (0x1fb000, 0x1000, 64, 62),
            ]
            .into_iter()
            .map(|(address, size, record_bytes, record_count)| RecordRegion {
                address,
                basis: AddressBasis::Absolute,
                allocation_bytes: Some(size),
                record_bytes,
                record_count,
                header_bytes: 2 * record_count,
                header_test: HeaderTest::WordFfff,
            })
            .collect(),
            encoding: WordEncoding::DirectOrBusPermutedLittleEndian,
            domains: vec![LogicalDomain {
                first: 0x160,
                last: 0x1ff,
                region: 0,
            }],
        });
    }
    found.map(Observation::Known).unwrap_or_else(missing)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_pointer(code: &mut [u8], hi: usize, lo: usize, target: u32) {
        code[hi..hi + 2]
            .copy_from_slice(&((target.wrapping_add(0x8000) >> 16) as u16).to_le_bytes());
        code[lo..lo + 2].copy_from_slice(&(target as u16).to_le_bytes());
    }
    fn fixture(second: bool) -> (Vec<u8>, Vec<u8>) {
        let mut normal = vec![0; 0x1000];
        let mut kernel = vec![0; 0x2000];
        for (at, bytes) in [
            (0x100, PRIMARY),
            (0x300, SCANNER),
            (0x500, RECORD_WIDTH),
            (0x600, REGION_SIZE),
            (0x700, HEADER_SIZE),
            (0x800, DIRECT_READER),
        ] {
            normal[at..at + bytes.len()].copy_from_slice(bytes);
        }
        normal[0x180..0x186].copy_from_slice(&[0x19, 0x50, 0x44, 6, 0xff, 0xf1]);
        let delta = 0x180u16 - 0x15a;
        // Format III BR: disp[8:4] | 1011 | disp[3:1] | cond 0101.
        let branch = 0x0585 | (((delta >> 1) & 7) << 4) | (((delta >> 4) & 31) << 11);
        normal[0x15a..0x15c].copy_from_slice(&branch.to_le_bytes());
        for (offset, target) in [(24, 0x500), (32, 0x600), (40, 0x700), (58, 0x300)] {
            let delta = (target - (0x100 + offset) as i32) as u32 & 0x3fffff;
            normal[0x100 + offset..0x102 + offset]
                .copy_from_slice(&(0xff80 | ((delta >> 16) as u16)).to_le_bytes());
            normal[0x102 + offset..0x104 + offset].copy_from_slice(&(delta as u16).to_le_bytes());
        }
        put_pointer(&mut normal[0x300..], 24, 34, (BASE + 0x300 + 38) as u32);
        let shape = if second { SELECTOR_B } else { SELECTOR_A };
        normal[0x900..0x900 + shape.len()].copy_from_slice(shape);
        let (khi, klo, dhi, dlo, slot1, slot2) = if second {
            (14, 18, 30, 34, 22, 38)
        } else {
            (8, 12, 22, 26, 16, 30)
        };
        put_pointer(&mut normal[0x900..], khi, klo, 0x1000);
        put_pointer(&mut normal[0x900..], dhi, dlo, (BASE + 0x800) as u32);
        let slot = [normal[0x31e], normal[0x31f]];
        normal[0x900 + slot1..0x902 + slot1].copy_from_slice(&slot);
        normal[0x900 + slot2..0x902 + slot2].copy_from_slice(&slot);
        kernel[0x1000..0x1000 + KERNEL_READER.len()].copy_from_slice(KERNEL_READER);
        (normal, kernel)
    }

    #[test]
    fn both_callback_selection_forms_require_the_kernel_reader() {
        for second in [false, true] {
            let (normal, kernel) = fixture(second);
            assert!(matches!(
                discover_v850_native(&normal, Some(&kernel)),
                Observation::Known(_)
            ));
            assert!(matches!(
                discover_v850_native(&normal, None),
                Observation::Unresolved(Unresolved::ResidentCodeRequired(0x1000))
            ));
            assert!(matches!(
                discover_v850_native(&normal, Some(&kernel[..0x1000])),
                Observation::Unresolved(_)
            ));
        }
    }

    #[test]
    fn end_branch_requires_the_format_iii_opcode() {
        let (mut normal, kernel) = fixture(false);
        let branch = le16(&normal, 0x15a);
        // Same displacement and condition bits, different opcode field.
        let other = (branch & !0x0780) | 0x0300;
        normal[0x15a..0x15c].copy_from_slice(&other.to_le_bytes());
        assert!(matches!(
            discover_v850_native(&normal, Some(&kernel)),
            Observation::Unresolved(Unresolved::ReaderNotRecognized)
        ));
    }

    #[test]
    fn bus_permutation_has_explicit_bit_and_address_direction() {
        let mut stored = vec![0; 8192];
        stored[2..4].copy_from_slice(&((1u16 << 2) | (1u16 << 14)).to_le_bytes());
        let decoded = decode_bus(&stored).unwrap();
        assert_eq!(&decoded[4..6], &((1u16 << 3) | (1u16 << 12)).to_le_bytes());
        assert_eq!(&decoded[2..4], &[0, 0]);
        assert!(decode_bus(&stored[..8190]).is_none());
        assert!(decode_bus(&[]).is_none());
    }

    #[test]
    fn full_bus_permutation_is_pinned_and_round_trips() {
        // Stored data bit k appears at native bit NATIVE_BIT[k].
        const NATIVE_BIT: [u32; 16] = [0, 1, 3, 2, 5, 4, 6, 7, 9, 8, 11, 10, 13, 14, 12, 15];
        for (k, &native) in NATIVE_BIT.iter().enumerate() {
            let mut stored = vec![0; 8192];
            stored[..2].copy_from_slice(&(1u16 << k).to_le_bytes());
            let decoded = decode_bus(&stored).unwrap();
            assert_eq!(le16(&decoded, 0), 1 << native, "data bit {k}");
            assert!(decoded[2..].iter().all(|&b| b == 0));
        }
        // Stored byte address bit pairs exchange positions within 8 KiB.
        for (stored_at, native_at) in [
            (2, 4),
            (4, 2),
            (8, 16),
            (16, 8),
            (128, 256),
            (256, 128),
            (512, 1024),
            (1024, 512),
            (2048, 4096),
            (4096, 2048),
            (32, 32),
            (64, 64),
            (8192 + 2, 8192 + 4),
        ] {
            let mut stored = vec![0; 16384];
            stored[stored_at..stored_at + 2].copy_from_slice(&1u16.to_le_bytes());
            let decoded = decode_bus(&stored).unwrap();
            let set: Vec<_> = (0..decoded.len()).filter(|&i| decoded[i] != 0).collect();
            assert_eq!(set, [native_at], "address {stored_at:#x}");
        }
        let mut state = 0x1234_5678u32;
        let x: Vec<u8> = (0..16384)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        assert_eq!(encode_bus(&decode_bus(&x).unwrap()).unwrap(), x);
        assert_eq!(decode_bus(&encode_bus(&x).unwrap()).unwrap(), x);
        assert!(encode_bus(&x[..8190]).is_none());
    }

    #[test]
    fn all_kernel_bus_permutation_bytes_are_required() {
        let (normal, kernel) = fixture(false);
        for offset in 0..KERNEL_READER.len() {
            let mut changed = kernel.clone();
            changed[0x1000 + offset] ^= 1;
            assert!(matches!(
                discover_v850_native(&normal, Some(&changed)),
                Observation::Unresolved(_)
            ));
        }
    }

    #[test]
    fn altered_normal_reads_and_helper_calls_cannot_match() {
        let (normal, kernel) = fixture(false);
        for at in [
            0x100 + 24,
            0x100 + 32,
            0x100 + 40,
            0x100 + 58,
            0x100 + 90,
            0x300 + 24,
            0x300 + 30,
            0x300 + 34,
            0x300 + 38,
            0x500 + 36,
            0x600 + 36,
            0x700,
            0x800,
            0x900 + 12,
            0x900 + 26,
        ] {
            let mut changed = normal.clone();
            changed[at] ^= 1;
            assert!(
                matches!(
                    discover_v850_native(&changed, Some(&kernel)),
                    Observation::Unresolved(_)
                ),
                "accepted normal mutation at {at:x}"
            );
        }
    }
}

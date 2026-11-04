//! Pure, offline conversion for an audited pair of native record layouts.
//!
//! This module performs no device I/O and does not authorize programming. A
//! caller must separately retain a verified full-storage backup, establish a
//! safe staging bank, verify every programmed byte, and publish the footer last.
//! The removed source range is returned as mandatory owned evidence, never lost.
use sha2::{Digest, Sha256};

const SOURCE_LEN: usize = 0x10000;
const TARGET_LEN: usize = 0xc000;
const FOOTER_LEN: usize = 8;
const SOURCE_MAGIC: u32 = 0xfedc4321;
const TARGET_MAGIC: u32 = 0xfedc4322;

/// An unsupported image or inconsistent storage capture prevents conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The supplied decoded image is outside the audited byte identities.
    UnknownFirmware,
    /// Native guard operands disagree with the audited record layout.
    NativeContract,
    /// A captured bank does not have its exact native size.
    BankLength,
    /// Neither captured source bank has the required native magic.
    NoAuthoritativeBank,
    /// The selected bank has an unrecognized maintenance state.
    MaintenanceState,
}

/// An audited pair, bound to actual decoded images rather than model names.
#[derive(Clone, Debug)]
pub struct LayoutPair {
    source_image_sha256: [u8; 32],
    target_image_sha256: [u8; 32],
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex_digest(s: &str) -> [u8; 32] {
    let mut result = [0; 32];
    for (i, slot) in result.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("audited digest");
    }
    result
}
impl LayoutPair {
    /// Bind only OEM images decoded with their matching Kernel policy.
    /// Standalone Normal decoding leaves XOR exceptions unresolved and is refused.
    pub fn discover(source_normal: &[u8], target_normal: &[u8]) -> Result<Self, Error> {
        let source_image_sha256 = digest(source_normal);
        let target_image_sha256 = digest(target_normal);
        let source_known = ["014868226d2b9ef07685fb612d0060e4aeee6552dc48aa53371bd2631462d09b"]
            .iter()
            .any(|s| hex_digest(s) == source_image_sha256);
        let target_known = ["4c57a8f1a43367489a24ed591ba3bcd0e87267a07b58d290a8f658d2cc200025"]
            .iter()
            .any(|s| hex_digest(s) == target_image_sha256);
        if !source_known || !target_known {
            return Err(Error::UnknownFirmware);
        }
        let source = super::discover(source_normal).ok_or(Error::NativeContract)?;
        let target = super::discover(target_normal).ok_or(Error::NativeContract)?;
        if source.magic != SOURCE_MAGIC
            || source.stride() != Some(SOURCE_LEN as u32)
            || target.magic != TARGET_MAGIC
            || target.stride() != Some(TARGET_LEN as u32)
        {
            return Err(Error::NativeContract);
        }
        Ok(Self {
            source_image_sha256,
            target_image_sha256,
        })
    }

    /// Convert the bank selected by the OEM source selector, keeping both input
    /// banks untouched. No footer is included in `body_before_commit`.
    ///
    /// The result alone is insufficient for live programming: the caller must
    /// also exclude any competing valid target header and preserve a source
    /// boot path through all erase/program failures and firmware handoff.
    pub fn convert(&self, banks: [&[u8]; 2]) -> Result<Conversion, Error> {
        if banks.iter().any(|b| b.len() != SOURCE_LEN) {
            return Err(Error::BankLength);
        }
        let valid = banks.map(|b| magic(b) == SOURCE_MAGIC);
        let authoritative = match valid {
            [false, false] => return Err(Error::NoAuthoritativeBank),
            [true, false] => 0,
            [false, true] => 1,
            [true, true] => usize::from(sequence(banks[0]) <= sequence(banks[1])),
        };
        let source = banks[authoritative];
        let state = u16::from_be_bytes(source[SOURCE_LEN - 8..SOURCE_LEN - 6].try_into().unwrap());
        if state != 0x8765 {
            return Err(Error::MaintenanceState);
        }
        let mut body = vec![0xff; TARGET_LEN - FOOTER_LEN];
        body[..0x4000].copy_from_slice(&source[..0x4000]);
        // Include unexplained padding/gaps through the final eight-byte footer;
        // FD5A..FFF8 is preserved, despite the normal accessor stopping at FD5A.
        body[0x4000..].copy_from_slice(&source[0x8000..SOURCE_LEN - FOOTER_LEN]);
        let mut footer = [0; FOOTER_LEN];
        // Preserve the proven committed maintenance state. FFFF is refused above:
        // its first-boot record initialization needs separate equivalence proof.
        footer[..2].copy_from_slice(&state.to_be_bytes());
        footer[2..6].copy_from_slice(&TARGET_MAGIC.to_be_bytes());
        footer[6..].copy_from_slice(&sequence(source).to_be_bytes());
        Ok(Conversion {
            body_before_commit: body,
            footer_to_commit_last: footer,
            receipt: Receipt {
                source_image_sha256: self.source_image_sha256,
                target_image_sha256: self.target_image_sha256,
                source_bank_sha256: banks.map(digest),
                authoritative_bank: authoritative,
                source_sequence: sequence(source),
                removed_source_offset: 0x4000,
                removed_source_bytes: source[0x4000..0x8000].to_vec(),
                original_source_footer: source[SOURCE_LEN - FOOTER_LEN..].try_into().unwrap(),
            },
        })
    }
}
fn magic(bank: &[u8]) -> u32 {
    u32::from_be_bytes(bank[bank.len() - 6..bank.len() - 2].try_into().unwrap())
}
fn sequence(bank: &[u8]) -> u16 {
    u16::from_be_bytes(bank[bank.len() - 2..].try_into().unwrap())
}

/// Conversion result intentionally separates the final native validity footer.
#[must_use = "retain the conversion receipt and full source backup before any device write"]
#[derive(Clone, Debug)]
pub struct Conversion {
    /// Target bytes up to, but excluding, its eight-byte native footer.
    body_before_commit: Vec<u8>,
    /// Native committed state 8765, target magic, and source sequence; publish last.
    footer_to_commit_last: [u8; FOOTER_LEN],
    /// Mandatory preservation evidence; includes every byte omitted from target.
    receipt: Receipt,
}

/// This receipt supplements, and never substitutes for, a verified full backup.
#[must_use = "the removed source bytes must be retained, not discarded"]
#[derive(Clone, Debug)]
pub struct Receipt {
    /// Audited decoded source image identity.
    source_image_sha256: [u8; 32],
    /// Audited decoded target image identity.
    target_image_sha256: [u8; 32],
    /// Hashes of both complete captured source banks in native A/B order.
    source_bank_sha256: [[u8; 32]; 2],
    /// Bank selected by native unsigned sequence ordering; ties select B.
    authoritative_bank: usize,
    /// Selected source sequence, without guessed wraparound arithmetic.
    source_sequence: u16,
    /// Source-relative start of the separately retained region.
    removed_source_offset: usize,
    /// Exact source 4000..7FFF bytes, including diagnostic history/state.
    removed_source_bytes: Vec<u8>,
    /// Exact source footer, permitting lossless offline reconstruction.
    original_source_footer: [u8; FOOTER_LEN],
}

impl Conversion {
    /// Target payload, excluding its native eight-byte footer.
    pub fn body_before_commit(&self) -> &[u8] {
        &self.body_before_commit
    }
    /// Complete logical footer for offline verification only. A live writer must
    /// program state and sequence first, then publish magic last; eight bytes
    /// must never be assumed to program atomically.
    pub fn footer_to_commit_last(&self) -> &[u8; 8] {
        &self.footer_to_commit_last
    }
    /// Maintenance word to program before publishing magic (bank end minus eight).
    pub fn footer_state(&self) -> [u8; 2] {
        self.footer_to_commit_last[..2].try_into().unwrap()
    }
    /// Sequence to program before publishing magic (bank end minus two).
    pub fn footer_sequence(&self) -> [u8; 2] {
        self.footer_to_commit_last[6..].try_into().unwrap()
    }
    /// Four-byte validity marker to publish only after all other bytes verify.
    pub fn footer_magic_commit_last(&self) -> [u8; 4] {
        self.footer_to_commit_last[2..6].try_into().unwrap()
    }
    /// Mandatory immutable preservation evidence.
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
}
impl Receipt {
    /// Audited decoded source identity.
    pub fn source_image_sha256(&self) -> [u8; 32] {
        self.source_image_sha256
    }
    /// Audited decoded target identity.
    pub fn target_image_sha256(&self) -> [u8; 32] {
        self.target_image_sha256
    }
    /// Complete source bank identities, A then B.
    pub fn source_bank_sha256(&self) -> [[u8; 32]; 2] {
        self.source_bank_sha256
    }
    /// Native-selected source bank index.
    pub fn authoritative_bank(&self) -> usize {
        self.authoritative_bank
    }
    /// Native-selected source sequence.
    pub fn source_sequence(&self) -> u16 {
        self.source_sequence
    }
    /// Start of separately retained source data.
    pub fn removed_source_offset(&self) -> usize {
        self.removed_source_offset
    }
    /// Every omitted source byte, retained without reinterpretation.
    pub fn removed_source_bytes(&self) -> &[u8] {
        &self.removed_source_bytes
    }
    /// Original footer for lossless reconstruction.
    pub fn original_source_footer(&self) -> [u8; 8] {
        self.original_source_footer
    }
}

#[cfg(test)]
pub(crate) fn fixture_conversion(banks: [&[u8]; 2]) -> Result<Conversion, Error> {
    LayoutPair {
        source_image_sha256: [0; 32],
        target_image_sha256: [0; 32],
    }
    .convert(banks)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair() -> LayoutPair {
        LayoutPair {
            source_image_sha256: [1; 32],
            target_image_sha256: [2; 32],
        }
    }
    fn bank(seq: u16) -> Vec<u8> {
        let mut b: Vec<_> = (0..SOURCE_LEN)
            .map(|i| ((i * 13 + i / 257) % 251) as u8)
            .collect();
        b[SOURCE_LEN - 8..SOURCE_LEN - 6].copy_from_slice(&0x8765u16.to_be_bytes());
        b[SOURCE_LEN - 6..SOURCE_LEN - 2].copy_from_slice(&SOURCE_MAGIC.to_be_bytes());
        b[SOURCE_LEN - 2..].copy_from_slice(&seq.to_be_bytes());
        b
    }
    fn joined(c: &Conversion) -> Vec<u8> {
        let mut b = c.body_before_commit.clone();
        b.extend(c.footer_to_commit_last);
        b
    }
    // Native parameter mapping and occupied-entry scan, independently modeled
    // from source54E1DC/54E0B8 and target550144/550020. No conversion offsets
    // are reused by the reader: its role-specific native region bases are explicit.
    fn parameter(bank: &[u8], id: usize, target: bool) -> Option<u16> {
        let (base, span, payload, first) = match (id, target) {
            (0..=0x9f, false) => (0x9984, 0x1928, 0x140, 0),
            (0..=0x9f, true) => (0x5984, 0x1928, 0x140, 0),
            (0xa0..=0xaf, false) => (0x8000, 0x352, 0x20, 0xa0),
            (0xa0..=0xaf, true) => (0x4000, 0x352, 0x20, 0xa0),
            (0xb0..=0x18f, false) => (0xc20c, 0x2328, 0x1c0, 0xb0),
            (0xb0..=0x18f, true) => (0x820c, 0x2328, 0x1c0, 0xb0),
            (0x190..=0x19f, false) => (0xe534, 0x1fe, 0x20, 0x190),
            (0x190..=0x19f, true) => (0xa534, 0x1fe, 0x20, 0x190),
            (0x1a0, false) => (0x8352, 0x32, 2, 0x1a0),
            (0x1a0, true) => (0x4352, 0x32, 2, 0x1a0),
            (0x210..=0x28f, false) => (0xe932, 0x1428, 0x100, 0x210),
            (0x210..=0x28f, true) => (0xa932, 0x1428, 0x100, 0x210),
            _ => return None,
        };
        let slots = span / (payload + 2);
        let used = (0..slots)
            .take_while(|i| bank[base + 2 * i] != 0xff)
            .count();
        let latest = used.saturating_sub(1);
        let p = base + slots * 2 + latest * payload + 2 * (id - first);
        Some(u16::from_be_bytes(bank[p..p + 2].try_into().unwrap()))
    }
    #[test]
    fn lossless_receipt_reconstructs_every_selected_source_byte() {
        let a = bank(7);
        let b = bank(8);
        let before = [a.clone(), b.clone()];
        let c = pair().convert([&a, &b]).unwrap();
        let target = joined(&c);
        assert_eq!(c.receipt.authoritative_bank, 1);
        assert_eq!(magic(&target), TARGET_MAGIC);
        assert_eq!(sequence(&target), 8);
        let mut restored = Vec::new();
        restored.extend(&target[..0x4000]);
        restored.extend(&c.receipt.removed_source_bytes);
        restored.extend(&target[0x4000..TARGET_LEN - 8]);
        restored.extend(c.receipt.original_source_footer);
        assert_eq!(restored, b);
        assert_eq!([a, b], before);
        assert_eq!(c.receipt.source_bank_sha256[1], digest(&restored));
        assert_eq!(c.receipt().removed_source_offset(), 0x4000);
        assert_eq!(
            c.receipt().removed_source_bytes(),
            &before[1][0x4000..0x8000]
        );
        assert_eq!(
            c.receipt().original_source_footer(),
            <[u8; 8]>::try_from(&before[1][0xfff8..]).unwrap()
        );
        let mut footer = [0u8; 8];
        footer[..2].copy_from_slice(&c.footer_state());
        footer[6..].copy_from_slice(&c.footer_sequence());
        footer[2..6].copy_from_slice(&c.footer_magic_commit_last());
        assert_eq!(&footer, c.footer_to_commit_last());
    }
    #[test]
    fn native_parameter_views_front_records_and_calibration_blocks_survive() {
        for occupied in [0, 1, 3, 12, 20, 25] {
            let mut a = bank(3);
            let b = bank(2);
            for (base, span, payload) in [
                (0x8000, 0x352, 0x20),
                (0x8352, 0x32, 2),
                (0x9984, 0x1928, 0x140),
                (0xc20c, 0x2328, 0x1c0),
                (0xe534, 0x1fe, 0x20),
                (0xe932, 0x1428, 0x100),
            ] {
                let slots = span / (payload + 2);
                for i in 0..slots {
                    a[base + 2 * i..base + 2 * i + 2].fill(if i < occupied { 0 } else { 0xff });
                }
            }
            let target = joined(&pair().convert([&a, &b]).unwrap());
            for id in 0..0x400 {
                assert_eq!(
                    parameter(&a, id, false),
                    parameter(&target, id, true),
                    "A0 {id:04x}"
                );
            }
            for (source, dest, size) in [
                (0x8984, 0x4984, 0x200),
                (0x8b84, 0x4b84, 0x400),
                (0x8384, 0x4384, 0x200),
                (0x8584, 0x4584, 0x400),
                (0x8f84, 0x4f84, 0x200),
                (0x9184, 0x5184, 0x400),
                (0x9584, 0x5584, 0x200),
                (0x9784, 0x5784, 0x80),
                (0x9804, 0x5804, 0x80),
                (0x9884, 0x5884, 0x80),
                (0x9904, 0x5904, 0x80),
                (0xe732, 0xa732, 0x114),
                (0xb2ac, 0x72ac, 0x164),
                (0, 0, 0x2000),
                (0x2000, 0x2000, 0x2000),
            ] {
                assert_eq!(a[source..source + size], target[dest..dest + size]);
            }
        }
    }
    #[test]
    fn full_record_compaction_preserves_native_views_in_both_layouts() {
        // Source54DEEE/target54FE56: a full tag array selects native compaction;
        // the newest payload moves to slot zero and the next write uses slot one.
        let regions = [
            (0x8000, 0x4000, 0x352, 0x20),
            (0x8352, 0x4352, 0x32, 2),
            (0x9984, 0x5984, 0x1928, 0x140),
            (0xc20c, 0x820c, 0x2328, 0x1c0),
            (0xe534, 0xa534, 0x1fe, 0x20),
            (0xe932, 0xa932, 0x1428, 0x100),
        ];
        let mut original = bank(3);
        for &(source, _, span, payload) in &regions {
            let slots = span / (payload + 2);
            original[source..source + slots * 2].fill(0);
        }
        let converted = joined(&pair().convert([&original, &bank(2)]).unwrap());
        let compact = |input: &[u8], target: bool| {
            let mut output = vec![0xff; input.len()];
            let front = if target { 0x4000 } else { 0x8000 };
            output[..front].copy_from_slice(&input[..front]);
            for &(source, dest, span, payload) in &regions {
                let base = if target { dest } else { source };
                let slots = span / (payload + 2);
                assert!((0..slots).all(|i| input[base + i * 2] != 0xff));
                let latest = base + slots * 2 + (slots - 1) * payload;
                output[base..base + 2].fill(0);
                output[base + slots * 2..base + slots * 2 + payload]
                    .copy_from_slice(&input[latest..latest + payload]);
            }
            for (source, dest, len) in [
                (0x8384, 0x4384, 0x1600),
                (0xe732, 0xa732, 0x114),
                (0xb2ac, 0x72ac, 0x164),
            ] {
                let base = if target { dest } else { source };
                output[base..base + len].copy_from_slice(&input[base..base + len]);
            }
            output
        };
        let source_after = compact(&original, false);
        let target_after = compact(&converted, true);
        for id in 0..0x400 {
            let expected = parameter(&original, id, false);
            assert_eq!(parameter(&source_after, id, false), expected);
            assert_eq!(parameter(&target_after, id, true), expected);
        }
        assert_eq!(&target_after[..0x4000], &original[..0x4000]);
        assert_eq!(&target_after[0x4384..0x5984], &original[0x8384..0x9984]);
    }

    #[test]
    fn selection_matches_native_unsigned_order_and_tie_to_b() {
        for (left, right, expected) in [
            (0, 1, 1),
            (8, 7, 0),
            (7, 7, 1),
            (0xffff, 0, 0),
            (0, 0xffff, 1),
        ] {
            assert_eq!(
                pair()
                    .convert([&bank(left), &bank(right)])
                    .unwrap()
                    .receipt
                    .authoritative_bank,
                expected
            );
        }
        let mut invalid = bank(100);
        invalid[SOURCE_LEN - 6..SOURCE_LEN - 2].fill(0xff);
        assert_eq!(
            pair()
                .convert([&invalid, &bank(0)])
                .unwrap()
                .receipt
                .authoritative_bank,
            1
        );
        assert_eq!(
            pair()
                .convert([&bank(0), &invalid])
                .unwrap()
                .receipt
                .authoritative_bank,
            0
        );
        assert_eq!(
            pair().convert([&invalid, &invalid]).unwrap_err(),
            Error::NoAuthoritativeBank
        );
    }
    #[test]
    fn unresolved_erased_maintenance_state_is_not_silently_initialized() {
        let mut a = bank(9);
        a[SOURCE_LEN - 8..SOURCE_LEN - 6].fill(0xff);
        for other_state in [0x8765u16, 0xffff] {
            let mut b = bank(8);
            b[SOURCE_LEN - 8..SOURCE_LEN - 6].copy_from_slice(&other_state.to_be_bytes());
            assert_eq!(
                pair().convert([&a, &b]).unwrap_err(),
                Error::MaintenanceState
            );
        }
    }

    #[test]
    fn unsupported_or_malformed_evidence_is_refused() {
        assert_eq!(
            LayoutPair::discover(&[], &[]).unwrap_err(),
            Error::UnknownFirmware
        );
        assert_eq!(
            pair().convert([&[], &bank(1)]).unwrap_err(),
            Error::BankLength
        );
        let mut a = bank(10);
        a[SOURCE_LEN - 8..SOURCE_LEN - 6].fill(0);
        assert_eq!(
            pair().convert([&a, &bank(1)]).unwrap_err(),
            Error::MaintenanceState
        );
    }
}

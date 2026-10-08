//! Legacy Normal container with an embedded ROM and a trailing word-key table.

use super::super::transform_with_policy;
use super::{DecodeError, EnvelopeCodec, HeaderInfo, Layout, SelectedLayout};
use crate::ComponentKind;

const CONTAINER_SIZE: usize = 0x100000;
const ROM_START: usize = 0xc000;
const PAYLOAD_START: usize = 0x10000;
const PAYLOAD_SIZE: usize = 0xc3000;
const PAYLOAD_END: usize = PAYLOAD_START + PAYLOAD_SIZE;
const KEY_START: usize = 0xe0000;
const KEY_SIZE: usize = PAYLOAD_SIZE / 16;
const KEY_END: usize = KEY_START + KEY_SIZE;
const PREFIX: &[u8] = b"PIONEER ";
const XOR_EXCEPTIONS: &[u32] = &[0x8000, 0x70000];
const CODE_END: usize = 0xbbffc;
const DATA_START: usize = 0xc0000;
const DATA_END: usize = 0xc1000;
const CHECKSUM: usize = 0xc2000;
const WORD: usize = 4;
const HARDWARE_TAG_SIZE: usize = 8;

pub(super) struct TailKey;

impl EnvelopeCodec for TailKey {
    fn layout(&self) -> Layout {
        Layout::NormalTailKey
    }

    fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
        if header.kind != Some(ComponentKind::Normal)
            || data.len() != CONTAINER_SIZE
            || header.hardware_version.len() != HARDWARE_TAG_SIZE
            || !data[ROM_START..PAYLOAD_START]
                .windows(header.hardware_version.len())
                .any(|tag| tag == header.hardware_version.as_bytes())
        {
            return None;
        }
        let key = &data[KEY_START..KEY_END];
        let prefix = self.transform(
            &data[PAYLOAD_START..PAYLOAD_START + PREFIX.len()],
            key,
            false,
            &[],
        )?;
        prefix.starts_with(PREFIX).then(|| {
            (
                self.layout(),
                PAYLOAD_START,
                PAYLOAD_END,
                key.to_vec(),
                data[PAYLOAD_END..].to_vec(),
            )
        })
    }

    fn validate(&self, data: &[u8]) -> Result<(), DecodeError> {
        let image = self
            .transform(
                data.get(PAYLOAD_START..PAYLOAD_END)
                    .ok_or(DecodeError::InvalidPayload)?,
                data.get(KEY_START..KEY_END)
                    .ok_or(DecodeError::InvalidPayload)?,
                false,
                &[],
            )
            .ok_or(DecodeError::InvalidPayload)?;
        let stored = u32::from_le_bytes(image[CHECKSUM..CHECKSUM + WORD].try_into().unwrap());
        let calculated = payload_checksum(&image).ok_or(DecodeError::InvalidPayload)?;
        if stored != calculated {
            return Err(DecodeError::ChecksumMismatch {
                layout: self.layout(),
                checksum_offset: PAYLOAD_START + CHECKSUM,
                stored,
                calculated,
            });
        }
        Ok(())
    }

    fn transform(&self, bytes: &[u8], key: &[u8], encode: bool, _: &[u32]) -> Option<Vec<u8>> {
        transform_with_policy(bytes, key, encode, false, XOR_EXCEPTIONS)
    }
}

// The receiver excludes the reserved gap and includes a separate data page.
fn payload_checksum(image: &[u8]) -> Option<u32> {
    Some(
        image
            .get(..CODE_END)?
            .chunks_exact(WORD)
            .chain(image.get(DATA_START..DATA_END)?.chunks_exact(WORD))
            .fold(0u32, |sum, word| {
                sum.wrapping_sub(u32::from_le_bytes(word.try_into().unwrap()))
            }),
    )
}

#[cfg(test)]
#[path = "tail_key_tests.rs"]
mod tests;

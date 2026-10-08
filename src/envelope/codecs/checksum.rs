//! Sparse checksum wrapper; the enclosed bytes retain their stored representation.

use super::{DecodeError, EnvelopeCodec, HeaderInfo, Layout, SelectedLayout};
use crate::ComponentKind;

const HEADER_END: usize = 0x200;
const CHECKSUM: usize = 0x8000;
const PAYLOAD: usize = 0x10000;
const WORD: usize = 4;
const ERASED: u8 = 0xff;

pub(super) struct Sparse;

impl EnvelopeCodec for Sparse {
    fn layout(&self) -> Layout {
        Layout::SparseChecksum
    }

    fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
        if !matches!(
            header.kind,
            Some(ComponentKind::Kernel | ComponentKind::Normal)
        ) || data.len() <= PAYLOAD
            || !data[HEADER_END..CHECKSUM].iter().all(|&b| b == ERASED)
            || !data[CHECKSUM + WORD..PAYLOAD].iter().all(|&b| b == ERASED)
        {
            return None;
        }
        Some((self.layout(), PAYLOAD, data.len(), Vec::new(), Vec::new()))
    }

    fn validate(&self, data: &[u8]) -> Result<(), DecodeError> {
        let payload = data.get(PAYLOAD..).ok_or(DecodeError::InvalidPayload)?;
        if payload.len() % WORD != 0 {
            return Err(DecodeError::PayloadAlignment {
                layout: self.layout(),
                alignment: WORD,
                actual: payload.len(),
            });
        }
        let stored = data
            .get(CHECKSUM..CHECKSUM + WORD)
            .and_then(|word| word.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(DecodeError::InvalidPayload)?;
        let calculated = checksum(payload);
        if stored != calculated {
            return Err(DecodeError::ChecksumMismatch {
                layout: self.layout(),
                checksum_offset: CHECKSUM,
                stored,
                calculated,
            });
        }
        Ok(())
    }

    fn transform(&self, bytes: &[u8], _: &[u8], _: bool, _: &[u32]) -> Option<Vec<u8>> {
        (bytes.len() % WORD == 0).then(|| bytes.to_vec())
    }

    fn finish_repack(&self, data: &mut [u8]) -> Option<()> {
        let value = checksum(data.get(PAYLOAD..)?);
        data.get_mut(CHECKSUM..CHECKSUM + WORD)?
            .copy_from_slice(&value.to_le_bytes());
        Some(())
    }
}

fn checksum(payload: &[u8]) -> u32 {
    payload.chunks_exact(WORD).fold(0u32, |sum, word| {
        sum.wrapping_sub(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
    })
}

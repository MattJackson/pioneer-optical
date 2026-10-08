//! Byte-block Normal decoding keyed by a proven embedded Kernel routine.

use super::{DecodeError, EnvelopeCodec, HeaderInfo, Layout, SelectedLayout};
use crate::{envelope::Envelope, ComponentKind};

const CONTAINER_SIZE: usize = 0x100000;
const ROM_START: usize = 0xc000;
const ROM_END: usize = 0x10000;
const PAYLOAD_START: usize = 0x10000;
const CODE_END: usize = 0x8c000 - PAYLOAD_START;
const DATA_START: usize = 0x90000 - PAYLOAD_START;
const PAYLOAD_END: usize = 0x91000;
const IMAGE_SIZE: usize = PAYLOAD_END - PAYLOAD_START;
const BLOCK: usize = 0x100;
const CHECKSUM_START: usize = 0x10;
const PREFIX: &[u8] = b"PIONEER ";

// Complete position-independent M32C decoder, including the boot-key address,
// byte complement, reversal, rotation, XOR, loop bound and return.
const DECODER: &[u8] = &[
    0xec, 0x0c, 0x8f, 0x7c, 0xbc, 0x00, 0xc0, 0xff, 0x03, 0x9d, 0xff, 0x00, 0xc1, 0xea, 0x89, 0xfb,
    0x83, 0xe3, 0xf8, 0x81, 0xb2, 0xc9, 0x3b, 0x88, 0x4b, 0xa8, 0x5e, 0xc1, 0x8b, 0xc9, 0x6b, 0xf9,
    0x20, 0x83, 0xeb, 0xfc, 0x78, 0xf8, 0xc1, 0xa2, 0x88, 0xcb, 0xa8, 0xde, 0x91, 0xf2, 0x08, 0x80,
    0x9b, 0xc2, 0xdb, 0xfe, 0x88, 0x7f, 0x07, 0xa1, 0xbe, 0x83, 0xeb, 0xf4, 0x99, 0xb2, 0x08, 0xc1,
    0xa3, 0x80, 0xcb, 0xc8, 0x7b, 0x88, 0x7f, 0x07, 0xa1, 0xfe, 0x83, 0xfb, 0xf6, 0x38, 0xf4, 0x98,
    0xb5, 0xf5, 0x98, 0x3b, 0xfe, 0xc8, 0x29, 0xc0, 0x0b, 0x38, 0xf6, 0x98, 0xb5, 0xf7, 0xc8, 0xe9,
    0x91, 0xbb, 0xfc, 0x91, 0xb2, 0x08, 0xc0, 0x3b, 0xe9, 0x71, 0xc9, 0x9b, 0x78, 0xf8, 0x47, 0x80,
    0x00, 0x8a, 0x97, 0x8e, 0x3e, 0xfc,
];

pub(super) struct BootKey;
impl EnvelopeCodec for BootKey {
    fn layout(&self) -> Layout {
        Layout::NormalBootKey
    }

    fn detect(&self, _: &[u8], _: &HeaderInfo) -> Option<SelectedLayout> {
        None
    }

    fn candidates_with_kernel(
        &self,
        data: &[u8],
        header: &HeaderInfo,
        kernel: &Envelope,
    ) -> Vec<SelectedLayout> {
        select(data, header, kernel).into_iter().collect()
    }

    fn validate_decoded(&self, image: &[u8]) -> Result<(), DecodeError> {
        let code = image
            .get(CHECKSUM_START..CODE_END)
            .ok_or(DecodeError::InvalidPayload)?;
        let data = image
            .get(DATA_START..IMAGE_SIZE)
            .ok_or(DecodeError::InvalidPayload)?;
        let sum = code
            .chunks_exact(2)
            .chain(data.chunks_exact(2))
            .fold(0u16, |sum, word| {
                sum.wrapping_add(u16::from_le_bytes([word[0], word[1]]))
            });
        if sum != 0 {
            return Err(DecodeError::DecodedChecksum {
                layout: self.layout(),
                word_bits: 16,
                sum: u32::from(sum),
            });
        }
        Ok(())
    }

    fn transform(&self, bytes: &[u8], key: &[u8], encode: bool, _: &[u32]) -> Option<Vec<u8>> {
        if bytes.len() != IMAGE_SIZE || key.len() != BLOCK {
            return None;
        }
        let mut out = bytes.to_vec();
        for range in [0..CODE_END, DATA_START..IMAGE_SIZE] {
            for (input, output) in bytes[range.clone()]
                .chunks_exact(BLOCK)
                .zip(out[range].chunks_exact_mut(BLOCK))
            {
                transform_block(input, output, key, encode);
            }
        }
        Some(out)
    }
}

fn select(data: &[u8], header: &HeaderInfo, kernel: &Envelope) -> Option<SelectedLayout> {
    if data.len() != CONTAINER_SIZE
        || header.kind != Some(ComponentKind::Normal)
        || kernel.info().kind != ComponentKind::Kernel
        || kernel.info().layout != Layout::KernelRom
        || kernel.info().payload_offset != ROM_START
        || kernel.image.len() != ROM_END - ROM_START
        || kernel
            .image
            .windows(DECODER.len())
            .filter(|bytes| *bytes == DECODER)
            .count()
            != 1
    {
        return None;
    }
    let key: Vec<u8> = kernel.image[..BLOCK].iter().map(|byte| !byte).collect();
    let mut prefix = [0; BLOCK];
    transform_block(
        &data[PAYLOAD_START..PAYLOAD_START + BLOCK],
        &mut prefix,
        &key,
        false,
    );
    prefix.starts_with(PREFIX).then(|| {
        (
            Layout::NormalBootKey,
            PAYLOAD_START,
            PAYLOAD_END,
            key,
            data[PAYLOAD_END..].to_vec(),
        )
    })
}

pub(super) fn transform_block(input: &[u8], output: &mut [u8], key: &[u8], encode: bool) {
    for (j, &key) in key.iter().enumerate() {
        let reversed = BLOCK - 1 - j;
        let shift = u32::from(key & 7);
        if encode {
            output[j] = (input[reversed] ^ key).rotate_right(shift);
        } else {
            output[reversed] = input[j].rotate_left(shift) ^ key;
        }
    }
}

#[cfg(test)]
#[path = "boot_key_tests.rs"]
mod tests;

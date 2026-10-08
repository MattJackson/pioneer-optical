use super::super::{
    contains, jump_seed, legacy_le_kernel, make_key, recover_seed, transform, HeaderInfo, Layout,
    SelectedLayout,
};
use super::EnvelopeCodec;
use crate::ComponentKind;

const HEADER: usize = 0x200;
const KEY: usize = 0x1000;
const BODY: usize = 0x10000;
const FRONT_BODY: usize = HEADER + KEY;
const END: usize = FRONT_BODY + BODY;
const ID_SAMPLE_END: usize = KEY + 0x40;
const SEED_SAMPLE: usize = 16;

pub(super) struct Front;
impl EnvelopeCodec for Front {
    fn decoded_checksum(&self, image: &[u8]) -> Option<u32> {
        Some(super::super::be32_sum(image))
    }
    fn kernel_transfer(&self, envelope: &super::super::DecodedEnvelope) -> Option<Vec<u8>> {
        front_key_transfer(envelope)
    }
    fn layout(&self) -> Layout {
        Layout::KernelFront
    }
    fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
        if header.kind != Some(ComponentKind::Kernel) || data.len() < END {
            return None;
        }
        let key = &data[HEADER..FRONT_BODY];
        let sample = transform(&data[FRONT_BODY..FRONT_BODY + ID_SAMPLE_END], key, false)?;
        contains(&sample[KEY..], b"SAT ").then(|| {
            (
                self.layout(),
                FRONT_BODY,
                END,
                key.to_vec(),
                data[END..].to_vec(),
            )
        })
    }
}

pub(super) struct Derived;
impl EnvelopeCodec for Derived {
    fn decoded_checksum(&self, image: &[u8]) -> Option<u32> {
        Some(super::super::be32_sum(image))
    }
    fn kernel_transfer(&self, envelope: &super::super::DecodedEnvelope) -> Option<Vec<u8>> {
        front_key_transfer(envelope)
    }
    fn layout(&self) -> Layout {
        Layout::KernelDerived
    }
    fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
        if header.kind != Some(ComponentKind::Kernel) || data.len() < END {
            return None;
        }
        let state = recover_seed(&data[data.len() - SEED_SAMPLE..])?;
        let seed = jump_seed(state, data.len() - HEADER - SEED_SAMPLE + KEY, true);
        let key = make_key(seed, KEY);
        let sample = transform(&data[HEADER..HEADER + ID_SAMPLE_END], &key, false)?;
        contains(&sample[KEY..], b"SAT ").then(|| {
            (
                self.layout(),
                HEADER,
                HEADER + BODY,
                key,
                data[HEADER + BODY..].to_vec(),
            )
        })
    }
}

pub(super) struct Legacy;
impl EnvelopeCodec for Legacy {
    fn layout(&self) -> Layout {
        Layout::KernelLegacyLe
    }
    fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
        if header.kind != Some(ComponentKind::Kernel) {
            return None;
        }
        legacy_le_kernel(data)
    }
}

// File framing and receiver framing are different representations. Both modern
// file codecs provide the same front-key receiver image without an OEM profile.
fn front_key_transfer(envelope: &super::super::DecodedEnvelope) -> Option<Vec<u8>> {
    if envelope.image.len() != BODY
        || envelope.key.len() != KEY
        || !super::super::be32_sum_zero(&envelope.image)
    {
        return None;
    }
    let file = envelope.repack(&envelope.image)?;
    if file.len() != END {
        return None;
    }
    let mut wire = Vec::with_capacity(END);
    wire.extend_from_slice(&file[..HEADER]);
    wire.extend_from_slice(&envelope.key);
    wire.extend(transform(&envelope.image, &envelope.key, true)?);
    Some(wire)
}

use super::super::{transform_with_rotation, HeaderInfo, Layout, SelectedLayout};
use super::EnvelopeCodec;
use crate::ComponentKind;

const HEADER: usize = 0x200;
const KEY: usize = 0x10000;
const PREFIX: usize = 64;
const WORD: usize = 4;

fn keyed(data: &[u8], header: &HeaderInfo, codec: &dyn EnvelopeCodec) -> Vec<SelectedLayout> {
    if header.kind != Some(ComponentKind::Normal) {
        return Vec::new();
    }
    let mut found = Vec::new();
    for start in [HEADER, HEADER + KEY] {
        let payload = start + KEY;
        let Some(sample) = data.get(payload..payload + PREFIX) else {
            continue;
        };
        let key = &data[start..payload];
        let Some(sample) = transform_with_rotation(sample, key, false, codec.reverse_rotation())
        else {
            continue;
        };
        if sample.starts_with(b"PIONEER ") {
            let end = data.len() & !(WORD - 1);
            found.push((
                codec.layout(),
                payload,
                end,
                key.to_vec(),
                data[end..].to_vec(),
            ));
        }
    }
    found
}

pub(super) struct Keyed;
impl EnvelopeCodec for Keyed {
    fn normal_transfer(&self, envelope: &super::super::DecodedEnvelope) -> Option<Vec<u8>> {
        continuous_transfer(self, envelope)
    }
    fn layout(&self) -> Layout {
        Layout::Normal
    }
    fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
        keyed(data, header, self).into_iter().next()
    }
    fn candidates(&self, data: &[u8], header: &HeaderInfo) -> Vec<SelectedLayout> {
        keyed(data, header, self)
    }
}
pub(super) struct Reverse;
impl EnvelopeCodec for Reverse {
    fn normal_transfer(&self, envelope: &super::super::DecodedEnvelope) -> Option<Vec<u8>> {
        continuous_transfer(self, envelope)
    }
    fn layout(&self) -> Layout {
        Layout::NormalReverse
    }
    fn reverse_rotation(&self) -> bool {
        true
    }
    fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
        keyed(data, header, self).into_iter().next()
    }
    fn candidates(&self, data: &[u8], header: &HeaderInfo) -> Vec<SelectedLayout> {
        keyed(data, header, self)
    }
}
pub(super) struct Scaled;
impl EnvelopeCodec for Scaled {
    fn normal_transfer(&self, envelope: &super::super::DecodedEnvelope) -> Option<Vec<u8>> {
        continuous_transfer(self, envelope)
    }
    fn layout(&self) -> Layout {
        Layout::NormalScaledKey
    }
    fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
        const UNITS: usize = 17;
        let size = data.len().checked_sub(HEADER)?;
        if header.kind != Some(ComponentKind::Normal) || size % UNITS != 0 {
            return None;
        }
        let key_len = size / UNITS;
        if key_len < WORD || key_len % WORD != 0 {
            return None;
        }
        let payload = HEADER + key_len;
        let key = &data[HEADER..payload];
        let sample =
            transform_with_rotation(data.get(payload..payload + PREFIX)?, key, false, false)?;
        sample
            .starts_with(b"PIONEER ")
            .then(|| (self.layout(), payload, data.len(), key.to_vec(), Vec::new()))
    }
}

fn continuous_transfer(
    codec: &dyn EnvelopeCodec,
    envelope: &super::super::DecodedEnvelope,
) -> Option<Vec<u8>> {
    if envelope.info.kind != ComponentKind::Normal
        || envelope.info.receiver_xor_policy.is_none()
        || envelope.unrecovered_tail().is_some()
        || !envelope.suffix.is_empty()
        || envelope.image.len() != envelope.info.payload_size
        || !super::super::be32_sum_zero(&envelope.image)
    {
        return None;
    }
    let mut out = envelope.header.clone();
    out.extend_from_slice(&envelope.prefix);
    out.extend(codec.transform(
        &envelope.image,
        &envelope.key,
        true,
        &envelope.xor_exceptions,
    )?);
    Some(out)
}

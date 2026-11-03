use super::super::{transform_with_rotation, HeaderInfo, Layout, SelectedLayout};
use super::EnvelopeCodec;
use crate::ComponentKind;

const HEADER: usize = 0x200;
const KEY: usize = 0x10000;
const PREFIX: usize = 64;
const WORD: usize = 4;

fn keyed(
    data: &[u8],
    header: &HeaderInfo,
    codec: &dyn EnvelopeCodec,
    native: Option<&super::super::NormalLayout>,
) -> Vec<SelectedLayout> {
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
        if sample.starts_with(b"PIONEER ")
            || native.is_some_and(|layout| layout.resolve(&sample).is_ok())
        {
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
    fn decoded_checksum(&self, image: &[u8]) -> Option<u32> {
        Some(super::super::be32_sum(image))
    }
    fn normal_transfer(&self, envelope: &super::super::DecodedEnvelope) -> Option<Vec<u8>> {
        continuous_transfer(self, envelope)
    }
    fn layout(&self) -> Layout {
        Layout::Normal
    }
    fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
        keyed(data, header, self, None).into_iter().next()
    }
    fn candidates(&self, data: &[u8], header: &HeaderInfo) -> Vec<SelectedLayout> {
        keyed(data, header, self, None)
    }
    fn candidates_with_kernel(
        &self,
        data: &[u8],
        header: &HeaderInfo,
        kernel: &super::super::Envelope,
    ) -> Vec<SelectedLayout> {
        let native = kernel.normal_layout().ok();
        keyed(data, header, self, native.as_ref())
    }
}
pub(super) struct Reverse;
impl EnvelopeCodec for Reverse {
    fn decoded_checksum(&self, image: &[u8]) -> Option<u32> {
        Some(super::super::be32_sum(image))
    }
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
        keyed(data, header, self, None).into_iter().next()
    }
    fn candidates(&self, data: &[u8], header: &HeaderInfo) -> Vec<SelectedLayout> {
        keyed(data, header, self, None)
    }
    fn candidates_with_kernel(
        &self,
        data: &[u8],
        header: &HeaderInfo,
        kernel: &super::super::Envelope,
    ) -> Vec<SelectedLayout> {
        let native = kernel.normal_layout().ok();
        keyed(data, header, self, native.as_ref())
    }
}
pub(super) struct Scaled;
impl EnvelopeCodec for Scaled {
    fn decoded_checksum(&self, image: &[u8]) -> Option<u32> {
        Some(super::super::be32_sum(image))
    }
    fn repair_decoded(&self, original: &[u8], image: &[u8]) -> Option<Vec<u8>> {
        if original.len() < 24
            || original.len() % 4 != 0
            || original.len() != image.len()
            || !original.starts_with(b"PIONEER ")
            || super::super::be32_sum(original) != 0
            || original[16..20] != image[16..20]
        {
            return None;
        }
        let mut corrected = image.to_vec();
        let old = u32::from_be_bytes(original[16..20].try_into().ok()?);
        let value = old.wrapping_sub(super::super::be32_sum(image));
        corrected[16..20].copy_from_slice(&value.to_be_bytes());
        (super::super::be32_sum(&corrected) == 0).then_some(corrected)
    }
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

#[cfg(test)]
mod scaled_tests {
    use super::*;

    #[test]
    fn legacy_scaled_checksum_repairs_operands_without_assuming_modern_header_length() {
        let mut original = vec![0xff; 64];
        original[..16].copy_from_slice(b"PIONEER TEST    ");
        // Legacy SAT1003 starts code here rather than storing a length word.
        original[20..24].copy_from_slice(&[0x79, 0, 0, 0x20]);
        original[16..20].fill(0);
        let sum = super::super::super::be32_sum(&original);
        original[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
        let mut changed = original.clone();
        changed[35] ^= 1;
        let repaired = Scaled.repair_decoded(&original, &changed).unwrap();
        assert_eq!(super::super::super::be32_sum(&repaired), 0);
        assert_eq!(&repaired[20..24], &original[20..24]);
        assert!(repaired
            .iter()
            .zip(&changed)
            .enumerate()
            .all(|(i, (a, b))| a == b || (16..20).contains(&i)));
        let mut reverse = repaired.clone();
        reverse[35] ^= 1;
        assert_eq!(
            Scaled.repair_decoded(&repaired, &reverse).unwrap(),
            original
        );
        assert_eq!(
            Scaled.repair_decoded(&original, &original).unwrap(),
            original
        );
        changed[16] ^= 1;
        assert!(Scaled.repair_decoded(&original, &changed).is_none());
        assert!(Scaled
            .repair_decoded(&original[..63], &original[..63])
            .is_none());
        assert!(Scaled.repair_decoded(&original, &original[..60]).is_none());
        let mut invalid = original.clone();
        invalid[36] ^= 1;
        assert!(Scaled.repair_decoded(&invalid, &invalid).is_none());
    }
}

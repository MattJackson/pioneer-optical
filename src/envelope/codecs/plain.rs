use super::super::{
    has_plain_image_layout, plane_lcg_xor, transformed_plane_layout, HeaderInfo, Layout,
    SelectedLayout, HEADER_LEN, PLANE_XOR_OFFSET,
};
use super::EnvelopeCodec;
use crate::ComponentKind;

pub(super) struct Plain;
impl EnvelopeCodec for Plain {
    fn layout(&self) -> Layout {
        Layout::Plain
    }
    fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
        if !matches!(
            header.kind,
            Some(ComponentKind::Normal | ComponentKind::Plane)
        ) || !has_plain_image_layout(data)
        {
            return None;
        }
        Some((
            self.layout(),
            HEADER_LEN,
            data.len(),
            Vec::new(),
            Vec::new(),
        ))
    }
    fn transform(&self, bytes: &[u8], _: &[u8], _: bool, _: &[u32]) -> Option<Vec<u8>> {
        Some(bytes.to_vec())
    }
}
pub(super) struct Whitened;
impl EnvelopeCodec for Whitened {
    fn layout(&self) -> Layout {
        Layout::TransformedPlane
    }
    fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
        transformed_plane_layout(data, header.kind?)
    }
    fn transform(&self, bytes: &[u8], _: &[u8], _: bool, _: &[u32]) -> Option<Vec<u8>> {
        let split = PLANE_XOR_OFFSET - HEADER_LEN;
        let mut output = bytes.get(..split)?.to_vec();
        output.extend(plane_lcg_xor(bytes.get(split..)?));
        Some(output)
    }
}

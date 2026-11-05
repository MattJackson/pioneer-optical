//! Complete OEM DSP writer ABI used by native phase loaders.
//! The body takes the DSP address in R0 and the value in E0, preserves ER4/ER5
//! and CCR, polls FF94, and writes through FF90/FF91. Address 0x2a0 additionally
//! updates a local shadow word. This binds instructions, not device readiness.
use super::Error;
use core::ops::Range;

/// Bound writer body and its one image-local relocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Complete executable body, including RTS.
    pub program: Range<usize>,
    /// Address of the existing shadow word; never relocated by a transplant.
    pub shadow: u32,
}
const BODY: &[u8] = &[
    0x01, 0x10, 0x6d, 0xf4, 0x0d, 0x85, 0x0d, 0x09, 0x02, 0x04, 0x04, 0x80, 0x79, 0x20, 0x10, 0x00,
    0x44, 0x06, 0xfc, 0x10, 0x0d, 0x92, 0x40, 0x14, 0x79, 0x29, 0x18, 0x00, 0x45, 0x4a, 0x79, 0x29,
    0x1c, 0x00, 0x44, 0x44, 0xfc, 0xb0, 0x0d, 0x92, 0x79, 0x62, 0x0f, 0xff, 0x6a, 0x09, 0xff, 0x94,
    0x77, 0x09, 0x45, 0xf8, 0x0c, 0x20, 0xe0, 0x0f, 0x14, 0xc0, 0x6a, 0x80, 0xff, 0x90, 0x6a, 0x8a,
    0xff, 0x91, 0x6a, 0x09, 0xff, 0x94, 0x77, 0x09, 0x45, 0xf8, 0x0c, 0x50, 0x6a, 0x80, 0xff, 0x90,
    0x6a, 0x8d, 0xff, 0x91, 0x6a, 0x09, 0xff, 0x94, 0x77, 0x09, 0x45, 0xf8, 0x79, 0x29, 0x02, 0xa0,
    0x46, 0x06, 0x6b, 0xa5, 0x00, 0x00, 0x32, 0xd4, 0x03, 0x04, 0x01, 0x10, 0x6d, 0x75, 0x54, 0x70,
];

/// Verify a loader's writer target against the complete native ABI.
/// The only variable operand is the shadow-word destination at bytes 100..104.
pub fn observe(normal: &[u8], address: u32) -> Result<Binding, Error> {
    let start = address
        .checked_sub(0x410000)
        .ok_or(Error::ResourceMismatch)? as usize;
    let end = start
        .checked_add(BODY.len())
        .ok_or(Error::ResourceMismatch)?;
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    if start & 1 != 0
        || !regions.stored.iter().any(|region| {
            let at = region.as_ptr() as usize - normal.as_ptr() as usize;
            start >= at && end <= at + region.len()
        })
    {
        return Err(Error::ResourceMismatch);
    }
    let bytes = normal.get(start..end).ok_or(Error::ResourceMismatch)?;
    if !bytes
        .iter()
        .zip(BODY)
        .enumerate()
        .all(|(i, (a, b))| (100..104).contains(&i) || a == b)
    {
        return Err(Error::ResourceMismatch);
    }
    let shadow = u32::from_be_bytes(bytes[100..104].try_into().expect("shadow operand"));
    if shadow & 1 != 0 || shadow > 0xffffff {
        return Err(Error::ResourceMismatch);
    }
    Ok(Binding {
        program: start..end,
        shadow,
    })
}

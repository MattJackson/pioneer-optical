//! Bounded MMC queries shared by device snapshots and individual callers.
use super::{Device, Error};
use crate::drive::Transport;

/// INQUIRY data, including the vendor's extra identification bytes.
#[derive(Clone, Debug)]
pub struct Inquiry {
    raw: [u8; 96],
    len: usize,
}
impl Inquiry {
    /// Validate a standard identity; retain only the declared response length.
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < 36 || b[0] & 0x1f != 5 {
            return None;
        }
        let len = (b[4] as usize + 5).min(b.len()).min(96);
        if len < 36 {
            return None;
        }
        let mut raw = [0; 96];
        raw[..len].copy_from_slice(&b[..len]);
        Some(Self { raw, len })
    }
    /// Device vendor.
    pub fn vendor(&self) -> &str {
        crate::field(&self.raw[8..16])
    }
    /// Product/model string.
    pub fn product(&self) -> &str {
        crate::field(&self.raw[16..32])
    }
    /// Firmware revision.
    pub fn revision(&self) -> &str {
        crate::field(&self.raw[32..36])
    }
    /// Vendor-specific extra information, often a firmware date on Pioneer.
    pub fn extra(&self) -> &str {
        crate::field(&self.raw[36..self.len.min(56)])
    }
    /// Exact transferred, declared bytes.
    pub fn raw(&self) -> &[u8] {
        &self.raw[..self.len]
    }
}
/// One complete GET CONFIGURATION feature descriptor.
#[derive(Clone, Debug)]
pub struct Feature {
    raw: [u8; 259],
    len: usize,
}
impl Feature {
    /// Validate the response for a request of exactly one feature (RT=2).
    pub fn parse(b: &[u8], code: u16) -> Result<Option<Self>, &'static str> {
        if b.len() < 8 {
            return Err("short header");
        }
        let declared = u32::from_be_bytes(b[..4].try_into().unwrap()) as u64 + 4;
        if declared < 8 || declared > b.len() as u64 {
            return Err("truncated response");
        }
        if declared == 8 {
            return Ok(None);
        }
        if declared < 12 || u16::from_be_bytes([b[8], b[9]]) != code {
            return Err("wrong feature");
        }
        let len = b[11] as usize + 4;
        if declared != (8 + len) as u64 {
            return Err("invalid feature length");
        }
        let mut raw = [0; 259];
        raw[..len].copy_from_slice(&b[8..8 + len]);
        Ok(Some(Self { raw, len }))
    }
    /// Descriptor bytes, including feature code, version and additional length.
    pub fn raw(&self) -> &[u8] {
        &self.raw[..self.len]
    }
    /// Descriptor payload, excluding its four-byte header.
    pub fn payload(&self) -> &[u8] {
        &self.raw[4..self.len]
    }
    /// Feature version, independent of current-medium activation.
    pub fn version(&self) -> u8 {
        (self.raw[2] >> 2) & 15
    }
}
/// A mode page 2A response, after skipping any block descriptors.
#[derive(Clone, Debug)]
pub struct Mechanical {
    page: [u8; 16],
}
impl Mechanical {
    /// Decode MODE SENSE(10), validating both outer and page lengths.
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < 8 {
            return None;
        }
        let end = u16::from_be_bytes([b[0], b[1]]) as usize + 2;
        let at = 8 + u16::from_be_bytes([b[6], b[7]]) as usize;
        let p = b.get(..end)?.get(at..)?;
        if p.len() < 16 || p[0] & 0x7f != 0x2a || p[1] < 14 || p.len() < p[1] as usize + 2 {
            return None;
        }
        let mut page = [0; 16];
        page.copy_from_slice(&p[..16]);
        Some(Self { page })
    }
    /// Drive buffer in KiB; zero is treated as not reported.
    pub fn buffer_kib(&self) -> Option<u16> {
        let n = u16::from_be_bytes([self.page[12], self.page[13]]);
        (n != 0).then_some(n)
    }
    /// Loading mechanism code, preserving future values.
    pub fn loader(&self) -> u8 {
        self.page[6] >> 5
    }
}
/// Read/write capability, with unknown distinguished from an explicit false.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MediaSupport {
    /// Whether the drive can read this medium.
    pub read: Option<bool>,
    /// Whether the drive can write this medium.
    pub write: Option<bool>,
}
/// Medium families displayed by optical-drive information panels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Media {
    /// CD-ROM.
    CdRom,
    /// CD-R.
    CdR,
    /// CD-RW.
    CdRw,
    /// DVD-ROM.
    DvdRom,
    /// DVD-R.
    DvdR,
    /// DVD-R dual layer.
    DvdRDl,
    /// DVD-RW.
    DvdRw,
    /// DVD+R.
    DvdPlusR,
    /// DVD+R dual layer.
    DvdPlusRDl,
    /// DVD+RW.
    DvdPlusRw,
    /// DVD+RW dual layer.
    DvdPlusRwDl,
    /// DVD-RAM.
    DvdRam,
    /// BD-ROM.
    BdRom,
    /// BD-R.
    BdR,
    /// BD-RE.
    BdRe,
    /// BD-R XL; needs more than a BD profile to establish support.
    BdRXl,
    /// BD-RE XL.
    BdReXl,
    /// HD DVD-ROM.
    HdDvdRom,
    /// HD DVD-R.
    HdDvdR,
    /// HD DVD-RAM.
    HdDvdRam,
    /// HD DVD-RW.
    HdDvdRw,
}
type FeatureResult<E> = (u16, Result<Option<Feature>, Error<E>>);

/// Individually queried descriptors. A refused feature does not hide its siblings.
#[derive(Debug)]
pub struct Configuration<E> {
    features: [FeatureResult<E>; 14],
}
impl<E> Configuration<E> {
    /// Exact descriptor result. `Ok(None)` means a successful negative response.
    pub fn feature(&self, code: u16) -> Option<&Result<Option<Feature>, Error<E>>> {
        self.features
            .iter()
            .find(|(id, _)| *id == code)
            .map(|(_, r)| r)
    }
    fn bytes(&self, code: u16) -> Option<&[u8]> {
        self.feature(code)?
            .as_ref()
            .ok()?
            .as_ref()
            .map(Feature::raw)
    }
    fn bit(&self, code: u16, offset: usize, mask: u8) -> Option<bool> {
        match self.feature(code)? {
            Ok(None) => Some(false),
            Ok(Some(f)) => f.raw().get(offset).map(|b| b & mask != 0),
            Err(_) => None,
        }
    }
    /// Physical interface reported by the drive, which may sit behind a USB bridge.
    pub fn interface(&self) -> Option<u32> {
        Some(u32::from_be_bytes(
            self.bytes(1)?.get(4..8)?.try_into().ok()?,
        ))
    }
    /// Standard drive serial number when present.
    pub fn serial(&self) -> Option<&str> {
        Some(crate::field(self.bytes(0x108)?.get(4..)?))
    }
    /// Removable-medium feature's loader code.
    pub fn loader(&self) -> Option<u8> {
        Some(self.bytes(3)?.get(4)? >> 5)
    }
    fn profile(&self, profiles: &[u16]) -> Option<bool> {
        let p = self.bytes(0)?.get(4..)?;
        if p.len() % 4 != 0 {
            return None;
        }
        Some(
            p.chunks_exact(4)
                .any(|c| profiles.contains(&u16::from_be_bytes([c[0], c[1]]))),
        )
    }
    fn bd(&self, code: u16, at: usize) -> Option<bool> {
        match self.feature(code)? {
            Ok(None) => Some(false),
            Ok(Some(f)) => Some(f.raw().get(at..at + 8)?.iter().any(|b| *b != 0)),
            Err(_) => None,
        }
    }
    /// Combine standard descriptors without confusing current media with support.
    pub fn media(&self, media: Media, mechanical: Option<&Mechanical>) -> MediaSupport {
        use Media::*;
        let mode = |byte: usize, mask: u8| mechanical.map(|m| m.page[byte] & mask != 0);
        let (read, write) = match media {
            CdRom => (self.profile(&[8, 9, 10]), Some(false)),
            CdR => (mode(2, 1), mode(3, 1)),
            CdRw => (mode(2, 2), mode(3, 2)),
            DvdRom => (mode(2, 8), Some(false)),
            DvdR => (mode(2, 16), mode(3, 16)),
            DvdRw => (
                self.profile(&[0x13, 0x14]).filter(|v| *v),
                self.profile(&[0x13, 0x14]),
            ),
            DvdRDl => (self.bit(0x1f, 6, 1), self.profile(&[0x15, 0x16])),
            DvdRam => (mode(2, 32), mode(3, 32)),
            DvdPlusR | DvdPlusRDl | DvdPlusRw | DvdPlusRwDl => {
                let code = match media {
                    DvdPlusR => 0x2b,
                    DvdPlusRDl => 0x3b,
                    DvdPlusRw => 0x2a,
                    _ => 0x3a,
                };
                let read = self
                    .feature(code)
                    .and_then(|r| r.as_ref().ok())
                    .map(Option::is_some);
                (read, self.bit(code, 4, 1))
            }
            BdRom => (self.bd(0x40, 24), Some(false)),
            BdR => (self.bd(0x40, 16), self.bd(0x41, 16)),
            BdRe => (self.bd(0x40, 8), self.bd(0x41, 8)),
            BdRXl | BdReXl => (None, None),
            HdDvdRom => (
                self.feature(0x50)
                    .and_then(|r| r.as_ref().ok())
                    .map(Option::is_some),
                Some(false),
            ),
            HdDvdR => (self.bit(0x50, 4, 1), self.bit(0x51, 4, 1)),
            HdDvdRam => (self.bit(0x50, 6, 1), self.bit(0x51, 6, 1)),
            HdDvdRw => (self.profile(&[0x53]).filter(|v| *v), self.profile(&[0x53])),
        };
        MediaSupport { read, write }
    }
}
/// Independent query results suitable for a GUI or CLI.
#[derive(Debug)]
pub struct Information<E> {
    /// Standard identity remains usable if vendor identity fails.
    pub inquiry: Result<Inquiry, Error<E>>,
    /// Pioneer serial, hardware and kernel/normal tags.
    pub pioneer: Result<crate::Identity, Error<E>>,
    /// Buffer and mechanical properties.
    pub mechanical: Result<Mechanical, Error<E>>,
    /// Standard medium and interface descriptors.
    pub configuration: Configuration<E>,
}
impl<T: Transport> Device<'_, T> {
    /// Query exactly one feature without allocating or truncating its descriptor.
    pub fn feature(&mut self, code: u16) -> Result<Option<Feature>, Error<T::Error>> {
        let mut b = [0; 268];
        let [hi, lo] = code.to_be_bytes();
        let n = self.read(&[0x46, 2, hi, lo, 0, 0, 0, 1, 12, 0], &mut b)?;
        Feature::parse(&b[..n], code).map_err(|_| Error::Malformed)
    }
}
pub(super) fn read<T: Transport>(d: &mut Device<'_, T>) -> Information<T::Error> {
    let mut b = [0; 96];
    let inquiry = d
        .read(&crate::cdb::inquiry(96), &mut b)
        .and_then(|n| Inquiry::parse(&b[..n]).ok_or(Error::Malformed));
    let pioneer = match &inquiry {
        Ok(i) => {
            let mut vendor = [0; crate::IDENTITY_LEN];
            d.read(&crate::cdb::vendor_identity(), &mut vendor)
                .and_then(|n| crate::Identity::parse(i.raw(), &vendor[..n]).ok_or(Error::Malformed))
        }
        _ => Err(Error::NotReported),
    };
    let mut b = [0; 512];
    let mechanical = d
        .read(&[0x5a, 8, 0x2a, 0, 0, 0, 0, 2, 0, 0], &mut b)
        .and_then(|n| Mechanical::parse(&b[..n]).ok_or(Error::Malformed));
    let features = [
        0, 1, 3, 0x1f, 0x2a, 0x2b, 0x3a, 0x3b, 0x40, 0x41, 0x50, 0x51, 0x108, 0x10c,
    ]
    .map(|code| (code, d.feature(code)));
    Information {
        inquiry,
        pioneer,
        mechanical,
        configuration: Configuration { features },
    }
}

//! Narrow metadata exclusions for established decoded component layouts.
use super::Region;
use crate::envelope::{Envelope, Layout};
use std::ops::Range;

const DESCRIPTOR: Range<usize> = 0..16;
const NORMAL_CHECKSUM: Range<usize> = 16..20;
const DESTINATION: Range<usize> = 24..40;
const KERNEL_ID: Range<usize> = 0x1000..0x1020;
const KERNEL_CHECKSUM: Range<usize> = 0x1020..0x1024;

pub(super) fn identify(envelope: &Envelope, regions: &mut [Region<'_>]) {
    let image = &envelope.image;
    let mut ranges = Vec::new();
    match envelope.info().layout {
        Layout::Normal | Layout::NormalReverse | Layout::NormalScaledKey
            if image.starts_with(b"PIONEER ") =>
        {
            if image
                .get(DESCRIPTOR)
                .is_some_and(|s| s.iter().all(u8::is_ascii))
            {
                ranges.push(DESCRIPTOR);
            }
            // These keyed layouts validate the decoded additive checksum.
            ranges.push(NORMAL_CHECKSUM);
            if image.get(DESTINATION).is_some_and(|s| {
                s.starts_with(b"ID") && s.iter().all(|b| b.is_ascii_alphanumeric() || *b == b' ')
            }) {
                ranges.push(DESTINATION);
            }
        }
        Layout::KernelFront | Layout::KernelDerived => {
            if image.get(KERNEL_ID).is_some_and(|s| {
                s.starts_with(envelope.info().hardware_version.as_bytes())
                    && s.iter().all(|b| b.is_ascii_alphanumeric() || *b == b' ')
            }) {
                ranges.push(KERNEL_ID);
            }
            ranges.push(KERNEL_CHECKSUM);
        }
        _ => {}
    }
    for region in regions {
        if region.stream.is_some() {
            continue;
        }
        for range in &ranges {
            let start = range.start.max(region.stored.start);
            let end = range.end.min(region.stored.end);
            if start < end {
                region
                    .metadata
                    .push(start - region.stored.start..end - region.stored.start);
            }
        }
    }
}

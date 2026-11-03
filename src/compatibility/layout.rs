//! Admission constraints for Normal-only persistent-address corrections.
//! Matching primary record dimensions alone never establishes correctability.
use crate::image::{
    layout::{AddressBasis, ParameterLayout},
    matrix::{Key, SatKey},
};

fn sat_layout(key: &Key) -> Option<&ParameterLayout> {
    match key {
        Key::Sat(
            SatKey::Sat1 { layout, .. } | SatKey::Sat8 { layout, .. } | SatKey::Sat9 { layout, .. },
        ) => Some(layout),
        _ => None,
    }
}

/// Find a concrete address collision when retaining the installed primary
/// records would place them inside non-erased bytes of the target Normal.
/// This describes supplied decoded bytes, not an observed device mutation.
/// A missing collision is not proof of safe relocation: writers, erases,
/// initialization, bank routing and component ownership still need proof.
pub(super) fn relocation_overlap(
    installed: &Key,
    target: &Key,
    normal: &[u8],
) -> Option<(u32, u32)> {
    let (Key::Sat(a), Key::Sat(b)) = (installed, target) else {
        return None;
    };
    if core::mem::discriminant(a) != core::mem::discriminant(b) {
        return None;
    }
    let installed = sat_layout(installed)?;
    let target = sat_layout(target)?;
    let ParameterLayout::FlashRecords { regions, .. } = installed else {
        return None;
    };
    let ParameterLayout::FlashRecords {
        regions: target_regions,
        ..
    } = target
    else {
        return None;
    };
    if regions.len() != target_regions.len() {
        return None;
    }
    // Limit this diagnosis to equal record formats and logical mappings. Only
    // the region addresses may differ; a format change is a separate blocker.
    let mut normalized = target.clone();
    if let ParameterLayout::FlashRecords { regions: copy, .. } = &mut normalized {
        for (region, required) in copy.iter_mut().zip(regions) {
            region.address = required.address;
        }
    }
    if &normalized != installed {
        return None;
    }
    const NORMAL_BASE: u32 = 0x410000;
    let normal_end = NORMAL_BASE.checked_add(u32::try_from(normal.len()).ok()?)?;
    for (required, original) in regions.iter().zip(target_regions) {
        if required.address == original.address || required.basis != AddressBasis::Absolute {
            continue;
        }
        let payload = required
            .address
            .checked_add(u32::from(required.header_bytes))?;
        let record_bytes = required
            .record_bytes
            .checked_mul(u32::from(required.record_count))?;
        let end = payload.checked_add(record_bytes)?;
        let first = payload.max(NORMAL_BASE);
        let last = end.min(normal_end);
        if first >= last {
            continue;
        }
        let bytes = normal.get((first - NORMAL_BASE) as usize..(last - NORMAL_BASE) as usize)?;
        if bytes.iter().any(|&byte| byte != 0xff) {
            return Some((required.address, end));
        }
    }
    None
}

/// Permit planning only a same-format primary-address difference. Every other
/// key field is retained in the returned comparison key, including independent
/// bank geometry. The native whole-program prover must still approve the bytes.
pub(super) fn address_only_candidate(installed: &Key, target: &Key) -> Option<(Key, u32, u32)> {
    let (Key::Sat(a), Key::Sat(b)) = (installed, target) else {
        return None;
    };
    if core::mem::discriminant(a) != core::mem::discriminant(b) {
        return None;
    }
    let source = sat_layout(installed)?;
    let destination = sat_layout(target)?;
    let ParameterLayout::FlashRecords { regions, .. } = source else {
        return None;
    };
    let ParameterLayout::FlashRecords {
        regions: target_regions,
        ..
    } = destination
    else {
        return None;
    };
    if regions.len() != 1
        || target_regions.len() != 1
        || regions[0].address == target_regions[0].address
    {
        return None;
    }
    let (from, to) = (target_regions[0].address, regions[0].address);
    let mut normalized = destination.clone();
    if let ParameterLayout::FlashRecords { regions, .. } = &mut normalized {
        regions[0].address = to;
    }
    if &normalized != source {
        return None;
    }
    let mut adjusted = target.clone();
    match &mut adjusted {
        Key::Sat(
            SatKey::Sat1 { layout, .. } | SatKey::Sat8 { layout, .. } | SatKey::Sat9 { layout, .. },
        ) => *layout = normalized,
        _ => return None,
    }
    Some((adjusted, from, to))
}

#[cfg(test)]
mod tests;

//! Apply shared COMP loader facts to the analysis report.
use super::Region;

pub(super) fn identify(image: &[u8], base: u32, regions: &mut [Region<'_>]) -> Result<(), usize> {
    let sizes: Vec<_> = regions
        .iter()
        .filter_map(|r| r.stream.map(|i| (i, r.size)))
        .collect();
    for destination in crate::comp_runtime::discover(image, base, &sizes)? {
        for region in regions
            .iter_mut()
            .filter(|r| r.stream == Some(destination.stream))
        {
            region.address = Some(destination.address);
            region.address_source = Some(destination.evidence.clone());
        }
    }
    Ok(())
}

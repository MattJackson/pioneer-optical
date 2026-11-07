use super::super::native_graph;
use super::*;
/// Coherent native source controller/profile locations. External hardware
/// service and RAM references remain exact unless another owner proves them.
#[derive(Clone, Debug)]
pub struct SoftwareRoles {
    canonical: Vec<Range<usize>>,
    actual: Vec<Range<usize>>,
    code_count: usize,
    data_count: usize,
    digest: [u8; 32],
}
impl SoftwareRoles {
    /// Discover full controller/profile bodies, scalar data and explicit vtable.
    pub fn discover(normal: &[u8]) -> Option<Self> {
        let (mut reference, mut code, data) = trajectory_profile::source_graph_parts(normal.len())?;
        let packed = include_bytes!("../trajectory_code/controller-source.bin");
        let mut cursor = 0;
        let mut pointers = Vec::new();
        for (index, &(a, z, _)) in SOURCE.iter().enumerate() {
            let r = span(a, z);
            reference
                .get_mut(r.clone())?
                .copy_from_slice(packed.get(cursor..cursor + r.len())?);
            cursor += r.len();
            if index == 5 {
                pointers.push(r)
            } else {
                code.push(r)
            }
        }
        let graph =
            native_graph::Graph::with_pointer_tables(&reference, BASE, &code, &data, &pointers)?;
        let regions = crate::image::regions(normal)?;
        let stored: Vec<_> = regions
            .stored
            .iter()
            .map(|r| {
                let at = r.as_ptr() as usize - normal.as_ptr() as usize;
                at..at + r.len()
            })
            .collect();
        let found = graph.discover(normal, BASE, &stored);
        let [bound] = found.as_slice() else {
            return None;
        };
        Some(Self {
            code_count: code.len(),
            data_count: data.len(),
            canonical: code.into_iter().chain(data).chain(pointers).collect(),
            actual: bound.ranges.clone(),
            digest: Sha256::digest(normal).into(),
        })
    }
    /// Resolve a canonical CPU role address into the bound source image.
    pub fn address(&self, canonical: u32) -> Option<u32> {
        let at = canonical.checked_sub(BASE)? as usize;
        let i = self.canonical.iter().position(|r| r.contains(&at))?;
        Some(BASE + (self.actual[i].start + at - self.canonical[i].start) as u32)
    }
    /// Resolve a canonical Normal-offset range within a complete bound node.
    pub fn span(&self, range: Range<usize>) -> Option<Range<usize>> {
        let i = self
            .canonical
            .iter()
            .position(|r| r.start <= range.start && range.end <= r.end)?;
        let start = self.actual[i].start + range.start - self.canonical[i].start;
        Some(start..start + range.len())
    }
    /// Complete native code/data authority at actual image locations.
    pub fn protected(&self) -> &[Range<usize>] {
        &self.actual
    }
    /// Pin the exact original image used for this immutable discovery.
    pub fn verify(&self, normal: &[u8]) -> bool {
        <[u8; 32]>::from(Sha256::digest(normal)) == self.digest
    }
    pub(super) fn canonical_view(&self, source: &[u8]) -> Option<Vec<u8>> {
        if !self.verify(source) {
            return None;
        }
        let mapping: Vec<_> = self
            .actual
            .iter()
            .zip(&self.canonical)
            .map(|(a, c)| {
                (
                    BASE + a.start as u32,
                    BASE + a.end as u32,
                    BASE + c.start as u32,
                )
            })
            .collect();
        let mut view = source.to_vec();
        for (i, (actual, role)) in self.actual.iter().zip(&self.canonical).enumerate() {
            let body = if i < self.code_count {
                native_graph::relocate(
                    source.get(actual.clone())?,
                    BASE + actual.start as u32,
                    BASE + role.start as u32,
                    &mapping,
                )?
            } else if i < self.code_count + self.data_count {
                source.get(actual.clone())?.to_vec()
            } else {
                source
                    .get(actual.clone())?
                    .chunks_exact(4)
                    .flat_map(|w| {
                        let v = u32::from_be_bytes(w.try_into().unwrap());
                        mapping
                            .iter()
                            .find(|(a, z, _)| (*a..*z).contains(&v))
                            .map_or(v, |(a, _, to)| to + v - a)
                            .to_be_bytes()
                    })
                    .collect()
            };
            view.get_mut(role.clone())?.copy_from_slice(&body);
        }
        bind(&view, SOURCE)?;
        trajectory_profile::canonical_source(&view)
    }
}

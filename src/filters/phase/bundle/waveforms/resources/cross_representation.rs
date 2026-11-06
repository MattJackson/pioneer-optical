//! Complete native computed-to-literal phase composition. The existing
//! generator and its diagnostics retain their code, data, buffers and schedule.
//! Identical COMP expansion supplies owned storage; only the bound inflater's
//! arithmetic calls move to proven OEM implementations.
use super::{dispatch_bridge, dsp_control_bridge, generated, native_comp, retirement};
use crate::filters::phase::{bundle, native};
use alloc::vec::Vec;
use core::ops::Range;
use sha2::{Digest, Sha256};
const BASE: u32 = 0x410000;

/// A complete ownership, native-program or representation proof is missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Native source and destination graphs do not fit this complete strategy.
    Graph,
    /// An unchanged COMP expansion or its storage ownership was not established.
    Compression,
    /// Reclaimed compressed suffix has a visible external reference.
    References,
    /// A non-replaced client still uses the computed coefficient basis.
    BasisReferences,
    /// A retained native ownership witness was altered by composition.
    AuthorityChanged,
    /// The reclaimed, aligned stored payload does not fit the complete graph.
    Space,
    /// Whole native instruction transplantation failed.
    Native,
    /// Output representation and channel adaptation could not be composed.
    Encoder,
    /// Complete dispatcher adaptation could not be composed.
    Dispatcher,
    /// Native DSP loader adaptation could not be composed.
    Loader,
    /// Complete parameter conversion program adaptation failed.
    Conversions,
    /// Native calibration source adaptation failed.
    Calibration,
    /// Complete composed output did not reproduce the source convention.
    Verification,
}
/// Complete image and byte ranges whose retained effects must survive composition.
#[derive(Clone, Debug)]
pub struct Plan {
    /// Normal image before shared integrity repair.
    pub(crate) image: Vec<u8>,
    /// Bound code/data, including unchanged generator and decoder effects.
    protected: Vec<Range<usize>>,
    target_digest: [u8; 32],
    kernel_digest: [u8; 32],
    convention: bundle::Bundle,
}
struct Pool {
    spans: Vec<Range<usize>>,
}
impl Pool {
    fn take(&mut self, length: usize) -> Result<Range<usize>, Error> {
        let index = self
            .spans
            .iter()
            .enumerate()
            .filter(|(_, s)| s.len() >= length)
            .min_by_key(|(_, s)| s.len())
            .map(|(i, _)| i)
            .ok_or(Error::Space)?;
        let span = self.spans[index].start..self.spans[index].start + length;
        self.spans[index].start = (span.end + 1) & !1;
        Ok(span)
    }
}
fn address(span: &Range<usize>) -> Result<u32, Error> {
    u32::try_from(span.start)
        .ok()
        .and_then(|x| x.checked_add(BASE))
        .filter(|x| *x <= 0xffffff)
        .ok_or(Error::Space)
}
struct Repacked {
    image: Vec<u8>,
    pool: Pool,
    protected: Vec<Range<usize>>,
    ownership_witnesses: Vec<Range<usize>>,
}
fn repack(target: &[u8], kernel: &[u8]) -> Result<Repacked, Error> {
    let (base, streams) = crate::comp_streams::read(target, 4 * 1024 * 1024, &mut || true)
        .map_err(|_| Error::Compression)?
        .ok_or(Error::Compression)?;
    if base != BASE || streams.iter().any(|s| s.expanded.len() > 1024 * 1024) {
        return Err(Error::Compression);
    }
    let mut candidates = Vec::new();
    for (i, stream) in streams.iter().enumerate() {
        let mut compressed = Vec::new();
        zopfli::compress(
            zopfli::Options::default(),
            zopfli::Format::Zlib,
            stream.expanded.as_slice(),
            &mut compressed,
        )
        .map_err(|_| Error::Compression)?;
        if compressed.len() < stream.compressed_size {
            candidates.push((i, compressed));
        }
    }
    let (i, compressed) = candidates
        .into_iter()
        .max_by_key(|(i, c)| streams[*i].compressed_size - c.len())
        .ok_or(Error::Space)?;
    let stream = &streams[i];
    let mut output = target.to_vec();
    let start = stream.image_offset + 4;
    let end = start + compressed.len();
    let original_end = start + stream.compressed_size;
    output[start..end].copy_from_slice(&compressed);
    output[end..original_end].fill(255);
    let directory = crate::comp::COMP_OFFSET + 8 + i * 8;
    let encoded_end = stream
        .image_offset
        .checked_add(compressed.len())
        .and_then(|v| u32::try_from(v).ok())
        .and_then(|v| v.checked_add(BASE))
        .ok_or(Error::Compression)?;
    output[directory..directory + 4].copy_from_slice(&encoded_end.to_be_bytes());
    let mut protected = Vec::new();
    for (j, stream) in streams.iter().enumerate() {
        protected.push(
            stream.image_offset..if i == j {
                end
            } else {
                stream.image_offset + 4 + stream.compressed_size
            },
        );
    }
    let (_, verified) =
        crate::comp_streams::read(&output, crate::comp::MAX_TOTAL_EXPANDED, &mut || true)
            .map_err(|_| Error::Compression)?
            .ok_or(Error::Compression)?;
    if streams.len() != verified.len()
        || streams
            .iter()
            .zip(&verified)
            .any(|(a, b)| a.image_offset != b.image_offset || a.expanded != b.expanded)
    {
        return Err(Error::Compression);
    }
    // On this view the shortened stream suffixes are stored bytes. Their former
    // ownership is the validated original stream, not their current erasure.
    let ownership =
        super::comp_ownership::prove(target, kernel, &output).ok_or(Error::References)?;
    let spans = ownership
        .tails
        .into_iter()
        .map(|r| (r.start + 1) & !1..r.end & !1)
        .filter(|r| !r.is_empty())
        .collect();
    let ownership_witnesses = ownership.protected_normal;
    protected.extend(ownership_witnesses.iter().cloned());
    Ok(Repacked {
        image: output,
        pool: Pool { spans },
        protected,
        ownership_witnesses,
    })
}
/// Compose the full static donor mechanism while preserving the target's
/// original runtime generation and reporting graph. No persistent writes or
/// new runtime buffer allocations occur.
pub fn plan(
    target: &[u8],
    donor: &[u8],
    kernel: &[u8],
    donor_kernel: &[u8],
) -> Result<Plan, Error> {
    use super::loader::{self, Table};
    if target.len() > 0x1f0000 {
        return Err(Error::Graph);
    }
    let target_bundle = bundle::bind(target).map_err(|_| Error::Graph)?;
    let source_bundle = bundle::bind(donor).map_err(|_| Error::Graph)?;
    let generator = generated::observe(target).map_err(|_| Error::Graph)?;
    let computed = loader::computed::observe(target).map_err(|_| Error::Graph)?;
    let source = dispatch_bridge::observe(donor).map_err(|_| Error::Graph)?;
    let destination = dispatch_bridge::observe(target).map_err(|_| Error::Graph)?;
    let source_loader = loader::observe(donor).map_err(|_| Error::Graph)?;
    if source.kind != dispatch_bridge::Kind::Literal
        || destination.kind != dispatch_bridge::Kind::Software
        || source.argument != destination.argument
        || source_bundle.table_select_0x28f
        || target_bundle.table_select_0x28f
        || source_loader.computed
    {
        return Err(Error::Graph);
    }
    let coherence = dsp_control_bridge::prove_plain_transplant(target, donor, kernel, donor_kernel)
        .map_err(|_| Error::Graph)?
        .target;
    let inflater = native_comp::observe_with_kernel(target, kernel).ok_or(Error::Graph)?;
    let Repacked {
        mut image,
        mut pool,
        mut protected,
        ownership_witnesses,
    } = repack(target, kernel)?;
    let mut resources = Vec::new();
    for from in &source.tables {
        let old = from.checked_sub(BASE).ok_or(Error::Graph)? as usize;
        let bytes = donor.get(old..old + 256).ok_or(Error::Graph)?;
        let alias = if bytes.iter().all(|b| *b == 0) {
            let regions = crate::image::regions(target).ok_or(Error::Graph)?;
            regions.stored.iter().find_map(|region| {
                let origin = region.as_ptr() as usize - target.as_ptr() as usize;
                region
                    .windows(256)
                    .enumerate()
                    .find(|(at, b)| (origin + at) & 1 == 0 && *b == bytes)
                    .map(|(at, _)| origin + at..origin + at + 256)
            })
        } else {
            None
        };
        let slot = if let Some(alias) = alias {
            alias
        } else {
            let slot = pool.take(256)?;
            image[slot.clone()].copy_from_slice(bytes);
            slot
        };
        resources.push((*from, address(&slot)?));
        protected.push(slot);
    }
    let Some([Table::Literal(a), Table::Literal(b)]) = source_loader.tables else {
        return Err(Error::Graph);
    };
    let mut tables = [Table::Literal(0); 2];
    for (i, from) in [a, b].into_iter().enumerate() {
        let old = from.checked_sub(BASE).ok_or(Error::Graph)? as usize;
        let slot = pool.take(72)?;
        image[slot.clone()].copy_from_slice(donor.get(old..old + 72).ok_or(Error::Graph)?);
        tables[i] = Table::Literal(address(&slot)?);
        protected.push(slot);
    }
    let lengths = native::arithmetic::lengths();
    let arithmetic = [
        pool.take(lengths[0])?,
        pool.take(lengths[1])?,
        pool.take(lengths[2])?,
    ];
    let entries = [
        address(&arithmetic[0])?,
        address(&arithmetic[1])?,
        address(&arithmetic[2])?,
    ];
    let bodies = native::arithmetic::emit(entries).ok_or(Error::Native)?;
    for (span, body) in arithmetic.into_iter().zip(bodies) {
        image[span.clone()].copy_from_slice(&body);
        protected.push(span);
    }
    image = native_comp::retarget_arithmetic(&image, entries).ok_or(Error::Native)?;
    // The complete plain loader owns its shorter retired suffix. The old
    // computed coefficient basis has no remaining consumer after that graph
    // replacement; keep all software-generator code/data and its diagnostics.
    let loader_plan = loader::coefficient_bridge::transplant_plain(&image, donor, tables, kernel)
        .map_err(|_| Error::Loader)?;
    retirement::references_clear(
        target,
        kernel,
        core::slice::from_ref(&computed.basis),
        &[computed.basis.clone(), computed.loader.program.clone()],
        core::slice::from_ref(&computed.loader.program),
    )
    .ok_or(Error::BasisReferences)?;
    image = loader_plan.image;
    image[loader_plan.retired.clone()].fill(255);
    image[computed.basis.clone()].fill(255);
    let dispatch = loader_plan.retired.start..loader_plan.retired.start + source.dispatch.len();
    if dispatch.end > loader_plan.retired.end {
        return Err(Error::Space);
    }
    let full = native::encoders::observe(donor).map_err(|_| Error::Graph)?;
    let exchanged = usize::from(target_bundle.coil != source_bundle.coil);
    let sizes = [
        full.programs[exchanged]
            .iter()
            .map(|r| r.len())
            .sum::<usize>(),
        full.programs[1 ^ exchanged]
            .iter()
            .map(|r| r.len())
            .sum::<usize>(),
    ];
    let coils = [
        Some(computed.basis.start..computed.basis.start + sizes[0]),
        Some(dispatch.end..dispatch.end + sizes[1]),
    ];
    if coils[0].as_ref().unwrap().end > computed.basis.end
        || coils[1].as_ref().unwrap().end > loader_plan.retired.end
    {
        return Err(Error::Space);
    }
    protected.extend(coils.iter().flatten().cloned());
    protected.push(dispatch.clone());
    image = native::encoders::transplant(&image, donor, coils).map_err(|_| Error::Encoder)?;
    image = dispatch_bridge::transplant(&image, donor, &resources, [Some(dispatch), None])
        .map_err(|_| Error::Dispatcher)?;
    let conversions = [None, Some(pool.take(10)?), None];
    protected.extend(conversions.iter().flatten().cloned());
    image = bundle::conversions::rewrite_specialized_with_kernel(
        &image,
        donor,
        conversions,
        Some(kernel),
    )
    .map_err(|_| Error::Conversions)?;
    image = bundle::conversions::rewrite_controls(&image, donor).map_err(|_| Error::Native)?;
    image =
        native::calibration::transplant_effective(&image, donor).map_err(|_| Error::Calibration)?;
    image = bundle::rewrite_step_offsets(&image, source_bundle.step_minus_source)
        .map_err(|_| Error::Native)?;
    for (from, to) in &resources {
        let a = (*from - BASE) as usize;
        let b = (*to - BASE) as usize;
        if donor.get(a..a + 256) != image.get(b..b + 256) {
            return Err(Error::Verification);
        }
    }
    for (from, to) in [a, b].into_iter().zip(tables) {
        let Table::Literal(to) = to else {
            return Err(Error::Verification);
        };
        let a = (from - BASE) as usize;
        let b = (to - BASE) as usize;
        if donor.get(a..a + 72) != image.get(b..b + 72) {
            return Err(Error::Verification);
        }
    }
    let retained = generator.evaluator.programs.iter().chain([
        &generator.evaluator.basis,
        &generator.calibration.0,
        &generator.producer.program,
        &generator.producer.initializer,
    ]);
    if retained
        .into_iter()
        .any(|r| target.get(r.clone()) != image.get(r.clone()))
    {
        return Err(Error::Verification);
    }
    // The only ownership-witness edits permitted here are the ten separately
    // certified inflater call operands. Re-encoded stream payloads have their
    // own expansion/execution proof and are not unchanged-code witnesses.
    for span in &ownership_witnesses {
        if target.get(span.clone()) == image.get(span.clone()) {
            continue;
        }
        if (span.start..span.end).any(|at| {
            target[at] != image[at]
                && !inflater
                    .calls
                    .iter()
                    .any(|call| (call.offset + 1..call.offset + 4).contains(&at))
        }) {
            return Err(Error::AuthorityChanged);
        }
    }
    native_comp::execution::validate(target, &image, &inflater, entries)
        .ok_or(Error::Verification)?;
    if bundle::bind(&image).map_err(|_| Error::Verification)? != source_bundle {
        return Err(Error::Verification);
    }
    let original_coils = native::encoders::observe(target).map_err(|_| Error::Graph)?;
    protected.extend(original_coils.programs.into_iter().flatten());
    protected.extend([
        destination.dispatch,
        destination.selector,
        computed.loader.program,
    ]);
    protected.extend([
        coherence.coherence,
        coherence.control,
        coherence.setter,
        coherence.movement,
        coherence.tick,
        coherence.vtable,
    ]);
    protected.push(crate::comp::COMP_OFFSET..crate::comp::COMP_OFFSET + 0x100);
    protected
        .extend(bundle::conversions::protected_ranges(&image).map_err(|_| Error::Verification)?);
    protected
        .extend(native::calibration::protected_ranges(&image).map_err(|_| Error::Verification)?);
    protected.extend(inflater.programs);
    protected.push(inflater.data);
    protected.push(inflater.loader);
    protected.push(inflater.boundary_program);
    protected.extend(generator.evaluator.programs);
    protected.extend([
        generator.evaluator.basis,
        generator.calibration.0,
        generator.producer.program,
        generator.producer.initializer,
        computed.mode_context,
        computed.mode_reader,
        computed.basis,
    ]);
    Ok(Plan {
        image,
        protected,
        target_digest: Sha256::digest(target).into(),
        kernel_digest: Sha256::digest(kernel).into(),
        convention: source_bundle,
    })
}
impl Plan {
    /// The Normal bytes certified by this immutable operation.
    pub fn image(&self) -> &[u8] {
        &self.image
    }

    /// Check the already certified operation without recompression or repeated
    /// native execution. Other owners may change only disjoint bytes.
    pub fn verify(&self, target: &[u8], kernel: &[u8], actual: &[u8]) -> Result<(), Error> {
        if <[u8; 32]>::from(Sha256::digest(target)) != self.target_digest
            || <[u8; 32]>::from(Sha256::digest(kernel)) != self.kernel_digest
            || actual.len() != target.len()
            || self
                .protected
                .iter()
                .any(|span| actual.get(span.clone()) != self.image.get(span.clone()))
            || target
                .iter()
                .zip(&self.image)
                .zip(actual)
                .enumerate()
                .any(|(at, ((a, b), c))| !(16..20).contains(&at) && a != b && b != c)
            || bundle::bind(actual).map_err(|_| Error::Verification)? != self.convention
        {
            return Err(Error::Verification);
        }
        Ok(())
    }
}

//! Complete pointer-donor mechanism in a computed target, with immutable image
//! pointer cells specializing the donor's native parameter-selected branch.
//! Storage comes only from certified COMP shortening and whole replaced code/data.
/// Composition failures have the same closed ownership categories as the
/// computed-to-literal strategy.
pub use super::cross_representation::Error;
use super::{
    cross_representation::{address, repack, Repacked},
    dispatch_bridge, dsp_control_bridge, generated, native_comp, pointer_bridge, retirement,
};
use crate::filters::{
    phase::{bundle, native},
    prerequisites::Word,
};
use alloc::{vec, vec::Vec};
use core::ops::Range;
use sha2::{Digest, Sha256};
const BASE: u32 = 0x410000;

/// Complete immutable mechanism operation; no persistent parameter writes.
#[derive(Clone, Debug)]
pub struct Plan {
    image: Vec<u8>,
    protected: Vec<Range<usize>>,
    target_digest: [u8; 32],
    kernel_digest: [u8; 32],
    convention: bundle::Bundle,
    selected: super::Tables,
    required_words: Vec<Word>,
}
/// Compose the pointer donor's complete selected mechanism under 0x28F==1.
/// The original target generator/diagnostic graph remains unchanged.
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
    let before = bundle::bind(target).map_err(|_| Error::Graph)?;
    let wanted = bundle::bind(donor).map_err(|_| Error::Graph)?;
    let graph = super::observe(donor).map_err(|_| Error::Graph)?;
    let source = dispatch_bridge::observe(donor).map_err(|_| Error::Graph)?;
    let destination = dispatch_bridge::observe(target).map_err(|_| Error::Graph)?;
    let computed = loader::computed::observe(target).map_err(|_| Error::Graph)?;
    let generator = generated::observe(target).map_err(|_| Error::Graph)?;
    let source_loader = loader::observe(donor).map_err(|_| Error::Graph)?;
    if source.kind != dispatch_bridge::Kind::Pointer
        || destination.kind != dispatch_bridge::Kind::Software
        || !wanted.table_select_0x28f
        || before.table_select_0x28f
        || source_loader.computed
        || !matches!(
            source_loader.tables,
            Some([Table::Pointer(_), Table::Pointer(_)])
        )
        || graph.initializer.is_none()
        || graph.erased_parameter.is_none()
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
    for from in pointer_bridge::tables(donor).map_err(|_| Error::Graph)? {
        let old = from.checked_sub(BASE).ok_or(Error::Graph)? as usize;
        let bytes = donor.get(old..old + 256).ok_or(Error::Graph)?;
        // Exact unchanged ROM equality is an alias, never writable free space.
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
        resources.push((from, address(&slot)?));
        protected.push(slot);
    }
    // Up to two padding bytes establish the native MOV.L cell alignment.
    let cell_storage = pool.take(18)?;
    let cell_start = (cell_storage.start + 3) & !3;
    let cells = [0, 4, 8, 12].map(|delta| BASE + (cell_start + delta) as u32);
    if cell_start + 16 > cell_storage.end {
        return Err(Error::Space);
    }
    for (index, from) in graph.selected.motion.iter().enumerate() {
        let value = resources
            .iter()
            .find(|(a, _)| *a == BASE + from.start as u32)
            .ok_or(Error::Graph)?
            .1;
        let at = (cells[index] - BASE) as usize;
        image[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }
    protected.push(cell_storage);
    // This stage closes every incoming edge into the replaced dispatcher,
    // selector, and three complete argument preparations before their reuse.
    let dispatch_plan =
        pointer_bridge::plan(&image, donor, kernel, &resources, [cells[0], cells[1]])
            .map_err(|_| Error::Dispatcher)?;
    let coefficient_cells = [Table::Pointer(cells[2]), Table::Pointer(cells[3])];
    let loader_plan =
        loader::coefficient_bridge::transplant_plain(&image, donor, coefficient_cells, kernel)
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
    let jump = native::encoding::jump(BASE).ok_or(Error::Native)?;
    let old_dispatch_tail = destination.dispatch.start + jump.len()..destination.dispatch.end;
    if old_dispatch_tail.is_empty() {
        return Err(Error::Space);
    }
    // Whole replaced native objects, with their entry JMP kept out of the pool.
    for span in [&loader_plan.retired, &computed.basis, &old_dispatch_tail] {
        if span.start & 1 != 0 || span.end & 1 != 0 {
            return Err(Error::Space);
        }
        image[span.clone()].fill(255);
        pool.spans.push(span.clone());
    }
    let dispatch = pool.take(dispatch_plan.dispatch.len())?;
    image[dispatch.clone()].copy_from_slice(&dispatch_plan.dispatch);
    let jump = native::encoding::jump(address(&dispatch)?).ok_or(Error::Native)?;
    image[destination.dispatch.start..destination.dispatch.start + jump.len()]
        .copy_from_slice(&jump);
    if dispatch_plan.selector.len() > destination.selector.len() {
        return Err(Error::Space);
    }
    native::encoding::nops(&mut image[destination.selector.clone()]).ok_or(Error::Native)?;
    image[destination.selector.start..destination.selector.start + dispatch_plan.selector.len()]
        .copy_from_slice(&dispatch_plan.selector);
    for (span, bytes) in &dispatch_plan.arguments {
        image[span.clone()].copy_from_slice(bytes);
        protected.push(span.clone());
    }
    protected.push(dispatch);
    let full = native::encoders::observe(donor).map_err(|_| Error::Graph)?;
    let exchanged = usize::from(before.coil != wanted.coil);
    let lengths = [0, 1].map(|i| {
        full.programs[i ^ exchanged]
            .iter()
            .map(|r| r.len())
            .sum::<usize>()
    });
    let coils = [Some(pool.take(lengths[0])?), Some(pool.take(lengths[1])?)];
    protected.extend(coils.iter().flatten().cloned());
    image = native::encoders::transplant(&image, donor, coils).map_err(|_| Error::Encoder)?;
    let mut coefficients = Vec::new();
    for (index, from) in graph.selected.coefficients.iter().enumerate() {
        let slot = pool.take(72)?;
        image[slot.clone()].copy_from_slice(&donor[from.clone()]);
        let at = (cells[index + 2] - BASE) as usize;
        image[at..at + 4].copy_from_slice(&address(&slot)?.to_be_bytes());
        coefficients.push(slot.clone());
        protected.push(slot);
    }
    let sizes = native::arithmetic::lengths();
    let arithmetic = [
        pool.take(sizes[0])?,
        pool.take(sizes[1])?,
        pool.take(sizes[2])?,
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
    image = bundle::rewrite_step_offsets(&image, wanted.step_minus_source)
        .map_err(|_| Error::Native)?;
    for (from, to) in &resources {
        let a = (*from - BASE) as usize;
        let b = (*to - BASE) as usize;
        if donor.get(a..a + 256) != image.get(b..b + 256) {
            return Err(Error::Verification);
        }
    }
    for (index, (from, to)) in graph
        .selected
        .coefficients
        .iter()
        .zip(&coefficients)
        .enumerate()
    {
        if donor.get(from.clone()) != image.get(to.clone())
            || read_pointer(&image, cells[index + 2]) != Some(address(to)?)
        {
            return Err(Error::Verification);
        }
    }
    for (index, from) in graph.selected.motion.iter().enumerate() {
        let value = resources
            .iter()
            .find(|(a, _)| *a == BASE + from.start as u32)
            .ok_or(Error::Verification)?
            .1;
        if read_pointer(&image, cells[index]) != Some(value) {
            return Err(Error::Verification);
        }
    }
    let after = dispatch_bridge::observe(&image).map_err(|_| Error::Verification)?;
    let actual_loader = loader::observe(&image).map_err(|_| Error::Verification)?;
    if after.kind != dispatch_bridge::Kind::Pointer
        || after.argument != dispatch_bridge::Argument::Zero
        || after.state != destination.state
        || after.callers != destination.callers
        || actual_loader.tables != Some(coefficient_cells)
        || actual_loader.computed
        || actual_loader.loader != source_loader.loader
    {
        return Err(Error::Verification);
    }
    let rebound = super::observe(&image).map_err(|_| Error::Verification)?;
    if rebound.initializer.is_some()
        || rebound.erased_parameter.is_some()
        || rebound.selected.coefficients != [coefficients[0].clone(), coefficients[1].clone()]
        || rebound
            .selected
            .motion
            .iter()
            .enumerate()
            .any(|(i, span)| read_pointer(&image, cells[i]) != Some(BASE + span.start as u32))
    {
        return Err(Error::Verification);
    }
    // Keep the complete retained DSP helper implementations and encoder leaf,
    // not merely the call operands in the transplanted programs.
    let writer =
        loader::writer::observe(&image, actual_loader.writer).map_err(|_| Error::Verification)?;
    let reader = loader::readback::observe(&image, actual_loader.readback, actual_loader.writer)
        .map_err(|_| Error::Verification)?;
    protected.extend([writer.program, reader.program]);
    protected.extend(reader.clear);
    let coefficient_leaf = (actual_loader.coefficient_getter - BASE) as usize;
    protected.push(coefficient_leaf..coefficient_leaf + 4);
    protected.push(
        native::encoders::observe(&image)
            .map_err(|_| Error::Verification)?
            .leaf,
    );
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
    for span in &ownership_witnesses {
        if (span.start..span.end).any(|at| {
            target[at] != image[at]
                && !inflater
                    .calls
                    .iter()
                    .any(|c| (c.offset + 1..c.offset + 4).contains(&at))
        }) {
            return Err(Error::AuthorityChanged);
        }
    }
    native_comp::execution::validate(target, &image, &inflater, entries)
        .ok_or(Error::Verification)?;
    // The parameter branch is specialized to immutable image cells. Its
    // selection is enforced by the operation's external read-only word guard.
    let convention = bundle::Bundle {
        table_select_0x28f: false,
        ..wanted
    };
    if bundle::bind(&image).map_err(|_| Error::Verification)? != convention
        || !matches!((native::discover(&image), native::discover(donor)), (crate::image::layout::Observation::Known(a), crate::image::layout::Observation::Known(b)) if a == b)
    {
        return Err(Error::Verification);
    }
    protected.extend(
        native::encoders::observe(target)
            .map_err(|_| Error::Graph)?
            .programs
            .into_iter()
            .flatten(),
    );
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
        coherence.getter,
    ]);
    protected.push(crate::comp::COMP_OFFSET..crate::comp::COMP_OFFSET + 0x100);
    protected
        .extend(bundle::conversions::protected_ranges(&image).map_err(|_| Error::Verification)?);
    protected
        .extend(native::calibration::protected_ranges(&image).map_err(|_| Error::Verification)?);
    protected.extend(inflater.programs);
    protected.extend([inflater.data, inflater.loader, inflater.boundary_program]);
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
        convention,
        selected: rebound.selected,
        required_words: vec![Word {
            parameter: 0x28f,
            value: 1,
        }],
    })
}
fn read_pointer(image: &[u8], address: u32) -> Option<u32> {
    let at = address.checked_sub(BASE)? as usize;
    Some(u32::from_be_bytes(image.get(at..at + 4)?.try_into().ok()?))
}
impl Plan {
    /// Normal bytes before shared integrity repair.
    pub fn image(&self) -> &[u8] {
        &self.image
    }
    /// Native read-only selection prerequisite; never a parameter write.
    pub fn required_words(&self) -> &[Word] {
        &self.required_words
    }
    /// Check every emitted effect and unchanged ownership witness against the
    /// exact original Normal/Kernel pair without recompression or re-execution.
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
        let bound = super::observe(actual).map_err(|_| Error::Verification)?;
        if bound.selected != self.selected
            || bound.initializer.is_some()
            || bound.erased_parameter.is_some()
            || !matches!(native::discover(actual), crate::image::layout::Observation::Known(native::Phase {assignment,interface:native::Interface::SplitWord}) if assignment == self.convention.coil)
        {
            return Err(Error::Verification);
        }
        Ok(())
    }
}

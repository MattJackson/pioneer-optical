//! Guarded native generated-waveform composition onto the literal target.
//! Source software trajectory, actual table values and target hardware services
//! form the convention; absent source DSP/conversion patterns are not invented.
use super::{
    dispatch_bridge, materialized, profile_ownership, trajectory_bridge, trajectory_profile,
};
use crate::filters::{
    phase::{bundle, native},
    prerequisites::Word,
};
use alloc::{vec, vec::Vec};
use core::ops::Range;
use sha2::{Digest, Sha256};
const BASE: usize = 0x410000;

/// A complete native graph, ownership, placement or emitted result is missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Complete original native source/target contract is absent.
    Graph,
    /// A live Normal/Kernel reference prevents replacing the native resource.
    Ownership,
    /// Positively owned storage cannot fit the complete native graph.
    Space,
    /// Native relocation failed.
    Native,
    /// Two staged effects overlap inconsistently.
    Conflict,
    /// Final native observations disagree with the required mechanism.
    Verification,
}
/// A composed image and its retained immutable ownership witnesses.
#[derive(Clone, Debug)]
pub struct Plan {
    image: Vec<u8>,
    protected: Vec<Range<usize>>,
    target_digest: [u8; 32],
    kernel_digest: [u8; 32],
    words: Vec<Word>,
    observed: Observed,
}
fn span(start: usize, end: usize) -> Range<usize> {
    start - BASE..end - BASE
}
struct Pool(Vec<Range<usize>>);
impl Pool {
    fn take(&mut self, length: usize) -> Result<Range<usize>, Error> {
        let i = self
            .0
            .iter()
            .enumerate()
            .filter(|(_, r)| r.len() >= length)
            .min_by_key(|(_, r)| r.len())
            .map(|(i, _)| i)
            .ok_or(Error::Space)?;
        let r = self.0[i].start..self.0[i].start + length;
        self.0[i].start = (r.end + 1) & !1;
        Ok(r)
    }
}
/// Compose the exact materialized source tables, output encoders, selector and
/// complete native trajectory/profile graph. This entry does not waive the
/// owner's read-only prerequisites or final emitted-mechanism observation.
pub fn plan(
    target: &[u8],
    source: &[u8],
    kernel: &[u8],
    source_kernel: &[u8],
) -> Result<Plan, Error> {
    if source_kernel.len() != crate::image::KERNEL_LEN {
        return Err(Error::Graph);
    }
    let material = materialized::prove(source).map_err(|_| Error::Graph)?;
    let destination = dispatch_bridge::observe(target).map_err(|_| Error::Graph)?;
    let donor = dispatch_bridge::observe(source).map_err(|_| Error::Graph)?;
    let coefficients = super::observe(target)
        .map_err(|_| Error::Graph)?
        .selected
        .coefficients;
    let loader = bundle::waveforms::loader::observe(target).map_err(|_| Error::Graph)?;
    if destination.kind != dispatch_bridge::Kind::Literal
        || donor.kind != dispatch_bridge::Kind::Software
        || destination.tables.len() != 5
        || material.tables.len() != donor.tables.len()
        || loader.computed
    {
        return Err(Error::Graph);
    }
    let motion: Vec<_> = destination
        .tables
        .iter()
        .map(|a| *a as usize - BASE..*a as usize - BASE + 256)
        .collect();
    let roles = trajectory_bridge::TargetRoles::discover(target).ok_or(Error::Graph)?;
    let resolve = |r| roles.span(r).ok_or(Error::Graph);
    let old_profile = [
        resolve(span(0x5378b6, 0x537b58))?,
        resolve(span(0x537b58, 0x537e26))?,
    ];
    let old_tables = resolve(span(0x5a4d0c, 0x5a4edc))?;
    let old_controller = resolve(span(0x5398a6, 0x539b2c))?;
    let mut owned = motion.clone();
    owned.extend(coefficients.clone());
    owned.extend(loader.spans.clone());
    owned.push(old_tables.clone());
    let original_coils = native::encoders::observe(target).map_err(|_| Error::Graph)?;
    owned.push(destination.dispatch.start + 1..destination.dispatch.end);
    owned.push(destination.selector.clone());
    owned.extend(
        original_coils
            .programs
            .iter()
            .flatten()
            .map(|r| r.start + 1..r.end),
    );
    let mut replaced = owned.clone();
    replaced.extend(original_coils.programs.iter().flatten().cloned());
    replaced.extend(destination.callers.iter().flatten().cloned());
    replaced.extend(old_profile.clone());
    replaced.extend([
        destination.dispatch.clone(),
        destination.selector.clone(),
        old_controller.clone(),
    ]);
    let mut complete = old_profile.to_vec();
    complete.extend([
        destination.dispatch.clone(),
        destination.selector.clone(),
        old_controller.clone(),
    ]);
    complete.extend(loader.spans.clone());
    complete.extend(original_coils.programs.iter().flatten().cloned());
    let mut protected = profile_ownership::prove(target, kernel, &owned, &replaced, &complete)
        .ok_or(Error::Ownership)?;
    protected.push(original_coils.leaf);
    protected.extend(bundle::conversions::protected_ranges(target).map_err(|_| Error::Graph)?);
    protected.extend(native::calibration::protected_ranges(target).map_err(|_| Error::Graph)?);
    // Bound profile bodies supply storage only after shared_plan proves and
    // redirects every existing client. Their actual layout need not be adjacent.
    let (code_sizes, data_sizes) = trajectory_profile::shared_lengths();
    let mut code: [Range<usize>; 13] = core::array::from_fn(|_| 0..0);
    let mut slots = old_profile.to_vec();
    slots.extend([old_tables, motion[4].clone()]);
    let auxiliary = roles.auxiliary_slots().ok_or(Error::Graph)?;
    // Keep diagnostic bytes outside the waveform allocation. Their opaque
    // logging consumer is not an exclusive-data proof; unused controller-tail
    // bytes remain padding and the final observer scans the strings normally.
    let diagnostic = auxiliary[1].start..auxiliary[1].start + data_sizes[4];
    if diagnostic.end > auxiliary[1].end {
        return Err(Error::Space);
    }
    slots.push(auxiliary[0].clone());
    slots.extend(coefficients);
    slots.extend(loader.spans.clone());
    slots.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<usize>> = Vec::new();
    for r in slots {
        if let Some(last) = merged.last_mut() {
            if last.end == r.start {
                last.end = r.end;
                continue;
            }
            if last.end > r.start {
                return Err(Error::Conflict);
            }
        }
        merged.push(r);
    }
    let mut pool = Pool(merged.clone());
    let mut data: [Range<usize>; 5] = core::array::from_fn(|_| 0..0);
    data[4] = diagnostic;
    let mut requests: Vec<_> = code_sizes
        .iter()
        .enumerate()
        .map(|(i, n)| (*n, false, i))
        .chain(
            data_sizes
                .iter()
                .enumerate()
                .take(4)
                .map(|(i, n)| (*n, true, i)),
        )
        .chain(core::iter::once((donor.selector.len(), false, 13)))
        .collect();
    requests.sort_by_key(|(n, kind, i)| (core::cmp::Reverse(*n), *kind, *i));
    let mut selector = 0..0;
    for (n, is_data, i) in requests {
        let r = pool.take(n)?;
        if is_data {
            data[i] = r;
        } else if i == 13 {
            selector = r;
        } else {
            code[i] = r;
        }
    }
    let shared = trajectory_profile::shared_plan_with_roles(
        target,
        source,
        kernel,
        trajectory_profile::SharedPlacements { code, data },
        roles.private_ram(),
        roles.services().ok_or(Error::Graph)?,
        &roles,
    )
    .ok_or(Error::Native)?;
    if !old_controller.contains(&shared.replaced_by_outer.start)
        || shared.replaced_by_outer.end > old_controller.end
    {
        return Err(Error::Graph);
    }
    let trajectory = trajectory_bridge::plan_with_profile_with_roles(
        target,
        source,
        kernel,
        shared.profile,
        &roles,
    )
    .ok_or(Error::Native)?;
    let mut image = target.to_vec();
    for r in &merged {
        image[r.clone()].fill(255);
    }
    for r in &old_profile {
        image[r.clone()].fill(255);
    }
    let mut resources = Vec::new();
    for (table, to) in material.tables.iter().zip(&motion) {
        image[to.clone()].copy_from_slice(&table.bytes);
        resources.push((table.source, (BASE + to.start) as u32));
        protected.push(to.clone());
    }
    image =
        native::encoders::transplant(&image, source, [None, None]).map_err(|_| Error::Native)?;
    let new_dispatch =
        destination.dispatch.start..destination.dispatch.start + donor.dispatch.len();
    image = dispatch_bridge::transplant_relocating_entries(
        &image,
        source,
        &resources,
        new_dispatch.clone(),
        selector.clone(),
    )
    .map_err(|_| Error::Native)?;
    image = bundle::rewrite_step_offsets(&image, material.source.step_minus_source)
        .map_err(|_| Error::Native)?;
    // Profile/controller stages were prepared against the original immutable
    // image. Their writes may occupy only proved pool bytes or their bound
    // original code/client instructions, never a prior phase write.
    for (range, bytes) in trajectory.writes {
        if range.len() != bytes.len() {
            return Err(Error::Conflict);
        }
        for (at, value) in (range.start..range.end).zip(&bytes) {
            if image[at] != target[at] && image[at] != 255 && image[at] != *value {
                return Err(Error::Conflict);
            }
        }
        image[range.clone()].copy_from_slice(&bytes);
        protected.push(range);
    }
    let actual = dispatch_bridge::observe(&image).map_err(|_| Error::Verification)?;
    let coils = native::encoders::observe(&image).map_err(|_| Error::Verification)?;
    let source_coils = native::encoders::observe(source).map_err(|_| Error::Graph)?;
    if actual.kind != dispatch_bridge::Kind::Software
        || actual.tables
            != donor
                .tables
                .iter()
                .map(|from| resources.iter().find(|(a, _)| a == from).map(|(_, b)| *b))
                .collect::<Option<Vec<_>>>()
                .ok_or(Error::Verification)?
        || coils.representation != source_coils.representation
        || coils.pair.assignment != source_coils.pair.assignment
    {
        return Err(Error::Verification);
    }
    let observed = observe(&image, kernel).ok_or(Error::Verification)?;
    protected.extend(observed.protected().iter().cloned());
    let authority = super::profile_code::observe(target);
    if authority
        .as_ref()
        .map_or_else(Vec::new, |a| a.protected_normal())
        .iter()
        .any(|r| target.get(r.clone()) != image.get(r.clone()))
    {
        return Err(Error::Conflict);
    }
    protected.extend([new_dispatch, selector]);
    protected.extend(coils.programs.into_iter().flatten());
    Ok(Plan {
        image,
        protected,
        target_digest: Sha256::digest(target).into(),
        kernel_digest: Sha256::digest(kernel).into(),
        words: material.required_words,
        observed,
    })
}
impl Plan {
    /// Composed Normal bytes before envelope integrity repair.
    pub fn image(&self) -> &[u8] {
        &self.image
    }
    /// Required existing calibration words; no persistent writes are performed.
    pub fn required_words(&self) -> &[Word] {
        &self.words
    }
    /// Preserve the immutable image/component and instruction/data witnesses.
    pub fn verify(&self, target: &[u8], kernel: &[u8], actual: &[u8]) -> Result<(), Error> {
        if !self.observed.verify(actual, kernel)
            || actual.len() != self.image.len()
            || <[u8; 32]>::from(Sha256::digest(target)) != self.target_digest
            || <[u8; 32]>::from(Sha256::digest(kernel)) != self.kernel_digest
            || self
                .protected
                .iter()
                .any(|r| actual.get(r.clone()) != self.image.get(r.clone()))
            || target.iter().zip(&self.image).zip(actual).enumerate().any(
                |(at, ((old, expected), got))| {
                    !(16..20).contains(&at) && old != expected && expected != got
                },
            )
        {
            return Err(Error::Verification);
        }
        Ok(())
    }
}

/// A software-controlled mechanism recognized directly from emitted native
/// code and image tables. It has no invented legacy DSP-loader convention.
#[derive(Clone, Debug)]
pub struct Observed {
    /// Actual source-word assignment and complete native output representation.
    pub coils: native::encoders::Binding,
    /// Full-step negative-offset source established through native coil calls.
    pub step_minus_source: u8,
    /// Native selector predicates and their image-resident paired-word tables.
    pub choices: Vec<(Option<u8>, Range<usize>)>,
    trajectory: trajectory_bridge::Observed,
    protected: Vec<Range<usize>>,
    fingerprint: [u8; 32],
}
/// Recognize the complete emitted software mechanism without an original image,
/// donor package, saved patch plan, marker or legacy loader signature.
pub fn observe(normal: &[u8], kernel: &[u8]) -> Option<Observed> {
    let trajectory = trajectory_bridge::observe(normal, kernel)?;
    let coils = native::encoders::observe(normal).ok()?;
    if coils.representation != native::encoders::Representation::HighByte {
        return None;
    }
    let dispatcher = dispatch_bridge::observe(normal).ok()?;
    if dispatcher.kind != dispatch_bridge::Kind::Software {
        return None;
    }
    let software = super::software::observe(normal).ok()?;
    let choices: Vec<_> = software
        .choices
        .into_iter()
        .map(|(mode, source)| match source {
            super::software::Source::Image(range) => Some((mode, range)),
            super::software::Source::Runtime(_) => None,
        })
        .collect::<Option<_>>()?;
    if choices.len() != 4 {
        return None;
    }
    let regions = crate::image::regions(normal)?;
    let step_minus_source = bundle::step_source(normal, &regions.stored, &coils.pair).ok()?;
    let tables: Vec<_> = choices.iter().map(|(_, r)| r.clone()).collect();
    let complete = vec![dispatcher.dispatch.clone(), dispatcher.selector.clone()];
    let mut retired = Vec::new();
    retired.push(dispatcher.dispatch.start + 1..dispatcher.dispatch.end);
    retired.push(dispatcher.selector.clone());
    retired.extend(coils.programs.iter().flatten().map(|r| r.start + 1..r.end));
    let mut replaced = tables.clone();
    replaced.extend(complete.iter().cloned());
    replaced.extend(coils.programs.iter().flatten().cloned());
    replaced.extend(dispatcher.callers.iter().flatten().cloned());
    let mut known = complete.clone();
    known.extend(coils.programs.iter().flatten().cloned());
    known.extend(trajectory.code_ranges().iter().cloned());
    let mut protected = profile_ownership::prove_with_software_tables(
        normal,
        kernel,
        &retired,
        &replaced,
        &known,
        &trajectory.profile().data_authority,
    )?;
    protected.extend(trajectory.protected().iter().cloned());
    protected.extend(complete);
    protected.extend(tables);
    protected.extend(dispatcher.callers.into_iter().flatten());
    protected.extend(coils.programs.iter().flatten().cloned());
    protected.push(coils.leaf.clone());
    protected.extend(bundle::conversions::protected_ranges(normal).ok()?);
    protected.extend(native::calibration::protected_ranges(normal).ok()?);
    protected.sort_by_key(|r| (r.start, r.end));
    protected.dedup();
    let mut digest = Sha256::new();
    for r in &protected {
        digest.update((r.start as u32).to_be_bytes());
        digest.update((r.end as u32).to_be_bytes());
        digest.update(normal.get(r.clone())?);
    }
    Some(Observed {
        fingerprint: digest.finalize().into(),
        coils,
        step_minus_source,
        choices,
        trajectory,
        protected,
    })
}
impl Observed {
    /// Equal positively recognized native mechanism effects.
    pub fn equivalent(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint
    }

    /// Rebind the native graph and reject newly introduced external references.
    pub fn verify(&self, normal: &[u8], kernel: &[u8]) -> bool {
        observe(normal, kernel).is_some_and(|actual| actual.fingerprint == self.fingerprint)
    }
    /// All native code, clients and table bytes defining this observation.
    pub fn protected(&self) -> &[Range<usize>] {
        &self.protected
    }
    /// Native software trajectory and retained target hardware-service proof.
    pub fn trajectory(&self) -> &trajectory_bridge::Observed {
        &self.trajectory
    }
}

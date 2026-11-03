//! Persistent parameter layout recognition and bounded Normal-only correction.
use super::{
    Assessment, Comparison, Context, Filter, Finding, Operation, Preparation, Role, Transition,
    Value,
};
use crate::{
    compatibility::Error,
    image::{
        layout::{
            self, AddressBasis, HeaderTest, Observation, ParameterLayout, SerialSelection,
            Unresolved, WordEncoding,
        },
        phase,
    },
};
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use sha2::{Digest, Sha256};

/// Owner of native persistent layout recognition, matching and correction.
pub struct LayoutFilter;
/// Registered persistent parameter-layout owner.
pub static FILTER: LayoutFilter = LayoutFilter;

impl Filter for LayoutFilter {
    fn id(&self) -> &'static str {
        "persistent-parameter-layout"
    }
    fn name(&self) -> &'static str {
        "Persistent parameter layout"
    }
    fn inspect(&self, context: &Context<'_>) -> Assessment {
        match native(context) {
            Observation::Known(layout) => match value(&layout) {
                Some(value) => Assessment::known(self.id(), Role::Hardware, value, "Complete native reader, region/header/selection rules and established logical domains"),
                None => Assessment::unresolved(self.id(), Role::Hardware, "Native logical-domain region index cannot be represented"),
            },
            Observation::Conflicting => Assessment::conflicting(self.id(), Role::Hardware, "Independent native persistent reader candidates disagree"),
            Observation::Unresolved(why) => Assessment::unresolved(self.id(), Role::Hardware, reason(why)),
        }
    }
    fn plan(
        &self,
        transition: &Transition<'_, '_>,
        installed: &Assessment,
        target: &Assessment,
    ) -> Result<Option<Box<dyn Operation>>, Error> {
        match self.compare(installed, target) {
            Comparison::Match => return Ok(None),
            Comparison::Unresolved | Comparison::Conflicting => {
                return Err(Error::UnresolvedIdentity)
            }
            Comparison::Different => {}
        }
        if self.inspect(transition.installed) != *installed
            || self.inspect(transition.target) != *target
        {
            return Err(Error::ComponentMismatch);
        }
        let Observation::Known(expected_layout) = native(transition.installed) else {
            return Err(Error::UnresolvedIdentity);
        };
        let Observation::Known(requested_layout) = native(transition.target) else {
            return Err(Error::UnresolvedIdentity);
        };
        let h8_pair = transition
            .installed
            .sat
            .as_ref()
            .zip(transition.target.sat.as_ref())
            .is_some_and(|(a, b)| a.platform == b.platform);
        // Diagnose a concrete Normal/retained-data collision before a generic
        // mismatch. This depends on native layouts and target bytes, never keys.
        if h8_pair {
            if let Some((start, end)) = absolute_overlap(
                &expected_layout,
                &requested_layout,
                transition.target.firmware.normal,
                true,
            ) {
                return Err(Error::PersistentLayoutOverlap { start, end });
            }
        }
        let source_geometry = super::geometry::FILTER.inspect(transition.installed);
        let target_geometry = super::geometry::FILTER.inspect(transition.target);
        match super::geometry::FILTER.compare(&source_geometry, &target_geometry) {
            Comparison::Match => {}
            Comparison::Different => return Err(Error::Incompatible),
            _ => return Err(Error::UnresolvedIdentity),
        }
        let source = transition.installed.firmware;
        let requested = transition.target.firmware;
        let proof = layout::plan_h8_relocation(
            source.normal,
            source.kernel.ok_or(Error::UnresolvedIdentity)?,
            requested.normal,
            requested.kernel.ok_or(Error::UnresolvedIdentity)?,
        )
        .map_err(|error| match error {
            layout::H8RelocationError::FormatChange => Error::Incompatible,
            layout::H8RelocationError::NormalOverlap if h8_pair => {
                match absolute_overlap(&expected_layout, &requested_layout, requested.normal, false)
                {
                    Some((start, end)) => Error::PersistentLayoutOverlap { start, end },
                    None => Error::PersistentLayout(error),
                }
            }
            other => Error::PersistentLayout(other),
        })?;
        let prepared = proof.prepare_normal().map_err(Error::PersistentLayout)?;
        let (from, to) = (proof.from(), proof.to());
        Ok(Some(Box::new(LayoutOperation {
            from,
            to,
            hardware: requested.hardware.into(),
            target: requested.normal.to_vec(),
            kernel: requested.kernel.expect("proof requires Kernel").to_vec(),
            prepared_digest: digest(&prepared),
            source_digest: digest(source.normal),
            prepared,
            expected_layout,
            expected_geometry: source_geometry.finding,
            source_phase: match phase::discover(source.normal) {
                Observation::Known(value) => Some(value),
                _ => None,
            },
            target_phase: match phase::discover(requested.normal) {
                Observation::Known(value) => Some(value),
                _ => None,
            },
        })))
    }
}

/// Equal native record formats whose installed absolute region intersects the
/// target Normal span. `occupied` additionally requires concrete non-FF bytes;
/// the broad span is used only after the native corrector diagnoses overlap.
fn absolute_overlap(
    installed: &ParameterLayout,
    target: &ParameterLayout,
    normal: &[u8],
    occupied: bool,
) -> Option<(u32, u32)> {
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
    let mut adjusted = target.clone();
    if let ParameterLayout::FlashRecords {
        regions: adjusted, ..
    } = &mut adjusted
    {
        for (region, required) in adjusted.iter_mut().zip(regions) {
            region.address = required.address;
        }
    }
    if &adjusted != installed {
        return None;
    }
    const NORMAL_BASE: u32 = 0x410000;
    let normal_end = NORMAL_BASE.checked_add(u32::try_from(normal.len()).ok()?)?;
    for (required, original) in regions.iter().zip(target_regions) {
        if required.address == original.address || required.basis != AddressBasis::Absolute {
            continue;
        }
        let end = required
            .address
            .checked_add(u32::from(required.header_bytes))?
            .checked_add(
                required
                    .record_bytes
                    .checked_mul(u32::from(required.record_count))?,
            )?;
        let first = required.address.max(NORMAL_BASE);
        let last = end.min(normal_end);
        if first >= last {
            continue;
        }
        let bytes = normal.get((first - NORMAL_BASE) as usize..(last - NORMAL_BASE) as usize)?;
        if !occupied || bytes.iter().any(|&byte| byte != 0xff) {
            return Some((required.address, end));
        }
    }
    None
}

pub(super) fn reason(reason: Unresolved) -> String {
    match reason {
        Unresolved::ReaderNotRecognized => {
            "No complete supported native persistent reader was established".into()
        }
        Unresolved::AmbiguousReader => {
            "Multiple native reader sites have unproved runtime selection".into()
        }
        Unresolved::ResidentCodeRequired(address) => {
            format!("Exact resident persistent reader at {address:#x} is unavailable")
        }
        Unresolved::TruncatedEvidence => {
            "Native persistent reader references bytes outside the exact supplied component".into()
        }
    }
}

pub(super) fn legacy_serial(context: &Context<'_>) -> Observation<ParameterLayout> {
    let firmware = context.firmware;
    if firmware.hardware.starts_with("ATA ") {
        layout::discover_m7900_ata(firmware.normal, 0x3800)
    } else if firmware.hardware.len() == 8 && firmware.hardware.starts_with("SCSI") {
        layout::discover_m7900_scsi(firmware.normal, 0x3800)
    } else {
        Observation::Unresolved(Unresolved::ReaderNotRecognized)
    }
}

fn native(context: &Context<'_>) -> Observation<ParameterLayout> {
    if let Some(sat) = &context.sat {
        return sat.layout.clone();
    }
    let mut found = None;
    let mut why = Unresolved::ReaderNotRecognized;
    for observation in context
        .ata
        .iter()
        .map(|candidate| candidate.layout.clone())
        .chain(core::iter::once(legacy_serial(context)))
    {
        match observation {
            Observation::Known(value) => {
                if found.as_ref().is_some_and(|previous| previous != &value) {
                    return Observation::Conflicting;
                }
                found = Some(value);
            }
            Observation::Conflicting => return Observation::Conflicting,
            Observation::Unresolved(reason @ Unresolved::ResidentCodeRequired(_)) => why = reason,
            Observation::Unresolved(reason @ Unresolved::AmbiguousReader) => why = reason,
            Observation::Unresolved(_) => {}
        }
    }
    found
        .map(Observation::Known)
        .unwrap_or(Observation::Unresolved(why))
}

fn encoding(value: WordEncoding) -> Value {
    Value::U8(match value {
        WordEncoding::LittleEndian => 0,
        WordEncoding::DirectOrBusPermutedLittleEndian => 1,
        WordEncoding::SerialHighByteFirst => 2,
    })
}
fn value(layout: &ParameterLayout) -> Option<Value> {
    Some(match layout {
        ParameterLayout::FlashRecords {
            regions,
            encoding: word_encoding,
            domains,
        } => Value::Variant(
            1,
            vec![
                Value::Sequence(
                    regions
                        .iter()
                        .map(|r| {
                            Value::Sequence(vec![
                                Value::U32(r.address),
                                Value::U8(match r.basis {
                                    AddressBasis::Absolute => 0,
                                    AddressBasis::SelectedBank => 1,
                                }),
                                match r.allocation_bytes {
                                    Some(n) => Value::Variant(1, vec![Value::U32(n)]),
                                    None => Value::Variant(0, vec![]),
                                },
                                Value::U32(r.record_bytes),
                                Value::U16(r.record_count),
                                Value::U16(r.header_bytes),
                                Value::U8(match r.header_test {
                                    HeaderTest::ByteFf => 0,
                                    HeaderTest::WordFfff => 1,
                                }),
                            ])
                        })
                        .collect(),
                ),
                encoding(*word_encoding),
                Value::Sequence(
                    domains
                        .iter()
                        .map(|d| {
                            Some(Value::Sequence(vec![
                                Value::U16(d.first),
                                Value::U16(d.last),
                                Value::U32(u32::try_from(d.region).ok()?),
                            ]))
                        })
                        .collect::<Option<Vec<_>>>()?,
                ),
            ],
        ),
        ParameterLayout::SerialRange {
            address_bits,
            first_word,
            word_count,
            encoding: word_encoding,
        } => Value::Variant(
            2,
            vec![
                Value::U8(*address_bits),
                Value::U16(*first_word),
                Value::U16(*word_count),
                encoding(*word_encoding),
            ],
        ),
        ParameterLayout::SerialSelected {
            address_bits,
            bases,
            slots,
            selection,
            encoding: word_encoding,
        } => Value::Variant(
            3,
            vec![
                Value::U8(*address_bits),
                Value::Sequence(bases.iter().copied().map(Value::U16).collect()),
                Value::Sequence(slots.iter().copied().map(Value::U8).collect()),
                match selection {
                    SerialSelection::Header(word) => Value::Variant(0, vec![Value::U16(*word)]),
                    SerialSelection::FallbackWords(words) => Value::Variant(
                        1,
                        vec![Value::Sequence(
                            words.iter().copied().map(Value::U16).collect(),
                        )],
                    ),
                },
                encoding(*word_encoding),
            ],
        ),
    })
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
struct LayoutOperation {
    from: u32,
    to: u32,
    hardware: String,
    target: Vec<u8>,
    kernel: Vec<u8>,
    prepared: Vec<u8>,
    prepared_digest: [u8; 32],
    source_digest: [u8; 32],
    expected_layout: ParameterLayout,
    expected_geometry: Finding,
    source_phase: Option<phase::Phase>,
    target_phase: Option<phase::Phase>,
}
impl core::fmt::Debug for LayoutOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LayoutOperation")
            .field("hardware", &self.hardware)
            .field("normal_bytes", &self.target.len())
            .field("source_digest", &self.source_digest)
            .field("prepared_digest", &self.prepared_digest)
            .field("expected_layout", &self.expected_layout)
            .finish_non_exhaustive()
    }
}
impl LayoutOperation {
    fn guard(&self, context: &Preparation<'_>) -> Result<(), Error> {
        if context.target.hardware != self.hardware
            || context.target.normal != self.target
            || context.target.kernel != Some(self.kernel.as_slice())
        {
            return Err(Error::ComponentMismatch);
        }
        #[cfg(feature = "envelope")]
        match (context.normal, context.kernel) {
            (None, None) => {}
            (Some(normal), Some(kernel)) => {
                if normal.image != self.target
                    || kernel.image != self.kernel
                    || normal.info().kind != crate::ComponentKind::Normal
                    || kernel.info().kind != crate::ComponentKind::Kernel
                    || normal.info().hardware_version != self.hardware
                {
                    return Err(Error::ComponentMismatch);
                }
                let (n, k) = (normal.header_info(), kernel.header_info());
                for (a, b) in [
                    (&n.hardware_version, &k.hardware_version),
                    (&n.destination, &k.destination),
                    (&n.kernel_version, &k.kernel_version),
                    (&n.kernel_version2, &k.kernel_version2),
                ] {
                    if a.is_empty() || a != b {
                        return Err(Error::ComponentMismatch);
                    }
                }
            }
            _ => return Err(Error::ComponentMismatch),
        }
        Ok(())
    }
}
impl Operation for LayoutOperation {
    fn description(&self) -> Option<crate::compatibility::Correction> {
        Some(
            crate::compatibility::Correction::PersistentParameterLayout {
                from: self.from,
                to: self.to,
            },
        )
    }
    fn integrity(&self) -> Option<super::Integrity> {
        Some(super::be32_normal_integrity())
    }
    fn filter_id(&self) -> &'static str {
        FILTER.id()
    }
    fn prepare(&self, context: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
        self.guard(context)?;
        self.verify(context, &self.prepared)?;
        Ok(Some(self.prepared.clone()))
    }
    fn verify(&self, context: &Preparation<'_>, normal: &[u8]) -> Result<(), Error> {
        self.guard(context)?;
        let actual_digest = digest(normal);
        // The complete native proof establishes these two exact whole programs:
        // layout-only with unchanged target phase, or installed source phase.
        // The phase owner independently requires the correct final assignment.
        if actual_digest != self.prepared_digest && actual_digest != self.source_digest {
            return Err(Error::VerificationFailed);
        }
        if self
            .source_phase
            .zip(self.target_phase)
            .is_some_and(|(a, b)| a.interface != b.interface)
        {
            return Err(Error::VerificationFailed);
        }
        if !matches!(layout::discover_h8(normal,Some(&self.kernel)), Observation::Known(layout) if layout==self.expected_layout)
        {
            return Err(Error::VerificationFailed);
        }
        let after = Context::new(crate::compatibility::Firmware {
            hardware: &self.hardware,
            normal,
            kernel: Some(&self.kernel),
        });
        if super::geometry::FILTER.inspect(&after).finding != self.expected_geometry {
            return Err(Error::VerificationFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

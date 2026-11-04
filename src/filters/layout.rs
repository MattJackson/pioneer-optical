//! Persistent parameter layout recognition and comparison; never corrected.
use super::{
    Assessment, Comparison, Context, Filter, Operation, Role, Transition,
    Value,
};
use crate::{
    compatibility::Error,
    image::{
        layout::{
            self, AddressBasis, HeaderTest, Observation, ParameterLayout, SerialSelection,
            Unresolved, WordEncoding,
        },
    },
};
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};

/// Owner of native persistent layout recognition and matching.
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
            ) {
                return Err(Error::PersistentLayoutOverlap { start, end });
            }
        }
        // The hardware matrix marks persistent parameter layout required and
        // not correctable: every known difference refuses.
        Err(Error::Incompatible)
    }
}

/// Equal native record formats whose installed absolute region intersects
/// concrete non-FF target Normal bytes: a specific collision diagnosis.
fn absolute_overlap(
    installed: &ParameterLayout,
    target: &ParameterLayout,
    normal: &[u8],
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
        if bytes.iter().any(|&byte| byte != 0xff) {
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

#[cfg(test)]
mod tests;

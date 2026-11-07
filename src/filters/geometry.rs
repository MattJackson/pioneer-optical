//! Persistent storage geometry: native bank or peripheral-region projections.
use super::{Assessment, Context, Filter, Role, Value};
use crate::image::{
    geometry::{self, Geometry, PeripheralGeometry},
    layout::{Observation, Unresolved},
};
use alloc::{format, vec, vec::Vec};

/// Owner of storage geometry recognition, equality and correction refusal.
pub struct GeometryFilter;
/// Registered native storage-geometry owner.
pub static FILTER: GeometryFilter = GeometryFilter;

/// Rules declared beside this owner's enforcing code; rendered verbatim by reports.
static RULES: super::Rules = super::Rules {
    description: "Compares the observed storage contract: H8 bank markers or addresses and spacing, ATA flash or serial ranges, or SCSI serial records. It does not establish physical flash capacity, erase boundaries or safe migration. Correction requires complete copy, erase, commit and recovery proof.",
    role: super::Role::Hardware,
    correctability: super::Correctability::Never,
    correction: "Never corrected. Values must match; matching capacity case addresses also requires the receiver's capacity-selection relation. Equal geometry does not authorize bank migration, and differing storage contracts refuse under every policy, including the Recovery family override.",
    policies: &[
        super::Policy {
            domains: &[],
            text: "Matching geometry does not imply a matching parameter layout; the persistent parameter layout is a separate required filter.",
        },
        super::Policy {
            domains: &[],
            text: "A storage reader that is not recognized, or that needs resident code which is not supplied, stays Unresolved; no default geometry is assumed.",
        },
    ],
};

impl Filter for GeometryFilter {
    fn id(&self) -> &'static str {
        "persistent-storage-geometry"
    }
    fn name(&self) -> &'static str {
        "Storage geometry"
    }
    fn rules(&self) -> Option<&'static super::Rules> {
        Some(&RULES)
    }
    fn inspect(&self, context: &Context<'_>) -> Assessment {
        if let Some(sat) = &context.sat {
            return match &sat.geometry {
                Observation::Known(value) => Assessment::known(self.id(), Role::Hardware, sat_value(*value), "Native bank marker/spacing or bound bank consumer; equality does not authorize bank migration"),
                Observation::Conflicting => Assessment::conflicting(self.id(), Role::Hardware, "Native bank consumers disagree"),
                Observation::Unresolved(reason) => Assessment::unresolved(self.id(), Role::Hardware, super::layout::reason(*reason)),
            };
        }
        let mut values = Vec::new();
        for candidate in &context.ata {
            match &candidate.geometry {
                Observation::Known(value) => values.push(value.clone()),
                Observation::Conflicting => {
                    return Assessment::conflicting(
                        self.id(),
                        Role::Hardware,
                        "Native peripheral geometry candidates disagree",
                    )
                }
                Observation::Unresolved(_) => {}
            }
        }
        // M7900 ATA/SCSI has its own complete native serial consumer, not an
        // H8/M32C miss interpreted as an absent geometry filter.
        match super::layout::legacy_serial(context) {
            Observation::Known(layout) => match geometry::peripheral_geometry(&layout) {
                Observation::Known(value) => values.push(value),
                Observation::Conflicting => {
                    return Assessment::conflicting(
                        self.id(),
                        Role::Hardware,
                        "Native serial geometry conflicts",
                    )
                }
                Observation::Unresolved(_) => {}
            },
            Observation::Conflicting => {
                return Assessment::conflicting(
                    self.id(),
                    Role::Hardware,
                    "Native serial layout conflicts",
                )
            }
            Observation::Unresolved(_) => {}
        }
        let Some(first) = values.first() else {
            let detail = context.ata.iter().find_map(|c| match c.geometry {
                Observation::Unresolved(Unresolved::ResidentCodeRequired(address)) => Some(format!("Exact resident backend at {address:#x} is required for the complete peripheral geometry projection")),
                _ => None,
            }).unwrap_or_else(|| "No complete native storage geometry was established".into());
            return Assessment::unresolved(self.id(), Role::Hardware, detail);
        };
        if values.iter().any(|value| value != first) {
            return Assessment::conflicting(
                self.id(),
                Role::Hardware,
                "Native peripheral geometry candidates disagree",
            );
        }
        Assessment::known(self.id(), Role::Hardware, peripheral_value(first), "Geometry projected from completely bound native record regions or serial address/slot consumers")
    }
}

fn sat_value(value: Geometry) -> Value {
    match value {
        Geometry::MarkerBanks { marker, stride } => {
            Value::Variant(1, vec![Value::U32(marker), Value::U32(stride)])
        }
        Geometry::NativeBanks { bases, stride } => Value::Variant(
            2,
            vec![
                Value::Sequence(bases.into_iter().map(Value::U32).collect()),
                Value::U32(stride),
            ],
        ),
    }
}
fn peripheral_value(value: &PeripheralGeometry) -> Value {
    match value {
        PeripheralGeometry::FlashRecords(regions) => Value::Variant(
            3,
            vec![Value::Sequence(
                regions
                    .iter()
                    .map(|&(address, bytes)| {
                        Value::Sequence(vec![Value::U32(address), Value::U32(bytes)])
                    })
                    .collect(),
            )],
        ),
        PeripheralGeometry::SerialWords { first, last } => {
            Value::Variant(4, vec![Value::U16(*first), Value::U16(*last)])
        }
        PeripheralGeometry::SerialRecords { bases, slots } => Value::Variant(
            5,
            vec![
                Value::Sequence(bases.iter().copied().map(Value::U16).collect()),
                Value::Sequence(slots.iter().copied().map(Value::U8).collect()),
            ],
        ),
    }
}

#[cfg(test)]
mod tests;

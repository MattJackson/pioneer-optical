//! Guarded correction of the linked native external-event channel.
use super::{
    Assessment, Comparison, Context, Filter, Finding, Integrity, Operation, Preparation, Role,
    Transition, Value,
};
use crate::{
    compatibility::Error,
    image::{
        irq::channel::{Channel, Mapping},
        layout::Observation,
    },
};
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
/// Mapped setup/disarm/callback/vector owner.
pub struct LoadingChannel;
/// Registered mapped-channel owner.
pub static FILTER: LoadingChannel = LoadingChannel;
const ID: &str = "loading-interrupt-channel";
static RULES:super::Rules=super::Rules {
    description:"Identifies a positively linked H8 event channel: FFC5 legacy bit, external mode/pending/enable operands, callback acknowledgement, disarm and installed V58/V60 routing. Outside that complete native domain the existing architecture-native loading variant remains required unchanged.",
    role:Role::Hardware,
    correctability:super::Correctability::Guarded,
    correction:"Guarded, partial-domain correction: maps bound clear-five/clear-seven event channels using only target-local instruction operands and its existing V58/V60 entries. Independent V5C/input requirements remain enforced by loading-input-interrupt-setup. Direct writes, mixed setup and unbound programs are not corrected. A channel correction does not authorize the complete firmware pair.",
    policies:&[],
};
fn channel<'a>(context: &'a Context<'_>) -> Option<&'a Channel> {
    let irq = &context.sat.as_ref()?.irq;
    let Observation::Known(channel) = &irq.channel else {
        return None;
    };
    (matches!(irq.selected, Observation::Known(value) if value==channel.mapping.controller()))
        .then_some(channel)
}
fn value(mapping: Mapping) -> Value {
    Value::Variant(
        1,
        vec![Value::U8(if mapping == Mapping::Five { 5 } else { 7 })],
    )
}
impl Filter for LoadingChannel {
    fn id(&self) -> &'static str {
        ID
    }
    fn name(&self) -> &'static str {
        "Mapped loading interrupt channel"
    }
    fn rules(&self) -> Option<&'static super::Rules> {
        Some(&RULES)
    }
    fn inspect(&self, context: &Context<'_>) -> Assessment {
        if let Some(channel) = channel(context) {
            return Assessment::known(ID,Role::Hardware,value(channel.mapping),format!("Complete target-local setup/disarm/acknowledgement/vector binding: {channel:?}"));
        }
        let mut observed = super::loading::legacy(context);
        observed.id = ID;
        if let Finding::Known(value) = observed.finding {
            observed.finding = Finding::Known(Value::Variant(0, vec![value]));
        }
        observed.evidence=format!("No complete mapped-channel correction proof; retain original native requirement unchanged. {}",observed.evidence);
        observed
    }
    fn candidate(&self, context: &Context<'_>, assessment: &Assessment) -> Finding {
        if assessment.id != ID
            || assessment.role != Role::Hardware
            || self.inspect(context).finding != assessment.finding
        {
            return Finding::Unresolved(
                "Mapped-channel assessment is not bound to this owner and context".into(),
            );
        }
        if channel(context).is_some() {
            Finding::Known(Value::Variant(1, vec![]))
        } else {
            assessment.finding.clone()
        }
    }
    fn plan(
        &self,
        transition: &Transition<'_, '_>,
        installed: &Assessment,
        target: &Assessment,
    ) -> Result<Option<Box<dyn Operation>>, Error> {
        if installed.id != ID
            || target.id != ID
            || installed.role != Role::Hardware
            || target.role != Role::Hardware
            || self.inspect(transition.installed).finding != installed.finding
            || self.inspect(transition.target).finding != target.finding
        {
            return Err(Error::UnresolvedIdentity);
        }
        match self.compare(installed, target) {
            Comparison::Match => return Ok(None),
            Comparison::Unresolved | Comparison::Conflicting => {
                return Err(Error::UnresolvedIdentity)
            }
            Comparison::Different => {}
        }
        let required = channel(transition.installed)
            .ok_or(Error::Incompatible)?
            .mapping;
        let from = channel(transition.target)
            .ok_or(Error::Incompatible)?
            .clone();
        from.correct(transition.target.firmware.normal, required)
            .ok_or(Error::Unsupported)?;
        Ok(Some(Box::new(ChannelOperation {
            hardware: transition.target.firmware.hardware.into(),
            normal: transition.target.firmware.normal.to_vec(),
            kernel: transition.target.firmware.kernel.map(<[u8]>::to_vec),
            from,
            required,
        })))
    }
}
struct ChannelOperation {
    hardware: String,
    normal: Vec<u8>,
    kernel: Option<Vec<u8>>,
    from: Channel,
    required: Mapping,
}
impl core::fmt::Debug for ChannelOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChannelOperation")
            .field("from", &self.from.mapping)
            .field("required", &self.required)
            .field("normal_bytes", &self.normal.len())
            .finish()
    }
}
impl ChannelOperation {
    fn bound(&self, context: &Preparation<'_>) -> Result<(), Error> {
        if context.target.hardware != self.hardware
            || context.target.normal != self.normal
            || context.target.kernel != self.kernel.as_deref()
        {
            return Err(Error::ComponentMismatch);
        }
        #[cfg(feature = "envelope")]
        {
            use crate::{envelope::Layout, ComponentKind};
            if let Some(normal) = context.normal {
                if normal.image != self.normal
                    || normal.info().kind != ComponentKind::Normal
                    || normal.info().hardware_version != self.hardware
                {
                    return Err(Error::ComponentMismatch);
                }
                if !matches!(
                    normal.info().layout,
                    Layout::Normal | Layout::NormalReverse | Layout::NormalScaledKey
                ) {
                    return Err(Error::Representation);
                }
                if self.kernel.is_some() && context.kernel.is_none() {
                    return Err(Error::UnresolvedIdentity);
                }
            }
            if let Some(kernel) = context.kernel {
                if kernel.info().kind != ComponentKind::Kernel
                    || Some(kernel.image.as_slice()) != self.kernel.as_deref()
                    || kernel.info().hardware_version != self.hardware
                {
                    return Err(Error::ComponentMismatch);
                }
                if let Some(normal) = context.normal {
                    let n = normal.header_info();
                    let k = kernel.header_info();
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
            }
        }
        Ok(())
    }
}
impl Operation for ChannelOperation {
    fn filter_id(&self) -> &'static str {
        ID
    }
    fn integrity(&self) -> Option<Integrity> {
        Some(super::be32_normal_integrity())
    }
    fn prepare(&self, context: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
        self.bound(context)?;
        let result = self
            .from
            .correct(&self.normal, self.required)
            .ok_or(Error::Unsupported)?;
        // Establish checksum/codec authority now; the composer repairs once
        // after combining every independent owner's non-checksum edits.
        (super::be32_normal_integrity().repair)(context, &result)?;
        self.verify(context, &result)?;
        Ok(Some(result))
    }
    fn verify(&self, context: &Preparation<'_>, normal: &[u8]) -> Result<(), Error> {
        self.bound(context)?;
        if !self.from.verify(&self.normal, normal, self.required) {
            return Err(Error::VerificationFailed);
        }
        Ok(())
    }
}

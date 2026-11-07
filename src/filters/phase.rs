//! Native phase observation, comparison and correction ownership.
//!
//! A detected phase is not evidence that its file can be corrected. Native
//! interfaces remain part of identity even when source assignment is normalized.
/// Sled mechanism convention bundle bound from native code.
pub mod bundle;
mod mechanism;
/// Native phase recognition, operand corrections and instruction contracts.
pub mod native;

use super::{
    Assessment, Comparison, Context, Filter, Finding, Integrity, Operation, Preparation, Role,
    Transition, Value,
};
use crate::compatibility::{Error, Firmware};
use crate::image::{
    layout::{self, Observation, Unresolved},
    peripheral,
};
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};

/// Native processor family establishing a phase interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    /// Complete H8 output programs.
    H8,
    /// Complete M32C output consumers and writers.
    M32c,
    /// Complete V850 output consumers and Kernel-bound writer coordinates.
    V850,
}

/// Physical output coordinates and the native representation driving them.
/// RAM sources, helper addresses and relocated tables are not hardware identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interface {
    /// Combined H8 source-byte program and its encoded output register operands.
    H8BytePair {
        /// Canonical ascending native sixteen-bit output register operands.
        outputs: [u16; 2],
    },
    /// H8 source-word programs with separate control and output registers.
    H8SplitWord {
        /// Canonical ascending native sixteen-bit output register operands.
        outputs: [u16; 2],
        /// Canonical ascending native sixteen-bit control register operands.
        controls: [u16; 2],
    },
    /// Direct byte output registers.
    Direct8 {
        /// Canonical ascending native channel addresses.
        channels: [u32; 2],
    },
    /// Indexed word output bus.
    Indexed16 {
        /// Exact native bus window, including Kernel-derived EP when required.
        window: u32,
        /// Canonical ascending native output register indices.
        channels: [u32; 2],
    },
}

/// Complete native phase fact, independent of correction capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativePhase {
    /// Processor family established by the native detector.
    pub architecture: Architecture,
    /// Native output representation and hardware register coordinates.
    pub interface: Interface,
    /// Which source element supplies the first output channel.
    pub assignment: native::Assignment,
}
impl NativePhase {
    /// Canonical typed phase contract. Variant tags are local to this filter.
    pub fn value(self) -> Value {
        let architecture = match self.architecture {
            Architecture::H8 => 0,
            Architecture::M32c => 1,
            Architecture::V850 => 2,
        };
        let interface = match self.interface {
            Interface::H8BytePair { outputs } => {
                Value::Variant(0, outputs.into_iter().map(Value::U16).collect())
            }
            Interface::H8SplitWord { outputs, controls } => Value::Variant(
                1,
                outputs
                    .into_iter()
                    .chain(controls)
                    .map(Value::U16)
                    .collect(),
            ),
            Interface::Direct8 { channels } => {
                Value::Variant(2, channels.into_iter().map(Value::U32).collect())
            }
            Interface::Indexed16 { window, channels } => Value::Variant(
                3,
                vec![
                    Value::U32(window),
                    Value::U32(channels[0]),
                    Value::U32(channels[1]),
                ],
            ),
        };
        Value::Variant(
            1,
            vec![
                Value::U8(architecture),
                interface,
                Value::U8(u8::from(self.assignment == native::Assignment::Swapped)),
            ],
        )
    }
    /// Recover only this filter's exact well-typed value contract.
    pub fn from_value(value: &Value) -> Option<Self> {
        let Value::Variant(1, fields) = value else {
            return None;
        };
        let [Value::U8(architecture), Value::Variant(tag, interface), Value::U8(assignment)] =
            fields.as_slice()
        else {
            return None;
        };
        let architecture = match architecture {
            0 => Architecture::H8,
            1 => Architecture::M32c,
            2 => Architecture::V850,
            _ => return None,
        };
        let assignment = match assignment {
            0 => native::Assignment::Direct,
            1 => native::Assignment::Swapped,
            _ => return None,
        };
        let interface = match (*tag, interface.as_slice()) {
            (0, [Value::U16(a), Value::U16(b)]) if architecture == Architecture::H8 => {
                Interface::H8BytePair { outputs: [*a, *b] }
            }
            (1, [Value::U16(a), Value::U16(b), Value::U16(c), Value::U16(d)])
                if architecture == Architecture::H8 =>
            {
                Interface::H8SplitWord {
                    outputs: [*a, *b],
                    controls: [*c, *d],
                }
            }
            (2, [Value::U32(a), Value::U32(b)]) if architecture == Architecture::M32c => {
                Interface::Direct8 { channels: [*a, *b] }
            }
            (3, [Value::U32(window), Value::U32(a), Value::U32(b)])
                if architecture != Architecture::H8 =>
            {
                Interface::Indexed16 {
                    window: *window,
                    channels: [*a, *b],
                }
            }
            _ => return None,
        };
        Some(Self {
            architecture,
            interface,
            assignment,
        })
    }
    fn same_interface(self, other: Self) -> bool {
        self.architecture == other.architecture && self.interface == other.interface
    }
}

fn h8(value: native::Phase) -> NativePhase {
    let interface = match value.interface {
        native::Interface::BytePair => Interface::H8BytePair {
            outputs: [0xf908, 0xf909],
        },
        native::Interface::SplitWord => Interface::H8SplitWord {
            outputs: [0xf910, 0xf911],
            controls: [0xf912, 0xf913],
        },
    };
    NativePhase {
        architecture: Architecture::H8,
        interface,
        assignment: value.assignment,
    }
}
fn ata(architecture: Architecture, value: peripheral::Phase) -> NativePhase {
    let interface = match value.interface {
        peripheral::Interface::Direct8 { channels } => Interface::Direct8 { channels },
        peripheral::Interface::Indexed16 { window, channels } => {
            Interface::Indexed16 { window, channels }
        }
    };
    NativePhase {
        architecture,
        interface,
        assignment: value.assignment,
    }
}
fn map<T>(
    observation: Observation<T>,
    convert: impl FnOnce(T) -> NativePhase,
) -> Observation<NativePhase> {
    match observation {
        Observation::Known(value) => Observation::Known(convert(value)),
        Observation::Unresolved(reason) => Observation::Unresolved(reason),
        Observation::Conflicting => Observation::Conflicting,
    }
}

/// Observe phase without requiring any other hardware filter or a usable codec.
/// Every native backend is considered; unknown legacy/SCSI is explicit.
pub fn observe(firmware: Firmware<'_>) -> Observation<NativePhase> {
    let mut observations = vec![map(native::discover(firmware.normal), h8)];
    for base in [0xf40000, 0xf80000] {
        observations.push(map(peripheral::m32c_phase(firmware.normal, base), |p| {
            ata(Architecture::M32c, p)
        }));
    }
    if let Some(normal) = layout::decode_v850_bus(firmware.normal) {
        let kernel = firmware.kernel.and_then(layout::decode_v850_bus);
        if firmware.kernel.is_none() || kernel.is_some() {
            observations.push(map(
                peripheral::v850_phase_native(&normal, kernel.as_deref()),
                |p| ata(Architecture::V850, p),
            ));
        }
    }
    let mut known = None;
    let mut unresolved = Unresolved::ReaderNotRecognized;
    for observation in observations {
        match observation {
            Observation::Known(value) => {
                if known.is_some_and(|previous| previous != value) {
                    return Observation::Conflicting;
                }
                known = Some(value);
            }
            Observation::Conflicting => return Observation::Conflicting,
            Observation::Unresolved(reason @ Unresolved::ResidentCodeRequired(_)) => {
                unresolved = reason
            }
            Observation::Unresolved(_) => {}
        }
    }
    known.map_or(Observation::Unresolved(unresolved), Observation::Known)
}

/// Registered native phase owner.
pub struct PhaseFilter;
/// Native phase filter, evaluated for every firmware context.
pub static FILTER: PhaseFilter = PhaseFilter;

/// Rules declared beside this owner's enforcing code; rendered verbatim by reports.
static RULES: super::Rules = super::Rules {
    description: "Identifies which source element drives which phase output (direct 0 or swapped 1) together with the native architecture and output interface: H8 byte or split-word outputs, M32C outputs or the V850 indexed bus. The assignment is not signed waveform winding or physical motor direction.",
    role: super::Role::Hardware,
    correctability: super::Correctability::Guarded,
    correction: "Corrected in Normal only for pairs the phase owner proves. A different native interface requires a complete mechanism conversion; assignment-only changes require the same interface. The matching family drops the assignment only for H8 programs with a complete paired-word grammar.",
    policies: &[
        super::Policy {
            domains: &[],
            text: "Unresolved or conflicting phase refuses. A phase correction authorizes only the phase change: every other registered value must still match, and the corrected image is re-verified.",
        },
        super::Policy {
            domains: &[super::identity::Domain::Sat1],
            text: "SAT1 phase correction requires a complete command-relative native graph, exact paired Kernel leaves, table ownership and caller/output verification. Other assignment changes remain suspended.",
        },
        super::Policy {
            domains: &[super::identity::Domain::H8Sat],
            text: "Split-word (F910-F913) corrections bind the complete sled mechanism bundle. Differing bundles use OEM routines and tables through the phase operation, with full resource and caller verification; equal coil assignments do not suppress required mechanism correction. Growth without proved placement remains Unsupported and cannot be waived by Recovery. Bound 0x28F selection requires the existing word to equal 1; the operation never writes it.",
        },
        super::Policy {
            domains: &[super::identity::Domain::Ata],
            text: "M32C corrections need a tail-key Normal, or a boot-key Normal with its Kernel. V850 corrections need sparse-checksum Normal and Kernel files and the exact paired Kernel.",
        },
        super::Policy {
            domains: &[super::identity::Domain::Scsi],
            text: "No SCSI phase program is recognized, so phase stays Unresolved and no correction is planned.",
        },
    ],
};
impl Filter for PhaseFilter {
    fn id(&self) -> &'static str {
        "phase"
    }
    fn name(&self) -> &'static str {
        "Phase output assignment"
    }
    fn rules(&self) -> Option<&'static super::Rules> {
        Some(&RULES)
    }
    fn inspect(&self, context: &Context<'_>) -> Assessment {
        match &context.native_phase {
            Observation::Known(value) => Assessment::known(self.id(),Role::Hardware,value.value(),format!("complete native {:?} phase program: {:?}; {:?}",value.architecture,value.interface,value.assignment)),
            Observation::Unresolved(reason) => Assessment::unresolved(self.id(),Role::Hardware,format!("native phase assignment/interface unresolved: {reason:?}; no default or legacy exclusion is inferred")),
            Observation::Conflicting => Assessment::conflicting(self.id(),Role::Hardware,"independent native phase programs establish different architecture/interface/assignment facts"),
        }
    }
    fn compare(&self, installed: &Assessment, target: &Assessment) -> Comparison {
        if installed.id != self.id()
            || target.id != self.id()
            || installed.role != Role::Hardware
            || target.role != Role::Hardware
        {
            return Comparison::Conflicting;
        }
        match (&installed.finding, &target.finding) {
            (Finding::Conflicting(_), _) | (_, Finding::Conflicting(_)) => Comparison::Conflicting,
            (Finding::Unresolved(_), _) | (_, Finding::Unresolved(_)) => Comparison::Unresolved,
            (Finding::Known(a), Finding::Known(b)) => {
                match (NativePhase::from_value(a), NativePhase::from_value(b)) {
                    (Some(a), Some(b)) if a == b => Comparison::Match,
                    (Some(_), Some(_)) => Comparison::Different,
                    _ => Comparison::Conflicting,
                }
            }
            _ => Comparison::Unresolved,
        }
    }
    fn candidate(&self, context: &Context<'_>, assessment: &Assessment) -> Finding {
        let Finding::Known(value) = &assessment.finding else {
            return assessment.finding.clone();
        };
        let Some(fact) = NativePhase::from_value(value) else {
            return Finding::Conflicting("invalid native phase value".into());
        };
        if assessment.id != self.id() || assessment.role != Role::Hardware {
            return Finding::Conflicting("phase assessment owner/role mismatch".into());
        }
        // This is a native grouping contract, not checksum/file admission.
        // Complete paired grammar is a reviewed two-way output permutation.
        // The candidate projection is the published family grouping and stays
        // assignment-free; correctability is decided per pair in `plan`, where
        // the complete mechanism bundle is gated.
        if fact.architecture == Architecture::H8
            && matches!(native::discover_pair(context.firmware.normal),Observation::Known(p) if p.assignment == fact.assignment)
            && matches!(&context.native_phase,Observation::Known(actual) if *actual == fact)
        {
            let Value::Variant(_, mut fields) = fact.value() else {
                unreachable!()
            };
            fields.pop();
            return Finding::Known(Value::Variant(2, fields));
        }
        // Other detectors expose the native fact but no unique raw permutation
        // proof object for candidate projection. In particular agreeing duplicate
        // SAT1/ATA programs may be observable while correction refuses. Retain
        // assignment here; per-pair preparation still supports their proved forms.
        Finding::Known(fact.value())
    }
    fn plan(
        &self,
        transition: &Transition<'_, '_>,
        installed: &Assessment,
        target: &Assessment,
    ) -> Result<Option<Box<dyn Operation>>, Error> {
        match self.compare(installed, target) {
            Comparison::Unresolved | Comparison::Conflicting => {
                return Err(Error::UnresolvedIdentity)
            }
            Comparison::Match | Comparison::Different => {}
        }
        let from = fact(target)?;
        let required = fact(installed)?;
        if !matches!(&transition.installed.native_phase,Observation::Known(p) if *p==required)
            || !matches!(&transition.target.native_phase,Observation::Known(p) if *p==from)
        {
            return Err(Error::UnresolvedIdentity);
        }
        let mechanism = mechanism_gate(transition, from, required)?;
        // A differing native interface needs a complete mechanism operation;
        // assignment-only patching never establishes an interface conversion.
        if !from.same_interface(required) && mechanism.is_none() {
            return Err(Error::Incompatible);
        }
        if from == required && mechanism.is_none() {
            return Ok(None);
        }
        Ok(Some(Box::new(PhaseOperation {
            hardware: transition.target.firmware.hardware.into(),
            normal: transition.target.firmware.normal.to_vec(),
            kernel: transition.target.firmware.kernel.map(<[u8]>::to_vec),
            from,
            required,
            mechanism,
        })))
    }
}
/// Split-word coil mapping is one element of the sled mechanism convention.
/// Differing bundles require a complete mechanism operation, even with equal
/// coil mappings. Missing composition or placement proof remains Unsupported
/// and cannot be waived by a family override.
fn mechanism_gate(
    transition: &Transition<'_, '_>,
    from: NativePhase,
    required: NativePhase,
) -> Result<Option<mechanism::Mechanism>, Error> {
    if transition.installed.firmware.normal == transition.target.firmware.normal
        && transition.installed.firmware.kernel == transition.target.firmware.kernel
    {
        return Ok(None);
    }
    // Byte-pair SAT1 programs need their command/table proof even when their
    // coarse phase labels match. The optional-component planner owns every
    // accepted graph; missing proofs are not converted into an equal-label no-op.
    if native::sat1::byte_pair::observe_normal(transition.installed.firmware.normal).is_ok()
        || native::sat1::byte_pair::observe_normal(transition.target.firmware.normal).is_ok()
    {
        return mechanism::Mechanism::plan_sat1(transition).map(Some);
    }
    // Complete command-relative SAT1 graphs establish their own authority;
    // hardware spelling is not a positive correction recipe. Equal coil facts
    // still require table comparison, and every change binds both exact Kernels.
    match (
        native::sat1::observe_normal(transition.installed.firmware.normal),
        native::sat1::observe_normal(transition.target.firmware.normal),
    ) {
        (Ok(source), Ok(target)) => {
            if source.assignment != required.assignment || target.assignment != from.assignment {
                return Err(Error::UnresolvedIdentity);
            }
            if source.assignment == target.assignment
                && source.tables.iter().zip(&target.tables).all(|(a, b)| {
                    transition.installed.firmware.normal[a.clone()]
                        == transition.target.firmware.normal[b.clone()]
                })
            {
                return Ok(None);
            }
            return mechanism::Mechanism::plan_sat1(transition).map(Some);
        }
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => return Err(Error::Unsupported),
        _ => {}
    }
    // Other SAT1 programs remain suspended without command-relative proof.
    let sat1 = |firmware: Firmware<'_>| {
        super::identity::Domain::from_hardware(firmware.hardware)
            == Some(super::identity::Domain::Sat1)
    };
    if from.assignment != required.assignment
        && (sat1(transition.installed.firmware) || sat1(transition.target.firmware))
    {
        return Err(Error::Unsupported);
    }
    if !matches!(from.interface, Interface::H8SplitWord { .. }) {
        return Ok(None);
    }
    // Materialized software mechanisms have their own complete native
    // observation. They do not acquire fabricated legacy DSP bundle fields.
    let software = |firmware: Firmware<'_>| {
        firmware.kernel.and_then(|kernel| {
            bundle::waveforms::resources::reverse_composition::observe(firmware.normal, kernel)
        })
    };
    match (
        software(transition.installed.firmware),
        software(transition.target.firmware),
    ) {
        (Some(a), Some(b)) if a.equivalent(&b) => return Ok(None),
        (Some(_), _) | (_, Some(_)) => return Err(Error::Unsupported),
        _ => {}
    }
    let generated = bundle::waveforms::resources::generated::observe;
    if let (Ok(a), Ok(b), installed_loader, target_loader) = (
        generated(transition.installed.firmware.normal),
        generated(transition.target.firmware.normal),
        bundle::waveforms::loader::observe(transition.installed.firmware.normal),
        bundle::waveforms::loader::observe(transition.target.firmware.normal),
    ) {
        let matching_loaders = match (&installed_loader, &target_loader) {
            (Err(_), Err(_)) => true,
            (Ok(a), Ok(b)) if a.computed && b.computed => {
                let computed = bundle::waveforms::loader::computed::observe;
                match (
                    computed(transition.installed.firmware.normal),
                    computed(transition.target.firmware.normal),
                ) {
                    (Ok(source), Ok(target)) => {
                        a.loader == b.loader
                            && source.calibration == target.calibration
                            && source.arithmetic == target.arithmetic
                            && transition.installed.firmware.normal[source.basis]
                                == transition.target.firmware.normal[target.basis]
                    }
                    _ => false,
                }
            }
            _ => false,
        };
        // Preserve the existing no-op when the actual generated convention
        // agrees. Relocated calibration services alone request no phase edit.
        use bundle::waveforms::resources::evaluators::Calibration;
        let calibration_agrees = match (&a.calibration.1, &b.calibration.1) {
            (Calibration::Constants(a), Calibration::Constants(b)) => a == b,
            (
                Calibration::Parameters {
                    indices: ai,
                    defaults: ad,
                    ..
                },
                Calibration::Parameters {
                    indices: bi,
                    defaults: bd,
                    ..
                },
            ) => ai == bi && ad == bd,
            _ => false,
        };
        if matching_loaders
            && calibration_agrees
            && a.coils.assignment == b.coils.assignment
            && a.step_minus_source == b.step_minus_source
            && transition.installed.firmware.normal[a.evaluator.basis.clone()]
                == transition.target.firmware.normal[b.evaluator.basis.clone()]
        {
            return Ok(None);
        }
        return mechanism::Mechanism::plan_generated(transition).map(Some);
    }
    if let Ok(source) = generated(transition.installed.firmware.normal) {
        if source.coils.assignment != required.assignment {
            return Err(Error::UnresolvedIdentity);
        }
        return mechanism::Mechanism::plan_reverse(transition).map(Some);
    }
    let installed = bundle::bind(transition.installed.firmware.normal);
    let target = bundle::bind(transition.target.firmware.normal);
    match (installed, target) {
        (Ok(a), Ok(b))
            if matches!(
                bundle::composition::equivalent(
                    transition.target.firmware.normal,
                    transition.installed.firmware.normal,
                ),
                Ok(true)
            ) =>
        {
            if a.coil != required.assignment || b.coil != from.assignment {
                return Err(Error::UnresolvedIdentity);
            }
            Ok(None)
        }
        (Ok(a), Ok(b)) => {
            if a.coil != required.assignment || b.coil != from.assignment {
                return Err(Error::UnresolvedIdentity);
            }
            mechanism::Mechanism::plan(transition, a.table_select_0x28f || b.table_select_0x28f)
                .map(Some)
        }
        // Equal coil facts do not establish agreement with a generated target
        // when either complete Bundle is unbound. Positive Bundle proofs above
        // remain available for generated mechanisms with a native DSP loader.
        _ if generated(transition.target.firmware.normal).is_ok() => Err(Error::Unsupported),
        _ if from.assignment != required.assignment => Err(Error::Unsupported),
        _ => Ok(None),
    }
}

fn fact(assessment: &Assessment) -> Result<NativePhase, Error> {
    match &assessment.finding {
        Finding::Known(value) => NativePhase::from_value(value).ok_or(Error::UnresolvedIdentity),
        _ => Err(Error::UnresolvedIdentity),
    }
}

struct PhaseOperation {
    hardware: String,
    normal: Vec<u8>,
    kernel: Option<Vec<u8>>,
    from: NativePhase,
    required: NativePhase,
    mechanism: Option<mechanism::Mechanism>,
}
impl core::fmt::Debug for PhaseOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PhaseOperation")
            .field("hardware", &self.hardware)
            .field("normal_bytes", &self.normal.len())
            .field("kernel_bytes", &self.kernel.as_ref().map(Vec::len))
            .field("from", &self.from)
            .field("required", &self.required)
            .finish()
    }
}
impl PhaseOperation {
    fn bound(&self, context: &Preparation<'_>) -> Result<(), Error> {
        if context.target.hardware != self.hardware
            || context.target.normal != self.normal
            || context.target.kernel != self.kernel.as_deref()
        {
            return Err(Error::ComponentMismatch);
        }
        #[cfg(feature = "envelope")]
        {
            use crate::ComponentKind;
            if let Some(normal) = context.normal {
                if normal.info().kind != ComponentKind::Normal
                    || normal.image != self.normal
                    || normal.info().hardware_version != self.hardware
                {
                    return Err(Error::ComponentMismatch);
                }
                if context.target.kernel.is_some() && context.kernel.is_none() {
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
impl Operation for PhaseOperation {
    fn filter_id(&self) -> &'static str {
        "phase"
    }
    fn description(&self) -> Option<crate::compatibility::Correction> {
        Some(crate::compatibility::Correction::Phase {
            from: self.from.assignment,
            to: self.required.assignment,
        })
    }
    fn required_words(&self) -> Vec<super::prerequisites::Word> {
        self.mechanism
            .as_ref()
            .map_or_else(Vec::new, mechanism::Mechanism::required_words)
    }
    fn integrity(&self) -> Option<Integrity> {
        (self.from.architecture == Architecture::H8).then(super::be32_normal_integrity)
    }
    fn prepare(&self, context: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
        self.bound(context)?;
        if let Some(mechanism) = &self.mechanism {
            return self.prepared(context, mechanism.prepare(context)?);
        }
        let mut image = match self.from.architecture {
            Architecture::H8 => {
                #[cfg(feature = "envelope")]
                if let Some(normal) = context.normal {
                    use crate::envelope::Layout;
                    match normal.info().layout {
                        Layout::NormalScaledKey => {
                            let modified =
                                h8_native(context.target.normal, self.required.assignment)?;
                            // Validate the original codec/checksum authority; the
                            // shared composer owns final checksum compensation.
                            normal
                                .repair_image_checksum(&modified)
                                .ok_or(Error::Representation)?;
                            return self.prepared(context, modified);
                        }
                        Layout::Normal | Layout::NormalReverse => {}
                        _ => return Err(Error::Unsupported),
                    }
                }
                native::correct_normal(context.target.normal, self.required.assignment)
                    .map_err(Error::Phase)?
            }
            Architecture::M32c => {
                #[cfg(feature = "envelope")]
                {
                    use crate::envelope::Layout;
                    let normal = context.normal.ok_or(Error::Unsupported)?;
                    let base = match normal.info().layout {
                        Layout::NormalTailKey => 0xf40000,
                        Layout::NormalBootKey if context.kernel.is_some() => 0xf80000,
                        _ => return Err(Error::Unsupported),
                    };
                    let modified = peripheral::correct_m32c_phase_pair(
                        context.target.normal,
                        base,
                        self.required.assignment,
                    )
                    .map_err(Error::Phase)?;
                    normal
                        .repair_image_checksum(&modified)
                        .ok_or(Error::Representation)?
                }
                #[cfg(not(feature = "envelope"))]
                return Err(Error::Unsupported);
            }
            Architecture::V850 => {
                #[cfg(feature = "envelope")]
                if let Some(normal) = context.normal {
                    use crate::envelope::Layout;
                    if normal.info().layout != Layout::SparseChecksum
                        || context.kernel.map(|k| k.info().layout) != Some(Layout::SparseChecksum)
                    {
                        return Err(Error::Unsupported);
                    }
                }
                let kernel = context.target.kernel.ok_or(Error::UnresolvedIdentity)?;
                peripheral::correct_v850_normal_phase(
                    context.target.normal,
                    kernel,
                    self.required.assignment,
                )
                .map_err(Error::Phase)?
            }
        };
        if self.from.architecture == Architecture::H8 {
            image[16..20].copy_from_slice(&context.target.normal[16..20]);
        }
        self.prepared(context, image)
    }
    fn verify(&self, context: &Preparation<'_>, normal: &[u8]) -> Result<(), Error> {
        self.bound(context)?;
        if normal.len() != self.normal.len() {
            return Err(Error::VerificationFailed);
        }
        if let Some(mechanism) = &self.mechanism {
            mechanism.verify(context, normal)?;
        }
        let firmware = Firmware {
            normal,
            ..context.target
        };
        if !matches!(observe(firmware),Observation::Known(p) if p==self.required) {
            return Err(Error::VerificationFailed);
        }
        Ok(())
    }
}
impl PhaseOperation {
    fn prepared(
        &self,
        context: &Preparation<'_>,
        image: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.verify(context, &image)?;
        Ok(Some(image))
    }
}

/// Bounded H8 operand correction without checksum compensation.
/// Layout proofs may share this native operation; their integrity is separate.
#[cfg(feature = "envelope")]
pub(crate) fn h8_native(normal: &[u8], assignment: native::Assignment) -> Result<Vec<u8>, Error> {
    match native::discover_pair(normal) {
        Observation::Known(_) => native::correct_pair(normal, assignment),
        _ => native::correct_legacy(normal, assignment),
    }
    .map_err(Error::Phase)
}

#[cfg(test)]
mod tests;

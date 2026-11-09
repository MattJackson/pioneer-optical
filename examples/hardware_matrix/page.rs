//! Pioneer hardware matrix page model, shared by the `hardware_matrix` example
//! and its tests.
//!
//! Every value on the page comes from the code path the update path uses:
//! `filters::Context`, the registered filters, `filters::identity::discover`
//! and each owner's declared `Rules`. The checked-in template only lays the
//! embedded JSON out; it states no rule of its own.
#![allow(dead_code)]

use pioneer_optical::compatibility::Firmware;
use pioneer_optical::envelope::Envelope;
use pioneer_optical::filters::{self, identity, Assessment, Context, Finding, Role, Value};
use pioneer_optical::startup::inspection::{
    self, Inspection, ReaderEvidenceState, RequirementObservation,
};
use serde_json::{json, Value as Json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The checked-in static page template.
pub const TEMPLATE: &str = include_str!("template.html");
const DATA_SLOT: &str = "__MATRIX_DATA__";
/// Hand-written notes that are not rules; linked from the page.
pub const NOTES: &str =
    "https://github.com/MattJackson/pioneer-optical/blob/dev/docs/hardware-matrix-notes.md";

/// One held firmware package (a listing in the hoard index).
#[derive(Clone, Debug)]
pub struct Package {
    pub model: String,
    pub hardware: String,
    pub destination: String,
    pub revision: String,
    pub component: String,
    pub kernel: Option<String>,
    pub path: String,
    /// Tar member names of the Normal and the paired Kernel.
    pub members: (String, Option<String>),
}

/// Exact decoded components of one distinct Normal image.
pub struct Image<'a> {
    pub component: String,
    pub hardware: String,
    pub normal: &'a [u8],
    pub kernel: Option<&'a [u8]>,
}

/// Registered findings and identities of one image, from the update code path.
#[derive(Clone, Debug)]
pub struct Analysis {
    pub component: String,
    pub hardware: String,
    pub as_is: Option<String>,
    pub candidate: Option<String>,
    pub filters: Vec<Assessment>,
    pub startup_inspection: Option<Inspection>,
}

/// Run every registered filter and the identity discovery for one image.
pub fn analyze(image: &Image<'_>) -> Analysis {
    let context = Context::new(Firmware {
        hardware: &image.hardware,
        normal: image.normal,
        kernel: image.kernel,
    });
    let identity = identity::discover(&context);
    Analysis {
        component: image.component.clone(),
        hardware: image.hardware.clone(),
        as_is: identity
            .as_ref()
            .map(|i| format!("{:016x}", i.as_is.fingerprint())),
        candidate: identity
            .as_ref()
            .map(|i| format!("{:016x}", i.candidate.fingerprint())),
        filters: context.filters(),
        startup_inspection: context
            .sat
            .as_ref()
            .map(|_| inspection::inspect(image.normal, image.kernel)),
    }
}

fn startup_inspection(value: &Inspection) -> Json {
    let reader = match value.reader() {
        ReaderEvidenceState::Normal(_) => "Normal",
        ReaderEvidenceState::Resident { .. } => "Resident",
        ReaderEvidenceState::MissingResident { .. } => "Missing Kernel",
        ReaderEvidenceState::Unrecognized => "Reader not recognized",
        ReaderEvidenceState::Conflicting => "Conflicting reader",
    };
    let requirement = match value.requirement() {
        RequirementObservation::Fixed(_) => "Fixed comparison",
        RequirementObservation::Conditional(_) => "Conditional comparison",
        RequirementObservation::NoSupportedComparison => "No fixed comparison",
        RequirementObservation::Conflicting => "Conflicting comparison",
    };
    let label = if matches!(
        value.reader(),
        ReaderEvidenceState::MissingResident { .. }
            | ReaderEvidenceState::Unrecognized
            | ReaderEvidenceState::Conflicting
    ) {
        reader.into()
    } else if let RequirementObservation::Fixed(bound) = value.requirement() {
        format!(
            "Word {:04X} = {:04X}",
            bound.requirement.parameter, bound.requirement.required
        )
    } else if matches!(
        value.requirement(),
        RequirementObservation::Conditional(_) | RequirementObservation::Conflicting
    ) {
        requirement.into()
    } else if value.preservation().is_some() {
        String::from("Scoped preservation")
    } else if matches!(
        value.sink_failure(),
        Some(
            pioneer_optical::startup::coverage::sinks::Failure::UnclassifiedAddressReference { .. }
        )
    ) {
        String::from("Unclassified reference")
    } else {
        requirement.into()
    };
    let state = if matches!(value.requirement(), RequirementObservation::Fixed(_))
        && matches!(
            value.reader(),
            ReaderEvidenceState::Normal(_) | ReaderEvidenceState::Resident { .. }
        ) {
        requirement
    } else {
        label.as_str()
    };
    let mut details = vec![
        format!("Reader: {reader}"),
        format!("Requirement: {requirement}"),
    ];
    if let ReaderEvidenceState::MissingResident { entry } = value.reader() {
        details.push(format!("Required resident reader: {entry:#08x}"));
    }
    if let Some(preservation) = value.preservation() {
        details.push(format!(
            "Preservation scope: {:?}; this is not an application admission",
            preservation.scope()
        ));
        details.push(format!(
            "Native profile: {:?}",
            preservation.certificate().kind()
        ));
    }
    if let Some(failure) = value.sink_failure() {
        details.push(format!("Native boundary: {failure:?}"));
    }
    details.extend(
        value
            .rooted_obligations()
            .iter()
            .map(|obligation| format!("Remaining obligation: {obligation:?}")),
    );
    json!({
        "label": label,
        "state": state,
        "reader": reader,
        "requirement": requirement,
        "details": details,
        "normal_sha256": value.context().normal().iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "kernel_sha256": value.context().kernel().map(|id| id.iter().map(|b| format!("{b:02x}")).collect::<String>()),
    })
}

fn summary(finding: &Assessment) -> String {
    if finding.id == "phase" {
        if let Finding::Known(Value::Variant(1, fields)) = &finding.finding {
            return match fields.get(2) {
                Some(Value::U8(0)) => "Direct".into(),
                Some(Value::U8(1)) => "Swapped".into(),
                _ => "Assignment not bound".into(),
            };
        }
    }
    match &finding.finding {
        Finding::Known(_) => label(finding.id, &finding.finding),
        Finding::Unresolved(_) => "Not established".into(),
        Finding::Conflicting(_) => "Conflicting".into(),
        Finding::NotApplicable { .. } => "Not applicable".into(),
    }
}

/// Explicit provenance line; the page carries no timestamp.
#[derive(Clone, Debug)]
pub struct Source {
    pub crate_version: String,
    pub revision: String,
    pub hoard: String,
}

/// A distinct image that could not be decoded, kept visible on the page.
#[derive(Clone, Debug)]
pub struct Failure {
    pub component: String,
    pub path: String,
    pub error: String,
}

/// Owner expectations checked against the generated families. They are
/// reference checks, not rules: a result is reported, never enforced.
struct Control {
    name: &'static str,
    same: bool,
    by_model: bool,
    classes: &'static [&'static [&'static str]],
}
const CONTROLS: &[Control] = &[
    Control {
        name: "8301 / 8600 / 8680 / 8800",
        same: true,
        by_model: false,
        classes: &[&["SAT 8301"], &["SAT 8600"], &["SAT 8680"], &["SAT 8800"]],
    },
    Control {
        name: "8601 / 8801 / 8F00 / 8F01",
        same: true,
        by_model: false,
        classes: &[&["SAT 8601"], &["SAT 8801"], &["SAT 8F00"], &["SAT 8F01"]],
    },
    Control {
        name: "9000 / 9001",
        same: true,
        by_model: false,
        classes: &[&["SAT 9000"], &["SAT 9001"]],
    },
    Control {
        name: "UD02D / UD03 / UD04 matching family",
        same: true,
        by_model: true,
        classes: &[&["BDR-UD02D"], &["BDR-UD03"], &["BDR-UD04"]],
    },
    Control {
        name: "UD04 ≠ 211M",
        same: false,
        by_model: true,
        classes: &[&["BDR-UD04"], &["BDR-211M"]],
    },
    Control {
        name: "212U ≠ 213U",
        same: false,
        by_model: true,
        classes: &[&["BDR-212U"], &["BDR-213U"]],
    },
    Control {
        name: "1034 (206M) ≠ 8000",
        same: false,
        by_model: false,
        classes: &[&["SAT 1034"], &["SAT 8000"]],
    },
    Control {
        name: "SAT1xxx ≠ SAT8xxx",
        same: false,
        by_model: false,
        classes: &[
            &[
                "SAT 1003", "SAT 1005", "SAT 1007", "SAT 1010", "SAT 1011", "SAT 1013", "SAT 1014",
                "SAT 1030", "SAT 1031", "SAT 1034", "SAT 1040", "SAT 1041", "SAT 1046", "SAT 1050",
            ],
            &[
                "SAT 8000", "SAT 8130", "SAT 8211", "SAT 8221", "SAT 8231", "SAT 8232", "SAT 8291",
                "SAT 8301", "SAT 8410", "SAT 8420", "SAT 8510", "SAT 8511", "SAT 8520", "SAT 8591",
                "SAT 8600", "SAT 8601", "SAT 8680", "SAT 8721", "SAT 8722", "SAT 8800", "SAT 8801",
                "SAT 8A10", "SAT 8B30", "SAT 8D30", "SAT 8D31", "SAT 8E20", "SAT 8E21", "SAT 8F00",
                "SAT 8F01",
            ],
        ],
    },
];

/// Platform label from the structured hardware tag (the identity partition).
pub fn platform(hardware: &str) -> String {
    identity::Domain::from_hardware(hardware)
        .map_or_else(|| hardware.to_owned(), |d| d.label().to_owned())
}

fn state(finding: &Finding) -> &'static str {
    match finding {
        Finding::Known(_) => "Known",
        Finding::NotApplicable { .. } => "NotApplicable",
        Finding::Unresolved(_) => "Unresolved",
        Finding::Conflicting(_) => "Conflicting",
    }
}

fn num(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::U8(v) => Some((*v).into()),
        Value::U16(v) => Some((*v).into()),
        Value::U32(v) => Some((*v).into()),
        _ => None,
    }
}
fn hexw(value: Option<u64>, width: usize) -> String {
    value.map_or_else(|| "?".into(), |v| format!("0x{v:0width$X}"))
}
fn hex(value: Option<&Value>) -> String {
    hexw(num(value), 2)
}
fn seq(value: Option<&Value>) -> &[Value] {
    match value {
        Some(Value::Sequence(values)) => values,
        _ => &[],
    }
}
fn var(value: Option<&Value>) -> (Option<u16>, &[Value]) {
    match value {
        Some(Value::Variant(tag, fields)) => (Some(*tag), fields),
        _ => (None, &[]),
    }
}
fn boolean(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(true)))
}
fn bytes(value: Option<&Value>) -> &[u8] {
    match value {
        Some(Value::Bytes(b)) => b,
        _ => &[],
    }
}
fn join(values: &[Value], f: impl Fn(&Value) -> String, sep: &str) -> String {
    values.iter().map(f).collect::<Vec<_>>().join(sep)
}
fn predicate(value: &Value) -> String {
    let (_, f) = var(Some(value));
    format!(
        "{}.b{} = {} ({})",
        hex(f.first()),
        num(f.get(2)).map_or("?".into(), |b| b.to_string()),
        u8::from(boolean(f.get(3))),
        if num(f.get(1)) == Some(1) {
            "absolute16"
        } else {
            "absolute32"
        }
    )
}

/// Short presentation label of a known native value. Labels never feed
/// identity; the exact typed value is shown beside them.
fn known_label(id: &str, value: &Value) -> String {
    let (tag, f) = var(Some(value));
    let Some(tag) = tag else {
        return match value {
            Value::U8(v) => format!("U8 0x{v:02X}"),
            Value::U16(v) => format!("U16 0x{v:04X}"),
            Value::U32(v) => format!("U32 0x{v:08X}"),
            Value::Bool(v) => format!("Bool {v}"),
            other => format!("{other:?}"),
        };
    };
    let g = |i: usize| f.get(i);
    let label = match (id, tag) {
        ("persistent-storage-geometry", 1) => Some(format!(
            "Marker {}; bank spacing {} bytes",
            hex(g(0)),
            hex(g(1))
        )),
        ("persistent-storage-geometry", 2) => Some(format!(
            "Banks {}; spacing {} bytes",
            join(seq(g(0)), |x| hex(Some(x)), " / "),
            hex(g(1))
        )),
        ("persistent-storage-geometry", 3) => Some(format!(
            "Flash regions {}",
            join(
                seq(g(0)),
                |x| join(seq(Some(x)), |y| hex(Some(y)), " / "),
                "; "
            )
        )),
        ("persistent-storage-geometry", 4) => {
            Some(format!("Serial words {}–{}", hex(g(0)), hex(g(1))))
        }
        ("persistent-storage-geometry", 5) => Some(format!(
            "Serial record bases {}; {} ordered slots",
            join(seq(g(0)), |x| hex(Some(x)), " / "),
            seq(g(1)).len()
        )),
        ("startup-inputs-initialization" | "host-interface-setup", 1) => {
            Some(format!("{} & {} = {}", hex(g(0)), hex(g(1)), hex(g(2))))
        }
        ("startup-inputs-initialization", 2) => Some(format!(
            "Complete older H8 E4 initializer ({} bytes)",
            bytes(g(0)).len()
        )),
        ("startup-inputs-initialization", 3) => Some(format!(
            "Closed: {}; open: {}",
            join(seq(g(0)), predicate, " AND "),
            join(seq(g(1)), predicate, " AND ")
        )),
        ("startup-inputs-initialization", 4) => Some(format!(
            "M32C initialization: {}",
            join(
                seq(g(0)),
                |op| {
                    let (t, f) = var(Some(op));
                    match t {
                        Some(1 | 2) => format!("{} ← {}", hex(f.first()), hex(f.get(1))),
                        Some(3) => format!(
                            "set {}.b{}",
                            hex(f.first()),
                            num(f.get(1)).map_or("?".into(), |b| b.to_string())
                        ),
                        _ => format!("{} & {} | {}", hex(f.first()), hex(f.get(1)), hex(f.get(2))),
                    }
                },
                "; "
            )
        )),
        ("startup-inputs-initialization", 5) => Some(format!(
            "M7900 I/O: {}",
            join(
                seq(g(0)),
                |op| {
                    let (_, f) = var(Some(op));
                    format!("{} ← {}", hex(f.first()), hex(f.get(1)))
                },
                "; "
            )
        )),
        ("startup-inputs-initialization", 6) => {
            let pins = |v: Option<&Value>| {
                join(
                    seq(v),
                    |term| {
                        let (_, f) = var(Some(term));
                        format!(
                            "{}.b{} = {}",
                            hexw(num(f.first()), 8),
                            num(f.get(1)).map_or("?".into(), |b| b.to_string()),
                            u8::from(boolean(f.get(2)))
                        )
                    },
                    " AND ",
                )
            };
            Some(format!("V850 closed: {}; open: {}", pins(g(0)), pins(g(1))))
        }
        ("startup-inputs-initialization", 7) => {
            let io = |v: Option<&Value>| {
                join(
                    seq(v),
                    |term| {
                        let (t, f) = var(Some(term));
                        let pin = format!(
                            "{}.b{}",
                            hexw(num(f.first()), 8),
                            num(f.get(1)).map_or("?".into(), |b| b.to_string())
                        );
                        match t {
                            Some(2) => format!("out {pin} ← {}", u8::from(boolean(f.get(2)))),
                            _ => format!("in {pin}"),
                        }
                    },
                    ", ",
                )
            };
            Some(format!("Closed I/O: {}; open I/O: {}", io(g(0)), io(g(1))))
        }
        ("host-interface-setup", 2) => Some(format!(
            "Complete older H8 host initializer ({} bytes)",
            bytes(g(0)).len()
        )),
        ("host-interface-setup", 3 | 4) => Some(format!(
            "{} host {}; signature {} / {}; reset writes {}",
            if tag == 3 { "M32C" } else { "V850" },
            hex(g(0)),
            hex(g(1)),
            hex(g(2)),
            join(seq(g(3)), |x| hex(Some(x)), " / ")
        )),
        ("loading-input-interrupt-setup", 1) => {
            let (t, f) = var(g(0));
            match t {
                Some(0) => Some(format!(
                    "{} = (old & {}) | {}",
                    hex(f.first()),
                    hex(f.get(1)),
                    hex(f.get(2))
                )),
                Some(1) => {
                    let term = seq(f.first());
                    let (_, address) = var(term.first());
                    Some(format!(
                        "{}.b{} = {}",
                        hex(address.first()),
                        num(term.get(1)).map_or("?".into(), |b| b.to_string()),
                        u8::from(boolean(term.get(2)))
                    ))
                }
                Some(2) => Some("Installed tray-close vector route: V58 active / V60 empty".into()),
                _ => None,
            }
        }
        ("loading-input-interrupt-setup", 2) => {
            let (t, f) = var(g(0));
            Some(if t == Some(0) {
                format!(
                    "M32C {}: closed b{}, open b{} = {}",
                    hex(f.first()),
                    num(f.get(1)).map_or("?".into(), |b| b.to_string()),
                    num(f.get(2)).map_or("?".into(), |b| b.to_string()),
                    u8::from(boolean(f.get(3)))
                )
            } else {
                format!(
                    "M32C key {} & {} = {}",
                    hex(f.first()),
                    hex(f.get(1)),
                    hex(f.get(2))
                )
            })
        }
        ("loading-input-interrupt-setup", 3) => {
            let (t, _) = var(g(0));
            let kind = [
                "counter-low",
                "timer-low",
                "high/falling/selected",
                "low/rising/selected",
                "low/rising/mode",
            ]
            .get(usize::from(t.unwrap_or(u16::MAX)))
            .copied()
            .unwrap_or("native");
            Some(format!(
                "V850 {kind} key program; 45 native counter/timer units"
            ))
        }
        ("persistent-parameter-layout", 1) => Some(join(
            seq(g(0)),
            |region| {
                let r = seq(Some(region));
                format!(
                    "{}{} · {} × {} B · header {} B",
                    if num(r.get(1)) == Some(1) {
                        "Selected bank + "
                    } else {
                        "Absolute "
                    },
                    hex(r.first()),
                    num(r.get(4)).map_or("?".into(), |v| v.to_string()),
                    num(r.get(3)).map_or("?".into(), |v| v.to_string()),
                    num(r.get(5)).map_or("?".into(), |v| v.to_string())
                )
            },
            "; ",
        )),
        ("persistent-parameter-layout", _) => Some(format!(
            "Native serial layout · {}",
            if tag == 2 {
                "contiguous word range"
            } else {
                "ordered selected records"
            }
        )),
        ("phase", _) => {
            let architecture = ["H8", "M32C", "V850"]
                .get(num(g(0)).unwrap_or(u64::MAX) as usize)
                .copied()
                .unwrap_or("Native");
            let (t, outputs) = var(g(1));
            let interface = [
                "byte outputs",
                "split-word outputs/control",
                "direct byte outputs",
                "indexed word bus",
            ]
            .get(usize::from(t.unwrap_or(u16::MAX)))
            .copied()
            .unwrap_or("output interface");
            let assignment = match num(g(2)) {
                Some(0) => "Direct (0)",
                Some(1) => "Swapped (1)",
                _ => "Assignment projected away",
            };
            Some(format!(
                "{assignment} · {architecture} {interface} {}",
                join(outputs, |x| hex(Some(x)), " / ")
            ))
        }
        ("startup-prerequisite", 1 | 10) => Some(format!(
            "Required word {} = {}",
            hexw(num(g(0)), 4),
            hexw(num(g(1)), 4)
        )),
        ("startup-prerequisite", 2) => Some(format!(
            "Accept {}; {} additionally requires the complete native predicate",
            hexw(num(g(1)), 4),
            hexw(num(g(2)), 4)
        )),
        ("startup-prerequisite", 11) => Some(format!(
            "V850 expected Kernel identity at +{}: {}",
            hex(g(0)),
            String::from_utf8_lossy(bytes(g(1))).replace('\0', "")
        )),
        ("startup-prerequisite", 20) => {
            Some("Resident checksum and matching 16-byte image-pair header".into())
        }
        _ => None,
    };
    label.unwrap_or_else(|| format!("Known native contract · variant {tag}"))
}

/// Presentation label of any finding.
pub fn label(id: &str, finding: &Finding) -> String {
    match finding {
        Finding::Known(value) => known_label(id, value),
        Finding::NotApplicable { proof, .. } => format!("Not applicable · native proof {proof}"),
        Finding::Unresolved(reason) => format!("Unresolved: {reason}"),
        Finding::Conflicting(reason) => format!("Conflicting: {reason}"),
    }
}

fn rules() -> Result<Json, String> {
    let mut out = Vec::new();
    for filter in filters::filters() {
        let rules = filter
            .rules()
            .ok_or_else(|| format!("registered filter {} declares no rules", filter.id()))?;
        let policies: Vec<Json> = rules
            .policies
            .iter()
            .map(|p| {
                json!({
                    "platforms": p.domains.iter().map(|d| d.label()).collect::<Vec<_>>(),
                    "text": p.text,
                })
            })
            .collect();
        out.push(json!({
            "id": filter.id(),
            "name": filter.name(),
            "role": rules.role,
            "correctability": rules.correctability,
            "description": rules.description,
            "correction": rules.correction,
            "policies": policies,
        }));
    }
    Ok(Json::Array(out))
}

fn controls(records: &[(&Package, Option<&Analysis>)]) -> Json {
    let mut out = Vec::new();
    for control in CONTROLS {
        let class = |p: &Package| {
            let field = if control.by_model {
                &p.model
            } else {
                &p.hardware
            };
            control
                .classes
                .iter()
                .position(|c| c.contains(&field.as_str()))
        };
        let rows: Vec<_> = records
            .iter()
            .filter_map(|(p, a)| class(p).map(|c| (c, *p, *a)))
            .collect();
        let absent: Vec<&str> = control
            .classes
            .iter()
            .flat_map(|c| c.iter().copied())
            .filter(|name| {
                !rows.iter().any(|(_, p, _)| {
                    (if control.by_model {
                        &p.model
                    } else {
                        &p.hardware
                    }) == name
                })
            })
            .collect();
        let (mut checked, mut failed, mut unknown) = (0u32, 0u32, 0u32);
        for (i, (ca, a, x)) in rows.iter().enumerate() {
            for (cb, b, y) in &rows[i + 1..] {
                if ca == cb {
                    continue;
                }
                if !control.same && platform(&a.hardware) != platform(&b.hardware) {
                    checked += 1;
                    continue;
                }
                match (
                    x.and_then(|x| x.candidate.as_ref()),
                    y.and_then(|y| y.candidate.as_ref()),
                ) {
                    (Some(x), Some(y)) => {
                        checked += 1;
                        if (x == y) != control.same {
                            failed += 1;
                        }
                    }
                    _ => unknown += 1,
                }
            }
        }
        let result = if failed > 0 {
            "Native contracts differ"
        } else if unknown > 0 || !absent.is_empty() || checked == 0 {
            "Incomplete"
        } else {
            "Pass"
        };
        out.push(json!({
            "name": control.name,
            "same": control.same,
            "result": result,
            "checked": checked,
            "failed": failed,
            "unknown": unknown,
            "absent": absent,
        }));
    }
    Json::Array(out)
}

fn revisions(records: &[(&Package, Option<&Analysis>)]) -> Json {
    type Revisions<'a> = Vec<(&'a str, Option<&'a str>)>;
    let mut models: BTreeMap<(&str, &str), Revisions> = BTreeMap::new();
    for (p, a) in records {
        models
            .entry((&p.model, &p.hardware))
            .or_default()
            .push((&p.revision, a.and_then(|a| a.as_is.as_deref())));
    }
    let (mut cases, mut incomplete, mut conflicts) = (0, 0, Vec::new());
    for ((model, hardware), rows) in &models {
        if rows.iter().map(|r| r.0).collect::<BTreeSet<_>>().len() < 2 {
            continue;
        }
        cases += 1;
        if rows.iter().any(|r| r.1.is_none()) {
            incomplete += 1;
        }
        if rows
            .iter()
            .filter_map(|r| r.1)
            .collect::<BTreeSet<_>>()
            .len()
            > 1
        {
            conflicts.push(format!("{model} | {hardware}"));
        }
    }
    json!({"cases": cases, "incomplete": incomplete, "conflicts": conflicts})
}

/// Validate an optional routes export: an object with a `routes` array of objects.
pub fn check_routes(routes: &Json) -> Result<(), String> {
    let list = routes
        .get("routes")
        .and_then(Json::as_array)
        .ok_or("routes export: expected an object with a \"routes\" array")?;
    if let Some(i) = list.iter().position(|r| !r.is_object()) {
        return Err(format!("routes export: route {i} is not an object"));
    }
    Ok(())
}

/// Assemble the page model. Inputs are sorted here, so the output does not
/// depend on hoard or thread order.
pub fn data(
    packages: &[Package],
    analyses: &[Analysis],
    failures: &[Failure],
    source: &Source,
    routes: Option<&Json>,
) -> Result<Json, String> {
    if let Some(routes) = routes {
        check_routes(routes)?;
    }
    let mut analyses: Vec<&Analysis> = analyses.iter().collect();
    analyses.sort_by(|a, b| a.component.cmp(&b.component));
    let by_component: BTreeMap<&str, &Analysis> = analyses
        .iter()
        .map(|a| (a.component.as_str(), *a))
        .collect();
    if by_component.len() != analyses.len() {
        return Err("duplicate image component".into());
    }
    let mut packages: Vec<&Package> = packages.iter().collect();
    packages.sort_by(|a, b| {
        (&a.model, &a.hardware, &a.destination, &a.revision, &a.path).cmp(&(
            &b.model,
            &b.hardware,
            &b.destination,
            &b.revision,
            &b.path,
        ))
    });
    let joined: Vec<(&Package, Option<&Analysis>)> = packages
        .iter()
        .map(|p| (*p, by_component.get(p.component.as_str()).copied()))
        .collect();

    let images: Vec<Json> = analyses
        .iter()
        .map(|a| {
            let filters: Vec<Json> = a
                .filters
                .iter()
                .map(|f| {
                    json!({
                        "id": f.id,
                        "role": f.role,
                        "state": state(&f.finding),
                        "label": label(f.id, &f.finding),
                        "finding": f.finding,
                        "evidence": f.evidence,
                        "summary": summary(f),
                        "inspection": (f.id == "startup-prerequisite")
                            .then(|| a.startup_inspection.as_ref().map(startup_inspection)).flatten(),
                    })
                })
                .collect();
            let unresolved: Vec<&str> = a
                .filters
                .iter()
                .filter(|f| {
                    f.role == Role::Hardware
                        && matches!(f.finding, Finding::Unresolved(_) | Finding::Conflicting(_))
                })
                .map(|f| f.id)
                .collect();
            json!({
                "component": a.component,
                "hardware": a.hardware,
                "platform": platform(&a.hardware),
                "as_is": a.as_is,
                "candidate": a.candidate,
                "unresolved": unresolved,
                "filters": filters,
            })
        })
        .collect();

    let records: Vec<Json> = packages
        .iter()
        .map(|p| {
            json!({
                "model": p.model,
                "hardware": p.hardware,
                "destination": p.destination,
                "revision": p.revision,
                "component": p.component,
                "kernel": p.kernel,
                "path": p.path,
            })
        })
        .collect();

    let mut platforms: BTreeMap<String, usize> = BTreeMap::new();
    for a in &analyses {
        *platforms.entry(platform(&a.hardware)).or_default() += 1;
    }
    let order = |p: &str| {
        identity::Domain::ALL
            .iter()
            .position(|d| d.label() == p)
            .unwrap_or(identity::Domain::ALL.len())
    };
    let mut platform_list: Vec<(&String, &usize)> = platforms.iter().collect();
    platform_list.sort_by(|a, b| (order(a.0), a.0).cmp(&(order(b.0), b.0)));

    let mut splits: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for a in &analyses {
        if let (Some(c), Some(x)) = (&a.candidate, &a.as_is) {
            splits.entry(c).or_default().insert(x);
        }
    }
    let known = analyses.iter().filter(|a| a.candidate.is_some()).count();
    let as_is: BTreeSet<_> = analyses.iter().filter_map(|a| a.as_is.as_ref()).collect();
    let normalized: BTreeMap<&str, Vec<&str>> = splits
        .iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(k, v)| (*k, v.iter().copied().collect()))
        .collect();

    let mut failures: Vec<&Failure> = failures.iter().collect();
    failures.sort_by(|a, b| (&a.component, &a.path).cmp(&(&b.component, &b.path)));

    Ok(json!({
        "title": "Pioneer hardware matrix",
        "notes": NOTES,
        "source": {
            "crate": format!("pioneer-optical {}", source.crate_version),
            "revision": source.revision,
            "hoard": source.hoard,
            "scheme": pioneer_optical::image::MATRIX_FAMILY_SCHEME,
        },
        "identity": {"partition": identity::PARTITION, "rules": identity::RULES},
        "platforms": platform_list.iter().map(|(p, n)| json!({"id": p, "images": n})).collect::<Vec<_>>(),
        "filters": rules()?,
        "summary": {
            "packages": packages.len(),
            "images": analyses.len(),
            "known": known,
            "unresolved": analyses.len() - known,
            "candidate_families": splits.len(),
            "as_is_families": as_is.len(),
            "phase_normalized": normalized,
            "failures": failures.iter().map(|f| json!({"component": f.component, "path": f.path, "error": f.error})).collect::<Vec<_>>(),
        },
        "controls": controls(&joined),
        "revisions": revisions(&joined),
        "images": images,
        "records": records,
        "routes": routes,
    }))
}

/// Render the self-contained page: the static template plus the embedded model.
pub fn render(data: &Json) -> String {
    // Inside a <script> element only "</" and "<!--" can end or confuse it.
    let json = serde_json::to_string(data)
        .expect("page model serializes")
        .replace("</", "<\\/")
        .replace("<!--", "<\\!--");
    TEMPLATE.replacen(DATA_SLOT, &json, 1)
}

fn tar_members(bytes: &[u8]) -> Result<BTreeMap<String, &[u8]>, String> {
    let mut out = BTreeMap::new();
    let mut at = 0;
    let text = |v: &[u8]| {
        String::from_utf8_lossy(&v[..v.iter().position(|x| *x == 0).unwrap_or(v.len())])
            .into_owned()
    };
    while let Some(h) = bytes.get(at..at + 512) {
        if h.iter().all(|b| *b == 0) {
            break;
        }
        let size = usize::from_str_radix(text(&h[124..136]).trim(), 8).map_err(|_| "tar size")?;
        let prefix = text(&h[345..500]);
        let name = if prefix.is_empty() {
            text(&h[..100])
        } else {
            format!("{prefix}/{}", text(&h[..100]))
        };
        let data = bytes
            .get(at + 512..at + 512 + size)
            .ok_or("truncated tar")?;
        if h[156] == b'0' || h[156] == 0 {
            out.insert(name, data);
        }
        at += 512 + size.div_ceil(512) * 512;
    }
    Ok(out)
}

/// Every Pioneer package listed by a firmware-extractor hoard index.
pub fn hoard_packages(root: &Path) -> Result<(Vec<Package>, Vec<u8>), String> {
    let raw = std::fs::read(root.join("index/packages.json")).map_err(|e| e.to_string())?;
    let index: Json = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let text = |v: &Json, k: &str| v[k].as_str().unwrap_or_default().to_owned();
    let mut out = Vec::new();
    for p in index["packages"]
        .as_array()
        .ok_or("index: missing packages")?
    {
        if p["family"] != "pioneer" {
            continue;
        }
        let component = |role: &str| {
            p["components"]
                .as_array()
                .and_then(|c| c.iter().find(|c| c["role"] == role))
                .map(|c| (text(c, "sha256"), text(c, "member")))
        };
        let (normal, normal_member) = component("normal")
            .ok_or_else(|| format!("{}: no Normal component", text(p, "path")))?;
        let kernel = component("kernel");
        out.push(Package {
            model: text(p, "embedded_model"),
            hardware: text(p, "hardware_version"),
            destination: text(p, "destination"),
            revision: text(p, "revision"),
            component: normal,
            kernel: kernel.as_ref().map(|k| k.0.clone()),
            path: text(p, "path"),
            members: (normal_member, kernel.map(|k| k.1)),
        });
    }
    Ok((out, raw))
}

/// Decoded Normal (with its paired Kernel when the package carries one).
pub struct Decoded {
    pub normal: Envelope,
    pub kernel: Option<Envelope>,
}

/// Decode one package's components exactly as the update path does.
pub fn decode(root: &Path, package: &Package) -> Result<Decoded, String> {
    let tar = std::fs::read(root.join(&package.path)).map_err(|e| e.to_string())?;
    let files = tar_members(&tar)?;
    let normal = files
        .get(&package.members.0)
        .ok_or("Normal member not found")?;
    let kernel = package
        .members
        .1
        .as_ref()
        .and_then(|m| files.get(m))
        .and_then(|k| Envelope::load(k).ok());
    // The paired Kernel supplies the codec where the Normal needs it; a Normal
    // that decodes standalone is still decoded when its Kernel is unusable.
    let normal = match &kernel {
        Some(k) => Envelope::load_with_kernel(normal, k).or_else(|_| Envelope::load(normal)),
        None => Envelope::load(normal),
    }
    .map_err(|e| e.to_string())?;
    Ok(Decoded { normal, kernel })
}

/// Hex SHA-256 of bytes (hoard digest and member matching).
pub fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Decode and analyze every distinct Normal in parallel. For a Normal held in
/// several packages, the first package (by path) that pairs a Kernel is used,
/// else the first package.
pub fn analyze_hoard(
    root: &Path,
    packages: &[Package],
    mut each: impl FnMut(&Package, &Decoded, &Analysis) + Send,
) -> (Vec<Analysis>, Vec<Failure>) {
    let mut chosen: BTreeMap<&str, &Package> = BTreeMap::new();
    let mut sorted: Vec<&Package> = packages.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    for p in sorted {
        let entry = chosen.entry(&p.component).or_insert(p);
        if entry.kernel.is_none() && p.kernel.is_some() {
            *entry = p;
        }
    }
    let work: Vec<&Package> = chosen.into_values().collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results = std::sync::Mutex::new((Vec::new(), Vec::new()));
    let each = std::sync::Mutex::new(&mut each);
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(package) = work.get(i) else { break };
                match decode(root, package) {
                    Ok(decoded) => {
                        let analysis = analyze(&Image {
                            component: package.component.clone(),
                            hardware: decoded.normal.info().hardware_version.clone(),
                            normal: &decoded.normal.image,
                            kernel: decoded.kernel.as_ref().map(|k| k.image.as_slice()),
                        });
                        (each.lock().unwrap())(package, &decoded, &analysis);
                        results.lock().unwrap().0.push(analysis);
                    }
                    Err(error) => results.lock().unwrap().1.push(Failure {
                        component: package.component.clone(),
                        path: package.path.clone(),
                        error,
                    }),
                }
            });
        }
    });
    results.into_inner().unwrap()
}

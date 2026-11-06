//! Pointer-dispatch stage proof. Reservations here are synthetic test resources,
//! not permission for a production composer to overwrite those image locations.
#![cfg(feature = "image")]
use pioneer_optical::filters::phase::bundle::waveforms::resources::{
    dispatch_bridge, pointer_bridge,
};

#[test]
#[ignore = "requires PIONEER_POINTER_SOURCE, PIONEER_POINTER_TARGET, PIONEER_POINTER_KERNEL decoded native images"]
fn native_pointer_dispatch_binds_resources_and_command_arguments() {
    let read = |name| std::fs::read(std::env::var(name).unwrap()).unwrap();
    let donor = read("PIONEER_POINTER_SOURCE");
    let mut target = read("PIONEER_POINTER_TARGET");
    let kernel = read("PIONEER_POINTER_KERNEL");
    let source = dispatch_bridge::observe(&donor).unwrap();
    let destination = dispatch_bridge::observe(&target).unwrap();
    let tables = pointer_bridge::tables(&donor).unwrap();
    let mapping: Vec<_> = tables
        .iter()
        .enumerate()
        .map(|(i, a)| (*a, 0x418000 + i as u32 * 256))
        .collect();
    for (from, to) in &mapping {
        let a = (*from - 0x410000) as usize;
        let b = (*to - 0x410000) as usize;
        target[b..b + 256].copy_from_slice(&donor[a..a + 256]);
    }
    let graph =
        pioneer_optical::filters::phase::bundle::waveforms::resources::observe(&donor).unwrap();
    let cells = [0x418800, 0x418804];
    for (i, cell) in cells.iter().enumerate() {
        let original = 0x410000 + graph.selected.motion[i].start as u32;
        let mapped = mapping.iter().find(|(a, _)| *a == original).unwrap().1;
        let at = (*cell - 0x410000) as usize;
        target[at..at + 4].copy_from_slice(&mapped.to_be_bytes());
    }
    let plan = pointer_bridge::plan(&target, &donor, &kernel, &mapping, cells).unwrap();
    assert_eq!(plan.dispatch.len(), source.dispatch.len());
    assert_eq!(plan.selector.len(), source.selector.len());
    assert_eq!(plan.arguments.len(), 3);
    assert_eq!(
        (
            plan.required_words[0].parameter,
            plan.required_words[0].value
        ),
        (0x28f, 1)
    );
    for (range, bytes) in &plan.arguments {
        assert!(destination.callers[0]
            .iter()
            .any(|call| call.start == range.end));
        assert_eq!(bytes, &[0, 0, 0x6e, 0x30, 0, 4, 0x18, 0x88]);
    }
    let mut bad = target.clone();
    bad[0x8800] ^= 1;
    assert_eq!(
        pointer_bridge::plan(&bad, &donor, &kernel, &mapping, cells),
        Err(pointer_bridge::Failure::Resources)
    );
    let mut bad = target.clone();
    bad[0x8000] ^= 1;
    assert_eq!(
        pointer_bridge::plan(&bad, &donor, &kernel, &mapping, cells),
        Err(pointer_bridge::Failure::Resources)
    );
    let mut bad = target.clone();
    let entry = 0x410000 + plan.arguments[0].0.start as u32;
    bad[0x8900..0x8904].copy_from_slice(&entry.to_be_bytes());
    assert_eq!(
        pointer_bridge::plan(&bad, &donor, &kernel, &mapping, cells),
        Err(pointer_bridge::Failure::References)
    );
    let prepared = prepare(&donor, &target, &kernel);
    prove_native_trace(&donor, &prepared);
    prove_native_commands(&donor, &prepared);
}

#[path = "support/pointer_dispatch_execution.rs"]
mod execution;
use execution::{Machine, Program, BASE, OBJECT};
use pioneer_optical::{
    filters::phase::{bundle::waveforms::resources, native},
    image::layout::Observation,
};
use std::collections::BTreeSet;

fn sparse_fixture(role: &str) -> Vec<u8> {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-pointer-dispatch.json")).unwrap();
    let record = fixtures
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["role"] == role)
        .unwrap();
    let mut image = vec![255; record["size"].as_u64().unwrap() as usize];
    let mut apply = |record: &serde_json::Value| {
        for span in record["spans"].as_array().unwrap() {
            let start = span[0].as_u64().unwrap() as usize;
            let bytes = span[1].as_str().unwrap();
            for i in 0..bytes.len() / 2 {
                image[start + i] = u8::from_str_radix(&bytes[i * 2..i * 2 + 2], 16).unwrap();
            }
        }
    };
    if record["base_fixture"] == "phase-native-spans.json" {
        let base: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/phase-native-spans.json")).unwrap();
        apply(
            base.as_array()
                .unwrap()
                .iter()
                .find(|f| f["original_sha256"] == record["original_sha256"])
                .unwrap(),
        );
    }
    apply(record);
    image
}
struct Prepared {
    image: Vec<u8>,
    plan: pointer_bridge::Plan,
    mapping: Vec<(u32, u32)>,
    cells: [u32; 2],
    source: dispatch_bridge::Binding,
    destination: dispatch_bridge::Binding,
}
fn prepare(source: &[u8], target: &[u8], kernel: &[u8]) -> Prepared {
    let source_binding = dispatch_bridge::observe(source).unwrap();
    let destination = dispatch_bridge::observe(target).unwrap();
    let graph = resources::observe(source).unwrap();
    let mapping: Vec<_> = pointer_bridge::tables(source)
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(i, address)| (address, 0x418000 + i as u32 * 256))
        .collect();
    let mut image = target.to_vec();
    for &(from, to) in &mapping {
        image[(to - BASE) as usize..(to - BASE) as usize + 256]
            .copy_from_slice(&source[(from - BASE) as usize..(from - BASE) as usize + 256]);
    }
    let cells = [0x418800, 0x418804];
    for (index, cell) in cells.iter().enumerate() {
        let from = BASE + graph.selected.motion[index].start as u32;
        let to = mapping.iter().find(|(a, _)| *a == from).unwrap().1;
        image[(*cell - BASE) as usize..(*cell - BASE) as usize + 4]
            .copy_from_slice(&to.to_be_bytes());
    }
    let plan = pointer_bridge::plan(&image, source, kernel, &mapping, cells).unwrap();
    assert_eq!(plan.required_words.len(), 1);
    assert_eq!(
        (
            plan.required_words[0].parameter,
            plan.required_words[0].value
        ),
        (0x28f, 1)
    );
    Prepared {
        image,
        plan,
        mapping,
        cells,
        source: source_binding,
        destination,
    }
}
fn coil_entries(image: &[u8]) -> [u32; 2] {
    let Observation::Known(pair) = native::discover_pair(image) else {
        panic!("native coils missing")
    };
    pair.functions.map(|at| BASE + at as u32)
}
fn source_program<'a>(source: &'a [u8], p: &Prepared) -> (Program<'a>, Machine) {
    let mut code = Program::new(
        source,
        coil_entries(source),
        p.mapping.iter().map(|(a, _)| (*a, *a)).collect(),
    );
    for range in [&p.source.dispatch, &p.source.selector] {
        code.add(BASE + range.start as u32, &source[range.clone()]);
    }
    let graph = resources::observe(source).unwrap();
    let init = graph.initializer.unwrap();
    code.add(BASE + init.start as u32, &source[init.clone()]);
    code.reader = Some(u32::from_be_bytes([
        0,
        source[init.start + 5],
        source[init.start + 6],
        source[init.start + 7],
    ]));
    let mut initial = Machine::new();
    initial.run(&code, BASE + init.start as u32, None, &mut BTreeSet::new());
    assert_eq!(initial.parameter_reads, [0x28f]);
    assert_eq!(initial.writes.len(), 4);
    let expected = [
        &graph.selected.motion[0],
        &graph.selected.motion[1],
        &graph.selected.coefficients[0],
        &graph.selected.coefficients[1],
    ];
    for ((_, size, value), range) in initial.writes.iter().zip(expected) {
        assert_eq!(*size, 4);
        assert_eq!(*value, BASE + range.start as u32);
    }
    // The opposite initializer branch is real native behavior and differs; the
    // stage's read-only prerequisite is essential, not a nominal annotation.
    let mut erased = Machine::new();
    erased.word = 0xffff;
    erased.run(&code, BASE + init.start as u32, None, &mut BTreeSet::new());
    let erased_graph = graph.erased_parameter.unwrap();
    assert_eq!(
        erased.writes[0].2,
        BASE + erased_graph.motion[0].start as u32
    );
    assert_ne!(erased.writes[0].2, initial.writes[0].2);
    let mut memory = Machine::new();
    memory.ram = initial.ram;
    (code, memory)
}
const EMITTED_DISPATCH: u32 = 0x419000;
const EMITTED_SELECTOR: u32 = 0x419100;
fn emitted_program<'a>(p: &'a Prepared) -> Program<'a> {
    let mut code = Program::new(
        &p.image,
        coil_entries(&p.image),
        p.mapping.iter().map(|(a, b)| (*b, *a)).collect(),
    );
    code.add(EMITTED_DISPATCH, &p.plan.dispatch);
    code.add(EMITTED_SELECTOR, &p.plan.selector);
    code.readonly = p.cells.iter().map(|a| *a..*a + 4).collect();
    code
}
#[derive(Debug, PartialEq, Eq)]
struct Trace {
    calls: Vec<execution::CoilCall>,
    writes: Vec<(usize, usize, u32)>,
    returned: u8,
    preserved: [u32; 5],
}
fn trace(
    code: &Program<'_>,
    initial: &Machine,
    entries: [u32; 2],
    state: [u32; 3],
    input: [u8; 4],
    edges: &mut BTreeSet<(u32, bool)>,
) -> Trace {
    let [row, mode, step, argument] = input;
    let mut machine = initial.clone();
    machine.put(state[0], 1, u32::from(step));
    machine.put(state[1], 1, 0xa5);
    machine.put(state[2], 4, 0xdead_beef);
    machine.r[0] = u32::from(mode);
    machine.run(code, entries[1], None, edges);
    machine.r[0] = (u32::from(row) << 8) | u32::from(argument);
    machine.run(code, entries[0], None, edges);
    assert_eq!(machine.row(), row & 63);
    assert_eq!(machine.calls.len(), 2);
    let writes = machine
        .writes
        .iter()
        .map(|(a, size, value)| {
            let role = state
                .iter()
                .position(|p| p == a)
                .expect("only declared state may be written");
            assert!(role == 1 || role == 2);
            (
                role,
                *size,
                if role == 2 { code.role(*value) } else { *value },
            )
        })
        .collect();
    Trace {
        calls: machine.calls.clone(),
        writes,
        returned: machine.row(),
        preserved: machine.r[3..].try_into().unwrap(),
    }
}
fn prove_native_trace(source: &[u8], p: &Prepared) {
    let (original, initial) = source_program(source, p);
    let emitted = emitted_program(p);
    let native_entries = [
        BASE + p.source.dispatch.start as u32,
        BASE + p.source.selector.start as u32,
    ];
    let emitted_entries = [EMITTED_DISPATCH, EMITTED_SELECTOR];
    let mut original_edges = BTreeSet::new();
    let mut emitted_edges = BTreeSet::new();
    // Exact partitions of both native programs: selector distinguishes1/3/4;
    // pointer dispatch also distinguishes0/2. Step distinguishes0/1/2; argument
    // only zero/nonzero. Extreme representatives catch byte signedness errors.
    for row in 0..=255 {
        for mode in [0, 1, 2, 3, 4, 5, 255] {
            for step in [0, 1, 2, 3, 255] {
                for argument in [0, 1, 255] {
                    let input = [row, mode, step, argument];
                    assert_eq!(
                        trace(
                            &original,
                            &initial,
                            native_entries,
                            p.source.state,
                            input,
                            &mut original_edges
                        ),
                        trace(
                            &emitted,
                            &Machine::new(),
                            emitted_entries,
                            p.destination.state,
                            input,
                            &mut emitted_edges
                        ),
                        "input {input:?}"
                    );
                }
            }
        }
    }
    original.all_conditional_edges_seen(
        &original_edges,
        &[
            native_entries[0]..native_entries[0] + p.source.dispatch.len() as u32,
            native_entries[1]..native_entries[1] + p.source.selector.len() as u32,
        ],
    );
    emitted.all_conditional_edges_seen(
        &emitted_edges,
        &[
            EMITTED_DISPATCH..EMITTED_DISPATCH + p.plan.dispatch.len() as u32,
            EMITTED_SELECTOR..EMITTED_SELECTOR + p.plan.selector.len() as u32,
        ],
    );
    // A wrong pointer-cell role is syntactically valid native code, but must
    // fail the execution comparison; this is not just a template equality test.
    let mut bad = p.plan.dispatch.clone();
    bad[40..44].copy_from_slice(&p.cells[1].to_be_bytes());
    let mut changed = Program::new(
        &p.image,
        coil_entries(&p.image),
        p.mapping.iter().map(|(a, b)| (*b, *a)).collect(),
    );
    changed.add(EMITTED_DISPATCH, &bad);
    changed.add(EMITTED_SELECTOR, &p.plan.selector);
    assert_ne!(
        trace(
            &original,
            &initial,
            native_entries,
            p.source.state,
            [7, 0, 0, 0],
            &mut BTreeSet::new()
        ),
        trace(
            &changed,
            &Machine::new(),
            emitted_entries,
            p.destination.state,
            [7, 0, 0, 0],
            &mut BTreeSet::new()
        )
    );
}
#[test]
fn sparse_native_pointer_stage_preserves_complete_call_trace() {
    let source = sparse_fixture("source");
    let target = sparse_fixture("target");
    // Sparse CI fixture tests a stage only. This synthetic Kernel has no inbound
    // references; the ignored actual-image test retains the real paired Kernel.
    let kernel = vec![255; pioneer_optical::image::KERNEL_LEN];
    let p = prepare(&source, &target, &kernel);
    prove_native_trace(&source, &p);
}
#[test]
fn sparse_command_preparations_ignore_every_object_byte_five() {
    let source = sparse_fixture("source");
    let target = sparse_fixture("target");
    let p = prepare(
        &source,
        &target,
        &vec![255; pioneer_optical::image::KERNEL_LEN],
    );
    prove_native_commands(&source, &p);
}

fn prove_native_commands(source: &[u8], p: &Prepared) {
    let native_calls: Vec<_> = p.source.callers[0]
        .iter()
        .filter(|c| source[..c.start].ends_with(&[0x6e, 0x30, 0, 4, 0x18, 0x88]))
        .collect();
    assert_eq!(native_calls.len(), 3);
    assert_eq!(p.plan.arguments.len(), 3);
    for (native, (span, bytes)) in native_calls.iter().zip(&p.plan.arguments) {
        let a = BASE + native.start as u32 - 6;
        let b = BASE + span.start as u32;
        let mut old = Program::new(source, [0; 2], vec![]);
        old.add(a, &source[native.start - 6..native.start]);
        let mut new = Program::new(&p.image, [0; 2], vec![]);
        new.add(b, bytes);
        for row in 0..=255 {
            for unrelated in 0..=255 {
                let mut original = Machine::new();
                original.r[3] = OBJECT;
                original.put(OBJECT + 4, 1, row);
                original.put(OBJECT + 5, 1, unrelated);
                let mut emitted = original.clone();
                original.run(&old, a, Some(a + 6), &mut BTreeSet::new());
                emitted.run(&new, b, Some(b + bytes.len() as u32), &mut BTreeSet::new());
                assert_eq!(emitted.r, original.r);
                assert_eq!(emitted.r[0] & 65535, row << 8);
                assert!(original.writes.is_empty() && emitted.writes.is_empty());
            }
        }
    }
}

#[test]
fn immutable_pointer_resources_rebind_without_an_initializer_contract() {
    use pioneer_optical::filters::phase::bundle::waveforms::loader::{self, Table};
    let source = sparse_fixture("source");
    let native = resources::observe(&source).unwrap();
    let dispatcher = dispatch_bridge::observe(&source).unwrap();
    let loader = loader::observe(&source).unwrap();
    let Some([Table::Pointer(a), Table::Pointer(b)]) = loader.tables else {
        panic!()
    };
    let mut materialized = source.clone();
    let cells = [0x418800u32, 0x418804, 0x418808, 0x41880c];
    for (cell, span) in cells.iter().zip(
        native
            .selected
            .motion
            .iter()
            .chain(&native.selected.coefficients),
    ) {
        let at = (*cell - BASE) as usize;
        materialized[at..at + 4].copy_from_slice(&(BASE + span.start as u32).to_be_bytes());
    }
    for (field, cell) in [
        (40, cells[0]),
        (54, cells[0]),
        (124, cells[1]),
        (138, cells[1]),
    ] {
        let at = dispatcher.dispatch.start + field;
        materialized[at..at + 4].copy_from_slice(&cell.to_be_bytes());
    }
    for (from, to) in [(a, cells[2]), (b, cells[3])] {
        let matches: Vec<_> = source[loader.program.clone()]
            .windows(4)
            .enumerate()
            .filter(|(_, bytes)| *bytes == from.to_be_bytes())
            .map(|(i, _)| loader.program.start + i)
            .collect();
        assert_eq!(matches.len(), 1);
        materialized[matches[0]..matches[0] + 4].copy_from_slice(&to.to_be_bytes());
    }
    let observed = resources::observe(&materialized).unwrap();
    assert_eq!(observed.selected, native.selected);
    assert!(observed.initializer.is_none() && observed.erased_parameter.is_none());
    // Every byte of the old RAM initializer can disappear: the materialized
    // graph is proved from native consumers and actual ROM cells alone.
    materialized[native.initializer.unwrap()].fill(255);
    assert_eq!(resources::observe(&materialized).unwrap(), observed);
    let cell = (cells[0] - BASE) as usize;
    for target in [0x3120, BASE + dispatcher.dispatch.start as u32, cells[0]] {
        let mut bad = materialized.clone();
        bad[cell..cell + 4].copy_from_slice(&target.to_be_bytes());
        assert!(
            resources::observe(&bad).is_err(),
            "invalid sourceextent {target:x}"
        );
    }
    let mut alias = materialized.clone();
    for field in [40, 54] {
        alias[dispatcher.dispatch.start + field..dispatcher.dispatch.start + field + 4]
            .copy_from_slice(&cells[2].to_be_bytes());
    }
    assert!(
        resources::observe(&alias).is_err(),
        "motioncell must not alias coefficientcell"
    );
}

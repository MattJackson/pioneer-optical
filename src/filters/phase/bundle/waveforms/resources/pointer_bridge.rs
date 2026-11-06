//! Native pointer dispatch specialized to the installed non-erased table branch.
//! This emits a stage, not a complete mechanism operation or storage allocation.
use super::*;
use crate::filters::{phase::native::encoding, prerequisites::Word};

/// Required native graph, resource content, or external-entry proof is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Native source/target caller conventions do not match this adapter.
    Graph,
    /// The mapped image tables or immutable pointer cells are not exact.
    Resources,
    /// Another visible entry reaches a replaced instruction or routine.
    References,
    /// A typed instruction could not be emitted.
    Encoding,
}

/// Complete emitted bodies and exact caller argument edits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Native dispatcher, retaining its original instruction lengths/branches.
    pub dispatch: Vec<u8>,
    /// Native selector, using the target's existing state coordinates.
    pub selector: Vec<u8>,
    /// Three complete command argument preparations; caller JSRs are separate.
    pub arguments: Vec<(Range<usize>, Vec<u8>)>,
    /// Existing words required before transfer; never writes.
    pub required_words: Vec<Word>,
}

/// Actual image table resources used by the pointer dispatcher and selector.
/// The two native RAM cells resolve only through the complete initializer.
pub fn tables(donor: &[u8]) -> Result<Vec<u32>, Failure> {
    let source = dispatch_bridge::observe(donor).map_err(|_| Failure::Graph)?;
    let graph = observe(donor).map_err(|_| Failure::Graph)?;
    if source.kind != dispatch_bridge::Kind::Pointer
        || source.argument != dispatch_bridge::Argument::Zero
        || graph.dispatch != source.dispatch
        || graph.initializer.is_none()
        || graph.erased_parameter.is_none()
    {
        return Err(Failure::Graph);
    }
    let body = &donor[source.dispatch];
    let cells = [word(body, 40), word(body, 124)];
    let mut result = Vec::new();
    for address in source.tables {
        let actual = match cells.iter().position(|a| *a == address) {
            Some(index) => 0x410000 + graph.selected.motion[index].start as u32,
            None => address,
        };
        table(donor, actual, 256).map_err(|_| Failure::Resources)?;
        if !result.contains(&actual) {
            result.push(actual);
        }
    }
    Ok(result)
}

/// Emit the source pointer graph using already populated, explicitly owned
/// target image tables/cells. The composer still owns code placement, all caller
/// retargeting, coefficients, calibration, DSP coherence, and final verification.
pub fn plan(
    target: &[u8],
    donor: &[u8],
    kernel: &[u8],
    resources: &[(u32, u32)],
    cells: [u32; 2],
) -> Result<Plan, Failure> {
    let source = dispatch_bridge::observe(donor).map_err(|_| Failure::Graph)?;
    let destination = dispatch_bridge::observe(target).map_err(|_| Failure::Graph)?;
    let graph = observe(donor).map_err(|_| Failure::Graph)?;
    let required = tables(donor)?;
    if destination.kind != dispatch_bridge::Kind::Software
        || destination.argument != dispatch_bridge::Argument::StateByte
        || source.selector.len() != shapes::SOFTWARE_ROM_SELECTOR.len()
        || resources.len() != required.len()
    {
        return Err(Failure::Graph);
    }
    let mapped = |address| {
        let mut values = resources.iter().filter(|(from, _)| *from == address);
        let value = values.next().ok_or(Failure::Resources)?.1;
        if values.next().is_some() {
            return Err(Failure::Resources);
        }
        Ok(value)
    };
    let mut protected = Vec::new();
    for from in required {
        let to = mapped(from)?;
        let old = table(donor, from, 256).map_err(|_| Failure::Resources)?;
        let new = table(target, to, 256).map_err(|_| Failure::Resources)?;
        if donor[old] != target[new.clone()] {
            return Err(Failure::Resources);
        }
        protected.push(new);
    }
    for (index, cell) in cells.into_iter().enumerate() {
        let span = table(target, cell, 4).map_err(|_| Failure::Resources)?;
        let value = mapped(0x410000 + graph.selected.motion[index].start as u32)?;
        if word(target, span.start) != value
            || protected
                .iter()
                .any(|r| r.start < span.end && span.start < r.end)
        {
            return Err(Failure::Resources);
        }
        protected.push(span);
    }
    let mut arguments = Vec::new();
    for call in &destination.callers[0] {
        let Some(start) = call.start.checked_sub(8) else {
            return Err(Failure::Graph);
        };
        if target[start..call.start] == [0x6e, 0x38, 0, 5, 0x6e, 0x30, 0, 4] {
            // The source's full six-byte preparation, preceded by one NOP.
            // R0H reads the same object byte; R0L is explicitly zero.
            let mut body = alloc::vec![0; 8];
            encoding::nops(&mut body[..2]).ok_or(Failure::Encoding)?;
            body[2..].copy_from_slice(&[0x6e, 0x30, 0, 4, 0x18, 0x88]);
            typed(&body)?;
            arguments.push((start..call.start, body));
        }
    }
    if arguments.len() != 3 {
        return Err(Failure::Graph);
    }
    let mut retired = alloc::vec![destination.dispatch.clone(), destination.selector.clone()];
    retired.extend(arguments.iter().map(|(r, _)| r.clone()));
    let mut replaced = retired.clone();
    replaced.extend(destination.callers.iter().flatten().cloned());
    if protected
        .iter()
        .any(|p| replaced.iter().any(|r| p.start < r.end && r.start < p.end))
    {
        return Err(Failure::Resources);
    }
    retirement::references_clear(
        target,
        kernel,
        &retired,
        &replaced,
        &[destination.dispatch.clone(), destination.selector.clone()],
    )
    .ok_or(Failure::References)?;
    let mut dispatch = donor[source.dispatch.clone()].to_vec();
    let mut selector = donor[source.selector.clone()].to_vec();
    for (field, index) in [(10, 0), (22, 1), (100, 2), (164, 2)] {
        encoding::retarget_field(&mut dispatch, field, 4, destination.state[index])
            .ok_or(Failure::Encoding)?;
    }
    for (field, cell) in [
        (40, cells[0]),
        (54, cells[0]),
        (124, cells[1]),
        (138, cells[1]),
    ] {
        encoding::retarget_field(&mut dispatch, field, 4, cell).ok_or(Failure::Encoding)?;
    }
    let ordinary = mapped(word(&dispatch, 78))?;
    encoding::retarget_field(&mut dispatch, 78, 4, ordinary).ok_or(Failure::Encoding)?;
    let Observation::Known(from_coils) = native::discover_pair(donor) else {
        return Err(Failure::Graph);
    };
    let Observation::Known(to_coils) = native::discover_pair(target) else {
        return Err(Failure::Graph);
    };
    for field in [47, 87, 111, 131, 173, 197] {
        let callee = bundle::resolve_call(donor, call(&dispatch, field)).ok_or(Failure::Graph)?;
        let channel = from_coils
            .functions
            .iter()
            .position(|at| *at == callee)
            .ok_or(Failure::Graph)?;
        encoding::retarget_field(
            &mut dispatch,
            field,
            3,
            0x410000 + to_coils.functions[channel] as u32,
        )
        .ok_or(Failure::Encoding)?;
    }
    encoding::retarget_field(&mut selector, 2, 4, destination.state[1]).ok_or(Failure::Encoding)?;
    for field in [20, 28, 36] {
        let value = mapped(word(&selector, field))?;
        encoding::retarget_field(&mut selector, field, 4, value).ok_or(Failure::Encoding)?;
    }
    encoding::retarget_field(&mut selector, 44, 4, destination.state[2])
        .ok_or(Failure::Encoding)?;
    typed(&dispatch)?;
    typed(&selector)?;
    Ok(Plan {
        dispatch,
        selector,
        arguments,
        required_words: alloc::vec![Word {
            parameter: 0x28f,
            value: 1
        }],
    })
}

fn typed(bytes: &[u8]) -> Result<(), Failure> {
    use h8_asm::{
        isa::{decode_insn, encode_insn},
        Mode, Target,
    };
    let mut at = 0;
    while at < bytes.len() {
        let d = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced)
            .map_err(|_| Failure::Encoding)?;
        if encode_insn(d.insn, Target::H8S2000, Mode::Advanced).map_err(|_| Failure::Encoding)?
            != bytes[at..at + d.len]
        {
            return Err(Failure::Encoding);
        }
        at += d.len;
    }
    Ok(())
}

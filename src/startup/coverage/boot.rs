//! Native Normal startup boundary binding. The witnesses describe decoded local
//! control flow and retain every call-return assumption explicitly. In particular,
//! a Kernel tail transfer is not a proof of scheduler or host READY behavior.
use crate::image::layout::{Observation, Unresolved};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use h8_asm::{
    isa::{decode_insn, Ea, Operand as O, Reg as R},
    Mode, Target,
};
const BASE: u32 = 0x410000;

/// Complete native body with relocation operands represented as typed values.
pub(super) struct Shape {
    pub bytes: &'static [u8],
    pub holes: &'static [(usize, usize)],
}
/// A transfer target whose callee semantics have not been established here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetAddress {
    /// External Kernel service. Normal bytes cannot establish its behavior.
    Kernel(u32),
    /// Stored or expanded Normal address; this alone proves no callee contract.
    Normal(u32),
    /// CPU address outside the Kernel and Normal address ranges.
    External(u32),
    /// Register-indirect target without a preceding immediate target load.
    IndirectRegister(u8),
}
/// An unproven obligation on a native call or tail transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dependency {
    /// Decoded Normal instruction offset.
    pub offset: usize,
    /// Native target, retaining unknown indirect targets.
    pub target: TargetAddress,
    /// A tail target must eventually return to the original caller for that
    /// caller's continuation to execute. Such a return is not proven here.
    pub tail_transfer: bool,
}
/// Literal data operands in a bound body, never silently treated as code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataOperand {
    /// A long immediate, with its destination register if applicable.
    LongImmediate {
        /// Decoded Normal instruction offset.
        offset: usize,
        /// Encoded immediate value.
        value: u32,
        /// Destination extended register, if present.
        register: Option<u8>,
    },
    /// Absolute data address.
    Absolute {
        /// Decoded Normal instruction offset.
        offset: usize,
        /// Encoded CPU data address.
        address: u32,
    },
    /// Displacement data address; the base register remains part of the shape.
    Displacement {
        /// Decoded Normal instruction offset.
        offset: usize,
        /// Encoded displacement value, before addition of the base register.
        address: u32,
    },
}
/// The actual boundary of a full native body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Boundary {
    /// A decoded native RTS.
    Return(usize),
    /// A decoded terminal JMP whose external callee remains opaque.
    Tail(Dependency),
}
/// Complete matching body, including all branch operands and native terminator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    /// Decoded Normal entry offset.
    pub start: usize,
    /// Exclusive end offset, including the terminator.
    pub end: usize,
    /// Actual native return or external tail transfer.
    pub boundary: Boundary,
    /// Every call in the complete body, plus an external terminal tail transfer.
    pub dependencies: Vec<Dependency>,
    /// Actual relocated data operands. No data address is an absence proof.
    pub data: Vec<DataOperand>,
}
/// One local control-flow edge in a conservative path witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Edge {
    /// Ordinary instruction continuation.
    Next {
        /// Instruction before the edge.
        from: usize,
        /// Next instruction boundary.
        to: usize,
    },
    /// A possible conditional or unconditional branch edge; flag feasibility is
    /// not claimed, because both conditional outcomes are explored.
    Branch {
        /// Branch instruction.
        from: usize,
        /// Chosen target instruction boundary.
        to: usize,
    },
    /// Continuation exists only if the target returns. This is an obligation,
    /// including for callees whose entry is bound elsewhere in the chain.
    IfCallReturns {
        /// Unproven return obligation on the called target.
        dependency: Dependency,
        /// Instruction executed only after that call returns.
        to: usize,
    },
}
/// A graph path through instruction boundaries, conditional on its call returns
/// and branch choices. It is neither an execution trace nor an acceptance proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Continuation {
    /// First instruction boundary.
    pub from: usize,
    /// Last instruction boundary.
    pub to: usize,
    /// Ordered native edges.
    pub edges: Vec<Edge>,
}
/// Native Normal vector through the dispatcher boundary, tied to one proven
/// cache. An opaque Normal tail target does not establish a Kernel handoff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootChain {
    /// Normal's actual absolute JMP at offset 0x2000.
    pub vector: usize,
    /// Complete saved-register C startup body.
    pub c_startup: Function,
    /// C startup's final direct JSR, which targets this dispatcher.
    pub dispatch_call: usize,
    /// Exact 32-byte dispatcher, ending in an opaque native tail transfer.
    pub dispatcher: Function,
    /// Complete hardware initializer body ending at a decoded RTS.
    pub hardware_init: Function,
    /// Hardware initializer's exact call to the initializer below.
    pub cache_init_call: usize,
    /// Complete initializer, including its post-bulk continuation and terminator.
    pub cache_initializer: Function,
    /// Initializer's call into the bulk wrapper below.
    pub bulk_wrapper_call: usize,
    /// Complete bulk wrapper, including any tail-return dependency.
    pub bulk_wrapper: Function,
    /// Wrapper's exact call to the complete bulk reader below.
    pub bulk_reader_call: usize,
    /// Complete bulk reader, including preceding loops and decoded restore/RTS.
    pub bulk_reader: Function,
    /// Loop bound independently by the getter/cache native contract.
    pub bulk_loop: usize,
    /// RAM destination established by that cache contract.
    pub cache_ram: u32,
    /// Local paths to the linked calls, and from those calls' return addresses
    /// to actual native terminators. Every opaque return remains explicit.
    pub continuations: Vec<Continuation>,
    /// Three dispatcher calls in instruction order. Actual Kernel services and
    /// opaque Normal targets retain their distinct target classifications.
    pub dispatcher_calls: [Dependency; 3],
    /// Actual terminal dispatcher jump. An opaque Normal target does not prove
    /// that this transfer reaches Kernel code or that its target returns.
    pub dispatch_handoff: Dependency,
}
fn classify(address: u32, normal_len: usize) -> TargetAddress {
    if (0x400000..BASE).contains(&address) {
        TargetAddress::Kernel(address)
    } else if address
        .checked_sub(BASE)
        .is_some_and(|n| (n as usize) < normal_len)
    {
        TargetAddress::Normal(address)
    } else {
        TargetAddress::External(address)
    }
}
struct Code<'a> {
    normal: &'a [u8],
    stored: Vec<(usize, usize)>,
}
impl<'a> Code<'a> {
    fn contains(&self, start: usize, end: usize) -> bool {
        start & 1 == 0 && start < end && self.stored.iter().any(|&(a, z)| start >= a && end <= z)
    }
    fn offset(&self, address: u32) -> Option<usize> {
        let at = address.checked_sub(BASE)? as usize;
        (at < self.normal.len() && at & 1 == 0).then_some(at)
    }
    fn body(&self, start: usize, shapes: &[Shape]) -> Option<Body> {
        shapes.iter().find_map(|shape| {
            let end = start.checked_add(shape.bytes.len())?;
            let bytes = self.normal.get(start..end)?;
            if !self.contains(start, end)
                || !bytes
                    .iter()
                    .zip(shape.bytes)
                    .enumerate()
                    .all(|(i, (a, b))| {
                        shape
                            .holes
                            .iter()
                            .any(|&(at, len)| (at..at + len).contains(&i))
                            || a == b
                    })
            {
                return None;
            }
            decode(self, start, end)
        })
    }
}
#[derive(Clone)]
struct Instruction {
    at: usize,
    next: usize,
    op: &'static str,
    operands: [O; 3],
}
struct Body {
    function: Function,
    instructions: Vec<Instruction>,
}
impl Body {
    fn calls(&self) -> impl Iterator<Item = (usize, u32)> + '_ {
        self.instructions
            .iter()
            .filter_map(|i| match (i.op, i.operands[0]) {
                ("JSR", O::Address(Ea::Absolute { value, .. })) => Some((i.at, value)),
                ("BSR", O::Address(Ea::PcRelative { value, .. })) => i
                    .next
                    .checked_add_signed(value as isize)
                    .and_then(|at| BASE.checked_add(u32::try_from(at).ok()?))
                    .map(|target| (i.at, target)),
                _ => None,
            })
    }
    fn terminator(&self) -> usize {
        self.instructions.last().expect("nonempty native body").at
    }
    fn path(&self, from: usize, to: usize) -> Option<Continuation> {
        let instructions: BTreeMap<_, _> = self.instructions.iter().map(|i| (i.at, i)).collect();
        let mut todo = alloc::vec![from];
        let mut seen = BTreeSet::new();
        let mut parents: BTreeMap<usize, (usize, Edge)> = BTreeMap::new();
        while let Some(at) = todo.pop() {
            if !seen.insert(at) {
                continue;
            }
            if at == to {
                let mut edges = Vec::new();
                let mut cursor = to;
                while cursor != from {
                    let (previous, edge) = parents.get(&cursor)?.clone();
                    edges.push(edge);
                    cursor = previous;
                }
                edges.reverse();
                return Some(Continuation { from, to, edges });
            }
            let ins = *instructions.get(&at)?;
            let mut successors = Vec::new();
            if branch(ins.op) {
                let O::Address(Ea::PcRelative { value, .. }) = ins.operands[0] else {
                    return None;
                };
                let target = ins.next.checked_add_signed(value as isize)?;
                successors.push((
                    target,
                    Edge::Branch {
                        from: at,
                        to: target,
                    },
                ));
                if ins.op != "BRA" {
                    successors.push((
                        ins.next,
                        Edge::Next {
                            from: at,
                            to: ins.next,
                        },
                    ));
                }
            } else if matches!(ins.op, "JSR" | "BSR") {
                let dependency = self
                    .function
                    .dependencies
                    .iter()
                    .find(|d| d.offset == at)?
                    .clone();
                successors.push((
                    ins.next,
                    Edge::IfCallReturns {
                        dependency,
                        to: ins.next,
                    },
                ));
            } else if ins.op == "JMP" {
                let O::Address(Ea::Absolute { value, .. }) = ins.operands[0] else {
                    return None;
                };
                if let Some(target) = value
                    .checked_sub(BASE)
                    .map(|n| n as usize)
                    .filter(|n| instructions.contains_key(n))
                {
                    successors.push((
                        target,
                        Edge::Branch {
                            from: at,
                            to: target,
                        },
                    ));
                }
            } else if ins.op != "RTS" {
                successors.push((
                    ins.next,
                    Edge::Next {
                        from: at,
                        to: ins.next,
                    },
                ));
            }
            for (next, edge) in successors {
                if instructions.contains_key(&next)
                    && !seen.contains(&next)
                    && !parents.contains_key(&next)
                {
                    parents.insert(next, (at, edge));
                    todo.push(next);
                }
            }
        }
        None
    }
}
fn branch(op: &str) -> bool {
    matches!(
        op,
        "BRA"
            | "BEQ"
            | "BNE"
            | "BHI"
            | "BLS"
            | "BCC"
            | "BCS"
            | "BGE"
            | "BLT"
            | "BGT"
            | "BLE"
            | "BPL"
            | "BMI"
            | "BVC"
            | "BVS"
    )
}
fn decode(code: &Code<'_>, start: usize, end: usize) -> Option<Body> {
    let mut instructions = Vec::new();
    let mut dependencies = Vec::new();
    let mut data = Vec::new();
    let mut at = start;
    let mut previous: Option<Instruction> = None;
    while at < end {
        let decoded =
            decode_insn(code.normal.get(at..end)?, Target::H8S2000, Mode::Advanced).ok()?;
        if decoded.len == 0 {
            return None;
        }
        let next = at.checked_add(decoded.len)?;
        if next > end {
            return None;
        }
        let op = decoded.insn.mnemonic;
        let operands = decoded.insn.operands;
        let ins = Instruction {
            at,
            next,
            op,
            operands,
        };
        if matches!(op, "JSR" | "BSR" | "JMP") {
            let target = match operands[0] {
                O::Address(Ea::Absolute { value, .. }) => classify(value, code.normal.len()),
                O::Address(Ea::PcRelative { value, .. }) => classify(
                    BASE.checked_add(
                        u32::try_from(next.checked_add_signed(value as isize)?).ok()?,
                    )?,
                    code.normal.len(),
                ),
                O::Address(Ea::Indirect(R::Long(register))) => {
                    // Only an immediately preceding target load proves a value;
                    // no callee-saved register ABI is assumed across other calls.
                    match previous.as_ref().map(|i| (i.op, i.operands)) {
                        Some((
                            "MOV",
                            [O::Immediate { value, bits: 32 }, O::Register(R::Long(r)), O::None],
                        )) if r == register => classify(value, code.normal.len()),
                        _ => TargetAddress::IndirectRegister(register),
                    }
                }
                _ => return None,
            };
            dependencies.push(Dependency {
                offset: at,
                target,
                tail_transfer: op == "JMP",
            });
        } else {
            for operand in operands {
                match operand {
                    O::Immediate { value, bits: 32 } => data.push(DataOperand::LongImmediate {
                        offset: at,
                        value,
                        register: match operands[1] {
                            O::Register(R::Long(r)) => Some(r),
                            _ => None,
                        },
                    }),
                    O::Address(Ea::Absolute { value, .. }) => data.push(DataOperand::Absolute {
                        offset: at,
                        address: value,
                    }),
                    O::Address(Ea::Displacement {
                        value, bits: 32, ..
                    }) => data.push(DataOperand::Displacement {
                        offset: at,
                        address: value as u32,
                    }),
                    _ => {}
                }
            }
        }
        previous = Some(ins.clone());
        instructions.push(ins);
        at = next;
    }
    let last = instructions.last()?;
    let boundary = match last.op {
        "RTS" => Boundary::Return(last.at),
        "JMP" => Boundary::Tail(dependencies.last()?.clone()),
        _ => return None,
    };
    let boundaries: BTreeSet<_> = instructions.iter().map(|i| i.at).collect();
    for ins in &instructions {
        if branch(ins.op) {
            let O::Address(Ea::PcRelative { value, .. }) = ins.operands[0] else {
                return None;
            };
            if !boundaries.contains(&ins.next.checked_add_signed(value as isize)?) {
                return None;
            }
        }
        if ins.at != last.at {
            if ins.op == "RTS" {
                return None;
            }
            if ins.op == "JMP" {
                let O::Address(Ea::Absolute { value, .. }) = ins.operands[0] else {
                    return None;
                };
                let target = code.offset(value)?;
                if !boundaries.contains(&target) {
                    return None;
                }
                // An absolute jump to a decoded boundary in this body is local
                // control flow, not a return obligation on an opaque callee.
                dependencies.retain(|dependency| dependency.offset != ins.at);
            }
        }
    }
    Some(Body {
        function: Function {
            start,
            end,
            boundary,
            dependencies,
            data,
        },
        instructions,
    })
}
/// Bind a complete native startup chain to the actual Normal vector and proven
/// bulk cache. A known result supplies local shape/CFG witnesses with explicit
/// external dependencies; it does not establish a complete no-009F certificate.
/// All compressed bytes are excluded from native entry and body matching.
pub fn bind(normal: &[u8]) -> Observation<BootChain> {
    let unknown = || Observation::Unresolved(Unresolved::ReaderNotRecognized);
    let caches = match super::cache::discover(normal) {
        Observation::Known(v) => v,
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    let Some(regions) = crate::image::regions(normal) else {
        return unknown();
    };
    let code = Code {
        normal,
        stored: regions
            .stored
            .iter()
            .map(|b| {
                let at = b.as_ptr() as usize - normal.as_ptr() as usize;
                (at, at + b.len())
            })
            .collect(),
    };
    if !code.contains(0x2000, 0x2004) {
        return unknown();
    }
    let Some([0x5a, a, b, c]) = normal.get(0x2000..0x2004) else {
        return unknown();
    };
    let Some(entry) = code.offset(u32::from_be_bytes([0, *a, *b, *c])) else {
        return unknown();
    };
    let Some(c_startup) = code.body(entry, super::boot_shapes::C_STARTUP) else {
        return unknown();
    };
    let Some((dispatch_call, dispatch_address)) = c_startup
        .calls()
        .filter(|(at, _)| normal[*at] == 0x5e)
        .last()
    else {
        return unknown();
    };
    let Some(dispatch_at) = code.offset(dispatch_address) else {
        return unknown();
    };
    let Some(dispatcher) = code.body(dispatch_at, super::boot_shapes::DISPATCH) else {
        return unknown();
    };
    // The hardware initializer is the second JSR. Other boundary targets may
    // be Kernel services or native Normal wrappers; their return/forwarding
    // behavior remains an explicit dependency, with no inferred Kernel role.
    let boundary: Vec<_> = dispatcher
        .function
        .dependencies
        .iter()
        .filter(|d| d.offset != dispatch_at + 4)
        .cloned()
        .collect();
    if boundary.len() != 4
        || boundary.iter().map(|d| d.offset).ne([
            dispatch_at,
            dispatch_at + 20,
            dispatch_at + 24,
            dispatch_at + 28,
        ])
        || boundary[..3].iter().any(|d| d.tail_transfer)
        || !boundary[3].tail_transfer
        || boundary.iter().any(|d| {
            !matches!(
                d.target,
                TargetAddress::Kernel(_) | TargetAddress::Normal(_)
            )
        })
    {
        return unknown();
    }
    let Some((_, init_address)) = dispatcher.calls().find(|(at, _)| *at == dispatch_at + 4) else {
        return unknown();
    };
    let Some(init_at) = code.offset(init_address) else {
        return unknown();
    };
    let Some(hardware) = code.body(init_at, super::boot_shapes::HARDWARE_INIT) else {
        return unknown();
    };
    let mut results = Vec::new();
    for cache in caches {
        let Some(reader) = [0x46usize, 0x50]
            .iter()
            .filter_map(|n| cache.offset.checked_sub(*n))
            .find_map(|at| code.body(at, super::boot_shapes::BULK_READER))
        else {
            continue;
        };
        if !reader.instructions.iter().any(|i| i.at == cache.offset)
            || cache.getter_call >= reader.function.end
        {
            continue;
        }
        for (cache_init_call, initializer_address) in hardware.calls() {
            let Some(initializer) = code
                .offset(initializer_address)
                .and_then(|at| code.body(at, super::boot_shapes::CACHE_INIT_WRAPPER))
            else {
                continue;
            };
            for (bulk_wrapper_call, wrapper_address) in initializer.calls() {
                let Some(wrapper) = code
                    .offset(wrapper_address)
                    .and_then(|at| code.body(at, super::boot_shapes::BULK_WRAPPER))
                else {
                    continue;
                };
                for (bulk_reader_call, reader_address) in wrapper
                    .calls()
                    .filter(|(_, target)| code.offset(*target) == Some(reader.function.start))
                {
                    let _ = reader_address;
                    let requests = [
                        (&c_startup, c_startup.function.start, dispatch_call),
                        (&dispatcher, dispatcher.function.start, dispatch_at + 4),
                        (&hardware, hardware.function.start, cache_init_call),
                        (&hardware, cache_init_call, hardware.terminator()),
                        (&initializer, initializer.function.start, bulk_wrapper_call),
                        (&initializer, bulk_wrapper_call, initializer.terminator()),
                        (&wrapper, wrapper.function.start, bulk_reader_call),
                        (&wrapper, bulk_reader_call, wrapper.terminator()),
                        (&reader, reader.function.start, cache.offset),
                        (&reader, cache.offset, reader.terminator()),
                        (&dispatcher, dispatch_at + 4, dispatcher.terminator()),
                    ];
                    let Some(continuations) = requests
                        .into_iter()
                        .map(|(body, from, to)| body.path(from, to))
                        .collect::<Option<Vec<_>>>()
                    else {
                        continue;
                    };
                    results.push(BootChain {
                        vector: 0x2000,
                        c_startup: c_startup.function.clone(),
                        dispatch_call,
                        dispatcher: dispatcher.function.clone(),
                        hardware_init: hardware.function.clone(),
                        cache_init_call,
                        cache_initializer: initializer.function.clone(),
                        bulk_wrapper_call,
                        bulk_wrapper: wrapper.function.clone(),
                        bulk_reader_call,
                        bulk_reader: reader.function.clone(),
                        bulk_loop: cache.offset,
                        cache_ram: cache.ram_base,
                        continuations,
                        dispatcher_calls: [
                            boundary[0].clone(),
                            boundary[1].clone(),
                            boundary[2].clone(),
                        ],
                        dispatch_handoff: boundary[3].clone(),
                    });
                }
            }
        }
    }
    match results.len() {
        0 => unknown(),
        1 => Observation::Known(results.remove(0)),
        _ => Observation::Conflicting,
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::boot_shapes as shapes;
    use super::*;
    fn put_address(normal: &mut [u8], at: usize, opcode: u8, target: u32) {
        normal[at] = opcode;
        normal[at + 1..at + 4].copy_from_slice(&target.to_be_bytes()[1..]);
    }
    fn install(normal: &mut [u8], at: usize, shape: &Shape) {
        normal[at..at + shape.bytes.len()].copy_from_slice(shape.bytes);
        for &(offset, len) in shape.holes {
            let value: u32 = if len == 3 {
                0x400100
            } else if len == 2 {
                0x100
            } else {
                0xa00000
            };
            normal[at + offset..at + offset + len].copy_from_slice(&value.to_be_bytes()[4 - len..]);
        }
    }
    pub(in super::super) fn fixture() -> Vec<u8> {
        let mut normal = alloc::vec![0xff;0x10000];
        crate::image::layout::install_test_layout(&mut normal, 0x1000);
        install(&mut normal, 0x3000, &shapes::C_STARTUP[0]);
        let startup = decode(
            &Code {
                normal: &normal,
                stored: alloc::vec![(0, normal.len())],
            },
            0x3000,
            0x3000 + shapes::C_STARTUP[0].bytes.len(),
        )
        .unwrap();
        let dispatch_call = startup
            .calls()
            .filter(|(at, _)| normal[*at] == 0x5e)
            .last()
            .unwrap()
            .0;
        put_address(&mut normal, dispatch_call, 0x5e, BASE + 0x4000);
        put_address(&mut normal, 0x2000, 0x5a, BASE + 0x3000);
        install(&mut normal, 0x4000, &shapes::DISPATCH[0]);
        put_address(&mut normal, 0x4004, 0x5e, BASE + 0x5000);
        install(&mut normal, 0x5000, &shapes::HARDWARE_INIT[0]);
        put_address(&mut normal, 0x50a2, 0x5e, BASE + 0x6000);
        install(&mut normal, 0x6000, &shapes::CACHE_INIT_WRAPPER[0]);
        // This native initializer's fixed BSR -92 at +18 selects entry -72.
        install(&mut normal, 0x5fb8, &shapes::BULK_WRAPPER[0]);
        put_address(&mut normal, 0x5fb8, 0x5e, BASE + 0x8000);
        install(&mut normal, 0x8000, &shapes::BULK_READER[0]);
        for &(offset, len) in shapes::BULK_READER[0].holes {
            if len == 3 {
                normal[0x8000 + offset..0x8000 + offset + 3]
                    .copy_from_slice(&(BASE + 0x1000).to_be_bytes()[1..]);
            }
        }
        normal
    }
    #[test]
    fn native_chain_retains_kernel_and_opaque_return_obligations() {
        let normal = fixture();
        let Observation::Known(chain) = bind(&normal) else {
            panic!("complete native fixture");
        };
        assert_eq!(chain.bulk_loop, 0x8046);
        assert_eq!(chain.bulk_reader.end, 0x8080);
        assert_eq!(chain.cache_ram, 0xa00000);
        assert!(matches!(
            chain.dispatch_handoff.target,
            TargetAddress::Kernel(0x400100)
        ));
        assert!(chain.dispatch_handoff.tail_transfer);
        assert!(matches!(chain.bulk_wrapper.boundary, Boundary::Tail(_)));
        assert!(chain
            .continuations
            .iter()
            .flat_map(|p| &p.edges)
            .any(|edge| matches!(
                edge,
                Edge::IfCallReturns {
                    dependency: Dependency {
                        target: TargetAddress::IndirectRegister(_),
                        ..
                    },
                    ..
                }
            )));
        assert!(chain
            .continuations
            .iter()
            .flat_map(|p| &p.edges)
            .any(|edge| matches!(
                edge,
                Edge::IfCallReturns {
                    dependency: Dependency { offset: 0x50a2, .. },
                    ..
                }
            )));
        assert!(chain
            .continuations
            .iter()
            .flat_map(|p| &p.edges)
            .any(|edge| matches!(edge, Edge::Branch { .. })));
    }
    #[test]
    fn two_complete_chains_conflict_instead_of_selecting_one() {
        let mut normal = fixture();
        assert!(matches!(bind(&normal), Observation::Known(_)));
        // The initializer's second call reaches another complete bulk wrapper
        // calling the same reader, so two rooted chains bind.
        install(&mut normal, 0x7000, &shapes::BULK_WRAPPER[0]);
        put_address(&mut normal, 0x7000, 0x5e, BASE + 0x8000);
        put_address(&mut normal, 0x6006, 0x5e, BASE + 0x7000);
        assert!(matches!(bind(&normal), Observation::Conflicting));
    }
    #[test]
    fn normal_dispatch_targets_remain_opaque_normal_dependencies() {
        let mut normal = fixture();
        for at in [0x4000, 0x4014, 0x4018, 0x401c] {
            let opcode = normal[at];
            put_address(&mut normal, at, opcode, BASE + 0x9000);
        }
        let Observation::Known(chain) = bind(&normal) else {
            panic!("native Normal boundary fixture");
        };
        assert!(chain
            .dispatcher_calls
            .iter()
            .all(|d| d.target == TargetAddress::Normal(BASE + 0x9000)));
        assert_eq!(
            chain.dispatch_handoff.target,
            TargetAddress::Normal(BASE + 0x9000)
        );
        assert!(chain.dispatch_handoff.tail_transfer);
    }
    #[test]
    fn mutations_of_native_roots_calls_branches_loops_and_returns_fail_closed() {
        let original = fixture();
        let Observation::Known(chain) = bind(&original) else {
            panic!("fixture");
        };
        let offsets = [
            0x2000,
            0x2003,
            0x3000,
            chain.dispatch_call + 3,
            0x4000,
            0x4007,
            0x4009,
            0x401c,
            0x5000,
            0x5035,
            0x50a5,
            chain.hardware_init.end - 1,
            0x6000,
            0x6013,
            0x6014,
            0x5fb8,
            0x5fbc,
            0x8000,
            0x801f,
            0x804f,
            0x8077,
            0x807f,
        ];
        for at in offsets {
            let mut mutated = original.clone();
            mutated[at] ^= 1;
            assert!(
                !matches!(bind(&mutated), Observation::Known(_)),
                "native mutation {at:x}"
            );
        }
        for end in [
            0x2003,
            chain.c_startup.end - 1,
            chain.hardware_init.end - 1,
            chain.bulk_reader.end - 1,
        ] {
            assert!(
                !matches!(bind(&original[..end]), Observation::Known(_)),
                "truncated {end:x}"
            );
        }
    }
    #[test]
    fn decoded_rts_and_branch_boundaries_cannot_be_supplied_by_operand_bytes() {
        let normal = [0x5e, 0x54, 0x70, 0x00, 0x54, 0x70];
        let code = Code {
            normal: &normal,
            stored: alloc::vec![(0, normal.len())],
        };
        let body = decode(&code, 0, 6).unwrap();
        assert_eq!(body.function.boundary, Boundary::Return(4));
        assert!(decode(&code, 0, 3).is_none());
        let bad = [0x47, 0x01, 0x79, 0x00, 0x00, 0x9f, 0x54, 0x70];
        assert!(decode(
            &Code {
                normal: &bad,
                stored: alloc::vec![(0, bad.len())]
            },
            0,
            bad.len()
        )
        .is_none());
    }
    #[test]
    fn internal_absolute_jump_is_local_cfg_and_requires_an_instruction_boundary() {
        let mut normal = [0x5a, 0x41, 0x00, 0x04, 0x54, 0x70];
        let code = Code {
            normal: &normal,
            stored: alloc::vec![(0, normal.len())],
        };
        let body = decode(&code, 0, normal.len()).unwrap();
        assert!(body.function.dependencies.is_empty());
        assert!(matches!(
            body.path(0, 4).unwrap().edges.as_slice(),
            [Edge::Branch { from: 0, to: 4 }]
        ));
        normal[3] = 5;
        assert!(decode(
            &Code {
                normal: &normal,
                stored: alloc::vec![(0, normal.len())]
            },
            0,
            normal.len()
        )
        .is_none());
    }
    /// Optional private evidence check. Run explicitly only after development
    /// signoff; normal tests require no firmware corpus or identity allowlist.
    #[test]
    #[ignore = "private native corpus; explicit post-development execution only"]
    fn private_native_startup_manifests_and_mutations() {
        let root = std::env::var_os("PIONEER_STARTUP_ROOTS").expect("startup-roots directory");
        let corpus = std::env::var_os("PIONEER_NORMAL_CORPUS").expect("decoded Normal directory");
        let mut checked = BTreeSet::new();
        for manifest in [
            "sat9/boot-chains.json",
            "boot-chains.json",
            "boot-chains-r1.json",
        ] {
            let bytes = std::fs::read(std::path::Path::new(&root).join(manifest)).unwrap();
            let data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            for row in data["images"].as_array().unwrap() {
                let component = row["component"].as_str().unwrap();
                if !checked.insert(component.to_owned()) {
                    continue;
                }
                let normal = std::fs::read(
                    std::path::Path::new(&corpus).join(alloc::format!("{component}.bin")),
                )
                .unwrap();
                let Observation::Known(chain) = bind(&normal) else {
                    panic!("native chain {component}");
                };
                for (key, actual) in [
                    ("c_startup", chain.c_startup.start),
                    ("dispatch", chain.dispatcher.start),
                    ("hardware_init", chain.hardware_init.start),
                    ("cache_init_wrapper", chain.cache_initializer.start),
                    ("bulk_wrapper", chain.bulk_wrapper.start),
                    ("bulk_reader", chain.bulk_reader.start),
                    ("bulk_loop", chain.bulk_loop),
                ] {
                    let expected = u32::from_str_radix(
                        row[key].as_str().unwrap().trim_start_matches("0x"),
                        16,
                    )
                    .unwrap();
                    assert_eq!(BASE + actual as u32, expected, "{component} {key}");
                }
                for at in [
                    chain.vector,
                    chain.c_startup.start,
                    chain.dispatch_call,
                    chain.dispatcher.start,
                    chain.hardware_init.start,
                    chain.cache_init_call,
                    chain.cache_initializer.start,
                    chain.bulk_wrapper.start,
                    chain.bulk_reader.start,
                    chain.bulk_loop,
                    chain.bulk_reader.end - 1,
                ] {
                    let mut mutated = normal.clone();
                    mutated[at] ^= 1;
                    assert!(
                        !matches!(bind(&mutated), Observation::Known(_)),
                        "{component} native mutation {at:x}"
                    );
                }
            }
        }
        assert_eq!(
            checked.len(),
            292,
            "complete R0/R1/SAT9 native evidence set"
        );
    }
}

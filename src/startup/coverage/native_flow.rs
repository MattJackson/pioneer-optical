//! Native startup control flow with explicit call-return prerequisites.
//!
//! SAT8's historical evidence walked past opaque calls by assuming they return.
//! This graph keeps those continuations as conditional edges. `reachable` follows
//! only continuations supported by an exact native return contract. Neither the
//! graph nor a missing fixed-comparison pattern establishes word-009F admission.
//! Bound normal-return relations do not establish callee termination.
use crate::image::layout::{self, Observation, Unresolved};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use h8_asm::{
    isa::{decode_insn, Ea, Operand as O},
    Mode, Target,
};

const BASE: u32 = 0x410000;
const NODE_LIMIT: usize = 16384;

/// Native semantics used to discharge a call's normal-return prerequisite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnKind {
    /// A complete sequence of NOP instructions followed by RTS.
    Leaf,
    /// The complete parameter getter and its bound native reader graph.
    ParameterGetter,
}

/// A return contract bound to exact complete native routines in one image.
/// Fields are private so an arbitrary address cannot be supplied as a proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnContract {
    entry: u32,
    kind: ReturnKind,
    bindings: Vec<(usize, Vec<u8>)>,
}
impl ReturnContract {
    /// CPU entry whose normal-return relation is covered by this contract.
    pub fn entry(&self) -> u32 {
        self.entry
    }
    /// Semantics establishing the native normal-return contract.
    pub fn kind(&self) -> ReturnKind {
        self.kind
    }
    fn valid(&self, normal: &[u8], spans: &[(usize, usize)]) -> bool {
        self.bindings.iter().all(|(at, bytes)| {
            at.checked_add(bytes.len()).is_some_and(|end| {
                inside(spans, *at, end) && normal.get(*at..end) == Some(bytes.as_slice())
            })
        })
    }
}

/// Bind a side-effect-free native leaf: at most eight NOPs followed by RTS.
/// No other instruction, indirect transfer, stack write or external call is
/// accepted. This constructor does not infer a return from an arbitrary body.
pub fn bind_leaf(normal: &[u8], entry: u32) -> Option<ReturnContract> {
    let spans = stored_spans(normal)?;
    let start = entry.checked_sub(BASE)? as usize;
    if start & 1 != 0 {
        return None;
    }
    for n in 0..=8 {
        let at = start.checked_add(n * 2)?;
        let end = at.checked_add(2)?;
        if !inside(&spans, start, end) {
            return None;
        }
        match normal.get(at..end)? {
            [0x54, 0x70] => {
                return Some(ReturnContract {
                    entry,
                    kind: ReturnKind::Leaf,
                    bindings: alloc::vec![(start, normal[start..end].to_vec())],
                })
            }
            [0, 0] => {}
            _ => return None,
        }
    }
    None
}

/// Bind the complete recognized Normal getter, retaining every helper's bytes.
/// A contract is revalidated against the supplied image before use, so a proof
/// from another image or from before a mutation cannot close a call frontier.
pub fn bind_getter(normal: &[u8]) -> Observation<ReturnContract> {
    let evidence = match layout::discover_h8_reader(normal, None) {
        Observation::Known(v) if v.component == layout::H8ReaderComponent::Normal => v,
        Observation::Known(_) => return Observation::Unresolved(Unresolved::ReaderNotRecognized),
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    let Some(spans) = stored_spans(normal) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    let mut bindings = Vec::new();
    for function in evidence.functions {
        let Some(at) = function.address.checked_sub(BASE).map(|v| v as usize) else {
            return Observation::Unresolved(Unresolved::TruncatedEvidence);
        };
        let Some(end) = at.checked_add(function.bytes) else {
            return Observation::Unresolved(Unresolved::TruncatedEvidence);
        };
        if !inside(&spans, at, end) {
            return Observation::Unresolved(Unresolved::TruncatedEvidence);
        }
        bindings.push((at, normal[at..end].to_vec()));
    }
    if bindings.is_empty() {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    }
    Observation::Known(ReturnContract {
        entry: evidence.getter,
        kind: ReturnKind::ParameterGetter,
        bindings,
    })
}

/// How an instruction transfers control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Ordinary decoded instruction with a sequential successor.
    Step,
    /// Conditional native branch; both flag outcomes are retained.
    Branch,
    /// Unconditional direct branch or jump.
    Jump,
    /// Native subroutine call.
    Call,
    /// Native RTS, observed without assuming a matching caller stack.
    Return,
    /// Instruction requiring additional execution semantics.
    Unresolved,
}
/// A decoded instruction at its native CPU address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// CPU instruction address.
    pub address: u32,
    /// Complete decoded instruction length.
    pub bytes: usize,
    /// Control-flow meaning.
    pub flow: Flow,
}
/// Whether a graph edge can be traversed without a missing call contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeKind {
    /// A native sequential, conditional-branch or direct-jump edge.
    Native,
    /// Entry into the directly addressed native subroutine.
    Call,
    /// Continuation conditional on a call returning normally, with its native
    /// normal-return relation bound. This does not establish termination.
    BoundReturn,
    /// Hypothetical continuation requiring proof that the call returns.
    RequiresReturn,
}
/// One explicit control-flow edge; conditional returns are never native edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edge {
    /// CPU address of the originating instruction.
    pub from: u32,
    /// CPU destination address, including external component addresses.
    pub to: u32,
    /// Prerequisite for traversing this edge.
    pub kind: EdgeKind,
}
/// A native proof obligation. These are not evidence of known absence.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Obligation {
    /// This call has no complete, image-bound native normal-return contract.
    CallReturn {
        /// CPU address of JSR or BSR.
        site: u32,
        /// Decoded target; None preserves an unresolved indirect target.
        target: Option<u32>,
    },
    /// Native control flow reaches bytes outside a stored instruction region.
    Boundary(u32),
    /// Native decoding failed or the instruction needs execution semantics.
    Instruction(u32),
    /// A control-flow target enters another decoded instruction's interior.
    InstructionOverlap(u32),
    /// An indirect jump requires register or vector-table target analysis.
    IndirectJump(u32),
    /// A decoded RTS needs a caller-stack integrity contract to prove return.
    ReturnStack(u32),
    /// A supplied return contract no longer matches its complete native graph.
    StaleReturnContract(u32),
    /// Finite native graph exploration bound was reached.
    NodeLimit,
    /// Control-flow coverage alone does not close parameter value propagation,
    /// cached consumers, queue predicates, or alternate native entry paths.
    PersistentWordFlow {
        /// Persistent native parameter word requiring value-flow closure.
        parameter: u16,
    },
}
/// A bounded structural native graph, including explicitly conditional edges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Graph {
    /// Native CPU entry being explored.
    pub entry: u32,
    /// All decoded nodes, including those behind missing call contracts.
    pub nodes: Vec<Node>,
    /// Native and conditional edges; callers must preserve their kinds.
    pub edges: Vec<Edge>,
    /// Nodes reached without traversing a RequiresReturn edge. BoundReturn
    /// edges retain the precondition that their callee returns normally.
    /// Branch predicates are forked, so membership is possible structural
    /// reachability, not proof of termination or a runtime condition's value.
    pub reachable: Vec<u32>,
    /// Remaining execution and persistent-value proof prerequisites.
    pub obligations: Vec<Obligation>,
}

fn stored_spans(normal: &[u8]) -> Option<Vec<(usize, usize)>> {
    Some(
        crate::image::regions(normal)?
            .stored
            .iter()
            .map(|b| {
                let at = b.as_ptr() as usize - normal.as_ptr() as usize;
                (at, at + b.len())
            })
            .collect(),
    )
}
fn inside(spans: &[(usize, usize)], start: usize, end: usize) -> bool {
    start < end && spans.iter().any(|&(a, z)| start >= a && end <= z)
}
fn target(operand: O, next: u32) -> Option<u32> {
    match operand {
        O::Address(Ea::Absolute { value, .. }) => Some(value),
        O::Address(Ea::PcRelative { value, .. }) => next.checked_add_signed(value),
        _ => None,
    }
}
fn is_branch(op: &str) -> bool {
    matches!(
        op,
        "BRA"
            | "BRN"
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

/// Decode a generic native startup graph without granting opaque calls returns.
///
/// The structural graph also describes instructions after unresolved calls, but
/// only through RequiresReturn edges. `reachable` excludes those edges. Return
/// contracts are checked against all their original code bytes on every call.
/// A BoundReturn edge remains conditional on normal return; the graph proves
/// neither termination nor concrete runtime path feasibility.
/// Computed targets, external routines, stack-return integrity and persistent
/// word propagation remain typed obligations. No SHA, model name, SAT label or
/// missing instruction pattern authorizes admission.
pub fn trace(normal: &[u8], entry: u32, contracts: &[ReturnContract]) -> Graph {
    let mut obligations = BTreeSet::new();
    obligations.insert(Obligation::PersistentWordFlow { parameter: 0x9f });
    let spans = stored_spans(normal).unwrap_or_default();
    let mut returns = BTreeSet::new();
    for contract in contracts {
        if contract.valid(normal, &spans) {
            returns.insert(contract.entry);
        } else {
            obligations.insert(Obligation::StaleReturnContract(contract.entry));
        }
    }
    let mut nodes: BTreeMap<u32, Node> = BTreeMap::new();
    let mut edges = Vec::new();
    let mut todo = alloc::vec![entry];
    let mut considered = BTreeSet::new();
    while let Some(pc) = todo.pop() {
        if !considered.insert(pc) {
            continue;
        }
        if considered.len() > NODE_LIMIT {
            obligations.insert(Obligation::NodeLimit);
            break;
        }
        let Some(at) = pc.checked_sub(BASE).map(|v| v as usize) else {
            obligations.insert(Obligation::Boundary(pc));
            continue;
        };
        let Some((_, end)) = spans.iter().find(|&&(a, z)| at >= a && at < z) else {
            obligations.insert(Obligation::Boundary(pc));
            continue;
        };
        if at & 1 != 0 {
            obligations.insert(Obligation::Boundary(pc));
            continue;
        }
        let Ok(decoded) = decode_insn(&normal[at..*end], Target::H8S2000, Mode::Advanced) else {
            obligations.insert(Obligation::Instruction(pc));
            continue;
        };
        let Some(next) = pc.checked_add(decoded.len as u32) else {
            obligations.insert(Obligation::Boundary(pc));
            continue;
        };
        if decoded.len == 0 || at + decoded.len > *end {
            obligations.insert(Obligation::Boundary(pc));
            continue;
        }
        if nodes
            .range(..=pc)
            .next_back()
            .is_some_and(|(_, n)| pc < n.address + n.bytes as u32)
            || nodes.range(pc..next).next().is_some()
        {
            obligations.insert(Obligation::InstructionOverlap(pc));
            continue;
        }
        let op = decoded.insn.mnemonic;
        let [a, _, _] = decoded.insn.operands;
        let mut outgoing = Vec::new();
        let flow;
        if op == "RTS" {
            flow = Flow::Return;
            obligations.insert(Obligation::ReturnStack(pc));
        } else if op == "JSR" || op == "BSR" {
            flow = Flow::Call;
            let destination = target(a, next);
            let bound = destination.is_some_and(|t| returns.contains(&t));
            if let Some(to) = destination {
                outgoing.push(Edge {
                    from: pc,
                    to,
                    kind: EdgeKind::Call,
                });
            }
            outgoing.push(Edge {
                from: pc,
                to: next,
                kind: if bound {
                    EdgeKind::BoundReturn
                } else {
                    EdgeKind::RequiresReturn
                },
            });
            if !bound {
                obligations.insert(Obligation::CallReturn {
                    site: pc,
                    target: destination,
                });
            }
        } else if op == "JMP" || is_branch(op) {
            flow = if op == "JMP" || op == "BRA" {
                Flow::Jump
            } else {
                Flow::Branch
            };
            if op != "BRN" {
                if let Some(to) = target(a, next) {
                    outgoing.push(Edge {
                        from: pc,
                        to,
                        kind: EdgeKind::Native,
                    });
                } else {
                    obligations.insert(Obligation::IndirectJump(pc));
                }
            }
            if op != "JMP" && op != "BRA" {
                outgoing.push(Edge {
                    from: pc,
                    to: next,
                    kind: EdgeKind::Native,
                });
            }
        } else if matches!(op, "RTE" | "TRAPA" | "SLEEP" | "EEPMOV") {
            flow = Flow::Unresolved;
            obligations.insert(Obligation::Instruction(pc));
        } else {
            flow = Flow::Step;
            outgoing.push(Edge {
                from: pc,
                to: next,
                kind: EdgeKind::Native,
            });
        }
        nodes.insert(
            pc,
            Node {
                address: pc,
                bytes: decoded.len,
                flow,
            },
        );
        for edge in outgoing {
            // External transfer targets are retained as edges and obligations;
            // no bytes from another component are decoded as Normal code.
            if edge.to >= BASE
                && edge
                    .to
                    .checked_sub(BASE)
                    .is_some_and(|v| inside(&spans, v as usize, v as usize + 1))
            {
                // Exact getters/leaves are summarized by their return contract.
                if !(edge.kind == EdgeKind::Call && returns.contains(&edge.to)) {
                    todo.push(edge.to);
                }
            } else if edge.kind != EdgeKind::RequiresReturn {
                obligations.insert(Obligation::Boundary(edge.to));
            }
            edges.push(edge);
        }
    }
    let mut successors: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for edge in &edges {
        if edge.kind != EdgeKind::RequiresReturn && nodes.contains_key(&edge.to) {
            successors.entry(edge.from).or_default().push(edge.to);
        }
    }
    let mut reachable = BTreeSet::new();
    let mut queue = alloc::vec![entry];
    while let Some(pc) = queue.pop() {
        if !reachable.insert(pc) {
            continue;
        }
        if let Some(next) = successors.get(&pc) {
            queue.extend(next);
        }
    }
    reachable.retain(|pc| nodes.contains_key(pc));
    Graph {
        entry,
        nodes: nodes.into_values().collect(),
        edges,
        reachable: reachable.into_iter().collect(),
        obligations: obligations.into_iter().collect(),
    }
}

/// Start at the native Normal vector instruction at CPU 0x412000.
/// A malformed vector stays unresolved rather than being replaced with a root.
pub fn discover(normal: &[u8]) -> Observation<Graph> {
    let Some(spans) = stored_spans(normal) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    if !inside(&spans, 0x2000, 0x2004) || normal.get(0x2000) != Some(&0x5a) {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    }
    let mut contracts = Vec::new();
    if let Observation::Known(getter) = bind_getter(normal) {
        contracts.push(getter);
    }
    Observation::Known(trace(normal, BASE + 0x2000, &contracts))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut raw = alloc::vec![0xff; 0x4000];
        raw[0x2000..0x2004].copy_from_slice(&[0x5a, 0x41, 0x21, 0]);
        raw
    }
    #[test]
    fn opaque_call_continuation_is_explicitly_conditional() {
        let mut raw = fixture();
        raw[0x2100..0x210a]
            .copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x00, 0x00, 0x5a, 0x40, 0xbf, 0xb0]);
        let Observation::Known(graph) = discover(&raw) else {
            panic!("native vector");
        };
        assert!(graph.nodes.iter().any(|n| n.address == 0x412106));
        assert!(!graph.reachable.contains(&0x412104));
        assert!(!graph.reachable.contains(&0x412106));
        assert!(graph.edges.contains(&Edge {
            from: 0x412100,
            to: 0x412104,
            kind: EdgeKind::RequiresReturn
        }));
        assert!(graph.obligations.contains(&Obligation::CallReturn {
            site: 0x412100,
            target: Some(0x400a1a)
        }));
        assert!(graph.obligations.contains(&Obligation::Boundary(0x400a1a)));
    }
    #[test]
    fn leaf_binding_rejects_odd_long_non_nop_and_truncated_bodies() {
        let mut raw = fixture();
        raw[0x2200..0x2212].fill(0);
        raw[0x2212..0x2214].copy_from_slice(&[0x54, 0x70]);
        assert!(bind_leaf(&raw, 0x412200).is_none(), "nine NOPs");
        assert!(bind_leaf(&raw, 0x412202).is_some(), "eight NOPs");
        raw[0x2301..0x2305].copy_from_slice(&[0, 0, 0x54, 0x70]);
        assert!(bind_leaf(&raw, 0x412301).is_none(), "odd entry");
        raw[0x2400..0x2404].copy_from_slice(&[0x01, 0, 0x54, 0x70]);
        assert!(bind_leaf(&raw, 0x412400).is_none(), "non-NOP body");
        raw[0x3ffe..0x4000].fill(0);
        assert!(
            bind_leaf(&raw, 0x413ffe).is_none(),
            "leaf past the stored end"
        );
        assert!(bind_leaf(&raw, 0x40fffe).is_none(), "below the Normal base");
    }
    #[test]
    fn unresolved_transfers_and_overlaps_are_explicit_obligations() {
        let mut raw = fixture();
        raw[0x2100..0x2102].copy_from_slice(&[0x59, 0x00]);
        assert!(trace(&raw, 0x412100, &[])
            .obligations
            .contains(&Obligation::IndirectJump(0x412100)));
        // MOV.L #imm,ER0 then BRA into its immediate operand.
        raw[0x2100..0x2108].copy_from_slice(&[0x7a, 0, 0, 0, 0, 0, 0x40, 0xfa]);
        let graph = trace(&raw, 0x412100, &[]);
        assert!(graph
            .obligations
            .contains(&Obligation::InstructionOverlap(0x412102)));
        assert!(!graph.nodes.iter().any(|n| n.address == 0x412102));
        raw[0x2100..0x2104].copy_from_slice(&[0x5a, 0x40, 0, 0]);
        let graph = trace(&raw, 0x412100, &[]);
        assert!(graph.obligations.contains(&Obligation::Boundary(0x400000)));
        assert!(graph.edges.contains(&Edge {
            from: 0x412100,
            to: 0x400000,
            kind: EdgeKind::Native
        }));
    }
    #[test]
    fn branch_never_keeps_only_its_fall_through_edge() {
        let mut raw = fixture();
        raw[0x2100..0x2104].copy_from_slice(&[0x41, 0x10, 0x54, 0x70]);
        let graph = trace(&raw, 0x412100, &[]);
        let edges: Vec<_> = graph.edges.iter().filter(|e| e.from == 0x412100).collect();
        assert_eq!(
            edges,
            [&Edge {
                from: 0x412100,
                to: 0x412102,
                kind: EdgeKind::Native
            }]
        );
        assert!(!graph.reachable.contains(&0x412112));
    }
    #[test]
    fn exploration_bound_is_reported() {
        let mut raw = alloc::vec![0xff; 0x2100 + 2 * (NODE_LIMIT + 8)];
        raw[0x2000..0x2004].copy_from_slice(&[0x5a, 0x41, 0x21, 0]);
        let sled = raw.len() - 2;
        raw[0x2100..sled].fill(0);
        raw[sled..].copy_from_slice(&[0x54, 0x70]);
        let Observation::Known(graph) = discover(&raw) else {
            panic!("native vector");
        };
        assert!(graph.obligations.contains(&Obligation::NodeLimit));
        raw.truncate(0x2100 + 2 * (NODE_LIMIT - 8));
        let sled = raw.len() - 2;
        raw[sled..].copy_from_slice(&[0x54, 0x70]);
        let Observation::Known(graph) = discover(&raw) else {
            panic!("native vector");
        };
        assert!(!graph.obligations.contains(&Obligation::NodeLimit));
    }
    #[test]
    fn vector_must_be_a_native_absolute_jump() {
        let mut raw = fixture();
        assert!(matches!(discover(&raw), Observation::Known(_)));
        assert!(matches!(bind_getter(&raw), Observation::Unresolved(_)));
        raw[0x2000] = 0x5e;
        assert!(matches!(discover(&raw), Observation::Unresolved(_)));
    }
    #[test]
    fn exact_leaf_closes_return_but_mutated_or_foreign_contract_does_not() {
        let mut raw = fixture();
        raw[0x2100..0x2108].copy_from_slice(&[0x5e, 0x41, 0x22, 0, 0x5a, 0x40, 0xbf, 0xb0]);
        raw[0x2200..0x2204].copy_from_slice(&[0, 0, 0x54, 0x70]);
        let leaf = bind_leaf(&raw, 0x412200).expect("complete leaf");
        let graph = trace(&raw, 0x412000, core::slice::from_ref(&leaf));
        assert!(graph.reachable.contains(&0x412104));
        assert!(!graph
            .obligations
            .iter()
            .any(|o| matches!(o, Obligation::CallReturn { site: 0x412100, .. })));
        for i in 0..4 {
            raw[0x2200 + i] ^= 1;
            let graph = trace(&raw, 0x412000, core::slice::from_ref(&leaf));
            assert!(
                !graph.reachable.contains(&0x412104),
                "mutated leaf byte {i}"
            );
            assert!(graph
                .obligations
                .contains(&Obligation::StaleReturnContract(0x412200)));
            raw[0x2200 + i] ^= 1;
        }
    }
    #[test]
    fn decoding_native_rts_does_not_invent_a_call_stack_contract() {
        let mut raw = fixture();
        raw[0x2100..0x2106].copy_from_slice(&[0x5e, 0x41, 0x22, 0, 0x54, 0x70]);
        raw[0x2200..0x2202].copy_from_slice(&[0x54, 0x70]);
        let graph = trace(&raw, 0x412000, &[]);
        assert!(graph.reachable.contains(&0x412200));
        assert!(!graph.reachable.contains(&0x412104));
        assert!(graph
            .obligations
            .contains(&Obligation::ReturnStack(0x412200)));
    }
    #[test]
    fn both_branch_outcomes_and_relative_calls_keep_native_targets() {
        let mut raw = fixture();
        raw[0x2100..0x210a].copy_from_slice(&[0x47, 4, 0x55, 4, 0x40, 2, 0, 0, 0x54, 0x70]);
        let leaf = bind_leaf(&raw, 0x412108).unwrap();
        let graph = trace(&raw, 0x412000, &[leaf]);
        assert!(graph.reachable.contains(&0x412102));
        assert!(graph.reachable.contains(&0x412106));
        assert!(graph.edges.contains(&Edge {
            from: 0x412102,
            to: 0x412108,
            kind: EdgeKind::Call
        }));
        assert!(graph.reachable.contains(&0x412104));
        // An indirect call cannot borrow the neighboring leaf's return proof.
        raw[0x2102..0x2104].copy_from_slice(&[0x5d, 0]);
        let graph = trace(&raw, 0x412000, &[]);
        assert!(graph.obligations.contains(&Obligation::CallReturn {
            site: 0x412102,
            target: None
        }));
        assert!(!graph.reachable.contains(&0x412104));
    }
    #[test]
    fn getter_contract_retains_complete_helper_bindings() {
        let mut raw = alloc::vec![0xff; 0x7000];
        layout::install_test_layout(&mut raw, 0x1000);
        let Observation::Known(contract) = bind_getter(&raw) else {
            panic!("complete getter");
        };
        raw[0x80..0x86].copy_from_slice(&[0x5e, 0x41, 0x10, 0, 0x54, 0x70]);
        assert!(trace(&raw, BASE + 0x80, core::slice::from_ref(&contract))
            .reachable
            .contains(&(BASE + 0x84)));
        for (at, bytes) in &contract.bindings {
            for i in 0..bytes.len() {
                raw[at + i] ^= 1;
                let graph = trace(&raw, BASE + 0x80, core::slice::from_ref(&contract));
                assert!(
                    !graph.reachable.contains(&(BASE + 0x84)),
                    "reader mutation {at:x}+{i:x}"
                );
                raw[at + i] ^= 1;
            }
        }
    }
    #[test]
    fn missing_vector_and_missing_patterns_never_admit_a_word() {
        assert!(matches!(discover(&[]), Observation::Unresolved(_)));
        let graph = trace(&fixture(), BASE + 0x2100, &[]);
        assert!(graph
            .obligations
            .contains(&Obligation::PersistentWordFlow { parameter: 0x9f }));
    }
}

//! Combined local cache-index coverage. This joins direct CFG observations to
//! bound helper/caller contracts; it does not establish boot reachability.
use super::{cache_flow, cache_helpers, cache_rom, r1_pair};
use crate::image::layout::Observation;
use alloc::vec::Vec;
/// How a local accessor index set was established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Bounded function control flow defines the byte index on every path.
    ControlFlow,
    /// Complete R0 byte/pair function and observed caller input definitions.
    R0Helper,
    /// Bound mode selectors and actual ROM table bytes.
    RomTable,
    /// R1 pair and complete saved-register initialization graph, on normal returns.
    R1Pair,
    /// Unsupported flow, alias or incoming input remains unresolved.
    Unresolved,
}
/// One direct cache-reader call and its effective local index set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// Decoded Normal call offset.
    pub offset: usize,
    /// Byte indices; None means local coverage is incomplete.
    pub indices: Option<Vec<u8>>,
    /// Native evidence used for this set.
    pub source: Source,
}
/// Local cache-call coverage with remaining scope explicitly retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// Effective direct-call observations in offset order.
    pub calls: Vec<Call>,
    /// R1 allocator and final initialization callees still needing startup analysis.
    pub initialization_dependencies: Vec<u32>,
    /// Direct accessor references without a native function boundary.
    pub uncovered: Vec<cache_flow::Reference>,
}
fn known<T>(observation: Observation<T>) -> Result<T, Observation<Evidence>> {
    match observation {
        Observation::Known(v) => Ok(v),
        Observation::Unresolved(r) => Err(Observation::Unresolved(r)),
        Observation::Conflicting => Err(Observation::Conflicting),
    }
}
/// Combine complete local evidence without converting an absent caller, alias,
/// missing domain or unsupported CFG into a no-restriction claim. Required
/// initialization callees and boot paths are separate obligations.
pub fn discover(normal: &[u8]) -> Observation<Evidence> {
    let flows = match known(cache_flow::discover_direct(normal)) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let r0 = match known(cache_helpers::discover(normal)) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let rom = match known(cache_rom::discover(normal)) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let r1 = match known(r1_pair::discover(normal)) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut result = Evidence {
        calls: Vec::new(),
        initialization_dependencies: Vec::new(),
        uncovered: Vec::new(),
    };
    for f in flows {
        result.uncovered.extend(f.uncovered);
        for function in f.functions {
            for call in function.calls {
                let mut indices = if function.issues.is_empty() {
                    call.indices.into_iter().collect::<Option<Vec<_>>>()
                } else {
                    None
                };
                let mut source = if indices.is_some() {
                    Source::ControlFlow
                } else {
                    Source::Unresolved
                };
                if indices.is_none() {
                    if let Some(h) = r0.iter().find(|h| h.reads.contains(&call.offset)) {
                        if !h.callers.is_empty() && h.other_references.is_empty() {
                            let p = h.reads.iter().position(|&v| v == call.offset).unwrap();
                            indices = h
                                .callers
                                .iter()
                                .map(|c| c.indices.as_ref().and_then(|v| v.get(p)).copied())
                                .collect();
                            if indices.is_some() {
                                source = Source::R0Helper;
                            }
                        }
                    }
                    if let Some(h) = rom.iter().find(|h| h.reads.contains(&call.offset)) {
                        if !h.callers.is_empty() && h.other_references.is_empty() {
                            let second = h.reads[1] == call.offset;
                            let mut values = Vec::new();
                            let mut complete = true;
                            for caller in &h.callers {
                                if let Some(modes) = &caller.modes {
                                    for &mode in modes {
                                        if let Some(&first) = h.first_indices.get(mode as usize) {
                                            values.push(if second {
                                                first.wrapping_add(1)
                                            } else {
                                                first
                                            });
                                        } else {
                                            complete = false;
                                        }
                                    }
                                } else {
                                    complete = false;
                                }
                            }
                            if complete {
                                indices = Some(values);
                                source = Source::RomTable;
                            }
                        }
                    }
                    if let Some(h) = r1.iter().find(|h| h.reads.contains(&call.offset)) {
                        if !h.callers.is_empty() && h.other_references.is_empty() {
                            let p = usize::from(h.reads[1] == call.offset);
                            indices = h.callers.iter().map(|c| c.indices.map(|v| v[p])).collect();
                            if indices.is_some() {
                                source = Source::R1Pair;
                                result.initialization_dependencies.extend(h.external_calls);
                            }
                        }
                    }
                }
                if let Some(values) = &mut indices {
                    values.sort_unstable();
                    values.dedup();
                }
                result.calls.push(Call {
                    offset: call.offset,
                    indices,
                    source,
                });
            }
        }
    }
    result.calls.sort_by_key(|c| c.offset);
    result.initialization_dependencies.sort_unstable();
    result.initialization_dependencies.dedup();
    Observation::Known(result)
}

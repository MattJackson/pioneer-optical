//! Typed limits of native Normal startup evidence. Local getter/cache matches
//! are useful witnesses; they are not a certificate for an unexamined callee.
use super::{argument, cache_flow, direct};
use crate::image::layout::{Observation, Unresolved};
use alloc::vec::Vec;

/// Boundary of this assessment. Later Kernel execution and host READY are not
/// covered by a Normal-startup observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Native Normal entry, initialization and dispatch up to Kernel handoff.
    NormalStartupToKernelHandoff,
}

/// A remaining native obligation. No variant means a guessed numeric value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Obligation {
    /// A complete native getter and its exact parameter layout are unavailable.
    Reader(Unresolved),
    /// Native getter paths conflict.
    ConflictingReader,
    /// One getter call has only a local input observation. Incoming CFG edges
    /// and its effect on the startup path still need a joined contract.
    GetterInput {
        /// Decoded Normal call offset.
        offset: usize,
        /// Local domain; an unknown domain remains explicit.
        domain: argument::Domain,
    },
    /// A complete dynamic consumer is bound, but its callers or queue inputs
    /// have not been connected to the startup root.
    ConsumerCaller {
        /// Complete block entry in decoded Normal.
        offset: usize,
        /// Native operation performed by the block.
        kind: direct::Kind,
    },
    /// Getter call outside the complete recognized local consumer forms.
    GetterCall(usize),
    /// Getter-pointer lifetime without a complete local form.
    GetterPointer(usize),
    /// A cache accessor call can read the final two bytes, or its index is unknown.
    CacheInput(usize),
    /// A native cache-address occurrence lacks a complete local interpretation.
    CacheReference(cache_flow::Reference),
    /// Literal cache RAM alias without a complete read/write contract.
    CacheWriterAlias(cache_flow::Reference),
    /// Queue contents and producer inputs are not yet joined to a proven cold
    /// startup clear and the Normal dispatch path.
    QueueStartup {
        /// Decoded Normal producer entry.
        producer: usize,
        /// Actual RAM count byte.
        count: u32,
    },
    /// Producer input occurrence without joined incoming-path coverage.
    QueueInput(cache_flow::Reference),
    /// A constructor/initializer callee must be joined to the startup proof.
    InitializationCallee(u32),
    /// A bound word-output function still has an unbound formatter callee.
    FormatterCallee(usize),
    /// A complete startup-body binding is unavailable.
    Boot(Unresolved),
    /// Complete startup bodies establish conflicting paths.
    ConflictingBoot,
    /// Actual startup call/tail target whose behavior is not established by a
    /// local body match. Its return is never silently assumed.
    StartupCallee(super::boot::Dependency),
    /// Local stored-reference observations do not establish startup reachability,
    /// computed aliases or incoming edges. A root-to-boundary proof is required.
    StartupPath,
}

/// Read-only evidence summary with explicit remaining work. An empty collection
/// of matches is never interpreted as unrestricted startup acceptance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assessment {
    /// Exact boundary being assessed.
    pub scope: Scope,
    /// Getter CPU entry when the native reader graph is established.
    pub getter: Option<u32>,
    /// Number of enumerated direct/relative getter calls.
    pub getter_calls: usize,
    /// Number of enumerated literal getter loads.
    pub getter_pointers: usize,
    /// Number of complete dynamic direct-consumer blocks.
    pub direct_blocks: usize,
    /// Number of complete getter-pointer lifetime blocks.
    pub pointer_blocks: usize,
    /// Number of direct cache calls with an established local byte-index set.
    pub cache_calls_with_domains: usize,
    /// Complete rooted startup-body witnesses, conditional on their explicitly
    /// retained call-return dependencies.
    pub boot: Option<alloc::boxed::Box<super::boot::BootChain>>,
    /// Number of complete write/update/zero blocks bound to the actual cache.
    pub cache_writer_blocks: usize,
    /// Number of complete parameter/value queue producers.
    pub queue_producers: usize,
    /// Requirements not discharged by the held native contracts.
    pub obligations: Vec<Obligation>,
}

/// Combine bounded native observations without promoting them into an absence
/// proof. This is deliberately separate from selection of a persistent word.
pub fn assess(normal: &[u8]) -> Assessment {
    let mut result = Assessment {
        scope: Scope::NormalStartupToKernelHandoff,
        getter: None,
        getter_calls: 0,
        getter_pointers: 0,
        direct_blocks: 0,
        pointer_blocks: 0,
        cache_calls_with_domains: 0,
        boot: None,
        cache_writer_blocks: 0,
        queue_producers: 0,
        obligations: Vec::new(),
    };
    let references = match super::references(normal) {
        Observation::Known(value) => value,
        Observation::Unresolved(reason) => {
            result.obligations.push(Obligation::Reader(reason));
            return result;
        }
        Observation::Conflicting => {
            result.obligations.push(Obligation::ConflictingReader);
            return result;
        }
    };
    result.getter = Some(references.getter);
    result.getter_calls = references.calls.len();
    result.getter_pointers = references.pointers.len();
    let mut covered_calls = Vec::new();
    if let Observation::Known(value) = super::direct::discover(normal) {
        result.direct_blocks = value.blocks.len();
        for block in value.blocks {
            covered_calls.extend(block.calls);
            if block.kind != direct::Kind::SelectorFlags {
                result.obligations.push(Obligation::ConsumerCaller {
                    offset: block.offset,
                    kind: block.kind,
                });
            }
        }
    }
    if let Observation::Known(value) = super::pointer::discover(normal) {
        result.pointer_blocks = value.blocks.len();
        result
            .obligations
            .extend(value.uncovered.into_iter().map(Obligation::GetterPointer));
    } else {
        result.obligations.extend(
            references
                .pointers
                .iter()
                .map(|p| Obligation::GetterPointer(p.offset)),
        );
    }
    if let Observation::Known(value) = super::cache::discover(normal) {
        covered_calls.extend(value.into_iter().map(|block| block.getter_call));
    }
    if let Observation::Known(value) = super::table::discover(normal) {
        // The complete function binds its two calls. Actual table contents are
        // retained; introducing 009F must not disappear into a role label.
        for block in value {
            if !block.indices.contains(&0x9f) {
                covered_calls.extend([block.offset + 12, block.dynamic_call]);
            }
        }
    }
    if let Observation::Known(value) = super::word_pair::discover(normal) {
        for block in value {
            covered_calls.extend([block.offset + 10, block.offset + 20]);
            result
                .obligations
                .push(Obligation::FormatterCallee(block.formatter));
        }
    }
    if let Observation::Known(value) = super::cache_indices::discover(normal) {
        for call in value.calls {
            match call.indices {
                Some(indices) if !indices.iter().any(|i| (126..=127).contains(i)) => {
                    result.cache_calls_with_domains += 1;
                }
                _ => result.obligations.push(Obligation::CacheInput(call.offset)),
            }
        }
        result
            .obligations
            .extend(value.uncovered.into_iter().map(Obligation::CacheReference));
        result.obligations.extend(
            value
                .initialization_dependencies
                .into_iter()
                .map(Obligation::InitializationCallee),
        );
    }
    if let Observation::Known(value) = super::cache_writers::discover(normal) {
        for cache in value {
            result.cache_writer_blocks += cache.writers.len();
            result.obligations.extend(
                cache
                    .aliases
                    .into_iter()
                    .filter(|alias| alias.kind.is_none())
                    .map(|alias| Obligation::CacheWriterAlias(alias.reference)),
            );
        }
    }
    if let Observation::Known(value) = super::queue::discover(normal) {
        result.queue_producers = value.len();
        for producer in value {
            result.obligations.push(Obligation::QueueStartup {
                producer: producer.offset,
                count: producer.count,
            });
            result.obligations.extend(
                producer
                    .references
                    .into_iter()
                    .map(|reference| Obligation::QueueInput(reference.reference)),
            );
            result.obligations.extend(
                producer
                    .overflow_callees
                    .into_iter()
                    .map(Obligation::InitializationCallee),
            );
            for contract in producer.input_contracts {
                result.obligations.extend(
                    contract
                        .external_calls
                        .into_iter()
                        .map(Obligation::InitializationCallee),
                );
            }
        }
    }
    let arguments = match argument::discover(normal) {
        Observation::Known(value) => value,
        _ => Vec::new(),
    };
    covered_calls.sort_unstable();
    covered_calls.dedup();
    // argument::discover emits one entry per getter call in the same order.
    for (i, call) in references.calls.into_iter().enumerate() {
        if covered_calls.binary_search(&call.offset).is_ok() {
            continue;
        }
        let matches = |arg: &&argument::Argument| {
            #[cfg(test)]
            tests::PROBES.with(|c| c.set(c.get() + 1));
            arg.call == call.offset
        };
        if let Some(arg) = arguments
            .get(i)
            .filter(matches)
            .or_else(|| arguments.iter().find(matches))
        {
            result.obligations.push(Obligation::GetterInput {
                offset: call.offset,
                domain: arg.domain,
            });
        } else {
            result.obligations.push(Obligation::GetterCall(call.offset));
        }
    }
    match super::boot::bind(normal) {
        Observation::Known(boot) => {
            for function in [
                &boot.c_startup,
                &boot.dispatcher,
                &boot.hardware_init,
                &boot.cache_initializer,
                &boot.bulk_wrapper,
                &boot.bulk_reader,
            ] {
                result.obligations.extend(
                    function
                        .dependencies
                        .iter()
                        .filter(|dependency| {
                            dependency.target
                                != super::boot::TargetAddress::Normal(references.getter)
                        })
                        .cloned()
                        .map(Obligation::StartupCallee),
                );
            }
            result.boot = Some(alloc::boxed::Box::new(boot));
        }
        Observation::Unresolved(reason) => result.obligations.push(Obligation::Boot(reason)),
        Observation::Conflicting => result.obligations.push(Obligation::ConflictingBoot),
    }
    // Local suffix domains and native roles cannot eliminate this obligation.
    // Only a joined startup root / callee / handoff proof may discharge it.
    result.obligations.push(Obligation::StartupPath);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    std::thread_local! {
        pub(super) static PROBES: Cell<usize> = const { Cell::new(0) };
    }

    #[test]
    fn getter_call_matching_is_not_quadratic() {
        let mut normal = alloc::vec![0xff; 0x8000];
        crate::image::layout::install_test_layout(&mut normal, 0x1000);
        let n = 2000;
        for i in 0..n {
            normal[0x2000 + i * 4..0x2004 + i * 4].copy_from_slice(&[0x5e, 0x41, 0x10, 0]);
        }
        PROBES.with(|c| c.set(0));
        let report = assess(&normal);
        assert_eq!(report.getter_calls, n);
        let inputs = report
            .obligations
            .iter()
            .filter(|o| matches!(o, Obligation::GetterInput { .. }))
            .count();
        assert_eq!(inputs, n);
        let probes = PROBES.with(Cell::get);
        assert!(probes <= n * 32, "{probes} argument probes for {n} calls");
    }

    fn getter_obligation_at(report: &Assessment, at: usize) -> bool {
        report.obligations.iter().any(|o| {
            matches!(o, Obligation::GetterInput { offset, .. } | Obligation::GetterCall(offset) if *offset == at)
        })
    }

    #[test]
    fn table_loop_covers_its_calls_unless_a_table_word_is_009f() {
        use super::super::table_shape::{BYTES, RELOCATIONS};
        let mut normal = alloc::vec![0xff; 0x6000];
        crate::image::layout::install_test_layout(&mut normal, 0x1000);
        normal[0x2000..0x2000 + BYTES.len()].copy_from_slice(BYTES);
        for &(i, n, g) in RELOCATIONS {
            let v = match i {
                13 | 59 => 0x411000u32,
                32 => 0x414000,
                _ => 0x415000 + g as u32 * 32,
            };
            normal[0x2000 + i..0x2000 + i + n].copy_from_slice(&v.to_be_bytes()[4 - n..]);
        }
        normal[0x4000..0x400e].copy_from_slice(&[
            0, 0x50, 0, 0x51, 0, 0x52, 0, 0x54, 0, 0x53, 0, 0x55, 1, 0x10,
        ]);
        let report = assess(&normal);
        assert_eq!(report.getter_calls, 2);
        assert!(!getter_obligation_at(&report, 0x200c));
        assert!(!getter_obligation_at(&report, 0x203a));
        normal[0x4006..0x4008].copy_from_slice(&[0, 0x9f]);
        let report = assess(&normal);
        assert!(getter_obligation_at(&report, 0x200c));
        assert!(getter_obligation_at(&report, 0x203a));
    }

    #[test]
    fn cache_reads_of_the_final_two_bytes_remain_inputs() {
        let read = 0x4006;
        let report = assess(&super::super::cache_helpers::tests::byte_helper_fixture(5));
        assert!(!report.obligations.contains(&Obligation::CacheInput(read)));
        assert!(report.cache_calls_with_domains >= 1);
        for index in [126, 127] {
            let report = assess(&super::super::cache_helpers::tests::byte_helper_fixture(
                index,
            ));
            assert!(
                report.obligations.contains(&Obligation::CacheInput(read)),
                "index {index}"
            );
        }
    }

    #[test]
    fn startup_callees_exclude_only_the_bound_getter() {
        let report = assess(&super::super::boot::tests::fixture());
        assert!(report.boot.is_some());
        let callees: Vec<_> = report
            .obligations
            .iter()
            .filter_map(|o| match o {
                Obligation::StartupCallee(d) => Some(d.target),
                _ => None,
            })
            .collect();
        assert!(!callees.is_empty());
        assert!(!callees.contains(&super::super::boot::TargetAddress::Normal(0x411000)));
    }

    #[test]
    fn missing_reader_retains_a_typed_unknown() {
        let report = assess(&[0xff; 64]);
        assert_eq!(report.scope, Scope::NormalStartupToKernelHandoff);
        assert_eq!(report.getter, None);
        assert!(matches!(
            report.obligations.as_slice(),
            [Obligation::Reader(_)]
        ));
    }

    #[test]
    fn empty_local_inventory_does_not_discharge_startup() {
        let mut normal = alloc::vec![0xff; 0x2000];
        crate::image::layout::install_test_layout(&mut normal, 0x1000);
        let report = assess(&normal);
        assert_eq!(report.getter, Some(0x411000));
        assert_eq!(report.getter_calls, 0);
        assert!(report.obligations.contains(&Obligation::StartupPath));
    }
}

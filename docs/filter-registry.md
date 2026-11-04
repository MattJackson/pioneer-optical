# Native filter ownership

A filter owns recognition, comparison, candidate projection, correction planning
and verification of its result. `filters::Context` caches decoded native facts;
every definition in `filters::filters()` inspects every context. Platform and
architecture dispatch belong inside the owner. The coordinator has no parallel
list of filters for SAT1, SAT8, SAT9, ATA or SCSI.

Add an owner module and one entry in `filters::filters()`. Give it a unique,
stable ID and a presentation name. `inspect` returns its role and a typed Known,
Unresolved, Conflicting or positively NotApplicable finding. A hardware owner
contributes to both keys automatically, in sorted ID order. The operational
startup owner is evaluated and planned without being serialized as hardware.
A known constant is still detected and compared; an unsupported recognizer
must return Unresolved rather than a constant or NotApplicable.

`compare` classifies detected facts independently of correction support.
`candidate` may project a value only under its own native proof. `plan` returns
an immutable owner operation or refuses the transition. An `Operation` supplies
its owner ID, exact byte preparation, integrity contract and postcondition
verification. New owners do not need a new central correction enum or a second
platform registration table. Existing compatibility descriptions are optional
metadata for older callers.

The shared runner validates the full operation set before mutation, rejects
overlap, composes disjoint non-checksum edits, applies one agreed integrity
repair, and runs each owner's verifier. The receiver retains codec rebuilding,
authentication, live read/change/verify/rollback and transport execution.
Phase correction belongs to the phase owner; persistent-address correction
belongs to the layout owner.

## Live parameter actions

Each owner's `parameters()` method supplies its target-selected `ParameterAction`
values. The registry collects every owner's actions automatically; adding an
action requires no separate receiver or settings dispatch table. Each action
retains its owner, semantic ID, selected physical word/value and native
assessment. Native assessment and explicit selection policy remain distinct.
The shared transactional executor deduplicates equal physical-word requests and
refuses conflicting requests before I/O. It owns read/change/verify and rollback
of the actual before-value. A Known ATA D9 predicate does not grant H8's A0 word
write command or another unproved writable surface.

Detection coverage is not correction coverage. For example, a native phase
contract can be Known while an unavailable codec or Kernel prevents file
preparation. A V850 phase file operation can be proven while the full firmware
identity remains unresolved because initialization is unsupported. Similarly,
a bounded initialization block is not complete downstream reset or resident
acceptance proof. Each owner reports its exact scope and obligations.

The 722-image native replay reports 626 complete identities, 96 unresolved and
two previous groups split by additional native findings. Tests cover owner
registration, typed recognition, canonical identity ordering, unknown refusal,
operation composition, postcondition verification and parameter transactions.
The Hardware Matrix exposes native findings, required unknowns and correction
capability separately. See [v7 identity](family-v7.md) for canonical serialization.

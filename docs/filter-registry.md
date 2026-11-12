# Native filter ownership

A filter owns recognition, comparison, candidate projection, correction planning
and verification of its result. `filters::Context` caches decoded native facts;
every definition in `filters::filters()` inspects every context. Platform and
architecture dispatch belong inside the owner. The coordinator has no parallel
list of filters for SAT1, SAT8, SAT9, ATA or SCSI.

Add an owner module and one entry in `filters::filters()`. Give it a unique,
stable ID, a presentation name and its declared `Rules` (`Filter::rules`):
plain-language description, role, `Correctability`, correction policy and any
platform-scoped policies. The generated hardware matrix page renders those
statements verbatim, so write only what the owner's code enforces. `inspect` returns its role and a typed Known,
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
authentication, read-only prerequisite enforcement and transport execution.
Phase and startup correction each belong to their registered owner. Persistent parameter layout is
never corrected; a known difference refuses.

## Read-only correction prerequisites

Each selected `Operation::required_words()` supplies the existing live values
its correction requires. The shared collector retains filter ownership,
deduplicates equal requests and rejects conflicts before I/O. The receiver reads
and checks these requirements before firmware transfer. This includes phase's
`0x28F == 1` and equal bound startup words; it never writes a requirement.

`Operation::word_writes()` is disjoint from those reads. Only the startup owner
supplies one: a differing fixed H8 comparison keeps the target image and sets
the target's own startup word. The receiver writes it once, in the first
stage's startup settings transaction (read, write, verify, rollback if no
firmware was written), with the drive in normal mode under a Flash execution,
before the first transfer. Any other placement or Recovery mode refuses
before I/O (`check_plan`); a loader is refused by execution's live identity
read (`IdentityMismatch`) before any write. A differing conditional comparison
refuses.

Historical `ParameterAction` and standalone settings APIs remain separate from
release image correction. Receiver preparation rejects nonempty parameter
actions rather than turning them into persistent writes. Temporary Kernel
marker restoration remains an image effect. A Known ATA D9 predicate does not
grant H8's A0 word-write command or another unproved writable surface.

Detection coverage is not correction coverage. For example, a native phase
contract can be Known while an unavailable codec or Kernel prevents file
preparation. A V850 phase file operation can be proven while the full firmware
identity remains unresolved because initialization is unsupported. Similarly,
a bounded initialization block is not complete downstream reset or resident
acceptance proof. Each owner reports its exact scope and obligations.

The earlier 722-image native replay reported 626 complete identities, 96 unresolved and
two previous groups split by additional native findings. Tests cover owner
registration, typed recognition, canonical identity ordering, unknown refusal,
operation composition, postcondition verification and read-only prerequisites.
The Hardware Matrix ([generated from code](hardware-matrix.md)) exposes native
findings, required unknowns and correction capability separately. See [v7 identity](family-v7.md) for canonical serialization.

# Correction architecture and validation

The 1.6.0 correction workflow is based on dev 1.5. This document records its
architecture, validated software scope and unsupported cases. Plans remain
component-bound; successful software tests do not grant unsupported hardware
routes or transfer representations.

## Admission and effects

Native recognition, comparison and correction live with each registered owner
under `filters`; lower-level decoders remain under `image`. They return typed
Known, Unresolved or Conflicting observations bound to decoded components and,
where required, the exact associated Kernel. An unresolved required observation
produces no family key. Display labels and model names do not select native
patches. Matching candidate identities alone do not authorize an update.

`compatibility` invokes the registered owners for installed and requested
firmware. Each owner enumerates its own supported effects, and the shared runner
produces component-bound plans. Every unrelated required filter
must match. Firmware operands, startup selections and read-only mechanism
prerequisites remain distinct effects within that workflow. The receiver owns
execution and rechecks each stage's hardware and live requirements before
settings, bridge or firmware writes. Planning performs no device I/O.

Normal edits validate all original operands and reject overlap before mutation.
They apply to owned bytes, compensate the checksum once, and re-extract the
required identity. `prepare_image` and `prepare_file` bind the exact envelope
components, use the codec's checksum contract, rebuild and authenticate, then
decode and verify the prepared image. File preparation does not grant a receiver
support for a transfer representation it otherwise refuses.

## Phase and mechanism correction

SAT8/SAT9 use native output-pair correction. SAT1 has explicit operand edits on
thirteen complete native forms. M32C and V850 use architecture-specific native
output and checksum proofs. Unsupported or conflicting forms refuse correction.
Same assignment produces no edit; changed assignment must preserve every other
required filter. Published SAT1 and ATA candidate keys retain phase even when
an individual transition has a supported correction.

Mechanism correction retains all eleven reviewed dev 1.5 definitions and six
original-hardware routing rules as typed Rust contracts. UD02, UD03 and UD04
routes retain exact firmware guards, calibration-format recognition and live
prerequisites. Pristine return and native inverse correction are distinct routes.
They share the correction handoff with native phase; a mechanism recipe cannot
be replaced by a generic phase edit. See [mechanism contracts](settings-adaptation.md).
Production JSON recipes are removed; test fixtures retain independent reference
data and invalid-registry cases. Existing diagnostic names and forwarding API
aliases remain available to callers.

## Startup selection

`compatibility::startup` records the selected word and its evidence. A bound
native comparison selects its accepted 0x009F value through the recognized
getter and correct R0/R1 argument convention. A recognized but unbound or
ambiguous comparison refuses selection.

`StartupPolicy::NeutralSelection` deliberately selects 0x009F = 0xFFFF when no
comparison is recognized. `Evidence::NeutralSelection` retains the separate
native assessment. This is the real neutral startup choice, not a claim that
native code accepts every value. `NativeEvidenceOnly` admission remains
unresolved without a complete positive selection. Bounded Normal-to-Kernel-
handoff evidence retains obligations for callees, getter inputs, cache aliases,
queued callbacks and later Kernel execution; it does not prove global absence
of additional startup requirements.

The settings transaction reads the actual before-value, changes it only when
needed, verifies the selected value and preserves the before-value for rollback.
No firmware edit represents a live startup write, and 0xFFFF is never invented
as a restoration value. Read-only mechanism prerequisites remain independent.

## Persistent parameter layout

Persistent layout is a required filter on every platform. Matching primary
record dimensions alone does not prove safe conversion. Normal-only relocation
is limited to an address-only whole-program-equivalence subset: the exact
Kernel is unchanged; readers and formats bind completely; after permitted
address operands and independently proven phase normalization, the complete
program must equal the installed program. This preserves the installed writer,
erase, initialization and bank routes without moving or rewriting retained data.
New layout correction does not edit Kernel code.

No held SAT1 or SAT9 layout groups become mutually correctable. All 64 held SAT1
0x7F0000-primary Normal images contain non-erased decoded bytes in the older
0x5E0000..0x5E3250 primary area (end exclusive); redirecting them there would
point into target Normal payload. This is a decoded-address observation, not a device-write trial
or proof of updater erase behavior. SAT9 differs in independent 0xC000/0x10000 bank
strides and the secondary mapping: logical word 0x01A0 resolves to selected-bank
offset 0x4352 on the 29 primary-0x5984 images, versus 0x8352 on the 37
primary-0x9984 images,
so primary-address relocation alone is insufficient. SAT8 record-format
conversion remains blocked. An absence of overlap is not itself a relocation
proof, and a Kernel-owned getter does not prove a Kernel edit is necessary.

## Kernel transitions

`plan_kernel` derives an ordered transition from the installed programmer
restart, target startup entry and receiver marker rules. It plans the two
existing temporary bridge effects: handoff jump destinations plus checksum,
and generation marker plus checksum. Every sequence ends with the unmodified
target Kernel. The receiver checks the materialized stage count and final bytes.
These existing bridges do not authorize new persistent-layout Kernel edits.

## Registry validation and limits

The registered v7 corpus replay passes over all 722 distinct Normal images:
626 have complete identities and 96 retain required unresolved findings. All
seven owners report on every image; hardware entries are sorted by stable ID,
and operational startup evidence is retained separately. Two previous SAT1
groups split through additional initialization facts; 49 previously identified
V850 images are deferred by unsupported initialization. These are native
contract and coverage results, not physical failure claims.

Native filter, identity, runner and layout tests verify recognition, complete
owner registration, typed comparison and refusal boundaries. Three SAT1003
layouts require the unavailable exact resident reader at 0x404622; their other
five hardware findings are recognized, and no layout mismatch is established.
The independent phase operation proofs retain their exact scope: 58 SAT1 file
plans, 346 paired SAT8/SAT9 signed file plans, 98 M32C files and 49 exact-Kernel
V850 pairs. A file-operation proof does not override a required unknown field
or grant full update admission. Invalid files and missing exact Kernels refuse.

The startup owner independently recognizes 85 M32C `0x00D9 == 0xFFFF`
comparisons. H8's deliberate neutral `0x009F = 0xFFFF` choice uses its own
transaction; ATA/SCSI never inherit it. A native requirement is not fabricated
from a missing pattern. Actual SAT1/SAT9 layout pairs and SAT8 format conversion
remain blocked; file preparation does not expand receiver transport support.

See [filter ownership](filter-registry.md) and [v7 family identity](family-v7.md).
No new physical flash, media trial or full-drive emulation is claimed.

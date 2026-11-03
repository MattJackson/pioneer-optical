# Correction architecture and validation

The 1.6.0 correction workflow is based on dev 1.5. This document records its
architecture, validated software scope and unsupported cases. Plans remain
component-bound; successful software tests do not grant unsupported hardware
routes or transfer representations.

## Admission and effects

Native observers live with their filters under `image`. They return typed
Known, Unresolved or Conflicting observations bound to decoded components and,
where required, the exact associated Kernel. An unresolved required observation
produces no family key. Display labels and model names do not select native
patches. Matching candidate identities alone do not authorize an update.

`compatibility` compares installed and requested firmware, enumerates supported
effects, and produces component-bound plans. Every unrelated required filter
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

## Validation and limits

The frozen release all-target suite passes 756 tests (715 library and 41 other
tests). Private corpus suites are also run explicitly; their ignored-by-default
status in the ordinary Cargo run does not replace that verification.

| Verification | Result |
| --- | --- |
| Feature matrix | 16 configurations; 7,119 passing test instances |
| Documentation and portability | 16 documentation builds, 16 MSRV configurations plus all features, four thumb builds, six doctests |
| Existing OEM, held-image and analysis regressions | 849 passing tests: 845 OEM, three held-image tests and one analysis test over 614 inputs |
| Required filters | 18 passing corpus tests, including 11 persistent-layout tests |
| ATA native and file correction | Nine passing corpus tests; 98 M32C files and 49 Kernel-bound V850 pairs; missing exact Kernels refuse |
| Startup | 107 distinct tests, including 722 Normal images and 3,212 boot-chain mutations |
| Mechanism contracts | 35 distinct tests; all 11 output digests, 40 phase compositions, 40 idempotence cases and 126 routing cases |
| Receiver workflow | 89 workflow tests, four Kernel cases, 48 synthetic combinations and 48 preparations over an actual-image grid |

SAT1 independently proves all 73 native operand contracts across 13 forms:
58 original files pass complete plans and codec reversal; 15 invalid standalone
files refuse, including all three unresolved exact-Kernel identities. SAT8/SAT9
prove all 457 native programs and original wrappers: 346 complete signed file
plans pass both directions and idempotence; the other 111 invalid-sum files
without their exact Kernel refuse. Independent decoded-image oracles and exact
signature-block-only wrapper changes are checked. M32C and V850 retain their
architecture-specific checksum and missing-Kernel gates.

Formatting, warnings-denied Clippy, documentation, doctests and packaging checks
pass. The reference inventory remains 723 package records, 722 distinct Normal
images, 675 known v6 identities and 47 required deferrals. The desktop Hardware
Matrix and review copy retain identical historical source data, all platform
filters, four complete green correctable sections and working PDF export;
browser checks confirm unchanged published grouping keys and no script errors.

No new physical flash, media trial or full-drive emulation is claimed. Actual
SAT1/SAT9 layout pairs and SAT8 format conversion remain blocked as described
above. File preparation does not expand live receiver transport support.

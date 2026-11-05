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
must match. Phase and startup are guarded image corrections within that same
workflow. The receiver owns execution and checks each selected operation's
read-only requirements before firmware writes. Planning performs no device I/O.

Normal edits validate all original operands and reject overlap before mutation.
They apply to owned bytes, compensate the checksum once, and re-extract the
required identity. `prepare_image` and `prepare_file` bind the exact envelope
components, use the codec's checksum contract, rebuild and authenticate, then
decode and verify the prepared image. File preparation does not grant a receiver
support for a transfer representation it otherwise refuses.

## Phase correction

SAT8/SAT9 bind the native output interface and the complete supported sled
mechanism convention. A differing convention can require source exchange,
calibration reader/caller changes, conversion routines and DSP waveform edits,
even when coil assignments match. OEM donor code and tables are recognized,
relocated and emitted through h8-asm. Routine specialization preserves proved
caller semantics; reclaimed loader suffixes require exact component evidence.
Unproved growth or resource ownership refuses preparation.

Parameter `0x28F == 1`, when required by the bound mechanism, is read-only. The
executor checks it before transfer and never selects or writes it. Independent
phase proofs do not waive tray inputs, storage layout or other filter failures.
SAT1 phase correction remains suspended. M32C and V850 retain their supported
architecture-specific native output/checksum proofs.

## Startup correction

The startup filter implements the same `Operation` contract as phase. For a
bound H8 comparison, it corrects the target Normal to preserve the installed
accepted word and retains the complete conditional predicate. It declares the
live word as a read-only prerequisite. Preparation composes the image effect
with other owners; verification rebinds the resulting native comparison.

Exact component preservation needs no comparison rewrite. Other transitions
require the startup owner's positive native evidence; an unresolved finding
never authorizes a neutral `0x009F = 0xFFFF` choice. Missing resident getters and
ambiguous predicates remain refusals. Standalone historical selection APIs do
not authorize receiver preparation to issue persistent parameter writes.

The image-correction pipeline performs no separate settings, NVRAM, calibration
or bank writes. Kernel bridges only retain their existing temporary image
changes and restoration. Read-only prerequisites cannot be waived by a family
override.

## Persistent parameter layout

Persistent layout is a required filter on every platform and, as the owner's
hardware matrix states, it is not correctable: any known difference refuses.
The former address-only relocation prover was removed in 1.6.0; it could only
reinstall the installed program and admitted no held pair.

No held SAT1 or SAT9 layout groups are mutually compatible. All 64 held SAT1
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

The earlier v7 corpus replay covered 722 distinct Normal images:
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
Historical isolated phase file-operation counts are not current release
admission evidence. In particular, the former SAT1 file proofs do not override
the current suspension. Full mechanism conversions require the actual shared
planner, composition, prerequisites and original-codec verification; an operand
reversal alone is insufficient. Invalid files and missing exact Kernels refuse.

The startup owner independently recognizes 85 M32C `0x00D9 == 0xFFFF`
comparisons. These remain native read-only requirements; ATA/SCSI do not
inherit an H8 selection policy. No requirement or accepted value is fabricated
from a missing pattern. Actual SAT1/SAT9 layout pairs and SAT8 format conversion
remain blocked; file preparation does not expand receiver transport support.

See [filter ownership](filter-registry.md) and [v7 family identity](family-v7.md).
No new physical flash, media trial or full-drive emulation is claimed.

# Pioneer register analysis backlog — 2026-11-01

## Decision and evidence

Exclude **FEC0 bit 6 only** from hardware-family matching. Keep FE94, the
remaining FEC0 bits, ASIC setup, board markers and servo evidence. Scheme v5
normalizes FEC0 values with `value & 0xBF`, deduplicating the resulting set.
Raw values remain available as `FamilyFingerprint::raw_pins` and in the saved
unmodified evidence. No firmware register value is patched by this change.

BDX-PR1ML SAT 8801 initializes FEC0 to C7; BDR-211M SAT 8801 initializes it
to 87. Their ASIC, board, FE94 and servo fingerprints otherwise match.
Both Kernel and Normal contain the differing write, in initialization/reset
code. A feature/mode selection on a shared platform is the working hypothesis;
its physical function is **not established**. Do not label it a confirmed PR1
feature enable or infer what flipping it will do.

Observed direct accesses also set/clear bit 0, clear bits 2/7 and update bits
3/4 using a read/modify/write sequence. These preserve bit 6. This is not a
proof that indirect or resident code never changes it.

PR1ML Kernel body offsets: immediate C7 at 0x3bc2, FEC0 write at 0x3bc4.
211M SAT8801 ID60 Kernel: immediate 87 at 0x3bf4, write at 0x3bf6.
PR1ML Normal stored-region offsets: immediate C7 at 0xa0168, write at 0xa016a.
211M Normal: immediate 87 at 0xa06b6, write at 0xa06b8.
Offsets identify decoded regions, not universal addresses across versions.

On the retained 723-package corpus (531 fingerprinted), masking bit 6 joins
three pairs of v4 families. It joins PR1ML and 211M SAT8801, but does not join
the distinct 211M SAT8800 board/servo fingerprint. Family equality alone does
not establish completion of a physical crossflash.

## Bit-by-bit research backlog

| Register | Family filter status | What is established / open |
|---|---|---|
| FE8F | Excluded since v4 | Seen in ATA/ATAPI host bring-up; individual bit meanings and possible feature selection remain open. |
| FE94 | Retained | Fixed host initialization write. C0/40 differs in bit 7; 49/40 differs in bits 0 and 3. Exact physical functions remain unestablished. Removal impact is measured below. |
| FE9D | Excluded since v4 | Seen in host bring-up; investigate mode, feature, timing and electrical constraints per bit. |
| FE9F | Excluded since v4 | Seen in host bring-up and retained settings evidence; all bit meanings remain research items. |
| FEC0 | All bits except bit 6 retained in v5 | Bits 3:4 select CRC diagnostic source; bit 0 is actively cleared/set by host-interface state machines. Bit 6 C7/87 split above remains physically unresolved. See the field evidence below. |
| E436/E43A/E43B/E45B/E463/E46A/E46B | Retained | Fixed DSP/ASIC initialization writes. Exact meanings remain open. E46B alone does not identify loading mechanism. Individual and combined removal impacts differ. |
| FFC5 | Retained | Interrupt-related setup context established; exact trigger/routing field semantics remain open. Removing this field changes current relationships. |
| EDCC/EDCD | Retained pending matching redesign | High/low movement-command bytes in the collimator path, rather than fixed board IDs. Existing immediate-write fingerprints reflect initialization and incidental command constants. Removing these two fields alone changes no current relationships. |

For each bit 0–7 in each register: catalog exact OEM values by firmware and
platform, distinguish initialization/reset from runtime changes, trace direct
and indirect reads/writes and dependent branches, correlate differences on
otherwise matching hardware, and seek chip-specific documentation. Record
whether software controls the bit or hardware supplies status; identify any
reserved or write-one-to-clear semantics before proposing experiments.
Only then design isolated bit-flip experiments with measurable expected
behavior. No bit-flip firmware experiments or physical tests were performed.

Historical removal: pioneer-optical commit 07e9b8eee03c26b045f7639dd076ae0f67e6a7d5
removed FE8F/FE9D/FE9F from the family key on October 24; FE94 was retained.
This established a host-configuration versus identity distinction, not a
complete bitfield map or proof that the excluded bits are feature switches.

## Research priority: changes to current family relationships

The current audit uses firmware only. Prioritize distinctions which change
existing family relationships, then investigate whether they represent a real
hardware requirement or a proxy for another difference. Zero impact means
redundancy in this corpus; it does not establish that the physical function is
unimportant. Check combinations as well as individual fields.

Fresh baseline: 700 decoded Normal images, 530 recognized images representing
531 packages, and 21 families. The following are read-only omissions from the
comparison key. Counts are newly matching **directed package pairs**. Existing
servo evidence remains included throughout these listed comparisons.

| Omitted evidence | Families after | Newly matching directed package pairs |
|---|---:|---:|
| Any one of E436, E43A, E43B, E45B, E463, E46A or E46B | 21 | 0 |
| EDCC alone, EDCD alone, or both together | 21 | 0 |
| FEC0 alone | 21 | 0 |
| FE94 alone | 20 | 8 |
| FFC5 alone | 19 | 3,258 |
| FE94 and FEC0 together | 18 | 248 |
| All seven E4 configuration fields together | 18 | 6,966 |

In particular, removing E46B alone currently changes no matches, although
E46B participates in joint distinctions with other fields. Removing the whole
E4 block is therefore a different proposal. Removing EDCC/EDCD alone preserves
relationships; deleting fields from a serialized family key would still change
literal family-ID hashes and require a separate namespace decision.

FFC5 removal joins two groups:

- The 81-package AD07/AD08, XD05–XD08 and XS07/XS08 group (`BCLR5`) with the
  20-package XS05/XS06 group (`BCLR7`). Both groups otherwise have the same
  compared evidence. This adds 3,240 directed package pairs.
- BDC-TD04/BDR-TD04 (three packages, no recognized FFC5 write) with
  BD-W26SS-B/BDR-US01 (three packages, explicit FFC5 bit operations). This adds
  18 directed package pairs.

Of these 3,258 new pairs, 2,458 have different native loading-type reports and
800 have the same native loading-type report. Loading type is therefore not a
complete replacement for the FFC5 distinction. The existing AD07/AD08,
XD05–XD08, XS07/XS08 family itself includes 61 packages reporting tray and 20
reporting caddy/slot. Adding loading-type equality would also split existing
family relationships. A capability report is evidence of firmware behavior;
by itself it does not prove the required physical mechanism or crossflash
safety.

FE94-only removal joins the four TD01/TD01RS packages (`49`) with the single
TD02 0.05e package (`40`). Removing FE94 and FEC0 together additionally joins
the previously recorded XD04/TD05 and XU02/XU03/UD02/UD03/UD04 groups. Their
host-interface differences need explanation before treating them as irrelevant.

## Concrete firmware findings

### EDCC/EDCD: collimator movement-command bytes

OEM XD04 1.20 Normal component key
`c3820bc685d9fce27419c21e914c5b628da4cbc6371c6c06bfee93638e222a96`
contains a direct `CCollimator::MovePrivate` string reference at decoded file
offset 0x1c9f06. The routine subtracts target and current positions, passes the
magnitude and direction through 0x5da392 to 0x5da5f2, and reports
`COL MOVE TIME OUT!` on timeout. The writer at file 0x1ca5f2..0x1ca608 forms a
signed count, then writes its high byte to EDCC and low byte to EDCD. The
implemented hardware count width is not established solely by this CPU's
16-bit arithmetic.

211M 1.51 has the same writer at file 0x12c972 and an additional routine which
writes the pair 0001 and FFFF (+1 and -1 in this command representation). That
routine's exact purpose remains open. Its adjacent immediate loads/stores
explain the fingerprint `edcc=0.ff edcd=1`; these are not fixed board IDs.

All 530 recognized images have one split-word writer candidate: 457 use the
canonical audited form, 64 use an R3/count-and-position-accumulator form and
nine use an R2 count form. All three forms contain direction-dependent
negation. This does not establish identical motion profiles or operating limits.

The current immediate-write extractor only sees a load/zeroing instruction
immediately followed by a store. A zero shared across two consecutive stores
can therefore produce `edcc=0 edcd=-`, even though both registers are written.
The `-` denotes missing recognized immediate evidence, not an unwritten register.

### FEC0: distinguish diagnostic selection from bit 0

In that XD04 image, file 0x1280a6..0x12811c updates FEC0 bits 3:4 using
`AND E7`, then selects 00, 08 and 10. The corresponding 32-bit FEC4 reads are
directly labeled by embedded OEM strings `CRCVAL from Host`,
`CRCVAL from InputData` and `CRCVAL from OutputData`. FEC4 contains the CRC
result; FEC0 selects its source. CRC results and this diagnostic selection do
not independently establish hardware identity.

The family distinction 86/87 is **bit 0**, which this CRC-source finding does
not explain. TD01 1.03 clears bit 0 at decoded file 0x00952c; TD02 0.05e sets
it at 0x0ef860. The UD04 Kernel also clears and sets it in its host-interface
state machine (file 0x37c2/0x37d8 and 0x383c). These prove firmware control,
not an immutable identification value, but do not yet establish the bit's
exact role or its relevance to different host-interface hardware.

Further tracing narrows bit 0 to SATA link-state handling. UD04 1.14 Kernel
component key
`36996326ae5eaa369ef34a8434514ca137b31a3f144af0955c2d12f4a8b2ea83`
reads FEFC, FEFD and FEFE into object offsets 0x20, 0x21 and 0x22 at file
0x36fa..0x3712, then masks them with the inverses of FF00, FF01 and FF02.
The bit-0 clear at 0x37c2 is conditional on object+0x21 bit 2; the clear at
0x37d8 is conditional on object+0x21 bit 3; the set at 0x383c is conditional
on object+0x22 bit 1. Thus these are masked hardware-event branches, not
unrelated calls which happen to occur near host code.

The homologous XD04 1.20 Normal branches carry OEM text: object event bit
2 at file 0x127a32..0x127a46 logs `PMREQ`, with `_P` and `_S` subconditions;
the ready branch at 0x127ae4..0x127af8 logs `PhyRdy`. These establish the
power-management request and PHY-ready event identities for that homolog.
Transferring those labels to the matching Kernel branch structure is an
explicit inference. The alternate bit-3 event's exact identity and the
hardware function controlled by FEC0 bit 0 remain unresolved.

A narrow aligned-instruction scan of all 410 retained Kernels finds:

| Immediate FEC0 initialization | Kernel images | Clear on the PMREQ-form event | Clear on alternate bit-3 event | Set on the PHY-ready-form event |
|---|---:|---|---|---|
| C6 | 101 | Yes | No | Yes |
| C7 | 64 | Yes | Yes | Yes |
| 87 | 135 | No | Yes | Yes |

These 300 images all contain the same audited event-bit test followed by a
direct FEC0 bit-0 set. Another 11 have an older clear-only form and 99 have
neither recognized form; neither group is assumed to lack equivalent logic.
The counts describe these exact compiler signatures, not complete reachability
or physical execution. They do not justify assigning an invented enable-bit
name. C6 firmware can set the bit at runtime despite initializing it clear.
The initial value and event policy travel together; replacing this field
with a host/link requirement is a stronger direction than calling it a fixed
hardware ID, but the requirement is not sufficiently understood to enforce.

Paired retained Kernel/Normal immediate writes were also checked for UD04,
XD04, XU03JM, XS06JM and XS07JM packages: each pair agrees on its initial
FEC0 value (UD04 C7, the checked others C6). This is consistent initialization
across components, not evidence of an accidental Kernel/Normal mismatch.

### FE94: a shared-constant extraction gap, with zero relationship changes

A broader read-only scan covered all 700 decoded Normal images (including
validated expanded COMP regions) and 410 Kernels. The audited direct-reference
forms found 521 Normal and 337 Kernel byte writes to FE94. No byte read,
word access, bit operation, full-address literal or word-immediate pointer
candidate was found in those forms. This does not exclude addresses computed
indirectly or other unrecognized instruction forms, and it does not assign
a physical meaning to FE94.

Ten Normal images and four Kernels contain an initialization write missed
by the existing adjacent-load extractor. They execute:

```text
MOV.B #40,R1L
MOV.B R1L,@FE9D
MOV.B #01,R0L
MOV.B R0L,@FE9F
MOV.B R1L,@FE94
```

R1L still contains 40 at the final store. The intervening operations only
write R0L and FE9F; they do not change R1L. For example, TD04 1.01 Normal
key `ff6dbac35aa954dc1f5102bb52cce7baf0ae7b3b6648852c6e923e341459b3a8`
has this exact block at file 0x101d78..0x101d84. The current `fe94=-` means
"not recovered by the immediate-adjacency signature", not that FE94 is
uninitialized. The recovered value is 40.

The ten Normal images cover BDR/BDC-TD04, BDR-US01, BD-W26SS-B and BDR-206M
variants. Resolving these ten values was audited against all 531 recognized
packages: 281,961 directed comparisons including self-pairs; zero added
matches, zero removed matches, and 21 families before and after. This audit
compares family relationships only; it does not claim a settings/receiver
admission replay. Three legacy family keys would serialize differently if
the recovered values were inserted directly, despite unchanged relationships.

This is a concrete improvement for the proposed richer evidence layer:
show the actual recovered initialization and its source, while retaining
the legacy key projection until an explicit family-ID migration. There is
no reason to force a family merge to correct the displayed evidence.

### E46B: loading-type hypothesis ruled out

The OEM feature-0003 callback builds the removable-medium descriptor. Its
loading-type getter supplies descriptor byte 4 bit 5. In XD04, the feature
table is at file 0x21845c, callback at CPU address 0x460394, and getter at
0x5e75c8. The table consumer reads the requested feature and allocation length
from the CDB, invokes the descriptor callbacks and assembles the response.
The getter's constant return is independently visible in each image below.

| Firmware | E46B | Native loading mechanism type |
|---|---:|---|
| XD04 1.20 | 12 | 1: tray |
| UD04 1.14 | 01 | 1: tray |
| XU03JM 1.04 | 01 | 0: caddy/slot |
| XS06JM 1.10 | 12 | 0: caddy/slot |

The audited builder/getter form is recognized in 509 of 530 images; 21 remain
unclassified by this narrow extractor. Both loading-type values occur with
E46B=01 and E46B=12. The exact meanings of 01 and 12 remain unresolved; do not
rename them as loading types or infer voltage/timing semantics without proof.

### FFC5: interrupt setup, exact field semantics still open

UD04's FFC5 bit-5 clear is bracketed by source-mask handling for 0x200040 and
CPU interrupt configuration. Its source handler acknowledges FFEA and changes
FFDA masking; the corresponding callback masks that same source again.
Executable dispatchers read status, apply the masks, and dispatch individual
event bits. XS06JM has a homologous setup with FFC5 bit 7 and different
CPU-side interrupt configuration. BD-W26SS-B explicitly programs adjacent
two-bit fields in FFC4/FFC5. These facts establish interrupt-related context;
they do not yet identify trigger mode, routing, edge polarity, or a physical pin.

The E4 register-window assertion code references the embedded OEM source path
`Share/Driver/Hardware/Indigo5/CDsp.cpp`. That establishes a native hardware/DSP
abstraction, not the individual E4 field names. Diagnostic labels above come
from OEM firmware text and verified references; analysis headings such as
"ASIC setup" and "Board markers" are not manufacturer-provided register names.

### FFC5: corresponding mechanism inputs differ too

The 101 packages in the first FFC5-only merged group have a second,
independently observed distinction. All 20 XS05/XS06 images read primary
input `FF414100 bit 1`; all 81 AD07/AD08, XD05–XD08 and XS07/XS08 images
read primary input `FF414000 bit 0` in the corresponding state predicates.
In the slot-reporting subset, both generations also read FDCD bits 0 and 4.
Those three inputs feed complementary all-high/all-low predicates used by
the loading/mechanism state initialization. The 61 tray-reporting images in
the newer family use a single-input predicate instead. Requiring equality
of the entire predicate would therefore split an existing family.

Representative XS06JM 1.10 Normal key
`a8bb925d36812558d1d81f87bd0585005597f5dd67f2d34bbfd30e8a9a476f04`
has the primary getter at file 0x162cd0. XS07JM 1.04 Normal key
`032f07365f164221cb31f6bbe5a50e6fd843e66d85d9e3b0313a7ed31ffc6846`
has its getter at 0x1648d6. Their I/O initialization additionally sets versus
clears FDD8 bit 0 (file 0x162ab6 versus 0x1646bc). That distinction holds
across the same 20 versus 81 packages. FDD8's exact electrical function is
unresolved; do not label it voltage, pull-up or direction without evidence.

XD04 provides an independently labeled consumer: file 0x1b26ea calls
CPU 0x5f3d98, which calls the `FF414000 bit 0` getter at CPU 0x5f3c6c.
The high-input branch loads OEM text `%sTRAYOPEN SW -> High` at file
0x1b2702 (string CPU address 0x6599b4). This identifies that input as the
tray-open switch in XD04. It does not establish the exact physical signal
name or wiring in every slot-loading model.

The XS06/XS07 FFC5 initialization also changes CPU interrupt flag/enable
selection and priority register, while retaining source mask 0x200040.
This is evidence for retaining the distinction pending a validated input-map
replacement. It does not prove that FFC5 itself is a board identifier.
An independent-input Boolean model differs for four of 16 input states;
that is a derived predicate comparison, not CPU emulation or a hardware test.

Compact firmware log arguments in the 0x90xxxx/0x92xxxx ranges are numeric
log IDs, not assumed string pointers. The audited UD04 logger serializes
the low three bytes into its record without dereferencing them. Only actual
OEM strings with traced consumers support the semantic labels above.

## Proposed filtering design: preserve current decisions first

The first implementation adds `image::family_evidence`, independent register
observations and selectable `FamilyCriterion` comparisons. It retains scheme
v5's identity projection. Shared constants are recovered in observations and
`FamilyFingerprint::raw_pins`; legacy key fields remain stable. This does not
replace the current flash admission policy.

A Rust API replay of all 700 retained Normal images preserves every recognized
family ID and all legacy key fields. All 531 recognized packages pass 281,961
directed comparisons including self-pairs: zero added or removed family matches,
21 families. Exactly ten raw-pin diagnostic records change, recovering FE94=40.
Unrecognized images remain unrecognized. Settings/receiver execution is not
claimed by this family-only audit.

The implementation principles are:

1. Extract evidence once, preserving raw register operations, masks, decoded
   region/offset, consumer context and recognition status. Give each field
   its own comparison result and reason. An unrecognized form is explicitly
   unclassified evidence; it must not be presented as a confirmed match.
2. Keep the existing v5 key and normalization as the authoritative policy
   during migration, including its present treatment of absent evidence.
   The richer evidence does not silently alter admission. Preserve legacy
   serialization so a structural refactor does not rekey family IDs.
3. Present separate checks: the seven E4 initialization fields; FFC5
   interrupt configuration; EDCC/EDCD collimator-command evidence; FE94 host
   initialization; FEC0 bit fields; and existing servo evidence. Replace
   the misleading collective label "Board markers" with these specific
   labels. E4 fields retain address names where their meanings are unknown.
4. Add mechanism input maps, FDD8 observations and OEM loading capabilities
   as explanatory evidence initially. Do not add tray/slot equality as a
   gate: it would split existing matches. Do not substitute the new input
   extractor for FFC5 until other groups/compiler forms are covered.
5. Keep startup requirements, validated settings conversion and transport
   feasibility as separate admission checks after family comparison. A
   family match does not imply that a usable flash route exists. The CLI,
   GUI and website should consume the same comparison and planning results.
6. Replay the complete corpus and compare every before/after pair, exact
   family ID and plan outcome. Acceptance is zero added/removed matches and
   zero changed admission outcomes, rather than merely the same family count.

Servo comparison stays unchanged through this refactor. Missing legacy
anchor evidence must be described honestly; expanding to newly identified
servo consumers is a separate policy change with its own pairwise audit.

## Recommended removals and outcome-changing candidates

**Strongest semantic removal: EDCC/EDCD as family criteria.** These are
collimator commands, and incidental immediate constants are a poor hardware
identity test. Removing both currently adds zero pairs and leaves 21 families.
Keep them in diagnostics. Changing the serialized key still needs an explicit
scheme/ID migration; do not combine that with the initial structural refactor.

**FE94 is the first outcome-changing candidate to investigate.** Removing
it alone joins BDR/BDC-TD01 and TD01RS variants with TD02 0.05e: eight directed
package pairs, 21 to 20 families. The writes occur in host initialization,
but their exact physical effects remain unknown. This is a small reviewable
candidate, not a justified production removal yet.

**The combined FE94/FEC0 family gate is a candidate for replacement by
specific host/settings requirements.** Omitting both joins three groups:
XD04 with BDR/BDC-TD05 (64 pairs); XU02/XU03 variants with UD02D/UD03/UD04,
SlimtypeEB1 and SBC-06D2X-U/SBW-06D2X-U (176 pairs); and the TD01/TD02 group
above (eight pairs). Total: 248 additional directed package pairs across
36 packages, 21 to 18 families. These counts include both directions and
firmware versions. They are not counts of newly executable crossflashes.
FEC0 bits 3:4 have a diagnostic-source role, but that does not explain the
86/87 bit-0 difference. Validated settings conversions must remain enforced,
including restrictions on native versus previously adapted mechanisms.

**Do not remove FFC5 now.** It would add 3,258 pairs, joining XS05/XS06
with the newer AD/XD/XS group, and TD04 with US01/W26. The independent
mechanism-input changes above support a real distinction in the first
group. The TD04/US01/W26 group still needs equivalent consumer tracing.
Likewise, do not remove the E4 block or servo gate on current evidence.
Individual-field redundancy does not justify deleting a jointly separating
block: deleting all E4 fields would add 6,966 pairs.

The semantic audit is therefore sufficient to specify the refactor and
prioritize candidate policy changes. It does not establish every bit's
physical meaning or validate those proposed family mergers.

## Retained evidence

Private evidence: `freemkv-private/research/pioneer-registers-20261101/`.
Contains original 723-package fingerprints, comparison results, disassembly
contexts and four hash-bound Kernel/Normal probe pairs. Inputs were decoded
using pioneer-optical c8fbc1581cb29c99e929291d24c8ac616b0cf778.
Raw firmware and archives remain private; do not add them to the public crate.

Additional read-only evidence is retained in
`freemkv-private/test-runs/pioneer-other-setup-ablation-20261101/`:
`REGISTER-SEMANTICS.md`, `family-field-impact.json`,
`collimator-writer-expanded-coverage.json`,
`native-loading-mechanism-inventory.json`, `kernel-register-candidates.json`,
the three reproducible Python inventory scripts, and bounded disassembly
contexts. The Python COMP-region decoder was compared byte-for-byte with the
existing Rust analysis exports: 54 regions across six representative images
match. No production matching change, bit-flip firmware, or physical test was
made during this semantic audit.

Further evidence: `scan_kernel_fec0_link.py` and its
`kernel-fec0-link-signatures.json` output, the broader raw
`kernel-fec0-bit0-link-transitions.json` inventory, and
`paired-kernel-normal-fec0-immediates.json`. The first script classifies only
the audited immediate event-test forms and leaves other forms unclassified.

FE94 follow-up: `scan_fe94_accesses.py`, `fe94-access-candidates.json`,
`audit_fe94_recovered_values.py` and `fe94-recovery-family-impact.json` retain
the expanded-region inventory, exact shared-constant recovery signature and
complete recognized-package pair comparison. The scanner reports candidate
instruction forms; the shared-constant sequence was independently disassembled.

# Hardware matrix notes (not rules)

These notes were moved out of the hand-maintained `Pioneer-Hardware-Matrix.html`
when the page became generated from code (`examples/hardware_matrix`, see
[hardware-matrix.md](hardware-matrix.md)). They are research notes, audit
history and evidence summaries. **They are not rules and nothing here is
enforced.** The rules are declared beside the code that enforces them
(`Filter::rules()` in each `src/filters/*.rs` owner and
`filters::identity::{PARTITION, RULES}`) and the generated page renders only
those. Where a note below disagrees with the code, the code is authoritative.

## What moved where

Since 1.6.0, SAT9 startup inputs are identified by the tray input predicates,
as on SAT8. The SAT9 E46B values that the hand-made page grouped on are now
evidence only, so every SAT9 family identifier changed.

| Hand-made page section | Now |
| --- | --- |
| Header stats, families, groups, matrix, compare, all firmware, SAT compare | Generated from the registered filters and `identity::discover` |
| Per-filter name, role, description, correction policy | Generated from `Filter::name()` and `Filter::rules()` |
| Per-platform value groupings with counts, typed values and evidence | Generated from each image's registered findings |
| Reference comparisons (the "KAT" controls) | Generated: listed in `examples/hardware_matrix/page.rs` (`CONTROLS`) and evaluated against the generated families. They are reported, not enforced |
| Revision consistency check | Generated |
| Per-platform intro paragraphs and per-filter "How this is determined" prose in the Hardware key | Moved here (archived text below) |
| "When 0xFE09 is accepted" (BDX-PR1UAME 2.05 predicate) | Moved here. The code enforces the general rule ("0xFE23 unconditionally, 0xFE09 only with the complete bound predicate"); the per-firmware ranges are research detail |
| "Can a difference be converted?" overview, SAT1/SAT8/SAT9 conversion evidence, "Bank, phase and 0x009F" | Moved here |
| Embedded `report-data` research/audit blobs: `sat1PhaseAudit`, `sat1FilterNativeAudit`, `filterConvertibility`, `conversionProfileReplay`, `bankAndPhaseConversion`, `hostConfigConversionTrace`, `normalOnlyFilterAudit`, `normalPhaseAssignmentAudit`, `normalStartupProofProgress`, `sat1/sat9/r0/r1StartupProofProgress`, `ataNativeAudit`, `legacyNativePartialAudit`, `archive`, per-image `startup009f` traces, `phaseCorrectionPolicy`, `platformPolicy`, `platformInputPolicy`, `inputContractPolicy`, historical v1/v2 `groupHashes` | Dropped from the page. The policy strings are now code rules; the audits remain in the archived hand-made HTML and the private evidence directories it cites |
| Embedded `persistent-layout-data`, `all-platform-layout-data`, `v850-input-data` | Dropped; superseded by the layout and loading filters' per-image findings |
| Embedded `signoff-data`, `sat8000-servo-evidence`, `sat8000-storage-evidence`, `sat8000-afe-evidence` | Dropped; no page script read them |
| `file:///` links to private evidence (FE94 correction proof, selected pair routes) | Dropped; they only resolve on the owner's machine |

## Statements that conflict with the code

The hand-made page carried these statements; the 1.6.0 code does not enforce
them (see CHANGELOG 1.6.0):

- SAT1 phase: "Correctable in Normal across all 13 native forms." The phase owner
  suspends every SAT1 phase correction (`mechanism_gate`): any assignment change
  refuses.
- SAT1 phase: "Phase remains in both published family keys." The matching
  (candidate) family drops the assignment for H8 programs with a complete paired-word
  grammar; only the as-is identity keeps it.
- SAT8/SAT9 phase: historical exact-image recipes are replaced by the phase
  filter's native mechanism composition. Differing bound bundles can be corrected
  with OEM instructions/tables and read-only prerequisites. The complete update
  still requires every other filter; XS08U and XD08 have different tray inputs.
  Native reference conversion evidence does not establish every family-wide pair.
- Startup: historical neutral FFFF selection and persistent word transactions
  are superseded by filter-owned image correction and read-only prerequisites.
  Missing native evidence remains a refusal.
- Persistent parameter layout: "A conditional Normal-only address-equivalence
  engine exists" and the "Normal-only address corrector accepts only variants..."
  prose. Layout is never corrected; that corrector was removed.
- Bank conversion "layout candidate" prose (212U/213U). The bank conversion was
  removed. Differing storage contracts refuse under every policy.

## Archived text from the hand-made page

The text and counts below describe the historical 722-image page and are not
current admission or correction rules. The generated page recomputes every count
and reads its current policies directly from the filter owners.

All seven filters run on every image. Two correction types apply to the held firmware: phase and H8 startup word 0x009F. Required hardware unknowns produce no family ID; startup requirements are planned separately. Counts are distinct Normal images.

#### SAT1xxx

All 73 phase assignments are extracted from Normal: 72 direct, 1 swapped. Geometry and persistent-layout observations use the exact paired Kernel where the native code is resident; a missing required Kernel stays unresolved. Full waveform validation remains separate.

73 distinct Normal images.

**Persistent storage geometry**

_Required hardware field; native value compared._

Identifies the persistent bank markers, locations and spacing used by the firmware. Addresses, marker constants, record widths and bank spacing are different quantities. This observation does not specify a complete calibration record schema. Marker and spacing are hexadecimal: FEDC4321/10000 means marker 0xFEDC4321 and bank spacing 0x10000 bytes (65,536); FEDC4322/C000 means marker 0xFEDC4322 and spacing 0xC000 bytes (49,152). Native-bank variants specify two CPU bank bases and their byte spacing; no footer marker is inferred. Persistent storage geometry identifies the storage banks, selectors and spacing. Persistent parameter layout identifies the parameter addresses, record sizes, headers and value encoding within that storage. Matching geometry does not imply matching parameter layout; neither field alone specifies every calibration value.

**Startup inputs / initialization**

_Native finding evaluated on every image; see its registered role._

Identifies the input states or initialization values used during startup. The representation is platform-specific; a summary flag is not a register value to write. For an immediate E46B write, retain the full u8 immediate and report immediate & 0x11. This projection selects bits 4 and 0 only. Legacy init is a separate recognized initialization program, not zero. This registered native value is included in the hardware identity on every platform.

**Host interface setup**

_Native finding evaluated on every image; see its registered role._

Identifies the host-interface register settings written by the firmware. H8 platforms report a masked FE94 initialization value; ATA and SCSI report architecture-specific register mappings. These representations are not interchangeable. Track the byte register value through the FE94 store, including nonadjacent stores, and report full_value & 0x80. 0x00 means bit 7 clear; 0x80 means bit 7 set. Neither is necessarily the full register value. The legacy host program is a separate program variant. The precise peripheral effect of bit 7 is not established.

**Loading input / interrupt setup**

_Required hardware field; native value compared._

Identifies the loading input, interrupt-register operation or installed callback used by the firmware. Preserve the variant tag: matching text or numbers across different variants does not establish equality. For FFC5, encode the resulting u8 transformation as new = (old & preserve_mask) | set_bits. Write 0x20 uses mask 0x00/set 0x20; clear bit 5 uses mask 0xDF/set 0x00; clear bit 7 uses mask 0x7F/set 0x00. An input predicate instead carries address encoding, address, bit and required level. Vector routes retain RAM pointer-slot addresses and callback behavior; old V58/V60 labels mean hexadecimal slots 0x58/0x60, not decimal interrupt numbers.

**Persistent parameter layout**

_Required match for held layouts. Address correction requires whole-program proof._

Locates primary parameter words 0x0000–0x009F in absolute flash. The traced layouts use 40 records of 320 bytes and an 80-byte header.

**How this is determined**

Persistent storage geometry identifies banks, selectors and spacing. This filter identifies the parameter addresses and record format within that storage. Matching geometry does not imply matching parameter layout.

Native readers were exercised for all 160 primary words at every header position in 70 images. Six layouts are established through their exact Kernel-owned reader. Three other images call an exact Kernel getter that is not held; their layout is unresolved.

All 64 held images with primary records at 0x7F0000 contain non-erased decoded Normal payload bytes in 0x5E0000–0x5E3250 (end exclusive), the older primary-record area. Redirecting those readers to 0x5E0000 would point into the target Normal payload. Matching record dimensions do not make this a safe address-only correction: target program bytes and retained records must both be preserved. This is a decoded-address comparison, not a device-flash experiment.

Compare the exact typed layout. An unresolved layout produces no family ID; it does not match another unresolved layout. This filter is retained when phase is corrected. No held layout pair on this platform meets the two-way correction contract. The Normal-only address corrector accepts only variants with the exact unchanged Kernel, equal record formats and complete program equality after bounded native address edits and independently proven phase normalization. That complete equality preserves every read, write, erase, initialization and bank-selection path. It moves no retained data and changes no Kernel code.

**Correctable filters**

**Phase output assignment**

_Correctable in Normal across all 13 native forms. Complete-file integrity and exact Kernel requirements still apply._

Direct (0) assigns source element 0 to the first output; swapped (1) assigns it to the second. Complete native operand and reverse-correction proof covers all 73 SAT1 images across 13 forms, including their distinct legacy output indices. Fifty-eight checksum-valid original files pass complete correction plans, decoded-image checks and codec reversal. Fifteen invalid standalone files without an associated Kernel refuse preparation; file integrity remains a separate requirement from a native hardware identity. Native edits change Normal, then the codec repairs integrity and authentication as required. Phase remains in both published family keys; the planner can correct an individual phase difference when every other required filter and output interface agrees.

**Startup prerequisite**

_Native finding evaluated on every image; see its registered role._

Specifies the parameter value or condition that Normal requires at startup; it does not report the value stored in a connected drive. Fixed requirements, conditional requirements, no fixed comparison within an audited scope, and missing evidence are distinct typed results. Startup selection uses the bound firmware-required word when recognized; otherwise it deliberately selects the neutral word 0x009F = 0xFFFF. Recognized but unbound or ambiguous comparisons refuse selection. The update reads the actual word, changes it only when needed and verifies the selected value; rollback retains the actual before-value.

#### SAT8xxx

391 distinct Normal images.

**Persistent storage geometry**

_Native finding evaluated on every image; see its registered role._

Identifies the persistent bank markers, locations and spacing used by the firmware. Addresses, marker constants, record widths and bank spacing are different quantities. This observation does not specify a complete calibration record schema. Marker and spacing are hexadecimal: FEDC4321/10000 means marker 0xFEDC4321 and bank spacing 0x10000 bytes (65,536); FEDC4322/C000 means marker 0xFEDC4322 and spacing 0xC000 bytes (49,152). Native-bank variants specify two CPU bank bases and their byte spacing; no footer marker is inferred. Persistent storage geometry identifies the storage banks, selectors and spacing. Persistent parameter layout identifies the parameter addresses, record sizes, headers and value encoding within that storage. Matching geometry does not imply matching parameter layout; neither field alone specifies every calibration value.

**Startup inputs / initialization**

_Required hardware field; native value compared._

Identifies the input states or initialization values used during startup. The representation is platform-specific; a summary flag is not a register value to write. The u8 summary is (reads FDCD absolute16 bit 0 ? 4 : 0) | (reads FF414000 bit 7 ? 2 : 0) | (reads FF414100 bit 4 ? 1 : 0), derived only from the validated closed/open predicates. 0x00 means none of those three selected features, not no input reads. Preserve every address, bit, required level and AND relation in the full predicate; 0x04 represents two different full predicates.

**Host interface setup**

_Required hardware field; native value compared._

Identifies the host-interface register settings written by the firmware. H8 platforms report a masked FE94 initialization value; ATA and SCSI report architecture-specific register mappings. These representations are not interchangeable. Track the byte register value through the FE94 store, including nonadjacent stores, and report full_value & 0x80. 0x00 means bit 7 clear; 0x80 means bit 7 set. Neither is necessarily the full register value. The legacy host program is a separate program variant. The precise peripheral effect of bit 7 is not established.

**Loading input / interrupt setup**

_Required hardware field; native value compared._

Identifies the loading input, interrupt-register operation or installed callback used by the firmware. Preserve the variant tag: matching text or numbers across different variants does not establish equality. For FFC5, encode the resulting u8 transformation as new = (old & preserve_mask) | set_bits. Write 0x20 uses mask 0x00/set 0x20; clear bit 5 uses mask 0xDF/set 0x00; clear bit 7 uses mask 0x7F/set 0x00. An input predicate instead carries address encoding, address, bit and required level. Vector routes retain RAM pointer-slot addresses and callback behavior; old V58/V60 labels mean hexadecimal slots 0x58/0x60, not decimal interrupt numbers.

**Persistent parameter layout**

_Required match. Not correctable._

Locates retained settings and calibration words 0x0000–0x009F and determines their record layout in writable flash. A mismatch makes unchanged Normal read a different location or select the wrong record. Changing 0x009F alone does not correct this layout.

**How this is determined**

Persistent storage geometry identifies the storage banks, selectors and spacing. Persistent parameter layout identifies the parameter addresses, record sizes, headers and value encoding within that storage. Matching geometry does not imply matching parameter layout; neither field alone specifies every calibration value.

All 391 SAT8 Normal images resolve to one of the two layouts shown. Both contain a 320-byte active payload: 160 little-endian 16-bit words. Each record has a two-byte header entry. Scan the even header bytes until the first 0xFF and select the preceding record; select record 0 if the first entry is 0xFF, or the last record if the header is full.

What breaks: unchanged Normal reads from its own expected location and uses its own record geometry. In the examined BDR-209 1.51 → PR1ML 1.73 direction, 0xFF01 at the 209 location for word 0x009F does not satisfy PR1ML when its separate 0x7F0000 area is erased. PR1ML reads 0xFFFF and enters the Kernel loader. This is a native-code counterexample with constructed storage, not a captured drive failure. The reverse direction has no equivalent proven 0x009F boot gate.

Not correctable: no data migration or Normal patch is supported by this filter. The two layouts differ in location, header length and record capacity. Native writes and cleanup also depend on the storage layout and can affect other parameter groups. Isolated payload conversion does not prove safe overwriting, preservation of neighboring data, or equivalent meanings for every word. A read-address patch does not correct writes and cleanup. This is an implementation restriction, not a claim that future correction is impossible.

Code contract: extract from decoded Normal and bind the getter, parameter resolver, record resolver, header scanner and address mapper. Return a typed known layout only when the complete primary read path is recognized unambiguously. Missing, partial or contradictory evidence returns Unresolved or Conflicting; neither produces a candidate ID. Compare the complete typed tuple exactly and retain it when phase is normalized. Do not infer a layout from a model name, SAT number, bank marker or 0x009F value.

Scope: primary logical words 0x0000–0x009F only. The filter does not certify the rest of persistent storage or authorize flashing. SAT8000 separates from SAT8301/8600/8680/8800; all other existing SAT8 memberships remain unchanged. SAT8130 shares the absolute layout but stays separate through other filters.

**Correctable filters**

**Phase output assignment**

_Correctable in Normal. Automatic native-code detection; retained in as-is keys and normalized only for supported correction plans._

Identifies which source word supplies each output: direct (0) or swapped (1). Automatic correction binds both native output functions, changes only their proven output-register operands to match the installed drive, updates the Normal checksum, and re-extracts the complete family key. Servo data and persistent parameters stay in place. All other required filters must match. Specialized mechanism adaptations retain their separate prerequisites. The paired SAT8/SAT9 proof covers all 457 native operand reversals and original file wrappers. With exact associated Kernels, 346 checksum-valid files pass complete signed correction plans, reversal and idempotence; decoded bytes match the independent oracle and wrapper changes stay within the signature block. The other 111 original files have invalid sums without their exact Kernel and refuse preparation. A matching group does not waive complete-file integrity or authentication.

**Startup prerequisite**

_Native finding evaluated on every image; see its registered role._

Specifies the parameter value or condition that Normal requires at startup; it does not report the value stored in a connected drive. Fixed requirements, conditional requirements, no fixed comparison within an audited scope, and missing evidence are distinct typed results. Startup selection uses the bound firmware-required word when recognized; otherwise it deliberately selects the neutral word 0x009F = 0xFFFF. Recognized but unbound or ambiguous comparisons refuse selection. The update reads the actual word, changes it only when needed and verifies the selected value; rollback retains the actual before-value.

#### SAT9xxx

66 distinct Normal images.

**Persistent storage geometry**

_Required hardware field; native value compared._

Identifies the persistent bank markers, locations and spacing used by the firmware. Addresses, marker constants, record widths and bank spacing are different quantities. This observation does not specify a complete calibration record schema. Marker and spacing are hexadecimal: FEDC4321/10000 means marker 0xFEDC4321 and bank spacing 0x10000 bytes (65,536); FEDC4322/C000 means marker 0xFEDC4322 and spacing 0xC000 bytes (49,152). Native-bank variants specify two CPU bank bases and their byte spacing; no footer marker is inferred. Persistent storage geometry identifies the storage banks, selectors and spacing. Persistent parameter layout identifies the parameter addresses, record sizes, headers and value encoding within that storage. Matching geometry does not imply matching parameter layout; neither field alone specifies every calibration value.

**Startup inputs / initialization**

_Native finding evaluated on every image; see its registered role._

Identifies the input states or initialization values used during startup. The representation is platform-specific; a summary flag is not a register value to write. For an immediate E46B write, retain the full u8 immediate and report immediate & 0x11. This projection selects bits 4 and 0 only. Legacy init is a separate recognized initialization program, not zero. This registered native value is included in the hardware identity on every platform.

**Host interface setup**

_Required hardware field; native value compared._

Identifies the host-interface register settings written by the firmware. H8 platforms report a masked FE94 initialization value; ATA and SCSI report architecture-specific register mappings. These representations are not interchangeable. Track the byte register value through the FE94 store, including nonadjacent stores, and report full_value & 0x80. 0x00 means bit 7 clear; 0x80 means bit 7 set. Neither is necessarily the full register value. The legacy host program is a separate program variant. The precise peripheral effect of bit 7 is not established.

**Loading input / interrupt setup**

_Native finding evaluated on every image; see its registered role._

Identifies the loading input, interrupt-register operation or installed callback used by the firmware. Preserve the variant tag: matching text or numbers across different variants does not establish equality. For FFC5, encode the resulting u8 transformation as new = (old & preserve_mask) | set_bits. Write 0x20 uses mask 0x00/set 0x20; clear bit 5 uses mask 0xDF/set 0x00; clear bit 7 uses mask 0x7F/set 0x00. An input predicate instead carries address encoding, address, bit and required level. Vector routes retain RAM pointer-slot addresses and callback behavior; old V58/V60 labels mean hexadecimal slots 0x58/0x60, not decimal interrupt numbers.

**Persistent parameter layout**

_Required match for held layouts. Address correction requires whole-program proof._

Locates primary parameter words 0x0000–0x009F relative to the selected storage bank: offset 0x5984 or 0x9984, with 20 records of 320 bytes and a 40-byte header.

**How this is determined**

Persistent storage geometry identifies banks, selectors and spacing. This filter identifies the parameter addresses and record format within that storage. Matching geometry does not imply matching parameter layout.

Native readers were exercised for all 160 primary words at every header position in all 66 images. Both selected banks were checked. The 0x5984 layout accompanies 0xC000 bank spacing; 0x9984 accompanies 0x10000 spacing. Bank spacing remains a separate geometry input. Logical word 0x01A0 also resolves to selected-bank offset 0x4352 in all 29 primary-0x5984 images, versus 0x8352 in all 37 primary-0x9984 images. Changing only the primary address would leave that secondary domain and the independent bank geometry inconsistent.

Compare the exact typed layout. An unresolved layout produces no family ID; it does not match another unresolved layout. This filter is retained when phase is corrected. No held layout pair on this platform meets the two-way correction contract. The Normal-only address corrector accepts only variants with the exact unchanged Kernel, equal record formats and complete program equality after bounded native address edits and independently proven phase normalization. That complete equality preserves every read, write, erase, initialization and bank-selection path. It moves no retained data and changes no Kernel code.

**Correctable filters**

**Phase output assignment**

_Correctable in Normal. Automatic native-code detection; retained in as-is keys and normalized only for supported correction plans._

Identifies which source word supplies each output: direct (0) or swapped (1). Automatic correction binds both native output functions, changes only their proven output-register operands to match the installed drive, updates the Normal checksum, and re-extracts the complete family key. Servo data and persistent parameters stay in place. All other required filters must match. Specialized mechanism adaptations retain their separate prerequisites. The paired SAT8/SAT9 proof covers all 457 native operand reversals and original file wrappers. With exact associated Kernels, 346 checksum-valid files pass complete signed correction plans, reversal and idempotence; decoded bytes match the independent oracle and wrapper changes stay within the signature block. The other 111 original files have invalid sums without their exact Kernel and refuse preparation. A matching group does not waive complete-file integrity or authentication.

**Startup prerequisite**

_Native finding evaluated on every image; see its registered role._

Specifies the parameter value or condition that Normal requires at startup; it does not report the value stored in a connected drive. Fixed requirements, conditional requirements, no fixed comparison within an audited scope, and missing evidence are distinct typed results. Startup selection uses the bound firmware-required word when recognized; otherwise it deliberately selects the neutral word 0x009F = 0xFFFF. Recognized but unbound or ambiguous comparisons refuse selection. The update reads the actual word, changes it only when needed and verifies the selected value; rollback retains the actual before-value.

#### SCSI0001

Two legacy M7900 images. Native observations are documented; both remain solo while their full contracts are incomplete.

**Persistent storage geometry**

_Required hardware field; native value compared._

Identifies the persistent bank markers, locations and spacing used by the firmware. Addresses, marker constants, record widths and bank spacing are different quantities. This observation does not specify a complete calibration record schema. Persistent storage geometry identifies the storage banks, selectors and spacing. Persistent parameter layout identifies the parameter addresses, record sizes, headers and value encoding within that storage. Matching geometry does not imply matching parameter layout; neither field alone specifies every calibration value.

**Startup inputs / initialization**

_Required hardware field; native value compared._

Identifies the input states or initialization values used during startup. The representation is platform-specific; a summary flag is not a register value to write.

**Host interface setup**

_Required hardware field; native value compared._

Identifies the host-interface register settings written by the firmware. H8 platforms report a masked FE94 initialization value; ATA and SCSI report architecture-specific register mappings. These representations are not interchangeable.

**Loading input / interrupt setup**

_Required hardware field; native value compared._

Identifies the loading input, interrupt-register operation or installed callback used by the firmware. Preserve the variant tag: matching text or numbers across different variants does not establish equality.

**Persistent parameter layout**

_Required match. Not correctable._

Maps eight selected parameter slots to serial word sets based at 0x220 and 0x260, with header word 0x256. Slot indices are 8, 10, 11, 9, 12, 0, 1, 2.

**How this is determined**

Persistent storage geometry identifies banks, selectors and spacing. This filter identifies the parameter addresses and record format within that storage. Matching geometry does not imply matching parameter layout.

Both images have bound loader, selector and serial-reader bytes. This contract covers the traced parameter slots, not the complete EEPROM schema.

Compare the exact typed layout. An unresolved layout produces no family ID; it does not match another unresolved layout. This filter is retained when phase is corrected. No data migration or layout correction is supported.

**Phase output assignment**

_Required hardware field; native value compared._

Describes the source order supplied to the legacy sled-controller outputs. Preserve the actual controller indices and their order. This observation does not establish physical motion direction or authorize a correction. The 0x30/0x33 indices require their own complete native consumer contract; the later 0/1 assignment ABI does not apply unchanged.

**Startup prerequisite**

_Native finding evaluated on every image; see its registered role._

Specifies the parameter value or condition that Normal requires at startup; it does not report the value stored in a connected drive. Fixed requirements, conditional requirements, no fixed comparison within an audited scope, and missing evidence are distinct typed results. No recognized comparison is never an instruction to write 0xFFFF.

#### ATA

190 Normal images: 99 M32C, 71 V850E and 20 legacy M7900. Incomplete native contracts remain solo. Source evidence distinguishes observed values from active family restrictions.

**Persistent storage geometry**

_Required hardware field; native value compared._

Identifies the persistent bank markers, locations and spacing used by the firmware. Addresses, marker constants, record widths and bank spacing are different quantities. This observation does not specify a complete calibration record schema. Persistent storage geometry identifies the storage banks, selectors and spacing. Persistent parameter layout identifies the parameter addresses, record sizes, headers and value encoding within that storage. Matching geometry does not imply matching parameter layout; neither field alone specifies every calibration value.

**Startup inputs / initialization**

_Native finding evaluated on every image; see its registered role._

Identifies the input states or initialization values used during startup. The representation is platform-specific; a summary flag is not a register value to write. M32C and V850E are architecture tags, not initialization values. Native initialization operands remain evidence. M7900 rows retain the actual setup writes and unresolved resident calls. Architecture is an independent guard in ATA keys.

**Host interface setup**

_Required hardware field; native value compared._

Identifies the host-interface register settings written by the firmware. H8 platforms report a masked FE94 initialization value; ATA and SCSI report architecture-specific register mappings. These representations are not interchangeable.

**Loading input / interrupt setup**

_Required hardware field; native value compared._

Identifies the loading input, interrupt-register operation or installed callback used by the firmware. Preserve the variant tag: matching text or numbers across different variants does not establish equality.

**Persistent parameter layout**

_Required match. Not correctable._

Identifies the native parameter record format: fixed flash records or serial word ranges. Record addresses, lengths, header tests and slot mappings must agree within the architecture.

**How this is determined**

Persistent storage geometry identifies banks, selectors and spacing. This filter identifies the parameter addresses and record format within that storage. Matching geometry does not imply matching parameter layout.

M32C flash readers test an 8-bit 0xFF header value at two-byte intervals; V850 readers test a 16-bit 0xFFFF value. The V850 primary mechanical domain is logical words 0x0160–0x01FF, mapped into the 0x1FA000 records; all 71 resolver paths and helper targets are bound. Their header counts are 8, 9 and 62 for the three-region layouts. BDR-101A uses two regions with 8 and 62 records. Serial consumers use explicit word ranges or slot mappings. Twenty-two V850 images lack the exact Kernel for an alternate read backend; thirteen legacy ATA images lack their resident parameter reader. These 35 layouts are unresolved. Arithmetic helper calls in the M32C copier were not executed by the byte-binding audit.

Compare the exact typed layout. An unresolved layout produces no family ID; it does not match another unresolved layout. This filter is retained when phase is corrected. No data migration or layout correction is supported.

**Correctable filters**

**Phase output assignment**

_Correctable in supported M32C and Kernel-bound V850 Normal files. Other native forms require a match._

Identifies which source element supplies each physical output. Direct (0) sends element 0 to the first output; swapped (1) sends it to the second. M32C correction exchanges every output-channel operand in all 99 complete native programs and repairs the format-defined checksum. Complete file correction is verified in both directions for 98 original files (86 TailKey and 12 BootKey); one BootKey file is refused without its associated Kernel. All 71 V850 output programs have native phase proof; complete file correction additionally requires the associated Kernel, complete output writer, startup metadata and native flash-checksum proof. Forty-nine exact Kernel pairs pass those checks; 22 missing-Kernel cases remain unsupported. The output interface and every other required hardware filter must still match. ATA candidate keys retain phase; correction eligibility is proved for each firmware pair. Other ATA forms retain phase until their own correction contract is established. File correction does not grant receiver transfer support.

**Startup prerequisite**

_Native finding evaluated on every image; see its registered role._

Specifies the parameter value or condition that Normal requires at startup; it does not report the value stored in a connected drive. Fixed requirements, conditional requirements, no fixed comparison within an audited scope, and missing evidence are distinct typed results. No recognized comparison is never an instruction to write 0xFFFF.

**Native architecture evidence**

M32C: direct Normal phase, host and persistent-storage consumers. V850E: recovered bus representation, paired-word output and exact native API traces. Firmware Compare includes each image’s evidence and correction limits. Matching observations are candidate families, not hardware flash signoff.

Missing measurements remain missing. Solo groups have zero cross-flashes; candidate matches are not flash approval.

**When 0xFE09 is accepted**

For BDX-PR1UAME 2.05 (SAT8801), 0xFE23 always passes this gate. 0xFE09 passes when the stored fields satisfy the rule below. Prefix comes from word 0x0190, code from 0x0191 and 0x0195, and number from 0x0192–0x0194.

- SC + DLSP: 900001–900012

- TA + DLSP: 900025–900044

- TH + DLCN: 2811–2820, 3281–3290, 3311–3330, or 3371–3380

- TK + DLCN: 3861–3900

- All R prefixes and other S/T combinations fail.

- A first prefix byte other than R, S or T passes.

Ranges are inclusive. This is the native predicate, not an inferred hardware identity. The number calculation does not validate ASCII digits; exact byte arithmetic and branch evidence are included per firmware.

#### Can a difference be converted?

Current evidence by filter. A conversion applies only to the firmware and direction actually validated.

**Filter**

**Conversion status**

**What remains**

**Bank layout**

Layout candidate only

Nine record regions align after relocation; field meanings and safe storage updates are unproved.

**Startup config**

Unproved

Preserve complete initialization and input predicates, not the displayed summary bits.

**Host config**

Unproved

Kernel and Normal both initialize it; the peripheral effect is unresolved.

**Input / IRQ**

Unproved

Input wiring, interrupt setup and callbacks must agree throughout operation.

**Phase order**

Native output correction; guarded mechanism conversion

Complete native output consumers support two-way Normal correction for SAT1, SAT8/SAT9 and supported M32C and Kernel-bound V850 files. Complete-file integrity, authentication, associated Kernel and every unrelated required filter must still pass. Specialized UD mechanism conversions retain their exact-image guards and live parameter prerequisites.

**Startup parameter 0x009F**

Conditional native correction

Requires a bound write route, accepted target value, readback and record preservation.

Conversion is directional and firmware-specific. A matching report value is not proof of a working conversion.

**SAT1 conversion evidence**

##### Startup config

unresolved conversion; concrete operand known

Changing the target complete immediate to source value is a one-byte code change; changing only the reported bit yields0x05 or0x06, neither native value.

**Evidence and remaining proof**

TD02 SAT1010 E46B=0x07 at0x465CA8; SAT1011 E46B=0x04 at0x46849C. Report mask0x11 gives0x01 versus0x00.

Resolve E46B bits0/1 consumers or peripheral effect, startup and resume writers, and whether full source register setting is valid with target adjacent E4 configuration. No verified native runtime selector for alternate hardware was found in this bounded audit.

##### Host config

unresolved conversion; no present grouping effect

Preserve full source host initialization only after proving interface semantics. Bit7 alone is a report projection, not a complete host-setup plan.

**Evidence and remaining proof**

FE94bit7=0 for63,=1for1;9olderimages use explicit host initializer. Ten nonadjacent stores correctly preserveR1L=0x40.

Peripheral meaning and reachability through reset/resume; whole earlier host-program equivalence. No conversion is required to justify removing this currently redundant candidate split.

##### Input / IRQ

unresolved conversion; equivalent source-input cases need no conversion

For genuine differing inputs, remap source address/bit/polarity in all target consumers and coordinate IRQack/mask/install. A controller-write replacement does not establish that remapping.

**Evidence and remaining proof**

SAT1007/1010/1011 allreadFF414000bit1active-low. Their debounce/wake placement differences normalize without changing families. Other cohorts showFFC5writes20/80 or(old&0C)|A0, orFF414100bit3.

Physical input to action mapping for controller-only cohorts, cold/sleep/resume/error paths, and three missingTD04Kernel routes. No automatic conversion from typedcontroller_write totypedphysical_input.

**SAT8 conversion evidence**

##### Startup config

unresolved conversion; predicate transformation required

Keep source hardware input coordinates and polarity in every target closed/open/mechanism predicate, then preserve target state transitions. Editing report flag0x00/01/02/04 is not a firmware transform.

**Evidence and remaining proof**

391images have five closed/open predicates, projected into four read-presence flag values for the report.

Establish cross-board source pin mapping, target predicate callsites and all state consumers, cold/resume/error paths, and output control. Predicate transplant at one startup selector alone is insufficient.

##### Host config

unresolved conversion; paired-stage consistency required

A candidate source-preserving change must cover both Kernel and Normal initializers and retain unrelated bits and neighboringFE9A/FEAB setup.

**Evidence and remaining proof**

FE94bit7 partitions291/100images. Existing394pairedKernel/Normal observations agree on fullFE94 values40/C0/49.

Bit7 physical effect, all reset/resume writers, interface timing and initialization dependencies. Patching Normal alone cannot be assumed persistent across restart.

##### Input / IRQ

unresolved conversion; write lifecycle differs

Would require adapting interrupt install, masks, acknowledge and callback behavior together, not merely changing a bit instruction.

**Evidence and remaining proof**

209SAT8600writesFFC5=20 inCPUinit;8601clearsbit5 inperipheralinit whileenabling diagnosticcallbackroute. These are genuinely different local effects at different lifecycle stages.

Architectural meaning and actual mechanical dependency; predecessor/reset state; other writers and resume paths. Existing evidence does not show diagnosticsroute necessary for physicalcompatibility.

**SAT9 conversion evidence**

##### Startup config

unresolved conversion

Source-setting preservation is a candidate only after recovering full native operand and correlated initialization paths for each directed pair.

**Evidence and remaining proof**

Report retains E46B masked0x11 versus0x10;46/20images. These are not established physical function bits.

Trace native writers/callers and peripheral effect. Determine whether E46B difference follows hardware, host config, or firmware tuning. Bank-layout differences cannot be bypassed by this setting.

##### Host config

unresolved conversion

Requires fullKernel/Normal source-setting plan and proof target host behavior tolerates it.

**Evidence and remaining proof**

FE94bit7 partitions46/20images, aligned with currentE46B grouping.

Same peripheral and lifecycle dependencies asSAT8, plus independently respected bank contracts. Correlation is not proof that one setting causes the other.

##### Input / IRQ

no currently observed difference requiring conversion

None established or needed for this equal observed field.

**Evidence and remaining proof**

All66images report clearFFC5bit5; report treats this as shared evidence.

Equal local operations do not prove equal complete interrupt lifecycle; do not label universally convertible or incompatible.

**Bank, phase and 0x009F**

Bank conversion remains unproved. Nine observed record regions retain their sizes but move down 0x4000 in the 48K layout. Removing the blank 16K interval roundtrips both captured S12U banks exactly, but a native source command can write that interval and commit the bank. The target also commits a snapshot at the same offset, overlapping five of its record regions. Actual command enablement and storage behavior remain unverified; this is not proof of OEM corruption. Neither dropping the interval nor changing the marker alone is a validated migration.

An exact UD02-to-UD04 image transformation reproduces its expected digest; that does not validate a general phase conversion.

0x009F has a native read/write/readback route, conditional on the matched implementation and accepted target values. Physical record preservation and older setter routes still need proof.

# BDR-212U 1.01 to BDR-213U 1.02 native persistent-bank audit

Analysis only; no device writes or conversion implementation. Addresses are CPU addresses, big-endian H8 code. Normal image base is 0x410000; Kernel base is 0x400000. Findings refer to OEM images, not a claim of full-device emulation.

## Inputs

Source archive: hoard/packages/pioneer/8F01/ID83/1.01/276c667ac1383c3aac110cbb433bd8627e49d626ac7c2136b1fa9dd29ecd11a7.installer.tar; Kernel member components/S8F01830.100.enc.
Target archive: hoard/packages/pioneer/9201/ID58/1.02/967c3e42c65ae54802d9b6e1480e3fdf5f70b5de0d875da65731ab8567065415.installer.tar; Kernel member components/S9201580.101.enc.
Source Normal encoded SHA: 9201ee0287df6e6b2acbd26f79414c75d4ed08745a0f3c4bae0908880c86567a.
Target Normal encoded SHA: c45156efa3e19f3092cdd57e68a6d4e71cb2d7fa54509cb56a0c470a8fe65fc4.

## Geometry and boot guard

Source: magic FEDC4321, stride 10000, bank-base RAM33E0, selected-bank RAM33E4. Compact bank base5E0000, markers5EFFFA/5FFFFA; extended base7D0000, markers7DFFFA/7EFFFA.
Target: magic FEDC4322, stride C000, bank-base RAM3442, selected-bank RAM3446. Compact bank base5E8000, markers5F3FFA/5FFFFA; extended base7D0000, markers7DBFFA/7E7FFA.
Each bank has magic at end-6, sequence at end-2, maintenance marker8765 at end-8. Native selector uses unsigned sequence comparison when both magic values match.

Target boot chain: Kernel400100 ->4048E8 ->Normal412000 ->4AF954 ->5532EC ->Kernel40B6F4 ->45F73E. The final routine calls5509B2(base),5509E8(guard),550C4E(selection/maintenance).
40B6F4 calls40BA56 and stub40B600. 40BA56 initializes RAM/runtime state, calling40B9C2(CCR bookkeeping) and40CCDC(RAM heap header setup); this predecessor does not erase banks.

Target guard5509E8 loads FEDC4322 at5509F4. It reads base+BFFA and base+17FFA. If both are FFFFFFFF, it writes sequence1 and FEDC4322 to first-bank header (calls at550A44/550A5A). Otherwise either magic must match. Neither matching calls4AFA7C at550A72. That helper sets Kernel400A14/400A1A with1 then restarts through400A04. Kernel setters400456/400468 modify RAM0144 bits6/7, not persistent headers.

A0 parameter009F is not read by this guard. Both OEM Normal images produce Unknown under the existing startup-word recognizer; 009F=FFFF is the existing neutral policy, not native proof of bank conversion.

## Actual source updater bounds

Source Kernel WRITE BUFFER handler402D96 routes FE/F0/FF through404A4C and404F26. The Normal programming stub copied from400B0C erases ceil(decoded payload length/10000) sectors beginning at relative10000, then programs payload bytes. RAM0270 maps4005A6: add400000, erase requested length, step sector size. RAM031E maps400654, returning constant10000. Normal payload target length1CB900 therefore erases CPU410000..5DFFFF (29 sectors). This does not touch either source or target bank geometry.
Kernel programming stub400A60 erases relative0..FFFF and the first Normal sector10000..1FFFF, then writes only the Kernel. Again no bank erasure.
Consequently, a populated compact source second markerFEDC4321 at5FFFFA survives ordinary transfer and target guard rejects it. Extended target marker positions lie inside old payload; their actual contents require captured storage rather than inference from image metadata.

## Paired native record schema

Source resolver54EDA6 accepts offsets <FD5A; target550D10 accepts offsets <BD5A. Source payload-size function54E0F6 pairs with target55005E. Source region-span function54E14C pairs with target5500B4. The following offsets shift by4000 with unchanged sizes:

| Source offset | Target offset | Region span | Record payload bytes |
|---|---|---|---|
|8000|4000|352|20|
|8352|4352|32|2|
|8384|4384|1600|fixed blocks|
|9984|5984|1928|140|
|B2AC|72AC|164|named area3|
|C20C|820C|2328|1C0|
|E534|A534|1FE|20|
|E732|A732|114|named area2|
|E932|A932|1428|100|

Parameter mapper source54E1DC /target550144 maps IDs0..9F to region9984/5984; A0..AF to8000/4000; B0..18F toC20C/820C;190..19F toE534/A534;1A0 to8352/4352;210..28F toE932/A932. IDs1C0..1FF are rejected by this mapper.
The scanner source54E0B8 /target550020 advances by2 until the first byte of the entry isFF; returns the previous occupied index, or0 for initially empty. It is part of record selection, not a full schema/checksum proof.

Indexed fixed blocks source54D2D4 /target54F23C shift every immediate by4000: source8984,8B84,8384,8584,8F84,9184,9584,9784,9804,9884,9904. Corresponding size functions54D348/54F2B0 return200 for indexes0,2,4,6;400 for1,3,5;80 otherwise.
Native maintenance source54CF0C copies front8000 bytes; target54EE74 copies front4000 bytes before copying selected records. Early region accessor4AE594 /4AF932 still chooses offset0 or2000 in both images. Therefore discarded source4000..7FFF cannot yet be declared unused.

## Native maintenance is not established conversion

Target550978 erases C000 bytes at supplied bank;550AA2 selects inactive bank then erases it. Header updater55102E commits target magic, sequence and8765; source analogue54F0AE uses source magic. They are generation-local maintenance routines.
Source FE operation54F454 and target551332 both obtain inactive bank and add4000, write64*100 bytes from native buffers, then commit through54F9DC/5517AA. Their coexistence with target record tail at4000 requires further semantic analysis; it is not proof that the removed4000 range is disposable logging storage.
All-ref history searches found90f27c4 in pioneer-optical andc8d852d in freemkv adding bank analysis/planning/refusals, not a bank writer. Existing startup migration writes/verifies only A0 parameter words.

## Open requirements before safe conversion

Identify the complete meaning of front8000->4000 reduction, including FE operations; map remaining gaps; prove live-record selection and payload invariants; validate calibration/identity preservation; establish an actual supported erase/write transport; account for overlapping source/target physical banks and interruption recovery. A simple header change or truncation is not justified by this evidence. Record-tail structural similarity makes further conversion analysis plausible, but does not authorize a writer.

## Protocol and low-level ABI follow-up

Independent protocol inspection by fix owner: source Normal WRITE BUFFER main44B7CE; target44B982. FE source44B900/target44BB4C requires RAM2536/2584 bit1. OffsetFFFF skips64*100-byte log-buffer write but still commits. No A4/A8 write selectors found. A0 subtype2 routes43F024, getter54D862/setter54D4EC, bounded800 bytes. Generic host diagnostic_memory mode2 has no flash erase/program/recovery semantics. Existing freemkv-unlock memory writes are restricted to RAM0..8000 andA00000..E00000; no existing bank migrator identified.

Source Kernel RAM0270 ->4005A6 erase ABI: ER0 flash-relative offset (adds400000), ER1 byte count. Iterates sector sizes fromRAM031E (source400654 returns10000) and callsRAM040C with CPU addressER0 and R1L=1 only for2000-byte sectors, otherwise0. Source Kernel RAM02BC ->4005F2 program ABI: ER0 flash-relative offset, ER1 buffer, R2 word count. Doubles word count to bytes; chunks at256-byte boundaries; callsRAM043A with relative offsetER0, bufferER1, byte countR2. These are Kernel-mode vectors. Normal startup installs another low-vector table: do not use Kernel vector numbers under Normal without rebinding.

Source Normal54EE9A accepts CPU addressER0, bufferER1, word countR2, bounds address against current two-bank range, subtracts400000 then calls low053C. Its exact low-vector binding must be verified before proposing a writer.

## Pure conversion artifact and validation

`src/startup/bank/conversion.rs` implements offline conversion only. It copies source0..3FFF unchanged, source8000..FFF7 to target4000..BFF7 (including all unexplained tail gaps/padding), and returns the native footer separately. A mandatory receipt retains source4000..7FFF, the original footer, both source-bank hashes, selected bank/sequence, and both audited firmware hashes. Reconstruction from target body plus receipt reproduces every selected source byte. A verified full two-bank backup remains an external prerequisite; a receipt is not that backup.

Source indirect reader4A9BB2 accesses offsets4000,4001..4006,4007 into RAM12DC/12D6/12D0/12DE. Thus omitted bytes are not assumed unused. Source FE snapshot reads RAM circular bufferA06F12 of length4000 (getters54B1DA/54B1E0/54B1E8). Target FE551332 still writes inactivebank+4000 after551674 copies records, then5517AA commits; no post-snapshot record restoration was seen. Do not use FE as a conversion operation.

Source region-span and payload-size functions are byte-for-byte identical to target counterparts except the high bytes of the compared offsets, each reduced by40 (offset4000). Native parameter mapping is likewise unchanged aside from relocated calls/jumps and region offsets. Converter KATs compare all ordinary mapper-supported parameter groups within0..3FF (unsupported IDs returnNone and are not claimed as live values) with a separately implemented bitmap/latest-record reader, eleven indexed blocks, named areas and the two front2000-byte regions. These tests establish mapped byte/view preservation, not whole-drive behavior or all native reader modes.

Source Normal startup4AE63C copies57E8FC..57EB88 to RAM04BE. Therefore RAM04F0 maps57E92E(erase),053C maps57E97A(program),059E maps57E9DC(sector size10000). Program R2 is a word count; SHLL.W doubles in16 bits, so require<=7FFF words. Erase uses relativeoffsetER0 and bytecountER1; caller must impose10000-byte alignment/ranges. These wrappers do not independently establish a live atomic transaction.

Binding provenance was checked using exact archive extraction and Envelope::load_with_kernel with each matching OEMKernel. Authoritative decoded SHA256s are source014868226d2b9ef07685fb612d0060e4aeee6552dc48aa53371bd2631462d09b and target4c57a8f1a43367489a24ed591ba3bcd0e87267a07b58d290a8f658d2cc200025. Standalone load yields different bytes at16900/77300 because receiver XOR policy is missing; those hashes are deliberately refused.

Validation: four pure converter unit KATs passed. `PIONEER_BANK_HOARD=... cargo test --features envelope,drive --test bank_conversion_archives -- --ignored` passed1/1, extracting the exact two OEMarchives and checking memberSHA256s, successful paired constructor, refusal of standalone decode and a modified target byte. This test requires local proprietary OEM artifacts and is explicitly ignored otherwise.

Potential live entry-hook evidence (independent fix-owner analysis, not implemented here): source Normal FFpath44BA20 requires offset0,length<=100, verifies first16 header bytes44BA68..94, masks interrupts44BA96, checks9A782361/E8DA76BC, sets loaderflags, then44BAD6 calls4AE6F0. A prospective bounded stub would need to retain all native checks and tailcall original; buffer ownership, failure handling, backup receipts and power-loss-safe staging remain separate requirements.

## Final offline API safety review

Conversion and receipt fields are private with immutable getters. The selected source maintenance state must be8765; FFFF is refused pending a complete initialization-equivalence proof, including selectedFFFF/other8765 and bothFFFF cases. Target550C4E triggers maintenance when both state wordsFFFF;550F14 ->54EA86 invokes record updater54EDC6 at5784 with0 and writes8765. The converter does not suppress this by inventing8765.

A live footer write must program state and sequence first and magic last. The offline API exposes separate footer_state/footer_sequence/footer_magic_commit_last values; the eight-byte footer accessor is for logical verification, not an atomic-write claim.

Alternate E0!=0 mapper path source54DEEE/target54FE56 prepares a write slot. Full tag arrays trigger inactive-bank erase, front-region copy (8000 versus4000), latest-record copy into slot0, fixed/named block copy, native commit, and return nextslot1. Otherwise it returns0 for empty orlatest+1. A separate modeled compaction KAT checks supported parameter values, front records and fixed calibration bytes before/after both layouts; it is not an H8 execution test of flash side effects.

Six converter unit KATs pass. Exactarchive integration also binds BankBackup to both geometry branches, verifies both complete raw banks are embedded unchanged, accepts exact persistence readback, and refuses wrongliveactive/base. Application agent independently executed the actual converted output through its byte-driven native guard in both geometries; no live handoff claim follows from that bounded test.

FE offsetFFFF must not normalize source authority: source54F8A6 copies only tail records after erase; it does not preservefront0..7FFF. OffsetFFFF skips the subsequent log capture and commits. This would lose front records, so it was explicitly excluded from a lossless normalization plan.

## Temporary FF bridge execution audit

The original FF handler captures a 0x80-byte stack frame; its context pointer is
at frame+0x74. Native `44BA96 ORC #80,CCR` masks interrupts before control magic
validation, while the failure epilogue `44C102..44C110` does not restore CCR.
Consequently an abort-capable bridge must capture CCR before 44BA96 and restore
it on its own failure path. A raw-instruction CPU KAT covers incoming CCR
00/80/35/B5, including the incoming interrupt-mask bit.

The consumed control buffer uses selector **1** (`43EC8E`, `43EB8E`, `43EBC2`).
`4B3E96` obtains descriptor+4, the relative DRAM offset; `4B3EAE` obtains
its length at descriptor+8. Audited selector1 descriptor at59B61A yields
10000/1180, thus CPU address A10000. Both getters call task-context synchronizer
4B4170; runtime checks must precede reuse of the buffer. A relative offset10000
must never be mistaken for a CPU address. SHA writes13C2..14E8 (0x126 bytes),
its stack, and the supplied digest output; these limits are asserted by executing
the actual native SHA routines in the shared H8 CPU subset.

Native commit's bank switch `54ED22..54ED68` calls the inactive-bank getter,
logs its selected bank, and writes only the active pointer33E4 at54ED5C. It does
not rebuild a cache or update additional bank pointers. Startup selection
54ECE4 likewise writes33E4 at54ECFC before maintenance checks. An exact,
same-sequence clone retains all source bytes and avoids sequence wrap: ties
selectB. Thus compact originalB remains selected until invalidation; extended
cloneB wins the tie immediately, with identical content. Failure after cloning
must still leave RAM33E4 pointing to the surviving exact source bank.

The first offline generated-bridge KAT executes actual emitted H8 instructions
and actual OEM SHA, with only flash erase/program hardware services and task
buffer getters modeled. Compact/sourceA reaches the updater handoff with the
entire C000-byte target equal to the converter, sourceA byte-identical, and SHA
context restored. This is bounded software evidence, not a live bridge install
or a claim of fault coverage. Broader geometry, cloning and interrupted-write
cases remain separate required checks. The NOR model enforces 64KiB erase,
zero-to-one refusal, and at-most64-byte program pages; partial writes must stop
subsequent flash mutation before footer publication.

The unconditional generated-code suite subsequently passed all four capacity /
active-bank combinations and eleven partial erase/program/footer/clone faults.
Its hardware boundary is now lower than the initial test: actual copied RAM
04F0 erase and053C program wrappers execute too; only06C2 sector erase and070A
byte programming are modeled as NOR operations. Every hardware-operation
boundary retains an exact authoritative source bank; a failed readback permits
no later mutation. Abort asserts the current33E4 source bank, unwound FF frame,
live frame+74 context pointer, saved incoming interrupt mask, and SHA context.

All four successful cases then execute target bytes5509E8..550A7A directly
against that resulting NOR memory, require accepted exit550A76, and prohibit
reject4AFA7C or blank initialization550E04. This is independent native acceptance,
not a host footer comparison alone. Tiny retained native excerpts are verified
against paired-decoded full OEM images in the exact archive integration. The
unconditional tests use the private generator after validation; they do not
weaken public SHA/receipt validation or claim a proprietary corpus is in CI.

Four tests passed in114.04s on this workstation: geometry/active cases, target
partial-write faults, clone/publication faults, and image independence from fresh
capture. Fresh bank hashes and arming values live in FF control, not installed
code. These results still do not substitute for host receiver installation,
backup fsync, reconnect, and update orchestration tests.

Final frozen-generator checks: six core tests passed147.14s; extended-capacity
faults passed106.59s; competing-header post-clone mapping passed0.07s. The eight
unconditional tests include four success paths with native target guard,
fifteen partial NOR failures across both geometries, incoming IRQ masks0/1,
changed runtime-vector refusal, BNK0 restoration passthrough, malformed BNK0,
BNK1 reserved-byte refusal, unknown tags, and capture-independent installed
code. The extended collision check must inspect authoritative source bytes at
7FFA, since cloning sourceA to preservedB changes the physical contents under
the surviving target marker7E7FFA. A stale inactiveB collision can be replaced;
a collision in the authoritative bytes cannot be safely ignored.

The exact OEM archive suite additionally passed8.79s: all retained excerpts
match paired decoding, public bridge construction accepts only the canonical
pair and receipt, recognizer reconstructs the source image, and modifications
to either hook, appended padding or checksum are refused. These are the final
native-layer results; receiver transport/orchestration is a separate test layer.

After the final pre-erase footer hardening, the complete nine-test unconditional
native payload suite passed129.90s. The new negative cases alter the live-source
footer copy, target maintenance state, target magic, and target sequence in FF
control; all refuse with zero NOR operations. All geometry/active, interrupted
write, IRQ/context, restore-tag and native target-guard cases were rerun against
these exact emitted bytes, not reused from the earlier generator.

The expanded exact-archive integration passed30.18s. Binding a backup to the
canonical currently installed bridge changes its digest and requires a fresh
persisted-readback receipt; the original source-bound receipt does not match
that rebound backup. Wrong-capacity and mutated bridge images are rejected.
Public bridge construction accepts the fresh bridge-bound receipt and produces
the same canonical installed image/control for the unchanged captured banks.

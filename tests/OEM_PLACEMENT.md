# OEM Kernel placement audit, 2026-10-15

Scope: offline Kernel byte placement, not a physical flashing certification.
The baseline test run used unchanged production source from pioneer-optical `6c8c2be0243aafc82b2f33bdf757a50712a03a6e`
(0.15.1, used by freemkv-flash 0.12.3).

## Census and result

Scanned 678 Pioneer package archives. Their 352 members of size 0x11200
contain 290 distinct envelopes, decoding to 228 distinct 0x10000-byte Kernel
images. These counts are bounded to that modern Kernel envelope format;
they do not claim support for every legacy image in those archives.

| Shipped selection | Distinct kernels | Placement test pass | Placement test fail |
| --- | ---: | ---: | ---: |
| Linear | 192 | 192 | 0 |
| FrontKeyTwoRegion | 36 | 0 | 36 |

All 36 failures occur on the final FE write (offset 0x10200, length 0x1200):
the key read from the OEM address 0x10400 contains the wrong bytes.
The tests assert success for every image; none uses `should_panic` or treats
the known broken placement as the expected behavior.

The two receiver-model control tests pass. They check five legal chunk sizes
and reject swapped parts, gaps, base-as-command-offset, corrupted keys,
corrupted bodies, missing bytes, overlapping writes and repeated offset zero.

## What the OEM instructions establish

There are **40 absolute-address implementations and 188 base-relative
implementations**, rather than 36 distinct-layout implementations. Four
SAT 1003 kernels use absolute addresses but are selected as Linear by the
shipped code. They pass the placement tests.

Both implementation styles establish this same FE staging layout:

| Region | Command offset | Staging address | Bytes |
| --- | ---: | ---: | ---: |
| Header | 0 | 0x10200 | 0x200 |
| Key | 0x200 | 0x10400 | 0x1000 |
| Body | 0x1200 | 0x11400 | 0x10000 |

The FE path adds the supplied command offset to the staging base. Offset
zero resets the received-byte counter. Total received bytes reaching 0x11200
triggers decode/checksum/programming. The count does not determine placement.

For the absolute implementations the decode call takes explicit key=0x10400
and body=0x11400. For the relative implementations the mode-2 base getter
returns 0x10200; decode setup uses base+0x200 for key and base+0x1200 for body.
The 36-vs-192 selector distinction therefore does not establish a requirement
to move the body before the key or add a gap to the command offsets.

Representative independently disassembled OEM instruction sites (CPU image
base 0x400000; these are instruction addresses, not staging addresses):

| OEM specimen | FE placement instruction | Decode argument setup | Count check |
| --- | ---: | ---: | ---: |
| BDR-203, SAT 1005, Kernel 1.10 | 0x403B1C | 0x403B92 | 0x403B5C |
| BDR-205, SAT 1014, Kernel 1.02 | 0x401658 | 0x4016CA | 0x401696 |
| BDR-206, SAT 1030, Kernel 1.06 | 0x4016B2 | 0x401726 | 0x4016F0 |
| TEAC BD-W26SS-B, SAT 1046, Kernel 2.02 | 0x401606 | 0x40167A | 0x401644 |
| BDR-US01, SAT 1050, Kernel 1.01 | 0x401606 | 0x40167A | 0x401644 |
| Optiarc BC-5100S, SAT 1003, Kernel 1.10 | 0x40388C | 0x4038E2 | 0x4038CA |
| BDR-209M, SAT 8600, Kernel 1.52 | 0x40351A | 0x4051D4 | 0x4051BC |
| BDR-211M, SAT 8800, Kernel 1.54 | 0x402FEA | 0x404D12 | 0x404CFA |
| BDR-212M, SAT 8F00, Kernel 1.05 | 0x4035C8 | 0x4052F0 | 0x4052D8 |

Every corpus row pins its original archive/member, envelope SHA-256, decoded
image SHA-256, OEM instruction bytes and their file offsets. The tests verify
these against freshly loaded OEM files, check the FE dispatch branch target,
and read the address operands from the instructions. The production detector
is used only to obtain the plan under test and check which group it selects;
it supplies none of the receiver model's expected addresses.

The test executes the production planner and executor through a transport
that interprets actual CDB offsets/lengths and stages their payloads. It checks
full key/body/header bytes when the OEM byte count is reached. Ciphertext is
also checked against the original OEM file, and decode/repack must reproduce
that original file exactly. The succeeding cases additionally exercise the
Normal F0 stream with varied bytes and require a valid Kernel before Normal
and finish. This last check covers host ordering/offsets, not a separate audit
of every OEM Normal firmware receiver or codec.

This is a bounded model of traced OEM behavior, not execution of the complete
OEM CPU program. It does not verify hardware erase/program timing, USB bridge
behavior, update entry, every crossflash compatibility gate or live recovery.
The 0.12.2 timeout remains a separate unresolved observation.

## Reproduce

No OEM firmware is committed with these tests. Use the canonical package hoard:

```sh
python3 tests/support/extract_oem_corpus.py \
  /Users/matthew/Developer/firmware-extractor/hoard/packages/pioneer \
  /tmp/pioneer-oem-placement-inputs
PIONEER_OEM_CORPUS=/tmp/pioneer-oem-placement-inputs \
  cargo test --offline --features envelope,drive --test oem_placement -- --include-ignored
```

The shipped Cargo.lock records the package itself as 0.15.0 while Cargo.toml
is 0.15.1. Cargo updates only that self-version line for this test run; no
dependency version changes are needed. After that, `--locked` also works.

Expected on the unchanged shipped source: 194 passed, 36 failed (228 corpus
cases plus two receiver-model controls). A separate corpus-only invocation
with filter `oem_` reports 192 passed, 36 failed.

## Correction and retest

The corrected plan sends header/key at command offset zero, then body at
0x1200. The linear plan is unchanged. The same 228 corpus tests now pass,
as do the two receiver-model controls and the added BDR-205-to-BDR-206 case
(231 passed, zero failed). The baseline
results remain in support/shipped-placement-results.tsv for comparison.

The correction retains the existing selector; it does not introduce the
proposed general instruction/data-flow analyser. Static-vs-relative OEM
implementation differences are not claimed to require different placement.

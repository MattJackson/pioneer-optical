# Additional OEM firmware regression tests

## Evidence, not production output

`support/audit_kernel_files.py` independently decodes every unique 0x11200
Kernel envelope from the OEM package corpus: **290 files, 228 decoded kernels**,
including **108 derived-key files**. It uses Python integer operations and raw
OEM bytes, never pioneer-optical. The emitted manifests pin archive/member
provenance, full file/body/key hashes, framing offsets, and literal header fields.
Both front-key and derived-key layouts must decode to a zero BE32 additive sum
and an embedded SAT identity. Derived keys are recovered from the OEM tail LCG
sequence (214013*x+2531011 modulo 2^24), not the production key generator.

OEM BDR-205 Kernel body SHA-256:
`07ef382d8fe7e580817e783f206bf5a5a8eeb6acfdfd9f13eccac5a9a1a15255`.
H8/SX disassembly at load address 0x400000 shows:

* 0x401a66: XOR (`01 f0 65 01`), after the two skip branches.
* 0x401a72: key rotation mask 31 (`79 63 00 1f`).
* 0x401a7c..0x401a90: complementary shifts and OR, implementing rotate-right.
* 0x4019d4..0x4019ee / 0x401a2e..0x401a48: reversed byte reads from
  0xfb57..0xfb54 establish little-endian cipher/key words.
* 0x401a4c and 0x401a54: skip XOR at Normal offsets 0x16900 and 0x77300.
* 0x4016f0..0x40173a: sum the decoded 64 KiB Kernel as BE32 words and require zero.

These are the basis of the independent test receiver operation. Each other
Normal case additionally pins the actual sibling Kernel's compare/branch/XOR
instruction bytes and immediates. This is a bounded decoding/address model,
not an H8 CPU emulator or a hardware flash certification.

## Kernel tests

Each of the 290 `oem_kernel_files` cases checks:

* Original OEM file hash; independent decoded body and key hashes.
* Byte-exact repack, literal header identity, and correct file payload offset.
* Canonical wire header/key/body ordering and unmodified OEM ciphertext.
* Independent receiver decoding and OEM additive checksum.
* Corruption at the start/end/checksum word refuses a transfer.
* A checksum-preserving edit reaches the receiver, with no stale original body.
* A corrupted wire body fails the independent checksum.

`oem_placement` separately covers all 228 receiver kernels, plus model negative
controls and the specific OEM BDR-205 receiver receiving the BDR-206 1.06 target
Kernel. See [OEM_PLACEMENT.md](OEM_PLACEMENT.md) for the original 192-pass/36-fail
baseline and fixed placement proof. This cross-model test does not establish
that every other hardware/identity gate permits that crossflash.

## Normal tests

`support/audit_normal_files.py` inspects Normal files in the same packages as
the 290 Kernel envelopes. It reads same-register CMP.L immediates with BEQ
branches bypassing XOR from the decoded OEM Kernel, independently decodes the
Normal using those skip offsets, and requires the declared length and zero BE32
checksum. 324 files pass that independent audit; 27 are explicitly excluded.
Each accepted file has its own named test.

Tests check pinned instructions/offsets, exact decoded-body hashes, actual XOR
skips (removing each affects that exact word), byte-exact file and wire output,
and checksum-failure refusal. They do not derive their expected offsets from
`kernel_xor_branches` or the current encoder.

`support/oem_normal_exclusions.json` records files outside this independent
oracle's proven scope. Unsupported branch forms, reverse/scaled codecs and
spliced streams are **not** silently counted as passes. An exclusion here does
not mean the library cannot handle that file. Full control-flow verification of
all remaining receiver codecs, spliced-tail authenticity, and physical commit/
recovery behavior still need additional evidence.

## Reproduce

```sh
python3 tests/support/audit_kernel_files.py "$PACKAGES" tests/support/oem_kernel_files.json
python3 tests/support/extract_oem_corpus.py "$PACKAGES" "$CORPUS"
python3 tests/support/audit_normal_files.py "$PACKAGES" "$CORPUS" tests/support/oem_normal_files.json
PIONEER_OEM_CORPUS="$CORPUS" cargo test --all-features --test oem_kernel_files -- --ignored
PIONEER_OEM_CORPUS="$CORPUS" cargo test --all-features --test oem_normal_files -- --ignored
PIONEER_OEM_CORPUS="$CORPUS" cargo test --all-features --test oem_placement -- --include-ignored
```

`PACKAGES` is `hoard/packages/pioneer`. Tests are explicitly ignored without
external firmware; when invoked, missing files fail. No firmware binaries are
committed. Manifest regeneration is an explicit research step, never part of
test execution; review differences before replacing pinned evidence.

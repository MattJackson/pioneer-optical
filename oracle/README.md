# Golden oracles

Byte-for-byte behaviour contracts over the real firmware corpus. A refactor
that changes any line is wrong unless the change is the intended behaviour
and is recorded here.

- `golden-codec-v1.json`: envelope decode and repack round-trip for 1,124
  corpus components. Reproduce with
  `cargo run --release --features envelope --example oracle -- <corpus dirs>`.
- `golden-verdicts-v1.jsonl`: freemkv-flash's crossflash verdict (status,
  refusal reason, routes and required words) for every one of the 29,051 pairs
  the pre-filter schedules over 709 packages, plus the SHA-256 of every
  prepared image and transfer for each admitted pair. A re-signed Normal's
  random signature is masked, and its validity is recorded. Reproduce with
  freemkv-flash's `backends::pioneer::oracle_tests` (`ORACLE_TREE`, `ORACLE_OUT`).

## v1 provenance

Captured at pioneer-optical 3.0.0. It was cross-checked against the same
oracle run at the shipped 2.0.0 (a666e3c):

- 25,200 pairs have identical verdicts, reasons, routes and corrected-image
  hashes.
- The other 3,851 differ only as intended by the 0x9F change. The old
  `conditional` (a read-only startup-prerequisite word) is now `allowed`
  with no requirements, and the corrected images are identical.

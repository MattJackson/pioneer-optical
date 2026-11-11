# Capacity-dependent bank selection

`bank::Contract` and `bank::check` describe and compare storage formats. Matching `when_one` and `otherwise` addresses does not establish that two discriminator programs return one on the same installed controller. `Checks::plan_to_with_policy` additionally requires a capacity relation under both ordinary and explicit-crossflash policies. Failure has code `pioneer.startup.capacity_relation_unproved`.

The relation is sufficient when the actual recognized address expression is independent of its discriminator, when both complete decoded components are unchanged, or when both firmwares run an identical discriminator program over identical address cases. The unchanged case compares SHA-256 identities of both actual inputs and requires a complete 64 KiB Kernel. A missing Kernel is not an identity witness. Public storage enums cannot construct positive capacity evidence. Fixed-address and older resident-owned storage retain their existing comparison behavior.

## Discriminator program digest

The program proof is derived from the two images alone with `h8-asm` — no live query and no hand-rolled instruction decoding — so the offline and online compares are equal and the proof can only under-accept.

The discriminator does not run in place. The C initializer relocates a block out of Normal into low RAM (the `0x1058dc` memcpy; on the recognized family the complete 652-byte helper block is copied to 04BA..0746) and the versioned contract calls the discriminator there (e.g. query 05A2, which calls builder 0646 and resident 107C72). `coverage::copied_checksum::relocated` recognizes that bound copy generically: it decodes the complete C initializer, tracks the memcpy argument graph (ER0 source, ER1 destination, ER2 length) through the bound copy/clear helper chain, and returns the Normal source span and its RAM destination for the single validated copy that covers a given entry. An unrecognized initializer, an unrecognized helper, or an ambiguous or partial copy refuses.

`capacity::program` rebuilds the RAM image from that source and destination so each routine decodes where it executes, bounds every routine by `h8-asm` control-flow reachability (a gap or embedded data refuses), and fingerprints the discriminator independently of link layout. Builds of one discriminator differ only in where routines sit, the addresses of the routines they call, and the addresses of their own data and log handles, so routines are ordered by discovery from the entry, each call target becomes the callee's discovery index, and link-time addresses are renamed one-to-one in first-use order. Every instruction, constant, hardware address and resident-service call target is kept exactly.

The discriminator splits into three parts, and renaming is confined to the one that cannot reach the bank decision:

- **Query** — everything up to the last call that is not into Normal (the in-block builder and the resident query service). Kept exactly, so the drive is asked the same question.
- **Side calls** — calls into Normal code after the query, such as a diagnostic log. Their argument setup may store only into the stack frame; its handles are renamed unless they lie on a page the query or decision uses. The called code is not compared, because diagnostic implementations differ between firmware generations; instead each image's side closure is verified: it decodes completely, has no indirect call or jump, never calls a resident service the query uses, and never names or writes by fixed address a 64 KiB page the query or decision uses.
- **Decision** — everything after the last call. Kept exactly, straight-line or forward-branching, and it reads only registers it sets itself, so its result depends only on the hardware bytes the query produced.

Anything outside this shape refuses. On the 724-package Pioneer corpus all 385 capacity-dependent builds share one fingerprint; the previous byte-level digest produced 362, which refused nearly every cross-version route.

The installed resident query/copy interfaces and a stable completed identification result until the next command are existing OEM interface dependencies, as before: the fingerprint keeps their call targets exactly and does not digest their Kernel bodies, and it does not claim physical ROM, global startup termination, arbitrary hardware progress, or absence of NMI/reset/fault behavior. No saved parameter or bank migration is performed.

## Evidence and regression scope

Targeted unit tests cover the fingerprint directly: two builds differing only in link layout fingerprint equally; a changed query argument, decision constant, hardware base or resident target does not; a different side implementation still relates; side code that writes or names the query's hardware page, or calls the query service, refuses; a side argument on a query page stays exact; a side call before the query, a non-stack store in side setup, and a decision reading a register set before it all refuse. The corpus pair profiles assert both BDR-211M directions relate, and that changing the Normal query or its resident call target refuses. The shared C-startup scan behind `relocated` and `data_sections` is covered by the existing checksum and sink coverage tests.

Changed distinct-case routes refuse unless the discriminator fingerprints prove identical, even when the two case-address arrays match. This is a per-update evidence boundary that can only under-admit — a differing discriminator never relates — not a claim that all other devices or capacity queries are physically incompatible. Fixed-bank routes, actual collapsed cases and unchanged complete pairs retain their respective scopes. Startup CMP correction and other filter owners remain independent obligations.

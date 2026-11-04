# Hardware matrix page

`Pioneer-Hardware-Matrix.html` is generated from code. It is one self-contained
HTML file: the checked-in template `examples/hardware_matrix/template.html`
(HTML, CSS and layout-only JavaScript) with an embedded JSON model. The template
states no rule. Every value, family and rule statement in the model comes from
the code path the update path uses:

- `filters::Context` and every registered filter (`filters::filters()`), giving
  each image's typed findings, evidence and unresolved reasons;
- `filters::identity::discover`, giving the as-is identity and the matching
  (candidate) family, which equals `image::family_with_context` and
  `Envelope::family_with_kernel`;
- each owner's declared `Filter::rules()` (description, role, correctability,
  correction policy and platform-scoped policies) and
  `filters::identity::{PARTITION, RULES}`.

To change a rule on the page, change the owner's `Rules` next to the code that
enforces it. `src/hardware_matrix_tests.rs` pins the declared rules against the
owners' actual decisions.

## Generate

```sh
cargo run --release --all-features --example hardware_matrix -- \
    /path/to/firmware-extractor/hoard --out Pioneer-Hardware-Matrix.html
```

Options:

- `--routes routes.json` adds a Routes tab (see below).
- `--data model.json` also writes the embedded model as pretty JSON, for diffs.

Input is the hoard's `index/packages.json` (every `family: "pioneer"` package) and
its package tars. A Normal held in several packages is analyzed once, using the
first package by path that pairs a Kernel. Normals the envelope codec cannot
decode are listed under Report details, not dropped silently.

The output is deterministic. Input order does not matter and the page has no
timestamp. The only provenance is the source line: crate version, git revision
(`-dirty` with uncommitted tracked changes) and the SHA-256 of
`index/packages.json`.

## Page

Tabs: Groups (matching families by platform, with phase-normalized subgroups and
unresolved reasons), Matrix, Compare, All firmware, SAT compare, Hardware key
(family rules, then per platform every filter's description, correction policy,
platform rules and value groupings with counts, typed values and evidence) and,
when supplied, Routes. Report details holds the counts, the reference
comparisons, revision consistency and decode failures. Hand-written notes that
are not rules are in [hardware-matrix-notes.md](hardware-matrix-notes.md),
linked from the page.

## Routes export (hook for freemkv-crossflash)

`--routes` takes a JSON object with a `routes` array of objects:

```json
{
  "format": "freemkv-crossflash-routes",
  "version": 1,
  "routes": [
    {
      "from": "BDR-UD04 · SAT 8600 · GENERAL · 1.00",
      "to": "BDR-UD03 · SAT 8800 · GENERAL · 1.01",
      "hardware": "SAT 8xxx",
      "status": "untested",
      "steps": ["phase correction", "startup word 0x009F"],
      "evidence": []
    }
  ]
}
```

The generator only checks that shape. `format` and `version` are optional and
shown when present. `from`, `to`, `hardware`, `status` and `steps` (strings or
arrays) get their own columns. Any other route fields appear under the route's
Details. The page shows routes as supplied and does not evaluate them.

## Tests

- CI: `tests/hardware_matrix_page.rs` runs the generator on a small synthetic
  set. The real registry runs on synthetic bytes, together with hand-built
  established identities. The model is compared with
  `tests/fixtures/hardware-matrix-sample.json`. It also checks that rendering is
  deterministic and self-contained, that embedded text cannot end the data
  script, and that no rule text or filter ID is written in the template. After
  an intended change, regenerate the snapshot and review the diff:
  `PIONEER_UPDATE_SNAPSHOTS=1 cargo test --all-features --test hardware_matrix_page`.
- Private runner: `tests/hardware_matrix_corpus.rs` (ignored) generates the
  model from the hoard and checks these invariants: every package listed; every
  distinct Normal either analyzed or reported undecodable; family equal to the
  update path's family; no family crossing a platform; a family ID exactly when
  every hardware finding is established; unresolved findings carrying reasons;
  no phase correction admitted inside a family without identical bound mechanism
  bundles.

  ```sh
  PIONEER_HOARD=/path/to/hoard cargo test --release --all-features \
      --test hardware_matrix_corpus -- --ignored --nocapture
  ```

  Set `PIONEER_MATRIX_OUT=page.html` to keep the generated page.

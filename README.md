# oci-runtime-inventory

Standalone Python 3.10+ standard-library inventory for explicit local OCI-layout
or Docker-save archives and supported SBOM JSON. It never runs Docker, executes
an image/binary/package, extracts archive paths onto the host, follows archive
links, opens a network connection or guesses runtime versions from tags/names.
This optional supporting tool addresses
[node2shell-check #12](https://github.com/completetech-security/node2shell-check/issues/12).
No exploit checker requires it at runtime.

```sh
python oci_runtime_inventory.py --archive authorized-image.tar --output image-inventory.json
python oci_runtime_inventory.py --sbom examples/inventory.sbom.json
python oci_runtime_inventory.py --archive authorized-image.tar --consumer sharp --output sharp-input.json
python oci_runtime_inventory.py --archive authorized-image.tar --consumer node2shell --output node-input.json
python oci_runtime_inventory.py --sbom examples/inventory.sbom.json --consumer flowise --output flowise-input.json
python oci_runtime_inventory.py --sbom examples/inventory.sbom.json --consumer sharp --output sharp-input.json --receipt sharp-receipt.json
python -m unittest -v
```

The checked-in SBOM is synthetic. Real images, inventories and reports must stay
outside version control. Only read images/evidence you are authorized to inspect.
`--output` refuses existing files unless `--force` is explicit, and always protects
inputs, aliases and the executable. No installed dependencies or companion files
are required when the Python entry point is copied alone.

## Evidence and uncertainty

Canonical JSON schema 1.0 records supported parsing coverage, limits/usage,
artifact identities, layer digests and logical file provenance. OCI identities
are verified manifest digests; Docker-save identities are config-byte digests
(`identity_kind` distinguishes them). An OCI manifest digest binds its declared layer descriptors. A Docker-save
config digest identifies only config bytes and does not bind the archive layers:
`rootfs.diff_ids` are not validated, and identical configs with different supplied
layers retain the same config digest. Use the separately recorded ordered layer
digests when comparing observations. Neither identity establishes publisher trust
or that an archive can run. Config Env/Cmd/hostnames and image
tags are not reported. SBOM digests identify the SBOM artifact, not an image.

Canonical reports also retain `generated_at` (UTC inventory-generation time),
`tool.version` and `tool.executable_sha256` (SHA-256 of the standalone file's
bytes, including when invoked through a symlink). The code has no separate
advisory/rule table: the executable digest identifies its parser and export
rules. Generation time is captured once per invocation and reused if an
interruption produces a partial report. It is not an artifact build time,
evidence-acquisition time, publisher attestation or deployed-state observation.
No such times are inferred from file/archive modification timestamps.

`content_sha256` hashes the canonical JSON projection with `generated_at` and
`content_sha256` omitted, using sorted keys, ASCII escaping, two-space indentation
and a final newline in UTF-8. This permits stable content comparisons across
different generation times while retaining all tool, coverage and artifact
evidence. Existing artifact/config/layer/SBOM digests remain unchanged. For
deterministic Python fixtures, `main(argv, clock=...)` accepts a callable returning
an aware `datetime`; it is converted to UTC without altering content identities
or confidence. The public CLI uses the current UTC clock.

The virtual filesystem applies layers in order. Whiteouts remove lower-layer
entries; opaque whiteouts retain same-layer additions regardless of TAR ordering.
Replaced/deleted manifests cannot survive as current package observations.
Links and device entries are opaque replacement nodes, never followed or created.
Metadata under a nondirectory ancestor, or a selected metadata path that is a
link/device/directory, makes image coverage incomplete.

Exact versions come only from selected package manifests (Sharp, Flowise and
flowise-components) or Node.js package-database records (dpkg/APK). Installed
package metadata does not attest deployed runtime use, bundled/global native
linkage, vendor patches or custom builds. No filename/tag/binary-string inference
is performed. All local exploitability remains `not_tested`; no vulnerability or
safety verdict is produced. No observation is proof of absence.

`--consumer node2shell|sharp|flowise` emits actual input contracts for those
standalone checkers. Unverified provenance/library selection is retained, so
metadata alone produces unknown assessments. Qualified/oversized/control-bearing
versions are never normalized into patch claims. Incomplete images are excluded
from consumer records; absent supported records produce unknown placeholders,
not empty evidence presented as a clean scan. Canonical output retains the full
coverage/provenance record; consumer output intentionally carries only each
checker's accepted fields. Preserve the process exit code as well as the output.

Consumer schemas do not accept the canonical generation/tool envelope, so these
fields are never inserted into their records. Use `--receipt PATH` with a consumer
export to retain the canonical inventory alongside it. The receipt includes
`consumer`, `export_sha256` (the SHA-256 of the exact exported UTF-8 JSON bytes,
including the final newline), and `inventory`. It contains no input/output path
or hostname. The two output paths must be distinct and each uses the same
protected no-clobber/explicit-force policy. The receipt is published first;
publication of two files is not transactional. If interruption or output failure
leaves only the receipt, compare its `export_sha256` with the consumer bytes
actually received before associating them. Neither publication is retried after
either begins. A receipt for incomplete input retains `complete=false`; the
consumer retains its existing unknown placeholder policy and exit code.

## Supported formats and bounds

- Uncompressed outer USTAR/V7 TAR containing OCI image-layout 1.0 or Docker-save
  manifest/config/layers. Regular GNU members work when they fit basic header
  fields. No host filesystem extraction is used. SHA-256 OCI manifest/config/layer
  descriptors and declared blob sizes are checked; descriptor URLs are never used.
- OCI plain-TAR or gzip layers; Docker-save plain-TAR layers. Extended PAX/GNU
  long-name/sparse records, zstd, foreign layers, unsupported digests, outer gzip
  and other archive formats are unresolved, not silently accepted as complete.
- OCI-layout descriptors must explicitly identify an OCI image manifest/index
  or Docker schema-2 manifest/list. An optional manifest `mediaType` must match
  its descriptor. Only OCI image-config or Docker image-config media types
  authorize filesystem interpretation; the config bytes remain opaque and
  digest-verified. Manifests declaring `artifactType`, empty artifact configs,
  missing config media types and unknown descriptor/config types are incomplete
  artifact records with no package observations or consumer records. Verified
  manifest digests remain in canonical output, and supported image siblings
  retain their observations.
- JSON CycloneDX 1.4/1.5/1.6, including metadata.component and nested components;
  SPDX 2.2/2.3 package metadata. This reads selected metadata fields, not full SBOM
  conformance or deployment/relationship attestation.
- Default 512 MiB expanded layer bytes; `--max-expanded-mib` accepts 16-4096.
  Other limits: 8 GiB outer archive, 1 GiB compressed layer reads, 100,000 archive
  and layer members, 64 path components/512 path characters, 16 images, 256
  layers/image, 64 index descriptors and three nested indexes, 4 MiB metadata
  files, 16 MiB aggregate captured metadata, 10,000 visited SBOM component entries (including irrelevant entries) and
  10,000 selected component records per image,
  100 SBOM inputs, bounded JSON depth/node count and at most 1 MiB TAR tail padding.

Unsupported/malformed input, integrity mismatch or any limit marks coverage
incomplete with a symbolic reason and exits 2 while preserving completed images.
No components from a failed image are emitted. Exit 0 means supported inspection
completed, not that a runtime is safe. Interruption exits 130 and preserves
completed observations before output begins when possible. Once stdout or atomic
file publication starts, it is never retried; inspect interrupted output before
running again. Ordinary regular-file/path checks assume stable evidence copies
and are not a sandbox against concurrent filesystem mutation.

## Validation and provenance

Tests use synthetic archives only. They cover layer replacement/deletion,
whiteout ordering, links/devices, traversal, duplicate/sparse/extended records,
truncation/checksums/digests, expansion limits, metadata privacy, standalone
execution, output aliases and interruption. Real exported consumer payloads were
also accepted by the actual Node2Shell, Sharp and Flowise CLIs with unknown
assessments. Local checks and exact-commit hosted CI are separate evidence.
GitHub Copilot reviews published changes before merge.

Format references reviewed 2026-10-25:
[OCI layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md),
[OCI layers/whiteouts](https://github.com/opencontainers/image-spec/blob/main/layer.md),
[CycloneDX schema](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json),
[SPDX package metadata](https://spdx.github.io/spdx-spec/v2.3.1/package-information/).
No advisory fix table is embedded: this is supporting inventory, not an exploit
checker. Consumer schemas are pinned by the documented v1 contracts; no feed or
network dependency is introduced.

[AGENTS](AGENTS.md), [contribution terms](CONTRIBUTING.md), [security policy](SECURITY.md),
[AGPL license](LICENSE), [dual licensing](LICENSING.md), [brand policy](BRAND_ASSETS.md).

Consumer exports are bounded by the destination input contract: Sharp 1,000
records/four MiB, Node2Shell 10,000 records/four MiB, Flowise 10,000 records/16 MiB.
An oversized merged export fails before publication; use canonical output or split
the source inputs explicitly. No records are silently truncated. CycloneDX subject
component provenance uses `metadata/component` without an invented array index.

Layer application skips lower-snapshot traversal for empty layers and limits
aggregate lower-snapshot path visits to two million. Per-layer selected-file
ancestor validation examines only new file observations; earlier verified state
is not rescanned for empty layers. Layer trailing padding shares the outer
archive one-MiB cap. OCI indexes require schemaVersion 2. Held dpkg Node packages
retain installed-version metadata. Namespaced CycloneDX packages are not matched
as unscoped Sharp/Flowise/Node names.

Layer reads share a 200,000-call budget, bounding per-byte gzip header processing as well as byte/expansion limits. OCI image planning errors produce an incomplete image record while independently supported sibling images retain their observations. Limits remain shared across images.

Malformed child OCI indexes and independent Docker-save entries are localized
to incomplete records while supported siblings retain package observations and
digest provenance, regardless of sibling order. A rejected child index retains
its verified descriptor identity; a Docker entry retains its config digest only
after the config bytes have been read, otherwise its identity is `unknown`.
Rejected entries provide no consumer records. Overall status remains incomplete
and exits 2. Corruption of the root layout/index or exhaustion of global planning
limits may still prevent archive inspection; shared budgets are never reset for
a sibling.

Every candidate package.json is captured and strictly parsed before its package name is known. Irrelevant manifests still consume the shared capture budget; malformed or excessive candidates make that image incomplete. These deliberately conservative bounds can reject large valid images/SBOMs. OCI attestation manifests and unsupported layer media types are recorded as incomplete; platform labels are not collected. No-force publication requires hard-link support and fails closed otherwise.

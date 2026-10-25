# oci-runtime-inventory

Optional offline image/SBOM metadata inventory for the checker family tracked in
[node2shell-check #12](https://github.com/completetech-security/node2shell-check/issues/12).
The implementation is prepared for review in the initial implementation PR.
No production image, customer inventory or runtime assessment is included.

The tool is not a mandatory dependency of any exploit checker. The approved
implementation will remain standalone Python 3.10+, standard library only,
without image execution, archive extraction or network access.

See AGENTS.md, CONTRIBUTING.md, SECURITY.md, LICENSING.md and BRAND_ASSETS.md.

# Repository instructions

Read README.md, CONTRIBUTING.md, SECURITY.md and LICENSING.md before changes.
This is optional supporting infrastructure for node2shell-check issue #12.
Keep the Python entry point independently usable with the standard library.
Never execute native/package code, run Docker, extract archive members to disk,
follow links, infer runtime versions from tags/filenames, or expose config Env,
Cmd, hostnames, credentials or registry data. Preserve no-network defaults,
whiteout ordering, data/structure/expansion limits, exact digest evidence,
uncertainty, consumer provenance and protected/atomic publication.

Use synthetic local fixtures only. Run python -m unittest -v, actual CLI help
and git diff --check. GitHub Copilot must review published changes; address and
resolve findings and read exact-head hosted CI before merging. Report local
checks, hosted checks and artifact/runtime observations separately. Preserve
unrelated work and uncertain inputs. Never shut down or terminate WSL.

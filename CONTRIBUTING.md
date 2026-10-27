# Contributing

Target Ubuntu Server 24.04 amd64 and Python 3.12. Keep the root broker as the authority
for permissions; HTTP input must not select an acting administrator. Do not add
unbounded request-time subprocesses, remote UI assets, animations or broad package purges.

Build with `python3 build.py`; generated setup/update scripts must match source. Use
`python3 tools/package.py` for a Debian package. Run tests serially with at least 1 GiB
memory headroom. Installer, firewall and reset qualification belong in disposable VMs,
never on the developer's host. Preserve native profile and single-use delivery regressions.

Use branches and pull requests. Record verification and material limitations. A release
version is immutable after publication: fixes receive a new patch/prerelease version.

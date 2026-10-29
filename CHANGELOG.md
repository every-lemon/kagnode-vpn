# Changelog

## 4.0.0-rc.1 — candidate, unpublished

- Queued, bounded connection checks with cached findings and authenticated session evidence.
- Owner-only, allowlisted support reports without credentials, addresses or raw journals.
- Device administrative-state explanations, timestamped export tasks and clearer delivery history.
- Persistent-dashboard guidance in the TUI and explicit RC qualification/publication gates.
- Retire generated SysV services explicitly and serialize reset with legacy CLI/watchdog jobs.
- Use the explicit server-side Mode Config keyword for retained Libreswan engines;
  validate generated connections with the real Ubuntu Libreswan parser in CI.
- Encode the authenticated IPsec SPI in the byte order required by the firewall
  match, restoring client DNS/internet while retaining session binding and isolation.

Real-device/WAN testing and 24-hour observation must pass before this candidate is released.

## 4.0.0-beta.2 — 2026-10-27

- Fix the Debian download filename so GitHub preserves the name in the signed manifest.
  Package metadata still uses Debian's `~beta.2` ordering; the download uses `-beta.2`.
- Verify filenames, signatures and every downloaded asset from a draft before publication.
- Keep beta.1 immutable. Its package filename was normalized by GitHub on upload;
  use beta.2 for the corrected package/checksum workflow. The VPN backend is unchanged.

## 4.0.0-beta.1 — 2026-10-27

First evaluation prerelease for Ubuntu Server 24.04 LTS amd64.

- Consolidated VPN project and Ubuntu-native filesystem/package layout.
- Explicit clean start from 3.x; no automatic legacy-client import or starter client.
- Per-administrator MFA, roles, recovery codes and individual idle/absolute sessions.
- Group/resource policies, identity expiry, authenticated session enforcement.
- Persistent administration and native single-use profile delivery with history/QR controls.
- Separate Ubuntu security updates and signed application releases.
- Shared maintenance/reboot coordination and evidence-first managed repair.
- Native WireGuard startup ordering, Ubuntu Libreswan NSS paths and PPP-only L2TP credentials.
- Package removal pauses managed tunnel traffic while retaining private state for recovery.
- Bounded service startup and lightweight health telemetry for constrained servers.

The transition from 3.x is an explicit fresh start with a private recovery backup;
it is not an in-place client/account migration. Updates within 4.x preserve state.
Real Apple-device import and an external VPN connection remain qualification gates
before RC/stable promotion. This beta is not a production-stability claim.

See `docs/QUALIFICATION.md` for actual verification and remaining release gates.

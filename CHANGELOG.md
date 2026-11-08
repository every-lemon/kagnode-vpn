## Ecosystem update panel — packaging preview 2

## Account link recovery preview

Preserve typed profile failures across the private RPC broker and allow its bounded approval exchange to finish. Return retryable JSON when the broker is unavailable; retain existing native-operation timeouts.

Resume pending profile links after reload, provide attempt-scoped cancellation and visible retry controls, and ignore late browser responses. Retain failed cleanup of issued profile tokens for administrator retry. Preserve local sign-in, permissions and existing data.

## Declared Core binding preview

Document the pinned Core baseline explicitly for new server bindings and the reviewed application-upgrade workflow. Existing application data and stable release selections remain unchanged.

## Shared loading spinner preview

Use KagNode Core 1.0.5 for the shared split-orbit loading mark, with reduced-motion support and existing status/recovery controls retained. This changes web presentation without resetting data or provisioning native services.

## Core integration preview

Shared local UI components, manual animated navigation, natural scrolling rails and icon account menus. Added separate appearance-only account connections and signed UI patch controls. Existing storage, native services and prior release records are retained.

- Add local-administrator update checks, review and progress through KagNode CLI.
- Keep local permissions, CSRF checks, data paths and native provisioning unchanged.
- Source preview only; no new hardware qualification or native deployment claim.

# 4.2.0-beta.1

- Shared KagNode interface, consistent navigation and mobile controls.
- Theme preference and persistent product branding.
- Prebuilt minified UI code protected by existing CSP content hashes; source retained.
- VPN transport, account credentials, policies and native services are unchanged.

# 4.1.0-beta.1

KagNode branding, project-scoped path defaults and an explicit migration tool. Source history and prior releases are retained. See PATHS.md and LICENSES/.

# Changelog

## 4.0.0 — stable candidate, unpublished

- Freeze features for stable qualification with KagNode VPN branding.
- Preserve existing 4.x clients, trust material, administrator MFA and AdGuard settings.
- Recheck administrator authorization under the native lock before returning
  private attachments, preventing a concurrent disable/demotion from leaking profiles.
- Wait for all managed services to become ready under one bounded deadline, including
  ordered WireGuard restarts; keep rollback running even if diagnostic collection fails.
- Deploy all populated-page worker dependencies and record unexpected web errors
  without exposing request contents or exception messages.
- Recognize authenticated IPsec sessions in Ubuntu's text and JSON kernel output.
- Bind stable qualification to the exact release artifacts and completed observation.
- Reject skipped tests, expected failures and empty discovery in CI and release jobs.

Live deployment, independent-network testing and fresh-install/upgrade checks passed.
The 24-hour observation is running; no stable tag or release is published before
its complete results are reviewed. See `docs/QUALIFICATION.md`.

## 4.0.0-rc.1 — candidate, unpublished

- Rename the project to KagNode Open source VPN server, with the KagNode VPN
  wordmark and supplied blue logo across the web interface and setup tools.
- Refresh the compatible cryptography dependency and use the same hash-verified
  runtime lock for CI and release builds.
- Preserve the configured HTTPS delivery address in exported email drafts.
- Include AdGuard Home in service diagnostics and reject incomplete probe results.
- Pin the GitHub checkout action and keep repository credentials out of test jobs.
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

## Historical README release notes

## KagNode 4.1 preview

This release standardizes the KagNode identity and project-scoped paths. It remains a self-hosted VPN appliance, separate from planned KagNode Cloud hosting. Existing accounts, MFA, policy and profile-delivery controls are retained. [PATHS.md](PATHS.md) provides an explicit dry-run, verified migration and rollback tool; never apply it to a running appliance. Publishing this preview does not update an existing appliance or restart its clients.

Current combined release: **AGPL-3.0-only**. Prior MIT code retains its grants and notice in `LICENSES/MIT-legacy.txt`; upstream components retain `THIRD_PARTY_NOTICES.md`. [Brand policy](BRAND-POLICY.md) does not prohibit license-compliant forks or replacement branding.

[KagNode](https://nebulacoder.com) · [Developer](https://developer.nebulacoder.com) · [Logo assets](https://github.com/every-lemon/kagnode-logos)


### Product interface

The dashboard and profile-delivery pages use the shared KagNode black/white/blue UI, keyboard focus styles, responsive controls, and an appearance switch. Browser CSS and JavaScript are minified at build time and authorized by content hashes in the Content Security Policy. No source maps or remote UI dependencies are served. Readable sources and licenses stay in this repository; branding does not prevent inspection or lawful reuse.

Rebuild with esbuild 0.28.2: `ESBUILD=/path/to/esbuild python3 scripts/build-web.py`. The resulting Python asset module ships with the worker, so Node.js is not a runtime dependency. This UI preview does not mark outstanding stable-release hardware checks complete.

## Account profile integration preview

Added optional KagNode Account display-name/photo linking, local administrator disable controls and private credential storage. Existing local account authentication and data remain independent.

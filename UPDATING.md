# Updating VPN

Ubuntu security updates and application releases are independent. Ubuntu runs its
native APT timers; application updates require an explicit owner action.

The 3.x to 4.x transition is a deliberate fresh start, not an in-place migration.
See README before invoking `setup.sh --fresh-start`.

Within 4.x, application updates retain VPN keys, administrators, MFA enrollment,
profiles, token state and AdGuard settings. Failed deployment captures system journals
before restoring prior application code. It does not restore old client credentials.

Stable release checks exclude prereleases. Use `--prerelease` explicitly for beta/RC.
Verify `manifest.sig` with the pinned `release-key.pem`, then verify the asset digest
in `manifest.json`. A payload's embedded checksum detects corruption but is not an
independent signature; do not substitute it for release signature verification.

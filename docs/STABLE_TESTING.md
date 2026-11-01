# KagNode VPN 4.1.0 stable qualification

4.1.0 is the planned first stable release. The published evaluation release remains
4.1.0-beta.1. Freeze features and fix release blockers only in its unpublished
candidate. Do not create `v4.1.0` until all qualification gates pass. Historical
4.0.0 results remain available separately; their evidence is not a pass for the
new project paths or different release artifacts.

## Builder checks

Run the complete Ubuntu 24.04 suite, native encrypted-packet and profile validation,
MFA/RBAC/origin tests, concurrent single-use delivery and package lifecycle checks.
Test fresh installation and upgrades from 4.0.0-beta.2, 4.1.0-beta.1 and the deployed candidate, preserving
VPN trust, peer keys, administrator/MFA data and AdGuard settings. Exercise failed
and interrupted updates, including failed diagnostic collection during rollback.
Run desktop, iPad-size and mobile-size browser checks with normal authentication.
A simulated browser does not establish real iPad compatibility.

Keep all test credentials, VM disks and raw evidence private. Run one heavy VM at a
time, with 1024 MiB guest RAM, a 1536 MiB process cap and an active stop guard below
2 GiB host MemAvailable. Run browser checks separately with a 512 MiB cap. Do not
stop unrelated jobs. Keep verified earlier artifacts and recovery backups.

## Live update and functional checks

1. Establish authenticated SSH over the LAN or a fresh temporary key-only tunnel;
   verify its host key independently. Check current version, services,
   recovery access, disk and memory before modifying the server. Verify a private
   recovery backup and baseline hashes of identities; never publish either.
2. Verify the candidate manifest using the installed pinned public key and compare
   every asset hash. Review the project path migration dry-run and retained-original
   backup. Test that procedure in an isolated upgrade fixture before stopping live
   services. Run the stable updater in a durable console session. Preserve
   4.x identities and settings; do not run the 3.x fresh-start reset.
3. Check all eight managed services, resolver health, both web listeners, native VPN
   sessions, version and identity preservation. Log in normally with owner MFA.
4. Test native Apple delivery in Safari and installation through Settings, one total
   download per token, used-token rejection and revoke/reissue. Keep import passwords
   separate from links, QR codes, email drafts and qualification logs.
5. Connect the iPad on home Wi-Fi, then on a phone hotspot actually using mobile data.
   Verify DNS and websites, allowed resources and denied LAN/client traffic, reconnect
   and sleep/wake. Record private server counters and matching authenticated sessions.
   Also verify WireGuard and L2TP with compatible clients, including policy/revocation.
6. Check roles, MFA/session expiry, exports, security-update timers and manual reboot
   defaults. Investigate failures with bounded local logs; do not reset keys/MFA or
   broaden rules to force a passing test.

## Final observation

After functional checks pass, collect at least 24 completed continuous hours on the
exact candidate. Run the maintained `tools/observe_rc.py` helper in a dedicated
transient systemd service with a 64 MiB memory limit and at least 25 hours runtime.
Use a new root-only log pathname; never overwrite earlier evidence. The helper is
read-only and includes candidate identity and continuity checks, DNS UDP/TCP and
both web health endpoints. Its summary is an
input to review, not automatic approval to publish.

Review service failures, queue errors, DNS and VPN health, watchdog/reboot activity,
memory trends and private audit/journal history. Require no unexplained failures,
reboot loops, connectivity loss or sustained memory growth. A collector interruption,
server reboot or runtime change starts a new interval after affected checks pass.
Retain security updates and the configured manual-reboot policy throughout.

Record sanitized evidence in `qualification/4.1.0.json`, including hashes of all
three release payloads and the private observation log. Do not copy historical
pass flags into the stable record without reviewing applicability to this build.

## Publication

Build and sign the final package and scripts, then run `tools/verify_release.py` and
`tools/qualify_release.py`. Missing evidence must block publication. Freeze the
qualified assets, pass CI on the final commit and tag it `v4.1.0`. The release
workflow verifies its downloaded draft before publishing it as stable and Latest.

Title: `KagNode VPN 4.1.0`. Release description: exactly `Fixed for 4.1.0`.
Keep detailed notes here and in CHANGELOG.md. Published releases are immutable;
subsequent compatible fixes use 4.1.1. Neither the version string nor a passing
unit-test suite alone establishes stable qualification.

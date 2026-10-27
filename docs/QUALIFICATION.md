# 4.0.0-beta.1 qualification — in progress

This file records evidence, not promises. No RC/stable release is approved.

Evidence recorded on the builder (27 October 2026):

- Full suite: **221 tests, 3 skipped**, 74.963 seconds. Skips were the optional
  QuickJS browser-script tests; that dependency has since been installed for the next run.
- Actual temporary NSS/OpenSSL exports, encrypted bundles and the production broker
  capability restrictions passed. These tests create synthetic test certificates only.
- Actual isolated network namespaces passed WireGuard/IPsec/PPP policy enforcement,
  XFRM rekey and interface-reuse checks; no host VPN interface was changed.
- Actual isolated systemd services passed socket activation, privilege separation and
  health-restart recovery tests. No production VPN service was used.
- Interrupted reset rehearsal retained verified private backups and did not restart
  retired credentials. Concurrent system tasks admitted one request, and queued work
  rechecked the administrator's authorization before executing.
- MFA/session/RBAC, VPD concurrent claims/revocation, version ordering and code rollback passed.
- Standalone checksums, Python/Bash syntax, ShellCheck and staged source secret scan passed.
- Source archives verified by SHA-256; private MHTML and old screenshots excluded from Git.

Still in progress (do not interpret the preceding tests as completion of these gates):

- Disposable Ubuntu 24.04 amd64 installation with native engines and manual AdGuard flow.
- Rechecking after the latest firewall rebuild guard and resolver/repair changes.
- Package upgrade/removal, signed release artifacts and end-to-end application updating.
- Browser usability at desktop, iPad-sized and mobile viewports.

Release gates still requiring recorded evidence include real Apple-device import and an
external IKEv2 connection. A simulated browser or server-side export check does not
establish that a real device connects through the user's router.

Resource budget: test VM capped at 1024 MiB RAM/one vCPU; tests run serially. The development
memory guard reserves at least 1024 MiB in addition to each operation's declared budget.
Private test logs and VM disks live under ignored `private/`, never in release assets.

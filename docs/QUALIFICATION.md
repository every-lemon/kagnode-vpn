# 4.0.0-beta.1 qualification

This file records beta evidence. RC/stable promotion still requires the real-device
and external-network checks described below.

Evidence recorded on the builder (27 October 2026):

- GitHub Ubuntu 24.04 CI: **253 tests passed**, including QuickJS browser-script
  tests, on commit `35df239`. The release workflow repeats the suite on the tagged commit.
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
- Disposable Ubuntu 24.04 amd64 VM: native Ubuntu Libreswan, WireGuard and PPP/L2TP
  configuration, all engine/application services and AdGuard UDP/TCP DNS checks passed.
  The qualification fixture completed AdGuard's wizard API; production setup retains
  the manual browser wizard. No production server was reset or configured.
- Real native clients for all three protocols were created. Apple mobileconfig,
  Android sswan and password-protected PKCS#12 exports passed server-side validation.
- Package install, reinstall, removal and reinstall preserved hashes of VPN trust,
  WireGuard configuration, administrator password and MFA enrollment. Engine services
  and private state remained present. Removal pauses managed tunnel traffic until
  a verified policy rebuild restores application service.
- Browser checks passed MFA login, nine routes, no horizontal overflow and form
  preservation at desktop (1440px), iPad-sized (820px) and mobile (375px) widths.
  Chromium used a measured peak of 153.6 MiB under a 512 MiB cap.
- The populated group/resource controls passed a second browser run. Prepared
  delivery rendering also has a regression test preserving administrator context.
- The installed root broker completed a queued IKEv2 export under its production
  sandbox. An authenticated request to the installed dashboard returned HTTP 200.
- Application updating preserved the private identity hashes and archived its
  successful updater under its versioned native path. The VM rehearsal exposed
  startup-order and slow-disk issues; fixes have kernel/systemd and durability tests.
- The final candidate completed an application update, queued IKEv2 export,
  authenticated HTTP dashboard request and native Apple VPD download through the
  installed services. A second claim of the same delivery token was rejected.
- Recovery from an interrupted qualification run retained the database, VPN trust,
  all protocol clients, administrator password hash and MFA enrollment.
- A subsequent reboot brought up all VPN/application services, monitoring and native
  APT timers automatically. AdGuard UDP/TCP DNS, both HTTP health endpoints, public
  certificate delivery and the preserved identity hashes passed after boot. The
  single-vCPU software emulator needed native IPsec startup retries under CPU load;
  no manual service start was used to pass this check.

- The final updater resumed deliberately stopped watchdog/maintenance timers and
  again preserved the private identity hashes. Its versioned archive was retained.
- The local package and standalone assets built successfully, and the signed
  manifest verified against the pinned Ed25519 public key. The tagged release
  workflow repeats tests, package construction and signature verification before upload.

Release gates still requiring recorded evidence include real Apple-device import,
an external IKEv2 connection, and a complete deployed 3.x-to-4 reset rehearsal beyond
the isolated reset/interruption tests. A simulated browser or server-side export
check does not establish that a real device connects through the user's router.

Resource budget: test VM capped at 1024 MiB guest RAM/one vCPU; tests run serially.
The resumed VM initially used MemoryHigh=1280M, MemoryMax=1536M and a guard that terminates
only that test if host MemAvailable drops below 2048 MiB. Browser tests use a separate
512 MiB cap. After soft-limit reclaim was observed with over 7 GiB host headroom,
MemoryHigh was raised to the existing 1536 MiB hard cap; MemoryMax was unchanged.
No other workspace job was stopped to make room.
Private test logs and VM disks live under ignored `private/`, never in release assets.

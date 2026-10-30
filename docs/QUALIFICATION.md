# KagNode VPN 4.0 qualification

The current version is the **unpublished 4.0.0 stable candidate**. Features are frozen;
follow [stable testing](STABLE_TESTING.md) and `qualification/4.0.0.json`. Historical
RC evidence below is retained for traceability. Stable publication requires the
exact final artifacts and a completed, reviewed 24-hour observation.

Stable candidate CI `41044124999` on commit `c945ac3` passed all **308 tests**
without skips on Ubuntu 24.04. These include the private-download authorization
race regression, bounded individual-service readiness checks, rollback despite failed
diagnostic collection, populated deployed-worker routes, Ubuntu IPsec diagnostic
parsing, and strict artifact/observation qualification. CI's installer, updater
and Debian package hashes match the signed local candidate byte-for-byte. A
cross-builder comparison caught the package archive root inheriting the builder's
umask; explicit directory permissions and an umask regression corrected it.

The compiled 4.0.0 renderer passed 12 visual pages and 33 route checks across desktop,
iPad-sized and mobile viewports, with three synthetic MFA logins, no overflow/CSP/page
errors and edited forms preserved during polling. Desktop profile selections also
remained intact. The 512 MiB cap reclaimed memory without OOM; minimum builder memory
available was 7446 MiB. The subsequent final candidate adds a missing deployed-worker
dependency and diagnostic parsing; the rendered HTML/CSS is unchanged. The actual
installed final worker passed all 15 populated authenticated routes. Screenshots and
raw evidence remain private fixtures; real-device results are recorded separately below.

Stable candidate evidence recorded on 30 October 2026:

- The final signed installer, updater and package were deployed to the live Ubuntu
  24.04 server. The installed application and package both report 4.0.0. Libreswan
  5.4.1 was retained. VPN trust, all existing protocol clients, administrator password
  and MFA enrollment, and AdGuard configuration matched the verified private backup.
- An initial update caught WireGuard still starting after the firewall restart and
  rolled back safely. A bounded readiness wait now checks every required service;
  the final deployment passed all eight services, DNS over UDP/TCP, both HTTP health
  endpoints, database integrity and security-update timers. No production reset or
  reboot was performed.
- Real iPad Safari testing confirmed existing owner/MFA login and the KagNode
  dashboard. A missing module in the deployed worker initially broke populated
  navigation; the permanent fix and regression cover the actual installed layout.
  The user then confirmed Devices, device details, Users, Delivery and System work.
- The existing Apple profile connected on home Wi-Fi, with websites loading both
  initially and after reconnection. On an independent phone hotspot using mobile
  data with the phone's Wi-Fi off, the user confirmed VPN and websites work before
  and after iPad sleep. Later UI/helper/diagnostic fixes preserved native trust and
  policy code. Final server checks confirmed an authenticated binding and traffic
  in both directions; that later server snapshot was on LAN, not a simultaneous
  capture of the hotspot test.
- In an isolated Ubuntu VM, the final updater recovered a deliberately interrupted
  beta.2 upgrade after a cold boot. The interruption used the preceding candidate's
  unchanged staging/recovery path; recovery used the exact final updater. All eight
  services and the original identity, AdGuard, IPsec and networking checks passed.
- The exact final package passed installation, reinstallation, removal and
  restoration. Removal stopped application management while retaining the native
  engines and private state. Restoration preserved trust, protocol clients, owner
  password/MFA and Ubuntu networking.
- Through the actual installed broker and worker, queued IKEv2 export, all 15
  populated authenticated routes, native Apple MIME delivery, single-use token
  rejection, queued diagnostics and the Owner-only redacted report passed.
- A separate fresh Ubuntu installation rehearsal is still running. Its result
  will be added only after verification finishes.

The qualifying observation started **30 October 2026 at 10:56:27 UTC** on the exact
final installer. Earliest completion is **31 October at 10:56:27 UTC**. Its dedicated
read-only service is capped at 64 MiB and checks eight services, UDP/TCP DNS, both
HTTP health endpoints, job counters, recovery attempts and available memory every
minute. Initial samples passed, with about 11 MiB peak observer memory. The release
gate remains closed until the full interval and private evidence are reviewed.

## Historical RC and beta evidence

RC.1 remained unpublished. Its historical gates are tracked in
`qualification/4.0.0-rc.1.json`; follow [RC testing](RC_TESTING.md).
Beta.2's final tagged workflows passed **258 tests** and independent downloaded
asset signature/filename/checksum verification. Evidence below describes its backend.

RC candidate evidence recorded on 28 October 2026:

- The final runtime passed 279 Ubuntu 24.04 CI tests. Three additional tests cover
  observation counters and ensure they never export private job contents.
- A retained 3.8 runtime was deployed with real native engines in an isolated VM.
  Fixture-only NSS aliases accommodated Ubuntu's native database location. A deliberate
  interruption after verified backup, clean shutdown/reboot and resumed reset passed:
  legacy services stayed retired, while networking and engine binaries were preserved.
- Fresh setup produced a different CA, an empty client/token database, the built-in
  ungrouped group and a newly MFA-enrolled owner. Subsequent native WireGuard, IKEv2
  and L2TP creation and Apple/Android/PKCS12 validation passed.
- The exact RC package passed installation, reinstallation, removal and restoration,
  preserving client/trust and administrator password/MFA hashes. The restored broker,
  authenticated HTTP dashboard, native single-use VPD and Owner-only report passed.
- Browser checks passed eleven routes at three widths, with MFA, no page overflow
  and changed form/checkbox selections retained across real polling intervals.
  Earlier local headless navigation/login waits timed out; the final instrumented
  direct-connection run passed. Real-device login remains part of the manual gate.

This evidence does not replace real-device, external-network or completed
observation checks. RC publication remains blocked by their qualification record.

On 29 October, the approved deployment retained Libreswan 5.4.1 and exposed an
unprefixed Mode Config server keyword rejected by that engine. The corrected
connection passed its real parser before installation resumed. CI now installs
Ubuntu's Libreswan parser and tests the generated configuration, including rejection
of an invalid connection. CI run `40867859053` passed all 283 tests; the same parser
regression passed against the retained 5.4.1 engine. The live installation then
completed every recorded setup stage: AdGuard DNS UDP/TCP, all VPN engines, both
HTTP services, monitoring and security-update timers passed verification. The first
owner enrolled MFA; the client database was initially empty for deliberate device creation.

A dedicated Apple profile was subsequently delivered once through native VPD. The
user reported the iPad connected, corroborated by its authenticated IPsec session.
That real traffic test exposed a firewall SPI byte-order error: source, policy,
protocol and request-ID selectors matched, while the SPI selector rejected traffic.
The corrected serialization matched live packets and was deployed as a signed
candidate package without changing client credentials, trust or administrator MFA.
DNS and internet forwarding then matched the intended per-device rules, with
bidirectional encrypted traffic observed. Independent-network testing remains
pending. Preliminary observation was stopped when the implementation changed;
the qualifying 24-hour interval has not started.

CI run `40876295960` passed all 285 tests without skips for the corrected candidate,
including real encrypted packets, wrong-SPI/request-ID and plaintext rejection,
rekey, revocation and native firewall reconciliation. Its installer digest matches
the deployed server before the subsequent branding/security changes. No RC tag or
release has been published.

The subsequent KagNode candidate adds the supplied logo, preserves HTTPS delivery
addresses in email exports, refreshes the compatible cryptography dependency and
includes AdGuard Home in service health checks. A focused review of authentication,
roles, proxy/origin handling and delivery found and fixed the email HTTPS downgrade;
it is not a complete penetration test. Existing deployment, attachment, access and
MFA regressions passed locally. Real browser checks passed login, dashboard, group
controls and delivery at desktop, iPad and mobile sizes, including three fixture MFA
logins, with no overflow or CSP errors. A narrow-sidebar logo overflow found during
the checks was corrected. The final browser run peaked at 263.6 MiB under a 512 MiB
cap, leaving over 7 GiB available on the builder. Final Ubuntu CI evidence is recorded
in the qualification JSON: run `40966884394` passed all 289 tests without skips on
commit `87837f7`, including the HTTPS email and AdGuard service regressions and
package inspection. The user deferred live deployment until a later session;
this candidate still requires deployment, external-network checks and observation.

This file records beta evidence. RC/stable promotion still requires the real-device
and external-network checks described below.

Beta.2 changes release packaging and publication verification. Its VPN backend is
the beta.1 backend qualified below; five additional tests cover downloaded artifacts.

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

Remaining RC gates are listed in the qualification record, including independent
external IKEv2 connectivity and completed observation. Real Apple installation and
the approved deployed 3.x-to-4 reset now have evidence above. A simulated browser
or server-side export check does not establish an external client connection.

Resource budget: test VM capped at 1024 MiB guest RAM/one vCPU; tests run serially.
The resumed VM initially used MemoryHigh=1280M, MemoryMax=1536M and a guard that terminates
only that test if host MemAvailable drops below 2048 MiB. Browser tests use a separate
512 MiB cap. After soft-limit reclaim was observed with over 7 GiB host headroom,
MemoryHigh was raised to the existing 1536 MiB hard cap; MemoryMax was unchanged.
No other workspace job was stopped to make room.
Private test logs and VM disks live under ignored `private/`, never in release assets.

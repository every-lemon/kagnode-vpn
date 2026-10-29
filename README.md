# KagNode Open source VPN server

![KagNode VPN](assets/kagnode-wordmark.svg)

KagNode VPN provides Ubuntu-native administration for WireGuard, IKEv2, L2TP/IPsec, AdGuard Home and VPN profile delivery.

**This checkout prepares 4.0.0-rc.1; it is not published yet. The published evaluation release is 4.0.0-beta.2.** RC publication requires [qualification and real-device testing](docs/RC_TESTING.md).
See [qualification status](docs/QUALIFICATION.md) for what has actually been tested.

Target: Ubuntu Server 24.04 LTS amd64, physical server or VM; systemd required.

## Installation

Install a signed release package, then configure it explicitly:

```sh
sudo apt install ./vpn_4.0.0-beta.2_amd64.deb
sudo vpn setup --install
```

Alternatively, [verify the signed release](docs/VERIFYING.md) and run the standalone `setup.sh`.
The setup pauses for first-owner MFA enrollment and the manual AdGuard browser wizard.
SSH is an explicit choice. No starter VPN clients are created.

Package installation installs application code; it does not reset credentials or remove
unrelated packages. An existing newer working Libreswan engine is preserved. Fresh
installations use Ubuntu's Libreswan package.

### Explicit 3.x fresh start

`sudo bash setup.sh --fresh-start` requires typing `RESET VPN AND ADGUARD` at a private
interactive console. It verifies a private backup, then removes the managed old VPN
trust material, clients, administrative state and AdGuard settings. OS networking and
installed engine binaries are preserved. Mixed unmanaged PPP/IPsec configurations
cause a refusal before deletion. Old clients do not become active again after failure.
Backups are under `/var/lib/vpn-recovery/`; recovery is deliberate, never automatic.

## Administration

`sudo vpn` opens the authenticated arrow-key console (search with `/`, help with `?`).
Use `VPN_STACK_PLAIN=1 sudo -E vpn` for plain text. The dashboard stays online on LAN
port **9001**; profile delivery stays online on **9000**. Individual sessions expire
at 30 idle minutes or eight hours absolute. Background polling does not extend sessions.

Every administrator uses a username, password and authenticator MFA. Recovery codes
are single-use and stored as hashes. If all owners lose access, `sudo vpn recover-owner`
provides an explicit, audited root-console recovery path with new MFA enrollment. Owners manage administrators/system settings;
Operators manage clients/profiles/policies; Auditors receive redacted status/audit.

New clients belong to **ungrouped clients**: internet and server DNS allowed,
LAN/resources and client-to-client traffic blocked. Group/user/device rules apply
only to IPv4 traffic **through the VPN**. They are not a device-wide kill switch.
Explicit denies take precedence; expired/disabled/revoked identities have no grants.

VPD preserves native `.mobileconfig` delivery to Safari. One token permits one file
download total, including when multiple formats are offered. HEAD/inspection does
not consume tokens. Revocation, reissue, QR sharing and token history are separate
from import passwords. Share passwords through a separate channel.

## Ubuntu maintenance and application updates

Ubuntu security updates use `unattended-upgrades` and native APT timers. Reboots default
to manual; owners can schedule a one-time reboot or a daily reboot-required window in
an explicit timezone. The coordinator serializes maintenance and uses durable reboot
budgets. Application releases are separate and are applied explicitly:

```sh
sudo vpn update                 # check stable releases and signatures
sudo vpn update --apply         # owner MFA required
sudo vpn update --prerelease    # explicitly include beta/RC
sudo vpn doctor
sudo vpn repair                 # authenticated repair workflow
sudo vpn status
```

A downloaded updater can run with `sudo bash update.sh --prerelease` for a beta/RC.
It preserves 4.x clients, administrator accounts, MFA and AdGuard configuration.
After success it archives itself under `/var/lib/vpn/updates/update-VERSION.sh`.

## Native layout

The application displays **KagNode VPN**. Its command and Debian package remain
`vpn`, with the native paths and `vpn-*` service names below.

| Purpose | Location |
| --- | --- |
| Configuration | `/etc/vpn/` |
| Code / helpers | `/usr/lib/vpn/`, `/usr/libexec/vpn/` |
| Private state | `/var/lib/vpn/` (restricted databases/subdirectories) |
| Logs / runtime | `/var/log/vpn/`, `/run/vpn/` |
| Application services | `vpn-control`, `vpn-management`, `vpn-downloads`, `vpn-firewall`, `vpn-watchdog`, `vpn-maintenance` |

`vpn doctor` and repair write diagnostic evidence locally; private journals can contain
operational details. Do not publish runtime databases, exports, keys or recovery archives.

## Development and releases

`VERSION` is authoritative. Versions use `Major.Minor.Patch[-beta.N|-rc.N]`; tags use
`v4.0.0-beta.1`, etc. Debian packages map prereleases to `4.0.0~beta.1`.

```sh
python3 build.py
python3 tools/package.py
bash update.sh --verify
```

See [release procedure](docs/RELEASING.md), [security](SECURITY.md),
[contribution guide](CONTRIBUTING.md), and [third-party notices](THIRD_PARTY_NOTICES.md).

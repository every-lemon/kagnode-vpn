<p align="center"><img src="assets/kagnode-wordmark.svg" width="440" alt="KagNode."></p>

# KagNode VPN

## Overview

Self-hosted VPN accounts, access policy, MFA and profile delivery.

## Release status

Product source: **5.0.0**. Stable source/data release: **5.0.0**.

KagNode 5 uses the same locally served Core login frame and action icons across applications. Existing local sign-in, explicit KagNode connection, profile-sync policy, local roles and storage formats are preserved. The stable assets are reviewed source/data packages and the management web interface. Existing native networking remains unchanged by the web rollout; this release does not claim new protocol, router or real-device qualification.

Earlier packaging prereleases remain available. The 5.0 stable release is limited to the verified source/data and web-interface scope; native and hardware evidence remains separate. See [verification](docs/VERIFICATION.md) and [changelog](CHANGELOG.md).

## Features

- Shared local sign-in and explicit Login with KagNode; local access and security requirements stay available. See [account sign-in](docs/ACCOUNT-SYNC.md).

- WireGuard, IKEv2 and L2TP administration.
- Accounts, access controls, MFA and profile downloads.
- Signed release manifests and explicit setup/update workflows.

Optional KagNode Account linking syncs your display name and photo after explicit approval. Your local application administrator can disable it. Local sign-in and permissions stay independent.

## Requirements

Ubuntu 24.04 amd64 for the existing native installer. WireGuard/IPsec operation requires the documented kernel, networking and firewall prerequisites.

## Installation and downloads

Download from [GitHub Releases](https://github.com/every-lemon/kagnode-vpn/releases). Verify `SHA256SUMS` before extracting or installing a package.

| Payload | Formats | Support |
| --- | --- | --- |
| Complete source / artwork | `.tar.xz`, `.tar.gz`, `.zip` | Named top-level directory; manual setup |
| Source/data | `.deb` | Source only; does not provision a service |
| Source/data | `.rpm` | Rocky Linux 10 source package; no native service qualification |

Existing signed `.deb`, setup.sh and update.sh workflows remain available for the documented Ubuntu target.

Source packages install under `/usr/share/kagnode/`; they do not replace an existing application, migrate data, start services or configure networking.  See [package details](docs/PACKAGING.md).

## Usage

```sh
python3 build.py
bash update.sh --verify
```

See [operations and existing setup instructions](docs/OPERATIONS.md) for the full workflow and its prerequisites.

## Configuration and storage

Shared presentation uses [KagNode Core](docs/CORE.md), with a pinned local fallback and reviewed server adapters. Compatible stable UI patches have a separate local-administrator policy.

Keep /etc/kagnode/vpn and /var/lib/kagnode/vpn separate from editable source. Existing migrations and package identities remain unchanged.

## Security

Use HTTPS and least-privilege accounts for hosted services. Keep secrets and user data out of Git. Source/data packages support inspection and manual setup; native service and hardware claims remain limited to recorded verification. See [security guidance](docs/SECURITY.md).

## Development and testing

```sh
python3 tools/run_release_tests.py
python3 scripts/repository_check.py
python3 scripts/format_source.py --check
python3 scripts/release.py --output dist/packages
```

Install the formatting dependencies from `requirements-format.txt`. Package building additionally needs `dpkg-deb`, `rpmbuild`, XZ support and, for CLI binaries, Go. Read [the repository map](docs/STRUCTURE.md) before editing generated files.

## Documentation

- [Ecosystem installation and updates](docs/ECOSYSTEM.md)

- [Repository structure](docs/STRUCTURE.md)
- [Operations](docs/OPERATIONS.md)
- [Packages and release process](docs/PACKAGING.md)
- [Verification and limits](docs/VERIFICATION.md)
- [KagNode Account linking](docs/ACCOUNT-SYNC.md)
- [Changelog](CHANGELOG.md)

## Licensing

See [LICENSE](LICENSE) and retained third-party notices. KagNode artwork retains its separate permission and brand policy; the application uses AGPL-3.0-only.

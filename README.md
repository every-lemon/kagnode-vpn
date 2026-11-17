<p align="center"><img src="assets/kagnode-wordmark.svg" width="440" alt="KagNode."></p>

# KagNode VPN

Self-hosted VPN accounts, access policy, MFA and profile delivery.

## Overview

This README has no screenshot yet.

| Step                     | Detail                                                                                                                                       |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| You run the VPN services | KagNode VPN administers WireGuard, IKEv2 and L2TP on your own server.                                                                        |
| Accounts and access      | Administrators create accounts, set access controls and require MFA.                                                                         |
| Split by privilege       | A control process with the needed privileges does the native work, and a separate web process serves the pages and talks to it over a local… |
| Signed updates           | Release manifests are signed and setup and update steps are explicit workflows you start, not silent background changes.                     |
| Sign-in stays local      | Local sign-in always works.                                                                                                                  |
| Scope                    | The stable 5.0 release covers the source and data packages and the management web interface.                                                 |

## Release status

Product source: **5.0.4**. Stable source/data release: **5.0.4**.

KagNode 5 uses the same locally served Core login frame and action icons across applications.

## Features

- WireGuard, IKEv2 and L2TP administration.
- Accounts, access controls, MFA and profile downloads.
- Signed release manifests and explicit setup/update workflows.

## Requirements

Ubuntu 24.04 amd64 for the existing native installer. WireGuard/IPsec operation requires the documented kernel, networking and firewall prerequisites.

## Installation and downloads

Take releases only from [GitHub Releases](https://github.com/every-lemon/kagnode-vpn/releases) and verify `SHA256SUMS`.

| Payload                   | Formats                      | Support                                                        |
| ------------------------- | ---------------------------- | -------------------------------------------------------------- |
| Complete source / artwork | `.tar.xz`, `.tar.gz`, `.zip` | Named top-level directory; manual setup                        |
| Source/data               | `.deb`                       | Source only; does not provision a service                      |
| Source/data               | `.rpm`                       | Rocky Linux 10 source package; no native service qualification |

## Usage

```sh
python3 build.py
bash update.sh --verify
```

See [operations and existing setup instructions](docs/OPERATIONS.md) for the full workflow and its prerequisites.

## Configuration and storage

Shared presentation uses [KagNode Core](docs/CORE.md), with a pinned local fallback and reviewed server adapters. Compatible stable UI patches have a separate local-administrator policy.

## Security

Use HTTPS and least-privilege accounts for hosted services. Keep secrets and user data out of Git.

## Development and testing

```sh
python3 tools/run_release_tests.py
python3 scripts/repository_check.py
python3 scripts/format_source.py --check
python3 scripts/release.py --output dist/packages
```

## Documentation

|                                    |                                              |
| ---------------------------------- | -------------------------------------------- |
| Reviewed local setup               | [docs/INSTALLER.md](docs/INSTALLER.md)       |
| Ecosystem installation and updates | [docs/ECOSYSTEM.md](docs/ECOSYSTEM.md)       |
| Repository structure               | [docs/STRUCTURE.md](docs/STRUCTURE.md)       |
| Operations                         | [docs/OPERATIONS.md](docs/OPERATIONS.md)     |
| Packages and release process       | [docs/PACKAGING.md](docs/PACKAGING.md)       |
| Verification and limits            | [docs/VERIFICATION.md](docs/VERIFICATION.md) |
| KagNode Account linking            | [docs/ACCOUNT-SYNC.md](docs/ACCOUNT-SYNC.md) |
| Changelog                          | [CHANGELOG.md](CHANGELOG.md)                 |

## Licensing

See [LICENSE](LICENSE) and retained third-party notices. KagNode artwork retains its separate permission and brand policy; the application uses AGPL-3.0-only.

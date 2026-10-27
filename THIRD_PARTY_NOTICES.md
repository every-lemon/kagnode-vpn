# Third-party software

Original VPN application code is MIT licensed. This does not relicense third-party works.

`src/vendor/ikev2.sh` (Copyright 2020–2026 Lin Song) originates
from [hwdsl2/setup-ipsec-vpn](https://github.com/hwdsl2/setup-ipsec-vpn), revision
`e13d110ed35198f8314ef8215d84d8060b3424e5`. Its original header and
[CC BY-SA 3.0](https://creativecommons.org/licenses/by-sa/3.0/legalcode) licensing
are retained. It is a separate work, not covered by the application's MIT license.

The IKEv2 helper is used for explicit certificate lifecycle operations. The application
injects a documented adapter at runtime: it accepts an Ubuntu-packaged Libreswan
engine, suppresses upstream exports/password output, and fixes the output directory.
The modified helper remains CC BY-SA 3.0. Source for the adapter is in
`src/vpn_clients.py`. VPN 4 does not compile or downgrade an existing engine during an application update.

Ubuntu packages, AdGuard Home, Libreswan, WireGuard, xl2tpd, Waitress, pyzipper and
PyCryptodome retain their own licenses. AdGuard Home is fetched using its official
installer. Python runtime dependencies are pinned with hashes in `src/vpn_dependencies.py`.

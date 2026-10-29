# Protocol and network scope

KagNode VPN 4 initially targets Ubuntu Server 24.04 LTS on amd64. Policies govern IPv4
traffic carried through this server. They do not control traffic a device sends
outside the tunnel. IPv6 tunneling and an operating-system-wide kill switch are
not implemented; configure client IPv6 behavior separately before relying on a
full-tunnel deployment.

WireGuard admission is bound to the configured public key and its live, exact
AllowedIPs address. IKEv2 rules are bound to authenticated certificate sessions
and current kernel XFRM identifiers. L2TP rules use authenticated PPP sessions and
interface generations. An IP address by itself does not authorize a client.

Use IKEv2 or WireGuard for new devices. L2TP/IPsec is retained for legacy clients;
it uses IKEv1 and a shared IPsec PSK in addition to individual PPP credentials.
Concurrent L2TP clients behind the same NAT can have implementation-specific
limitations. See the [Libreswan L2TP notes](https://libreswan.github.io/Obsolete-HOWTOs/VPN-server-for-remote-clients-using-IKEv1-with-L2TP).

The router must forward UDP 500/4500 for IPsec and UDP 51820 for WireGuard to this
server. Do not forward UDP 1701, DNS 53 or AdGuard's wizard/admin ports to the
internet. A public endpoint tested from the same Wi-Fi may require router NAT
loopback; also test from an independent network. CGNAT requires an independently
reachable endpoint or an upstream forwarding arrangement.

Apple IKEv2 delivery uses a direct `.mobileconfig` response with the native MIME
type. Open the delivery link in Safari. An import password protects its embedded
PKCS#12 identity; give it separately from the token, QR code or email draft.
Revocation prevents further use through this server, but cannot erase a profile
already copied onto a recipient's device.

The builder's synthetic profile checks do not establish successful connection
from a real iPad or through a particular router. Record those tests before RC or
stable promotion.

Removing the application package pauses traffic from its managed tunnel pools before
stopping the policy controller. Trust keys, administrator MFA, engine binaries and
configuration remain on disk. Reinstall the package, then run the supported setup or
application updater to verify policy and resume service. LAN/SSH traffic outside the
VPN pools is unaffected by this removal guard.

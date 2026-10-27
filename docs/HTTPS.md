# HTTPS and administrator access

The dashboard listens on the configured server LAN IPv4 at port 9001. The default
access mode is LAN. Enabling approved VPN access also requires approving each
administrator's VPN device from that device's Access page. Account MFA is still required.

For public administration, an Owner opens System → Dashboard access and selects HTTPS.
LAN access remains available for recovery. Do not forward port 9001 from the router.

## Managed nginx

First obtain a valid certificate for the chosen hostname and copy the certificate chain
and private key to absolute paths on the server. Keep the key root-owned, mode 0600.
Choose managed nginx, enter the HTTPS origin and certificate/key paths, then apply.
The task validates the hostname, expiry and nginx configuration before enabling it.
A failed nginx deployment restores the previous managed nginx configuration.
Forward TCP 443 to the server. Certificate renewal remains the certificate provider's
responsibility; reload nginx after renewal. This release does not issue ACME certificates.

## Existing proxy

Configure an existing reverse proxy to reach the LAN address on port 9001. Set `Host`
to the public hostname and `X-Forwarded-Proto` to `https`, replacing client-supplied
values. Enter that exact origin and the proxy's source IPv4 in System. Verify the proxy's
TLS configuration before checking the confirmation box and applying.

Only the configured proxy may supply the HTTPS header. Forwarded client-IP headers do
not grant access or bypass throttling. Untrusted origins and hostnames are rejected.
Do not put credentials in URLs, query strings or proxy access logs.

## Optional HTTPS delivery

VPD remains on port 9000. A separate hostname/proxy may forward to that port without
changing native `/files/…mobileconfig` paths, content types or response disposition.
Enter its HTTPS origin in System → Dashboard access → Profile delivery HTTPS origin;
new delivery links and QR codes use that origin.
Disable access logging for delivery URLs because they contain single-use bearer tokens.
Do not cache profile responses. Share import passwords separately from delivery links.

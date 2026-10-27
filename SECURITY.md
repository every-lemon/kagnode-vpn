# Security

Use GitHub private vulnerability reporting for security issues in this repository.
Do not put credentials, profiles, private keys, session cookies, MFA seeds or full server
journals into public issues. Minimal redacted reproduction steps are sufficient initially.

Beta releases are under qualification. The deployment model assumes a dedicated Ubuntu
server, a trusted root console, application authentication, and protected management
networking. Public administration requires HTTPS and an explicitly trusted reverse proxy.
Root can deliberately recover administrator access; automated repair cannot reset MFA,
rotate VPN trust material, broaden policy, wipe databases or rewrite unrelated networking.

Private runtime data and archives are never release artifacts. Verify signed release
manifests against the pinned release key before executing downloaded installers/updaters.

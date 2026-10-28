# Release procedure

`VERSION` is the only authoritative release version. Supported examples:
`4.0.0-beta.1`, `4.0.0-rc.1`, `4.0.0`, `4.0.1`. Tags prepend `v`.
Debian package versions map `-beta.N`/`-rc.N` to `~beta.N`/`~rc.N`.
The download filename retains canonical SemVer, for example
`vpn_4.0.0-beta.2_amd64.deb`; its internal Debian version is `4.0.0~beta.2`.
GitHub normalizes special characters in uploaded names, so do not put `~` in
asset filenames. The workflow downloads and verifies a draft before publishing.

1. Update VERSION/changelog and the short RELEASE_NOTES.md (one or two sentences
   plus a link to the tagged changelog); complete and record the applicable qualification gates.
2. Run CI/tests, syntax checks, package tests and secret scanning on the exact commit.
3. Build with `VPN_RELEASE_KEY=/private/path/key.pem python3 tools/package.py`.
   Use an Ed25519 key. Keep the private key out of Git; distribute only `release-key.pem`.
4. Verify `openssl pkeyutl -verify -pubin -inkey release-key.pem -rawin -in dist/manifest.json -sigfile dist/manifest.sig`.
5. Tag the tested commit `v$(cat VERSION)`. Upload a draft with checksums, signature,
   manifest, `.deb`, `setup.sh` and `update.sh`. Download its assets and run
   `python3 tools/verify_release.py downloaded "$(cat VERSION)"` before publishing.
   Mark beta/RC releases as prereleases.
6. Keep stable update selection excluding prereleases. Never replace assets under an
   existing tag; bump the version instead.

GitHub CLI publication uses browser/device login. No access token belongs in this repo.
For CI signing, store the private release key in the protected GitHub environment's
`VPN_RELEASE_KEY` secret and restrict release permissions. The signing public key is a
trust anchor; rotation needs a deliberate documented trust update, not a downloaded
replacement key accepted without verification.

4.x updates preserve operational state. A failure can restore previous application code;
it must not restore retired 3.x client trust or silently re-enable old administrators.

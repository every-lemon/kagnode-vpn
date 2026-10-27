# Verify a release before installation

Download the package or scripts, `manifest.json`, and `manifest.sig` from the
same [GitHub release](https://github.com/every-lemon/vpn/releases). Use
`release-key.pem` from a previously trusted checkout or installation; do not
replace your trusted key with a key supplied by an unverified update.

The initial Ed25519 public key has this SHA-256 fingerprint of its DER encoding:

```text
c7431a8f18f8f804d98da247cbcc0a340c66aaec91bed130f636d74b37a08e64
```

In the download directory, verify the manifest signature first:

```sh
openssl pkey -pubin -in release-key.pem -outform DER | sha256sum
openssl pkeyutl -verify -pubin -inkey release-key.pem -rawin \
  -in manifest.json -sigfile manifest.sig
```

Only after `Signature Verified Successfully`, verify the downloaded asset against
the signed manifest. Set `asset` below to the exact package or script you will run:

```sh
python3 - <<'PY'
import hashlib, json
from pathlib import Path
asset = 'setup.sh'  # Or update.sh / vpn_4.0.0-beta.2_amd64.deb
manifest = json.loads(Path('manifest.json').read_text())
assert manifest['schema'] == 1
assert manifest['platform'] == 'ubuntu-24.04-amd64'
assert manifest['version'] == '4.0.0-beta.2'
expected = manifest['assets'][asset]
data = Path(asset).read_bytes()
assert len(data) == expected['size'], 'Size mismatch'
assert hashlib.sha256(data).hexdigest() == expected['sha256'], 'Checksum mismatch'
print('Verified:', asset)
PY
```

Stop on any error. `SHA256SUMS` is convenient for checking all downloaded files,
but checksums alone do not authenticate a release. `bash update.sh --verify`
checks embedded integrity and syntax; it also does not replace signature verification.

Normal `vpn update` uses the installed pinned public key and verifies the manifest
and update payload automatically. Beta/RC selection requires `--prerelease`.

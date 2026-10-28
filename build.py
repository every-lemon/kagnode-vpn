#!/usr/bin/env python3
"""Build standalone installer and updater; standard library only."""
import base64
import gzip
import hashlib
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parent
release = (root / 'VERSION').read_text().strip()
shell = (root / 'src/installer.sh').read_text().replace('@@VERSION@@', release).replace('@@RELEASE_KEY@@', (root/'release-key.pem').read_text().strip())
manager_source = (root / 'src/manage.py').read_text().rstrip()
modules = {name: (root / 'src' / (name + '.py')).read_text().replace('@@VERSION@@', release).replace('@@IKE_HELPER@@', base64.b64encode((root/'src/vendor/ikev2.sh').read_bytes()).decode()) for name in ('vpn_clients', 'vpn_web', 'vpn_ui', 'vpn_backend', 'vpn_policy', 'vpn_dependencies', 'vpn_watchdog', 'vpn_admin', 'vpn_harden', 'vpn_portal', 'vpn_auth', 'vpn_version', 'vpn_business', 'vpn_native', 'vpn_maintenance', 'vpn_setup', 'vpn_repair', 'vpn_console', 'vpn_dashboard', 'vpn_access', 'vpn_release', 'vpn_tasks', 'vpn_diagnostics')}
module_blob = base64.b64encode(gzip.compress(json.dumps(modules, sort_keys=True).encode(), mtime=0)).decode()
manager = manager_source.replace('@@MODULE_ARCHIVE@@', module_blob)
assert shell.count('@@PYTHON_RUNTIME@@') == 1
setup = shell.replace('@@PYTHON_RUNTIME@@', manager)
assert re.fullmatch(r'\d+\.\d+\.\d+(?:-(?:beta|rc)\.[1-9]\d*)?', release)
files = {'setup.sh': setup, 'manage.py': manager + '\n'}
for name in ('ikev2.sh',):
    files[name] = (root / 'src/vendor' / name).read_text()
payload = {'version': release, 'files': files,
           'sha256': {name: hashlib.sha256(text.encode()).hexdigest() for name, text in files.items()}}
packed = gzip.compress(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode(), mtime=0)
encoded = base64.b64encode(packed).decode()
encoded = '\n'.join(encoded[i:i+100] for i in range(0, len(encoded), 100))
runtime = (root / 'src/updater.py').read_text().replace('@@UPDATE_PAYLOAD@@', encoded)
runtime = runtime.replace('@@UPDATE_PAYLOAD_HASH@@', hashlib.sha256(packed).hexdigest())
runtime = runtime.replace('@@UPDATE_VERSION@@', release)
runtime = runtime.replace('"""@@VERSION_RUNTIME@@"""', repr((root / 'src/vpn_version.py').read_text()))
update = (root / 'src/updater.sh').read_text().replace('@@UPDATER_RUNTIME@@', runtime)
update = update.replace('@@UPDATE_VERSION@@', release)
for name, text in (('setup.sh', setup), ('update.sh', update)):
    out = root / name
    out.write_text(text)
    out.chmod(0o755)
    print(out)

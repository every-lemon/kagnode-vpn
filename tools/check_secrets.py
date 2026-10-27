#!/usr/bin/env python3
"""Check the exact tracked release inputs, including decoded embedded application modules."""
import base64,gzip,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
patterns=[re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}'),re.compile(rb'github_pat_[A-Za-z0-9_]{40,}'),re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/]{30,}')]
result=subprocess.run(['git','ls-files','-z'],cwd=ROOT,capture_output=True,check=True)
errors=[]
for name in result.stdout.decode().split('\0'):
 if not name:continue
 path=ROOT/name
 if name.startswith(('private/','.venv/','dist/','build/')) or path.suffix in ('.mhtml','.p12','.mobileconfig','.sswan','.db','.key'):
  errors.append(name+': private/runtime file is tracked');continue
 raw=path.read_bytes()
 if any(pattern.search(raw) for pattern in patterns):errors.append(name+': credential material found')
 if name=='setup.sh':
  match=re.search(rb"^_MODULE_ARCHIVE = '([^']+)'$",raw,re.M)
  if not match:errors.append('setup.sh: embedded modules missing')
  else:
   data=gzip.decompress(base64.b64decode(match[1]))
   if any(pattern.search(data) for pattern in patterns):errors.append('setup.sh: credential material in embedded sources')
if errors:
 print('\n'.join(errors),file=sys.stderr);sys.exit(1)
print('Tracked inputs contain no forbidden runtime files or recognized private credentials.')

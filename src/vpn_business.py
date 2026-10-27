"""Business policy model. Evaluates only IPv4 traffic carried through this VPN."""
import ipaddress
import json
import re
import secrets
import time

DEFAULT_GROUP = 'ungrouped'
DEFAULT_POLICY = {'internet': True, 'isolation': True, 'rules': []}

def validate(policy):
    if not isinstance(policy, dict) or set(policy) - {'internet','isolation','rules'}:
        raise ValueError('Invalid access policy.')
    for flag in ('internet','isolation'):
        if flag in policy and type(policy[flag]) is not bool:
            raise ValueError('Policy flags must be booleans.')
    rules = policy.get('rules', [])
    if not isinstance(rules,list) or len(rules) > 64:
        raise ValueError('Use at most 64 policy rules.')
    for rule in rules:
        if set(rule) != {'effect','resource'} or rule['effect'] not in ('allow','deny') or not re.fullmatch(r'[a-f0-9]{32}', rule['resource']):
            raise ValueError('Rules require an allow/deny effect and a resource ID.')
    return policy

def expired(item, now=None):
    now = time.time() if now is None else now
    return bool(item.get('disabled') or item.get('revoked') or item.get('deleted') or (item.get('expires') and float(item['expires']) <= now))

class Business:
    def __init__(self, repo):
        self.repo = repo
        with repo.connect() as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='access_groups'").fetchone():
                return
            db.executescript('''BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS access_groups(id TEXT PRIMARY KEY,name TEXT UNIQUE NOT NULL,policy TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS group_members(device TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,group_id TEXT NOT NULL REFERENCES access_groups(id));
CREATE TABLE IF NOT EXISTS resources(id TEXT PRIMARY KEY,name TEXT UNIQUE NOT NULL,cidr TEXT NOT NULL,protocol TEXT NOT NULL,ports TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS access_policies(kind TEXT NOT NULL CHECK(kind IN ('user','device')),id TEXT NOT NULL,policy TEXT NOT NULL,PRIMARY KEY(kind,id));
''')
            db.execute('INSERT OR IGNORE INTO access_groups VALUES (?,?,?)', (DEFAULT_GROUP,'ungrouped clients',json.dumps(DEFAULT_POLICY)))

    def snapshot(self, connection=None):
        import contextlib
        with (contextlib.nullcontext(connection) if connection is not None else self.repo.connect()) as db:
            return {'groups': {i:{'name':n,'policy':json.loads(p)} for i,n,p in db.execute('SELECT id,name,policy FROM access_groups')},
                    'members':dict(db.execute('SELECT device,group_id FROM group_members')),
                    'resources': {i:{'name':n,'cidr':c,'protocol':p,'ports':json.loads(v)} for i,n,c,p,v in db.execute('SELECT * FROM resources')},
                    'policies':{(k,i):json.loads(p) for k,i,p in db.execute('SELECT * FROM access_policies')}}

    def change(self, form, apply=None):
        action = form['action']
        ident = form.get('id') or secrets.token_hex(16)
        with self.repo.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if action in ('group-add','group-save'):
                name = str(form.get('name','')).strip()
                if not name or len(name) > 80 or any(ord(c)<32 for c in name):
                    raise ValueError('Group name must be 1–80 printable characters.')
                if ident == DEFAULT_GROUP:
                    raise ValueError('The built-in ungrouped clients group cannot be changed.')
                policy = validate(json.loads(form.get('policy','{}')))
                db.execute('INSERT INTO access_groups VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,policy=excluded.policy', (ident,name,json.dumps(policy)))
            elif action == 'group-delete':
                if ident == DEFAULT_GROUP:
                    raise ValueError('The default group cannot be deleted.')
                if db.execute('SELECT 1 FROM group_members WHERE group_id=?',(ident,)).fetchone():
                    raise ValueError('Move members to another group and review access before deleting it.')
                db.execute('DELETE FROM access_groups WHERE id=?',(ident,))
            elif action == 'device-group':
                db.execute('INSERT INTO group_members VALUES (?,?) ON CONFLICT(device) DO UPDATE SET group_id=excluded.group_id', (form['device'],form['group']))
            elif action == 'resource-save':
                name = str(form.get('name','')).strip()
                if not name or len(name)>80 or any(ord(c)<32 for c in name):
                    raise ValueError('Invalid resource name.')
                cidr = str(ipaddress.IPv4Network(form['cidr'], strict=False))
                protocol = form.get('protocol','any')
                if protocol not in ('any','tcp','udp'): raise ValueError('Choose TCP, UDP or any.')
                ports = sorted(set(int(p.strip()) for p in form.get('ports','').split(',') if p.strip()))
                if len(ports)>15 or any(not 1<=p<=65535 for p in ports) or (ports and protocol=='any'):
                    raise ValueError('Use at most 15 ports (1–65535) with TCP or UDP.')
                db.execute('INSERT INTO resources VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,cidr=excluded.cidr,protocol=excluded.protocol,ports=excluded.ports', (ident,name,cidr,protocol,json.dumps(ports)))
            elif action == 'resource-delete':
                # A referenced deny must never disappear silently.
                policies = [p for (p,) in db.execute('SELECT policy FROM access_groups UNION ALL SELECT policy FROM access_policies')]
                if any(any(r['resource']==ident for r in json.loads(p).get('rules',[])) for p in policies):
                    raise ValueError('Remove resource references from policies before deleting it.')
                db.execute('DELETE FROM resources WHERE id=?',(ident,))
            elif action == 'access-policy':
                kind = form['kind']
                if kind not in ('device','user'): raise ValueError('Invalid subject.')
                if not db.execute('SELECT 1 FROM '+('devices' if kind=='device' else 'users')+' WHERE id=?',(ident,)).fetchone():
                    raise ValueError('Subject not found.')
                policy = validate(json.loads(form.get('policy','{}')))
                db.execute('INSERT INTO access_policies VALUES (?,?,?) ON CONFLICT(kind,id) DO UPDATE SET policy=excluded.policy',(kind,ident,json.dumps(policy)))
            else: raise ValueError('Unknown policy action.')
            for (raw,) in db.execute('SELECT policy FROM access_groups UNION ALL SELECT policy FROM access_policies'):
                for r in json.loads(raw).get('rules',[]):
                    if not db.execute('SELECT 1 FROM resources WHERE id=?',(r['resource'],)).fetchone(): raise ValueError('Unknown resource in rule.')
            if apply:
                apply(self.snapshot(db))
            db.execute("UPDATE metadata SET value=CAST(value AS INTEGER)+1 WHERE key='revision'")
        return ident

    def effective(self, registry, device, snapshot=None):
        snap = snapshot or self.snapshot()
        d = registry['devices'][device]; user = registry['users'][d['user']]
        if expired(d) or expired(user):
            return {'blocked':True, 'reason':'Identity disabled, revoked or expired','internet':False,'isolation':True,'rules':[]}
        group = snap['members'].get(device,DEFAULT_GROUP)
        sources = [('group:'+group,snap['groups'].get(group,snap['groups'][DEFAULT_GROUP])['policy']),('user:'+d['user'],snap['policies'].get(('user',d['user']),{})),('device:'+device,snap['policies'].get(('device',device),{}))]
        rules=[]
        for source,policy in sources:
            for rule in policy.get('rules',[]):
                resource = snap['resources'].get(rule['resource'])
                if resource is None: return {'blocked':True,'reason':'Unresolved resource','internet':False,'isolation':True,'rules':[]}
                rules.append(dict(resource, effect=rule['effect'], source=source, id=rule['resource']))
        internet = [p['internet'] for _,p in sources if 'internet' in p]
        isolation = [p['isolation'] for _,p in sources if 'isolation' in p]
        return {'blocked':False,'group':group,'internet':False not in internet and True in internet,'isolation':True in isolation or not isolation,'rules':sorted(rules,key=lambda r:r['effect']!='deny'),'reason':'Group, user and device grants; explicit denies take precedence.'}

    def preview(self, registry, device, address, protocol, port, state=None):
        target=ipaddress.IPv4Address(address);port=int(port)
        if protocol not in ('tcp','udp') or not 1<=port<=65535:raise ValueError('Choose TCP/UDP and a port from 1–65535.')
        policy=self.effective(registry,device)
        if policy['blocked']:return {'allowed':False,'reason':policy['reason']}
        def match(rule):
            return target in ipaddress.IPv4Network(rule['cidr']) and rule['protocol'] in ('any',protocol) and (not rule['ports'] or port in rule['ports'])
        for rule in policy['rules']:
            if rule['effect']=='deny' and match(rule):return {'allowed':False,'reason':rule['source']+' / '+rule['name']+' / deny'}
        if state:
            if str(target)==state['lan']:
                if port==53:return {'allowed':True,'reason':'Server DNS for authenticated clients'}
                if protocol=='tcp' and port==9000:return {'allowed':True,'reason':'Profile delivery'}
                if protocol=='tcp' and port in (3000,8080,9001):
                    allowed=port==9001 and state.get('admin_mode') in ('vpn','https') and device in state.get('admin_devices',[])
                    return {'allowed':allowed,'reason':'Explicit administrator VPN device approval required'}
            if policy['isolation'] and any(target in ipaddress.IPv4Network(state[k]) for k in ('wg_net','ike_net','l2tp_net')):
                return {'allowed':False,'reason':'Client isolation'}
        for rule in policy['rules']:
            if rule['effect']=='allow' and match(rule):return {'allowed':True,'reason':rule['source']+' / '+rule['name']+' / allow'}
        if state and str(target)==state['lan']:return {'allowed':False,'reason':'No server resource grant'}
        if state:
            networks=[state['lan_net'],'10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','169.254.0.0/16','127.0.0.0/8','224.0.0.0/4']
            with self.repo.connect() as db:
                row=db.execute("SELECT value FROM metadata WHERE key='protected_networks'").fetchone()
            if row:networks+=json.loads(row[0])
            if any(target in ipaddress.IPv4Network(n) for n in networks):return {'allowed':False,'reason':'Protected network without a resource grant'}
            return {'allowed':policy['internet'],'reason':'Internet policy'}
        return {'allowed':policy['internet'] and target.is_global,'reason':'Internet policy' if target.is_global else 'No resource grant'}

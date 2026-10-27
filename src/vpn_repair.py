"""Evidence-first, bounded repair of application-owned resources only."""
import datetime
import hashlib
import json
import time

class Doctor:
    def __init__(self, manager): self.m=manager

    def inspect(self):
        from vpn_web import unit_files
        checks=[]
        for name, expected in unit_files().items():
            path=self.m.ETC/'systemd/system'/name
            checks.append({'id':'unit:'+name,'ok':path.is_file() and not path.is_symlink() and path.read_text()==expected,'repair':'owned-unit'})
        private={'database':self.m.BASE/'backend.db','configuration':self.m.ETC/'vpn/state.json'}
        for name,path in private.items():
            if path.exists(): checks.append({'id':'mode:'+name,'ok':not path.is_symlink() and path.stat().st_mode&0o777==0o600,'repair':'private-mode' if not path.is_symlink() else None})
        result=self.m.command(['systemctl','is-active','vpn-control','vpn-downloads','vpn-management','vpn-firewall'],check=False,timeout=10)
        checks.append({'id':'services','ok':result.returncode==0,'observed':result.stdout.strip().splitlines(),'repair':'restart'})
        # Only restore policy rules previously installed by this application.
        if (self.m.BASE/'policy-installed').exists():
            result=self.m.command(['iptables-save','-t','filter'],check=False,timeout=10)
            lines=[line for line in result.stdout.splitlines() if line.startswith(('-A VPNSTACK-LAN-IN ','-A VPNSTACK-LAN-FWD '))]
            try: expected=json.loads((self.m.BASE/'policy-snapshot.json').read_text()).get('kernel')
            except (OSError,ValueError):expected=None
            actual=hashlib.sha256('\n'.join(lines).encode()).hexdigest()
            checks.append({'id':'managed-policy','ok':result.returncode==0 and bool(expected) and actual==expected,'repair':'managed-policy' if result.returncode==0 else None})
        dropin=self.m.ETC/'systemd/resolved.conf.d/zzzz-vpn.conf'
        if dropin.is_file():
            result=self.m.command(['ss','-H','-lntup','( sport = :53 )'],check=False,timeout=10)
            conflict=any('systemd-resolve' in line and ('127.0.0.53' in line or '127.0.0.54' in line) for line in result.stdout.splitlines())
            checks.append({'id':'managed-resolver-stub','ok':result.returncode==0 and not conflict,'repair':'resolver' if result.returncode==0 else None})
        return checks

    def repair(self, maintenance_held=False):
        from vpn_maintenance import Coordinator
        with Coordinator(self.m).exclusive(held=maintenance_held):
            return self._repair_locked()

    def _repair_locked(self):
        from vpn_web import unit_files
        checks=self.inspect(); stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        directory=self.m.BASE/'logs'; directory.mkdir(mode=0o700,parents=True,exist_ok=True)
        evidence={'before':checks,'actions':[]}
        path=directory/('repair-'+stamp+'.json')
        for args in (['journalctl','-u','vpn-control','-u','vpn-management','-u','vpn-downloads','-n','100','--no-pager'],['systemctl','status','vpn-control','vpn-management','vpn-downloads','--no-pager']):
            result=self.m.command(args,check=False,timeout=15)
            self.m.atomic(directory/('repair-'+stamp+'-'+args[0]+'.log'),result.stdout+result.stderr)
        self.m.atomic(path,json.dumps(evidence,indent=2))
        budget=self.m.BASE/'repair-budget.json';now=time.time()
        history=json.loads(budget.read_text()) if budget.exists() else []
        history=[t for t in history if now-t<600]
        if any(not c['ok'] and c['repair'] for c in checks):
            if len(history)>=2:raise RuntimeError('Repair limit reached. Evidence recorded; inspect the fault before retrying.')
            self.m.atomic(budget,json.dumps(history+[now]))
        restart=False
        try:
            for check in checks:
                if check['ok'] or not check['repair']:continue
                action=check['repair']
                if action=='owned-unit':
                    name=check['id'].split(':',1)[1]
                    self.m.atomic(self.m.ETC/'systemd/system'/name,unit_files()[name],0o644)
                    restart=True
                elif action=='private-mode':
                    target=self.m.BASE/'backend.db' if check['id']=='mode:database' else self.m.ETC/'vpn/state.json'
                    target.chmod(0o600)
                elif action=='resolver':
                    self.m.prepare_dns()  # Verifies upstream resolution and rolls back on failure.
                    restart=True
                elif action=='managed-policy':
                    import vpn_policy
                    vpn_policy.apply(self.m.clients_backend())
                elif action=='restart': restart=True
                evidence['actions'].append(check['id'])
            # Operation lock excludes executing jobs. Never replay a native credential operation.
            database=self.m.BASE/'backend.db'
            if database.exists():
                repo=self.m.clients_backend().repo
                with repo.connect() as db:
                    running=db.execute("SELECT count(*) FROM jobs WHERE status='running'").fetchone()[0]
                if running:
                    repo.recover_jobs();evidence['actions'].append('mark-interrupted-jobs')
            if restart:
                self.m.command(['systemctl','daemon-reload'])
                self.m.command(['systemctl','restart','vpn-control','vpn-downloads','vpn-management','vpn-firewall'])
            evidence['after']=self.inspect()
            evidence['verified']=all(c['ok'] for c in evidence['after'])
            return evidence
        except Exception as exc:
            evidence['error']=str(exc)[:500];raise
        finally:
            self.m.atomic(path,json.dumps(evidence,indent=2))
            # Keep the most recent twenty evidence sets; do not touch other logs.
            records=sorted(directory.glob('repair-*.json'),reverse=True)
            for old in records[20:]:
                stem=old.stem
                for file in directory.glob(stem+'*'):
                    if file.is_file() and not file.is_symlink():file.unlink()


def repair_unit():
    return """[Unit]
Description=VPN evidence-first managed fault recovery
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/lib/vpn/manage.py repair-auto
UMask=0077
PrivateTmp=yes
LimitCORE=0
MemoryMax=256M
TimeoutStartSec=120
"""

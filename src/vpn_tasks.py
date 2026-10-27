"""Fixed owner-authorized system tasks outside the HTTP broker sandbox."""
import contextlib
import fcntl
import json
import time
from pathlib import Path

ALLOWED={'system-repair','access-save','update'}

@contextlib.contextmanager
def task_lock(manager):
    with (manager.BASE/'system-task.lock').open('a') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError('A system task is already pending or running.') from None
        yield

def submit(manager, actor, form):
    with task_lock(manager):
        return _submit(manager,actor,form)

def _submit(manager, actor, form):
    from vpn_web import Store
    action=form.get('action')
    if action not in ALLOWED: raise ValueError('Unsupported system task.')
    Store(manager.BASE/'backend.db').require_actor(actor,action)
    path=manager.BASE/'system-task.json'
    if path.exists() and json.loads(path.read_text()).get('status') in ('queued','running'):
        raise ValueError('A system task is already pending. Inspect its status before retrying.')
    manager.atomic(path,json.dumps({'actor':actor,'form':form,'status':'queued','created':time.time()}))
    try: manager.command(['systemctl','start','--no-block','vpn-system-task.service'],timeout=10)
    except Exception:
        data=json.loads(path.read_text());data['status']='failed';manager.atomic(path,json.dumps(data));raise
    return {'message':'System task queued. Progress and diagnostic result are shown under System.'}

def execute(manager):
    with task_lock(manager):
        return _execute(manager)

def _execute(manager):
    from vpn_web import Store
    from vpn_maintenance import Coordinator
    path=manager.BASE/'system-task.json';task=json.loads(path.read_text())
    if task.get('status')!='queued':return
    actor=task['actor'];form=task['form'];action=form.get('action')
    if action not in ALLOWED:raise ValueError('Unsupported system task.')
    try:
        Store(manager.BASE/'backend.db').require_actor(actor,action)
        task.update(status='running',started=time.time());manager.atomic(path,json.dumps(task))
        if action=='system-repair':
            from vpn_repair import Doctor
            result=Doctor(manager).repair()
        elif action=='access-save':
            from vpn_access import configure
            with Coordinator(manager).exclusive(apt=False):
                state=configure(manager,form)
                import vpn_policy,vpn_web
                vpn_policy.apply(manager.clients_backend())
                vpn_web.enable(manager.clients_backend(),manager.module_source('vpn_web'),open_manager=False)
                result={'mode':state['admin_mode']}
        else:
            from vpn_release import fetch
            result=fetch(manager,prerelease=form.get('prerelease')=='yes',apply=True)
        task.update(status='complete',result=result)
    except Exception as exc:
        task.update(status='failed',result={'error':str(exc)[:500]})
        raise
    finally:
        task['finished']=time.time();manager.atomic(path,json.dumps(task))

def unit():
    return '''[Unit]
Description=VPN owner-authorized system maintenance task
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/lib/vpn/manage.py system-task
UMask=0077
PrivateTmp=yes
LimitCORE=0
MemoryMax=384M
TimeoutStartSec=30min
'''

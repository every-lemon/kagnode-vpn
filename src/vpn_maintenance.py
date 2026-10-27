"""Native APT timers and a shared, durable maintenance/reboot coordinator."""
import contextlib
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import time
from zoneinfo import ZoneInfo

SECURITY = '''// Managed by VPN: security updates only; reboot decisions belong to VPN.
#clear Unattended-Upgrade::Allowed-Origins;
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Allowed-Origins {
  "${distro_id}:${distro_codename}-security";
  "${distro_id}ESMApps:${distro_codename}-apps-security";
  "${distro_id}ESM:${distro_codename}-infra-security";
};
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "false";
'''

class Coordinator:
    def __init__(self, manager, clock=time.time):
        self.m, self.clock = manager, clock
        self.path = manager.BASE/'maintenance.json'

    def load(self):
        if not self.path.exists():
            return {'mode':'manual','timezone':'UTC','window':'03:00','reboots':[]}
        return json.loads(self.path.read_text())

    def save(self, data):
        self.m.atomic(self.path,json.dumps(data,indent=2)+'\n')

    @contextlib.contextmanager
    def exclusive(self, held=False, apt=True):
        with contextlib.ExitStack() as stack:
            for name in ([] if held else ['maintenance.lock']) + ['operation.lock']:
                stream=stack.enter_context((self.m.BASE/name).open('a'))
                try: fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError: raise RuntimeError('Maintenance or a native job is running; retry later.') from None
            # APT uses POSIX record locks, not flock. Retain these through the request.
            for filename in (('/var/lib/dpkg/lock-frontend','/var/lib/dpkg/lock','/var/lib/apt/lists/lock','/var/cache/apt/archives/lock') if apt else ()):
                path=self.m.ETC.parent/filename.lstrip('/')
                if not path.exists(): continue
                stream=stack.enter_context(path.open('r+'))
                try: fcntl.lockf(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError: raise RuntimeError('Ubuntu package maintenance is active; reboot deferred.') from None
            yield

    def configure(self, values):
        mode=values.get('mode','manual'); zone=values.get('timezone','UTC'); window=values.get('window','03:00')
        if mode not in ('manual','window','once') or not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d',window):
            raise ValueError('Choose manual, once, or window, and HH:MM.')
        ZoneInfo(zone)
        once=float(values.get('at') or 0)
        if mode=='once' and not self.clock()+60<=once<=self.clock()+365*86400:
            raise ValueError('One-time reboot must be between one minute and one year ahead (Unix timestamp).')
        with self.exclusive():
            state=self.load(); state.update(mode=mode,timezone=zone,window=window,at=once)
            self.save(state)
        return state

    def reboot(self, reason, actor, held=False):
        with self.exclusive(held):
            data=self.load(); now=self.clock(); previous=float(data.get('last_clock',now))
            history=[t for t in data.get('reboots',[]) if now-t<86400]
            if now<previous or len(history)>=2 or (history and now-max(history)<1800):
                raise RuntimeError('Reboot budget/cooldown or clock guard prevents another reboot.')
            data.update(reboots=history+[now],last_clock=now,last_reason=reason,last_actor=actor)
            if data.get('mode')=='once': data['mode']='manual'
            self.save(data)  # Durable budget before side effects; failed requests still consume a slot.
            os.sync()
            self.m.command(['systemctl','reboot'],timeout=10)

    def tick(self):
        data=self.load(); now=self.clock(); required=(self.m.ETC.parent/'run/reboot-required').exists()
        local=datetime.datetime.fromtimestamp(now,ZoneInfo(data.get('timezone','UTC')))
        mode=data.get('mode','manual')
        due=(mode=='once' and now>=data.get('at',float('inf'))) or (mode=='window' and required and local.strftime('%H:%M')==data['window'] and data.get('last_window')!=local.date().isoformat())
        if due:
            self.reboot('scheduled maintenance','maintenance-timer')
            data=self.load(); data['last_window']=local.date().isoformat(); self.save(data)
        return self.status()

    def status(self):
        state=self.load()
        state['reboot_required']=(self.m.ETC.parent/'run/reboot-required').exists()
        try:
            state['apt']=self.m.command(['systemctl','show','apt-daily.timer','apt-daily-upgrade.timer','apt-daily-upgrade.service','-p','Id','-p','LastTriggerUSec','-p','NextElapseUSecRealtime','-p','Result','-p','ActiveState'],check=False,timeout=5).stdout
        except (OSError,RuntimeError): state['apt']='unavailable'
        return state


def install(manager):
    manager.command(['apt-get','-y','-o','DPkg::Lock::Timeout=120','install','unattended-upgrades'],timeout=600)
    manager.atomic(manager.ETC/'apt/apt.conf.d/52vpn-security',SECURITY,0o644)
    for unit,mode in (('apt-daily','update'),('apt-daily-upgrade','install')):
        manager.atomic(manager.ETC/f'systemd/system/{unit}.service.d/vpn.conf', '[Service]\nExecStart=\nExecStart=/usr/bin/flock --exclusive /var/lib/vpn/maintenance.lock /usr/lib/apt/apt.systemd.daily '+mode+'\n',0o644)
    manager.atomic(manager.ETC/'systemd/system/vpn-maintenance.service','[Unit]\nDescription=VPN scheduled maintenance coordinator\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /usr/lib/vpn/manage.py maintenance-tick\nUMask=0077\n',0o644)
    manager.atomic(manager.ETC/'systemd/system/vpn-maintenance.timer','[Unit]\nDescription=VPN maintenance schedule\n[Timer]\nOnCalendar=*-*-* *:*:00\nAccuracySec=1s\nPersistent=false\n[Install]\nWantedBy=timers.target\n',0o644)
    if not Coordinator(manager).path.exists(): Coordinator(manager).save(Coordinator(manager).load())
    manager.command(['systemctl','daemon-reload'])
    manager.command(['systemctl','enable','--now','apt-daily.timer','apt-daily-upgrade.timer','vpn-maintenance.timer'])

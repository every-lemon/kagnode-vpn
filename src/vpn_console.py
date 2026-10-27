"""Authenticated console workflows with the same broker permissions as the web UI."""
import getpass
import json
import os
import sys


def enroll_owner(manager):
    from vpn_web import Store
    store=Store(manager.BASE/'backend.db')
    if store.has_password(): return
    if not sys.stdin.isatty(): raise RuntimeError('Owner enrollment requires a private interactive console.')
    username=input('First owner username: ').strip()
    password=getpass.getpass('Password (12–256 characters): ')
    if getpass.getpass('Confirm password: ')!=password: raise ValueError('Passwords differ.')
    with store.connect() as db:
        pending=db.execute('SELECT 1 FROM administrators WHERE username=? AND enrolled=0',(username,)).fetchone()
    result=store.resume_enrollment(username,password) if pending else store.create_admin(username,password,'owner')
    print('Add this secret to your authenticator app (issuer VPN): '+result['secret'])
    codes=store.enroll(result['enrollment'],input('Current authenticator code: ').strip())
    print('Single-use recovery codes. Store privately; they are not shown again:\n'+'\n'.join(codes))
    input('Press Enter after saving your recovery codes: ')


def ssh_choice(manager):
    path=manager.BASE/'ssh-choice.json'
    if path.exists(): return
    import vpn_ui as ui
    choice=ui.choose('Setup / SSH access', [('keep','Keep the current SSH configuration'),('disable','Disable SSH (console access required)'),('enable','Explicitly install and enable OpenSSH')])
    if choice=='disable':
        if not ui.confirm('Disable SSH? Current remote access may end. Console access is required.'): return
        manager.command(['systemctl','disable','--now','ssh.socket','ssh.service'],check=False)
        manager.atomic(manager.BASE/'ssh-disabled','yes\n')
    elif choice=='enable':
        manager.command(['apt-get','-y','-o','DPkg::Lock::Timeout=120','install','openssh-server'],timeout=600)
        manager.command(['systemctl','enable','--now','ssh.service'])
        (manager.BASE/'ssh-disabled').unlink(missing_ok=True)
    manager.atomic(path,json.dumps({'choice':choice}))


def run(manager, initial=None):
    from vpn_web import Controller,Store
    from vpn_auth import permitted
    import vpn_ui as ui
    backend=manager.clients_backend(); store=Store(backend.repo.path); controller=Controller(backend,store)
    username=ui.ask('VPN / Sign in / Username')
    password=ui.ask('VPN / Sign in / Password',secret=True)
    code=ui.ask('VPN / Sign in / Authenticator or recovery code',secret=True)
    session,csrf=store.login(password,'console',username,code)
    state=manager.load()
    context={'session':session,'csrf':csrf,'peer':state['lan'],'host':state['lan']+':9001'}
    try:
        while True:
            identity=store.identity(session)
            options=[('status','Status and audit'),('users','Users'),('devices','Devices'),('groups','Groups and resources'),('delivery','Profile delivery'),('admins','Administrators'),('system','System maintenance'),('logout','Sign out')]
            if identity['role']=='auditor': options=[options[0],options[-1]]
            section=initial or ui.choose('VPN / '+identity['username']+' ('+identity['role']+')',options); initial=None
            if section=='logout': return
            if section=='status':
                ui.show('VPN / Status',json.dumps(controller.handle(dict(context,op='audit-view'),0),indent=2)); continue
            reg=backend.load()
            form={}
            if section=='users':
                form={'action':'user-add','name':ui.ask('VPN / Users / New name')}
            elif section in ('devices','delivery'):
                if not reg['users']: raise ValueError('Create a user first.')
                if section=='devices':
                    user=ui.choose('VPN / Devices / Owner',[(i,u['name']) for i,u in reg['users'].items()])
                    form={'action':'device-add','user':user,'name':ui.ask('VPN / Devices / New name')}
                else:
                    device=ui.choose('VPN / Delivery / Device',[(i,d['name']) for i,d in reg['devices'].items() if not d.get('deleted')])
                    action=ui.choose('VPN / Delivery / Action',[('protocols-add','Add protocols'),('prepare-export','Prepare native files'),('delivery-link','Publish a one-download link')])
                    form={'action':action,'device':device,'protocols':'ikev2','platform':'apple'}
                    if action=='protocols-add': form['protocols']=','.join(ui.multi_select('Protocols',[('ikev2','IKEv2'),('wireguard','WireGuard'),('l2tp','L2TP/IPsec')]))
            elif section=='groups':
                form={'action':'group-add','name':ui.ask('VPN / Groups / New group name'),'policy':'{"internet":true,"isolation":true,"rules":[]}'}
            elif section=='admins':
                form={'action':'admin-add','username':ui.ask('VPN / Administrators / Username'),'password':ui.ask('Initial password',secret=True),'role':ui.choose('Role',[(r,r.title()) for r in ('owner','operator','auditor')])}
            elif section=='system':
                action=ui.choose('VPN / System',[('doctor','Diagnose'),('system-repair','Repair known managed faults'),('maintenance-status','Security updates and reboots')])
                if action in ('doctor','maintenance-status'):
                    from vpn_repair import Doctor
                    from vpn_maintenance import Coordinator
                    ui.show('VPN / System',json.dumps(Doctor(manager).inspect() if action=='doctor' else Coordinator(manager).status(),indent=2)); continue
                form={'action':action}
            if not permitted(identity['role'],form.get('action','')): raise ValueError('Your role cannot perform this operation.')
            result=controller.handle(dict(context,op='action',form=form),0)
            ui.show('VPN / Result',result.get('message',json.dumps(result)))
    except ui.Cancel:
        return
    finally: store.logout(session)


def authenticate_owner(manager):
    from vpn_web import Store
    store=Store(manager.BASE/'backend.db')
    username=input('Owner username: ').strip()
    password=getpass.getpass('Password: ')
    code=getpass.getpass('Authenticator/recovery code: ')
    session,_=store.login(password,'console',username,code)
    try:
        if store.identity(session)['role']!='owner':raise ValueError('Owner authorization required.')
    finally:store.logout(session)


def recover_owner(manager):
    """Deliberate OS-root escape hatch; creates a new MFA-enrolled owner."""
    from vpn_web import Store
    if os.geteuid()!=0 or not sys.stdin.isatty():
        raise RuntimeError('Owner recovery requires OS root at a private interactive console.')
    print('Emergency owner recovery is audited. Existing accounts and VPN keys remain unchanged.')
    if input('Type RECOVER OWNER: ')!='RECOVER OWNER': raise ValueError('Recovery cancelled.')
    store=Store(manager.BASE/'backend.db')
    username=input('New recovery owner username: ').strip()
    password=getpass.getpass('New password (12–256 characters): ')
    if getpass.getpass('Confirm password: ')!=password: raise ValueError('Passwords differ.')
    result=store.create_admin(username,password,'owner',actor='console-recovery')
    print('Authenticator secret (issuer VPN): '+result['secret'])
    codes=store.enroll(result['enrollment'],input('Authenticator code: ').strip())
    print('Save these single-use recovery codes privately:\n'+'\n'.join(codes))

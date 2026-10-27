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
    print('Use the next authenticator code when signing in; the enrollment code has already been used.')
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


def name_valid(value):
    if not value.strip() or len(value)>80 or any(ord(c)<32 for c in value):
        raise ValueError('Use 1–80 printable characters.')


def workflow(section,backend,controller,identity,context):
    import vpn_ui as ui
    from vpn_business import Business
    reg=backend.load()
    def choose_items(title,items):
        if not items: raise ValueError('No matching entries. Create an entry first.')
        return ui.choose(title,items)
    def name(title,default=''):
        return ui.ask(title,default,validate=name_valid)
    def protocol(device):
        return choose_items('VPN / Device / Protocol',[(p,p) for p,v in reg['devices'][device]['protocols'].items() if v.get('status')!='revoked'])
    if section=='status':
        ui.show('VPN / Status and audit',json.dumps(controller.handle(dict(context,op='audit-view'),0),indent=2));return
    if section in ('users','devices'):
        kind='user' if section=='users' else 'device'
        items=reg[section]
        ident=ui.choose('VPN / '+section.title(),[('__new__','Create '+kind)]+[(i,v['name']) for i,v in items.items() if not v.get('deleted')])
        if ident=='__new__':
            form={'action':kind+'-add','name':name('VPN / '+section.title()+' / New name')}
            if kind=='device':form['user']=choose_items('VPN / Device / Owner',[(i,u['name']) for i,u in reg['users'].items() if not u.get('deleted')])
            return form
        options=[('rename','Rename'),('identity-state','Enable, disable or set expiry')]
        if kind=='device':options += [('assign','Change owner'),('device-group','Change group'),('protocols-add','Add VPN protocols'),('revoke','Revoke a protocol'),('policy-preview','Preview effective access')]
        else: options += [('user-revoke','Revoke every device for this user')]
        action=ui.choose('VPN / '+section.title()+' / '+items[ident]['name'],options)
        form={'action':action,'id':ident,'kind':kind,'device':ident if kind=='device' else ''}
        if action=='rename':form['name']=name('New name',items[ident]['name'])
        elif action=='assign':form['user']=choose_items('New owner',[(i,u['name']) for i,u in reg['users'].items()])
        elif action=='identity-state':
            import datetime
            record=items[ident]
            form['disabled']=ui.choose('Identity access',[('no','Enabled'),('yes','Disabled')],default=1 if record.get('disabled') else 0)
            previous=datetime.datetime.fromtimestamp(record['expires'],datetime.timezone.utc).isoformat(timespec='minutes') if record.get('expires') else ''
            def expiry(value):
                if value:datetime.datetime.fromisoformat(value)
            form['expires']=ui.ask('Expiry in UTC (ISO date/time; blank means no expiry)',previous,validate=expiry)
        elif action=='device-group':form['group']=ui.choose('Group',[(i,g['name']) for i,g in Business(backend.repo).snapshot()['groups'].items()])
        elif action=='protocols-add':form['protocols']=','.join(ui.multi_select('VPN protocols',[(p,p) for p in ('ikev2','wireguard','l2tp')]))
        elif action in ('revoke','user-revoke'):
            if action=='revoke':form['protocol']=protocol(ident)
            else:form['user']=ident
            if not ui.confirm('Revoke these credentials? Existing profiles will stop working.'):return
            form['confirm']='REVOKE'
        elif action=='policy-preview':
            import ipaddress
            form.update(address=ui.ask('Destination IPv4',validate=ipaddress.IPv4Address),protocol=ui.choose('Protocol',[('tcp','TCP'),('udp','UDP')]),port=ui.ask('Destination port','443'))
        return form
    if section=='delivery':
        device=choose_items('VPN / Delivery / Device',[(i,d['name']) for i,d in reg['devices'].items() if not d.get('deleted')])
        action=ui.choose('VPN / Delivery / Action',[('prepare-export','Prepare native files'),('delivery-link','Publish a one-download link')])
        protocols=ui.multi_select('Protocols',[(p,p) for p,v in reg['devices'][device]['protocols'].items() if v.get('status')=='active'])
        form={'action':action,'device':device,'protocols':','.join(protocols),'platform':'apple'}
        if action=='prepare-export' and 'ikev2' in protocols:
            form['platform']=ui.choose('Recipient platform',[(p,p.title()) for p in ('apple','android','windows','other')])
            form['password']=ui.ask('Import password (blank generates one)',secret=True)
        return form
    if section=='groups':
        action=ui.choose('VPN / Groups and resources',[('group-add','Create group'),('resource-save','Create network resource'),('group-rule','Grant or deny a resource'),('group-delete','Delete an empty group')])
        snap=Business(backend.repo).snapshot();form={'action':action}
        if action=='group-add':
            form.update(name=name('Group name'),internet=ui.choose('VPN internet access',[('yes','Allowed'),('no','Blocked')]),isolation=ui.choose('Client isolation',[('yes','Isolated'),('no','Allow client traffic')]))
        elif action=='resource-save':
            import ipaddress
            form.update(name=name('Resource name'),cidr=ui.ask('IPv4 CIDR',validate=lambda v:ipaddress.IPv4Network(v,strict=False)),protocol=ui.choose('Protocol',[('any','Any'),('tcp','TCP'),('udp','UDP')]),ports=ui.ask('Ports, comma-separated (blank means all)'))
        else:
            form['id']=choose_items('Group',[(i,g['name']) for i,g in snap['groups'].items() if i!='ungrouped'])
            if action=='group-rule':form.update(resource=choose_items('Resource',[(i,r['name']) for i,r in snap['resources'].items()]),effect=ui.choose('Rule',[('allow','Allow'),('deny','Deny')]))
            elif not ui.confirm('Delete this empty group?'):return
        return form
    if section=='admins':
        return {'action':'admin-add','username':ui.ask('VPN / Administrators / Username'),'password':ui.ask('Initial password',secret=True),'role':ui.choose('Role',[(r,r.title()) for r in ('owner','operator','auditor')])}
    if section=='system':
        action=ui.choose('VPN / System',[('doctor','Diagnose'),('system-repair','Repair known managed faults'),('maintenance-status','Security updates and reboots')])
        if action in ('doctor','maintenance-status'):
            from vpn_repair import Doctor
            from vpn_maintenance import Coordinator
            ui.show('VPN / System',json.dumps(Doctor(backend.m).inspect() if action=='doctor' else Coordinator(backend.m).status(),indent=2));return
        return {'action':action}


def run(manager, initial=None):
    from vpn_web import Controller,Store
    from vpn_auth import AuthError,permitted
    import vpn_ui as ui
    backend=manager.clients_backend();store=Store(backend.repo.path);controller=Controller(backend,store)
    session=None
    try:
        username=ui.ask('VPN / Sign in / Username')
        password=ui.ask('VPN / Sign in / Password',secret=True)
        code=ui.ask('VPN / Sign in / Authenticator or recovery code',secret=True)
        session,csrf=store.login(password,'console',username,code)
        password=code=None
        state=manager.load();context={'session':session,'csrf':csrf,'peer':state['lan'],'host':state['lan']+':9001'}
        while True:
            identity=store.identity(session)
            options=[('status','Status and audit')]
            if identity['role']!='auditor':options += [('users','Users'),('devices','Devices'),('groups','Groups and resources'),('delivery','Profile delivery')]
            if identity['role']=='owner':options += [('admins','Administrators'),('system','System maintenance')]
            options += [('logout','Sign out')]
            section=initial or ui.choose('VPN / '+identity['username']+' ('+identity['role']+')',options);initial=None
            if section=='logout':return
            try:
                # Deliberate keyboard navigation is activity; passive status polling is not.
                store.identity(session,touch=True)
                form=workflow(section,backend,controller,identity,context)
                if not form:continue
                if not permitted(identity['role'],form.get('action','')):raise ValueError('Your role cannot perform this operation.')
                result=controller.handle(dict(context,op='action',form=form),0)
                message=result.get('message','Completed.')
                if result.get('url'):message+='\n'+result['url']
                ui.show('VPN / Result',message)
            except ui.Cancel:
                continue
            except (ValueError,RuntimeError) as exc:
                ui.show('VPN / Could not complete',str(exc))
                store.identity(session)  # Expired/revoked sessions leave the console.
    except AuthError as exc:
        ui.show('VPN / Sign in required',str(exc))
    except ui.Cancel:
        return
    finally:
        if session:store.logout(session)


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

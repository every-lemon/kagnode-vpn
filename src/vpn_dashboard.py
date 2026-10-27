"""4.x dashboard sections; static, accessible forms, no animation or remote assets."""
import html
import json
import re

def e(value): return html.escape(str(value),quote=True)

def select(name, items, selected=None):
    return '<select name="'+e(name)+'">'+''.join('<option value="'+e(k)+'"'+(' selected' if str(k)==str(selected) else '')+'>'+e(v)+'</option>' for k,v in items)+'</select>'

def identity_fields(record):
    import datetime
    expiry=datetime.datetime.fromtimestamp(record['expires'],datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M') if record.get('expires') else ''
    return select('disabled',[('no','Enabled'),('yes','Disabled')],'yes' if record.get('disabled') else 'no')+'<label>Expires (UTC, blank for no expiry)<input type="datetime-local" name="expires" value="'+e(expiry)+'"></label>'

def render(data, message='', view='overview', **options):
    from vpn_admin import render as original, form, link, STYLE, SCRIPT
    from vpn_web import page
    actor=data.get('identity',{})
    if view not in ('groups','administrators','audit') and actor.get('role')!='auditor':
        document=original(data,message,view=view,**options)
        document=re.sub(rb'<form\b[^>]*>(?:(?!</form>).)*name="action" value="policy"(?:(?!</form>).)*</form>', b'<p>Manage access through Groups &amp; resources.</p>',document,flags=re.S)
        document=re.sub(rb'<p data-policy-kind="[^"]*"[^>]*>.*?</p>',b'',document,flags=re.S)
        links=b'<a href="/manage/groups">Groups &amp; resources</a><a href="/manage/audit">Audit</a>'
        if actor.get('role')=='owner': links+=b'<a href="/manage/administrators">Administrators</a>'
        document=document.replace(b'</nav><div class="sidebar-bottom">',links+b'</nav><div class="sidebar-bottom">',1)
        if view=='delivery':
            document=document.replace(b'<footer>',token_history(data,form).encode()+b'<footer>',1)
        if view=='system':
            document=document.replace(b'<footer>',maintenance(data,form).encode()+b'<footer>',1)
        if view=='users':
            controls='<section><h2>User access and expiry</h2>'
            for ident,record in data.get('registry',{}).get('users',{}).items():
                controls+='<details><summary>'+e(record['name'])+'</summary>'+form('identity-state',data['csrf'],{'kind':'user','id':ident,'return_view':'users'},identity_fields(record),'Apply user state')+'</details>'
            document=document.replace(b'<footer>',(controls+'</section>').encode()+b'<footer>',1)
        if view=='device' and options.get('tab','profiles')=='access':
            document=document.replace(b'<footer>',device_access(data,options.get('device',''),form).encode()+b'<footer>',1)
        return document
    csrf=data.get('csrf','')
    body='<div class="content"><a href="/manage">← Dashboard</a><h1>'+e({'groups':'Groups and resources','administrators':'Administrators','audit':'Status and audit'}.get(view,'Status and audit'))+'</h1>'
    message=message or data.get('flash','')
    if message: body+='<p role="status" class="notice">'+e(message)+'</p>'
    if actor.get('role')=='auditor' or view=='audit':
        body+='<p>Redacted operational history. Credentials and delivery tokens are never included.</p><pre>'+e(json.dumps(data.get('audit',{}),indent=2))+'</pre>'
    elif view=='administrators':
        body+='<p>Every administrator must enroll an authenticator. Disabling or changing a role invalidates existing sessions.</p>'
        for row in data.get('administrators',[]):
            body+='<article><h2>'+e(row['username'])+'</h2><p>'+e(row['role'])+' · '+('enabled' if row['enabled'] else 'disabled')+' · '+('MFA ready' if row['enrolled'] else 'enrollment pending')+'</p>'
            body+=form('admin-role',csrf,{'id':row['id'],'return_view':view},select('role',[(r,r.title()) for r in ('owner','operator','auditor')],row['role']),'Change role')
            body+=form('admin-disable',csrf,{'id':row['id'],'enabled':'no' if row['enabled'] else 'yes','return_view':view},label='Disable' if row['enabled'] else 'Enable')+'</article>'
        body+='<section><h2>Create administrator</h2>'+form('admin-add',csrf,{'return_view':view},'<label>Username<input name="username" autocomplete="off" required></label><label>Initial password<input type="password" name="password" minlength="12" autocomplete="new-password" required></label>'+select('role',[(r,r.title()) for r in ('operator','auditor','owner')]),'Create enrollment')+'</section>'
    elif view=='groups':
        business=data.get('business',{}); groups=business.get('groups',{}); resources=business.get('resources',{})
        body+='<p>These controls apply to IPv4 traffic through the VPN. Explicit denies override grants. Ungrouped clients have internet and server DNS, with LAN access and client-to-client traffic blocked.</p>'
        for ident,g in groups.items():
            body+='<article><h2>'+e(g['name'])+'</h2><p>Internet: '+e(g['policy'].get('internet',False))+' · Client isolation: '+e(g['policy'].get('isolation',True))+'</p><ul>'
            for r in g['policy'].get('rules',[]): body+='<li>'+e(r['effect'])+' '+e(resources.get(r['resource'],{}).get('name','Unavailable'))+'</li>'
            body+='</ul>'
            if ident!='ungrouped':
                body+=form('group-rule',csrf,{'id':ident,'return_view':view},select('effect',[('deny','Deny'),('allow','Allow')])+select('resource',[(i,r['name']) for i,r in resources.items()]),'Add rule')
                body+=form('group-delete',csrf,{'id':ident,'return_view':view},label='Delete empty group')
            body+='</article>'
        body+='<section><h2>New group</h2>'+form('group-add',csrf,{'return_view':view},'<label>Name<input name="name" maxlength="80" required></label>'+select('internet',[('yes','Internet allowed'),('no','Internet blocked')])+select('isolation',[('yes','Isolate clients'),('no','Allow granted client resources')]),'Create group')+'</section>'
        body+='<section><h2>Resources</h2><ul>'+''.join('<li>'+e(r['name'])+' — '+e(r['cidr'])+' '+e(r['protocol'])+' '+e(','.join(map(str,r['ports'])))+'</li>' for r in resources.values())+'</ul>'+form('resource-save',csrf,{'return_view':view},'<label>Name<input name="name" required maxlength="80"></label><label>IPv4 network<input name="cidr" placeholder="192.168.10.0/24" required></label>'+select('protocol',[('tcp','TCP'),('udp','UDP'),('any','Any protocol')])+'<label>Ports (blank for all)<input name="ports" placeholder="443,8443"></label>','Save resource')+'</section>'
    body+='</div>'
    navigation=[('overview','Dashboard'),('devices','Devices'),('users','Users'),('groups','Groups & resources'),('delivery','Delivery'),('jobs','Tasks'),('system','System'),('audit','Audit')]
    if actor.get('role')=='owner':navigation.append(('administrators','Administrators'))
    if actor.get('role')=='auditor':navigation=[('audit','Status & audit')]
    nav='<aside class="sidebar"><a class="brand" href="/manage">VPN</a><nav aria-label="Main navigation">'+''.join('<a href="'+link(key)+'"'+(' aria-current="page"' if key==view else '')+'>'+e(label)+'</a>' for key,label in navigation)+'</nav></aside>'
    top='<header class="topbar"><span>'+e(actor.get('username',''))+' · '+e(actor.get('role',''))+'</span><span class="session">Session expires in <strong data-management data-countdown="'+str(int(data.get('remaining',1800)))+'">30:00</strong></span>'+form('logout',csrf,label='Sign out',target='/manage/logout')+'</header>'
    shell='<div class="app-shell">'+nav+'<div class="workspace" data-view="'+e(view)+'">'+top+body+'</div></div>'
    if actor.get('role')!='auditor':shell+='<script>'+SCRIPT+'</script>'
    return page('VPN management',shell)

def token_history(data, form):
    csrf=data['csrf']; rows=''
    for item in data.get('tokens',[]):
        rows+='<tr><td>'+e(item['device'])+'</td><td>'+e(item['status'])+'</td><td>'+e(item['expires'])+'</td><td>'
        if item['status']=='available': rows+=form('delivery-revoke',csrf,{'hash':item['hash'],'return_view':'delivery'},label='Revoke')
        rows+=form('delivery-reissue',csrf,{'hash':item['hash'],'return_view':'delivery'},label='Reissue')+'</td></tr>'
    return '<section><h2>Delivery history</h2><p>Reissuing invalidates the old token. One download total per token.</p><div class="table-wrap"><table><tr><th>Device</th><th>Status</th><th>Expires (UTC epoch)</th><th>Controls</th></tr>'+rows+'</table></div></section>'

def maintenance(data,form):
    state=data.get('maintenance',{})
    body='<section><h2>Ubuntu security updates</h2><p>Reboot required: '+e(state.get('reboot_required',False))+'</p><pre>'+e(state.get('apt','Unavailable'))+'</pre>'
    if data.get('identity',{}).get('role')=='owner':
        body+=form('maintenance-save',data['csrf'],{'return_view':'system'},select('mode',[('manual','Manual reboots'),('window','Daily window when reboot required'),('once','One scheduled reboot')],state.get('mode','manual'))+'<label>Timezone<input name="timezone" value="'+e(state.get('timezone','UTC'))+'" required></label><label>Daily time<input type="time" name="window" value="'+e(state.get('window','03:00'))+'"></label><label>One-time date/time (in selected timezone)<input type="datetime-local" name="date"></label>','Save reboot policy')
        access=data.get('access',{})
        body+='<h3>Dashboard access</h3><p>LAN access remains available. VPN access requires individual device approval. Public access requires HTTPS.</p>'
        body+=form('access-save',data['csrf'],{'return_view':'system'},select('mode',[('lan','LAN only'),('vpn','LAN and approved VPN devices'),('https','LAN, approved VPN devices and HTTPS')],access.get('admin_mode','lan'))+'<label>Profile delivery HTTPS origin (optional)<input name="vpd_origin" value="'+e(access.get('vpd_origin',''))+'" placeholder="https://profiles.example.com"></label><label>HTTPS origin<input name="origin" value="'+e(access.get('admin_origin',''))+'" placeholder="https://vpn.example.com"></label><label>Trusted proxy IP<input name="proxy" value="'+e(access.get('trusted_proxy') or '127.0.0.1')+'"></label>'+select('managed',[('no','Existing proxy integration'),('yes','Manage nginx using existing TLS files')])+'<label>TLS certificate path<input name="cert"></label><label>TLS private key path<input name="key"></label><label><input type="checkbox" name="tls_verified" value="yes">Existing proxy has been configured and HTTPS verified</label>','Apply access settings')
        body+=form('update',data['csrf'],{'return_view':'system'},'<label><input type="checkbox" name="prerelease" value="yes">Opt in to beta/RC releases</label>','Check and apply signed application update')
        body+=form('reboot',data['csrf'],{'return_view':'system'},'<input name="confirm" placeholder="Type REBOOT" required>','Reboot now')
        body+=form('system-repair',data['csrf'],{'return_view':'system'},label='Diagnose and repair managed faults')
    if data.get('system_task'): body+='<h3>System task</h3><pre>'+e(json.dumps(data['system_task'],indent=2))+'</pre>'
    return body+'</section>'

def device_access(data,device,form):
    business=data.get('business',{}); groups=business.get('groups',{})
    if not device: return ''
    body='<section><h2>Business access</h2>'+form('device-group',data['csrf'],{'device':device,'return_device':device,'return_tab':'access'},select('group',[(i,g['name']) for i,g in groups.items()],business.get('members',{}).get(device,'ungrouped')),'Assign group')
    policy=data.get('effective',{})
    body+='<details><summary>Effective access and rule sources</summary><pre>'+e(json.dumps(policy,indent=2))+'</pre></details>'
    body+=form('identity-state',data['csrf'],{'kind':'device','id':device,'return_device':device,'return_tab':'access'},identity_fields(data.get('registry',{}).get('devices',{}).get(device,{})),'Apply identity state')
    resources=business.get('resources',{})
    body+=form('policy-preview',data['csrf'],{'device':device,'return_device':device,'return_tab':'access'},'<label>Destination IPv4<input name="address" required></label>'+select('protocol',[('tcp','TCP'),('udp','UDP')])+'<label>Port<input type="number" min="1" max="65535" name="port" required></label>','Explain effective access')
    body+=form('device-rule',data['csrf'],{'device':device,'return_device':device,'return_tab':'access'},select('effect',[('deny','Deny'),('allow','Allow')])+select('resource',[(i,r['name']) for i,r in resources.items()]),'Add device rule')
    if data.get('identity',{}).get('role')=='owner':
        body+=form('admin-device',data['csrf'],{'device':device,'return_device':device,'return_tab':'access'},select('approved',[('no','Not approved for administration'),('yes','Approve dashboard access through this VPN device')],'yes' if data.get('admin_approved') else 'no'),'Set administrator device approval')
    return body+'</section>'

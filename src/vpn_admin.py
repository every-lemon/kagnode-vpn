"""Static server-rendered management views and private admin export attachments."""
import base64
import datetime
import hashlib
import html
import json
from pathlib import Path
import re
from urllib.parse import urlencode

STYLE = '''*{box-sizing:border-box}html{color-scheme:dark}body{margin:0;background:#101114;color:#e5e7eb;font:14px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:#83b4ff;text-decoration:none}a:hover{text-decoration:underline}h1,h2,h3,p{margin-top:0}h1{font-size:25px;letter-spacing:-.5px}h2{font-size:21px;letter-spacing:-.3px}h3{font-size:16px}small,.muted,footer{color:#a0a6b3}small{display:block;font-size:12px}button,input,select{font:inherit}button{border:1px solid #427bf1;background:#3972df;color:#fff;border-radius:5px;padding:8px 14px;cursor:pointer;font-weight:600}button:hover{background:#4782ed}button:disabled{opacity:.45;cursor:default}input,select{border:1px solid #424650;background:#15171c;color:#f3f4f6;border-radius:5px;padding:8px 10px;max-width:100%}input[type=checkbox],input[type=radio]{accent-color:#6a9fff;margin-right:7px}input:focus,select:focus,button:focus-visible,a:focus-visible,summary:focus-visible{outline:2px solid #8eb9ff;outline-offset:3px}label{display:inline-block;margin:5px 14px 10px 0;color:#c4cad4}label.block{display:block}label.block input{display:block;width:100%;margin-top:8px}form{margin:12px 0}section,article,.card{background:#191b20;border:1px solid #34373f;border-radius:7px;padding:22px;margin:18px 0}section>h2,section>h3{margin-bottom:12px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(185px,1fr));gap:16px}.grid .card{margin:0}.metric{font-size:30px;font-weight:650;letter-spacing:-1px}.eyebrow{font-size:11px;letter-spacing:1.3px;font-weight:650;color:#b2b8c4}.notice{padding:12px 15px;border:1px solid #315481;border-left:3px solid #72a6f8;background:#172538;border-radius:5px;overflow-wrap:anywhere}.error{background:#341d21;border-color:#a74650}.badge{display:inline-block;font-size:11px;border:1px solid #444954;background:#252830;color:#d3dae6;border-radius:4px;padding:3px 7px;margin:2px 4px 2px 0;white-space:nowrap}.badge.active{color:#8addb3;border-color:#35694d}.badge.failed,.danger{color:#f3a0a5}.danger button{background:#9a3541;border-color:#c25662}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:13px 12px;border-bottom:1px solid #30343c;text-align:left;vertical-align:top}th{font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:#929aaa;font-weight:650}tbody tr:hover{background:#20232a}code,pre{overflow-wrap:anywhere;white-space:pre-wrap;font-size:12px}details{margin:14px 0}summary{cursor:pointer;font-weight:600;color:#c7cfdb}footer{margin:28px 0;font-size:12px}.standalone>header,.standalone>main{max-width:760px;margin:auto;padding:24px}.standalone>header{padding-bottom:0}.management>header{display:none}.management>main{padding:0;max-width:none}.sidebar{position:fixed;inset:0 auto 0 0;width:230px;background:#17191e;border-right:1px solid #34373f;padding:22px 14px;overflow-y:auto}.brand{display:flex;gap:9px;align-items:center;padding:0 12px 23px;color:#f8fafc;font-size:17px;font-weight:700;letter-spacing:.4px}.brand-mark{color:#fa9a4a;font-size:23px}.sidebar .eyebrow{padding:0 12px;margin:18px 0 9px}.sidebar nav{display:grid;gap:4px}.sidebar nav a{color:#aeb7c8;border-radius:5px;padding:9px 13px;font-weight:550}.sidebar nav a:hover{background:#262a32;text-decoration:none}.sidebar nav a[aria-current]{background:#263750;color:#b4d1ff}.sidebar-bottom{margin-top:30px;padding:12px;border-top:1px solid #34373f;font-size:12px;color:#919baa}.workspace{margin-left:230px;min-height:100vh}.topbar{position:sticky;top:0;z-index:3;background:#15171cf5;border-bottom:1px solid #34373f;padding:12px 28px;display:flex;gap:18px;align-items:center;justify-content:space-between}.topbar form{margin:0;display:flex;gap:7px}.topbar input{width:235px}.session{font-size:12px;color:#aeb8c8;white-space:nowrap}.session strong{color:#e6edf8;font-variant-numeric:tabular-nums}.content{max-width:1320px;margin:auto;padding:30px 34px}.page-heading{display:flex;gap:20px;justify-content:space-between;align-items:flex-start;margin-bottom:24px}.page-heading h1{margin-bottom:4px}.tabs{display:flex;gap:8px;flex-wrap:wrap;border-bottom:1px solid #34373f;margin:22px 0}.tabs a{padding:9px 13px;color:#a6b1c3;border-bottom:2px solid transparent}.tabs a[aria-current]{color:#a9cbff;border-color:#78a8fa}.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.toolbar form{margin:0}.pagination{display:flex;gap:20px;align-items:center;margin-top:18px}.file-choice{display:flex;gap:10px;align-items:center;border:1px solid #3c424e;border-radius:6px;padding:15px;margin:10px 0;cursor:pointer}.file-choice:has(input:checked){border-color:#7cabfa;background:#202e44}.file-choice small{margin-top:4px}.certificate-links{display:flex;gap:10px;flex-wrap:wrap}.certificate-links a{border:1px solid #3e4654;border-radius:5px;padding:8px 12px}.portal{max-width:640px;margin:0 auto}.portal h2{font-size:27px}.portal input[name=token]{font-family:monospace}.portal button{width:100%;margin-top:8px}.status-line{font-size:12px;color:#9faabe;display:flex;gap:15px;flex-wrap:wrap}.empty{padding:34px;text-align:center;color:#a0aabc}.mobile-nav{display:none}[hidden]{display:none!important}@media(max-width:900px){.sidebar{width:185px}.workspace{margin-left:185px}.content{padding:24px 20px}.topbar{padding:12px 20px}.topbar input{width:180px}.topbar .search-label{display:none}}@media(max-width:650px){.sidebar{position:static;width:auto;padding:13px;border-right:0;border-bottom:1px solid #34373f;overflow:visible}.brand{padding:0 6px 9px}.sidebar .eyebrow,.sidebar-bottom{display:none}.sidebar nav{display:flex;flex-wrap:wrap;gap:2px}.sidebar nav a{font-size:12px;padding:7px 9px}.workspace{margin:0}.topbar{position:static;padding:12px;flex-wrap:wrap;gap:10px}.topbar input{width:160px}.content{padding:20px 13px}.page-heading{display:block}section,article,.card{padding:16px}th,td{padding:11px 8px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.metric{font-size:24px}.standalone>header,.standalone>main{padding:18px}.session{white-space:normal}}'''


SCRIPT = r"""(() => {
function start() {
'use strict';
const management = document.querySelector('[data-management]');
if (!management) return;
let revision = '';
let remaining = Number(management.dataset.countdown || 0), anchor = performance.now(), closed = false, busy = false;
const links = Array.from(document.querySelectorAll('[data-countdown]:not([data-management])')).map(node => ({node, seconds:Number(node.dataset.countdown), anchor:performance.now()}));
function format(seconds) {
  seconds = Math.max(0, Math.ceil(seconds));
  const days = Math.floor(seconds / 86400); seconds %= 86400;
  return (days ? days + 'd ' : '') + String(Math.floor(seconds / 3600)).padStart(2,'0') + ':' + String(Math.floor(seconds % 3600 / 60)).padStart(2,'0') + ':' + String(seconds % 60).padStart(2,'0');
}
function tick() {
  const now = performance.now(), left = remaining - (now-anchor)/1000;
  management.textContent = left > 0 ? format(left) : 'Management expired';
  for (const item of links) item.node.textContent = format(item.seconds-(now-item.anchor)/1000);
  if (left <= 0) {
    closed = true;
    document.querySelectorAll('form button, form input, form select').forEach(node => node.disabled = true);
  }
}
function text(selector, value) { const node = document.querySelector(selector); if (node) node.textContent = value; }
async function poll() {
  if (closed || busy || document.hidden) return;
  busy = true;
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 5000);
  try {
    const targets = Array.from(document.querySelectorAll('[data-policy-kind]')).slice(0,50).map(node => [node.dataset.policyKind,node.dataset.policyId]);
    const workspace = document.querySelector('[data-view]');
    const view = workspace?.dataset.view || 'overview';
    const device = workspace?.dataset.device || '';
    const jobIds = Array.from(document.querySelectorAll('[data-job]')).slice(0,25).map(node => node.dataset.job);
    const batchIds = Array.from(document.querySelectorAll('[data-batch]')).slice(0,5).map(node => node.dataset.batch);
    const linkIds = links.map(item => item.node.dataset.delivery).filter(value => value).slice(0,10);
    const response = await fetch('/manage/status?jobs='+encodeURIComponent(JSON.stringify(jobIds))+'&batches='+encodeURIComponent(JSON.stringify(batchIds))+'&links='+encodeURIComponent(JSON.stringify(linkIds))+'&targets='+encodeURIComponent(JSON.stringify(targets))+'&view='+encodeURIComponent(view)+'&device='+encodeURIComponent(device)+'&since='+encodeURIComponent(revision), {credentials:'same-origin', cache:'no-store', signal:controller.signal});
    if (response.status === 403) { remaining=0; anchor=performance.now(); tick(); return; }
    if (!response.ok) throw new Error('unavailable');
    const data = await response.json();
    if (revision && revision !== data.revision) text('[data-updates]', 'Updates available — refresh when ready.');
    revision = data.revision || '';
    remaining = data.remaining; anchor = performance.now();
    text('[data-memory]', data.health.memory.MemAvailable + ' / ' + data.health.memory.MemTotal + ' MiB available');
    text('[data-services]', Object.entries(data.health.services).map(([name,state]) => name + ': ' + state).join(' · '));
    text('[data-updated]', new Date(data.health.sampled_at*1000).toLocaleTimeString());
    for (const policy of data.policies || []) {
      const node = document.querySelector('[data-policy-kind="'+policy.kind+'"][data-policy-id="'+policy.id+'"]');
      if (node) node.textContent = 'Effective: '+policy.effective+' · Applied: '+policy.applied+' · Desired: '+policy.desired+' · '+policy.status;
    }
    for (const item of links) {
      if (!item.node.dataset.delivery) continue;
      const state = (data.links || []).find(link => link.hash === item.node.dataset.delivery);
      item.seconds = state ? state.remaining : 0; item.anchor = performance.now();
    }
    if (data.progress?.job) {
      const row = document.querySelector('[data-job="'+data.progress.job+'"]');
      if (row) row.querySelector('[data-message]').textContent = data.progress.stage;
    }
    for (const job of data.jobs) {
      const row = document.querySelector('[data-job="'+job.id+'"]');
      if (!row) continue;
      row.querySelector('[data-status]').textContent = job.status === 'complete' && ['export','prepare-export','bundle'].includes(job.action) ? 'ready' : job.status;
      row.querySelector('[data-message]').textContent = ((job.status === 'running' && data.progress?.job === job.id ? data.progress.stage : '') || job.result?.message || (job.status === 'queued' ? 'Waiting for the current operation; policy changes have priority.' : 'Working')) + (job.result?.reference ? ' Reference: '+job.result.reference : '');
      row.querySelector('[data-elapsed]').textContent = Math.max(0,Math.floor((['queued','running'].includes(job.status)?Date.now()/1000:job.updated)-job.created))+'s elapsed';
    }
    for (const batch of data.batches || []) for (const item of batch.items) {
      const node = document.querySelector('[data-batch-item="'+batch.id+'-'+item.device+'"]');
      if (node) node.textContent = item.status + (item.message ? ' · '+item.message : '');
    }
    tick();
  } catch (_) { text('[data-updated]', 'Status unavailable; retrying. Countdown remains local.'); }
  finally { clearTimeout(timer); busy=false; }
}
tick(); poll();
setInterval(() => { if (!document.hidden) tick(); },1000);
setInterval(poll,15000);
document.addEventListener('keydown', event => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
    const search = document.querySelector('[data-global-search]');
    if (search) { event.preventDefault(); search.focus(); }
  }
});
document.addEventListener('visibilitychange', () => { if (!document.hidden) { tick(); poll(); } });
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, {once:true}); else start();
})();"""


def lifetime_controls():
    return '<label>Link expires in <select name="lifetime"><option value="3600">1 hour</option><option value="86400" selected>24 hours</option><option value="604800">7 days</option><option value="2592000">30 days</option></select></label>'


def e(value):
    return html.escape(str(value), quote=True)


def link(view, **params):
    return '/manage' + ('' if view == 'overview' else '/' + view) + ('?' + urlencode(params) if params else '')


def form(action, csrf, fields=None, extra='', label=None, target='/manage/action'):
    values = {'csrf': csrf, 'action': action, **(fields or {})}
    hidden = ''.join('<input type="hidden" name="' + e(k) + '" value="' + e(v) + '">' for k, v in values.items())
    return '<form method="post" action="' + e(target) + '">' + hidden + extra + '<button>' + e(label or action.replace('-', ' ').capitalize()) + '</button></form>'


APPLE_MIME = 'application/x-apple-aspen-config'


def profile_mime(filename):
    if filename.endswith('.mobileconfig'):
        return APPLE_MIME
    if filename.endswith('.zip'):
        return 'application/zip'
    return 'application/octet-stream'


def visible_device(record):
    if record.get('deleted'):
        return False
    values = record.get('protocols', {})
    return not values or any(value.get('status') != 'revoked' for value in values.values())


def delivery_choice(backend, ident, archive=False):
    _, device = backend.device(ident)
    record = device['protocols'].get('ikev2', {})
    export = record.get('export') or {}
    if not archive and record.get('status') == 'active':
        for suffix in ('.mobileconfig', '.sswan', '.p12'):
            name = next((name for name in export.get('files', []) if name.endswith(suffix)), None)
            if name:
                return backend.exported_file(ident, name), export['generation']
    from vpn_backend import delivery_file
    with backend.repo.connect() as db:
        row = db.execute('SELECT generation,data FROM deliveries WHERE device=?', (ident,)).fetchone()
    if not row:
        raise ValueError('Prepare a profile before publishing it. Use Apple as the device type for Safari installation.')
    meta = json.loads(row[1])
    return delivery_file(backend, ident, row[0], meta['filename']), row[0]


def protocols(record):
    return ' '.join('<span class="badge">' + e(name.upper()) + ' · ' + e(value.get('status', 'unknown')) + '</span>' for name, value in record.get('protocols', {}).items() if value.get('status') != 'revoked') or '<span class="muted">No protocols configured</span>'


def timestamp(value):
    try:
        return datetime.datetime.fromtimestamp(float(value), datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, TypeError, OverflowError, OSError):
        return 'Not recorded'


def diagnostic_panel(data, device=''):
    record=data.get('connection_check')
    fields={'device':device,'return_device':device} if device else {'return_view':'system'}
    body='<section><h3>Connection checks</h3><p>Checks are read-only and run through the job queue. Findings describe traffic through this VPN.</p>'
    body+=form('connection-check',data['csrf'],fields,label='Run connection check')
    if record:
        body+='<p>Checked '+e(timestamp(record['sampled_at']))+' · Reference <code>'+e(record['reference'])+'</code></p><p class="muted">This is a saved snapshot. Connect the device and run again for new evidence.</p><ul>'
        for check in record['checks']:
            body+='<li><span class="badge '+('failed' if check['status']=='failure' else '')+'">'+e(check['status'].upper())+'</span> '+e(check['message'])+('<small>'+e(check['next_step'])+'</small>' if check['status']!='pass' else '')+'</li>'
        body+='</ul>'
    else: body+='<p>Observed connection: unknown. No check has been recorded.</p>'
    if not device and data.get('identity',{}).get('role')=='owner':
        body+=form('support-report',data['csrf'],{'kind':'support'},label='Download redacted support report',target='/manage/file')
    return body+'</section>'


def job_list(jobs, registry, csrf, device=None):
    rows = ''
    for job in jobs:
        if device and job.get('device') != device:
            continue
        ident = job.get('device', '')
        name = registry['devices'].get(ident, {}).get('name', 'General task')
        result = job.get('result') or {}
        message = result.get('message', 'Waiting for the backend.' if job['status'] == 'queued' else 'Working…' if job['status'] == 'running' else '')
        if result.get('reference'): message+=' Reference: '+result['reference']
        retry = ''
        if job['status'] in ('failed', 'interrupted') and job['action'] in ('protocols-add', 'export', 'bundle', 'prepare-export', 'policy', 'repair', 'batch-run', 'delete-profile', 'connection-check'):
            retry = form('job-retry', csrf, {'id': job['id'], 'return_device': ident}, label='Retry task')
        state='ready' if job['status']=='complete' and job['action'] in ('export','prepare-export','bundle') else job['status']
        rows += '<tr data-job="' + e(job['id']) + '"><td>' + (('<a href="' + e(link('device', device=ident)) + '">' + e(name) + '</a>') if ident else e(name)) + '<br><small>' + e(job['action'].replace('-', ' ')) + '</small><small>Requested '+e(timestamp(job['created']))+'<br>Updated '+e(timestamp(job['updated']))+'</small><small data-elapsed></small></td><td data-status>' + e(state) + '</td><td><span data-message>' + e(message) + '</span>' + retry + '<details><summary>Task reference</summary><code>' + e(job['id']) + '</code></details></td></tr>'
    return '<div class="table-wrap"><table><thead><tr><th>Device / task</th><th>Status</th><th>Result</th></tr></thead><tbody>' + (rows or '<tr><td colspan="3">No tasks yet.</td></tr>') + '</tbody></table></div>'


def render(data, message='', view='overview', device='', query='', owner='', page=1, tab='profiles', document=None):
    if document is None:
        from vpn_web import page as document
    reg, csrf = data['registry'], data['csrf']
    navigation = [('overview','Dashboard'),('devices','Devices'),('users','Users'),('batches','Batches'),('delivery','Delivery'),('jobs','Tasks'),('system','System')]
    if view not in dict(navigation) and view not in ('device','search'):
        raise ValueError('Management page not found.')
    active = 'devices' if view in ('device','search') else view
    nav = '<aside class="sidebar"><a class="brand" href="/manage"><span class="brand-mark">◈</span>VPN</a><p class="eyebrow">YOUR APPLIANCE</p><nav aria-label="Main navigation">' + ''.join('<a href="' + link(key) + '"' + (' aria-current="page"' if key == active else '') + '>' + title + '</a>' for key,title in navigation) + '</nav><div class="sidebar-bottom">WireGuard · IKEv2 · L2TP<br>Local control. Private profiles.<br>v@@VERSION@@</div></aside>'
    top = '<header class="topbar"><form method="get" action="/manage/search"><label class="search-label" for="global-search">Search</label><input id="global-search" data-global-search name="q" placeholder="Search devices…  Ctrl K" maxlength="80" value="' + e(query if view == 'search' else '') + '"><button>Find</button></form><span class="session">Session expires in <strong data-management data-countdown="' + str(int(data.get('remaining',1800))) + '">30:00</strong></span>' + form('logout',csrf,label='Log out',target='/manage/logout') + '</header>'
    titles = dict(navigation) | {'device':'Device management','search':'Search results'}
    descriptions = {'overview':'Your VPN services, clients and recent activity.','devices':'Find a device, prepare profiles and manage access.','users':'Organize owners and their network access defaults.','batches':'Create and export devices with a reviewable preview.','delivery':'Publish a private device token. The recipient chooses one file.','jobs':'Track work, recover failures and keep the queue clear.','system':'Service health and focused appliance diagnostics.','device':'Profiles, settings and activity in one place.','search':'Search device and owner names without loading the entire registry.'}
    body = '<div class="page-heading"><div><p class="eyebrow">VPN / ' + e(titles[view].upper()) + '</p><h1>' + e(titles[view]) + '</h1><p class="muted">' + e(descriptions[view]) + '</p><small data-updates role="status"></small></div></div>'
    if message or data.get('flash'):
        body += '<p class="notice" role="status">' + e(message or data['flash']) + '</p>'
    body += '<div data-result-slot></div>'
    paging = data.get('pagination') or {}
    summary = paging.get('summary') or {'users':len(reg['users']),'devices':sum(visible_device(d) for d in reg['devices'].values()),'failed':sum(j['status'] in ('failed','interrupted') for j in data.get('jobs',[]))}
    current = paging.get('page',page)
    if view == 'overview':
        body += '<div class="grid">' + ''.join('<a class="card" href="' + link(key) + '"><small>' + title + '</small><div class="metric">' + str(summary[value]) + '</div></a>' for key,title,value in [('devices','Active devices','devices'),('users','Users','users'),('jobs','Needs attention','failed')]) + '<div class="card"><small>Available memory</small><strong data-memory>Loading…</strong><small>Updated <span data-updated>pending</span></small></div></div>'
        body += '<section><h2>Service health</h2><p data-services>Loading cached service status…</p></section><section><h2>Recent activity</h2>' + job_list(data.get('jobs',[])[:8],reg,csrf) + '</section>'
    elif view == 'users':
        body += '<section><form method="get" action="/manage/users"><label>Find user <input name="q" maxlength="80" value="' + e(query) + '"></label><button>Search</button></form></section><details><summary>Add user</summary>' + form('user-add',csrf,{'return_view':'users'},'<label>Name <input name="name" maxlength="80"></label><label><input type="checkbox" name="random_name" value="yes">Generate random name</label>','Create user') + '</details>'
        for ident,user in reg['users'].items():
            selected = user.get('lan_policy','block')
            options = ''.join('<option value="' + key + '"' + (' selected' if key == selected else '') + '>' + title + '</option>' for key,title in [('block','Block LAN'),('allow','Allow LAN')])
            body += '<article><h3>' + e(user['name']) + '</h3><p data-policy-kind="user" data-policy-id="' + e(ident) + '">Applied: ' + e(selected) + ' · Desired: ' + e(user.get('desired_lan_policy',selected)) + ' · ' + e(user.get('policy_status','applied')) + '</p><a href="' + e(link('devices',owner=ident)) + '">View devices →</a><details><summary>User settings</summary>' + form('rename',csrf,{'kind':'user','id':ident,'return_view':'users'},'<label>Name <input name="name" value="' + e(user['name']) + '" maxlength="80" required></label>','Save name') + form('policy',csrf,{'kind':'user','id':ident,'return_view':'users'},'<label>Network access <select name="policy">' + options + '</select></label>','Apply access') + '</details><details class="danger"><summary>Revoke user credentials</summary>' + form('user-revoke',csrf,{'user':ident,'return_view':'users'},'<input name="confirm" placeholder="Type REVOKE" required>','Revoke all credentials') + '</details></article>'
        body += pagination('users',current,paging.get('total',len(reg['users'])),query)
    elif view in ('devices','delivery','search'):
        owners = '<option value="">All owners</option>' + ''.join('<option value="' + e(key) + '"' + (' selected' if key==owner else '') + '>' + e(row['name']) + '</option>' for key,row in reg['users'].items())
        body += '<section><form method="get" action="' + link(view) + '"><label>Search <input name="q" value="' + e(query) + '" maxlength="80"></label><label>Owner <select name="owner">' + owners + '</select></label><label>Find owner <input name="owner_q" maxlength="80" value="' + e(paging.get('owner_query','')) + '" placeholder="Filter owner choices"></label><button>Filter</button></form>'
        devices = [(key,row) for key,row in reg['devices'].items() if visible_device(row) and (not owner or row['user']==owner) and query.casefold() in (row['name']+' '+reg['users'].get(row['user'],{}).get('name','')).casefold()]
        if not paging:
            devices.sort(key=lambda item:item[1]['name'].casefold())
            devices = devices[(page-1)*50:page*50]
        rows = ''
        for ident,row in devices:
            if view == 'delivery':
                operation = form('delivery-link',csrf,{'device':ident,'return_view':'delivery'},lifetime_controls(),'Create device token') + form('email-draft',csrf,{'device':ident,'kind':'email'},lifetime_controls(),'HTML email draft',target='/manage/file')
            else:
                operation = '<a href="' + e(link('device',device=ident)) + '">Manage →</a>'
            rows += '<tr><td><a href="' + e(link('device',device=ident)) + '">' + e(row['name']) + '</a></td><td>' + e(reg['users'].get(row['user'],{}).get('name','Unknown')) + '</td><td>' + protocols(row) + '</td><td>' + operation + '</td></tr>'
        body += '<div class="table-wrap"><table><thead><tr><th>Device</th><th>Owner</th><th>Protocols</th><th>' + ('Delivery' if view=='delivery' else 'Actions') + '</th></tr></thead><tbody>' + (rows or '<tr><td colspan="4" class="empty">No matching devices. Create one or try another search.</td></tr>') + '</tbody></table></div>' + pagination(view,current,paging.get('total',len(devices)),query,owner) + '</section>'
        if view == 'devices':
            body += '<details' + (' open' if paging.get('owner_query') else '') + '><summary>Add a device</summary>' + owner_search('devices',query=paging.get('owner_query','')) + form('device-add',csrf,{'return_view':'devices'},owner_options(reg) + '<label>Device name <input name="name" maxlength="80"></label><label><input type="checkbox" name="random_name" value="yes">Random name</label>','Create device') + '</details><details><summary>Batch export from this page</summary>' + batch_exports(devices,csrf) + '</details>'
    elif view == 'batches':
        body += '<details' + (' open' if paging.get('owner_query') else '') + '><summary>Create a batch</summary>' + owner_search('batches',query=paging.get('owner_query','')) + batch_creation(reg,csrf) + '</details>' + batch_results(data.get('batches',[]),csrf)
        body += pagination('batches',current,paging.get('total',len(data.get('batches',[]))),size=5)
    elif view == 'jobs':
        body += '<div class="toolbar">' + form('clear-history',csrf,{'return_view':'jobs'},label='Clear completed history') + '</div><section>' + job_list(data.get('jobs',[]),reg,csrf) + '</section>' + pagination('jobs',current,paging.get('total',len(data.get('jobs',[]))),size=25)
    elif view == 'system':
        body += diagnostic_panel(data)
        body += '<section><h2>Services and memory</h2><p data-services>Loading…</p><p data-memory>Loading…</p><small>Last health refresh <span data-updated>pending</span></small></section>'
        security = data.get('hardening') or {}
        body += '<section><h2>Appliance hardening</h2><p>SSH setup choice: ' + e(security.get('ssh','unknown')) + ' · Automatic package purging: disabled · Hardening: ' + e(security.get('status','not recorded')) + '</p><details><summary>Hardening details</summary><pre>' + e(json.dumps(security,indent=2)) + '</pre></details></section>'
        if data.get('diagnostic'):
            body += '<section><h2>Latest export diagnostic</h2><pre>' + e(json.dumps(data['diagnostic'],indent=2)) + '</pre></section>'
        body += '<p class="muted">Service readings are cached. Connection checks run only when requested; refresh after the queued check completes.</p>'
    else:
        if tab not in ('profiles','access','settings','activity'):
            tab = 'profiles'
        body += '<nav class="tabs" aria-label="Device sections">' + ''.join('<a href="' + e(link('device',device=device,tab=key)) + '"' + (' aria-current="page"' if tab==key else '') + '>' + title + '</a>' for key,title in [('profiles','Profiles'),('access','Access'),('settings','Settings'),('activity','Activity')]) + '</nav>'
        body += focused_device(data,device,tab)
        if tab == 'activity' and data.get('diagnostic'):
            body += '<section><h3>Latest export diagnostic</h3><pre>' + e(json.dumps(data['diagnostic'],indent=2)) + '</pre></section>'
    body += '<footer>Sessions expire after 30 idle minutes or 8 hours. <a href="' + e(link('device',device=device,tab=tab) if view=='device' else link(view,q=query,owner=owner,page=current)) + '">Refresh this page</a></footer>'
    shell = '<div class="app-shell">' + nav + '<div class="workspace" data-view="' + e(view) + '" data-device="' + e(device) + '">' + top + '<div class="content">' + body + '</div></div></div><script>' + SCRIPT + '</script>'
    return document('VPN management',shell)


def pagination(view, page, total, query='', owner='', size=50):
    body = '<div class="pagination"><span>' + str(total) + ' results · Page ' + str(page) + '</span>'
    if page>1:
        body += '<a href="' + e(link(view,page=page-1,q=query,owner=owner)) + '">Previous</a>'
    if page*size<total:
        body += '<a href="' + e(link(view,page=page+1,q=query,owner=owner)) + '">Next</a>'
    return body+'</div>'


def owner_options(reg):
    return '<label>Owner <select name="user">' + ''.join('<option value="' + e(key) + '">' + e(row['name']) + '</option>' for key,row in reg['users'].items()) + '</select></label>'


def owner_search(view, device='', query=''):
    fields = '<input type="hidden" name="device" value="' + e(device) + '"><input type="hidden" name="tab" value="settings">' if device else ''
    return '<form method="get" action="' + link(view) + '">' + fields + '<label>Find owner <input name="owner_q" maxlength="80" value="' + e(query) + '" placeholder="Filter owner choices"></label><button>Find owner</button><small>Owner choices are limited to 50 results.</small></form>'


def device_content(data, device, tab):
    reg, csrf = data['registry'], data['csrf']
    body = ''
    if device not in reg['devices']:
        raise ValueError('Device not found. Return to Devices.')
    row = reg['devices'][device]
    if not visible_device(row):
        return '<section><h2>Profile removed</h2><p>This device has no remaining active profiles. Any incomplete cleanup can be retried below.</p><a href="/manage/devices">Back to devices</a></section>' + job_list(data.get('jobs', []), reg, csrf, device)
    def action(name, extra='', label=None, fields=None, target='/manage/action'):
        return form(name, csrf, {'device': device, 'return_device': device, 'return_tab': tab, **(fields or {})}, extra, label, target)
    from vpn_business import expired
    enabled=not (expired(row) or expired(reg['users'].get(row['user'],{})))
    body += '<h2>' + e(row['name']) + '</h2><p>Owner: ' + e(reg['users'].get(row['user'], {}).get('name', 'Unknown')) + '</p><p>Administrative state: <strong>'+('Enabled' if enabled else 'Disabled, expired or revoked')+'</strong> · Observed connection: see timestamped connection checks.</p><p>' + protocols(row) + '</p>'
    options = ''.join('<option value="' + e(k) + '"' + (' selected' if k == row['user'] else '') + '>' + e(v['name']) + '</option>' for k, v in reg['users'].items())
    effective = row.get('lan_policy', 'inherit')
    if effective == 'inherit':
        effective = reg['users'][row['user']].get('lan_policy', 'block')
    if row.get('disabled') or reg['users'][row['user']].get('revoked') or reg['users'][row['user']].get('disabled'):
        effective='block'
    body += '<p data-policy-kind="device" data-policy-id="' + e(device) + '">Effective LAN access: ' + e(effective) + ' · Device setting: ' + e(row.get('lan_policy', 'inherit')) + ' · Desired: ' + e(row.get('desired_lan_policy', row.get('lan_policy', 'inherit'))) + ' · ' + e(row.get('policy_status', 'applied')) + '</p>'
    policy_options = ''.join('<option value="' + k + '"' + (' selected' if row.get('lan_policy', 'inherit') == k else '') + '>' + v + '</option>' for k, v in [('inherit', 'Inherit user'), ('block', 'Block LAN'), ('allow', 'Allow LAN')])
    body += '<section><h3>Device settings</h3>' + action('rename', '<label>Name <input name="name" value="' + e(row['name']) + '" required maxlength="80"></label>', 'Save device name', {'kind': 'device', 'id': device}) + action('assign', '<label>Owner <select name="user">' + options + '</select></label>', 'Move device') + action('policy', '<label>LAN access <select name="policy">' + policy_options + '</select></label>', 'Save access policy', {'kind': 'device', 'id': device}) + '</section>'
    if any(v.get('status') in ('export-pending', 'pending-recovery') for v in row['protocols'].values()):
        body += '<p class="notice">Existing credentials await recovery. Open Recovery and revoke below, then choose Check / recover incomplete operation before preparing profiles.</p>'
    active = [k for k, v in row['protocols'].items() if v.get('status') == 'active']
    missing = [p for p in ('wireguard', 'ikev2', 'l2tp') if p not in row['protocols'] or row['protocols'][p].get('status') == 'revoked']
    if missing:
        boxes = ''.join('<label><input type="checkbox" name="protocols" value="' + k + '">' + e(k.upper()) + '</label>' for k in missing)
        body += '<section><h3>Add protocols</h3>' + action('protocols-add', boxes + '<p>L2TP only: leave blank for random credentials.</p><label>VPN username <input name="username" maxlength="64"></label><label>VPN login password <input type="password" name="l2tp_password" minlength="12" maxlength="128" autocomplete="new-password"></label>', 'Configure selected protocols') + '</section>'
    if active:
        boxes = ''.join('<label><input type="checkbox" name="protocols" value="' + k + '" checked>' + e(k.upper()) + '</label>' for k in active)
        platform = '<label>Device type <select name="platform"><option value="apple">Apple</option><option value="android">Android</option><option value="windows">Windows</option><option value="other">All formats</option></select></label>'
        body += '<section><h3>Prepare profiles</h3><p>Choose active protocols. Apple delivery sends the mobileconfig directly to Safari. ZIP archives remain optional.</p>' + action('prepare-export', boxes + platform + password_controls('keep') + '<label><input type="checkbox" name="on_demand" value="yes" checked>Apple on demand</label>', 'Prepare selected profiles') + '</section>'
    body += '<section><h3>Download to this browser</h3><p>Private profiles download directly through this administrator session.</p>'
    ike = row['protocols'].get('ikev2', {})
    if ike.get('status') == 'active':
        for name in (ike.get('export') or {}).get('files', []):
            body += action('admin-download', label='Download ' + name.rsplit('.', 1)[-1], fields={'kind': 'ikev2', 'filename': name}, target='/manage/file')
    for protocol in ('wireguard', 'l2tp'):
        if protocol in active:
            body += action('admin-download', label='Download ' + protocol.upper() + ' profile', fields={'kind': protocol}, target='/manage/file')
    ready = device in data.get('deliveries', [])
    if ready:
        body += action('admin-download', label='Download encrypted ZIP', fields={'kind': 'delivery'}, target='/manage/file')
    if active:
        archive_boxes = ''.join('<label><input type="checkbox" name="protocols" value="' + value + '" checked>' + e(value.upper()) + '</label>' for value in active)
        body += '<details><summary>Optional ZIP archive</summary>' + action('bundle', archive_boxes + '<label>Archive password (blank: random) <input name="archive_password" type="password" minlength="12" maxlength="128" autocomplete="new-password"></label>', 'Create optional ZIP archive') + '</details>'
    body += '</section>'
    body += '<section><h3>Deliver to user</h3>'
    native_ready = ike.get('status') == 'active' and bool((ike.get('export') or {}).get('files'))
    if ready or native_ready or any(p in active for p in ('wireguard','l2tp')):
        body += '<p>Publish a single-use link with your chosen expiry on port 9000. Apple profiles are delivered directly as mobileconfig: open the link in Safari, allow the profile download, then install it in Settings. Share the import password separately.</p>' + action('delivery-link', lifetime_controls(), label='Publish profiles / create delivery link') + action('email-draft', lifetime_controls(), label='Download email as HTML', fields={'kind': 'email'}, target='/manage/file')
        if ready:
            body += action('delivery-link', lifetime_controls(), label='Create optional ZIP link', fields={'archive': 'yes'}) + action('delivery-password', '<input name="confirm" placeholder="Type REVEAL" required>', 'Reveal optional ZIP password')
    else:
        body += '<p>Prepare the selected profiles above to enable delivery links and HTML email drafts.</p>'
    if (ike.get('export') or {}).get('files') and ike.get('status') == 'active':
        body += action('reveal', '<input name="confirm" placeholder="Type REVEAL" required>', 'Reveal IKEv2 import password', {'protocol': 'ikev2'})
    body += '</section>'
    body += '<details><summary>Recovery and revoke</summary>' + action('repair', label='Check / recover incomplete operation')
    for protocol, protocol_record in row['protocols'].items():
        if protocol_record.get('status') == 'revoked':
            continue
        body += action('revoke', '<input name="confirm" placeholder="Type REVOKE" required>', 'Revoke ' + protocol.upper(), {'protocol': protocol})
        body += action('replace', '<input name="confirm" placeholder="Type REVOKE" required>', 'Revoke and replace ' + protocol.upper(), {'protocol': protocol})
    if 'l2tp' in active:
        body += action('rotate-l2tp', '<input type="password" name="password" placeholder="New password or leave blank">', 'Rotate L2TP password')
    body += '</details><details class="danger"><summary>Delete client profiles</summary><p>Revokes credentials, disconnects matched sessions, deletes generated files and invalidates links. Remove the installed profile on the client manually.</p>'
    for name in ['all'] + list(row['protocols']):
        body += action('delete-profile', '<label>Type DELETE <input name="confirm" required></label>', 'Revoke and delete ' + ('entire device' if name == 'all' else name.upper()), {'protocol': name})
    body += '</details><section><h3>Device tasks</h3>' + job_list(data.get('jobs', []), reg, csrf, device) + '</section>'
    return body


def focused_device(data, device, tab):
    from html.parser import HTMLParser
    source = device_content(data,device,tab)
    if not visible_device(data['registry']['devices'].get(device,{})):
        return source
    # Separate top-level panels from our own generated forms; never parse or
    # execute imported HTML. Nested ZIP/recovery details stay with their panel.
    class Panels(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=False)
            self.level=0;self.start=0;self.spans=[]
            self.offsets=[0]
            for match in re.finditer('\n',source):self.offsets.append(match.end())
        def position(self):
            line,column=self.getpos();return self.offsets[line-1]+column
        def handle_starttag(self,tag,attrs):
            if tag in ('section','details'):
                if not self.level:self.start=self.position()
                self.level+=1
        def handle_endtag(self,tag):
            if tag in ('section','details'):
                self.level-=1
                if not self.level:self.spans.append((self.start,self.position()+len(tag)+3))
    parser=Panels();parser.feed(source)
    if not parser.spans:
        return source
    body=source[:parser.spans[0][0]]
    if any(value.get('status') in ('export-pending','pending-recovery') for value in data['registry']['devices'].get(device,{}).get('protocols',{}).values()):
        body+='<p class="notice">A credential operation needs recovery. Open <a href="'+e(link('device',device=device,tab='settings'))+'">Settings → Recovery</a> before preparing profiles.</p>'
    for start,end in parser.spans:
        panel=source[start:end]
        title=re.search(r'<(?:h[23]|summary)>([^<]+)',panel)
        title=title[1] if title else ''
        if title=='Device settings':
            forms=re.findall(r'<form\b.*?</form>',panel,re.S)
            selected=[part for part in forms if ('name="action" value="policy"' in part)==(tab=='access')]
            if tab in ('settings','access'):
                body+='<section><h3>'+('Network access' if tab=='access' else 'Device settings')+'</h3>'+''.join(selected)+'</section>'
                if tab=='settings':body+=owner_search('device',device,data.get('pagination',{}).get('owner_query',''))
        elif (tab=='activity' and title=='Device tasks') or (tab=='settings' and title in ('Recovery and revoke','Delete client profiles')) or (tab=='profiles' and title not in ('Device settings','Device tasks','Recovery and revoke','Delete client profiles')):
            body+=panel
    if tab=='profiles':
        body+=diagnostic_panel(data,device)
        body+='<section><h3>Recent profile tasks</h3>'+job_list(data.get('jobs',[])[:5],data['registry'],data['csrf'],device)+'</section>'
    return body


def attachment(backend, store, state, form_data):
    ident = form_data.get('device', '')
    _, device = backend.device(ident)
    kind = form_data.get('kind')
    slug = re.sub(r'[^A-Za-z0-9_-]+', '-', device['name']).strip('-')[:40] or 'device'
    if kind in ('delivery', 'email'):
        if kind == 'delivery':
            path, generation = delivery_choice(backend, ident, archive=True)
        if kind == 'email':
            if not (backend.base / 'web-enabled').exists():
                raise ValueError('Enable the delivery service before creating an email draft.')
            from vpn_web import delivery_lifetime
            lifetime = delivery_lifetime(form_data)
            import vpn_portal
            token, manifest = vpn_portal.publish(backend, store, ident, lifetime)
            url = 'http://' + state['public'] + ':9000/?' + urlencode({'token': token})
            expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=lifetime)
            apple = any(item['filename'].endswith('.mobileconfig') for item in manifest['files'])
            guidance = ('Open this link in Safari on your iPhone or iPad. Tap Allow when asked to download the configuration profile, then open Settings → Profile Downloaded (or General → VPN &amp; Device Management) to review and install it. Enter the certificate import password provided separately.' if apple else 'Download and import the profile using the matching VPN application. If you requested a ZIP archive, extract it first. Your administrator will send the required passwords separately.')
            content = '<!doctype html><html><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Your VPN profiles</title></head><body><h1>Your VPN profiles</h1><p>Hello,</p><p>Your profiles for <strong>' + e(device['name']) + '</strong> are ready.</p><p><a href="' + e(url) + '">' + ('Install your Apple profile (open in Safari)' if apple else 'Download your VPN profile') + '</a></p><p>This link permits one download and expires at ' + e(expires.strftime('%Y-%m-%d %H:%M UTC')) + '.</p><p>' + guidance + '</p><p>If the link has expired, ask your administrator for a new link.</p></body></html>'
            payload = content.encode()
            filename = slug + '-vpn-email.html'
            mime = 'text/html; charset=utf-8'
        else:
            payload, filename, mime = path.read_bytes(), slug + '-profiles.zip', 'application/zip'
    elif kind == 'ikev2':
        path = backend.exported_file(ident, form_data.get('filename', ''))
        payload, filename, mime = path.read_bytes(), slug + path.suffix, profile_mime(path.name)
    elif kind in ('wireguard', 'l2tp'):
        record = device['protocols'].get(kind, {})
        if record.get('status') != 'active':
            raise ValueError('An active ' + kind + ' profile is required.')
        native = record['backend']
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', native):
            raise ValueError('Invalid native profile identifier.')
        suffix = '.conf' if kind == 'wireguard' else '.txt'
        path = backend.base / 'clients' / kind / (native + suffix)
        if path.is_symlink() or not path.is_file():
            raise ValueError('Private profile is missing or unsafe.')
        payload, filename, mime = path.read_bytes(), slug + suffix, 'application/octet-stream'
    else:
        raise ValueError('Unknown export type.')
    if len(payload) > 5 * 1024**2 + 65536:
        raise ValueError('Export exceeds the browser download size limit.')
    return {'filename': filename, 'mime': mime, 'data': base64.b64encode(payload).decode()}



def password_controls(default='random'):
    options = [('keep', 'Keep existing password'), ('random', 'Unique random password per device'), ('custom', 'Custom password (shared for batch)')]
    return '<label>IKEv2 import password <select name="password_mode">' + ''.join('<option value="' + key + '"' + (' selected' if key == default else '') + '>' + title + '</option>' for key, title in options) + '</select></label><label>Custom import password <input type="password" name="password" minlength="12" maxlength="128" autocomplete="new-password"></label>'


def batch_options(default):
    return '<p><label><input type="checkbox" name="protocols" value="ikev2" checked>IKEv2</label><label><input type="checkbox" name="protocols" value="wireguard">WireGuard</label><label><input type="checkbox" name="protocols" value="l2tp">L2TP</label></p><label>Platform <select name="platform"><option value="apple">Apple</option><option value="android">Android</option><option value="windows">Windows</option><option value="other">All formats</option></select></label><label><input type="checkbox" name="on_demand" value="yes" checked>Apple on demand</label>' + password_controls(default)


def batch_creation(registry, csrf):
    owners = ''.join('<option value="' + e(k) + '">' + e(v['name']) + '</option>' for k, v in registry['users'].items())
    fields = '<label>Create <select name="ownership"><option value="existing">Devices for an existing user</option><option value="new">New users, one device each</option></select></label><label>Existing owner <select name="user">' + owners + '</select></label><label>Count <input type="number" name="count" value="1" min="1" max="50" required></label><p><label><input type="checkbox" name="random_users" value="yes" checked>Random user names</label><label>User prefix <input name="user_prefix" value="User" maxlength="65"></label><label><input type="checkbox" name="random_devices" value="yes" checked>Random device names</label><label>Device prefix <input name="device_prefix" value="Device" maxlength="65"></label></p>' + '<p><label>L2TP username mode <select name="random_l2tp"><option value="yes">Random</option><option value="no">Numbered prefix</option></select></label><label>L2TP username prefix <input name="l2tp_prefix" value="vpn" maxlength="55"></label><label>Shared L2TP login password (blank: unique random) <input name="l2tp_password" type="password" minlength="12" maxlength="128" autocomplete="new-password"></label></p>' + batch_options('random')
    return '<section><h2>Create devices in batches</h2><p>Up to 50 devices, processed one at a time. Uncheck random names to use numbered prefixes. Credentials are generated securely; review before creation.</p>' + form('batch-preview', csrf, {'batch_kind': 'create', 'return_view': 'batches'}, fields, 'Preview creation') + '</section>'


def batch_exports(devices, csrf):
    choices = ''.join('<label><input type="checkbox" name="devices" value="' + e(ident) + '">' + e(row['name']) + '</label>' for ident, row in devices)
    return '<section><h2>Export selected devices</h2><p>Select up to 50 devices from this page. Every device must have the selected protocols active.</p>' + form('batch-preview', csrf, {'batch_kind': 'export', 'return_view': 'batches'}, choices + batch_options('keep'), 'Preview exports') + '</section>'


def batch_results(batches, csrf):
    body = '<section><h2>Batches</h2><p>Progress refreshes every 15 seconds while this page is visible. Open each device for browser downloads, delivery links, HTML email drafts, and private credential reveal.</p>'
    for batch in batches:
        ident = batch['id']
        body += '<article data-batch="' + e(batch['id']) + '"><h3>' + e(batch['kind'].capitalize()) + ' · ' + e(batch['status']) + '</h3><p>' + e(', '.join(batch['protocols'])) + ' · ' + e(batch['platform']) + ' · Import password: ' + e(batch['password_mode']) + '</p>'
        if batch['status'] == 'failed':
            body += form('batch-retry', csrf, {'batch': ident, 'return_view': 'batches'}, label='Retry failed items')
        if batch['status'] == 'preview' and not batch.get('cancel'):
            body += form('batch-confirm', csrf, {'batch': ident, 'return_view': 'batches'}, label='Confirm this batch')
        if batch['status'] not in ('complete', 'cancelled') and not batch.get('cancel'):
            body += form('batch-cancel', csrf, {'batch': ident, 'return_view': 'batches'}, label='Cancel remaining work')
        body += '<div class="table-wrap"><table><tr><th>User</th><th>Device</th><th>Status / result</th></tr>'
        for item in batch['items']:
            name = '<a href="' + e(link('device', device=item['device'])) + '">' + e(item['name']) + '</a>' if item['status'] != 'waiting' else e(item['name'])
            body += '<tr><td>' + e(item['user_name']) + '</td><td>' + name + '</td><td>' + '<span data-batch-item="' + e(ident + '-' + item['device']) + '">' + e(item['status']) + '</span>' + ('<br>VPN login: ' + e(item['l2tp_username']) if item.get('l2tp_username') else '') + '<br>' + e(item.get('message', '')) + '</td></tr>'
        body += '</table></div></article>'
    return body + '</section>'



def portal_markup(result=None, token='', certificates=()):
    title = 'Your profiles are ready' if result else 'Your connection starts here'
    intro = 'Select the profile format for your device. Your token permits one download.' if result else 'Enter the token provided by your administrator. Private files are shown only after authorization.'
    body = '<div class="portal"><p class="eyebrow">VPN · SECURE DELIVERY</p><h2>' + title + '</h2><p class="muted">' + intro + '</p>'
    if result is None:
        body += '<section><h3>Access your profiles</h3><form method="post" action="/access"><label class="block">Download token<input name="token" required minlength="64" maxlength="64" autocomplete="off" spellcheck="false" placeholder="Paste your download token"></label><button>View available files</button></form></section>'
    else:
        files = result.get('files', [{'filename': result['filename'], 'size': result.get('size', 0)}])
        expiry = datetime.datetime.fromtimestamp(result['expires'], datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        body += '<section><h3>' + e(result.get('device_name', 'Your VPN profile')) + '</h3><p class="notice">Choose carefully: this token permits <strong>one download total</strong>. Viewing this list does not consume it.</p><p class="muted">Expires ' + e(expiry) + '</p><form method="post" action="/download"><input type="hidden" name="token" value="' + e(token) + '"><input type="hidden" name="confirm" value="' + e(result['confirm']) + '">'
        for index, item in enumerate(files):
            name = item['filename']
            label = 'Apple profile · open in Safari' if name.endswith('.mobileconfig') else 'WireGuard configuration' if name.endswith('.conf') else 'Android profile' if name.endswith('.sswan') else 'Certificate bundle' if name.endswith('.p12') else 'Connection instructions' if name.endswith('.txt') else 'Encrypted archive'
            body += '<label class="file-choice"><input type="radio" name="filename" value="' + e(name) + '"' + (' checked' if not index else '') + '><span><strong>' + e(label) + '</strong><small>' + e(name) + ' · ' + str(max(1, (item.get('size', 0)+1023)//1024)) + ' KiB</small></span></label>'
        body += '<button>Download selected file</button></form><p class="muted">For Apple, open in Safari, allow the download, then install from Settings. Your administrator supplies the import password separately. Interrupted downloads require a new token.</p></section>'
    if certificates:
        body += '<section><h3>Public certificates</h3><p class="muted">These certificates are public. Client credentials are never listed here without a token.</p><div class="certificate-links">' + ''.join('<a href="/cert/' + e(name) + '">' + e(name) + '</a>' for name in certificates) + '</div></section>'
    return body + '<footer>Need another file or a new token? Contact your VPN administrator.</footer></div>'


def restore_form_values(document, values):
    """Restore only non-secret controls of the submitted form after validation."""
    from html.parser import HTMLParser
    action = values.get('action','')
    class Controls(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=False)
            self.parts=[];self.select=''
        def handle_starttag(self, tag, attrs):
            data=dict(attrs)
            name=data.get('name','')
            if tag=='select':self.select=name
            if tag=='input' and name in values and data.get('type','text') not in ('hidden','password','file','submit') and name!='confirm':
                if data.get('type') in ('checkbox','radio'):
                    data.pop('checked',None)
                    if data.get('value','on') in values[name].split(','):data['checked']=None
                else:
                    data['value']=''.join(c for c in values[name][:512] if ord(c)>=32)
            elif tag=='option' and self.select in values:
                data.pop('selected',None)
                if data.get('value')==values[self.select]:data['selected']=None
            self.parts.append('<'+tag+''.join(' '+key+('="'+e(value)+'"' if value is not None else '') for key,value in data.items())+'>')
        def handle_endtag(self,tag):
            if tag=='select':self.select=''
            self.parts.append('</'+tag+'>')
        def handle_data(self,text):self.parts.append(text)
        def handle_entityref(self,name):self.parts.append('&'+name+';')
        def handle_charref(self,name):self.parts.append('&#'+name+';')
    def replace(match):
        source=match[0]
        if 'name="action" value="'+e(action)+'"' not in source:return source
        for key in ('id','device','kind'):
            if values.get(key) and 'name="'+key+'" value="'+e(values[key])+'"' not in source:return source
        parser=Controls();parser.feed(source)
        return ''.join(parser.parts)
    return re.sub(r'<form\b.*?</form>',replace,document.decode(),flags=re.S).encode()

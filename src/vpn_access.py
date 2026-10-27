"""Administration reach and explicitly trusted reverse proxy configuration."""
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit


def configure(manager, form):
    state=manager.load()
    delivery=form.get('vpd_origin',state.get('vpd_origin','')).rstrip('/')
    if delivery:
        uri=urlsplit(delivery)
        if uri.scheme!='https' or not uri.hostname or uri.username or uri.password or uri.path or uri.query or uri.fragment or uri.port not in (None,443):
            raise ValueError('Use an HTTPS profile-delivery origin on port 443, or leave it blank.')
        if not re.fullmatch(r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}',uri.hostname):raise ValueError('Invalid delivery hostname.')
    mode=form.get('mode','lan')
    if mode not in ('lan','vpn','https'): raise ValueError('Choose LAN, approved VPN devices, or HTTPS.')
    devices=[v for v in form.get('devices',','.join(state.get('admin_devices',[]))).split(',') if v]
    if len(devices)>50 or any(not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',v) for v in devices): raise ValueError('Invalid administrator device IDs.')
    public=mode=='https'; origin=form.get('origin','').rstrip('/') if public else ''
    proxy=form.get('proxy','127.0.0.1')
    if public:
        uri=urlsplit(origin)
        if uri.scheme!='https' or not uri.hostname or uri.username or uri.password or uri.path or uri.query or uri.fragment or uri.port not in (None,443):
            raise ValueError('Use an HTTPS origin on port 443, such as https://vpn.example.com.')
        if not re.fullmatch(r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}',uri.hostname): raise ValueError('Invalid HTTPS hostname.')
        ipaddress.IPv4Address(proxy)
        if form.get('managed')=='yes':
            cert=Path(form.get('cert','')); key=Path(form.get('key',''))
            if not cert.is_absolute() or not key.is_absolute() or not cert.is_file() or not key.is_file(): raise ValueError('Provide existing absolute TLS certificate and key paths.')
            if not re.fullmatch(r'/[A-Za-z0-9_./-]+',str(cert)) or not re.fullmatch(r'/[A-Za-z0-9_./-]+',str(key)): raise ValueError('Invalid certificate paths.')
            if key.stat().st_uid!=0 or key.stat().st_mode&0o077: raise ValueError('TLS private key must be root-owned and mode 0600 or stricter.')
            manager.command(['apt-get','-y','-o','DPkg::Lock::Timeout=120','install','nginx'],timeout=600)
            text=f'''server {{
  listen 443 ssl;
  server_name {uri.hostname};
  ssl_certificate {cert};
  ssl_certificate_key {key};
  ssl_protocols TLSv1.2 TLSv1.3;
  access_log off;
  client_max_body_size 64k;
  location / {{
    proxy_pass http://{state['lan']}:9001;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $remote_addr;
  }}
}}
'''
            manager.command(['openssl','x509','-in',str(cert),'-noout','-checkhost',uri.hostname])
            manager.command(['openssl','x509','-in',str(cert),'-noout','-checkend','0'])
            path=manager.ETC/'nginx/conf.d/vpn-admin.conf'
            previous=path.read_bytes() if path.exists() else None
            try:
                manager.atomic(path,text,0o644)
                manager.command(['nginx','-t'])
                manager.command(['systemctl','enable','--now','nginx'])
                manager.command(['systemctl','reload','nginx'])
            except Exception:
                if previous is None:path.unlink(missing_ok=True)
                else:manager.atomic(path,previous,0o644)
                manager.command(['systemctl','reload','nginx'],check=False)
                raise
            proxy=state['lan']
        elif form.get('tls_verified')!='yes':
            raise ValueError('Confirm that the existing HTTPS reverse proxy is configured before enabling public administration.')
    state.update(vpd_origin=delivery,admin_mode=mode,admin_devices=devices,admin_origin=origin,trusted_proxy=proxy if public else '')
    manager.save(state)
    return state


def context(state, request):
    peer=ipaddress.ip_address(request.get('peer',''))
    host=request.get('host','').lower()
    origin=request.get('origin')
    expected='http://'+host
    proxy=state.get('trusted_proxy')
    if state.get('admin_mode')=='https' and proxy and str(peer)==proxy and host==urlsplit(state.get('admin_origin','')).netloc:
        if request.get('forwarded_proto')!='https': raise ValueError('HTTPS proxy attribution missing.')
        # XFF is deliberately unused for admission or rate-limit identity.
        expected=state['admin_origin']
        accepted=True
    else:
        local=peer in ipaddress.ip_network(state['lan_net']) and host==state['lan']+':9001'
        loopback=str(peer) in ('127.0.0.1',state['lan']) and host in ('127.0.0.1:9001','localhost:9001')
        accepted=local or loopback or request.get('_verified_vpn_device',False)
    if not accepted: raise ValueError('Administration is unavailable from this network or hostname.')
    if origin and origin!=expected: raise ValueError('Cross-origin management request denied.')
    return expected

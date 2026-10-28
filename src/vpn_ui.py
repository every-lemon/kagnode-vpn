"""Arrow-key terminal UI with a plain-text fallback; standard library only."""
import contextlib
import curses
import getpass
import json
import os
import pwd
import sys
import time


class Cancel(Exception):
    pass


def enabled():
    return os.environ.get('VPN_STACK_PLAIN') != '1' and sys.stdin.isatty() and os.environ.get('TERM', 'dumb') != 'dumb'


@contextlib.contextmanager
def terminal_output():
    # Shell command substitutions capture the result, never the curses screen.
    sys.stdout.flush()
    saved = os.dup(1)
    try:
        with open('/dev/tty', 'w') as terminal:
            os.dup2(terminal.fileno(), 1)
            yield
    finally:
        sys.stdout.flush()
        os.dup2(saved, 1)
        os.close(saved)


def draw(screen, row, text, attr=0):
    height, width = screen.getmaxyx()
    if 0 <= row < height and width > 1:
        try:
            screen.addnstr(row, 1, str(text).replace('\n', ' '), width - 2, attr)
        except curses.error:
            pass


def menu_key(key, selected, count, page=8):
    if key in (curses.KEY_UP, 'k'):
        return max(0, selected - 1)
    if key in (curses.KEY_DOWN, 'j', '\t'):
        return min(count - 1, selected + 1)
    if key in (curses.KEY_HOME, 'g'):
        return 0
    if key in (curses.KEY_END, 'G'):
        return count - 1
    if key == curses.KEY_PPAGE:
        return max(0, selected - page)
    if key == curses.KEY_NPAGE:
        return min(count - 1, selected + page)
    return selected


def choose(title, options, default=0):
    if not options:
        raise Cancel()
    if not enabled():
        print('\n' + title, file=sys.stderr)
        for i, (key, text) in enumerate(options):
            print(f'  {i+1}. {text}', file=sys.stderr)
        while True:
            print(f'Select [{default+1}], q to cancel: ', end='', file=sys.stderr, flush=True)
            value = sys.stdin.readline()
            if not value or value.strip().lower() in ('q', 'esc'):
                raise Cancel()
            try:
                index = int(value.strip() or str(default + 1)) - 1
                if 0 <= index < len(options):
                    return options[index][0]
            except ValueError:
                continue
    def render(screen):
        screen.keypad(True)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        selected, query, searching = min(default, len(options)-1), '', False
        while True:
            items = [(i, item) for i, item in enumerate(options) if query.casefold() in item[1].casefold()]
            selected = min(selected, max(0, len(items)-1))
            screen.erase()
            height, _ = screen.getmaxyx()
            draw(screen, 0, title, curses.A_BOLD)
            draw(screen, 1, '↑ ↓ Enter · / search · Esc back · Tab · Home/End · PgUp/PgDn')
            draw(screen, 2, 'Filter: ' + query)
            visible = max(1, height - 5)
            start = max(0, selected - visible + 1)
            for row, (_, item) in enumerate(items[start:start+visible], 3):
                index = start + row - 3
                draw(screen, row, ('> ' if index == selected else '  ') + item[1], curses.A_REVERSE if index == selected else 0)
            draw(screen, height-1, '? help · q back')
            screen.refresh()
            key = screen.get_wch()
            if searching:
                if key in ('\n', '\r', curses.KEY_ENTER):
                    searching = False
                elif key == '\x1b':
                    query, searching = '', False
                elif key in (curses.KEY_BACKSPACE, '\x7f', '\b'):
                    query = query[:-1]
                elif isinstance(key, str) and key.isprintable():
                    query += key
                selected = 0
                continue
            if key in ('\x1b', 'q'):
                raise Cancel()
            if key in ('\n', '\r', ' ', curses.KEY_ENTER) and items:
                return items[selected][1][0]
            if key == '/':
                searching = True
                selected = 0
            elif key == '?':
                screen.erase()
                for row, text in enumerate(('Menu help', 'Up/Down or j/k: move; Enter or Space: choose.', 'Tab / Shift+Tab: next / previous.', 'Home/End and Page Up/Down: jump.', '/: type a search, Enter: finish, Esc: clear.', 'Esc or q: return. Password fields are hidden.', 'Resize your terminal at any time.', 'Press any key to return.')):
                    draw(screen, row, text)
                screen.refresh()
                screen.get_wch()
            elif key == curses.KEY_BTAB:
                selected = max(0, selected - 1)
            elif key != curses.KEY_RESIZE:
                selected = menu_key(key, selected, len(items), visible)
    try:
        with terminal_output():
            return curses.wrapper(render)
    except curses.error:
        os.environ['VPN_STACK_PLAIN'] = '1'
        return choose(title, options, default)


def multi_select(title, options):
    selected = set()
    index = 0
    while True:
        choices = [(key, ('[x] ' if key in selected else '[ ] ') + text) for key, text in options]
        key = choose(title + ' · toggle with Space/Enter, then choose Done', choices + [('__done__', 'Done')], default=index)
        index = next(i for i, option in enumerate(choices + [('__done__', 'Done')]) if option[0] == key)
        if key == '__done__':
            if selected:
                return sorted(selected)
            show('Select protocols', 'Select at least one protocol.')
        elif key in selected:
            selected.remove(key)
        else:
            selected.add(key)


def ask(title, default='', secret=False, validate=None):
    if not enabled():
        while True:
            if secret:
                value = getpass.getpass(title + ': ')
            else:
                print(title + (f' [{default}]' if default else '') + ': ', end='', file=sys.stderr, flush=True)
                value = sys.stdin.readline()
                if not value:
                    raise Cancel()
                value = value.rstrip('\r\n')
            value = value or default
            try:
                if validate: validate(value)
                return value
            except ValueError as exc:
                print(str(exc),file=sys.stderr)
    def render(screen):
        screen.keypad(True)
        value = str(default)
        error = ''
        try:
            curses.curs_set(1)
        except curses.error:
            pass
        while True:
            screen.erase()
            draw(screen, 0, title, curses.A_BOLD)
            draw(screen, 2, '*' * len(value) if secret else value)
            draw(screen, 4, 'Enter/Tab accept · Esc cancel · Backspace delete · Ctrl-U clear')
            draw(screen, 6, error)
            screen.refresh()
            key = screen.get_wch()
            if key in ('\x1b',):
                raise Cancel()
            if key in ('\n', '\r', '\t', curses.KEY_ENTER):
                try:
                    if validate: validate(value)
                    return value
                except ValueError as exc:
                    error=str(exc)
                    continue
            if key in (curses.KEY_BACKSPACE, '\x7f', '\b'):
                value = value[:-1]
            elif key == '\x15':
                value = ''
            elif isinstance(key, str) and key.isprintable() and len(value) < 256:
                value += key
    with terminal_output():
        return curses.wrapper(render)


def show(title, message):
    lines = str(message).splitlines() or ['']
    if not enabled():
        print(title + '\n' + '\n'.join(lines), file=sys.stderr)
        ask('Press Enter to return')
        return
    def render(screen):
        offset = 0
        screen.keypad(True)
        while True:
            screen.erase()
            height, _ = screen.getmaxyx()
            draw(screen, 0, title, curses.A_BOLD)
            for row, line in enumerate(lines[offset:offset+max(1, height-3)], 1):
                draw(screen, row, line)
            draw(screen, height-1, '↑ ↓ scroll · Enter/Esc back')
            screen.refresh()
            key = screen.get_wch()
            if key in ('\n', '\r', '\x1b', 'q', curses.KEY_ENTER):
                return
            offset = menu_key(key, offset, max(1, len(lines)), max(1, height-3))
    with terminal_output():
        curses.wrapper(render)


def confirm(message):
    try:
        return choose(message, [('no', 'Cancel'), ('yes', 'Confirm')]) == 'yes'
    except Cancel:
        return False


def password(title):
    mode = choose(title, [('random', 'Generate a strong random password'), ('custom', 'Enter a custom password (hidden)'), ('keep', 'Keep existing password / default')])
    if mode == 'keep':
        return None
    if mode == 'random':
        import secrets
        return secrets.token_urlsafe(24)
    value = ask(title, secret=True)
    if value != ask('Repeat password', secret=True):
        raise ValueError('Passwords do not match.')
    return value


def select_device(backend):
    reg = backend.load()
    options = [(ident, reg['users'][item['user']]['name'] + ' / ' + item['name']) for ident, item in reg['devices'].items()]
    return choose('Select device', options)


def live(manager):
    if not enabled():
        manager.status(live=True)
        return
    def render(screen):
        screen.keypad(True)
        screen.timeout(2000)
        previous, last = {}, time.monotonic()
        while True:
            screen.erase()
            draw(screen, 0, 'Live traffic · server RX / TX · q/Esc back · r refresh', curses.A_BOLD)
            snapshot = manager.snapshot()
            now = time.monotonic()
            row = 2
            for name, (rx, tx, detail) in snapshot.items():
                old = previous.get(name, (rx, tx))
                text = (f'{name}: {manager.size(rx)} / {manager.size(tx)}; '
                        f'{manager.size(manager.rate(old[0], rx, now-last))}/s / {manager.size(manager.rate(old[1], tx, now-last))}/s')
                draw(screen, row, text)
                draw(screen, row+1, detail)
                row += 2
            draw(screen, row+1, 'Counters reset with sessions/rekeys; PPP and IPsec totals overlap.')
            screen.refresh()
            previous, last = snapshot, now
            try:
                key = screen.get_wch()
            except curses.error:
                continue
            if key in ('q', '\x1b', '\n'):
                return
    with terminal_output():
        curses.wrapper(render)


def management_password(manager, backend):
    import vpn_web
    with terminal_output():
        password = getpass.getpass('New management password (12–256 characters): ')
        confirmation = getpass.getpass('Confirm management password: ')
    if password != confirmation:
        raise ValueError('Passwords did not match.')
    with manager.lock():
        vpn_web.Store(backend.repo.path).set_password(password)
    show('Management password saved', 'Existing browser sessions were invalidated. The current window deadline is unchanged.')


def hardening_menu(manager):
    import vpn_harden
    appliance = vpn_harden.Hardening(manager)
    action = choose('Appliance hardening', [('status', 'Cleanup status and RAM snapshots'), ('queue', 'Run final package cleanup / purge SSH'), ('back', 'Back')])
    if action == 'queue':
        appliance.queue()
    if action != 'back':
        show('Hardening / package cleanup', json.dumps(appliance.status(), indent=2))


def watchdog_menu(manager):
    import vpn_watchdog
    monitor = vpn_watchdog.Watchdog(manager)
    action = choose('Watchdog and recovery', [('status', 'Health, settings and recovery history'),
        ('check', 'Run read-only health checks'), ('pause', 'Pause automatic recovery'),
        ('resume', 'Resume automatic recovery'), ('reboot-on', 'Allow limited automatic reboots'),
        ('reboot-off', 'Disable automatic reboots'), ('logs', 'View latest recovery diagnostics'), ('back', 'Back')])
    if action == 'status':
        show('Watchdog status', vpn_watchdog.status(manager))
    elif action == 'check':
        _, checks = monitor.probes()
        show('Local health checks', json.dumps(checks, indent=2))
    elif action in ('pause', 'resume'):
        monitor.configure('paused', action == 'pause')
        show('Watchdog updated', vpn_watchdog.status(manager))
    elif action in ('reboot-on', 'reboot-off'):
        monitor.configure('auto_reboot', action == 'reboot-on')
        show('Watchdog updated', vpn_watchdog.status(manager))
    elif action == 'logs':
        path = manager.BASE / 'logs/watchdog-failure-latest.txt'
        show('Latest watchdog diagnostics', path.read_text() if path.exists() else 'No recovery diagnostics yet.')


def web_menu(manager, backend):
    import vpn_console
    show('VPN dashboard', 'Management stays online on LAN port 9001. Sign in with your administrator username, password and MFA. Sessions expire after 30 idle minutes or 8 hours. Profile delivery uses port 9000. Public administration requires configured HTTPS.')
    vpn_console.run(manager, 'system')


def device_menu(manager, backend, ident):
    import vpn_web
    while True:
        reg, item = backend.device(ident)
        summary = ', '.join(p + ':' + v['status'] + (' expires ' + v['certificate_expires'] if v.get('certificate_expires') else '') for p, v in item['protocols'].items()) or 'No protocols'
        action = choose(item['name'] + ' · ' + summary, [
            ('add', 'Add one or several VPN protocols'), ('policy', 'LAN access: inherit / allow / block'), ('bundle', 'Create encrypted delivery ZIP'), ('delivery', 'Delivery ZIP link / password'), ('export', 'Export IKEv2 profile for a device type'),
            ('reveal', 'Reveal selected credentials'), ('copy', 'Copy private profile to SSH download folder'),
            ('link', 'Create one-time public IKEv2 download link'), ('wg', 'Show WireGuard QR / private config'),
            ('rotate-pass', 'Change L2TP password'), ('revoke', 'Revoke a protocol'), ('replace', 'Replace credentials / keys'),
            ('rename', 'Rename display label'), ('assign', 'Move device to another user'), ('repair', 'Recover pending operation'), ('back', 'Back')])
        if action == 'back':
            return
        try:
            if action == 'add':
                protocols = multi_select('Protocols', [('ikev2', 'IKEv2'), ('wireguard', 'WireGuard'), ('l2tp', 'L2TP/IPsec')])
                with manager.lock():
                    backend.add_protocols(ident, protocols)
            elif action == 'policy':
                policy = choose('LAN access', [('inherit', 'Inherit user default'), ('block', 'Block LAN; keep DNS/internet'), ('allow', 'Allow LAN')])
                with manager.lock():
                    backend.set_policy('device', ident, policy)
            elif action == 'bundle':
                from vpn_backend import bundle
                protocols = multi_select('Protocols to package', [(p, p) for p, v in item['protocols'].items() if v['status'] == 'active'])
                with manager.lock():
                    bundle(backend, ident, protocols)
                show('Delivery ready', 'Encrypted ZIP created. Use Delivery ZIP link / password to retrieve it. Native configuration bytes are unchanged.')
            elif action == 'delivery':
                controller = vpn_web.Controller(backend)
                mode = choose('Encrypted ZIP', [('link', 'Create one-use download link'), ('password', 'Reveal separate ZIP password')])
                result = controller.action({'action': 'delivery-link' if mode == 'link' else 'delivery-password', 'device': ident, 'confirm': 'REVEAL'})
                show('Private delivery', result.get('url', result['message']))
            elif action == 'export':
                platform = choose('Target device', [('apple', 'Apple Device (iPhone / iPad / macOS)'), ('android', 'Android (strongSwan)'), ('windows', 'Windows'), ('other', 'Other / all formats')])
                on_demand = choose('Apple Connect on demand', [('yes', 'Enabled on Wi-Fi and cellular'), ('no', 'Manual connection')]) == 'yes' if platform in ('apple', 'other') else False
                value = password('Certificate import password')
                with manager.lock():
                    result = backend.export_ike(ident, platform, value, on_demand)
                show('Export validated', result['message'] + '\n' + result['directory'] + '\n' + '\n'.join(result['files']))
            elif action == 'reveal':
                protocol = choose('Credentials', [(p, p) for p in item['protocols']])
                if confirm('Reveal private credentials in this terminal?'):
                    show('Private credential · ' + protocol, backend.reveal(ident, protocol))
            elif action == 'copy':
                protocol = choose('Private export protocol', [(p, p) for p, v in item['protocols'].items() if v['status'] != 'revoked'])
                accounts = [(p.pw_name, p.pw_name) for p in pwd.getpwall() if 1000 <= p.pw_uid < 65534 and p.pw_dir.startswith('/home/')]
                username = choose('SSH download user', accounts)
                with manager.lock():
                    destination = backend.copy_export(ident, username, protocol)
                show('Export copied privately', destination + '\nRetrieve with your normal SFTP/SCP connection. Import password is separate.')
            elif action == 'link':
                export = item['protocols'].get('ikev2', {}).get('export')
                if not export:
                    raise ValueError('Create a validated IKEv2 export first.')
                filename = choose('File for one-time link', [(f, f) for f in export['files']])
                if not (backend.base / 'web-enabled').exists():
                    raise ValueError('Start the web service first from Web access.')
                path = backend.exported_file(ident, filename)
                token = vpn_web.Store(backend.repo.path).issue(ident, filename, export['generation'])
                show('One-time link · 15 minutes', 'http://' + manager.load()['public'] + ':9000/?token=' + token + '\nShare the import password separately. Opening the link does not consume it; Download does.\nForward TCP 9000 to this server.')
            elif action == 'wg':
                name = item['protocols'].get('wireguard', {}).get('backend')
                if not name:
                    raise ValueError('WireGuard is not configured for this device.')
                text = (backend.base / 'clients/wireguard' / (name + '.conf')).read_text()
                if confirm('Display the private WireGuard key/QR?'):
                    mode = choose('Display', [('qr', 'QR code'), ('text', 'Private text')])
                    if mode == 'text':
                        show('Private WireGuard configuration', text)
                    else:
                        result = manager.command(['qrencode', '-t', 'UTF8'], data=text)
                        show('Private WireGuard QR', result.stdout)
            elif action in ('revoke', 'replace'):
                protocol = choose('Select protocol', [(p, p + ' · ' + v['status']) for p, v in item['protocols'].items()])
                if confirm('Invalidate ' + protocol + ' credentials? Replacement requires re-import.'):
                    with manager.lock():
                        result = backend.revoke(ident, protocol) if action == 'revoke' else backend.rotate(ident, protocol)
                        if backend.repo.path.exists():
                            vpn_web.Store(backend.repo.path).invalidate(ident)
                    show('Credentials changed', result or 'Replacement created. Export/import its new profile.')
            elif action == 'rotate-pass':
                value = password('New L2TP password') or manager.random_password()
                with manager.lock():
                    backend.rotate_l2tp(ident, value)
                show('Password changed', 'Reveal the new password explicitly. Old L2TP sessions can remain until disconnected.')
            elif action == 'rename':
                name = ask('Device display name', item['name'])
                with manager.lock():
                    backend.rename('device', ident, name)
            elif action == 'assign':
                user = choose('Assign user', [(key, value['name']) for key, value in reg['users'].items()])
                with manager.lock():
                    backend.assign(ident, user)
            elif action == 'repair':
                with manager.lock():
                    backend.repair(ident)
                show('Recovery', 'Pending operation reconciled.')
        except Cancel:
            continue
        except Exception as exc:
            show('Operation failed · inspect device recovery', str(exc))


def profiles(manager):
    import vpn_clients
    backend = vpn_clients.Backend(manager)
    with manager.lock():
        backend.migrate()
    while True:
        try:
            choice = choose('VPN · users and devices', [('users', 'Users and their devices'),
                ('new-user', 'Add user'), ('new-device', 'Add device'), ('devices', 'Search all devices'),
                ('discover', 'Recover unassigned IKEv2 certificates'), ('web', 'Web management / public links'),
                ('hardening', 'Appliance hardening / cleanup status'), ('watchdog', 'Watchdog and automatic recovery'), ('live', 'Live traffic and service status'), ('ports', 'Router and DNS instructions'), ('back', 'Back')])
            registry = backend.load()
            if choice == 'back':
                return
            if choice == 'new-user':
                name = ask('User display name')
                with manager.lock():
                    backend.user_add(name)
            elif choice == 'new-device':
                user = choose('Owner', [(key, value['name']) for key, value in registry['users'].items()])
                name = ask('Device display name')
                with manager.lock():
                    ident = backend.device_add(user, name)
                device_menu(manager, backend, ident)
            elif choice == 'hardening':
                hardening_menu(manager)
            elif choice == 'watchdog':
                watchdog_menu(manager)
            elif choice == 'devices':
                device_menu(manager, backend, select_device(backend))
            elif choice == 'users':
                user = choose('Users', [(key, value['name']) for key, value in registry['users'].items()])
                action = choose(registry['users'][user]['name'], [('devices', 'Devices'), ('rename', 'Rename display name'), ('policy', 'Default LAN policy'), ('revoke', 'Revoke all user devices')])
                if action == 'devices':
                    options = [(key, value['name']) for key, value in registry['devices'].items() if value['user'] == user]
                    device_menu(manager, backend, choose('Devices', options))
                elif action == 'policy':
                    policy = choose('User LAN default', [('block', 'Block LAN'), ('allow', 'Allow LAN')])
                    with manager.lock():
                        backend.set_policy('user', user, policy)
                elif action == 'rename':
                    name = ask('User display name', registry['users'][user]['name'])
                    with manager.lock():
                        backend.rename('user', user, name)
                elif confirm('Revoke every protocol on every device for this user?'):
                    with manager.lock():
                        backend.revoke_user(user)
            elif choice == 'discover':
                names = backend.discover()
                name = choose('Unassigned NSS client certificates', [(n, n) for n in names])
                user = choose('Assign to user', [(key, value['name']) for key, value in registry['users'].items()])
                with manager.lock():
                    backend.adopt(name, user, name)
            elif choice == 'web':
                web_menu(manager, backend)
            elif choice == 'live':
                live(manager)
            elif choice == 'ports':
                state = manager.load()
                show('Router instructions', f'UDP 500, 4500, 51820 → {state["lan"]}\nTCP 9000 only if public downloads are enabled.\nNever forward 53, 1701, 3000 or 8080.\nIPv4 full tunnel only. Disable client IPv6 if required.\nTest from mobile data and check AdGuard Query Log.')
        except Cancel:
            return
        except Exception as exc:
            show('Operation failed', str(exc))

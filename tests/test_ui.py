import curses
import fcntl
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import unittest
import io
import types
from unittest.mock import patch
from test_manager import ROOT
import vpn_ui as ui


class TerminalTests(unittest.TestCase):
    def session(self, operation, arguments, keys, resize=False):
        master, slave = pty.openpty()
        original = termios.tcgetattr(slave)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 100, 0, 0))
        def terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        process = subprocess.Popen([sys.executable, str(ROOT / 'src/manage.py'), operation] + arguments,
                                   stdin=slave, stdout=subprocess.PIPE, stderr=slave,
                                   env=dict(os.environ, TERM='xterm', ESCDELAY='25'), preexec_fn=terminal)
        screen = b''
        try:
            deadline = time.monotonic() + 4
            while b'VPN test' not in screen and time.monotonic() < deadline:
                if select.select([master], [], [], .1)[0]:
                    screen += os.read(master, 65536)
            self.assertIn(b'VPN test', screen)
            if resize:
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 18, 70, 0, 0))
                process.send_signal(signal.SIGWINCH)
            for key in keys:
                os.write(master, key)
                time.sleep(.08)
            output, _ = process.communicate(timeout=5)
            while select.select([master], [], [], 0)[0]:
                screen += os.read(master, 65536)
            self.assertEqual(termios.tcgetattr(slave), original)
            return process.returncode, output.strip(), screen
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)
            os.close(slave)

    def test_arrow_enter_and_resize(self):
        code, output, _ = self.session('ui-choice', ['VPN test', 'a=First', 'b=Second'], [b'\x1bOB', b'\r'], True)
        self.assertEqual((code, output), (0, b'b'))

    def test_filter_space_and_escape_cleanup(self):
        code, output, _ = self.session('ui-choice', ['VPN test', 'a=First', 'b=Second'], [b'/Second', b'\r', b' '])
        self.assertEqual((code, output), (0, b'b'))
        code, output, _ = self.session('ui-choice', ['VPN test', 'a=First'], [b'\x1b'])
        self.assertEqual((code, output), (0, b'0'))

    def test_navigation_boundaries(self):
        self.assertEqual(ui.menu_key(curses.KEY_UP, 0, 10), 0)
        self.assertEqual(ui.menu_key(curses.KEY_END, 0, 10), 9)
        self.assertEqual(ui.menu_key(curses.KEY_NPAGE, 8, 10), 9)

    def test_plain_validation_retries_without_accepting_invalid_value(self):
        from vpn_console import name_valid
        with patch.object(ui,'enabled',return_value=False),patch('sys.stdin',io.StringIO('\nPhone\n')),patch('sys.stderr',io.StringIO()) as output:
            self.assertEqual(ui.ask('Name',validate=name_valid),'Phone')
            self.assertIn('1–80 printable',output.getvalue())

    def test_device_revocation_requires_confirmation_and_identifies_protocol(self):
        from vpn_console import workflow
        backend=types.SimpleNamespace(load=lambda:{'users':{'u':{'name':'User'}},'devices':{'d':{'name':'Phone','user':'u','protocols':{'ikev2':{'status':'active'}}}}})
        with patch.object(ui,'choose',side_effect=['d','revoke','ikev2']),patch.object(ui,'confirm',return_value=False):
            self.assertIsNone(workflow('devices',backend,None,{},{}))
        with patch.object(ui,'choose',side_effect=['d','revoke','ikev2']),patch.object(ui,'confirm',return_value=True):
            form=workflow('devices',backend,None,{},{})
        self.assertEqual((form['device'],form['protocol'],form['confirm']),('d','ikev2','REVOKE'))

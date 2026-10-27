from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ClockTests(unittest.TestCase):
    def run_check(self, behavior):
        with tempfile.TemporaryDirectory() as tmp:
            script = ('source ' + str(ROOT / 'setup.sh') + '\nTEST_DIR=' + tmp + '\n'
                      'sleep() { :; }\n' + behavior + '\ncheck_clock\n')
            result = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
            calls = (Path(tmp) / 'enabled').exists()
            return result, calls

    def test_existing_synchronized_clock_is_preserved(self):
        result, enabled = self.run_check('''timedatectl() {
if [[ $1 == show ]]; then echo yes; else touch "$TEST_DIR/enabled"; fi
}''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(enabled)

    def test_enables_ntp_and_waits_for_synchronization(self):
        result, enabled = self.run_check('''timedatectl() {
if [[ $1 == set-ntp ]]; then touch "$TEST_DIR/enabled";
elif [[ -f $TEST_DIR/enabled ]]; then echo yes; else echo no; fi
}''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(enabled)

    def test_unsynchronized_clock_stops_before_apt(self):
        result, enabled = self.run_check('''timedatectl() {
if [[ $1 == set-ntp ]]; then touch "$TEST_DIR/enabled"; else echo no; fi
}''')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(enabled)
        self.assertIn('Clock is not synchronized', result.stderr)
        self.assertIn('APT date checks remain enabled', result.stderr)

    def test_clock_check_precedes_bootstrap_and_package_operations(self):
        source = (ROOT / 'src/installer.sh').read_text().split('install_stack() {', 1)[1]
        self.assertLess(source.index('check_clock'), source.index('apt-get'))


if __name__ == '__main__':
    unittest.main()

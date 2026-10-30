"""A successful unittest exit must not hide unexecuted release qualification."""
import io
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from run_release_tests import run_suite


class StrictReleaseRunnerTests(unittest.TestCase):
    def case(self,kind):
        def runTest(instance):
            if kind=='skip':instance.skipTest('Synthetic missing prerequisite')
            if kind in ('failure','expected_failure'):instance.fail('Synthetic failed assertion')
            if kind=='error':raise RuntimeError('Synthetic test error')
        if kind in ('expected_failure','unexpected_success'):
            runTest=unittest.expectedFailure(runTest)
        return type('Synthetic'+kind,(unittest.TestCase,),{'runTest':runTest})()

    def test_all_executed_tests_must_pass(self):
        output=io.StringIO()
        self.assertEqual(run_suite(unittest.TestSuite([self.case('pass')]),output),0)
        self.assertIn('Ran 1 test',output.getvalue())

    def test_skips_and_expected_failures_block_release(self):
        for kind in ('skip','expected_failure'):
            output=io.StringIO()
            with self.subTest(kind=kind):
                self.assertEqual(run_suite(unittest.TestSuite([self.case('pass'),self.case(kind)]),output),1)
                self.assertIn('every discovered test must run and pass',output.getvalue())

    def test_failures_errors_and_unexpected_success_block_release(self):
        for kind in ('failure','error','unexpected_success'):
            with self.subTest(kind=kind):
                self.assertEqual(run_suite(unittest.TestSuite([self.case(kind)]),io.StringIO()),1)

    def test_empty_discovery_blocks_release(self):
        output=io.StringIO()
        self.assertEqual(run_suite(unittest.TestSuite(),output),1)
        self.assertIn('run=0',output.getvalue())

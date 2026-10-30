#!/usr/bin/env python3
"""Run release qualification tests; unavailable prerequisites must fail the job."""
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]


def run_suite(suite,stream=None):
    stream=stream if stream is not None else sys.stderr
    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    if (not result.wasSuccessful() or result.testsRun==0 or
            result.skipped or result.expectedFailures):
        stream.write('Release qualification failed: every discovered test must run and pass; '
                     f'run={result.testsRun}, skipped={len(result.skipped)}, '
                     f'expected_failures={len(result.expectedFailures)}.\n')
        return 1
    return 0


if __name__=='__main__':
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'))
    raise SystemExit(run_suite(suite))

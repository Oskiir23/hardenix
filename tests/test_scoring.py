import unittest

from hardenix.core.model import Finding, Severity, Status
from hardenix.core.runner import score, summary


def f(status, sev):
    return Finding("id", "title", sev, status)


class ScoringTest(unittest.TestCase):
    def test_all_pass_is_100(self):
        self.assertEqual(score([f(Status.PASS, Severity.HIGH),
                                f(Status.PASS, Severity.LOW)]), 100)

    def test_all_fail_is_0(self):
        self.assertEqual(score([f(Status.FAIL, Severity.HIGH)]), 0)

    def test_weighted_mix(self):
        # HIGH=3 pass, HIGH=3 fail -> 3/6 = 50
        self.assertEqual(score([f(Status.PASS, Severity.HIGH),
                                f(Status.FAIL, Severity.HIGH)]), 50)

    def test_severity_weights(self):
        # LOW=1 pass, CRITICAL=5 fail -> 1/6 = 17 (redondeo)
        self.assertEqual(score([f(Status.PASS, Severity.LOW),
                                f(Status.FAIL, Severity.CRITICAL)]), 17)

    def test_na_and_error_not_scored(self):
        self.assertEqual(score([f(Status.NA, Severity.HIGH),
                                f(Status.ERROR, Severity.CRITICAL)]), 100)

    def test_empty_is_100(self):
        self.assertEqual(score([]), 100)

    def test_summary_counts(self):
        counts = summary([f(Status.PASS, Severity.LOW),
                          f(Status.PASS, Severity.LOW),
                          f(Status.FAIL, Severity.HIGH)])
        self.assertEqual(counts[Status.PASS], 2)
        self.assertEqual(counts[Status.FAIL], 1)
        self.assertEqual(counts[Status.NA], 0)


if __name__ == "__main__":
    unittest.main()

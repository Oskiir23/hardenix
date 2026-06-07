import unittest

from hardenix.checks.ssh import _seconds
from hardenix.checks.pam import _find_int


class HelpersTest(unittest.TestCase):
    def test_seconds_plain(self):
        self.assertEqual(_seconds("120"), 120)

    def test_seconds_minutes(self):
        self.assertEqual(_seconds("2m"), 120)

    def test_seconds_seconds_suffix(self):
        self.assertEqual(_seconds("30s"), 30)

    def test_seconds_invalid_uses_default(self):
        self.assertEqual(_seconds("", default=99), 99)
        self.assertEqual(_seconds("abc", default=42), 42)

    def test_find_int_basic(self):
        lines = ["password requisite pam_pwquality.so retry=3 minlen=12 difok=3"]
        self.assertEqual(_find_int(lines, "minlen"), 12)
        self.assertEqual(_find_int(lines, "retry"), 3)

    def test_find_int_with_spaces(self):
        self.assertEqual(_find_int(["minlen = 14"], "minlen"), 14)

    def test_find_int_module_filter(self):
        lines = ["auth required pam_faillock.so deny=4 unlock_time=300"]
        self.assertEqual(_find_int(lines, "deny", module=["pam_faillock.so"]), 4)
        self.assertIsNone(_find_int(lines, "deny", module=["pam_tally2.so"]))

    def test_find_int_absent(self):
        self.assertIsNone(_find_int(["nada que ver"], "minlen"))


if __name__ == "__main__":
    unittest.main()

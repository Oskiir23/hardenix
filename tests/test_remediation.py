import os
import tempfile
import unittest

from hardenix.core.system import Ctx
from hardenix.core.remediation import Remediator, rollback


def _manifest(rem):
    return {"files": list(rem._files.values()), "sysctl": [], "services": []}


def _read(path):
    with open(path) as fh:
        return fh.read()


class RemediationTest(unittest.TestCase):
    def test_set_directive_replaces_and_keeps_rest(self):
        fd, path = tempfile.mkstemp()
        os.write(fd, b"MaxAuthTries 6\nPort 22\n")
        os.close(fd)
        try:
            rem = Remediator(Ctx())
            rem.set_directive(path, "MaxAuthTries", "4")
            content = _read(path)
            self.assertIn("MaxAuthTries 4", content)
            self.assertNotIn("MaxAuthTries 6", content)
            self.assertIn("Port 22", content)  # otras líneas intactas
        finally:
            os.remove(path)

    def test_rollback_restores_file(self):
        fd, path = tempfile.mkstemp()
        os.write(fd, b"MaxAuthTries 6\n")
        os.close(fd)
        try:
            ctx = Ctx()
            rem = Remediator(ctx)
            rem.set_directive(path, "MaxAuthTries", "4")
            rollback(ctx, _manifest(rem))
            restored = _read(path)
            self.assertIn("MaxAuthTries 6", restored)
            self.assertNotIn("MaxAuthTries 4", restored)
        finally:
            os.remove(path)

    def test_dry_run_does_not_write(self):
        fd, path = tempfile.mkstemp()
        os.write(fd, b"UMASK 022\n")
        os.close(fd)
        try:
            rem = Remediator(Ctx(), dry_run=True)
            rem.set_directive(path, "UMASK", "027")
            self.assertIn("UMASK 022", _read(path))  # no se modifica
            self.assertTrue(rem.has_changes())             # pero registra el plan
        finally:
            os.remove(path)

    def test_chmod_and_rollback(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            os.chmod(path, 0o644)
            ctx = Ctx()
            rem = Remediator(ctx)
            rem.chmod(path, 0o600)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            rollback(ctx, _manifest(rem))
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()

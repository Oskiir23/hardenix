import os
import tempfile
import unittest

from hardenix.core.model import Status
from hardenix.checks import ssh, kernel, accounts, pam, filesystem
from hardenix.tests.fake import FakeCtx


def st(check_cls, ctx):
    return check_cls().audit(ctx).status


class SSHChecksTest(unittest.TestCase):
    def ctx(self, sshd):
        return FakeCtx(files={"/etc/ssh/sshd_config": sshd})

    def test_root_login_yes_fails(self):
        self.assertEqual(st(ssh.SSHRootLogin, self.ctx("PermitRootLogin yes")), Status.FAIL)

    def test_root_login_no_passes(self):
        self.assertEqual(st(ssh.SSHRootLogin, self.ctx("PermitRootLogin no")), Status.PASS)

    def test_maxauthtries(self):
        self.assertEqual(st(ssh.SSHMaxAuthTries, self.ctx("MaxAuthTries 6")), Status.FAIL)
        self.assertEqual(st(ssh.SSHMaxAuthTries, self.ctx("MaxAuthTries 3")), Status.PASS)

    def test_login_grace_time_default_fails(self):
        # sin directiva -> default 120s -> falla (>60)
        self.assertEqual(st(ssh.SSHLoginGraceTime, self.ctx("# vacío")), Status.FAIL)

    def test_login_grace_time_low_passes(self):
        self.assertEqual(st(ssh.SSHLoginGraceTime, self.ctx("LoginGraceTime 30")), Status.PASS)

    def test_pubkey_default_passes(self):
        self.assertEqual(st(ssh.SSHPubkeyAuth, self.ctx("# vacío")), Status.PASS)

    def test_pubkey_disabled_fails(self):
        self.assertEqual(st(ssh.SSHPubkeyAuth, self.ctx("PubkeyAuthentication no")), Status.FAIL)


class KernelChecksTest(unittest.TestCase):
    def test_aslr_enabled(self):
        ctx = FakeCtx(sysctls={"kernel.randomize_va_space": "2"})
        self.assertEqual(st(kernel.KernelASLR, ctx), Status.PASS)

    def test_aslr_disabled(self):
        ctx = FakeCtx(sysctls={"kernel.randomize_va_space": "0"})
        self.assertEqual(st(kernel.KernelASLR, ctx), Status.FAIL)


class AccountsChecksTest(unittest.TestCase):
    def test_umask_strong(self):
        ctx = FakeCtx(files={"/etc/login.defs": "UMASK 027"})
        self.assertEqual(st(accounts.DefaultUmask, ctx), Status.PASS)

    def test_umask_weak(self):
        ctx = FakeCtx(files={"/etc/login.defs": "UMASK 022"})
        self.assertEqual(st(accounts.DefaultUmask, ctx), Status.FAIL)

    def test_empty_password_detected(self):
        ctx = FakeCtx(files={"/etc/shadow": "root:x:1::\nbob::1::"})
        self.assertEqual(st(accounts.EmptyPasswords, ctx), Status.FAIL)

    def test_no_empty_password(self):
        ctx = FakeCtx(files={"/etc/shadow": "root:$6$abc:1::\nbob:$6$xyz:1::"})
        self.assertEqual(st(accounts.EmptyPasswords, ctx), Status.PASS)

    def test_extra_uid0_fails(self):
        ctx = FakeCtx(files={"/etc/passwd": "root:x:0:0::/root:/bin/bash\nbackdoor:x:0:0::/:/bin/bash"})
        self.assertEqual(st(accounts.UniqueRoot, ctx), Status.FAIL)

    def test_unique_root_passes(self):
        ctx = FakeCtx(files={"/etc/passwd": "root:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash"})
        self.assertEqual(st(accounts.UniqueRoot, ctx), Status.PASS)


class PamChecksTest(unittest.TestCase):
    def test_password_quality_ok(self):
        ctx = FakeCtx(files={"/etc/pam.d/common-password":
                             "password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1"})
        self.assertEqual(st(pam.PasswordQuality, ctx), Status.PASS)

    def test_password_quality_short(self):
        ctx = FakeCtx(files={"/etc/pam.d/common-password":
                             "password requisite pam_pwquality.so minlen=8"})
        self.assertEqual(st(pam.PasswordQuality, ctx), Status.FAIL)

    def test_password_quality_missing(self):
        ctx = FakeCtx(files={"/etc/pam.d/common-password": "password requisite pam_unix.so"})
        self.assertEqual(st(pam.PasswordQuality, ctx), Status.FAIL)

    def test_account_lockout_ok(self):
        ctx = FakeCtx(files={"/etc/pam.d/common-auth":
                             "auth required pam_faillock.so deny=3 unlock_time=300"})
        self.assertEqual(st(pam.AccountLockout, ctx), Status.PASS)

    def test_account_lockout_missing(self):
        ctx = FakeCtx(files={"/etc/pam.d/common-auth": "auth required pam_unix.so"})
        self.assertEqual(st(pam.AccountLockout, ctx), Status.FAIL)

    def test_password_history_ok(self):
        ctx = FakeCtx(files={"/etc/pam.d/common-password":
                             "password requisite pam_pwhistory.so remember=10"})
        self.assertEqual(st(pam.PasswordHistory, ctx), Status.PASS)


class FilesystemChecksTest(unittest.TestCase):
    def _check_with_path(self, path, max_mode):
        c = filesystem.ShadowPerms()
        c.path = path
        c.max_mode = max_mode
        c.owner_uid = os.getuid()  # el fichero temporal lo posee el usuario de test
        return c

    def test_perms_ok(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            os.chmod(path, 0o600)
            ctx = FakeCtx()
            self.assertEqual(self._check_with_path(path, 0o640).audit(ctx).status, Status.PASS)
        finally:
            os.remove(path)

    def test_perms_too_open(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            os.chmod(path, 0o644)
            ctx = FakeCtx()
            self.assertEqual(self._check_with_path(path, 0o640).audit(ctx).status, Status.FAIL)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()

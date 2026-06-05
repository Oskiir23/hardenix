"""Checks de endurecimiento del servidor SSH (OpenSSH)."""

from ..core.model import Check, Severity

REF = ["CIS Benchmark - SSH Server", "man sshd_config"]


class _SSHCheck(Check):
    references = REF
    remediable = True

    def applicable(self, ctx):
        return ctx.ssh_installed()

    def _value(self, ctx, key):
        cfg, _ = ctx.sshd_config()
        return (cfg.get(key, "") or "").lower()


class SSHRootLogin(_SSHCheck):
    id = "ssh-root-login"
    title = "Login de root por SSH deshabilitado"
    severity = Severity.HIGH
    rationale = "Permitir login directo de root facilita ataques de fuerza bruta y oculta la trazabilidad."

    def audit(self, ctx):
        v = self._value(ctx, "permitrootlogin")
        if v in ("no", "prohibit-password", "forced-commands-only"):
            return self.ok(current=f"PermitRootLogin {v}")
        return self.fail(
            current=f"PermitRootLogin {v or 'yes (por defecto)'}",
            expected="PermitRootLogin no",
            detail="root puede iniciar sesión directamente por SSH.",
        )


class SSHPasswordAuth(_SSHCheck):
    id = "ssh-password-auth"
    title = "Autenticación por contraseña deshabilitada (solo claves)"
    severity = Severity.MEDIUM
    rationale = "El uso de claves en vez de contraseñas elimina la fuerza bruta de credenciales."

    def audit(self, ctx):
        v = self._value(ctx, "passwordauthentication")
        if v == "no":
            return self.ok(current="PasswordAuthentication no")
        return self.fail(
            current=f"PasswordAuthentication {v or 'yes'}",
            expected="PasswordAuthentication no",
            detail="Se permite login por contraseña (vulnerable a fuerza bruta).",
        )


class SSHX11Forwarding(_SSHCheck):
    id = "ssh-x11-forwarding"
    title = "Reenvío X11 deshabilitado"
    severity = Severity.LOW
    rationale = "X11Forwarding amplía la superficie de ataque y rara vez es necesario en servidores."

    def audit(self, ctx):
        v = self._value(ctx, "x11forwarding")
        if v == "no":
            return self.ok(current="X11Forwarding no")
        return self.fail(
            current=f"X11Forwarding {v or 'yes'}",
            expected="X11Forwarding no",
        )


class SSHMaxAuthTries(_SSHCheck):
    id = "ssh-max-auth-tries"
    title = "MaxAuthTries limitado (<= 4)"
    severity = Severity.MEDIUM
    rationale = "Limitar los intentos de autenticación frena la fuerza bruta por conexión."

    def audit(self, ctx):
        v = self._value(ctx, "maxauthtries")
        try:
            n = int(v)
        except (TypeError, ValueError):
            n = 6
        if n <= 4:
            return self.ok(current=f"MaxAuthTries {n}")
        return self.fail(
            current=f"MaxAuthTries {n}",
            expected="MaxAuthTries 4",
        )


class SSHEmptyPasswords(_SSHCheck):
    id = "ssh-permit-empty-passwords"
    title = "Contraseñas vacías por SSH deshabilitadas"
    severity = Severity.HIGH
    rationale = "Permitir contraseñas vacías habilita el acceso a cuentas sin password."

    def audit(self, ctx):
        v = self._value(ctx, "permitemptypasswords")
        if v == "no":
            return self.ok(current="PermitEmptyPasswords no")
        return self.fail(
            current=f"PermitEmptyPasswords {v or 'yes'}",
            expected="PermitEmptyPasswords no",
        )


CHECKS = [
    SSHRootLogin,
    SSHPasswordAuth,
    SSHX11Forwarding,
    SSHMaxAuthTries,
    SSHEmptyPasswords,
]

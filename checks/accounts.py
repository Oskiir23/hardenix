"""Checks de cuentas y política de contraseñas."""

from ..core.model import Check, Severity

REF = ["CIS Benchmark - User Accounts and Environment"]


class PasswordMaxDays(Check):
    id = "accounts-pass-max-days"
    title = "Caducidad de contraseña configurada (PASS_MAX_DAYS <= 365)"
    severity = Severity.LOW
    references = REF
    remediable = True
    rationale = "Forzar el cambio periódico de contraseña limita la ventana de uso de credenciales robadas."

    def audit(self, ctx):
        defs = ctx.login_defs()
        raw = defs.get("PASS_MAX_DAYS")
        try:
            n = int(raw)
        except (TypeError, ValueError):
            return self.fail(
                current="PASS_MAX_DAYS sin definir",
                expected="PASS_MAX_DAYS 365",
            )
        if n <= 365:
            return self.ok(current=f"PASS_MAX_DAYS {n}")
        return self.fail(current=f"PASS_MAX_DAYS {n}", expected="PASS_MAX_DAYS 365")

    def remediate(self, ctx, rem):
        rem.set_login_defs("PASS_MAX_DAYS", "365")


class DefaultUmask(Check):
    id = "accounts-umask"
    title = "UMASK por defecto restrictivo (027 o 077)"
    severity = Severity.LOW
    references = REF
    remediable = True
    rationale = "Un umask laxo crea ficheros legibles por otros usuarios por defecto."

    def audit(self, ctx):
        defs = ctx.login_defs()
        v = (defs.get("UMASK") or "").strip()
        if v in ("027", "077", "0027", "0077"):
            return self.ok(current=f"UMASK {v}")
        return self.fail(current=f"UMASK {v or 'sin definir'}", expected="UMASK 027")

    def remediate(self, ctx, rem):
        rem.set_login_defs("UMASK", "027")


class EmptyPasswords(Check):
    id = "accounts-empty-passwords"
    title = "Ninguna cuenta con contraseña vacía"
    severity = Severity.CRITICAL
    references = REF
    rationale = "Una cuenta sin contraseña permite el acceso directo sin autenticación."

    def applicable(self, ctx):
        return ctx.read_file("/etc/shadow") is not None

    def audit(self, ctx):
        text = ctx.read_file("/etc/shadow") or ""
        empty = []
        for line in text.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "":
                empty.append(parts[0])
        if not empty:
            return self.ok(current="0 cuentas con contraseña vacía")
        return self.fail(
            current=f"cuentas sin contraseña: {', '.join(empty)}",
            expected="0 cuentas con contraseña vacía",
            detail="Asigna una contraseña o bloquea estas cuentas.",
        )


class UniqueRoot(Check):
    id = "accounts-unique-root"
    title = "Solo la cuenta root tiene UID 0"
    severity = Severity.HIGH
    references = REF
    rationale = "Cualquier cuenta con UID 0 tiene privilegios de root; debería existir solo 'root'."

    def audit(self, ctx):
        text = ctx.read_file("/etc/passwd") or ""
        uid0 = []
        for line in text.splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[2] == "0":
                uid0.append(parts[0])
        extra = [u for u in uid0 if u != "root"]
        if not extra:
            return self.ok(current="UID 0: root")
        return self.fail(
            current=f"UID 0: {', '.join(uid0)}",
            expected="UID 0: solo root",
            detail=f"Cuentas extra con UID 0: {', '.join(extra)}",
        )


CHECKS = [PasswordMaxDays, DefaultUmask, EmptyPasswords, UniqueRoot]

"""Checks de políticas de autenticación vía PAM:
complejidad de contraseña, historial y bloqueo por fuerza bruta.

Son report-only: editar la pila de PAM mal puede dejar al usuario sin poder
autenticarse, así que Hardenix los detecta pero no los modifica.
Multi-distro: Debian usa /etc/pam.d/common-*; RHEL usa system-auth/password-auth.
"""

import re

from ..core.model import Check, Severity

REF = ["CIS Benchmark - PAM / Authentication"]


def _lines(ctx, path):
    text = ctx.read_file(path)
    if not text:
        return []
    out = []
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def _password_files(ctx):
    if ctx.family() == "rhel":
        return ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
    return ["/etc/pam.d/common-password"]


def _auth_files(ctx):
    if ctx.family() == "rhel":
        return ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
    return ["/etc/pam.d/common-auth"]


def _gather(ctx, files, extra_conf=None):
    lines = []
    for f in files:
        lines += _lines(ctx, f)
    if extra_conf:
        lines += _lines(ctx, extra_conf)
    return lines


def _find_int(lines, key, module=None):
    """Busca key=N (o key = N) en las líneas; si module se indica, solo en
    líneas que mencionen ese/esos módulos. Devuelve el primero encontrado."""
    pat = re.compile(rf"\b{key}\s*=\s*(\d+)")
    for ln in lines:
        if module and not any(m in ln for m in module):
            continue
        m = pat.search(ln)
        if m:
            return int(m.group(1))
    return None


class _PamCheck(Check):
    references = REF

    def applicable(self, ctx):
        files = _password_files(ctx) + _auth_files(ctx)
        return any(ctx.read_file(f) is not None for f in files)


class PasswordQuality(_PamCheck):
    id = "pam-password-quality"
    title = "Política de complejidad de contraseñas (pwquality/cracklib)"
    severity = Severity.MEDIUM
    rationale = ("Sin una política de complejidad, los usuarios pueden poner contraseñas "
                 "débiles vulnerables a diccionario y fuerza bruta.")

    def audit(self, ctx):
        lines = _gather(ctx, _password_files(ctx), "/etc/security/pwquality.conf")
        has_module = any(("pam_pwquality.so" in l or "pam_cracklib.so" in l) for l in lines)
        minlen = _find_int(lines, "minlen")
        if not has_module and minlen is None:
            return self.fail(
                current="sin módulo de calidad de contraseñas",
                expected="pam_pwquality/cracklib con minlen>=12",
                detail="Instala libpam-pwquality y configura minlen y complejidad.",
            )
        if minlen is not None and minlen >= 12:
            return self.ok(current=f"minlen={minlen} con módulo de calidad")
        return self.fail(
            current=f"minlen={minlen if minlen is not None else 'sin definir'}",
            expected="minlen >= 12",
            detail="Refuerza la longitud mínima y la complejidad (ucredit/lcredit/dcredit/ocredit).",
        )


class PasswordHistory(_PamCheck):
    id = "pam-password-history"
    title = "Historial de contraseñas (pam_pwhistory)"
    severity = Severity.LOW
    rationale = "Recordar contraseñas anteriores impide que los usuarios reutilicen credenciales cíclicamente."

    def audit(self, ctx):
        lines = _gather(ctx, _password_files(ctx))
        remember = _find_int(lines, "remember")
        if remember is not None and remember >= 5:
            return self.ok(current=f"remember={remember}")
        if remember is not None:
            return self.fail(current=f"remember={remember}", expected="remember >= 5")
        return self.fail(
            current="sin historial de contraseñas",
            expected="pam_pwhistory con remember>=5",
            detail="Añade pam_pwhistory.so remember=10 en la pila de password.",
        )


class AccountLockout(_PamCheck):
    id = "pam-account-lockout"
    title = "Bloqueo de cuenta por intentos fallidos (faillock/tally2)"
    severity = Severity.MEDIUM
    rationale = "Bloquear tras varios intentos fallidos frena los ataques de fuerza bruta de credenciales."

    def audit(self, ctx):
        lines = _gather(ctx, _auth_files(ctx), "/etc/security/faillock.conf")
        has_module = any(("pam_faillock.so" in l or "pam_tally2.so" in l) for l in lines)
        deny = _find_int(lines, "deny")
        if not has_module and deny is None:
            return self.fail(
                current="sin bloqueo por intentos fallidos",
                expected="pam_faillock/tally2 con deny<=5",
                detail="Configura pam_faillock (deny=3, unlock_time=300) en la pila de auth.",
            )
        if deny is not None and 1 <= deny <= 5:
            return self.ok(current=f"deny={deny}")
        return self.fail(
            current=f"deny={deny if deny is not None else 'sin definir'}",
            expected="deny entre 1 y 5",
        )


CHECKS = [PasswordQuality, PasswordHistory, AccountLockout]

"""Checks de permisos sobre ficheros sensibles del sistema."""

import os
import stat

from ..core.model import Check, Severity

REF = ["CIS Benchmark - System File Permissions"]


class _PermCheck(Check):
    references = REF
    remediable = True
    path = ""
    max_mode = 0o644          # permisos máximos permitidos
    owner_uid = 0             # propietario esperado (root)

    def applicable(self, ctx):
        return os.path.exists(self.path)

    def audit(self, ctx):
        try:
            st = os.stat(self.path)
        except OSError as e:
            return self.fail(current=f"no se pudo leer {self.path}: {e}")
        mode = stat.S_IMODE(st.st_mode)
        too_open = mode & ~self.max_mode
        wrong_owner = st.st_uid != self.owner_uid
        if not too_open and not wrong_owner:
            return self.ok(current=f"{self.path} {oct(mode)} uid={st.st_uid}")
        detail = []
        if too_open:
            detail.append(f"permisos {oct(mode)} demasiado abiertos")
        if wrong_owner:
            detail.append(f"propietario uid={st.st_uid} (esperado {self.owner_uid})")
        return self.fail(
            current=f"{self.path} {oct(mode)} uid={st.st_uid}",
            expected=f"{self.path} <= {oct(self.max_mode)} uid={self.owner_uid}",
            detail="; ".join(detail),
        )


class ShadowPerms(_PermCheck):
    id = "fs-shadow-perms"
    title = "Permisos correctos en /etc/shadow"
    severity = Severity.HIGH
    path = "/etc/shadow"
    max_mode = 0o640
    rationale = "/etc/shadow contiene los hashes de contraseña; no debe ser legible por usuarios normales."


class PasswdPerms(_PermCheck):
    id = "fs-passwd-perms"
    title = "Permisos correctos en /etc/passwd"
    severity = Severity.LOW
    path = "/etc/passwd"
    max_mode = 0o644
    rationale = "/etc/passwd debe ser legible pero solo modificable por root."


CHECKS = [ShadowPerms, PasswdPerms]

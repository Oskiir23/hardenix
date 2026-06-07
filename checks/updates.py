"""Check de actualizaciones de seguridad pendientes (multi-distro, best-effort)."""

import re

from ..core.model import Check, Severity


class SecurityUpdates(Check):
    id = "updates-pending"
    title = "Sin actualizaciones pendientes"
    severity = Severity.MEDIUM
    references = ["CIS Benchmark - Patch Management"]
    rationale = "Aplicar parches cierra vulnerabilidades conocidas ya corregidas por el proveedor."
    # Report-only: aplicar actualizaciones es lento y puede requerir reinicios.

    def audit(self, ctx):
        fam = ctx.family()
        if fam == "debian":
            return self._debian(ctx)
        if fam == "rhel":
            return self._rhel(ctx)
        return self.na(f"gestor de paquetes no soportado ({fam})")

    def _debian(self, ctx):
        rc, out, _ = ctx.run(["apt-get", "-s", "upgrade"], timeout=90)
        if rc != 0:
            return self.na("no se pudo consultar apt (¿listas desactualizadas?)")
        n = None
        for line in out.splitlines():
            m = re.search(r"(\d+)\s+(?:upgraded|actualizados|reinstalled)", line)
            if m:
                n = int(m.group(1))
                break
        if n is None:
            return self.na("salida de apt no interpretable")
        if n == 0:
            return self.ok(current="0 paquetes por actualizar")
        return self.fail(
            current=f"{n} paquetes con actualización disponible",
            expected="0 paquetes pendientes",
            detail="Aplica: apt-get update && apt-get upgrade",
        )

    def _rhel(self, ctx):
        rc, out, _ = ctx.run(["dnf", "-q", "check-update"], timeout=120)
        if rc == 0:
            return self.ok(current="0 actualizaciones pendientes")
        if rc == 100:
            pkgs = [l for l in out.splitlines() if l.strip() and not l.startswith(" ")]
            return self.fail(
                current=f"{len(pkgs)} actualizaciones disponibles",
                expected="0 pendientes",
                detail="Aplica: dnf upgrade",
            )
        return self.na("no se pudo consultar dnf")


CHECKS = [SecurityUpdates]

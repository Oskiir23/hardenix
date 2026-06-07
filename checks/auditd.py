"""Check del subsistema de auditoría (auditd)."""

from ..core.model import Check, Severity


class AuditdEnabled(Check):
    id = "auditd-enabled"
    title = "auditd instalado y activo"
    severity = Severity.MEDIUM
    references = ["CIS Benchmark - Logging and Auditing"]
    remediable = True
    rationale = ("auditd registra eventos de seguridad (accesos, cambios, llamadas "
                 "al sistema) imprescindibles para detección e investigación forense.")

    def applicable(self, ctx):
        return ctx.has_systemd()

    def _installed(self, ctx):
        return bool(ctx.which("auditctl")) or ctx.unit_present("auditd.service")

    def audit(self, ctx):
        if not self._installed(ctx):
            pkg = "auditd" if ctx.family() == "debian" else "audit"
            return self.fail(
                current="auditd no instalado",
                expected="auditd instalado y activo",
                detail=f"Instala el paquete: {'apt install ' + pkg if ctx.family() == 'debian' else 'dnf install ' + pkg}",
            )
        if ctx.service_active("auditd"):
            return self.ok(current="auditd activo")
        return self.fail(
            current="auditd instalado pero inactivo",
            expected="auditd activo",
            detail="Actívalo: systemctl enable --now auditd",
        )

    def remediate(self, ctx, rem):
        if not self._installed(ctx):
            # La instalación de paquetes no se automatiza (requiere red/confirmación).
            raise NotImplementedError
        rem.enable_service("auditd")


CHECKS = [AuditdEnabled]

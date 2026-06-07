"""Check de servicios inseguros heredados (texto plano)."""

from ..core.model import Check, Severity

# Servicios en texto claro / heredados que no deberían estar activos.
INSECURE_UNITS = [
    "telnet.socket", "telnet.service",
    "rsh.socket", "rlogin.socket", "rexec.socket",
    "tftp.socket", "tftp.service",
    "finger.socket",
]


class InsecureServices(Check):
    id = "services-insecure"
    title = "Servicios inseguros heredados deshabilitados (telnet, rsh, tftp…)"
    severity = Severity.HIGH
    references = ["CIS Benchmark - Inetd/Legacy Services"]
    remediable = True
    rationale = ("Telnet, rsh/rlogin, tftp o finger transmiten datos sin cifrar y "
                 "son vías de ataque conocidas; deben estar deshabilitados.")

    def applicable(self, ctx):
        return ctx.has_systemd()

    def _active(self, ctx):
        return [u for u in INSECURE_UNITS
                if ctx.service_active(u) or ctx.service_enabled(u)]

    def audit(self, ctx):
        active = self._active(ctx)
        if not active:
            return self.ok(current="ninguno activo")
        return self.fail(
            current="activos: " + ", ".join(active),
            expected="todos deshabilitados",
            detail="Servicios en texto plano expuestos.",
        )

    def remediate(self, ctx, rem):
        for unit in self._active(ctx):
            rem.disable_service(unit)


CHECKS = [InsecureServices]

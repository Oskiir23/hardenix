"""Check de cortafuegos (ufw / firewalld / nftables / iptables)."""

from ..core.model import Check, Severity


class FirewallActive(Check):
    id = "firewall-active"
    title = "Cortafuegos activo"
    severity = Severity.HIGH
    references = ["CIS Benchmark - Firewall Configuration"]
    rationale = "Un cortafuegos con política restrictiva reduce la superficie de ataque de red."
    # Report-only: habilitar un cortafuegos sin reglas puede dejar al usuario
    # fuera del sistema (lockout). Se informa pero no se auto-corrige.

    def _signals(self, ctx):
        sig = set()
        conf = (ctx.read_file("/etc/ufw/ufw.conf") or "").replace(" ", "")
        if "ENABLED=yes" in conf:
            sig.add("ufw")
        if ctx.has_systemd():
            for svc in ("firewalld", "nftables", "ufw"):
                if ctx.service_active(svc):
                    sig.add(svc)
        if ctx.is_root():
            rc, out, _ = ctx.run(["nft", "list", "ruleset"])
            if rc == 0 and "chain" in out:
                sig.add("nftables")
            rc, out, _ = ctx.run(["iptables", "-S"])
            if rc == 0:
                has_rules = any(l.startswith("-A") for l in out.splitlines())
                drop_policy = "-P INPUT DROP" in out or "-P INPUT DENY" in out
                if has_rules or drop_policy:
                    sig.add("iptables")
        return sorted(sig)

    def audit(self, ctx):
        sig = self._signals(ctx)
        if sig:
            return self.ok(current="activo: " + ", ".join(sig))
        if not ctx.is_root():
            return self.na("no se pudo determinar sin privilegios (ejecuta con sudo)")
        return self.fail(
            current="sin cortafuegos activo detectado",
            expected="ufw/firewalld/nftables activo con política restrictiva",
            detail="Activa un cortafuegos permitiendo antes SSH (p. ej. 'ufw allow OpenSSH && ufw enable').",
        )


CHECKS = [FirewallActive]

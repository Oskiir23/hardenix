"""Checks de parámetros del kernel (sysctl)."""

from ..core.model import Check, Severity

REF = ["CIS Benchmark - Network/Kernel Parameters", "man sysctl"]


class _SysctlCheck(Check):
    references = REF
    remediable = True
    key = ""
    expected_value = ""

    def applicable(self, ctx):
        return ctx.sysctl(self.key) is not None

    def audit(self, ctx):
        v = ctx.sysctl(self.key)
        if v == self.expected_value:
            return self.ok(current=f"{self.key} = {v}")
        return self.fail(
            current=f"{self.key} = {v}",
            expected=f"{self.key} = {self.expected_value}",
            detail=self.rationale,
        )


class KernelASLR(_SysctlCheck):
    id = "kernel-aslr"
    title = "ASLR activado (randomize_va_space = 2)"
    severity = Severity.HIGH
    key = "kernel.randomize_va_space"
    expected_value = "2"
    rationale = "La aleatorización del espacio de direcciones dificulta exploits de corrupción de memoria."


class KernelSynCookies(_SysctlCheck):
    id = "kernel-tcp-syncookies"
    title = "TCP SYN cookies activadas"
    severity = Severity.MEDIUM
    key = "net.ipv4.tcp_syncookies"
    expected_value = "1"
    rationale = "Las SYN cookies mitigan ataques de inundación SYN (DoS)."


class KernelAcceptRedirects(_SysctlCheck):
    id = "kernel-accept-redirects"
    title = "ICMP redirects no aceptados"
    severity = Severity.MEDIUM
    key = "net.ipv4.conf.all.accept_redirects"
    expected_value = "0"
    rationale = "Aceptar ICMP redirects permite alterar la tabla de rutas (MITM)."


class KernelRpFilter(_SysctlCheck):
    id = "kernel-rp-filter"
    title = "Reverse path filtering activado"
    severity = Severity.LOW
    key = "net.ipv4.conf.all.rp_filter"
    expected_value = "1"
    rationale = "El rp_filter descarta paquetes con origen suplantado (anti-spoofing)."


CHECKS = [
    KernelASLR,
    KernelSynCookies,
    KernelAcceptRedirects,
    KernelRpFilter,
]

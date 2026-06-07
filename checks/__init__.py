"""Registro central de todos los checks disponibles."""

from . import ssh, kernel, accounts, filesystem, firewall, services, auditd, updates

ALL_CHECKS = [
    *ssh.CHECKS,
    *kernel.CHECKS,
    *accounts.CHECKS,
    *filesystem.CHECKS,
    *firewall.CHECKS,
    *services.CHECKS,
    *auditd.CHECKS,
    *updates.CHECKS,
]

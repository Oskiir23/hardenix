"""Registro central de todos los checks disponibles."""

from . import ssh, kernel, accounts, filesystem

ALL_CHECKS = [
    *ssh.CHECKS,
    *kernel.CHECKS,
    *accounts.CHECKS,
    *filesystem.CHECKS,
]

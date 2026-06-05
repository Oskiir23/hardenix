"""Informe por terminal con color ANSI (sin dependencias externas)."""

import os
import sys

from ..core.model import Status, Severity
from ..core.runner import score, summary

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text, code):
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def _green(t): return _c(t, "32")
def _red(t): return _c(t, "31")
def _yellow(t): return _c(t, "33")
def _dim(t): return _c(t, "2")
def _bold(t): return _c(t, "1")
def _cyan(t): return _c(t, "36")


_STATUS_BADGE = {
    Status.PASS: lambda: _green("[ OK ]"),
    Status.FAIL: lambda: _red("[FALLO]"),
    Status.NA: lambda: _dim("[ NA ]"),
    Status.ERROR: lambda: _yellow("[ERR ]"),
}

_SEV_COLOR = {
    Severity.LOW: _dim,
    Severity.MEDIUM: _yellow,
    Severity.HIGH: _red,
    Severity.CRITICAL: lambda t: _c(t, "1;31"),
}


def _score_color(s):
    if s >= 80:
        return _green
    if s >= 50:
        return _yellow
    return _red


def _bar(value, width=30):
    filled = round(width * value / 100)
    return "█" * filled + "░" * (width - filled)


def render(findings, ctx):
    s = score(findings)
    counts = summary(findings)
    col = _score_color(s)

    print()
    print(_bold(_cyan("  HARDENIX")) + _dim("  ·  auditoría de endurecimiento Linux"))
    print(_dim(f"  Sistema: {ctx.distro_name()}"))
    if not ctx.is_root():
        print(_yellow("  ⚠  Ejecutando sin root: algunos checks pueden no aplicar."))
    print()

    # Findings agrupados: primero los fallos (más severos arriba)
    order = {Status.FAIL: 0, Status.ERROR: 1, Status.PASS: 2, Status.NA: 3}
    sev_rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    for f in sorted(findings, key=lambda x: (order[x.status], sev_rank[x.severity])):
        badge = _STATUS_BADGE[f.status]()
        sev = _SEV_COLOR[f.severity](f.severity.label.ljust(7))
        print(f"  {badge}  {sev}  {f.title}")
        if f.status == Status.FAIL:
            if f.current:
                print(_dim(f"          actual:   {f.current}"))
            if f.expected:
                print(_dim(f"          esperado: {f.expected}"))
            if f.detail:
                print(_dim(f"          → {f.detail}"))
    print()

    # Resumen
    print(_dim("  " + "─" * 50))
    print(
        f"  {_green(str(counts[Status.PASS]) + ' OK')}   "
        f"{_red(str(counts[Status.FAIL]) + ' fallos')}   "
        f"{_dim(str(counts[Status.NA]) + ' n/a')}   "
        f"{_yellow(str(counts[Status.ERROR]) + ' err')}"
    )
    print()
    print(f"  Puntuación de seguridad:  {col(_bold(str(s) + '/100'))}")
    print(f"  {col(_bar(s))}")
    print()

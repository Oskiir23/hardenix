"""Informe por terminal con color ANSI (sin dependencias externas)."""

import os
import sys
import textwrap

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


def render(findings, ctx, ai=None):
    ai = ai or {}
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
            text = ai.get(f.id)
            if text:
                wrapped = textwrap.wrap(text, width=70)
                if wrapped:
                    print("          " + _cyan("🤖 " + wrapped[0]))
                    for ln in wrapped[1:]:
                        print("             " + _cyan(ln))
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


def render_fix(ctx, res, applied_now, snap_id, after):
    rem = res["rem"]
    skipped = res["skipped"]
    print()
    head = "APLICANDO CORRECCIONES" if applied_now else "VISTA PREVIA (no se ha cambiado nada)"
    print(_bold(_cyan("  HARDENIX fix")) + _dim(f"  ·  {head}"))
    print()
    if rem.changes:
        print(_bold("  Cambios:"))
        for typ, target, detail in rem.changes:
            print(f"    {_green('+')} {_dim(typ.ljust(7))} {target}  →  {detail}")
    else:
        print(_dim("  No hay correcciones aplicables."))
    if skipped:
        print()
        print(_bold("  Omitidos:"))
        for f, why in skipped:
            print(f"    {_yellow('-')} {f.title}  {_dim('(' + why + ')')}")
    if rem.notes:
        print()
        for n in rem.notes:
            print(_yellow(f"  ⚠ {n}"))
    print()
    if applied_now:
        b = res["before"]
        col = _score_color(after if after is not None else b)
        if after is not None:
            print(f"  Puntuación:  {b}/100  →  {col(_bold(str(after) + '/100'))}")
        if snap_id:
            print(_dim(f"  Snapshot guardado: {snap_id}  ·  revertir con:  hardenix rollback"))
    else:
        print(_dim("  Aplica los cambios con:  ") + _bold("hardenix fix --yes"))
    print()


def print_snapshots(snaps):
    print()
    if not snaps:
        print(_dim("  No hay snapshots guardados."))
        print()
        return
    print(_bold("  Snapshots disponibles:"))
    for s in snaps:
        print(f"    {_cyan(s['id'])}  {_dim(s['created'])}  ({len(s.get('changes', []))} cambios)")
    print()


def render_rollback(manifest, actions, applied):
    print()
    head = "ROLLBACK" if applied else "VISTA PREVIA ROLLBACK"
    print(_bold(_cyan("  HARDENIX rollback")) + _dim(f"  ·  {head}  ({manifest['id']})"))
    print()
    if not actions:
        print(_dim("  Nada que revertir."))
    for kind, target in actions:
        print(f"    {_yellow('↩')} {_dim(kind.ljust(9))} {target}")
    print()
    if applied:
        print(_green("  Rollback completado."))
    else:
        print(_dim("  Ejecuta el rollback con:  ") + _bold("hardenix rollback --yes"))
    print()

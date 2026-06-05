"""Punto de entrada de línea de comandos de Hardenix."""

import argparse
import json

from . import __version__
from .core.system import Ctx
from .core.runner import (
    discover_checks,
    run_audit,
    run_fix,
    score,
)
from .core import remediation as rem_mod
from .report.terminal import (
    render,
    render_fix,
    print_snapshots,
    render_rollback,
)


def cmd_audit(args):
    ctx = Ctx()
    findings = run_audit(ctx, discover_checks())
    if args.json:
        print(json.dumps(
            {"score": score(findings), "findings": [f.to_dict() for f in findings]},
            indent=2, ensure_ascii=False,
        ))
    else:
        render(findings, ctx)
    return 0


def cmd_fix(args):
    ctx = Ctx()
    only = set(args.only.split(",")) if args.only else None
    apply = args.yes and not args.dry_run

    res = run_fix(ctx, dry_run=not apply, only=only, include_risky=args.incluir_riesgo)
    rem = res["rem"]

    snap_id = None
    after = None
    if apply and rem.has_changes():
        snap_id = rem.save_snapshot()
        # Ctx nuevo: el anterior cachea sshd/login.defs y daría lecturas viejas.
        after = score(run_audit(Ctx(), discover_checks()))

    render_fix(ctx, res, applied_now=apply, snap_id=snap_id, after=after)
    return 0


def cmd_rollback(args):
    ctx = Ctx()
    if args.list:
        print_snapshots(rem_mod.list_snapshots(ctx))
        return 0
    manifest = rem_mod.load_snapshot(ctx, args.id)
    if not manifest:
        print("No se encontró el snapshot solicitado (usa --list para verlos).")
        return 1
    actions = rem_mod.rollback(ctx, manifest, dry_run=not args.yes)
    render_rollback(manifest, actions, applied=args.yes)
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="hardenix",
        description="Auditor y endurecedor de seguridad para Linux.",
    )
    p.add_argument("--version", action="version", version=f"hardenix {__version__}")
    sub = p.add_subparsers(dest="cmd")

    a = sub.add_parser("audit", help="Audita el sistema y muestra la puntuación.")
    a.add_argument("--json", action="store_true", help="Salida en formato JSON.")
    a.set_defaults(func=cmd_audit)

    f = sub.add_parser("fix", help="Aplica correcciones (con copia de seguridad).")
    f.add_argument("--yes", action="store_true", help="Aplica los cambios (sin esto, solo previsualiza).")
    f.add_argument("--dry-run", action="store_true", help="Fuerza solo vista previa.")
    f.add_argument("--only", metavar="ID[,ID...]", help="Aplica solo los checks indicados.")
    f.add_argument("--incluir-riesgo", action="store_true",
                   help="Incluye fixes que pueden bloquear el acceso (p. ej. SSH).")
    f.set_defaults(func=cmd_fix)

    r = sub.add_parser("rollback", help="Revierte un snapshot de cambios.")
    r.add_argument("--list", action="store_true", help="Lista los snapshots guardados.")
    r.add_argument("--id", metavar="ID", help="Snapshot a revertir (por defecto, el último).")
    r.add_argument("--yes", action="store_true", help="Ejecuta el rollback (sin esto, solo previsualiza).")
    r.set_defaults(func=cmd_rollback)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    return args.func(args)

"""Punto de entrada de línea de comandos de Hardenix."""

import argparse
import json

from . import __version__
from .core.system import Ctx
from .core.runner import discover_checks, run_audit, score
from .report.terminal import render


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

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    return args.func(args)

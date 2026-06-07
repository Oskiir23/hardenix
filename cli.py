"""Punto de entrada de línea de comandos de Hardenix."""

import argparse
import json
import os

from . import __version__
from .core.system import Ctx
from .core.model import Status
from .core.runner import (
    discover_checks,
    run_audit,
    run_fix,
    score,
    audit_to_dict,
)
from .core import remediation as rem_mod
from .report.terminal import (
    render,
    render_fix,
    print_snapshots,
    render_rollback,
)
from .report.html import render_html

AI_DEFAULT_URL = "http://localhost:1234/v1"


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _ai_map(findings, args):
    """Genera explicaciones IA para los fallos, si se pidió con --ai."""
    if not getattr(args, "ai", False):
        return {}
    from .ai.explain import AIClient

    client = AIClient(args.ai_url, args.ai_model)
    if not client.available():
        print(f"⚠ IA no disponible en {args.ai_url} ({client.last_error}). Continúo sin IA.")
        print("  Abre LM Studio, carga un modelo y activa el 'Local Server'.")
        return {}
    fails = [f for f in findings if f.status == Status.FAIL]
    print(f"🤖 Generando explicaciones con '{client.model}' ({len(fails)} hallazgos)...")
    out = {}
    for f in fails:
        try:
            out[f.id] = client.explain(f)
        except Exception as e:  # noqa: BLE001
            out[f.id] = f"(no se pudo generar la explicación: {e})"
    return out


def _inject_ai(data, ai_map):
    for f in data["findings"]:
        if f["id"] in ai_map:
            f["ai"] = ai_map[f["id"]]
    return data


def cmd_audit(args):
    ctx = Ctx()
    findings = run_audit(ctx, discover_checks())
    ai_map = _ai_map(findings, args)
    if args.json:
        data = _inject_ai(audit_to_dict(ctx, findings), ai_map)
        print(json.dumps(data, indent=2, ensure_ascii=False))
    elif args.html:
        data = _inject_ai(audit_to_dict(ctx, findings), ai_map)
        _write(args.html, render_html(data))
        print(f"Informe HTML generado: {args.html}")
    else:
        render(findings, ctx, ai=ai_map)
    return 0


def cmd_fix(args):
    ctx = Ctx()
    only = set(args.only.split(",")) if args.only else None
    apply = args.yes and not args.dry_run

    res = run_fix(ctx, dry_run=not apply, only=only, include_risky=args.incluir_riesgo)
    rem = res["rem"]

    snap_id = None
    after = None
    after_findings = None
    if apply and rem.has_changes():
        snap_id = rem.save_snapshot()
        after_findings = run_audit(Ctx(), discover_checks())  # Ctx nuevo: evita caché stale
        after = score(after_findings)

    render_fix(ctx, res, applied_now=apply, snap_id=snap_id, after=after)

    if args.report and after_findings is not None:
        ai_map = _ai_map(after_findings, args)
        before_dict = {
            "score": res["before"],
            "system": ctx.distro_name(),
            "findings": [f.to_dict() for f in res["before_findings"]],
        }
        after_dict = _inject_ai(audit_to_dict(Ctx(), after_findings), ai_map)
        _write(args.report, render_html(after_dict, before_dict))
        print(f"  Informe antes/después: {args.report}")
    return 0


def cmd_report(args):
    ctx = Ctx()
    findings = run_audit(ctx, discover_checks())
    ai_map = _ai_map(findings, args)
    after = _inject_ai(audit_to_dict(ctx, findings), ai_map)

    before = None
    if args.baseline:
        if not os.path.exists(args.baseline):
            print(f"No existe el baseline: {args.baseline}")
            return 1
        with open(args.baseline, encoding="utf-8") as fh:
            before = json.load(fh)

    out = args.output or "hardenix-report.html"
    _write(out, render_html(after, before))
    if args.save_baseline:
        with open(args.save_baseline, "w", encoding="utf-8") as fh:
            json.dump(after, fh, indent=2, ensure_ascii=False)
    print(f"Informe HTML generado: {out}")
    return 0


def cmd_serve(args):
    from .web.server import serve
    serve(args.host, args.port)
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
    if args.yes:
        rem_mod.delete_snapshot(ctx, manifest["id"])
    render_rollback(manifest, actions, applied=args.yes)
    return 0


def _add_ai_flags(sp):
    sp.add_argument("--ai", action="store_true",
                    help="Añade explicaciones generadas por un LLM local (LM Studio).")
    sp.add_argument("--ai-url", default=AI_DEFAULT_URL, metavar="URL",
                    help=f"Endpoint del LLM local (por defecto {AI_DEFAULT_URL}).")
    sp.add_argument("--ai-model", default=None, metavar="NAME",
                    help="Modelo a usar (por defecto, el primero disponible).")


def build_parser():
    p = argparse.ArgumentParser(
        prog="hardenix",
        description="Auditor y endurecedor de seguridad para Linux.",
    )
    p.add_argument("--version", action="version", version=f"hardenix {__version__}")
    sub = p.add_subparsers(dest="cmd")

    a = sub.add_parser("audit", help="Audita el sistema y muestra la puntuación.")
    a.add_argument("--json", action="store_true", help="Salida en formato JSON.")
    a.add_argument("--html", metavar="FILE", help="Genera un informe HTML en FILE.")
    _add_ai_flags(a)
    a.set_defaults(func=cmd_audit)

    f = sub.add_parser("fix", help="Aplica correcciones (con copia de seguridad).")
    f.add_argument("--yes", action="store_true", help="Aplica los cambios (sin esto, solo previsualiza).")
    f.add_argument("--dry-run", action="store_true", help="Fuerza solo vista previa.")
    f.add_argument("--only", metavar="ID[,ID...]", help="Aplica solo los checks indicados.")
    f.add_argument("--incluir-riesgo", action="store_true",
                   help="Incluye fixes que pueden bloquear el acceso (p. ej. SSH).")
    f.add_argument("--report", metavar="FILE", help="Genera informe HTML antes/después tras aplicar.")
    _add_ai_flags(f)
    f.set_defaults(func=cmd_fix)

    rp = sub.add_parser("report", help="Genera un informe HTML (con antes/después opcional).")
    rp.add_argument("--output", metavar="FILE", help="Fichero de salida (por defecto hardenix-report.html).")
    rp.add_argument("--baseline", metavar="FILE", help="JSON previo para comparar antes/después.")
    rp.add_argument("--save-baseline", metavar="FILE", help="Guarda la auditoría actual como baseline.")
    _add_ai_flags(rp)
    rp.set_defaults(func=cmd_report)

    sv = sub.add_parser("serve", help="Lanza el dashboard web (historial y tendencia).")
    sv.add_argument("--host", default="127.0.0.1", help="Host de escucha (por defecto 127.0.0.1).")
    sv.add_argument("--port", type=int, default=8080, help="Puerto (por defecto 8080).")
    sv.set_defaults(func=cmd_serve)

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

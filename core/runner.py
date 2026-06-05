"""Ejecuta los checks, recoge findings y calcula la puntuación."""

from datetime import datetime

from .model import Severity, Status, Finding

_WEIGHT = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 5,
}


def discover_checks():
    from ..checks import ALL_CHECKS
    return ALL_CHECKS


def run_audit(ctx, checks):
    findings = []
    for cls in checks:
        check = cls()
        try:
            if not check.applicable(ctx):
                findings.append(check.na("no aplica en este sistema"))
                continue
            findings.append(check.audit(ctx))
        except Exception as e:  # noqa: BLE001
            findings.append(
                Finding(
                    id=check.id,
                    title=check.title,
                    severity=check.severity,
                    status=Status.ERROR,
                    detail=f"error al evaluar: {e}",
                )
            )
    return findings


def score(findings):
    """Puntuación 0-100 ponderada por severidad (NA y ERROR no cuentan)."""
    total = got = 0
    for f in findings:
        if f.status in (Status.PASS, Status.FAIL):
            w = _WEIGHT[f.severity]
            total += w
            if f.status == Status.PASS:
                got += w
    return round(100 * got / total) if total else 100


def summary(findings):
    counts = {s: 0 for s in Status}
    for f in findings:
        counts[f.status] += 1
    return counts


def audit_to_dict(ctx, findings):
    """Serializa una auditoría completa (para JSON, baseline o informe HTML)."""
    counts = summary(findings)
    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "system": ctx.distro_name(),
        "score": score(findings),
        "summary": {s.name: counts[s] for s in Status},
        "findings": [f.to_dict() for f in findings],
    }


def checks_by_id():
    return {cls.id: cls for cls in discover_checks()}


def run_fix(ctx, dry_run=True, only=None, include_risky=False):
    """Aplica (o simula) las correcciones de los checks que fallan.

    Devuelve un dict con la puntuación previa, el Remediator (con los cambios
    registrados) y las listas de findings aplicados y omitidos.
    """
    from .remediation import Remediator

    findings = run_audit(ctx, discover_checks())
    before = score(findings)
    registry = checks_by_id()
    rem = Remediator(ctx, dry_run=dry_run)
    applied, skipped = [], []

    for f in findings:
        if f.status != Status.FAIL:
            continue
        if only and f.id not in only:
            continue
        if not f.remediable:
            skipped.append((f, "sin auto-fix disponible"))
            continue
        cls = registry.get(f.id)
        if cls is None:
            skipped.append((f, "check no encontrado"))
            continue
        check = cls()
        if check.risky and not include_risky:
            skipped.append((f, "riesgo de bloqueo — usa --incluir-riesgo"))
            continue
        try:
            check.remediate(ctx, rem)
            applied.append(f)
        except NotImplementedError:
            skipped.append((f, "sin auto-fix disponible"))
        except (OSError, PermissionError) as e:
            skipped.append((f, f"permiso denegado ({e}); prueba con sudo"))
        except Exception as e:  # noqa: BLE001
            skipped.append((f, f"error: {e}"))

    return {
        "before": before,
        "before_findings": findings,
        "rem": rem,
        "applied": applied,
        "skipped": skipped,
    }

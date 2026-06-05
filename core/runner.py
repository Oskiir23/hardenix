"""Ejecuta los checks, recoge findings y calcula la puntuación."""

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

"""Modelos base: severidad, estado y findings, y la clase Check."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self):
        return {
            Severity.LOW: "BAJA",
            Severity.MEDIUM: "MEDIA",
            Severity.HIGH: "ALTA",
            Severity.CRITICAL: "CRÍTICA",
        }[self]


class Status(Enum):
    PASS = "pass"      # cumple
    FAIL = "fail"      # no cumple
    NA = "na"          # no aplica
    ERROR = "error"    # fallo al evaluar


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    status: Status
    detail: str = ""
    current: str = ""
    expected: str = ""
    references: list = field(default_factory=list)
    remediable: bool = False

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.name,
            "status": self.status.value,
            "detail": self.detail,
            "current": self.current,
            "expected": self.expected,
            "references": self.references,
            "remediable": self.remediable,
        }


class Check:
    """Clase base para cada comprobación de seguridad."""

    id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    rationale: str = ""
    references: list = []
    remediable: bool = False

    def applicable(self, ctx) -> bool:
        return True

    def audit(self, ctx) -> Finding:
        raise NotImplementedError

    # helpers para construir findings de forma compacta
    def _f(self, status, **kw):
        return Finding(
            id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            references=list(self.references),
            remediable=self.remediable,
            **kw,
        )

    def ok(self, **kw):
        return self._f(Status.PASS, **kw)

    def fail(self, **kw):
        return self._f(Status.FAIL, **kw)

    def na(self, detail=""):
        return self._f(Status.NA, detail=detail)

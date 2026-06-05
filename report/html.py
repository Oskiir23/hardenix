"""Genera un informe HTML autocontenido (sin dependencias externas).

Soporta comparativa antes/después: si se pasa `before`, marca los checks
corregidos y muestra el salto de puntuación.
"""

import html as _html
import math
from datetime import datetime

_SEV_ES = {
    "LOW": ("BAJA", "#64748b"),
    "MEDIUM": ("MEDIA", "#eab308"),
    "HIGH": ("ALTA", "#f97316"),
    "CRITICAL": ("CRÍTICA", "#ef4444"),
}

_STATUS = {
    "pass": ("OK", "#22c55e"),
    "fail": ("FALLO", "#ef4444"),
    "na": ("N/A", "#64748b"),
    "error": ("ERROR", "#eab308"),
}


def _score_color(s):
    if s >= 80:
        return "#22c55e"
    if s >= 50:
        return "#eab308"
    return "#ef4444"


def _gauge(score, label=""):
    r = 60
    circ = 2 * math.pi * r
    frac = max(0, min(100, score)) / 100
    dash = circ * frac
    color = _score_color(score)
    return f"""
    <div class="gauge">
      <svg width="160" height="160" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r="{r}" fill="none" stroke="#1e293b" stroke-width="14"/>
        <circle cx="80" cy="80" r="{r}" fill="none" stroke="{color}" stroke-width="14"
          stroke-linecap="round" stroke-dasharray="{dash:.1f} {circ:.1f}"
          transform="rotate(-90 80 80)"/>
        <text x="80" y="74" text-anchor="middle" class="g-score" fill="{color}">{score}</text>
        <text x="80" y="98" text-anchor="middle" class="g-sub">/ 100</text>
      </svg>
      <div class="g-label">{_html.escape(label)}</div>
    </div>"""


def _badge(text, color, dark_text=False):
    fg = "#0f172a" if dark_text else "#fff"
    return f'<span class="badge" style="background:{color};color:{fg}">{_html.escape(text)}</span>'


def render_html(after, before=None):
    score_after = after.get("score", 0)
    findings = after.get("findings", [])
    system = after.get("system", "Linux")
    generated = after.get("generated") or datetime.now().isoformat(timespec="seconds")

    before_map = {}
    score_before = None
    if before:
        score_before = before.get("score")
        for f in before.get("findings", []):
            before_map[f["id"]] = f["status"]

    # cabecera de puntuación
    if before is not None and score_before is not None:
        delta = score_after - score_before
        delta_txt = f"+{delta}" if delta >= 0 else str(delta)
        gauges = (
            _gauge(score_before, "ANTES")
            + f'<div class="arrow">→<div class="delta">{delta_txt}</div></div>'
            + _gauge(score_after, "DESPUÉS")
        )
    else:
        gauges = _gauge(score_after, "PUNTUACIÓN")

    # resumen
    counts = {"pass": 0, "fail": 0, "na": 0, "error": 0}
    for f in findings:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    chips = "".join([
        _badge(f"{counts['pass']} OK", "#22c55e"),
        _badge(f"{counts['fail']} fallos", "#ef4444"),
        _badge(f"{counts['na']} n/a", "#334155"),
    ])

    # tabla de findings (fallos primero, luego por severidad)
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    st_rank = {"fail": 0, "error": 1, "pass": 2, "na": 3}
    rows = []
    for f in sorted(findings, key=lambda x: (st_rank.get(x["status"], 9),
                                             sev_rank.get(x["severity"], 9))):
        st_label, st_color = _STATUS.get(f["status"], ("?", "#888"))
        sev_label, sev_color = _SEV_ES.get(f["severity"], ("?", "#888"))
        fixed = before_map.get(f["id"]) == "fail" and f["status"] == "pass"
        fixed_badge = _badge("✔ corregido", "#0ea5e9") if fixed else ""
        detail = f.get("detail") or ""
        if f["status"] == "fail" and f.get("expected"):
            detail = (detail + f"  ·  esperado: {f['expected']}").strip()
        ai_block = ""
        if f.get("ai"):
            ai_block = f'<div class="ai">🤖 {_html.escape(f["ai"])}</div>'
        rows.append(f"""
        <tr class="st-{f['status']}">
          <td>{_badge(st_label, st_color)}</td>
          <td>{_badge(sev_label, sev_color, dark_text=(f['severity'] in ('MEDIUM',)))}</td>
          <td class="title">{_html.escape(f['title'])} {fixed_badge}</td>
          <td class="detail">{_html.escape(detail)}{ai_block}</td>
        </tr>""")

    return _PAGE.format(
        system=_html.escape(system),
        generated=_html.escape(generated),
        gauges=gauges,
        chips=chips,
        rows="".join(rows),
        year=datetime.now().year,
    )


_PAGE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hardenix · Informe de seguridad</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:#0b1220; color:#e2e8f0;
         font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:980px; margin:0 auto; padding:32px 20px 64px; }}
  header {{ display:flex; align-items:center; gap:12px; margin-bottom:4px; }}
  header .logo {{ font-size:30px; }}
  header h1 {{ font-size:24px; margin:0; letter-spacing:.5px; }}
  header h1 span {{ color:#38bdf8; }}
  .meta {{ color:#64748b; font-size:13px; margin-bottom:28px; }}
  .scoreboard {{ display:flex; align-items:center; justify-content:center; gap:28px;
                 background:#0f172a; border:1px solid #1e293b; border-radius:16px;
                 padding:28px; margin-bottom:18px; }}
  .gauge {{ text-align:center; }}
  .g-score {{ font-size:34px; font-weight:700; }}
  .g-sub {{ font-size:13px; fill:#64748b; }}
  .g-label {{ font-size:12px; letter-spacing:2px; color:#94a3b8; margin-top:4px; }}
  .arrow {{ font-size:34px; color:#475569; text-align:center; }}
  .arrow .delta {{ font-size:16px; color:#22c55e; font-weight:700; }}
  .chips {{ text-align:center; margin-bottom:26px; }}
  .badge {{ display:inline-block; padding:3px 10px; border-radius:999px;
            font-size:12px; font-weight:600; margin:2px; }}
  table {{ width:100%; border-collapse:collapse; background:#0f172a;
           border:1px solid #1e293b; border-radius:14px; overflow:hidden; }}
  th, td {{ padding:11px 14px; text-align:left; font-size:14px;
            border-bottom:1px solid #1e293b; vertical-align:top; }}
  th {{ background:#111c30; color:#94a3b8; font-size:12px; text-transform:uppercase;
        letter-spacing:1px; }}
  tr:last-child td {{ border-bottom:none; }}
  td.title {{ font-weight:600; }}
  td.detail {{ color:#94a3b8; font-size:13px; }}
  .ai {{ margin-top:8px; padding:8px 12px; background:#0b1a2e; border-left:3px solid #38bdf8;
         border-radius:6px; color:#cbd5e1; font-size:13px; line-height:1.5; }}
  tr.st-pass td.title {{ color:#cbd5e1; font-weight:500; }}
  tr.st-fail {{ background:rgba(239,68,68,.05); }}
  footer {{ text-align:center; color:#475569; font-size:12px; margin-top:28px; }}
  footer a {{ color:#38bdf8; text-decoration:none; }}
</style>
</head>
<body>
  <div class="wrap">
    <header>
      <div class="logo">🛡️</div>
      <h1>Harden<span>ix</span></h1>
    </header>
    <div class="meta">Sistema: {system} · Generado: {generated}</div>

    <div class="scoreboard">{gauges}</div>
    <div class="chips">{chips}</div>

    <table>
      <thead><tr><th>Estado</th><th>Severidad</th><th>Comprobación</th><th>Detalle</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>

    <footer>Generado por <a href="#">Hardenix</a> · auditor de endurecimiento Linux · {year}</footer>
  </div>
</body>
</html>
"""

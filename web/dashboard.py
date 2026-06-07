"""Página del dashboard web (HTML + CSS + JS vanilla, autocontenida)."""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hardenix · Dashboard</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; background:#0b1220; color:#e2e8f0;
         font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
  .wrap { max-width:1040px; margin:0 auto; padding:28px 20px 64px; }
  header { display:flex; align-items:center; gap:12px; margin-bottom:20px; }
  header .logo { font-size:30px; }
  header h1 { font-size:23px; margin:0; }
  header h1 span { color:#38bdf8; }
  header .sys { color:#64748b; font-size:13px; margin-left:6px; }
  button { margin-left:auto; background:#0ea5e9; color:#fff; border:none; cursor:pointer;
           padding:10px 18px; border-radius:10px; font-size:14px; font-weight:600; }
  button:disabled { opacity:.6; cursor:default; }
  .grid { display:grid; grid-template-columns:300px 1fr; gap:16px; margin-bottom:16px; }
  .card { background:#0f172a; border:1px solid #1e293b; border-radius:16px; padding:20px; }
  .card h2 { font-size:12px; text-transform:uppercase; letter-spacing:1px; color:#94a3b8;
             margin:0 0 14px; }
  .ring { width:170px; height:170px; border-radius:50%; margin:0 auto;
          display:flex; align-items:center; justify-content:center;
          background:conic-gradient(#334155 0deg, #1e293b 0deg); }
  .ring .inner { width:130px; height:130px; border-radius:50%; background:#0f172a;
                 display:flex; flex-direction:column; align-items:center; justify-content:center; }
  .ring .num { font-size:40px; font-weight:700; line-height:1; }
  .ring .sub { font-size:12px; color:#64748b; }
  .chips { text-align:center; margin-top:16px; }
  .badge { display:inline-block; padding:3px 10px; border-radius:999px;
           font-size:12px; font-weight:600; margin:2px; }
  svg { width:100%; height:160px; }
  table { width:100%; border-collapse:collapse; }
  th,td { padding:9px 12px; text-align:left; font-size:13.5px; border-bottom:1px solid #1e293b;
          vertical-align:top; }
  th { color:#94a3b8; font-size:11px; text-transform:uppercase; letter-spacing:1px; }
  tr:last-child td { border-bottom:none; }
  td.title { font-weight:600; }
  td.detail { color:#94a3b8; font-size:12.5px; }
  tr.st-fail { background:rgba(239,68,68,.05); }
  .muted { color:#64748b; font-size:13px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="logo">🛡️</div>
    <h1>Harden<span>ix</span> · Dashboard</h1>
    <span class="sys" id="sys"></span>
    <button id="run">Ejecutar auditoría</button>
  </header>

  <div class="grid">
    <div class="card">
      <h2>Puntuación</h2>
      <div class="ring" id="ring"><div class="inner">
        <div class="num" id="score">—</div><div class="sub">/ 100</div>
      </div></div>
      <div class="chips" id="chips"></div>
    </div>
    <div class="card">
      <h2>Evolución</h2>
      <svg id="trend" viewBox="0 0 600 160" preserveAspectRatio="none"></svg>
      <div class="muted" id="trendinfo"></div>
    </div>
  </div>

  <div class="card">
    <h2>Hallazgos</h2>
    <table>
      <thead><tr><th>Estado</th><th>Sev.</th><th>Comprobación</th><th>Detalle</th></tr></thead>
      <tbody id="rows"><tr><td colspan="4" class="muted">Ejecuta una auditoría…</td></tr></tbody>
    </table>
  </div>
</div>

<script>
const SEV = {LOW:["BAJA","#64748b"],MEDIUM:["MEDIA","#eab308"],HIGH:["ALTA","#f97316"],CRITICAL:["CRÍTICA","#ef4444"]};
const ST  = {pass:["OK","#22c55e"],fail:["FALLO","#ef4444"],na:["N/A","#64748b"],error:["ERR","#eab308"]};
const esc = s => (s||"").replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
function scoreColor(s){ return s>=80?"#22c55e":s>=50?"#eab308":"#ef4444"; }
function badge(t,c,dark){ return `<span class="badge" style="background:${c};color:${dark?'#0f172a':'#fff'}">${esc(t)}</span>`; }

function renderScore(data){
  const s = data.score;
  document.getElementById("score").textContent = s;
  const col = scoreColor(s), deg = 360*s/100;
  document.getElementById("ring").style.background =
    `conic-gradient(${col} ${deg}deg, #1e293b ${deg}deg)`;
  document.getElementById("score").style.color = col;
  const c = {pass:0,fail:0,na:0};
  data.findings.forEach(f => c[f.status]=(c[f.status]||0)+1);
  document.getElementById("chips").innerHTML =
    badge(c.pass+" OK","#22c55e")+badge(c.fail+" fallos","#ef4444")+badge((c.na||0)+" n/a","#334155");
  document.getElementById("sys").textContent = (data.system||"") + " · " + (data.generated||"");
}

function renderRows(findings){
  const stR={fail:0,error:1,pass:2,na:3}, svR={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
  const sorted=[...findings].sort((a,b)=>(stR[a.status]-stR[b.status])||(svR[a.severity]-svR[b.severity]));
  document.getElementById("rows").innerHTML = sorted.map(f=>{
    const st=ST[f.status]||["?","#888"], sv=SEV[f.severity]||["?","#888"];
    let d=f.detail||""; if(f.status==="fail"&&f.expected) d=(d+"  ·  esperado: "+f.expected).trim();
    return `<tr class="st-${f.status}">
      <td>${badge(st[0],st[1])}</td>
      <td>${badge(sv[0],sv[1],f.severity==="MEDIUM")}</td>
      <td class="title">${esc(f.title)}</td>
      <td class="detail">${esc(d)}</td></tr>`;
  }).join("");
}

function renderTrend(hist){
  const svg=document.getElementById("trend");
  if(!hist.length){ svg.innerHTML=""; document.getElementById("trendinfo").textContent="Sin historial todavía."; return; }
  const W=600,H=160,pad=14, pts=hist.slice(-30);
  const n=pts.length, dx=n>1?(W-2*pad)/(n-1):0;
  const xy=pts.map((h,i)=>[pad+dx*i, H-pad-(h.score/100)*(H-2*pad)]);
  const line=xy.map(p=>p[0].toFixed(1)+","+p[1].toFixed(1)).join(" ");
  const last=pts[pts.length-1].score, col=scoreColor(last);
  let dots=xy.map(p=>`<circle cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="3" fill="${col}"/>`).join("");
  svg.innerHTML=`<polyline fill="none" stroke="${col}" stroke-width="2" points="${line}"/>${dots}`;
  document.getElementById("trendinfo").textContent=`${n} auditorías · última: ${last}/100`;
}

async function loadTrend(){ const r=await fetch("/api/history"); renderTrend(await r.json()); }

async function runAudit(){
  const btn=document.getElementById("run");
  btn.disabled=true; btn.textContent="Auditando…";
  try{
    const r=await fetch("/api/audit"); const data=await r.json();
    renderScore(data); renderRows(data.findings); await loadTrend();
  }finally{ btn.disabled=false; btn.textContent="Ejecutar auditoría"; }
}

document.getElementById("run").addEventListener("click", runAudit);
runAudit();
</script>
</body>
</html>
"""

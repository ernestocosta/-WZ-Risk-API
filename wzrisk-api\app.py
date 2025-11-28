import os
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field, validator


# =========================
# App
# =========================
app = FastAPI(
    title="WZ-Risk API",
    version="1.8",
    description=(
        "API de classificação de vulnerabilidades com pesos por ENV, "
        "lote (/score/batch) com priorização, atalho compatível (/cve/check) e UI com gráfico e export. "
        "Visão geral (top N por agente) e detalhe por agente com filtros de severidade."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# Enums
# =========================
class Crit(str, Enum):
    baixa = "baixa"
    media = "media"
    alta = "alta"
    critica = "critica"


class Exposure(str, Enum):
    internet = "internet"
    interna = "interna"
    isolada = "isolada"


# =========================
# Pesos / Config via ENV
# =========================
def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except Exception:
        return default


def _env_enum(name: str, enum_cls, default):
    val = os.getenv(name)
    if val is None:
        return default
    try:
        return enum_cls(val)
    except Exception:
        return default


W_CVSS = _env_float("WZ_W_CVSS", 0.50)
W_CRIT = _env_float("WZ_W_CRIT", 0.20)
W_EXPO = _env_float("WZ_W_EXPO", 0.15)
W_RECENCY = _env_float("WZ_W_RECENCY", 0.10)
B_EXPLOIT = _env_float("WZ_B_EXPLOIT", 0.15)
B_ACTIVE = _env_float("WZ_B_ACTIVE", 0.25)

DEFAULT_CRIT = _env_enum("WZ_DEFAULT_CRIT", Crit, Crit.media)
DEFAULT_EXPO = _env_enum("WZ_DEFAULT_EXPO", Exposure, Exposure.interna)


# =========================
# Schemas
# =========================
class FindingIn(BaseModel):
    id: str = Field(..., description="CVE ID ou identificador")
    product: Optional[str] = Field(None, description="Produto/Componente")
    host: Optional[str] = Field(None, description="Hostname/Asset")
    agent: Optional[str] = Field(None, description="Nome do agente (ex.: Wazuh Agent)")
    cvss: float = Field(..., ge=0, le=10, description="CVSS base 0..10")
    published: datetime = Field(..., description="Data de publicação (ISO8601)")
    summary: Optional[str] = Field("", description="Resumo")
    asset_criticality: Optional[Crit] = Field(
        None, description="Criticidade do ativo (se ausente, usa padrão do ENV)"
    )
    has_known_exploit: bool = Field(False, description="Existe exploit conhecido?")
    is_actively_exploited: bool = Field(False, description="Exploração ativa?")
    exposure: Optional[Exposure] = Field(
        None, description="Exposição do ativo (se ausente, usa padrão do ENV)"
    )
    years: Optional[float] = Field(
        None, description="Anos desde publicação. Se vazio, a API calcula."
    )

    @validator("published")
    def force_tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class FindingOut(FindingIn):
    asset_criticality: Optional[Crit]
    exposure: Optional[Exposure]
    risk_score: float
    risk_level: str
    explanation: str
    work_order: Optional[int] = Field(None, description="Ordem global")


# =========================
# Modelo de risco
# =========================
CRIT_WEIGHTS = {
    Crit.baixa: 0.2,
    Crit.media: 0.5,
    Crit.alta: 0.8,
    Crit.critica: 1.0,
}

EXPO_WEIGHTS = {
    Exposure.isolada: 0.2,
    Exposure.interna: 0.6,
    Exposure.internet: 1.0,
}


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def years_since(pub: datetime) -> float:
    now = datetime.now(timezone.utc)
    delta = now - pub
    return delta.days / 365.25


def calc_score(data: FindingIn):
    asset_crit = data.asset_criticality or DEFAULT_CRIT
    exposure = data.exposure or DEFAULT_EXPO

    cvss_n = clamp(data.cvss / 10.0)
    crit_w = CRIT_WEIGHTS[asset_crit]
    expo_w = EXPO_WEIGHTS[exposure]

    yrs = years_since(data.published) if data.years is None else max(0.0, data.years)
    recency_factor = clamp(1.0 - clamp(yrs / 10.0))

    if yrs <= 1:
        recency_msg = f"A vulnerabilidade é muito recente (~{yrs:.2f} ano)."
    elif yrs <= 3:
        recency_msg = f"Publicada há {yrs:.2f} anos (ainda recente)."
    elif yrs <= 10:
        recency_msg = f"Publicada há {yrs:.2f} anos (perde peso com a idade)."
    else:
        recency_msg = f"Antiga (~{yrs:.2f} anos), impacto por recência é baixo."

    base = (
        W_CVSS * cvss_n
        + W_CRIT * crit_w
        + W_EXPO * expo_w
        + W_RECENCY * recency_factor
    )
    if data.has_known_exploit:
        base += B_EXPLOIT
    if data.is_actively_exploited:
        base += B_ACTIVE

    score = clamp(base) * 100.0

    if score >= 90:
        level = "CRITICAL"
    elif score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    expl = []
    expl.append(f"CVSS informado: {data.cvss:.1f} (peso {W_CVSS:.2f}).")
    expl.append(f"Criticidade do ativo: {asset_crit.value} (fator {crit_w:.2f}, peso {W_CRIT:.2f}).")
    expl.append(f"Exposição: {exposure.value} (fator {expo_w:.2f}, peso {W_EXPO:.2f}).")
    expl.append(f"Recência: {recency_msg} (peso {W_RECENCY:.2f}).")
    if data.has_known_exploit:
        expl.append(f"Há exploit conhecido (+{int(B_EXPLOIT*100)} pontos base).")
    if data.is_actively_exploited:
        expl.append(f"Exploração ativa em campo (+{int(B_ACTIVE*100)} pontos base).")
    expl.append(f"Score final: {score:.2f} → nível {level}.")

    return score, level, " ".join(expl), asset_crit, exposure


# =========================
# Endpoints
# =========================
@app.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse(url="/ui")


@app.get("/health")
def health():
    return {"status": "ok", "ts": datetime.now(timezone.utc).isoformat()}


@app.get("/config")
def config():
    return {
        "DEFAULT_CRIT": DEFAULT_CRIT.value,
        "DEFAULT_EXPO": DEFAULT_EXPO.value,
        "W_CVSS": W_CVSS,
        "W_CRIT": W_CRIT,
        "W_EXPO": W_EXPO,
        "W_RECENCY": W_RECENCY,
        "B_EXPLOIT": B_EXPLOIT,
        "B_ACTIVE": B_ACTIVE,
    }


@app.post("/score", response_model=FindingOut, tags=["core"])
def score_endpoint(inp: FindingIn):
    s, lvl, expl, crit_res, expo_res = calc_score(inp)
    base = inp.dict(exclude={"asset_criticality", "exposure"})
    return FindingOut(
        **base,
        asset_criticality=crit_res,
        exposure=expo_res,
        risk_score=round(s, 2),
        risk_level=lvl,
        explanation=expl,
    )


class BatchIn(BaseModel):
    items: List[FindingIn] = Field(..., description="Lista de achados")


@app.post("/score/batch", response_model=List[FindingOut], tags=["core"])
def score_batch(payload: BatchIn):
    ranked = []
    for idx, item in enumerate(payload.items):
        s, lvl, expl, crit_res, expo_res = calc_score(item)
        level_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[lvl]
        expo_w = EXPO_WEIGHTS[expo_res]
        crit_w = CRIT_WEIGHTS[crit_res]
        active = 1 if item.is_actively_exploited else 0
        known = 1 if item.has_known_exploit else 0

        res = FindingOut(
            **item.dict(exclude={"asset_criticality", "exposure"}),
            asset_criticality=crit_res,
            exposure=expo_res,
            risk_score=round(s, 2),
            risk_level=lvl,
            explanation=expl,
        )
        ranked.append((level_rank, -s, -active, -known, -expo_w, -crit_w, idx, res))

    ranked.sort(key=lambda t: (t[0], t[1], t[2], t[3], t[4], t[5], t[6]))
    ordered = [t[-1] for t in ranked]
    for i, obj in enumerate(ordered, start=1):
        obj.work_order = i
    return ordered


class CVECheckIn(BaseModel):
    id: str
    cvss: float = Field(..., ge=0, le=10)
    published: datetime
    summary: Optional[str] = ""
    product: Optional[str] = None
    host: Optional[str] = None
    agent: Optional[str] = None
    has_known_exploit: bool = False
    is_actively_exploited: bool = False
    asset_criticality: Optional[Crit] = None
    exposure: Optional[Exposure] = None
    years: Optional[float] = None

    @validator("published")
    def force_tz2(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


@app.post("/cve/check", response_model=FindingOut, tags=["compat"])
def cve_check_endpoint(inp: CVECheckIn):
    as_finding = FindingIn(**inp.dict())
    s, lvl, expl, crit_res, expo_res = calc_score(as_finding)
    base = as_finding.dict(exclude={"asset_criticality", "exposure"})
    return FindingOut(
        **base,
        asset_criticality=crit_res,
        exposure=expo_res,
        risk_score=round(s, 2),
        risk_level=lvl,
        explanation=expl,
    )


# =========================
# UI (HTML) — abas, visão geral e detalhe por agente
# =========================
HTML = """
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8" />
  <title>WZ-Risk — Classificador</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; }
    body { margin: 24px; color: #111; max-width: 1200px; }
    h1 { font-size: 22px; margin: 0 0 12px; }
    .muted { color: #666; font-size: 12px; }
    input, select, textarea { padding:8px; border:1px solid #ddd; border-radius:6px; width:100%; }
    textarea { min-height: 180px; font-family: monospace; }
    button { padding:8px 12px; border:0; border-radius:6px; background:#2563eb; color:#fff; cursor:pointer; }
    button:hover { background:#1d4ed8; }
    .btn-row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .card { border:1px solid #eee; border-radius:8px; padding:14px; margin-top:14px; background:#fff; }
    .error { background:#fee2e2; color:#7f1d1d; border:1px solid #fecaca; padding:10px; border-radius:8px; margin-top:8px; }
    table { width:100%; border-collapse: collapse; margin-top:10px; }
    th, td { padding:8px 10px; border-bottom:1px solid #eee; text-align:left; vertical-align:middle; }
    th { background:#fafafa; font-size:12px; color:#444; }
    .badge { padding:2px 8px; border-radius:999px; color:#fff; font-size:12px; }
    .b-crit{background:#dc2626}.b-high{background:#ea580c}.b-med{background:#d97706}.b-low{background:#059669}
    .bar { height: 10px; background:#eee; border-radius:999px; overflow:hidden; min-width:160px; }
    .fill { height:100%; border-radius:999px; background: linear-gradient(90deg,#60a5fa,#2563eb); }
    .canvas-wrap { border:1px solid #eee; border-radius:8px; padding:10px; margin-top:10px; background:#fff; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
    .tabs { display:flex; gap:8px; margin-top:8px; }
    .tab { padding:8px 12px; border-radius:8px; border:1px solid #ddd; cursor:pointer; }
    .tab.active { background:#2563eb; color:#fff; border-color:#2563eb; }
    .controls { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin: 8px 0 12px; }
    .grid { display: grid; grid-template-columns: 1fr; gap: 16px; }
  </style>
</head>
<body>
  <h1>WZ-Risk — Classificador</h1>
  <p class="muted">Cole uma lista JSON ou carregue um arquivo. O resultado sai na tabela e no(s) gráfico(s) (PNG).</p>

  <div class="card"><div id="cfg" class="muted">Carregando config...</div></div>

  <div class="card">
    <div class="btn-row" style="margin-bottom:8px;">
      <input type="file" id="file" accept="application/json" />
      <button id="load-file">Carregar arquivo</button>
      <button id="btn-batch">Classificar Lote</button>
      <button id="export-csv">Exportar CSV</button>
      <button id="export-json">Exportar JSON</button>
    </div>

    <textarea id="batch-input">{
  "items": [
    {
      "id": "CVE-2024-0001",
      "product": "Windows",
      "host": "SERVER-2016",
      "agent": "agent-win-01",
      "cvss": 9.8,
      "published": "2024-01-10T00:00:00Z",
      "asset_criticality": "alta",
      "exposure": "internet",
      "has_known_exploit": true,
      "is_actively_exploited": true
    },
    {
      "id": "CVE-2023-1000",
      "product": "Ubuntu 24.04",
      "host": "UBUNTU-2404",
      "agent": "agent-ubu-01",
      "cvss": 7.4,
      "published": "2023-05-01T00:00:00Z",
      "asset_criticality": "media",
      "exposure": "interna",
      "has_known_exploit": false,
      "is_actively_exploited": false
    },
    {
      "id": "CVE-2022-7777",
      "product": "Fedora 42",
      "host": "FEDORA-42",
      "agent": "agent-fed-01",
      "cvss": 6.1,
      "published": "2022-06-01T00:00:00Z",
      "asset_criticality": "baixa",
      "exposure": "interna",
      "has_known_exploit": false,
      "is_actively_exploited": false
    },
    {
      "id": "CVE-2020-9999",
      "product": "Windows Server 2016",
      "host": "SERVER-2016",
      "agent": "agent-win-01",
      "cvss": 5.0,
      "published": "2020-06-01T00:00:00Z",
      "asset_criticality": "baixa",
      "exposure": "isolada",
      "has_known_exploit": false,
      "is_actively_exploited": false
    }
  ]
}</textarea>

    <div id="batch-error"></div>

    <div class="tabs">
      <div class="tab active" data-tab="overview">Visão Geral</div>
      <div class="tab" data-tab="detail">Detalhe por Agente</div>
    </div>

    <!-- OVERVIEW -->
    <div id="overview" style="display:block;">
      <div class="controls">
        <label><b>Top N por agente:</b></label>
        <select id="topN">
          <option>1</option><option selected>3</option><option>5</option><option>10</option>
        </select>
        <button id="download-png-overview">Baixar gráfico (PNG) — primeira grade</button>
      </div>
      <div id="overview-table"></div>
      <div id="overview-charts" class="grid"></div>
    </div>

    <!-- DETAIL -->
    <div id="detail" style="display:none;">
      <div class="controls">
        <label><b>Agente:</b></label>
        <select id="agent-select"></select>
        <label><b>Severidades:</b></label>
        <label><input type="checkbox" class="sev" value="CRITICAL" checked/> CRITICAL</label>
        <label><input type="checkbox" class="sev" value="HIGH" checked/> HIGH</label>
        <label><input type="checkbox" class="sev" value="MEDIUM" checked/> MEDIUM</label>
        <label><input type="checkbox" class="sev" value="LOW" checked/> LOW</label>
        <button id="download-png-detail">Baixar gráfico (PNG) — detalhe</button>
      </div>
      <div id="detail-table"></div>
      <div id="detail-chart" class="grid"></div>
    </div>

  </div>

<script>
(function(){
  var lastBatch = null;

  function setText(el, text){ el.textContent = text; }
  function byId(id){ return document.getElementById(id); }

  // Tabs
  document.querySelectorAll('.tab').forEach(function(t){
    t.addEventListener('click', function(){
      document.querySelectorAll('.tab').forEach(function(o){ o.classList.remove('active'); });
      t.classList.add('active');
      var tab = t.getAttribute('data-tab');
      byId('overview').style.display = (tab==='overview' ? 'block':'none');
      byId('detail').style.display = (tab==='detail' ? 'block':'none');
      if (lastBatch){
        if (tab==='overview') renderOverview(lastBatch);
        else renderDetail(lastBatch);
      }
    });
  });

  // Config
  fetch('/config').then(r=>r.json()).then(function(cfg){
    setText(byId('cfg'),
      'DEFAULT_CRIT=' + cfg.DEFAULT_CRIT +
      ' | DEFAULT_EXPO=' + cfg.DEFAULT_EXPO +
      ' | W_CVSS=' + cfg.W_CVSS.toFixed(2) +
      ' | W_CRIT=' + cfg.W_CRIT.toFixed(2) +
      ' | W_EXPO=' + cfg.W_EXPO.toFixed(2) +
      ' | W_RECENCY=' + cfg.W_RECENCY.toFixed(2) +
      ' | B_EXPLOIT=' + cfg.B_EXPLOIT.toFixed(2) +
      ' | B_ACTIVE=' + cfg.B_ACTIVE.toFixed(2)
    );
  }).catch(()=>setText(byId('cfg'),'Falha ao carregar config.'));

  // Carregar arquivo
  byId('load-file').addEventListener('click', function(){
    var f = byId('file').files[0];
    if (!f){ alert('Escolha um arquivo .json'); return; }
    var reader = new FileReader();
    reader.onload = e => byId('batch-input').value = e.target.result;
    reader.readAsText(f);
  });

  // Classificar lote
  byId('btn-batch').addEventListener('click', function(){
    var err = byId('batch-error'); err.innerHTML = '';
    var payload;
    try {
      payload = JSON.parse(byId('batch-input').value);
      if (!payload.items || !Array.isArray(payload.items)) throw new Error('JSON precisa de {"items":[...]}');
    } catch(e){ err.innerHTML = '<div class="error">'+e.message+'</div>'; return; }

    fetch('/score/batch', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)})
      .then(r => r.ok? r.json(): r.text().then(t=>{throw new Error('HTTP '+r.status+' '+t)}))
      .then(data => { lastBatch = data; renderOverview(data); renderDetail(data); })
      .catch(e => err.innerHTML = '<div class="error">Erro: '+e.message+'</div>');
  });

  // Helpers
  function groupBy(list, key){
    var map={};
    list.forEach(it=>{
      var k = it[key] || '(sem '+key+')';
      (map[k] = map[k] || []).push(it);
    });
    return map;
  }
  function sortByRisk(list){
    return list.slice().sort(function(a,b){
      var la = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}[a.risk_level];
      var lb = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}[b.risk_level];
      if (la!==lb) return la-lb;
      if (a.risk_score !== b.risk_score) return b.risk_score - a.risk_score;
      return 0;
    });
  }

  // ---------- OVERVIEW ----------
  function renderOverview(data){
    var container = byId('overview-charts'); container.innerHTML = '';
    var tableBox = byId('overview-table'); tableBox.innerHTML = '';
    var perAgent = groupBy(data, 'agent');
    var topN = parseInt(byId('topN').value, 10) || 3;

    // tabela geral (mostra topN por agente como lista)
    var html = [];
    html.push('<div class="card"><h3>Visão Geral — Top '+topN+' por agente</h3>');
    html.push('<table><thead><tr><th>Agente</th><th>Ordem</th><th>ID/Asset</th><th>Nível</th><th>Score</th></tr></thead><tbody>');
    Object.keys(perAgent).sort().forEach(function(agent){
      var ordered = sortByRisk(perAgent[agent]).slice(0, topN);
      ordered.forEach(function(it, idx){
        var badge = (it.risk_level==='CRITICAL'?'b-crit':it.risk_level==='HIGH'?'b-high':it.risk_level==='MEDIUM'?'b-med':'b-low');
        html.push('<tr>');
        html.push('<td>'+agent+'</td>');
        html.push('<td>#'+(idx+1)+'</td>');
        html.push('<td class="mono"><b>'+it.id+'</b> — <span class="muted">'+(it.product||'-')+' @ '+(it.host||'-')+'</span></td>');
        html.push('<td><span class="badge '+badge+'">'+it.risk_level+'</span></td>');
        html.push('<td>'+it.risk_score.toFixed(1)+'</td>');
        html.push('</tr>');
      });
    });
    html.push('</tbody></table></div>');
    tableBox.innerHTML = html.join('');

    // gráficos (um por agente com topN)
    Object.keys(perAgent).sort().forEach(function(agent){
      var wrap = document.createElement('div');
      wrap.className = 'canvas-wrap';
      var h = document.createElement('h3');
      h.textContent = 'Agente: '+agent+' — Top '+topN;
      wrap.appendChild(h);

      var canvas = document.createElement('canvas');
      canvas.width = 1000; canvas.height = 380; canvas.style.width='100%';
      wrap.appendChild(canvas);
      container.appendChild(wrap);

      var items = sortByRisk(perAgent[agent]).slice(0, topN);
      drawBars(canvas, items, true);
    });
  }

  byId('topN').addEventListener('change', function(){
    if (lastBatch) renderOverview(lastBatch);
  });

  byId('download-png-overview').addEventListener('click', function(){
    var firstCanvas = byId('overview-charts').querySelector('canvas');
    if (!firstCanvas){ alert('Gere os gráficos primeiro.'); return; }
    var url = firstCanvas.toDataURL('image/png');
    var a = document.createElement('a'); a.href=url; a.download='overview.png'; a.click();
  });

  // ---------- DETAIL ----------
  function renderDetail(data){
    // preencher dropdown de agentes
    var sel = byId('agent-select');
    var agents = Object.keys(groupBy(data,'agent')).sort();
    sel.innerHTML = agents.map(a=>'<option>'+a+'</option>').join('');
    if (!agents.length){ byId('detail-table').innerHTML = ''; byId('detail-chart').innerHTML=''; return; }
    if (!sel.value) sel.value = agents[0];
    renderDetailFor(sel.value);
  }

  function getCheckedSeverities(){
    return Array.from(document.querySelectorAll('.sev'))
      .filter(c=>c.checked)
      .map(c=>c.value);
  }

  function renderDetailFor(agent){
    var sev = getCheckedSeverities();
    var data = lastBatch.filter(it => (it.agent||'(sem agent)') === agent)
                        .filter(it => sev.indexOf(it.risk_level) !== -1);
    data = sortByRisk(data);
    renderDetailTable(agent, data);
    renderDetailChart(data);
  }

  byId('agent-select').addEventListener('change', function(){ if (lastBatch) renderDetailFor(this.value); });
  document.querySelectorAll('.sev').forEach(c => c.addEventListener('change', function(){
    if (lastBatch) renderDetailFor(byId('agent-select').value);
  }));

  function renderDetailTable(agent, data){
    var box = byId('detail-table');
    var html = [];
    html.push('<div class="card"><h3>Detalhe do agente: '+agent+' ('+data.length+' itens)</h3>');
    html.push('<table><thead><tr><th>Ordem</th><th>ID/Asset</th><th>Nível</th><th>Score</th><th>Status</th><th>Exposição</th><th>Criticidade</th></tr></thead><tbody>');
    data.forEach(function(d, i){
      var badge = (d.risk_level==='CRITICAL'?'b-crit':d.risk_level==='HIGH'?'b-high':d.risk_level==='MEDIUM'?'b-med':'b-low');
      html.push('<tr>');
      html.push('<td>#'+(i+1)+'</td>');
      html.push('<td class="mono"><b>'+d.id+'</b><br><span class="muted">'+(d.product||'-')+' @ '+(d.host||'-')+'</span></td>');
      html.push('<td><span class="badge '+badge+'">'+d.risk_level+'</span></td>');
      html.push('<td style="min-width:160px;"><div class="bar"><div class="fill" style="width:'+d.risk_score+'%"></div></div><div class="muted" style="font-size:11px;">'+d.risk_score.toFixed(1)+' / 100</div></td>');
      html.push('<td>'+(d.is_actively_exploited?'ativo':'não')+' / '+(d.has_known_exploit?'exploit':'sem exploit')+'</td>');
      html.push('<td>'+d.exposure+'</td>');
      html.push('<td>'+d.asset_criticality+'</td>');
      html.push('</tr>');
    });
    html.push('</tbody></table></div>');
    box.innerHTML = html.join('');
  }

  function renderDetailChart(list){
    var box = byId('detail-chart'); box.innerHTML = '';
    var wrap = document.createElement('div'); wrap.className='canvas-wrap';
    var h = document.createElement('h3'); h.textContent='Gráfico — detalhe';
    wrap.appendChild(h);
    var canvas = document.createElement('canvas');
    canvas.width = 1000; canvas.height = 380; canvas.style.width='100%';
    wrap.appendChild(canvas);
    box.appendChild(wrap);
    drawBars(canvas, list, false);
  }

  byId('download-png-detail').addEventListener('click', function(){
    var firstCanvas = byId('detail-chart').querySelector('canvas');
    if (!firstCanvas){ alert('Gere o gráfico primeiro.'); return; }
    var url = firstCanvas.toDataURL('image/png');
    var a = document.createElement('a'); a.href=url; a.download='detail.png'; a.click();
  });

  // ---------- DESENHO ----------
  function drawBars(canvas, data, compact){
    var ctx = canvas.getContext('2d');
    var w = Math.min(1200, Math.max(600, data.length * (compact? 120 : 90)));
    canvas.width = w; canvas.height = 380;
    ctx.fillStyle = '#fff'; ctx.fillRect(0,0,w,canvas.height);

    var left = 160, top = 30, bottom = 40;
    var chartW = w - left - 30;
    var chartH = canvas.height - top - bottom;
    var gap = 10;
    var barH = Math.max(12, (chartH - (data.length-1)*gap) / Math.max(1,data.length));

    ctx.font = '12px monospace';
    ctx.fillStyle = '#111';
    ctx.fillText('Score (0-100) — ordem do mais crítico para o menos', 10, 18);

    for (var i=0;i<data.length;i++){
      var it = data[i], y = top + i*(barH + gap);

      ctx.fillStyle = '#eee';
      ctx.fillRect(left, y, chartW, barH);

      var fillW = Math.round((it.risk_score/100)*chartW);
      var grad = ctx.createLinearGradient(left, y, left+fillW, y);
      if      (it.risk_level==='CRITICAL'){ grad.addColorStop(0,'#ff9b9b'); grad.addColorStop(1,'#dc2626'); }
      else if (it.risk_level==='HIGH'    ){ grad.addColorStop(0,'#ffc59d'); grad.addColorStop(1,'#ea580c'); }
      else if (it.risk_level==='MEDIUM'  ){ grad.addColorStop(0,'#ffdca8'); grad.addColorStop(1,'#d97706'); }
      else                                { grad.addColorStop(0,'#aef0d0'); grad.addColorStop(1,'#059669'); }
      ctx.fillStyle = grad;
      ctx.fillRect(left, y, fillW, barH);

      ctx.fillStyle = '#111';
      var label = '#' + (i+1) + ' — ' + it.id + ' (' + it.risk_score.toFixed(1) + ')';
      ctx.fillText(label, 10, y + barH - 2);
    }
  }

  // Export JSON/CSV (dados crus do batch)
  byId('export-json').addEventListener('click', function(){
    if (!lastBatch){ alert('Classifique primeiro.'); return; }
    var blob = new Blob([JSON.stringify(lastBatch, null, 2)], {type:'application/json'});
    var url = URL.createObjectURL(blob); var a=document.createElement('a');
    a.href=url; a.download='wzrisk_batch.json'; a.click(); URL.revokeObjectURL(url);
  });

  byId('export-csv').addEventListener('click', function(){
    if (!lastBatch){ alert('Classifique primeiro.'); return; }
    var header = ['work_order','id','product','host','agent','cvss','published','asset_criticality','exposure','has_known_exploit','is_actively_exploited','risk_score','risk_level'];
    var rows = lastBatch.map(function(it){
      return header.map(function(k){
        var v = it[k]; if (v===null||v===undefined) v=''; return String(v).replace(/"/g,'""');
      }).join(',');
    });
    var csv = header.join(',') + "\\n" + rows.join("\\n");
    var blob = new Blob([csv], {type:'text/csv;charset=utf-8;'});
    var url = URL.createObjectURL(blob); var a=document.createElement('a');
    a.href=url; a.download='wzrisk_batch.csv'; a.click(); URL.revokeObjectURL(url);
  });

})();
</script>
</body>
</html>
"""

@app.get("/ui", response_class=HTMLResponse, tags=["ui"])
def ui():
    return HTML

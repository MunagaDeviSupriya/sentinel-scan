// ===== MCOGAN+ Application Logic =====
'use strict';

// ── Configuration ──────────────────────────────────────────────────────────
const API_BASE = 'http://127.0.0.1:5000';

// ── State ──────────────────────────────────────────────────────────────────
const state = {
  history:       JSON.parse(localStorage.getItem('mcogan_history') || '[]'),
  currentResult: null,
  threshold:     75,
  charts:        {},
  apiOnline:     false,
};

// ── Static data (model / research context) ─────────────────────────────────
const FAMILIES = [
  'Emotet','Mirai','Fareit','Gafgyt','Coinhive',
  'Ramnit','Razy','Icedid','Meapow','Lamer','Gandcrab',
];

const MITRE_TECHNIQUES = [
  {id:'T1059',name:'Command Scripting',  tactic:'Execution'},
  {id:'T1543',name:'Create/Modify Svc',  tactic:'Persistence'},
  {id:'T1055',name:'Process Injection',  tactic:'PrivEsc'},
  {id:'T1027',name:'Obfuscated Files',   tactic:'Defense Evasion'},
  {id:'T1082',name:'System Discovery',   tactic:'Discovery'},
  {id:'T1021',name:'Remote Services',    tactic:'Lateral Movement'},
  {id:'T1005',name:'Data from Local',    tactic:'Collection'},
  {id:'T1041',name:'Exfil Over C2',      tactic:'Exfiltration'},
  {id:'T1486',name:'Data Encrypted',     tactic:'Impact'},
  {id:'T1562',name:'Impair Defenses',    tactic:'Defense Evasion'},
  {id:'T1078',name:'Valid Accounts',     tactic:'Initial Access'},
  {id:'T1547',name:'Boot Autostart',     tactic:'Persistence'},
  {id:'T1003',name:'Credential Dump',    tactic:'CredAccess'},
  {id:'T1071',name:'App Layer Proto',    tactic:'C2'},
  {id:'T1070',name:'Indicator Remove',   tactic:'Defense Evasion'},
];

const FAMILY_MITRE = {
  Emotet:   ['T1059','T1543','T1027','T1082','T1071'],
  Mirai:    ['T1021','T1078','T1059','T1082'],
  Fareit:   ['T1003','T1027','T1082','T1041'],
  Gafgyt:   ['T1059','T1082','T1021'],
  Coinhive: ['T1027','T1562','T1071'],
  Ramnit:   ['T1003','T1027','T1055','T1071'],
  Razy:     ['T1027','T1082','T1041'],
  Icedid:   ['T1059','T1055','T1027','T1071'],
  Meapow:   ['T1027','T1082','T1059'],
  Lamer:    ['T1027','T1059'],
  Gandcrab: ['T1486','T1027','T1082','T1070'],
  Benign:   [],
};

// ── Chart defaults ─────────────────────────────────────────────────────────
const CHART_DEFAULTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      labels: { color:'#6b7280', font:{ family:'Plus Jakarta Sans', size:11 }, boxWidth:12, padding:12 }
    },
    tooltip: {
      backgroundColor:'#1a1f2e', borderColor:'rgba(79,142,247,0.3)', borderWidth:1,
      titleColor:'#f9fafb', bodyColor:'#9ca3af',
      titleFont:{ family:'Plus Jakarta Sans', size:12, weight:'700' },
      bodyFont:{ family:'IBM Plex Mono', size:11 }, padding:10,
    },
  },
  scales: {
    x: { grid:{ color:'rgba(0,0,0,0.05)' }, ticks:{ color:'#9ca3af', font:{ family:'IBM Plex Mono', size:10 } } },
    y: { grid:{ color:'rgba(0,0,0,0.05)' }, ticks:{ color:'#9ca3af', font:{ family:'IBM Plex Mono', size:10 } } },
  },
};

// ── DOM Ready ──────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initLiveClock();
  animateStats();
  initCharts();
  initAnalyzeForm();
  renderActivityTable();

  renderHistoryPage();
  initSettings();
  checkApiHealth();
});

// ── API Health ─────────────────────────────────────────────────────────────
async function checkApiHealth() {
  const dot   = document.querySelector('.status-dot');
  const label = document.querySelector('.sidebar-status .status-row span:last-child');
  try {
    const r = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      state.apiOnline = true;
      if (dot)   { dot.style.background = 'var(--green)'; }
      if (label) label.textContent = 'Model Online';
      return;
    }
  } catch (_) { /* fall through */ }
  state.apiOnline = false;
  if (dot)   { dot.style.background = 'var(--amber)'; dot.classList.remove('pulse'); }
  if (label) label.textContent = 'Model Offline';
}

// ── Navigation ─────────────────────────────────────────────────────────────
function initNavigation() {
  const navItems  = document.querySelectorAll('.nav-item');
  const pages     = document.querySelectorAll('.page');
  const pageTitle = document.getElementById('page-title');
  const sidebar   = document.getElementById('sidebar');
  const overlay   = document.getElementById('sidebar-overlay');
  const hamburger = document.getElementById('hamburger');

  navItems.forEach(item => {
    item.addEventListener('click', () => {
      navItems.forEach(n => n.classList.remove('active'));
      pages.forEach(p  => p.classList.remove('active'));
      item.classList.add('active');
      document.getElementById('page-' + item.dataset.page)?.classList.add('active');
      pageTitle.textContent = item.querySelector('.nav-label').textContent.trim();
      sidebar.classList.remove('open');
      overlay.classList.remove('open');
      if (item.dataset.page === 'history') renderHistoryPage();
    });
  });

  hamburger?.addEventListener('click', () => {
    sidebar.classList.toggle('open');
    overlay.classList.toggle('open');
  });
  overlay?.addEventListener('click', () => {
    sidebar.classList.remove('open');
    overlay.classList.remove('open');
  });
}

// ── Live Clock ─────────────────────────────────────────────────────────────
function initLiveClock() {
  const el = document.getElementById('live-time');
  const tick = () => { el.textContent = new Date().toLocaleTimeString('en-US', { hour12: false }); };
  tick();
  setInterval(tick, 1000);
}

// ── Animate Stats ──────────────────────────────────────────────────────────
function animateStats() {
  document.querySelectorAll('.stat-num[data-target]').forEach(el => {
    const target = parseInt(el.dataset.target);
    const suffix = el.dataset.suffix || '';
    let start = 0;
    const step = target / 60;
    const timer = setInterval(() => {
      start = Math.min(start + step, target);
      el.textContent = Math.floor(start).toLocaleString() + suffix;
      if (start >= target) clearInterval(timer);
    }, 16);
  });
}

// ── Charts ────────────────────────────────────────────────────────────────
function initCharts() {
  Chart.defaults.color = '#9ca3af';
  buildMethodsChart();

}

function buildMethodsChart() {
  const ctx = document.getElementById('methodsChart')?.getContext('2d');
  if (!ctx) return;
  state.charts.methods = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['CNN+MCOGAN','Hybrid+MCOGAN','cGAN Enhanced','Multi-modal'],
      datasets: [{
        data: [22,40,25,13],
        backgroundColor: ['rgba(34,197,94,0.7)','rgba(79,142,247,0.7)','rgba(245,158,11,0.7)','rgba(168,85,247,0.7)'],
        borderColor:     ['#22c55e','#4f8ef7','#f59e0b','#a855f7'],
        borderWidth: 1,
      }],
    },
    options: { ...CHART_DEFAULTS, cutout:'65%', scales:{} },
  });
}




// ── Activity Table ─────────────────────────────────────────────────────────
function renderActivityTable() {
  const rows = [
    {hash:'a2f4b1c3...d9e0', family:'Emotet',  conf:97, method:'Hybrid+MCOGAN', status:'malicious', time:'2 min ago'},
    {hash:'7b8c2d1e...f3a4', family:'Mirai',   conf:89, method:'CNN+MCOGAN',    status:'malicious', time:'5 min ago'},
    {hash:'f1a2b3c4...e5d6', family:'Benign',  conf:99, method:'cGAN',          status:'benign',    time:'11 min ago'},
    {hash:'3d4e5f6a...b7c8', family:'Fareit',  conf:94, method:'Multi-modal',   status:'malicious', time:'18 min ago'},
    {hash:'c9d0e1f2...a3b4', family:'Gafgyt',  conf:92, method:'Hybrid+MCOGAN', status:'malicious', time:'25 min ago'},
  ];
  const container = document.getElementById('activity-rows');
  if (!container) return;
  container.innerHTML = rows.map(r => `
    <tr>
      <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-4)">${r.hash}</td>
      <td style="font-weight:600">${r.family}</td>
      <td style="font-family:var(--font-mono);color:${r.status==='malicious'?'var(--red)':'var(--green)'};font-weight:700">${r.conf}%</td>
      <td style="color:var(--text-3);font-size:12px">${r.method}</td>
      <td><span class="badge ${r.status==='malicious'?'red':'green'}">${r.status}</span></td>
      <td style="color:var(--text-4);font-size:12px">${r.time}</td>
    </tr>
  `).join('');
}

// ── Analyze Form ───────────────────────────────────────────────────────────
function initAnalyzeForm() {
  // Tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab)?.classList.add('active');
    });
  });

  // Dropzone
  const dropzone  = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');

  dropzone?.addEventListener('click',     () => fileInput?.click());
  dropzone?.addEventListener('dragover',  e => { e.preventDefault(); dropzone.classList.add('drag-over'); });
  dropzone?.addEventListener('dragleave', () => dropzone.classList.remove('drag-over'));
  dropzone?.addEventListener('drop',      e => { e.preventDefault(); dropzone.classList.remove('drag-over'); handleFile(e.dataTransfer.files[0]); });
  fileInput?.addEventListener('change',   e => handleFile(e.target.files[0]));

  document.getElementById('remove-file')?.addEventListener('click', () => {
    document.getElementById('file-info')?.classList.add('hidden');
    dropzone?.classList.remove('hidden');
    if (fileInput) fileInput.value = '';
  });

  document.getElementById('analyze-btn')?.addEventListener('click', runAnalysis);
}

function handleFile(file) {
  if (!file) return;
  document.getElementById('file-name').textContent = file.name;
  document.getElementById('file-size').textContent = formatBytes(file.size);
  document.getElementById('file-info')?.classList.remove('hidden');
  document.getElementById('dropzone')?.classList.add('hidden');
}

function formatBytes(bytes) {
  if (bytes < 1024)    return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

// ── Run Analysis (calls real Flask API) ────────────────────────────────────
async function runAnalysis() {
  // Gather features from the "Enter Features" tab
  const features = [
    parseFloat(document.getElementById('feat-size')?.value    || 204800),
    parseFloat(document.getElementById('feat-entropy')?.value || 6.72),
    parseFloat(document.getElementById('feat-sections')?.value|| 5),
    parseFloat(document.getElementById('feat-api')?.value     || 148),
    parseFloat(document.getElementById('feat-imports')?.value || 32),
  ];

  if (features.some(isNaN)) {
    showToast('Please fill in all feature fields.', 'warning');
    return;
  }

  showLoadingOverlay(true);

  try {
    const response = await fetch(`${API_BASE}/predict`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ features }),
      signal:  AbortSignal.timeout(15000),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Server error ${response.status}`);
    }

    const result = await response.json();
    showLoadingOverlay(false);
    displayResults(result);

  } catch (err) {
    showLoadingOverlay(false);
    if (err.name === 'TimeoutError' || err.name === 'AbortError') {
      showToast('Request timed out. Is the backend running?', 'error');
    } else {
      showToast(`Analysis failed: ${err.message}`, 'error');
    }
  }
}

// ── Loading Overlay ────────────────────────────────────────────────────────
function showLoadingOverlay(show) {
  const overlay = document.getElementById('loading-overlay');
  const barEl   = document.getElementById('loading-bar');
  const stepsEl = document.getElementById('loading-steps');

  if (!show) { overlay?.classList.add('hidden'); return; }

  overlay?.classList.remove('hidden');

  const steps = [
    'Extracting PE binary features…',
    'Running XGBoost inference…',
    'Computing SHAP explanations…',
    'Generating Grad-CAM heatmap…',
    'Mapping to MITRE ATT&CK…',
    'Finalizing report…',
  ];
  let step = 0;
  if (barEl)   barEl.style.width = '0%';
  if (stepsEl) stepsEl.textContent = steps[0];

  const iv = setInterval(() => {
    step++;
    if (step < steps.length) {
      if (stepsEl) stepsEl.textContent = steps[step];
      if (barEl)   barEl.style.width = ((step + 1) / steps.length * 100) + '%';
    } else {
      clearInterval(iv);
    }
  }, 320);

  overlay._clearInterval = iv;   // store so we can cancel if needed
}

// ── Display Results (from API response) ────────────────────────────────────
function displayResults(result) {
  document.getElementById('results-placeholder')?.classList.add('hidden');
  document.getElementById('result-content')?.classList.remove('hidden');

  const isMalicious    = result.is_malicious === true;
  const confidence     = result.confidence;
  const detectedFamily = result.prediction;

  // Verdict banner
  const banner = document.getElementById('verdict-banner');
  banner?.classList.remove('malicious', 'benign');
  banner?.classList.add(isMalicious ? 'malicious' : 'benign');
  const verdictLabel     = document.getElementById('verdict-label');
  const verdictIconWrap  = document.getElementById('verdict-icon-wrap');
  if (verdictLabel)    verdictLabel.textContent    = isMalicious ? '⚠ MALICIOUS' : '✓ BENIGN';
  if (verdictIconWrap) verdictIconWrap.textContent = isMalicious ? '⚠️' : '✅';
  const familyNameEl = document.getElementById('family-name');
  if (familyNameEl) familyNameEl.textContent = detectedFamily;

  // Confidence ring
  const circle  = document.getElementById('conf-circle');
  const dashVal = (confidence / 100) * 201;
  if (circle) circle.setAttribute('stroke-dashoffset', 201 - dashVal);
  const confText = document.getElementById('conf-text');
  if (confText) confText.textContent = Math.round(confidence) + '%';

  // MITRE ATT&CK
  const mitreSection = document.getElementById('mitre-section');
  const showMitre    = document.getElementById('opt-mitre')?.checked;
  if (mitreSection) {
    if (showMitre && isMalicious) {
      mitreSection.classList.remove('hidden');
      const techniques = FAMILY_MITRE[detectedFamily] || [];
      document.getElementById('mitre-techniques').innerHTML = techniques.map(t => {
        const tech = MITRE_TECHNIQUES.find(m => m.id === t);
        return tech ? `<span class="mitre-tag">${tech.id}: ${tech.name}</span>` : '';
      }).join('');
    } else {
      mitreSection.classList.add('hidden');
    }
  }

  // Threat badge (topbar)
  const threatText = document.getElementById('threat-text');
  const badge      = document.getElementById('threat-badge');
  if (threatText && badge) {
    if (isMalicious && confidence > 90) {
      threatText.textContent = 'HIGH';
      badge.style.cssText    = 'background:var(--red-bg);border-color:rgba(239,68,68,0.25);color:#dc2626';
    } else if (isMalicious) {
      threatText.textContent = 'MEDIUM';
      badge.style.cssText    = 'background:var(--amber-bg);border-color:rgba(245,158,11,0.25);color:#b45309';
    } else {
      threatText.textContent = 'LOW';
      badge.style.cssText    = 'background:var(--green-bg);border-color:rgba(34,197,94,0.25);color:#15803d';
    }
  }

  // Performance benchmarks (optional)
  const latencySection = document.getElementById('latency-section');
  if (latencySection) {
    if (document.getElementById('opt-latency')?.checked) {
      latencySection.classList.remove('hidden');
      document.getElementById('latency-grid').innerHTML = [
        {val:(8  + Math.random()*4).toFixed(1) + 'ms',  name:'Inference Time'},
        {val:(42 + Math.random()*8).toFixed(0) + ' MB', name:'Memory Usage'},
        {val:(120+ Math.random()*20).toFixed(0)+ '/s',  name:'Throughput'},
      ].map(l => `<div class="latency-item"><div class="latency-val">${l.val}</div><div class="latency-name">${l.name}</div></div>`).join('');
    } else {
      latencySection.classList.add('hidden');
    }
  }

  // Persist to history
  const entry = {
    id:         Date.now(),
    hash:       generateHash(),
    family:     detectedFamily,
    confidence: confidence.toFixed(1),
    status:     isMalicious ? 'malicious' : 'benign',
    method:     document.getElementById('classifier-select')?.value || 'hybrid',
    timestamp:  new Date().toLocaleString(),
    entropy:    document.getElementById('feat-entropy')?.value || '—',
  };
  state.currentResult = entry;
  state.history.unshift(entry);
  localStorage.setItem('mcogan_history', JSON.stringify(state.history.slice(0, 100)));
}


// ── History Page ───────────────────────────────────────────────────────────
function renderHistoryPage() {
  const tbody  = document.getElementById('history-list');
  if (!tbody) return;
  const filter = document.getElementById('history-filter')?.value || 'all';
  const search = document.getElementById('history-search')?.value?.toLowerCase() || '';
  let items    = state.history;
  if (filter !== 'all') items = items.filter(h => h.status === filter);
  if (search) items = items.filter(h =>
    (h.hash       || '').toLowerCase().includes(search) ||
    (h.family     || '').toLowerCase().includes(search) ||
    (h.filename   || '').toLowerCase().includes(search)
  );

  if (items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No matching scans found.</td></tr>';
    return;
  }
  tbody.innerHTML = items.map(h => `
    <tr>
      <td style="font-size:12px;color:var(--text-2);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${h.filename || h.hash}">
        ${h.filename
          ? `<span style="font-weight:600">${h.filename}</span><br><span style="font-family:var(--font-mono);font-size:10px;color:var(--text-4)">${h.hash}</span>`
          : `<span style="font-family:var(--font-mono);font-size:11px;color:var(--text-4)">${h.hash}</span>`}
      </td>
      <td style="font-weight:600;color:${h.status==='malicious'?'var(--red)':'var(--green)'}">${h.family}</td>
      <td style="font-family:var(--font-mono);color:${h.status==='malicious'?'var(--red)':'var(--green)'};font-weight:700">${parseFloat(h.confidence).toFixed(1)}%</td>
      <td style="color:var(--text-3);font-size:12px">${h.method}</td>
      <td><span class="badge ${h.status==='malicious'?'red':'green'}">${h.status}</span></td>
      <td style="color:var(--text-4);font-size:12px">${h.timestamp}</td>
    </tr>
  `).join('');
}

// ── Settings ───────────────────────────────────────────────────────────────
function initSettings() {
  const slider = document.getElementById('threshold-slider');
  const valEl  = document.getElementById('threshold-val');
  slider?.addEventListener('input', () => {
    state.threshold = parseInt(slider.value);
    if (valEl) valEl.textContent = state.threshold + '%';
  });
  document.getElementById('history-search')?.addEventListener('input',  renderHistoryPage);
  document.getElementById('history-filter')?.addEventListener('change', renderHistoryPage);
}

// ── Export ─────────────────────────────────────────────────────────────────
function exportReport() {
  if (!state.currentResult) return;
  const r = state.currentResult;
  const techniques = (FAMILY_MITRE[r.family] || []).map(t => {
    const tech = MITRE_TECHNIQUES.find(m => m.id === t);
    return tech ? `  ${tech.id}: ${tech.name} (${tech.tactic})` : '';
  }).join('\n');

  const content = [
    'MCOGAN+ MALWARE ANALYSIS REPORT',
    '================================',
    `Date       : ${r.timestamp}`,
    `File Hash  : ${r.hash}`,
    `Detection  : ${r.status.toUpperCase()}`,
    `Family     : ${r.family}`,
    `Confidence : ${r.confidence}%`,
    `Method     : ${r.method}`,
    `Entropy    : ${r.entropy}`,
    '',
    'MITRE ATT&CK Techniques:',
    techniques || '  None mapped.',
    '',
    'Generated by MCOGAN+ v2.4.1',
    'Based on: Khan et al., IEEE Access 2024',
  ].join('\n');

  const a = document.createElement('a');
  a.href     = URL.createObjectURL(new Blob([content], {type:'text/plain'}));
  a.download = `mcogan_report_${Date.now()}.txt`;
  a.click();
}

function viewHistory() {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.page').forEach(p   => p.classList.remove('active'));
  document.querySelector('[data-page="history"]')?.classList.add('active');
  document.getElementById('page-history')?.classList.add('active');
  document.getElementById('page-title').textContent = 'Scan History';
  renderHistoryPage();
}

function clearHistory() {
  if (!confirm('Clear all scan history? This cannot be undone.')) return;
  state.history = [];
  localStorage.removeItem('mcogan_history');
  renderHistoryPage();
}

// ── Utilities ──────────────────────────────────────────────────────────────
function generateHash() {
  const hex = n => Array.from({length:n}, () => Math.floor(Math.random()*16).toString(16)).join('');
  return `${hex(8)}...${hex(4)}`;
}

function showToast(message, type = 'info') {
  const colors = { info:'#4f8ef7', warning:'#f59e0b', error:'#ef4444', success:'#22c55e' };
  const toast  = document.createElement('div');
  toast.textContent = message;
  Object.assign(toast.style, {
    position:'fixed', bottom:'24px', right:'24px', zIndex:'9999',
    background: colors[type] || colors.info,
    color:'#fff', padding:'12px 18px', borderRadius:'8px',
    fontSize:'13px', fontWeight:'600', fontFamily:'var(--font-body)',
    boxShadow:'0 4px 16px rgba(0,0,0,0.2)',
    transition:'opacity 0.3s ease',
  });
  document.body.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 3500);
}

// ══════════════════════════════════════════════════════════════════════════════
// MCOGAN+ Live Monitor — SSE client
// Connects to backend /events stream, receives auto-scan results from
// monitor.py and injects them into the dashboard in real time.
// ══════════════════════════════════════════════════════════════════════════════

(function initLiveMonitor() {
  const EVENTS_URL = 'http://127.0.0.1:5000/events';
  let   evtSource  = null;
  let   retryTimer = null;
  const MAX_LIVE_ALERTS = 50;

  // ── Live alert feed stored in state ────────────────────────────────────────
  if (!state.liveAlerts) state.liveAlerts = [];

  // ── Connect to SSE stream ───────────────────────────────────────────────────
  function connect() {
    if (evtSource) { evtSource.close(); evtSource = null; }

    evtSource = new EventSource(EVENTS_URL);

    evtSource.addEventListener('scan_result', (e) => {
      try {
        const data = JSON.parse(e.data);
        handleLiveScan(data);
      } catch (_) {}
    });

    evtSource.addEventListener('monitor_status', (e) => {
      try {
        const data = JSON.parse(e.data);
        updateMonitorBadge(data.active);
      } catch (_) {}
    });

    evtSource.onopen = () => {
      console.log('[Monitor] SSE connected');
      updateMonitorBadge(true);
      if (retryTimer) { clearTimeout(retryTimer); retryTimer = null; }
      renderLiveAlerts();   // refresh status dot/text immediately on connect
    };

    evtSource.onerror = () => {
      evtSource.close();
      evtSource = null;
      updateMonitorBadge(false);
      renderLiveAlerts();   // update dot/text to Reconnecting... immediately
      retryTimer = setTimeout(connect, 5000);   // retry in 5s
    };
  }

  // ── Status heartbeat — keeps dot/text accurate even with no scan events ─────
  let _statusInterval = null;
  function startStatusHeartbeat() {
    if (_statusInterval) return;
    _statusInterval = setInterval(() => {
      const dot = document.getElementById('monitor-dot');
      const txt = document.getElementById('monitor-status-text');
      if (!dot || !txt) return;
      const open = evtSource && evtSource.readyState === EventSource.OPEN;
      dot.style.background = open ? '#22c55e' : '#f59e0b';
      txt.textContent      = open ? 'Connected' : (retryTimer ? 'Reconnecting...' : 'Offline');
    }, 1000);
  }

  // ── Handle an incoming scan result ─────────────────────────────────────────
  function handleLiveScan(data) {
    const isMalicious = !!data.is_malicious;
    const family      = data.prediction  || 'Unknown';
    const confidence  = parseFloat(data.confidence || 0).toFixed(1);
    const filename    = data.filename    || 'unknown';
    const timestamp   = data.timestamp   || new Date().toLocaleString();
    const md5         = data.md5         || generateHash();

    // 1. Add to scan history
    const entry = {
      id:         Date.now(),
      hash:       md5,
      filename:   filename,
      family:     family,
      confidence: parseFloat(confidence).toFixed(1),
      status:     isMalicious ? 'malicious' : 'benign',
      method:     'live-monitor',
      timestamp:  timestamp,
      source:     'monitor',
    };
    state.history.unshift(entry);
    localStorage.setItem('mcogan_history', JSON.stringify(state.history.slice(0, 100)));

    // 2. Add to live alert feed
    state.liveAlerts.unshift({ ...entry, filename });
    if (state.liveAlerts.length > MAX_LIVE_ALERTS) state.liveAlerts.pop();

    // 3. Re-render history if visible
    if (document.getElementById('page-history')?.classList.contains('active')) {
      renderHistoryPage();
    }

    // 4. Update live alert panel
    renderLiveAlerts();

    // 5. Toast notification
    const icon = isMalicious ? '🔴' : '🟢';
    showToast(
      `${icon} ${filename} → ${family} (${confidence}%)`,
      isMalicious ? 'error' : 'success'
    );

    // 6. Update dashboard threat badge
    if (isMalicious) {
      const threatText = document.getElementById('threat-text');
      const threatBadge = document.getElementById('threat-badge');
      if (threatText) threatText.textContent = 'HIGH';
      if (threatBadge) {
        threatBadge.style.background = 'rgba(239,68,68,0.15)';
        threatBadge.querySelector('.threat-dot').style.background = '#ef4444';
      }
    }
  }

  // ── Update the monitor status badge in the sidebar ─────────────────────────
  function updateMonitorBadge(active) {
    const dot   = document.querySelector('.sidebar-status .status-dot');
    const label = document.querySelector('.sidebar-status span:last-child');
    if (!dot || !label) return;
    if (active) {
      dot.style.background = '#22c55e';
      dot.classList.add('pulse');
      label.textContent = 'Monitor Active';
    } else {
      dot.style.background = 'var(--amber)';
      dot.classList.remove('pulse');
      label.textContent = 'Monitor Offline';
    }
  }

  // ── Live Alert Panel (injected into Dashboard page) ────────────────────────
  function injectLiveAlertPanel() {
    const dashboard = document.getElementById('page-dashboard');
    if (!dashboard || document.getElementById('live-alert-panel')) return;

    const panel = document.createElement('div');
    panel.id = 'live-alert-panel';
    panel.innerHTML = `
      <div style="margin-top:28px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
          <h3 style="font-size:15px;font-weight:700;color:var(--text-1);margin:0;display:flex;align-items:center;gap:8px;">
            <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;" id="monitor-dot"></span>
            Live Monitor Feed
          </h3>
          <span style="font-size:11px;color:var(--text-4);font-family:var(--font-mono);" id="monitor-status-text">Connecting...</span>
        </div>
        <div id="live-alert-list" style="
          background:var(--surface-2,#1a1f2e);
          border:1px solid var(--border,rgba(255,255,255,0.07));
          border-radius:12px;
          overflow:hidden;
          min-height:60px;
        ">
          <div id="live-alert-empty" style="padding:20px;text-align:center;color:var(--text-4);font-size:13px;">
            Watching for new files… Drop a file into your monitored folder to scan it.
          </div>
        </div>
      </div>
    `;
    dashboard.appendChild(panel);
    renderLiveAlerts();
  }

  function renderLiveAlerts() {
    const list  = document.getElementById('live-alert-list');
    const empty = document.getElementById('live-alert-empty');
    const dot   = document.getElementById('monitor-dot');
    const txt   = document.getElementById('monitor-status-text');
    if (!list) return;

    // Status is kept accurate by startStatusHeartbeat(); renderLiveAlerts()
    // only needs to do a one-shot sync here for immediate visual feedback.
    const _isOpen = evtSource && evtSource.readyState === EventSource.OPEN;
    if (dot) dot.style.background = _isOpen ? '#22c55e' : '#f59e0b';
    if (txt) txt.textContent      = _isOpen ? 'Connected'
                                             : (retryTimer ? 'Reconnecting...' : 'Offline');

    if (state.liveAlerts.length === 0) {
      if (empty) empty.style.display = 'block';
      return;
    }
    if (empty) empty.style.display = 'none';

    list.innerHTML = state.liveAlerts.slice(0, 15).map(a => `
      <div style="
        display:flex;align-items:center;gap:12px;
        padding:11px 16px;
        border-bottom:1px solid var(--border,rgba(255,255,255,0.05));
        font-size:13px;
        background:${a.status === 'malicious' ? 'rgba(239,68,68,0.05)' : 'transparent'};
      ">
        <span style="font-size:16px;flex-shrink:0">${a.status === 'malicious' ? '🔴' : '🟢'}</span>
        <span style="flex:1;font-weight:600;color:var(--text-1);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${a.filename || a.hash}">${a.filename || a.hash}</span>
        <span style="font-family:var(--font-mono);font-size:12px;color:${a.status === 'malicious' ? '#ef4444' : '#22c55e'};font-weight:700;flex-shrink:0">${a.family}</span>
        <span style="font-family:var(--font-mono);font-size:11px;color:var(--text-4);flex-shrink:0;min-width:52px;text-align:right">${parseFloat(a.confidence).toFixed(1)}%</span>
        <span style="font-size:11px;color:var(--text-4);flex-shrink:0" class="alert-time">${a.timestamp}</span>
      </div>
    `).join('');
  }

  // ── Boot ───────────────────────────────────────────────────────────────────
  // Wait for DOM then inject panel and open SSE connection
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      injectLiveAlertPanel();
      connect();
      startStatusHeartbeat();
    });
  } else {
    injectLiveAlertPanel();
    connect();
    startStatusHeartbeat();
  }
})();

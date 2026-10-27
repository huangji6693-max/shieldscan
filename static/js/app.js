const API = '/api/scans';
let pollTimer = null;
let currentScanId = null;
let allFindings = [];
let activeFilter = 'all';

const els = {
  form: document.getElementById('scan-form'),
  url: document.getElementById('target-url'),
  auth: document.getElementById('authorised'),
  submit: document.getElementById('start-scan'),
  progress: document.getElementById('progress-section'),
  progressBar: document.getElementById('progress-bar'),
  progressStatus: document.getElementById('progress-status'),
  pipeline: document.getElementById('pipeline'),
  results: document.getElementById('results-section'),
  grade: document.getElementById('grade-badge'),
  summary: document.getElementById('executive-summary'),
  scanMeta: document.getElementById('scan-meta'),
  findingsBody: document.getElementById('findings-body'),
  report: document.getElementById('ai-report'),
  statTotal: document.getElementById('stat-total'),
  statCritical: document.getElementById('stat-critical'),
  statHigh: document.getElementById('stat-high'),
  statMedium: document.getElementById('stat-medium'),
  statLow: document.getElementById('stat-low'),
  owaspBreakdown: document.getElementById('owasp-breakdown'),
  remediationCards: document.getElementById('remediation-cards'),
  history: document.getElementById('history-list'),
  exportHtml: document.getElementById('export-html'),
  exportMd: document.getElementById('export-md'),
  newScan: document.getElementById('new-scan'),
  headerStatus: document.getElementById('header-status'),
  statusText: document.getElementById('status-text'),
  filterChips: document.getElementById('filter-chips'),
};

const PIPELINE_ORDER = ['queued', 'running', 'spidering', 'passive_scan', 'active_scan', 'ai_reporting', 'complete'];

document.addEventListener('DOMContentLoaded', () => {
  loadHealth();
  loadHistory();
  els.form.addEventListener('submit', startScan);
  els.newScan.addEventListener('click', resetUI);
  els.exportHtml.addEventListener('click', () => window.open(`${API}/${currentScanId}/report/html`, '_blank'));
  els.exportMd.addEventListener('click', () => window.location.href = `${API}/${currentScanId}/report/download`);

  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      els.url.value = btn.dataset.url;
      els.url.focus();
    });
  });

  els.filterChips.addEventListener('click', e => {
    const chip = e.target.closest('.filter-chip');
    if (!chip) return;
    activeFilter = chip.dataset.filter;
    document.querySelectorAll('.filter-chip').forEach(c => c.classList.toggle('active', c === chip));
    renderFindings(allFindings);
  });
});

async function loadHealth() {
  try {
    const res = await fetch('/health');
    if (!res.ok) throw new Error('offline');
    els.headerStatus.classList.add('online');
    els.statusText.textContent = 'Ready';
  } catch {
    els.headerStatus.classList.add('offline');
    els.statusText.textContent = 'Not running';
  }
}

function friendlyCategory(owasp) {
  if (!owasp) return 'Other';
  const after = owasp.split('—')[1];
  if (after) return after.trim();
  const labels = {
    'A01:2021': 'Access control',
    'A02:2021': 'Data protection',
    'A03:2021': 'Injection attacks',
    'A05:2021': 'Configuration',
    'A06:2021': 'Outdated software',
    'A07:2021': 'Login & passwords',
    'A10:2021': 'Server requests',
  };
  const code = owasp.split(' ')[0];
  return labels[code] || owasp;
}

async function startScan(e) {
  e.preventDefault();
  if (!els.auth.checked) {
    alert('You must confirm you have authorisation to scan this target.');
    return;
  }

  els.submit.disabled = true;
  els.submit.classList.add('scanning');
  els.progress.classList.add('active');
  els.results.classList.remove('active');
  setProgress(5, 'Submitting scan request...', 'queued');

  try {
    const res = await fetch(API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url: els.url.value, authorised: true }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Failed to start scan');
    }
    const scan = await res.json();
    currentScanId = scan.id;
    pollProgress(scan.id);
  } catch (err) {
    alert(err.message);
    els.submit.disabled = false;
    els.submit.classList.remove('scanning');
    els.progress.classList.remove('active');
  }
}

function pollProgress(id) {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    try {
      const res = await fetch(`${API}/${id}/progress`);
      const data = await res.json();
      setProgress(data.progress_percent, data.status_message, data.status);

      if (data.status === 'complete' || data.status === 'failed') {
        clearInterval(pollTimer);
        await loadResults(id);
        els.submit.disabled = false;
        els.submit.classList.remove('scanning');
        loadHistory();
      }
    } catch (err) {
      console.error(err);
    }
  }, 1500);
}

function setProgress(pct, msg, status) {
  els.progressBar.style.width = `${pct}%`;
  els.progressStatus.textContent = msg;
  if (status) updatePipeline(status);
}

function updatePipeline(status) {
  const idx = PIPELINE_ORDER.indexOf(status);
  els.pipeline.querySelectorAll('.pipeline-step').forEach(step => {
    const stepName = step.dataset.step;
    const stepIdx = PIPELINE_ORDER.indexOf(stepName);
    step.classList.remove('active', 'done');
    if (stepIdx < idx) step.classList.add('done');
    else if (stepIdx === idx) step.classList.add('active');
  });
}

function countByRisk(findings) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  findings.forEach(f => {
    const key = counts[f.risk] !== undefined ? f.risk : 'Informational';
    counts[key]++;
  });
  return counts;
}

const REMEDIATION_CARDS = {
  'A01:2021': {
    title: 'Access Control & Form Protection',
    what: 'Private pages or state-changing forms can be triggered without proper authorisation.',
    fix: 'Require login on admin/user pages, verify user ownership for every record ID, and add CSRF tokens to POST forms.',
  },
  'A02:2021': {
    title: 'Data & Connection Encryption',
    what: 'Passwords or session cookies may travel over unencrypted HTTP connections.',
    fix: 'Enable HTTPS site-wide, redirect HTTP to HTTPS, and set Secure + HttpOnly flags on login cookies.',
  },
  'A03:2021': {
    title: 'Input & Database Injection',
    what: 'Search boxes, URL parameters, or forms accept untrusted commands or scripts.',
    fix: 'Use parameterised database queries and escape all user input before rendering it in HTML.',
  },
  'A04:2021': {
    title: 'Safe Workflow Design',
    what: 'Password reset or public submission forms lack verification tokens or spam limits.',
    fix: 'Require one-time reset tokens for password recovery and add CAPTCHA/rate limits to public forms.',
  },
  'A05:2021': {
    title: 'Website Security Settings',
    what: 'Browser security headers are missing or internal folders/files (.env, backups) are exposed.',
    fix: 'Add CSP, HSTS, and X-Frame-Options headers, disable directory listing, and block dotfiles.',
  },
  'A06:2021': {
    title: 'Outdated Website Libraries',
    what: 'Older JavaScript or CMS plugin versions with known vulnerabilities are loaded.',
    fix: 'Upgrade jQuery, Bootstrap, and CMS plugins to their latest stable releases.',
  },
  'A07:2021': {
    title: 'Login & Account Protection',
    what: 'Login forms allow unlimited password guessing or expose credentials in URLs.',
    fix: 'Submit login forms via HTTPS POST only and enforce rate limiting / account lockout.',
  },
  'A08:2021': {
    title: 'Software & Script Integrity',
    what: 'Third-party scripts are loaded without cryptographic integrity hashes.',
    fix: 'Add Subresource Integrity (integrity="sha384-...") attributes to external script tags.',
  },
  'A09:2021': {
    title: 'Error Messages & Monitoring',
    what: 'Detailed technical stack traces or database errors are visible to site visitors.',
    fix: 'Display friendly generic error pages to visitors and log technical details server-side only.',
  },
  'A10:2021': {
    title: 'Outbound Server Requests (SSRF)',
    what: 'URL-accepting parameters could trick your server into fetching internal network resources.',
    fix: 'Allowlist trusted destination domains and block requests to internal/private IP addresses.',
  },
};

function getCardForCategory(owasp) {
  const code = (owasp || '').split(' ')[0].trim();
  return REMEDIATION_CARDS[code] || REMEDIATION_CARDS['A05:2021'];
}

function renderRemediationCards(findings) {
  if (!els.remediationCards) return;
  const seen = new Map();
  findings.forEach(f => {
    const code = (f.owasp_category || 'A05:2021').split(' ')[0].trim() || 'A05:2021';
    const card = getCardForCategory(code);
    if (!seen.has(code)) {
      seen.set(code, { code, count: 0, ...card });
    }
    seen.get(code).count += 1;
  });

  const cards = Array.from(seen.values());
  els.remediationCards.innerHTML = cards.length
    ? cards.map(c => `
        <div class="remediation-card">
          <div class="remediation-card-header">
            <strong>${esc(c.title)}</strong>
            <span class="remediation-badge">${esc(c.code)} &middot; ${c.count}</span>
          </div>
          <p class="remediation-what">${esc(c.what)}</p>
          <p class="remediation-fix"><strong>How to fix:</strong> ${esc(c.fix)}</p>
        </div>`).join('')
    : '<p style="color:var(--muted);font-size:0.85rem">No remediation actions needed.</p>';
}

function renderOwaspBreakdown(findings) {
  const buckets = {};
  findings.forEach(f => {
    const key = friendlyCategory(f.owasp_category);
    buckets[key] = (buckets[key] || 0) + 1;
  });
  const entries = Object.entries(buckets).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const max = entries.length ? entries[0][1] : 1;

  els.owaspBreakdown.innerHTML = entries.length
    ? entries.map(([cat, n]) => `
        <div class="owasp-row">
          <span title="${esc(cat)}">${esc(cat)}</span>
          <div class="owasp-bar-bg"><div class="owasp-bar" style="width:${(n / max) * 100}%"></div></div>
          <span>${n}</span>
        </div>`).join('')
    : '<p style="color:var(--muted);font-size:0.85rem">No issues grouped by type yet.</p>';
}

function displayParameter(f) {
  const p = (f.parameter || '').trim();
  if (p) return p;
  if (f.evidence && f.evidence.length < 60) return f.evidence;
  return 'Whole page';
}

function renderFindings(findings) {
  const filtered = activeFilter === 'all'
    ? findings
    : findings.filter(f => f.risk === activeFilter);

  els.findingsBody.innerHTML = '';
  if (!filtered.length) {
    const msg = findings.length
      ? 'No findings match this filter.'
      : 'No vulnerabilities detected.';
    els.findingsBody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--muted)">${msg}</td></tr>`;
    return;
  }

  filtered.forEach(f => {
    const tr = document.createElement('tr');
    const plainFix = f.solution || getCardForCategory(f.owasp_category).fix;
    tr.innerHTML = `
      <td><span class="risk-badge risk-${f.risk}">${esc(f.risk)}</span></td>
      <td><strong>${esc(f.name)}</strong></td>
      <td style="word-break:break-all;font-size:0.78rem">${esc(f.url)}</td>
      <td><code class="param-code">${esc(displayParameter(f))}</code></td>
      <td class="evidence-text">${esc(truncate(f.evidence || f.description || '—', 120))}</td>
      <td style="font-size:0.82rem">${esc(plainFix)}</td>
    `;
    els.findingsBody.appendChild(tr);
  });
}

async function loadResults(id) {
  const res = await fetch(`${API}/${id}`);
  const data = await res.json();

  els.progress.classList.remove('active');
  els.results.classList.add('active');

  if (data.status === 'failed') {
    els.summary.textContent = `Scan failed: ${data.error_message || 'Unknown error'}`;
    return;
  }

  const grade = data.risk_grade || 'N/A';
  els.grade.textContent = grade;
  els.grade.className = `grade-badge grade-${grade}`;
  requestAnimationFrame(() => {
    els.grade.classList.add('reveal');
    setTimeout(() => els.grade.classList.remove('reveal'), 500);
  });

  const counts = countByRisk(data.findings);
  els.statTotal.textContent = data.finding_count;
  els.statCritical.textContent = counts.Critical;
  els.statHigh.textContent = counts.High;
  els.statMedium.textContent = counts.Medium;
  els.statLow.textContent = counts.Low + counts.Informational;

  const duration = formatDuration(data.created_at, data.completed_at);
  els.scanMeta.textContent = [
    data.target_url,
    data.scanner_used ? `Scanner: ${data.scanner_used}` : null,
    duration,
    data.completed_at ? new Date(data.completed_at).toLocaleString() : null,
  ].filter(Boolean).join(' · ');

  els.summary.textContent = data.executive_summary || 'Scan complete.';
  allFindings = data.findings || [];
  activeFilter = 'all';
  document.querySelectorAll('.filter-chip').forEach(c => c.classList.toggle('active', c.dataset.filter === 'all'));
  renderOwaspBreakdown(allFindings);
  renderRemediationCards(allFindings);
  renderFindings(allFindings);
  els.report.textContent = data.ai_report || '';
}

function formatDuration(start, end) {
  if (!start || !end) return null;
  const ms = new Date(end) - new Date(start);
  if (ms < 1000) return `${ms}ms`;
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s scan time`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s scan time`;
}

function resetUI() {
  els.results.classList.remove('active');
  els.progress.classList.remove('active');
  els.url.value = '';
  els.auth.checked = false;
  currentScanId = null;
  allFindings = [];
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function loadHistory() {
  try {
    const res = await fetch(API);
    const scans = await res.json();
    els.history.innerHTML = '';
    if (!scans.length) {
      els.history.innerHTML = '<p style="color:var(--muted)">No scans yet.</p>';
      return;
    }
    scans.forEach(s => {
      const div = document.createElement('div');
      div.className = 'history-item';
      div.innerHTML = `
        <div>
          <strong>${esc(s.target_url)}</strong><br>
          <small style="color:var(--muted)">${new Date(s.created_at).toLocaleString()} — ${esc(s.scanner_used || 'unknown')}</small>
        </div>
        <div>
          <span class="risk-badge grade-${s.risk_grade || 'N/A'}" style="margin-right:8px">Grade ${esc(s.risk_grade || '?')}</span>
          <span style="color:var(--muted)">${s.finding_count} findings</span>
        </div>
      `;
      div.addEventListener('click', () => {
        currentScanId = s.id;
        loadResults(s.id);
        els.results.classList.add('active');
        els.results.scrollIntoView({ behavior: 'smooth' });
      });
      els.history.appendChild(div);
    });
  } catch (err) {
    console.error(err);
  }
}

function truncate(str, len) {
  if (!str || str.length <= len) return str || '';
  return str.slice(0, len) + '…';
}

function esc(str) {
  const d = document.createElement('div');
  d.textContent = str || '';
  return d.innerHTML;
}

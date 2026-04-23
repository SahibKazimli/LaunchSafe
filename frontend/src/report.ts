export {};

const SCAN_ID = window.location.pathname.replace(/\/$/, '').split('/').pop() || '';

// ---------------------------------------------------------------------------
// Scoring logic — ported 1:1 from backend/tools/scanners.py + core/config.py
// ---------------------------------------------------------------------------

const EXPOSURE_MULTIPLIER: Record<string, number> = {
  production: 1.00,
  internal:   0.60,
  test:       0.15,
  example:    0.05,
  doc:        0.03,
};

const SEVERITY_DEFAULT_CVSS: Record<string, number> = {
  critical: 9.0,
  high:     7.5,
  medium:   5.0,
  low:      2.0,
};

const GRADE_THRESHOLDS: [string, number][] = [
  ['A',  5.0],
  ['B', 12.5],
  ['C', 20.0],
  ['D', 30.0],
];

interface Finding {
  severity: string;
  title: string;
  location: string;
  description: string;
  fix: string;
  module?: string;
  compliance?: (string | { id?: string; summary?: string; url?: string })[];
  cvss_base?: number;
  exposure?: string;
  is_true_positive?: boolean;
}

interface ScoreRow {
  cvss_base: number;
  exposure: string;
  exposure_multiplier: number;
  contribution: number;
  counted: boolean;
}

interface Breakdown {
  rows: ScoreRow[];
  risk_total: number;
  score: number;
  grade: string;
  counted: number;
  skipped_low_confidence: number;
  thresholds: [string, number][];
}

function normalizeSeverity(s: string | null | undefined): string {
  return (s || 'low').trim().toLowerCase();
}

function cvssFor(finding: Finding): number {
  const raw = finding.cvss_base;
  if (raw !== undefined && raw !== null) {
    const v = Number(raw);
    if (v > 0 && v <= 10.0) return v;
  }
  return SEVERITY_DEFAULT_CVSS[normalizeSeverity(finding.severity)] || 0;
}

function inferExposureFromPath(location: string): string {
  const p = (location || '').toLowerCase().replace(/\\/g, '/');
  if (!p) return 'production';
  const parts = p.split('/');
  const name = parts[parts.length - 1] || '';

  if (parts.some(seg => ['tests', 'test', '__tests__', 'spec', 'specs', 'fixtures'].includes(seg))) return 'test';
  if (name.startsWith('test_')) return 'test';
  if (['_test.py', '.test.ts', '.test.tsx', '.spec.ts', '.spec.js', '.spec.tsx'].some(s => name.endsWith(s))) return 'test';
  if (name === 'conftest.py') return 'test';

  if (parts.some(seg => ['examples', 'example', 'samples', 'sample', 'demo', 'demos', 'cookbook'].includes(seg))) return 'example';

  if (parts.some(seg => ['docs', 'doc', 'documentation'].includes(seg))) return 'doc';
  if (name === 'readme.md' || (name.endsWith('.md') && parts.includes('docs'))) return 'doc';

  return 'production';
}

function exposureFor(finding: Finding): string {
  const raw = (finding.exposure || '').trim().toLowerCase();
  if (raw in EXPOSURE_MULTIPLIER) return raw;
  return inferExposureFromPath(finding.location || '');
}

function scoreFinding(finding: Finding): ScoreRow {
  const cvss = cvssFor(finding);
  const exposure = exposureFor(finding);
  const mult = EXPOSURE_MULTIPLIER[exposure] ?? 1.0;
  const contribution = Math.round(cvss * mult * 100) / 100;
  return {
    cvss_base: cvss,
    exposure,
    exposure_multiplier: mult,
    contribution,
    counted: finding.is_true_positive !== false,
  };
}

function computeScore(findings: Finding[]): { score: number; grade: string } {
  let riskTotal = 0;
  for (const f of findings) {
    if (f.is_true_positive === false) continue;
    riskTotal += scoreFinding(f).contribution;
  }
  const score = Math.max(0, Math.min(100, Math.round(100 - 2.0 * riskTotal)));
  let grade = 'F';
  for (const [g, threshold] of GRADE_THRESHOLDS) {
    if (riskTotal <= threshold) { grade = g; break; }
  }
  return { score, grade };
}

function scoreBreakdown(findings: Finding[]): Breakdown {
  const rows: ScoreRow[] = [];
  let riskTotal = 0;
  let counted = 0;
  let skippedLowConfidence = 0;
  for (const f of findings) {
    const s = scoreFinding(f);
    rows.push(s);
    if (s.counted) { riskTotal += s.contribution; counted++; }
    else { skippedLowConfidence++; }
  }
  const { score, grade } = computeScore(findings);
  return {
    rows,
    risk_total: Math.round(riskTotal * 100) / 100,
    score,
    grade,
    counted,
    skipped_low_confidence: skippedLowConfidence,
    thresholds: GRADE_THRESHOLDS,
  };
}

// ---------------------------------------------------------------------------
// HTML helpers
// ---------------------------------------------------------------------------

function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

const SEV_TITLES: Record<string, string> = {
  critical: 'easy to exploit and high-impact, likely to cause major compromise',
  high:     'serious weakness with significant security impact',
  medium:   'real issue, but requires more conditions or has limited impact',
  low:      'lower-risk issue, defense-in-depth, or limited practical exposure',
};

/** When the API omits `url` (or legacy string tags), map known ids to deep links. Mirrors backend `compliance_enrichment`. */
const OWASP_2021_PATHS: readonly string[] = [
  'A01_2021-Broken_Access_Control',
  'A02_2021-Cryptographic_Failures',
  'A03_2021-Injection',
  'A04_2021-Insecure_Design',
  'A05_2021-Security_Misconfiguration',
  'A06_2021-Vulnerable_and_Outdated_Components',
  'A07_2021-Identification_and_Authentication_Failures',
  'A08_2021-Software_and_Data_Integrity_Failures',
  'A09_2021-Security_Logging_and_Monitoring_Failures',
  'A10_2021-Server-Side_Request_Forgery_%28SSRF%29',
];

function guessComplianceUrl(rawId: string): string {
  const raw = rawId.trim();
  if (!raw) return '';
  const ow = raw.match(/OWASP-?\s*A(0[1-9]|10)\b/i) || raw.match(/OWASP\s*A(0[1-9]|10)\s*:\s*2021/i);
  if (ow) {
    const n = parseInt(ow[1], 10);
    if (n >= 1 && n <= 10) {
      return `https://owasp.org/Top10/${OWASP_2021_PATHS[n - 1]}/`;
    }
  }
  if (/gdpr/i.test(raw)) {
    const art = raw.match(/Art\.?\s*(\d+)/i);
    if (art && ['5', '13', '25', '32', '33'].includes(art[1])) {
      return `https://gdpr-info.eu/art-${art[1]}-gdpr/`;
    }
  }
  if (/ccpa/i.test(raw) && (raw.includes('1798.100') || raw.includes('1798-100'))) {
    return 'https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.100';
  }
  if (/ccpa/i.test(raw) && (raw.includes('1798.150') || raw.includes('1798-150'))) {
    return 'https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.150';
  }
  if (/soc\s*2|soc2|trust services/i.test(raw) && /cc\s*[67]\.\d/i.test(raw)) {
    return 'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022';
  }
  const nist = raw.match(/800-53[:\s]+([A-Z]{1,3})-?\s*(\d+)/i);
  if (nist) {
    const ctrl = `${nist[1].toUpperCase()}-${nist[2]}`;
    return `https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=${ctrl}`;
  }
  if (/27001/i.test(raw) && /A\.(9|12)\b/i.test(raw)) {
    return 'https://www.iso.org/standard/54534.html';
  }
  return '';
}

function renderComplianceTag(tag: string | { id?: string; summary?: string; url?: string }): string {
  let idStr: string;
  let tsum = '';
  if (typeof tag === 'string') {
    idStr = tag;
  } else {
    idStr = tag.id || '';
    tsum = tag.summary ? escapeHtml(tag.summary) : '';
  }
  const tid = escapeHtml(idStr);
  const turl = (typeof tag === 'object' && tag && typeof tag.url === 'string' && tag.url.trim())
    ? tag.url.trim()
    : guessComplianceUrl(idStr);
  if (turl) {
    return `<a class="comp-tag linked" href="${escapeHtml(turl)}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">${tid}<span class="comp-pop"><span class="pop-title">${tid}</span>${tsum ? `<span class="pop-summary">${tsum}</span>` : ''}<span class="pop-link">Open standard</span></span></a>`;
  } else if (tsum) {
    return `<span class="comp-tag linked" tabindex="0">${tid}<span class="comp-pop"><span class="pop-title">${tid}</span><span class="pop-summary">${tsum}</span></span></span>`;
  }
  return `<span class="comp-tag">${tid}</span>`;
}

function renderFindingItem(f: Finding, scoreRow: ScoreRow): string {
  const sev = normalizeSeverity(f.severity);

  let scoreMeta = '';
  scoreMeta = `<div class="score-meta">
    <span class="pill">CVSS ${scoreRow.cvss_base.toFixed(1)}</span>
    <span class="pill exposure-${scoreRow.exposure}">exposure: ${scoreRow.exposure} (\u00d7${scoreRow.exposure_multiplier.toFixed(2)})</span>
    <span class="pill ${scoreRow.counted ? 'contrib' : 'skipped'}">contributes ${scoreRow.contribution.toFixed(2)}${scoreRow.counted ? '' : ' (skipped: not a true positive)'}</span>
  </div>`;

  let complianceTags = '';
  if (f.compliance && f.compliance.length > 0) {
    complianceTags = `<div class="compliance-tags">${f.compliance.map(renderComplianceTag).join('')}</div>`;
  }

  return `<div class="finding-item" data-sev="${sev}" onclick="this.classList.toggle('expanded')">
    <div class="finding-top">
      <span class="sev-badge sev-${sev}" title="${escapeHtml(SEV_TITLES[sev] || '')}">${sev}</span>
      <span class="finding-title">${escapeHtml(f.title)}</span>
    </div>
    <div class="finding-location">${escapeHtml(f.location)}</div>
    ${scoreMeta}
    <div class="finding-desc">${escapeHtml(f.description)}</div>
    ${complianceTags}
    <div class="finding-fix">
      <div class="fix-label">Recommended fix</div>
      ${escapeHtml(f.fix)}
    </div>
  </div>`;
}

// ---------------------------------------------------------------------------
// Sidebar rendering
// ---------------------------------------------------------------------------

function renderSidebar(
  grade: string,
  score: number,
  counts: Record<string, number>,
  breakdown: Breakdown,
) {
  document.getElementById('grade-letter')!.textContent = grade;
  document.getElementById('grade-letter')!.className = `score-number grade-${grade}`;
  document.getElementById('score-value')!.textContent = `Score: ${score} / 100`;

  document.getElementById('count-critical')!.textContent = String(counts.critical);
  document.getElementById('count-high')!.textContent = String(counts.high);
  document.getElementById('count-medium')!.textContent = String(counts.medium);
  document.getElementById('count-low')!.textContent = String(counts.low);

  // Compliance gaps (same logic as the Jinja template)
  const hasCritical = counts.critical > 0;
  const hasHigh = counts.high > 0;
  setComplianceRow('comp-gdpr', hasCritical ? 'comp-gap' : 'comp-partial', hasCritical ? 'Gap' : 'Partial');
  setComplianceRow('comp-soc2', hasHigh ? 'comp-gap' : 'comp-partial', hasHigh ? 'Gap' : 'Partial');
  setComplianceRow('comp-iso', counts.critical > 1 ? 'comp-gap' : 'comp-partial', counts.critical > 1 ? 'Gap' : 'Partial');

  // Breakdown table
  const tbl = document.getElementById('breakdown-table')!;
  let rows = `<tr><td>Findings counted</td><td>${breakdown.counted}</td></tr>`;
  if (breakdown.skipped_low_confidence) {
    rows += `<tr><td>Skipped (low confidence)</td><td>${breakdown.skipped_low_confidence}</td></tr>`;
  }
  rows += `<tr><td>Risk total (\u03a3 contribution)</td><td>${breakdown.risk_total}</td></tr>`;
  rows += `<tr><td>Score</td><td>${breakdown.score} / 100</td></tr>`;
  rows += `<tr><td>Grade</td><td>${breakdown.grade}</td></tr>`;
  tbl.innerHTML = rows;

  // Thresholds
  const thEl = document.getElementById('breakdown-thresholds')!;
  let thHtml = '';
  for (const [label, ceil] of breakdown.thresholds) {
    thHtml += `<span class="th ${breakdown.grade === label ? 'active' : ''}">${label}: risk \u2264 ${ceil}</span>`;
  }
  thHtml += `<span class="th ${breakdown.grade === 'F' ? 'active' : ''}">F: risk &gt; 30</span>`;
  thEl.innerHTML = thHtml;
}

function setComplianceRow(id: string, dotClass: string, statusText: string) {
  const el = document.getElementById(id);
  if (!el) return;
  el.querySelector('.compliance-dot')!.className = `compliance-dot ${dotClass}`;
  el.querySelector('.compliance-status')!.textContent = statusText;
}

// ---------------------------------------------------------------------------
// Filter & Fix Mode (same as original)
// ---------------------------------------------------------------------------

function filter(sev: string, btn: HTMLElement) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const items = document.querySelectorAll('.finding-item[data-sev]') as NodeListOf<HTMLElement>;
  let shown = 0;
  items.forEach(item => {
    const match = sev === 'all' || item.dataset.sev === sev;
    item.style.display = match ? '' : 'none';
    if (match) shown++;
  });
  document.getElementById('shown-label')!.textContent =
    (sev === 'all' ? 'Showing all ' : 'Showing ') + shown + (sev !== 'all' ? ' ' + sev : '') + ' findings';
}

async function startFixMode() {
  const btn = document.getElementById('fix-mode-btn') as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = 'Starting fix agent\u2026';

  const items = document.querySelectorAll('.finding-item[data-sev]') as NodeListOf<HTMLElement>;
  const indices: number[] = [];
  items.forEach((item, i) => {
    if (item.style.display !== 'none') indices.push(i);
  });

  if (indices.length === 0) {
    alert('No findings currently visible to fix! Change your filter.');
    btn.disabled = false;
    btn.textContent = 'Fix Mode';
    return;
  }

  try {
    const resp = await fetch('/start-fix', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: SCAN_ID, finding_indices: indices }),
    });
    const data = await resp.json();
    if (data.error) {
      alert('Error: ' + data.error);
      btn.disabled = false;
      btn.textContent = 'Fix Mode';
      return;
    }
    window.location.href = '/fix/' + data.fix_id;
  } catch (err: unknown) {
    alert('Failed to start fix session: ' + (err instanceof Error ? err.message : String(err)));
    btn.disabled = false;
    btn.textContent = 'Fix Mode';
  }
}

// Expose to inline onclick handlers
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const _w = window as any;
_w.filter = filter;
_w.startFixMode = startFixMode;

// ---------------------------------------------------------------------------
// Page init — fetch data and render
// ---------------------------------------------------------------------------

async function init() {
  const loadingEl = document.getElementById('loading-state')!;

  try {
    const [findingsRes, statusRes] = await Promise.all([
      fetch(`/api/findings/${SCAN_ID}`),
      fetch(`/scan-status/${SCAN_ID}`),
    ]);
    const findingsData = await findingsRes.json();
    const statusData = await statusRes.json();

    if (findingsData.error || statusData.error) {
      loadingEl.textContent = 'Report not ready or scan not found.';
      return;
    }

    const findings: Finding[] = findingsData.findings || [];
    const target: string = statusData.target || '';
    const total = findings.length;

    const counts = {
      critical: findings.filter(f => normalizeSeverity(f.severity) === 'critical').length,
      high:     findings.filter(f => normalizeSeverity(f.severity) === 'high').length,
      medium:   findings.filter(f => normalizeSeverity(f.severity) === 'medium').length,
      low:      findings.filter(f => normalizeSeverity(f.severity) === 'low').length,
    };

    const breakdown = scoreBreakdown(findings);

    // Render sidebar
    renderSidebar(breakdown.grade, breakdown.score, counts, breakdown);

    // Render top bar
    document.getElementById('report-target')!.textContent =
      `Target: ${target} \u00b7 `;
    document.getElementById('report-count')!.textContent = `${total} findings`;
    document.getElementById('json-export-link')!.setAttribute('href', `/api/findings/${SCAN_ID}`);

    // Render filter buttons with counts
    document.getElementById('filter-all')!.textContent = `All (${total})`;
    document.getElementById('filter-critical')!.textContent = `Critical (${counts.critical})`;
    document.getElementById('filter-high')!.textContent = `High (${counts.high})`;
    document.getElementById('filter-medium')!.textContent = `Medium (${counts.medium})`;
    document.getElementById('filter-low')!.textContent = `Low (${counts.low})`;
    document.getElementById('shown-label')!.textContent = `Showing all ${total}`;

    // Render findings list
    const list = document.getElementById('findings-list')!;
    if (findings.length === 0) {
      list.innerHTML = '<div class="empty-state"><strong>Clean!</strong>No findings detected in this scan.</div>';
    } else {
      list.innerHTML = findings.map((f, i) => renderFindingItem(f, breakdown.rows[i])).join('');
    }

    // Hide loading, show report
    loadingEl.style.display = 'none';
    document.getElementById('screen-report')!.style.display = '';
  } catch (_err) {
    loadingEl.textContent = 'Failed to load report data.';
  }
}

init();

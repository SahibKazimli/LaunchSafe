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
  file_path?: string;
  line_start?: number;
  line_end?: number;
  snippet?: string;
  highlight_lines?: number[];
  /** Inclusive 1-based file line ranges; when set, drive highlighting (overrides single-line heuristics). */
  highlight_line_ranges?: [number, number][];
  /** True when the excerpt could not show every line in `highlight_line_ranges` / `highlight_lines`. */
  code_highlight_truncated?: boolean;
  snippet_start_line?: number;
  code_language?: string;
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

function normalizeSeverity(severityRaw: string | null | undefined): string {
  return (severityRaw || 'low').trim().toLowerCase();
}

function cvssFor(finding: Finding): number {
  const raw = finding.cvss_base;
  if (raw !== undefined && raw !== null) {
    const cvssValue = Number(raw);
    if (cvssValue > 0 && cvssValue <= 10.0) return cvssValue;
  }
  return SEVERITY_DEFAULT_CVSS[normalizeSeverity(finding.severity)] || 0;
}

function inferExposureFromPath(location: string): string {
  const normalizedPath = (location || '').toLowerCase().replace(/\\/g, '/');
  if (!normalizedPath) return 'production';
  const parts = normalizedPath.split('/');
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
  for (const finding of findings) {
    if (finding.is_true_positive === false) continue;
    riskTotal += scoreFinding(finding).contribution;
  }
  const score = Math.max(0, Math.min(100, Math.round(100 - 2.0 * riskTotal)));
  let grade = 'F';
  for (const [gradeLetter, riskThreshold] of GRADE_THRESHOLDS) {
    if (riskTotal <= riskThreshold) { grade = gradeLetter; break; }
  }
  return { score, grade };
}

function scoreBreakdown(findings: Finding[]): Breakdown {
  const rows: ScoreRow[] = [];
  let riskTotal = 0;
  let counted = 0;
  let skippedLowConfidence = 0;
  for (const finding of findings) {
    const scoreRow = scoreFinding(finding);
    rows.push(scoreRow);
    if (scoreRow.counted) { riskTotal += scoreRow.contribution; counted++; }
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

function parseGitHubRepo(target: string): { owner: string; repo: string } | null {
  const trimmedTarget = (target || '').trim();
  const githubMatch = trimmedTarget.match(/github\.com[:/]([^/]+)\/([^/?#]+)/i);
  if (!githubMatch) return null;
  return { owner: githubMatch[1], repo: githubMatch[2].replace(/\.git$/i, '') };
}

function buildGitHubBlobUrl(
  target: string,
  filePath: string,
  lineStart: number,
  lineEnd: number,
): string | null {
  const repoParts = parseGitHubRepo(target);
  if (!repoParts || !filePath) return null;
  const path = filePath.split('/').map(seg => encodeURIComponent(seg)).join('/');
  const hash = lineStart === lineEnd ? `L${lineStart}` : `L${lineStart}-L${lineEnd}`;
  return `https://github.com/${repoParts.owner}/${repoParts.repo}/blob/HEAD/${path}#${hash}`;
}

let _findings: Finding[] = [];
let _scanTarget = '';
let _escHandler: ((e: KeyboardEvent) => void) | null = null;

function splitSnippetLines(snippet: string): string[] {
  if (!snippet) return [];
  const parts = snippet.split(/\n/);
  if (parts.length > 0 && parts[parts.length - 1] === '' && snippet.endsWith('\n')) {
    parts.pop();
  }
  return parts;
}

function fileLineInHighlightRanges(
  fileLine: number,
  lineRanges: [number, number][] | undefined,
): boolean {
  if (!lineRanges || !lineRanges.length) return false;
  for (const lineRange of lineRanges) {
    if (!Array.isArray(lineRange) || lineRange.length < 2) continue;
    const rangeStart = Number(lineRange[0]);
    const rangeEnd = Number(lineRange[1]);
    if (!Number.isFinite(rangeStart) || !Number.isFinite(rangeEnd)) continue;
    const inclusiveStart = Math.min(rangeStart, rangeEnd);
    const inclusiveEnd = Math.max(rangeStart, rangeEnd);
    if (fileLine >= inclusiveStart && fileLine <= inclusiveEnd) return true;
  }
  return false;
}

function renderCodeLines(
  snippet: string,
  startLine: number,
  highlightLines: number[] | undefined,
  citedFileLine: number | undefined,
  fileLineRanges: [number, number][] | undefined,
): string {
  const snippetLines = splitSnippetLines(snippet);
  const lastLineInExcerpt = startLine + Math.max(0, snippetLines.length - 1);
  const relativeHighlightSet = new Set(
    highlightLines && highlightLines.length ? highlightLines : [],
  );
  const highlightByFileRanges = !!(
    fileLineRanges && fileLineRanges.length
  );
  return snippetLines
    .map((lineText, lineIndex) => {
      const fileLine = startLine + lineIndex;
      const fromRelativeList =
        !highlightByFileRanges && relativeHighlightSet.has(lineIndex + 1);
      const fromLineRanges =
        highlightByFileRanges &&
        fileLine >= startLine &&
        fileLine <= lastLineInExcerpt &&
        fileLineInHighlightRanges(fileLine, fileLineRanges);
      const fromCitedAlone =
        !highlightByFileRanges && citedFileLine != null && fileLine === citedFileLine;
      const isHighlighted = fromLineRanges || fromRelativeList || fromCitedAlone;
      const rowClass = isHighlighted ? 'code-line code-line--hl' : 'code-line';
      return `<div class="${rowClass}" data-line="${fileLine}"><span class="ln">${fileLine}</span><span class="src">${escapeHtml(lineText)}</span></div>`;
    })
    .join('');
}

function openCodeModal(index: number): void {
  const finding = _findings[index];
  if (!finding || !finding.snippet || !String(finding.snippet).trim()) return;

  const titleEl = document.getElementById('code-modal-title')!;
  const metaEl = document.getElementById('code-modal-meta')!;
  const scrollEl = document.getElementById('code-modal-scroll')!;
  const fixWrap = document.getElementById('code-modal-fix')!;
  const fixText = document.getElementById('code-modal-fix-text')!;
  const ghLink = document.getElementById('code-modal-gh') as HTMLAnchorElement;
  const backdrop = document.getElementById('code-modal-backdrop')!;

  titleEl.textContent = finding.title;
  const sev = normalizeSeverity(finding.severity);
  const fileLabel = finding.file_path || finding.location || '—';
  const lineStartLabel = finding.line_start ?? '—';
  const lineEndLabel = finding.line_end ?? lineStartLabel;
  metaEl.innerHTML = `${escapeHtml(sev)} · ${escapeHtml(fileLabel)} · lines ${lineStartLabel}–${lineEndLabel}`;

  if (finding.fix && finding.fix.trim()) {
    fixWrap.style.display = '';
    fixText.textContent = finding.fix;
  } else {
    fixWrap.style.display = 'none';
  }

  const snippetStartLine = finding.snippet_start_line ?? 1;
  const snippetLineCount = splitSnippetLines(finding.snippet).length;
  const excerptEndLine = snippetStartLine + Math.max(0, snippetLineCount - 1);
  const primaryCitedFileLine = finding.line_start;
  const cave = document.getElementById('code-modal-caveat')!;
  if (
    primaryCitedFileLine != null &&
    snippetLineCount > 0 &&
    (primaryCitedFileLine < snippetStartLine || primaryCitedFileLine > excerptEndLine)
  ) {
    cave.textContent = `Cited line ${primaryCitedFileLine} is outside this excerpt (showing ${snippetStartLine}–${excerptEndLine}). Open the full file on GitHub.`;
    cave.hidden = false;
    cave.classList.add('is-visible');
  } else if (finding.code_highlight_truncated) {
    cave.textContent =
      `Some related lines are outside this excerpt (showing ${snippetStartLine}–${excerptEndLine}). Open the full file on GitHub for the rest.`;
    cave.hidden = false;
    cave.classList.add('is-visible');
  } else {
    cave.textContent = '';
    cave.hidden = true;
    cave.classList.remove('is-visible');
  }
  const highlightFileLineRanges = Array.isArray(finding.highlight_line_ranges)
    ? finding.highlight_line_ranges
    : undefined;
  scrollEl.innerHTML = renderCodeLines(
    finding.snippet,
    snippetStartLine,
    finding.highlight_lines,
    typeof finding.line_start === 'number' ? finding.line_start : undefined,
    highlightFileLineRanges,
  );

  const url =
    finding.file_path && finding.line_start != null && finding.line_end != null
      ? buildGitHubBlobUrl(_scanTarget, finding.file_path, finding.line_start, finding.line_end)
      : null;
  if (url) {
    ghLink.style.display = '';
    ghLink.setAttribute('href', url);
  } else {
    ghLink.style.display = 'none';
  }

  backdrop.style.display = 'flex';
  backdrop.setAttribute('aria-hidden', 'false');

  if (_escHandler) {
    window.removeEventListener('keydown', _escHandler);
  }
  _escHandler = (e: KeyboardEvent) => {
    if (e.key === 'Escape') closeCodeModal();
  };
  window.addEventListener('keydown', _escHandler);

  requestAnimationFrame(() => {
    const firstHighlightedRow = scrollEl.querySelector('.code-line--hl') as HTMLElement | null;
    (firstHighlightedRow || scrollEl.firstElementChild)?.scrollIntoView({
      block: 'center',
      behavior: 'auto',
    });
  });
}

function closeCodeModal(): void {
  const backdrop = document.getElementById('code-modal-backdrop')!;
  backdrop.style.display = 'none';
  backdrop.setAttribute('aria-hidden', 'true');
  if (_escHandler) {
    window.removeEventListener('keydown', _escHandler);
    _escHandler = null;
  }
}

function countSnippetFindings(list: Finding[]): number {
  return list.filter(f => f.snippet && String(f.snippet).trim()).length;
}

function renderComplianceTag(tag: string | { id?: string; summary?: string; url?: string }): string {
  if (typeof tag === 'string') {
    return `<span class="comp-tag">${escapeHtml(tag)}</span>`;
  }
  const tid = escapeHtml(tag.id || '');
  const tsum = tag.summary ? escapeHtml(tag.summary) : '';
  const turl = tag.url || '';
  if (turl) {
    return `<a class="comp-tag linked" href="${escapeHtml(turl)}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">${tid}<span class="comp-pop"><span class="pop-title">${tid}</span>${tsum ? `<span class="pop-summary">${tsum}</span>` : ''}<span class="pop-link">Open standard</span></span></a>`;
  } else if (tsum) {
    return `<span class="comp-tag linked" tabindex="0">${tid}<span class="comp-pop"><span class="pop-title">${tid}</span><span class="pop-summary">${tsum}</span></span></span>`;
  }
  return `<span class="comp-tag">${tid}</span>`;
}

function renderFindingItem(f: Finding, scoreRow: ScoreRow, index: number, scanTarget: string): string {
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

  const hasSnippet = !!(f.snippet && String(f.snippet).trim());
  const ghUrl =
    hasSnippet && f.file_path != null && f.line_start != null && f.line_end != null
      ? buildGitHubBlobUrl(scanTarget, f.file_path, f.line_start, f.line_end)
      : null;
  const actions: string[] = [];
  if (hasSnippet) {
    actions.push(
      `<button type="button" class="view-code-btn" onclick="event.stopPropagation(); openCodeModal(${index})">View code</button>`,
    );
  }
  if (ghUrl) {
    actions.push(
      `<a class="gh-file-link" href="${escapeHtml(ghUrl)}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">View full file on GitHub</a>`,
    );
  }
  const actionsBlock = actions.length
    ? `<div class="finding-actions">${actions.join('')}</div>`
    : '';

  return `<div class="finding-item" data-sev="${sev}" data-finding-index="${index}" onclick="this.classList.toggle('expanded')">
    <div class="finding-top">
      <span class="sev-badge sev-${sev}" title="${escapeHtml(SEV_TITLES[sev] || '')}">${sev}</span>
      <span class="finding-title">${escapeHtml(f.title)}</span>
    </div>
    <div class="finding-location">${escapeHtml(f.location)}</div>
    ${actionsBlock}
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
_w.openCodeModal = openCodeModal;
_w.closeCodeModal = closeCodeModal;

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

    _findings = findings;
    _scanTarget = target;

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
    const snippetN = countSnippetFindings(findings);
    const badge = document.getElementById('snippet-count-badge')!;
    if (snippetN > 0) {
      badge.style.display = 'inline-block';
      badge.textContent = `${snippetN} issue${snippetN === 1 ? '' : 's'} with snippets`;
    } else {
      badge.style.display = 'none';
      badge.textContent = '';
    }
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
      list.innerHTML = findings
        .map((f, i) => renderFindingItem(f, breakdown.rows[i], i, target))
        .join('');
    }

    // Hide loading, show report
    loadingEl.style.display = 'none';
    document.getElementById('screen-report')!.style.display = '';
  } catch (_err) {
    loadingEl.textContent = 'Failed to load report data.';
  }
}

const _bd = document.getElementById('code-modal-backdrop');
if (_bd) {
  _bd.addEventListener('click', closeCodeModal);
  document.getElementById('code-modal-close')?.addEventListener('click', (e) => {
    e.stopPropagation();
    closeCodeModal();
  });
}

init();

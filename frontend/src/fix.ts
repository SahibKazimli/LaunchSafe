export {};

const FIX_ID = window.location.pathname.replace(/\/$/, '').split('/').pop() || '';

interface FixEvent {
  seq?: number;
  kind: string;
  branch?: string;
  t: string;
  text?: string;
}

interface Patch {
  path: string;
  explanation: string;
  diff: string;
  sanity_warnings?: string[];
}

interface PatchGroup {
  group_id: string;
  group_label?: string;
  notes?: string;
  patches: Patch[];
}

interface FixReview {
  approved?: boolean;
  notes?: string;
  warnings?: string[];
  conflicts?: string[];
}

const startedAt = Date.now();
const pollInterval = setInterval(poll, 600);
const tickInterval = setInterval(tick, 1000);
let lastSeq = 0;
const allEvents: FixEvent[] = [];

function tick() {
  const s = Math.round((Date.now() - startedAt) / 1000);
  document.getElementById('elapsed')!.textContent = s + 's';
}

function renderEventRow(ev: FixEvent): HTMLDivElement {
  const row = document.createElement('div');
  row.className = 'event ' + ev.kind;
  const branch = ev.branch || 'fix';
  row.innerHTML =
    `<span class="t">${ev.t}s</span>` +
    `<span class="branch b-${branch}">${branch}</span>` +
    `<span class="kind">${ev.kind}</span>` +
    `<span class="msg"></span>`;
  row.querySelector('.msg')!.textContent = ev.text || '';
  return row;
}

function renderEvents(events: FixEvent[]) {
  if (!events || events.length === 0) return;
  const list = document.getElementById('events-list')!;
  const atBottom = list.scrollTop + list.clientHeight >= list.scrollHeight - 20;
  for (const ev of events) {
    if (ev.seq && ev.seq <= lastSeq) continue;
    allEvents.push(ev);
    list.appendChild(renderEventRow(ev));
    if (ev.seq) lastSeq = ev.seq;
  }
  if (atBottom) list.scrollTop = list.scrollHeight;
}

function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/** Recover display when legacy diffs used lineterm=\"\" (single glued line). */
function normalizeDiffNewlines(diffText: string): string {
  let t = diffText.replace(/\r\n/g, '\n');
  if (t.includes('\n')) {
    return t;
  }
  if (t.length < 40 || (!t.includes('@@') && !t.includes('---'))) {
    return t;
  }
  return t
    .replace(/(---\s+)/g, '\n$1')
    .replace(/(\+\+\+\s+)/g, '\n$1')
    .replace(/(@@\s[-\d,]+\s[-\d,]+\s@@)/g, '\n$1')
    .replace(/([^\n])([-+][^\n])/g, '$1\n$2')
    .trim();
}

function formatDiff(diffText: string): string {
  if (!diffText) return 'No diff available.';
  const lines = normalizeDiffNewlines(diffText).split('\n');
  return lines
    .map((line) => {
      let rowClass = 'diff-ctx';
      if (line.startsWith('---') || line.startsWith('+++') || line.startsWith('@@')) {
        rowClass = 'diff-header';
      } else if (line.startsWith('+')) {
        rowClass = 'diff-add';
      } else if (line.startsWith('-')) {
        rowClass = 'diff-remove';
      }
      // One block row per line so the layout is never dependent on <pre> / newline quirks in innerHTML.
      return (
        `<div class="diff-line ${rowClass}">` + `<code class="diff-code">${escapeHtml(line)}</code></div>`
      );
    })
    .join('');
}

const REPO_HITS_MARKER = 'Repo-wide hits:';

function formatGroupNotes(notes: string): string {
  const raw = notes || '';
  if (!raw.trim()) {
    return '';
  }
  const idx = raw.indexOf(REPO_HITS_MARKER);
  if (idx === -1) {
    return `<div class="group-notes-text">${escapeHtml(raw)}</div>`;
  }
  const head = raw.slice(0, idx).trim();
  const tail = raw.slice(idx + REPO_HITS_MARKER.length).trim();
  const lines = tail.split('\n').map((l) => l.trim()).filter(Boolean);
  const listItems = lines
    .map((l) => `<li><code class="repo-hit-line">${escapeHtml(l)}</code></li>`)
    .join('');
  const summary = `Repo-wide search hits (${lines.length})`;
  return (
    (head ? `<div class="group-notes-text">${escapeHtml(head)}</div>` : '') +
    `<details class="group-repo-hits">` +
    `<summary>${escapeHtml(summary)}</summary>` +
    `<ul class="repo-hits-list">${listItems}</ul>` +
    `</details>`
  );
}

function renderResults(data: { review?: FixReview; patches?: PatchGroup[]; scan_id?: string }) {
  const review = data.review || {};
  const patches = data.patches || [];

  document.getElementById('working')!.style.display = 'none';
  document.getElementById('events-panel')!.style.display = 'none';
  document.getElementById('fix-results')!.style.display = 'block';

  const statusEl = document.getElementById('review-status')!;
  if (review.approved) {
    statusEl.innerHTML = `<span class="status-approved">Patches Approved &amp; Conflict-Free</span>`;
  } else {
    statusEl.innerHTML = `<span class="status-warning">Review Needed</span>`;
  }
  document.getElementById('review-notes')!.textContent = review.notes || '';

  if (review.warnings && review.warnings.length > 0) {
    const wEl = document.getElementById('review-warnings')!;
    wEl.style.display = 'block';
    wEl.innerHTML = '<strong>Warnings:</strong><ul>' + review.warnings.map(w => `<li>${escapeHtml(w)}</li>`).join('') + '</ul>';
  }

  if (review.conflicts && review.conflicts.length > 0) {
    const cEl = document.getElementById('review-conflicts')!;
    cEl.style.display = 'block';
    cEl.innerHTML = '<strong>Conflicts:</strong><ul>' + review.conflicts.map(c => `<li>${escapeHtml(c)}</li>`).join('') + '</ul>';
  }

  const container = document.getElementById('groups-container')!;
  container.innerHTML = '';

  for (const group of patches) {
    const gCard = document.createElement('div');
    gCard.className = 'group-card';

    const head = document.createElement('div');
    head.className = 'group-header';
    const title = (group.group_label && group.group_label.trim()) || group.group_id;
    const sub =
      group.group_label && group.group_label.trim() && group.group_label.trim() !== group.group_id
        ? `<p class="group-id-sub">${escapeHtml(group.group_id)}</p>`
        : '';
    head.innerHTML =
      `<h3>${escapeHtml(title)}</h3>${sub}<div class="group-notes">${formatGroupNotes(group.notes || '')}</div>`;
    gCard.appendChild(head);

    const pList = group.patches || [];
    for (const p of pList) {
      const pItem = document.createElement('div');
      pItem.className = 'patch-item';
      const sanity =
        p.sanity_warnings && p.sanity_warnings.length > 0
          ? `<div class="patch-sanity"><strong>Sanity check:</strong><ul>${p.sanity_warnings
              .map((w) => `<li>${escapeHtml(w)}</li>`)
              .join('')}</ul></div>`
          : '';
      pItem.innerHTML = `
        <div class="patch-path">${escapeHtml(p.path)}</div>
        <div class="patch-explanation">${escapeHtml(p.explanation)}</div>
        ${sanity}
        <div class="diff-block">${formatDiff(p.diff)}</div>
      `;
      gCard.appendChild(pItem);
    }

    container.appendChild(gCard);
  }

  // Update "Back to Report" link with scan_id
  if (data.scan_id) {
    const backLink = document.getElementById('back-to-report') as HTMLAnchorElement | null;
    if (backLink) backLink.href = '/report/' + data.scan_id;
  }
}

async function poll() {
  let data: {
    status: string;
    scan_id?: string;
    events?: FixEvent[];
    error?: string;
    review?: FixReview;
    patches?: PatchGroup[];
  };
  try {
    const res = await fetch('/fix-status/' + FIX_ID);
    data = await res.json();
  } catch (_e) { return; }

  if (data.events) {
    renderEvents(data.events);
  }

  if (data.error) {
    const banner = document.getElementById('error-banner')!;
    banner.style.display = 'block';
    banner.textContent = 'Fix agent error: ' + data.error;
    document.getElementById('working')!.style.display = 'none';
    clearInterval(pollInterval);
    clearInterval(tickInterval);
    return;
  }

  // Update "Back to Report" link as soon as we know scan_id
  if (data.scan_id) {
    const backLink = document.getElementById('back-to-report') as HTMLAnchorElement | null;
    if (backLink && backLink.href.endsWith('#')) backLink.href = '/report/' + data.scan_id;
  }

  const working = document.getElementById('working-label')!;
  const st = document.getElementById('status-label')!;
  if (data.status === 'running') {
    if (st && st.textContent!.indexOf('Initializing') !== -1) {
      st.innerHTML = 'In progress <span class="elapsed" id="elapsed">0s</span>';
    }
    if (data.events && data.events.length) {
      const last = data.events[data.events.length - 1];
      const b = String(last.branch || 'fix');
      if (b === 'fix-planner') {
        working.textContent = 'Planning fix batches\u2026';
      } else if (b === 'fix-reviewer') {
        working.textContent = 'Reviewing generated patches\u2026';
      } else if (b === 'fix' && (last.text || '').indexOf('Loading') !== -1) {
        working.textContent = 'Loading scan context\u2026';
      } else {
        let short = b;
        while (short.startsWith('fix-')) short = short.slice(4);
        working.textContent = 'Generating patches \u2014 ' + short + '\u2026';
      }
    } else {
      working.textContent = 'Starting fix agent\u2026';
    }
  }

  if (data.status === 'done') {
    clearInterval(pollInterval);
    clearInterval(tickInterval);
    document.getElementById('status-label')!.innerHTML =
      'Complete <span class="elapsed">' +
      Math.round((Date.now() - startedAt) / 1000) + 's</span>';

    renderResults(data);
  }
}

poll();

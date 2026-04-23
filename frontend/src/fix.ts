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
}

interface PatchGroup {
  group_id: string;
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

function formatDiff(diffText: string): string {
  if (!diffText) return 'No diff available.';
  const lines = diffText.split('\n');
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
    head.innerHTML = `<h3>${escapeHtml(group.group_id)}</h3><p>${escapeHtml(group.notes || '')}</p>`;
    gCard.appendChild(head);

    const pList = group.patches || [];
    for (const p of pList) {
      const pItem = document.createElement('div');
      pItem.className = 'patch-item';
      pItem.innerHTML = `
        <div class="patch-path">${escapeHtml(p.path)}</div>
        <div class="patch-explanation">${escapeHtml(p.explanation)}</div>
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

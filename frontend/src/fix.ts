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
  const elapsedSeconds = Math.round((Date.now() - startedAt) / 1000);
  document.getElementById('elapsed')!.textContent = elapsedSeconds + 's';
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
  let normalized = diffText.replace(/\r\n/g, '\n');
  if (normalized.includes('\n')) {
    return normalized;
  }
  if (normalized.length < 40 || (!normalized.includes('@@') && !normalized.includes('---'))) {
    return normalized;
  }
  return normalized
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
  const lines = tail.split('\n').map((line) => line.trim()).filter(Boolean);
  const listItems = lines
    .map((line) => `<li><code class="repo-hit-line">${escapeHtml(line)}</code></li>`)
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
    wEl.innerHTML =
      '<strong>Warnings:</strong><ul>'
      + review.warnings.map(warning => `<li>${escapeHtml(warning)}</li>`).join('')
      + '</ul>';
  }

  if (review.conflicts && review.conflicts.length > 0) {
    const cEl = document.getElementById('review-conflicts')!;
    cEl.style.display = 'block';
    cEl.innerHTML =
      '<strong>Conflicts:</strong><ul>'
      + review.conflicts.map(conflict => `<li>${escapeHtml(conflict)}</li>`).join('')
      + '</ul>';
  }

  const container = document.getElementById('groups-container')!;
  container.innerHTML = '';

  for (const group of patches) {
    const groupCard = document.createElement('div');
    groupCard.className = 'group-card';

    const headerRow = document.createElement('div');
    headerRow.className = 'group-header';
    const title = (group.group_label && group.group_label.trim()) || group.group_id;
    const sub =
      group.group_label && group.group_label.trim() && group.group_label.trim() !== group.group_id
        ? `<p class="group-id-sub">${escapeHtml(group.group_id)}</p>`
        : '';
    headerRow.innerHTML =
      `<h3>${escapeHtml(title)}</h3>${sub}<div class="group-notes">${formatGroupNotes(group.notes || '')}</div>`;
    groupCard.appendChild(headerRow);

    const patchList = group.patches || [];
    for (const patch of patchList) {
      const patchItem = document.createElement('div');
      patchItem.className = 'patch-item';
      const sanity =
        patch.sanity_warnings && patch.sanity_warnings.length > 0
          ? `<div class="patch-sanity"><strong>Sanity check:</strong><ul>${patch.sanity_warnings
              .map((sanityWarning) => `<li>${escapeHtml(sanityWarning)}</li>`)
              .join('')}</ul></div>`
          : '';
      patchItem.innerHTML = `
        <div class="patch-path">${escapeHtml(patch.path)}</div>
        <div class="patch-explanation">${escapeHtml(patch.explanation)}</div>
        ${sanity}
        <div class="diff-block">${formatDiff(patch.diff)}</div>
      `;
      groupCard.appendChild(patchItem);
    }

    container.appendChild(groupCard);
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
  const statusLabel = document.getElementById('status-label')!;
  if (data.status === 'running') {
    if (statusLabel && statusLabel.textContent!.indexOf('Initializing') !== -1) {
      statusLabel.innerHTML = 'In progress <span class="elapsed" id="elapsed">0s</span>';
    }
    if (data.events && data.events.length) {
      const last = data.events[data.events.length - 1];
      const branchName = String(last.branch || 'fix');
      if (branchName === 'fix-planner') {
        working.textContent = 'Planning fix batches\u2026';
      } else if (branchName === 'fix-reviewer') {
        working.textContent = 'Reviewing generated patches\u2026';
      } else if (branchName === 'fix' && (last.text || '').indexOf('Loading') !== -1) {
        working.textContent = 'Loading scan context\u2026';
      } else {
        let shortBranch = branchName;
        while (shortBranch.startsWith('fix-')) shortBranch = shortBranch.slice(4);
        working.textContent = 'Generating patches \u2014 ' + shortBranch + '\u2026';
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

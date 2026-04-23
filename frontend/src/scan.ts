export {};

const SCAN_ID = window.location.pathname.replace(/\/$/, '').split('/').pop() || '';

interface ScanEvent {
  seq?: number;
  kind: string;
  branch?: string;
  t: string;
  text?: string;
}

interface BranchInfo {
  status?: string;
  tool_calls?: number;
  count?: number;
}

const startedAt = Date.now();
const pollInterval = setInterval(poll, 1200);
const tickInterval = setInterval(tick, 1000);
let lastSeq = 0;
const seenBranchChips = new Set(['all']);
let activeBranchFilter = 'all';
const allEvents: ScanEvent[] = [];

document.getElementById('filter-bar')!.addEventListener('click', (e: Event) => {
  const btn = (e.target as HTMLElement).closest('.filter-chip') as HTMLElement | null;
  if (!btn) return;
  activeBranchFilter = btn.dataset.branch || 'all';
  for (const c of document.querySelectorAll('.filter-chip')) {
    c.classList.toggle('active', (c as HTMLElement).dataset.branch === activeBranchFilter);
  }
  rerenderEvents();
});

function tick() {
  const s = Math.round((Date.now() - startedAt) / 1000);
  document.getElementById('elapsed')!.textContent = s + 's';
}

function renderRecon(profile: {
  stack?: string;
  summary?: string;
  has_iac?: boolean;
  has_cicd?: boolean;
  has_auth?: boolean;
  has_payments?: boolean;
  has_user_data?: boolean;
} | null) {
  if (!profile) return;
  const card = document.getElementById('recon-card')!;
  if (card.style.display !== 'none') return;
  card.style.display = 'block';
  document.getElementById('recon-stack')!.textContent = profile.stack || '';
  document.getElementById('recon-summary')!.textContent = profile.summary || '';
  const tags = document.getElementById('recon-tags')!;
  const flags: [string, boolean | undefined][] = [
    ['IaC', profile.has_iac], ['CI/CD', profile.has_cicd],
    ['Auth', profile.has_auth], ['Payments', profile.has_payments],
    ['User PII', profile.has_user_data],
  ];
  tags.innerHTML = flags.map(([l, on]) =>
    `<span class="recon-tag ${on ? 'on' : ''}">${l}: ${on ? 'yes' : 'no'}</span>`
  ).join('');
}

function ensureBranchChip(branch: string | undefined) {
  if (!branch || seenBranchChips.has(branch)) return;
  seenBranchChips.add(branch);
  const bar = document.getElementById('filter-bar')!;
  const btn = document.createElement('button');
  btn.className = 'filter-chip';
  btn.dataset.branch = branch;
  btn.textContent = branch;
  bar.appendChild(btn);
}

function eventMatchesFilter(ev: ScanEvent): boolean {
  if (activeBranchFilter === 'all') return true;
  return (ev.branch || 'outer') === activeBranchFilter;
}

function renderEventRow(ev: ScanEvent): HTMLDivElement {
  const row = document.createElement('div');
  row.className = 'event ' + ev.kind;
  const branch = ev.branch || 'outer';
  row.innerHTML =
    `<span class="t">${ev.t}s</span>` +
    `<span class="branch b-${branch}">${branch}</span>` +
    `<span class="kind">${ev.kind}</span>` +
    `<span class="msg"></span>`;
  row.querySelector('.msg')!.textContent = ev.text || '';
  return row;
}

function rerenderEvents() {
  const list = document.getElementById('events-list')!;
  list.innerHTML = '';
  for (const ev of allEvents) {
    if (eventMatchesFilter(ev)) list.appendChild(renderEventRow(ev));
  }
  list.scrollTop = list.scrollHeight;
}

function renderEvents(events: ScanEvent[]) {
  if (!events || events.length === 0) return;
  const list = document.getElementById('events-list')!;
  const atBottom = list.scrollTop + list.clientHeight >= list.scrollHeight - 20;
  for (const ev of events) {
    if (ev.seq && ev.seq <= lastSeq) continue;
    allEvents.push(ev);
    ensureBranchChip(ev.branch);
    if (eventMatchesFilter(ev)) list.appendChild(renderEventRow(ev));
  }
  if (atBottom) list.scrollTop = list.scrollHeight;
}

function renderBranches(branches: Record<string, BranchInfo>) {
  const keys = Object.keys(branches || {}).filter(k => k !== 'recon');
  if (keys.length === 0) return;
  document.getElementById('branches-panel')!.style.display = 'block';
  const grid = document.getElementById('branches-grid')!;
  grid.innerHTML = '';
  let runningCount = 0, doneCount = 0;
  const order = ['payments', 'iac', 'auth', 'cicd', 'general', 'synthesize'];
  const sorted = [...keys].sort(
    (a, b) => (order.indexOf(a) === -1 ? 99 : order.indexOf(a))
            - (order.indexOf(b) === -1 ? 99 : order.indexOf(b))
  );
  for (const name of sorted) {
    const b = branches[name];
    if (b.status === 'running') runningCount++;
    if (b.status === 'done') doneCount++;
    const card = document.createElement('div');
    card.className = `branch-card b-${b.status || 'pending'}`;
    const tools = b.tool_calls || 0;
    const findings = b.count || 0;
    const meta =
      b.status === 'done'
        ? `${findings} finding${findings !== 1 ? 's' : ''} \u00b7 ${tools} call${tools !== 1 ? 's' : ''}`
        : b.status === 'running'
          ? `${tools} call${tools !== 1 ? 's' : ''} so far`
          : 'pending';
    card.innerHTML =
      `<span class="b-name"><span class="b-dot"></span>${name}</span>` +
      `<span class="b-meta">${meta}</span>`;
    grid.appendChild(card);
  }
  document.getElementById('branches-counter')!.textContent =
    `${doneCount}/${keys.length} done` + (runningCount ? `, ${runningCount} running` : '');
}

async function poll() {
  let data: {
    status: string;
    last_seq?: number;
    events?: ScanEvent[];
    error?: string;
    repo_profile?: Parameters<typeof renderRecon>[0];
    branches?: Record<string, BranchInfo>;
  };
  try {
    const res = await fetch('/scan-status/' + SCAN_ID + '?since=' + lastSeq);
    data = await res.json();
  } catch (_e) { return; }

  if (typeof data.last_seq === 'number') {
    renderEvents(data.events || []);
    lastSeq = Math.max(lastSeq, data.last_seq);
  }

  if (data.error) {
    const banner = document.getElementById('error-banner')!;
    banner.style.display = 'block';
    banner.textContent = 'Scan error: ' + data.error;
    document.getElementById('working')!.style.display = 'none';
    clearInterval(pollInterval);
    clearInterval(tickInterval);
    return;
  }

  renderRecon(data.repo_profile || null);
  renderBranches(data.branches || {});

  const working = document.getElementById('working-label')!;
  if (data.status === 'running') {
    const branches = data.branches || {};
    const total = Object.keys(branches).length;
    const running = Object.values(branches).filter(b => b.status === 'running').length;
    const done = Object.values(branches).filter(b => b.status === 'done').length;
    const totalCalls = Object.values(branches).reduce((a, b) => a + (b.tool_calls || 0), 0);
    if (!data.repo_profile) {
      working.textContent = 'Recon agent exploring the repo\u2026';
    } else if (total === 0) {
      working.textContent = 'Routing to specialist branches\u2026';
    } else if (running > 0) {
      working.textContent =
        `${running} specialist${running !== 1 ? 's' : ''} running in parallel ` +
        `\u00b7 ${done}/${total} done \u00b7 ${totalCalls} tool call${totalCalls !== 1 ? 's' : ''}`;
    } else if (done > 0 && done < total) {
      working.textContent = `Waiting on remaining branches\u2026 ${done}/${total} done`;
    } else if (done === total && total > 0) {
      working.textContent = 'Synthesizing final report\u2026';
    } else {
      working.textContent = 'Working\u2026';
    }
  }

  if (data.status === 'done') {
    clearInterval(pollInterval);
    clearInterval(tickInterval);
    document.getElementById('working')!.style.display = 'none';
    document.getElementById('status-label')!.innerHTML =
      'Complete \u2014 building report\u2026 <span class="elapsed">' +
      Math.round((Date.now() - startedAt) / 1000) + 's</span>';
    setTimeout(() => { window.location.href = '/report/' + SCAN_ID; }, 600);
  }
}

poll();

const STORAGE_KEY = 'ramn-ctf-state';

let state = {
  capturedFlags: [],
};

// Ephemeral, in-memory only — never persisted, so revealed write-ups collapse
// again on refresh. Kept out of `state` so it can't leak into saveState().
const revealedFullSolutions = new Set();

function loadState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const saved = JSON.parse(raw);
    if (Array.isArray(saved.capturedFlags)) state.capturedFlags = saved.capturedFlags;
    if (typeof saved.selectedEventId === 'string') selectedEventId = saved.selectedEventId;
  } catch (_) {}
}

function saveState() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    capturedFlags: state.capturedFlags,
    selectedEventId,
  }));
}

// Render markdown to HTML, with a graceful fallback if the vendored parser
// failed to load (so the detail pane never goes blank).
function renderMarkdown(src) {
  if (typeof marked !== 'undefined' && marked.parse) return marked.parse(src || '');
  const div = document.createElement('div');
  div.textContent = src || '';
  return div.innerHTML.replace(/\n/g, '<br>');
}

// Mermaid: turn ```mermaid fenced blocks (rendered by marked as
// <pre><code class="language-mermaid">) into diagrams. No-ops gracefully if the
// mermaid library hasn't loaded yet (it loads async as an ES module).
let _mermaidInit = false;
function ensureMermaid() {
  if (typeof mermaid === 'undefined') return false;
  if (!_mermaidInit) {
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: 'strict',
      theme: 'dark',
      themeVariables: {
        background: '#1a1d27',
        primaryColor: '#232638',
        primaryBorderColor: '#2e3250',
        primaryTextColor: '#e2e4f0',
        secondaryColor: '#1a1d27',
        lineColor: '#8890b0',
        fontFamily: "'Cascadia Code', 'Fira Code', 'Consolas', monospace",
      },
    });
    _mermaidInit = true;
  }
  return true;
}

function renderDiagrams(container) {
  if (!ensureMermaid()) return;
  const blocks = container.querySelectorAll('code.language-mermaid');
  blocks.forEach(code => {
    const div = document.createElement('div');
    div.className = 'mermaid';
    div.textContent = code.textContent;
    (code.closest('pre') || code).replaceWith(div);
  });
  if (blocks.length) {
    try { mermaid.run({ querySelector: '.mermaid', suppressErrors: true }); } catch (_) {}
  }
}

function findChallenge(id) {
  for (const event of CTF_EVENTS) {
    const c = event.challenges.find(ch => ch.id === id);
    if (c) return c;
  }
  return null;
}

function isCaptured(id) { return state.capturedFlags.includes(id); }
function isFullRevealed(id) { return revealedFullSolutions.has(id); }

function totalFlags() {
  return CTF_EVENTS.reduce((s, e) => s + e.challenges.length, 0);
}

function capturedInEvent(event) {
  return event.challenges.filter(c => isCaptured(c.id)).length;
}

// ── Sidebar ──────────────────────────────────────────────────────────────────

let selectedEventId = null;

function renderSidebar() {
  const sidebar = document.getElementById('event-sidebar');
  const total = totalFlags();
  const captured = state.capturedFlags.length;

  sidebar.innerHTML = '';

  const globalBar = document.createElement('div');
  globalBar.className = 'global-score';
  globalBar.innerHTML = `
    <span class="score-label">Total score</span>
    <span class="score-count">${captured} / ${total}</span>
    <div class="progress-bar"><div class="progress-fill" style="width:${total ? (captured/total*100) : 0}%"></div></div>
    <button class="reset-progress-btn" id="reset-progress-btn" title="Reset all progress">Reset progress</button>
  `;
  sidebar.appendChild(globalBar);
  document.getElementById('reset-progress-btn').addEventListener('click', () => {
    if (confirm('Reset all progress? This will clear all captured flags.')) {
      state = { capturedFlags: [] };
      revealedFullSolutions.clear();
      saveState();
      renderSidebar();
      renderDetail();
    }
  });

  CTF_EVENTS.forEach(event => {
    const n = event.challenges.length;
    const c = capturedInEvent(event);
    const pct = n ? (c / n * 100) : 0;
    const btn = document.createElement('button');
    btn.className = 'event-btn' + (event.id === selectedEventId ? ' active' : '');
    btn.dataset.id = event.id;
    btn.innerHTML = `
      <div class="event-name">${event.name}</div>
      <div class="event-meta">
        <span class="event-year">${event.year}</span>
        <span class="event-score">${c}/${n}</span>
      </div>
      <div class="progress-bar"><div class="progress-fill" style="width:${pct}%"></div></div>
    `;
    btn.addEventListener('click', () => selectEvent(event.id));
    sidebar.appendChild(btn);
  });
}

function selectEvent(id) {
  selectedEventId = id;
  saveState();
  renderSidebar();
  renderDetail();
}

// ── Detail pane ───────────────────────────────────────────────────────────────

function renderDetail() {
  const pane = document.getElementById('event-detail');
  if (!selectedEventId) {
    pane.innerHTML = '<p class="placeholder">Select an event from the sidebar.</p>';
    return;
  }
  const event = CTF_EVENTS.find(e => e.id === selectedEventId);
  if (!event) return;

  const flashUrl = `${FLASHER_URL}/?ctf=${encodeURIComponent(event.id)}#update`;

  let html = `
    <div class="event-header">
      <div class="event-title-row">
        <h2>${event.name}</h2>
        <a href="${flashUrl}" target="_blank" class="flash-btn">Flash firmware ↗</a>
      </div>
      <div>
        <span class="difficulty-label">${event.difficulty}</span>
        <span class="flag-format-label">Flag format: <code>${event.flagFormat}</code></span>
      </div>
    </div>
  `;

  let overviewCaptured = 0;
  const chips = event.challenges.map(c => {
    const cap = isCaptured(c.id);
    if (cap) overviewCaptured++;
    return `<button class="overview-chip${cap ? ' captured' : ''}" data-action="scrollTo" data-id="${c.id}">
      <span class="overview-chip-icon">${cap ? '✓' : '□'}</span>${c.title}
    </button>`;
  }).join('');
  html += `
    <div class="challenge-overview">
      <div class="challenge-overview-head">
        <span class="challenge-overview-title">Challenges</span>
        <span class="challenge-overview-count">${overviewCaptured} / ${event.challenges.length} captured</span>
      </div>
      <div class="challenge-overview-chips">${chips}</div>
    </div>
    <div class="challenges-list">
  `;

  event.challenges.forEach(challenge => {
    html += renderChallenge(challenge);
  });

  html += '</div>';
  pane.innerHTML = html;

  // Attach event listeners after DOM is set
  pane.querySelectorAll('[data-action]').forEach(el => {
    el.addEventListener('click', handleAction);
  });
  pane.querySelectorAll('form.flag-form').forEach(form => {
    form.addEventListener('submit', handleFlagSubmit);
  });

  renderDiagrams(pane);
}

function renderChallenge(challenge) {
  const captured = isCaptured(challenge.id);
  const fullSolutionShown = isFullRevealed(challenge.id);

  const tagPills = challenge.tags.map(t => `<span class="tag">${t}</span>`).join('');
  const statusIcon = captured ? '<span class="status-icon captured" title="Flag captured">✓</span>' : '<span class="status-icon" title="Not yet captured">□</span>';
  const ecuLabel = challenge.ecu === 'FILE' ? 'FILE' : `ECU ${challenge.ecu}`;

  let descHtml = renderMarkdown(challenge.description || '');

  // Attachments
  let attachHtml = '';
  if (challenge.attachments && challenge.attachments.length > 0) {
    const links = challenge.attachments.map(a =>
      `<a class="attachment-link" href="${a.url}" target="_blank" rel="noopener">📎 ${a.name}</a>`
    ).join('');
    attachHtml = `<div class="attachments-area">${links}</div>`;
  }

  // Sources / citations
  let sourcesHtml = '';
  const srcs = (typeof CHALLENGE_SOURCES !== 'undefined' && CHALLENGE_SOURCES[challenge.id]) || [];
  if (srcs.length) {
    const links = srcs.map(s =>
      `<a class="source-link" href="${s.url}" target="_blank" rel="noopener">${s.name} ↗</a>`
    ).join('');
    sourcesHtml = `<div class="sources-area"><span class="sources-label">Sources</span>${links}</div>`;
  }

  // Full write-up
  let fullSolutionHtml = '';
  if (challenge.fullSolution) {
    if (fullSolutionShown) {
      fullSolutionHtml = `<div class="full-solution-block"><div class="full-solution-label">Full Write-up</div>${renderMarkdown(challenge.fullSolution)}${sourcesHtml}</div>`;
    } else {
      fullSolutionHtml = `<button class="full-solution-btn" data-action="fullSolution" data-id="${challenge.id}">Show Full Solution</button>`;
    }
  }

  // Flag input
  let flagHtml = '';
  if (captured) {
    flagHtml = `<div class="flag-captured"><span class="captured-check">✓</span> Flag captured: <code>${challenge.flag}</code></div>`;
  } else {
    flagHtml = `
      <form class="flag-form" data-id="${challenge.id}">
        <input type="text" class="flag-input" placeholder="${challenge.flagFormat || 'flag{...}'}" autocomplete="off" spellcheck="false">
        <button type="submit" class="submit-btn">Submit</button>
        <span class="flag-error" aria-live="polite"></span>
      </form>
    `;
  }

  return `
    <div class="challenge-card${captured ? ' captured' : ''}" id="challenge-${challenge.id}">
      <div class="challenge-header">
        <div class="challenge-title-row">
          ${statusIcon}
          <h3 class="challenge-title">${challenge.title}</h3>
          <span class="ecu-badge">${ecuLabel}</span>
          ${tagPills}
          <span class="difficulty-badge difficulty-${challenge.difficulty.toLowerCase().replace(/\//g, '-').replace(/\s+/g, '-')}">${challenge.difficulty}</span>
        </div>
      </div>
      <div class="challenge-body">
        <div class="description">${descHtml}</div>
        ${attachHtml}
        <div class="full-solution-area">${fullSolutionHtml}</div>
        <div class="flag-area">${flagHtml}</div>
      </div>
    </div>
  `;
}

function handleAction(e) {
  const action = e.currentTarget.dataset.action;
  const id = e.currentTarget.dataset.id;
  if (action === 'scrollTo') {
    document.getElementById('challenge-' + id)
      ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    return;
  }
  if (action === 'fullSolution') {
    revealedFullSolutions.add(id);
  }
  renderDetail();
}

function handleFlagSubmit(e) {
  e.preventDefault();
  const id = e.currentTarget.dataset.id;
  const input = e.currentTarget.querySelector('.flag-input');
  const errorEl = e.currentTarget.querySelector('.flag-error');
  const submitted = input.value.trim();

  const challenge = findChallenge(id);
  if (!challenge) return;

  if (submitted === challenge.flag) {
    if (!state.capturedFlags.includes(id)) {
      state.capturedFlags.push(id);
      saveState();
    }
    renderSidebar();
    renderDetail();
  } else {
    errorEl.textContent = 'Incorrect flag.';
    input.classList.add('shake');
    setTimeout(() => {
      input.classList.remove('shake');
      errorEl.textContent = '';
    }, 600);
  }
}

function initPortal() {
  loadState();
  // Mermaid loads asynchronously as an ES module; re-render once it's ready so
  // diagrams in any already-visible solution get drawn.
  window.addEventListener('mermaid-ready', () => { if (selectedEventId) renderDetail(); });
  renderSidebar();
  const savedExists = selectedEventId && CTF_EVENTS.some(e => e.id === selectedEventId);
  if (savedExists) {
    selectEvent(selectedEventId);
  } else if (CTF_EVENTS.length > 0) {
    selectEvent(CTF_EVENTS[0].id);
  } else {
    document.getElementById('event-detail').innerHTML = '<p class="placeholder">No events found.</p>';
  }
}

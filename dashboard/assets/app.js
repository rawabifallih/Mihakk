// The dashboard.
//
// Two rules govern every line here.
//
// Nothing from the API becomes markup. Every value reaches the page through
// textContent or setAttribute on an element this file created. There is no
// innerHTML, no insertAdjacentHTML, no document.write, no eval and no string
// passed to setTimeout -- a structural test refuses them, because the engine's
// indicator reason embeds bytes taken from the target's own response body and
// the request summary carries the mutated payload. Escaping would be a second
// chance to get right what not building markup avoids entirely.
//
// Nothing is judged here. Completeness and confidence come from the orchestrator
// and are displayed as they arrived. This file does not recompute them, soften
// them, or colour by severity: a low-confidence timing observation is not drawn
// as an emergency, and "confidence" means confidence in the observation, never
// how bad it would be.
//
// There are no dependencies. The charts are SVG elements built by hand, so the
// page loads nothing from anywhere and the project keeps building offline.

'use strict';

// The CSRF token lives here and nowhere else: not in storage, not in a URL, not
// in this file. Fetched after load, held for the page's lifetime.
let csrfToken = null;

// The operator's uploaded inputs, held only while they are needed for the review
// and the submit. Clearing this drops our references and what the page shows; it
// is not a guarantee that the bytes are gone from the browser's memory.
let pending = null;

let refreshTimer = null;
let lastGoodFetch = null;
let currentSessionId = null;

const REFRESH_MS = 3000;
const STALE_AFTER_MS = 10000;

// --- DOM helpers -------------------------------------------------------------
// The only way anything reaches the page.

function el(tag, opts) {
  const node = document.createElement(tag);
  if (!opts) return node;
  if (opts.className) node.className = opts.className;
  if (opts.text !== undefined && opts.text !== null) node.textContent = String(opts.text);
  if (opts.attrs) {
    for (const [key, value] of Object.entries(opts.attrs)) {
      node.setAttribute(key, String(value));
    }
  }
  if (opts.children) {
    for (const child of opts.children) if (child) node.appendChild(child);
  }
  return node;
}

function svg(tag, attrs) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    node.setAttribute(key, String(value));
  }
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

// Dropping `pending` releases what this code holds, but a file input keeps its own
// reference to the chosen file until it is reset -- so the uploads are cleared too.
// Neither is a guarantee that the bytes have left the browser's memory; it removes
// the references and what the page is showing.
function clearUploads() {
  for (const id of ['config-file', 'corpus-file', 'openapi-file']) {
    const input = document.getElementById(id);
    if (input) input.value = '';
  }
}

// What became of the requests, in words that claim no more than was seen:
// refused (nothing left), attempted (let through -- a refused connection is an
// attempt), answered (a response was observed). The judgements are the
// backend's (app/delivery.py), never worked out here.
const DELIVERY_LABELS = {
  none_attempted: 'nothing attempted',
  partly_refused: 'partly refused',
  none_refused: 'attempted',
  unknown: 'unknown',
};
const RESPONSE_LABELS = {
  none_answered: 'no response',
  partly_answered: 'partly answered',
  all_answered: 'answered',
  not_applicable: '',
  unknown: 'responses unknown',
};
const DELIVERY_TITLES = {
  none_attempted: 'Nothing was attempted against the target',
  partly_refused: 'Part of this session was refused before sending',
  unknown: 'Whether anything was attempted is unknown',
};
const RESPONSE_TITLES = {
  none_answered: 'No response was observed from the target',
  partly_answered: 'Some requests got no response',
  unknown: 'Whether the target answered is unknown',
};

function known(table, value) {
  return Object.prototype.hasOwnProperty.call(table, value) ? value : 'unknown';
}
function deliveryVerdict(delivery) { return known(DELIVERY_LABELS, delivery && delivery.verdict); }
function deliveryResponses(delivery) { return known(RESPONSE_LABELS, delivery && delivery.responses); }

function row(label, value) {
  return el('tr', { children: [
    el('th', { text: label }),
    el('td', { children: [el('code', { text: value === null || value === undefined ? '—' : value })] }),
  ] });
}

// --- the API -----------------------------------------------------------------

async function api(path, options) {
  const opts = Object.assign({ headers: {} }, options || {});
  opts.credentials = 'same-origin';
  if (opts.method && opts.method !== 'GET') {
    opts.headers['X-Mihakk-CSRF'] = csrfToken || '';
    opts.headers['Content-Type'] = 'application/json';
  }
  const response = await fetch(path, opts);
  if (response.status === 401) {
    window.location.assign('/auth/login');
    throw new Error('the session has ended');
  }
  return response;
}

async function apiJson(path, options) {
  const response = await api(path, options);
  let body = null;
  try {
    body = await response.json();
  } catch (err) {
    body = null;
  }
  if (!response.ok) {
    const detail = body && body.detail ? body.detail : ('request failed (' + response.status + ')');
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  return body;
}

// --- staleness ---------------------------------------------------------------
// A dashboard that quietly stops updating is worse than one that says it has.

function markFresh() {
  lastGoodFetch = Date.now();
  paintStaleness(null);
}

function paintStaleness(message) {
  const node = document.getElementById('staleness');
  if (!node) return;
  if (message) {
    node.dataset.state = 'stale';
    node.textContent = message;
    return;
  }
  if (lastGoodFetch === null) {
    node.dataset.state = 'fresh';
    node.textContent = '';
    return;
  }
  const age = Date.now() - lastGoodFetch;
  if (age > STALE_AFTER_MS) {
    node.dataset.state = 'stale';
    node.textContent = 'Not updating — last successful update '
      + Math.round(age / 1000) + 's ago';
  } else {
    node.dataset.state = 'fresh';
    node.textContent = 'Updated ' + Math.round(age / 1000) + 's ago';
  }
}

function showState(id, kind, message) {
  const node = document.getElementById(id);
  if (!node) return;
  clear(node);
  if (!kind) { node.dataset.kind = ''; return; }
  node.dataset.kind = kind;
  node.appendChild(el('p', { text: message }));
}

// --- the session list --------------------------------------------------------

async function loadSessions() {
  showState('sessions-state', 'loading', 'Loading sessions…');
  let body;
  try {
    body = await apiJson('/v1/sessions');
  } catch (err) {
    showState('sessions-state', 'error', 'Could not load sessions: ' + err.message);
    paintStaleness('Not updating — the last request failed');
    return;
  }
  markFresh();

  const sessions = (body && body.sessions) || [];
  const tbody = document.getElementById('sessions-body');
  clear(tbody);

  if (sessions.length === 0) {
    showState('sessions-state', 'empty',
      'No sessions yet. Start one below with a configuration you wrote.');
    return;
  }
  showState('sessions-state', null);

  for (const session of sessions) {
    const complete = session.completeness && session.completeness.complete === true;
    const open = el('button', { text: 'Open', attrs: { type: 'button' } });
    open.addEventListener('click', () => showDetail(session.session_id));

    const stop = el('button', { text: 'Stop', attrs: { type: 'button' } });
    stop.addEventListener('click', () => stopSession(session.session_id));

    tbody.appendChild(el('tr', { children: [
      el('td', { children: [el('code', { text: session.session_id })] }),
      el('td', { children: [el('span', {
        text: session.status, className: 'status', attrs: { 'data-status': session.status },
      })] }),
      el('td', { text: session.findings === undefined ? '—' : session.findings }),
      // The backend's verdict, shown as it arrived. Never recomputed here.
      el('td', { children: [el('span', {
        text: complete ? 'complete' : 'incomplete',
        className: 'completeness',
        attrs: { 'data-complete': complete ? 'true' : 'false' },
      })] }),
      el('td', { children: [el('span', {
        text: [DELIVERY_LABELS[deliveryVerdict(session.delivery)],
               RESPONSE_LABELS[deliveryResponses(session.delivery)]].filter(Boolean).join(', '),
        className: 'delivery',
        attrs: { 'data-delivery': deliveryVerdict(session.delivery),
                 'data-responses': deliveryResponses(session.delivery) },
      })] }),
      el('td', { children: [open, session.status === 'running' ? stop : null] }),
    ] }));
  }
}

async function stopSession(sessionId) {
  try {
    await apiJson('/v1/sessions/' + encodeURIComponent(sessionId) + '/stop',
      { method: 'POST' });
  } catch (err) {
    showState('sessions-state', 'error', 'Could not stop the session: ' + err.message);
    return;
  }
  await loadSessions();
}

// --- one session -------------------------------------------------------------

async function showDetail(sessionId) {
  currentSessionId = sessionId;
  document.getElementById('list-view').hidden = true;
  document.getElementById('detail-view').hidden = false;
  const title = document.getElementById('detail-title');
  clear(title);
  title.appendChild(el('code', { text: sessionId }));
  await refreshDetail();
}

function showList() {
  currentSessionId = null;
  document.getElementById('detail-view').hidden = true;
  document.getElementById('list-view').hidden = false;
  loadSessions();
}

async function refreshDetail() {
  if (!currentSessionId) return;
  const id = encodeURIComponent(currentSessionId);
  showState('detail-state', 'loading', 'Loading…');

  let view, report, events;
  try {
    view = await apiJson('/v1/sessions/' + id);
  } catch (err) {
    showState('detail-state', 'error', 'Could not load the session: ' + err.message);
    paintStaleness('Not updating — the last request failed');
    return;
  }

  try {
    events = await apiJson('/v1/sessions/' + id + '/events?limit=2000');
  } catch (err) {
    events = null;
  }

  let reportError = null;
  try {
    report = await apiJson('/v1/sessions/' + id + '/report');
  } catch (err) {
    // A refused report is a result in itself: the aggregate contradicted
    // itself, and showing an empty page would look like a clean run.
    report = null;
    reportError = err.message;
  }

  markFresh();
  showState('detail-state', null);
  paintDetail(view, report, reportError, events);
}

function paintDetail(view, report, reportError, events) {
  const body = document.getElementById('detail-body');
  clear(body);

  // First, because it decides what everything below can mean.
  body.appendChild(deliveryPanel(view, report));
  body.appendChild(completenessPanel(view, report));
  body.appendChild(scopePanel(report));

  if (reportError) {
    body.appendChild(el('div', { className: 'banner', attrs: { 'data-kind': 'error' },
      children: [
        el('strong', { text: 'No report was produced' }),
        el('p', { text: reportError }),
      ] }));
  }

  body.appendChild(progressPanel(view, events));
  body.appendChild(distributionPanel(report));
  body.appendChild(reportLinks());
  body.appendChild(filtersPanel());
  body.appendChild(groupsPanel(report));
  applyFilters();
}

function deliveryPanel(view, report) {
  // The report's account is the engine's final record; the session view's is the
  // latest progress event, which is all there is while a run is going.
  const d = (report && report.delivery) || view.delivery || {};
  const verdict = deliveryVerdict(d);
  const responses = deliveryResponses(d);
  const children = [el('h3', { text: 'What became of the requests' })];
  const message = d.message || 'The engine did not report what became of the requests.';
  const title = DELIVERY_TITLES[verdict] || RESPONSE_TITLES[responses];
  if (title) {
    children.push(el('div', { className: 'banner', attrs: { 'data-kind': 'warning' },
      children: [el('strong', { text: title }), el('p', { text: message })] }));
  } else {
    children.push(el('p', { text: message }));
  }
  const shown = (v) => (typeof v === 'number' ? v : 'unknown');
  const cases = d.cases || {}, baseline = d.baseline || {}, http = d.http_requests || {};
  // Two units, two tables: a redirected case is one case and several requests.
  children.push(el('table', { attrs: { id: 'delivery-cases' }, children: [
    el('caption', { text: 'Cases (the plan\'s cases, and the baseline\'s requests)' }),
    el('thead', { children: [el('tr', { children: [
      el('th', { text: '' }), el('th', { text: 'Attempted' }),
      el('th', { text: 'Ended in local refusal' }), el('th', { text: 'Final response observed' }),
    ] })] }),
    el('tbody', { children: [cases, baseline].map((block, i) => el('tr', { children: [
      el('th', { text: i === 0 ? 'Cases' : 'Baseline' }),
      el('td', { text: String(shown(block.attempted)) }),
      el('td', { text: String(shown(block.refused)) }),
      el('td', { text: String(shown(block.answered)) }),
    ] })) }),
  ] }));
  children.push(el('table', { attrs: { id: 'delivery-http' }, children: [
    el('caption', { text: 'HTTP requests (one per redirect hop)' }),
    el('tbody', { children: [
      row('Response observed', shown(http.answered)),
      row('Attempted, no response', shown(http.unanswered)),
      row('Refused at connect (not sent)', shown(http.refused)),
    ] }),
  ] }));
  return el('section', { className: 'panel',
    attrs: { id: 'delivery-panel', 'data-delivery': verdict, 'data-responses': responses },
    children });
}

function completenessPanel(view, report) {
  // Taken from the report when it exists, and from the session view otherwise.
  // Either way it is the backend's answer, not one worked out here.
  const c = (report && report.completeness) || view.completeness || {};
  const complete = c.complete === true;

  const children = [
    el('h3', { text: 'Completeness' }),
    el('p', { className: 'verdict', attrs: { 'data-complete': complete ? 'true' : 'false' },
      text: complete
        ? 'Complete result set — the stored events run unbroken and the engine recorded everything it observed.'
        : 'Incomplete result set' }),
  ];

  if (!complete) {
    children.push(el('p', { className: 'warning',
      text: c.warning || 'This result set is a subset of what the run produced. '
        + 'Absence of a finding here does not mean the engine did not observe one.' }));
    const reasons = el('ul');
    for (const entry of c.reasons || []) {
      const side = entry.side === 'orchestrator' ? 'The orchestrator' : 'The engine';
      reasons.appendChild(el('li', { text: side + ': ' + entry.reason }));
    }
    if ((c.reasons || []).length) children.push(reasons);
  }

  if (c.stopped_early) {
    children.push(el('p', { className: 'warning', text: c.stopped_note || 'The run was stopped early.' }));
  }

  return el('section', { className: 'panel', attrs: { id: 'completeness-panel' }, children });
}

function scopePanel(report) {
  const scope = (report && report.scope) || null;
  if (!scope) {
    return el('section', { className: 'panel', children: [
      el('h3', { text: 'Scope' }),
      el('p', { text: 'No scope information is available for this session.' }),
    ] });
  }

  const children = [el('h3', { text: scope.title || 'Scope' })];
  if (scope.trustworthy !== true) {
    children.push(el('div', { className: 'banner', attrs: { 'data-kind': 'warn' }, children: [
      el('strong', { text: 'This is not an established description of what the run was allowed to reach' }),
      el('p', { text: scope.reason || 'The scope could not be established.' }),
    ] }));
  }

  const summary = el('ul');
  for (const target of scope.targets_summary || []) {
    summary.appendChild(el('li', { children: [el('code', { text: target })] }));
  }
  if ((scope.targets_summary || []).length) {
    children.push(el('h4', { text: 'Target authorities' }));
    children.push(summary);
  }

  if ((scope.targets || []).length) {
    const tbody = el('tbody');
    for (const target of scope.targets) {
      tbody.appendChild(el('tr', { children: [
        el('td', { text: target.scheme }),
        el('td', { text: target.host }),
        el('td', { text: target.port }),
        el('td', { text: (target.path_prefixes || []).join(', ') }),
        el('td', { text: (target.methods || []).join(', ') }),
      ] }));
    }
    children.push(el('h4', { text: 'Authorised requests' }));
    children.push(el('table', { children: [
      el('thead', { children: [el('tr', { children: [
        el('th', { text: 'Scheme' }), el('th', { text: 'Host' }), el('th', { text: 'Port' }),
        el('th', { text: 'Path prefixes' }), el('th', { text: 'Methods' }),
      ] })] }),
      tbody,
    ] }));
  }

  if ((scope.withheld || []).length) {
    children.push(el('p', { className: 'sub',
      text: 'Withheld from this view: ' + scope.withheld.join(', ')
        + '. The digest covers the full scope including what is withheld.' }));
  }
  return el('section', { className: 'panel', attrs: { id: 'scope-panel' }, children });
}

// --- charts ------------------------------------------------------------------
// Counts drawn as counts. No severity encoding, no colour that implies a verdict
// the backend did not give: one neutral fill for every bar, and the numbers
// printed beside them so the drawing is never the only source.

function progressPanel(view, events) {
  // HTTP requests ATTEMPTED over time, one per redirect hop: the unit the budget
  // is charged in. Not cases -- a redirected case is several requests -- and not
  // requests_used, which also charges attempts the address check then refused.
  // Attempted is not delivered; how many got a response is stated beside it.
  const children = [el('h3', { text: 'HTTP requests attempted over time (each redirect hop counts)' })];
  const points = [];
  let last = null;
  for (const event of (events && events.events) || []) {
    if (event.type !== 'progress') continue;
    const p = event.progress || {};
    if (typeof p.http_answered !== 'number' || typeof p.http_unanswered !== 'number'
        || typeof p.elapsed_ms !== 'number') continue;
    points.push({ x: p.elapsed_ms, y: p.http_answered + p.http_unanswered });
    last = p;
  }

  if (points.length < 2) {
    children.push(el('p', { className: 'sub', text: last
      ? 'Not enough progress events yet to draw a line.'
      : 'The engine did not report HTTP request counts for this session, so none is drawn.' }));
    const c = view.completeness || {};
    children.push(el('p', { text: 'Events stored: ' + (c.events_received === undefined ? '—' : c.events_received) }));
    return el('section', { className: 'panel', attrs: { id: 'progress-panel' }, children });
  }

  const width = 640, height = 180, pad = 32;
  const maxX = Math.max.apply(null, points.map(p => p.x)) || 1;
  const maxY = Math.max.apply(null, points.map(p => p.y)) || 1;
  const chart = svg('svg', {
    viewBox: '0 0 ' + width + ' ' + height, width: '100%', height: height,
    role: 'img', 'aria-label': 'HTTP requests attempted over elapsed time, redirect hops included',
  });
  chart.appendChild(svg('line', {
    x1: pad, y1: height - pad, x2: width - pad, y2: height - pad, class: 'axis',
  }));
  chart.appendChild(svg('line', { x1: pad, y1: pad, x2: pad, y2: height - pad, class: 'axis' }));

  let d = '';
  points.sort((a, b) => a.x - b.x);
  points.forEach((point, index) => {
    const x = pad + (point.x / maxX) * (width - 2 * pad);
    const y = (height - pad) - (point.y / maxY) * (height - 2 * pad);
    d += (index === 0 ? 'M' : 'L') + x.toFixed(1) + ' ' + y.toFixed(1) + ' ';
  });
  chart.appendChild(svg('path', { d: d.trim(), class: 'series' }));
  children.push(chart);
  const casesAttempted = (last.attempted || 0) + (last.baseline_attempted || 0);
  children.push(el('p', { className: 'sub', attrs: { id: 'progress-summary' },
    text: points[points.length - 1].y + ' HTTP request(s) attempted after '
      + Math.round(maxX / 1000) + 's: ' + last.http_answered + ' with a response, '
      + last.http_unanswered + ' without; ' + (last.http_refused || 0)
      + ' refused at connect. ' + casesAttempted + ' case(s) attempted, baseline included.' }));
  return el('section', { className: 'panel', attrs: { id: 'progress-panel' }, children });
}

function distributionPanel(report) {
  const children = [el('h3', { text: 'Indicators by type' })];
  const counts = new Map();
  for (const group of (report && report.groups) || []) {
    const type = (group.signature && group.signature.indicator_type) || 'unknown';
    counts.set(type, (counts.get(type) || 0) + (group.occurrences || 0));
  }

  if (counts.size === 0) {
    children.push(el('p', { className: 'sub', text: 'No indicators to distribute.' }));
    return el('section', { className: 'panel', attrs: { id: 'distribution-panel' }, children });
  }

  const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  const max = entries[0][1] || 1;
  const barHeight = 24, gap = 8, labelWidth = 170, width = 640;
  const height = entries.length * (barHeight + gap) + gap;
  const chart = svg('svg', {
    viewBox: '0 0 ' + width + ' ' + height, width: '100%', height: height,
    role: 'img', 'aria-label': 'Count of indicator instances by type',
  });

  entries.forEach((entry, index) => {
    const [type, count] = entry;
    const y = gap + index * (barHeight + gap);
    const barWidth = Math.max(1, (count / max) * (width - labelWidth - 60));
    const label = svg('text', { x: 0, y: y + barHeight * 0.7, class: 'bar-label' });
    label.textContent = type;
    chart.appendChild(label);
    // One neutral fill for every bar: the count is the fact, and a palette that
    // reddened some of them would assert a severity nothing here established.
    chart.appendChild(svg('rect', {
      x: labelWidth, y: y, width: barWidth, height: barHeight, class: 'bar',
    }));
    const value = svg('text', {
      x: labelWidth + barWidth + 8, y: y + barHeight * 0.7, class: 'bar-value',
    });
    value.textContent = String(count);
    chart.appendChild(value);
  });

  children.push(chart);
  children.push(el('p', { className: 'sub',
    text: 'Counts of indicator instances. Size is count, not severity.' }));
  return el('section', { className: 'panel', attrs: { id: 'distribution-panel' }, children });
}

function reportLinks() {
  const id = encodeURIComponent(currentSessionId);
  const json = el('a', { text: 'JSON report',
    attrs: { href: '/v1/sessions/' + id + '/report?format=json' } });
  const html = el('a', { text: 'HTML report',
    attrs: { href: '/v1/sessions/' + id + '/report?format=html', target: '_blank',
             rel: 'noopener noreferrer' } });
  return el('section', { className: 'panel', attrs: { id: 'report-links' }, children: [
    el('h3', { text: 'Reports' }),
    el('p', { children: [json, el('span', { text: ' · ' }), html] }),
  ] });
}

// --- filters -----------------------------------------------------------------

function filtersPanel() {
  const endpoint = el('input', { attrs: { type: 'search', id: 'filter-endpoint',
    placeholder: 'any endpoint' } });
  const type = el('select', { attrs: { id: 'filter-type' } });
  const confidence = el('select', { attrs: { id: 'filter-confidence' } });

  type.appendChild(el('option', { text: 'any type', attrs: { value: '' } }));
  for (const value of ['http_5xx', 'app_error_pattern', 'timeout',
                       'connection_error', 'latency_anomaly', 'size_anomaly']) {
    type.appendChild(el('option', { text: value, attrs: { value: value } }));
  }
  confidence.appendChild(el('option', { text: 'any confidence', attrs: { value: '' } }));
  for (const value of ['high', 'medium', 'low']) {
    confidence.appendChild(el('option', { text: value, attrs: { value: value } }));
  }

  for (const control of [endpoint, type, confidence]) {
    control.addEventListener('input', applyFilters);
    control.addEventListener('change', applyFilters);
  }

  return el('section', { className: 'panel', attrs: { id: 'filters' }, children: [
    el('h3', { text: 'Filter' }),
    el('div', { className: 'filter-row', children: [
      el('label', { text: 'Endpoint', attrs: { for: 'filter-endpoint' } }), endpoint,
      el('label', { text: 'Type', attrs: { for: 'filter-type' } }), type,
      el('label', { text: 'Confidence', attrs: { for: 'filter-confidence' } }), confidence,
    ] }),
    el('p', { className: 'sub', id: 'filter-count' }),
  ] });
}

function applyFilters() {
  const endpointInput = document.getElementById('filter-endpoint');
  const typeInput = document.getElementById('filter-type');
  const confidenceInput = document.getElementById('filter-confidence');
  if (!endpointInput) return;

  const wantedEndpoint = endpointInput.value.trim().toLowerCase();
  const wantedType = typeInput.value;
  const wantedConfidence = confidenceInput.value;

  let shown = 0, total = 0;
  for (const card of document.querySelectorAll('[data-group]')) {
    total += 1;
    const path = (card.dataset.path || '').toLowerCase();
    const okEndpoint = !wantedEndpoint || path.indexOf(wantedEndpoint) !== -1;
    const okType = !wantedType || card.dataset.type === wantedType;
    const okConfidence = !wantedConfidence || card.dataset.confidence === wantedConfidence;
    const visible = okEndpoint && okType && okConfidence;
    card.hidden = !visible;
    if (visible) shown += 1;
  }

  const count = document.getElementById('filter-count');
  if (count) {
    count.textContent = total === 0
      ? 'No groups to filter.'
      : ('Showing ' + shown + ' of ' + total + ' group(s).');
  }
  const empty = document.getElementById('groups-empty');
  if (empty) empty.hidden = !(total > 0 && shown === 0);
}

// --- the groups --------------------------------------------------------------

function groupsPanel(report) {
  const groups = (report && report.groups) || [];
  const children = [el('h3', { text: 'Grouped indicators (' + groups.length + ')' })];

  if (groups.length === 0) {
    const d = report && report.delivery;
    const verdict = deliveryVerdict(d);
    const responses = deliveryResponses(d);
    let text = 'No indicator was stored for this session.';
    if (verdict === 'none_attempted') {
      text = 'No indicator was stored, and none could have been: nothing was attempted against the target.';
    } else if (verdict === 'unknown' || responses === 'unknown') {
      text = 'No indicator was stored. What became of the requests is not fully known, so this is not a result about the target.';
    } else if (responses === 'none_answered') {
      text = 'No indicator was stored, and no response was observed from the target, so this is not a result about it.';
    } else if (verdict === 'partly_refused' || responses === 'partly_answered') {
      text = 'No indicator was stored for the requests that were answered. Those refused, or without a response, tested nothing.';
    }
    children.push(el('p', { className: 'sub',
      attrs: { 'data-delivery': verdict, 'data-responses': responses }, text }));
    return el('section', { className: 'panel', attrs: { id: 'groups' }, children });
  }

  children.push(el('p', { className: 'sub', id: 'groups-empty', attrs: { hidden: 'hidden' },
    text: 'No group matches the current filter.' }));

  for (const group of groups) children.push(groupCard(group));
  return el('section', { className: 'panel', attrs: { id: 'groups' }, children });
}

function groupCard(group) {
  const signature = group.signature || {};
  const classification = group.classification || {};
  const representative = group.representative || {};
  const request = representative.request_summary || {};
  const response = representative.response_summary || {};
  const caseIds = group.case_ids || [];

  const card = el('article', {
    className: 'group',
    attrs: {
      'data-group': group.group_id || '',
      'data-type': signature.indicator_type || '',
      'data-path': signature.path || '',
      'data-confidence': classification.confidence || '',
    },
  });

  card.appendChild(el('h4', {
    text: (signature.indicator_type || 'indicator') + ' — '
      + (signature.method || '') + ' ' + (signature.path || ''),
  }));

  // The judgement region. Everything in it is composed here from the backend's
  // own values; nothing from the target appears inside it.
  const verdict = el('div', { className: 'judgement', attrs: { 'data-origin': 'mihakk' }, children: [
    el('p', { children: [
      el('strong', { text: 'Confidence: ' + (classification.confidence || 'unrated') }),
      el('span', { text: ' — confidence in the observation, not how serious it would be.' }),
    ] }),
    // The one status the engine ever assigns, kept visible.
    el('p', { className: 'status-line', attrs: { 'data-status': 'indicator_needs_verification' },
      text: 'Status: indicator_needs_verification' }),
    el('p', { className: 'note',
      text: classification.note || 'This is an indicator that needs verification, not a confirmed vulnerability.' }),
  ] });

  const why = el('ul');
  for (const sentence of classification.rationale || []) {
    why.appendChild(el('li', { text: sentence }));
  }
  if ((classification.rationale || []).length) {
    verdict.appendChild(el('h5', { text: 'Why it is rated this way' }));
    verdict.appendChild(why);
  }
  verdict.appendChild(el('p', { className: 'sub',
    text: 'Occurrences: ' + (group.occurrences === undefined ? '—' : group.occurrences)
      + ' · cases: ' + caseIds.length
      + ((group.mutators || []).length ? ' · mutators: ' + group.mutators.join(', ') : '') }));
  card.appendChild(verdict);

  // The target's own output, fenced off. Labelled, visually distinct and marked
  // with data-origin so the separation can be asserted rather than eyeballed:
  // a sentence from a response body must never read as this tool's assessment.
  const raw = el('div', { className: 'target-output', attrs: { 'data-origin': 'target' } });
  raw.appendChild(el('h5', { text: 'Raw output from the target — not Mihakk’s assessment' }));
  raw.appendChild(el('p', { className: 'sub',
    text: 'The text below came from the application under test. It is shown as text, unchanged.' }));

  if (representative.reason) {
    raw.appendChild(el('p', { className: 'field-label', text: 'What the engine observed' }));
    raw.appendChild(el('pre', { text: representative.reason }));
  }
  if (request.url) {
    raw.appendChild(el('p', { className: 'field-label', text: 'Request URL (text, not a link)' }));
    raw.appendChild(el('pre', { text: request.url }));
  }
  if (request.body_preview) {
    raw.appendChild(el('p', { className: 'field-label', text: 'Request body (mutated, redacted)' }));
    raw.appendChild(el('pre', { text: request.body_preview }));
  }
  if (response.error) {
    raw.appendChild(el('p', { className: 'field-label', text: 'Transport error' }));
    raw.appendChild(el('pre', { text: response.error }));
  }
  card.appendChild(raw);

  const reproduction = representative.reproduction || {};
  const tbody = el('tbody', { children: [
    row('Case id', representative.case_id),
    row('Case index', representative.case_index),
    row('Status code', response.status_code),
    row('Latency (ms)', response.latency_ms),
    row('Seed', reproduction.master_seed),
    row('Engine version', reproduction.engine_version),
    row('Corpus digest', reproduction.corpus_digest),
    row('Config digest', reproduction.config_digest),
  ] });
  card.appendChild(el('h5', { text: 'Representative case' }));
  card.appendChild(el('table', { children: [tbody] }));
  return card;
}

// --- starting a session ------------------------------------------------------

function startForm() {
  const host = document.getElementById('start-form');
  clear(host);

  const sessionId = el('input', { attrs: { type: 'text', id: 'new-session-id',
    value: 'session-' + Date.now().toString(36) } });
  // Not readonly: repeating a run means supplying the seed it used, so a previous
  // one can be pasted here. It is validated before anything is sent, and the
  // engine validates it again.
  const seedField = el('input', { attrs: { type: 'text', id: 'new-seed',
    spellcheck: 'false', autocomplete: 'off',
    placeholder: 'generated, or paste a previous seed (hex)' } });
  seedField.value = generateSeed();

  const regenerate = el('button', { text: 'New seed', attrs: { type: 'button' } });
  regenerate.addEventListener('click', () => { seedField.value = generateSeed(); });

  const configFile = el('input', { attrs: { type: 'file', id: 'config-file', accept: '.json' } });
  const corpusFile = el('input', { attrs: { type: 'file', id: 'corpus-file', accept: '.json' } });
  const openapiFile = el('input', { attrs: { type: 'file', id: 'openapi-file',
    accept: '.json,.yaml,.yml' } });
  const baseUrl = el('input', { attrs: { type: 'text', id: 'base-url',
    placeholder: 'base URL, required with an OpenAPI document' } });

  const review = el('button', { text: 'Review before starting', attrs: { type: 'button' } });
  review.addEventListener('click', () => reviewInputs({
    sessionId: sessionId, seed: seedField, configFile: configFile,
    corpusFile: corpusFile, openapiFile: openapiFile, baseUrl: baseUrl,
  }));

  host.appendChild(el('div', { className: 'form-grid', children: [
    el('label', { text: 'Session id', attrs: { for: 'new-session-id' } }), sessionId,
    el('label', { text: 'Seed', attrs: { for: 'new-seed' } }),
    el('div', { className: 'seed-row', children: [seedField, regenerate] }),
    el('label', { text: 'Config file', attrs: { for: 'config-file' } }), configFile,
    el('label', { text: 'Corpus file', attrs: { for: 'corpus-file' } }), corpusFile,
    el('label', { text: 'or OpenAPI', attrs: { for: 'openapi-file' } }), openapiFile,
    el('label', { text: 'Base URL', attrs: { for: 'base-url' } }), baseUrl,
  ] }));
  host.appendChild(el('p', { className: 'sub',
    text: 'Supply a corpus or an OpenAPI document, not both. The seed is generated '
      + 'in your browser and shown so you can record it: without it a case cannot '
      + 'be regenerated.' }));
  host.appendChild(review);
  host.appendChild(el('div', { attrs: { id: 'review' } }));
  host.appendChild(el('div', { className: 'state', attrs: { id: 'start-state' } }));
}

// The engine requires hex it can decode, and a seed of no bytes cannot reproduce
// anything. Checked here so a mistake is caught beside the field rather than
// arriving as a refusal from two services away.
function seedProblem(value) {
  const seed = (value || '').trim();
  if (!seed) return 'A seed is required: without one a case cannot be regenerated.';
  if (!/^[0-9a-fA-F]+$/.test(seed)) return 'The seed must be hexadecimal.';
  if (seed.length % 2 !== 0) {
    return 'The seed must have an even number of hex digits: it decodes to bytes.';
  }
  return null;
}

function generateSeed() {
  // crypto.getRandomValues, not Math.random: the seed decides every mutation in
  // the run, and a predictable one makes the run predictable.
  const bytes = new Uint8Array(16);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function readFile(input) {
  const file = input.files && input.files[0];
  if (!file) return Promise.resolve(null);
  return file.text();
}

async function reviewInputs(fields) {
  const target = document.getElementById('review');
  clear(target);
  showState('start-state', null);

  let configText, corpusText, openapiText;
  try {
    configText = await readFile(fields.configFile);
    corpusText = await readFile(fields.corpusFile);
    openapiText = await readFile(fields.openapiFile);
  } catch (err) {
    showState('start-state', 'error', 'Could not read a file: ' + err.message);
    return;
  }

  const badSeed = seedProblem(fields.seed.value);
  if (badSeed) {
    showState('start-state', 'error', badSeed);
    return;
  }
  if (!configText) {
    showState('start-state', 'error', 'A configuration file is required.');
    return;
  }
  if (!corpusText && !openapiText) {
    showState('start-state', 'error',
      'Supply a corpus file or an OpenAPI document.');
    return;
  }
  if (corpusText && openapiText) {
    showState('start-state', 'error',
      'Supply a corpus or an OpenAPI document, not both — the engine refuses both together.');
    return;
  }

  let config, corpus = null;
  try {
    config = JSON.parse(configText);
  } catch (err) {
    // The message names the field, never the content: a parse error should not
    // print part of a file that may hold credentials.
    showState('start-state', 'error', 'The configuration file is not valid JSON.');
    return;
  }
  if (corpusText) {
    try {
      corpus = JSON.parse(corpusText);
    } catch (err) {
      showState('start-state', 'error', 'The corpus file is not valid JSON.');
      return;
    }
  }

  pending = {
    session_id: fields.sessionId.value.trim(),
    config: config,
    corpus: corpus,
    openapi: openapiText || null,
    base_url: fields.baseUrl.value.trim() || null,
    seed: fields.seed.value.trim(),
  };

  target.appendChild(reviewPanel(pending));
}

function reviewPanel(input) {
  const scope = (input.config && input.config.scope) || {};
  const ack = (input.config && input.config.authorization) || {};
  const limits = (input.config && input.config.limits) || {};

  const children = [
    el('h3', { text: 'Check this before starting' }),
    el('p', { className: 'sub',
      text: 'Read from the file you supplied. Nothing here was composed by this page: '
        + 'the acknowledgement and its scope digest are yours, and the engine is what '
        + 'verifies them.' }),
  ];

  const targets = el('tbody');
  for (const target of scope.targets || []) {
    targets.appendChild(el('tr', { children: [
      el('td', { text: target.scheme }),
      el('td', { text: target.host }),
      el('td', { text: target.port }),
      el('td', { text: (target.path_prefixes || []).join(', ') }),
      el('td', { text: (target.methods || []).join(', ') }),
    ] }));
  }
  children.push(el('h4', { text: 'Scope' }));
  children.push(el('table', { children: [
    el('thead', { children: [el('tr', { children: [
      el('th', { text: 'Scheme' }), el('th', { text: 'Host' }), el('th', { text: 'Port' }),
      el('th', { text: 'Path prefixes' }), el('th', { text: 'Methods' }),
    ] })] }),
    targets,
  ] }));

  children.push(el('h4', { text: 'Authorisation' }));
  children.push(el('table', { children: [el('tbody', { children: [
    row('Operator', ack.operator),
    row('Statement', ack.statement),
    row('Acknowledged at', ack.acked_at),
    row('Scope digest', ack.scope_digest),
  ] })] }));

  children.push(el('h4', { text: 'Limits' }));
  children.push(el('table', { children: [el('tbody', { children: [
    row('Requests per second', limits.requests_per_second),
    row('Max total requests', limits.max_total_requests),
    row('Max concurrency', limits.max_concurrency),
    row('Max session duration', limits.max_session_duration),
    row('Request timeout', limits.request_timeout),
  ] })] }));

  // The samples are where credentials live, so they are counted and never shown.
  const sampleCount = input.corpus && Array.isArray(input.corpus.samples)
    ? input.corpus.samples.length : null;
  children.push(el('h4', { text: 'Samples' }));
  children.push(el('p', {
    text: input.openapi
      ? 'An OpenAPI document was supplied; the engine builds the samples from it.'
      : (sampleCount === null ? 'No samples found in the corpus file.'
         : sampleCount + ' sample(s) supplied.') }));
  children.push(el('p', { className: 'sub',
    text: 'Sample contents are deliberately not displayed: request headers are '
      + 'where credentials live.' }));

  // Defaults shown by value, so a run never starts on settings nobody saw.
  children.push(el('h4', { text: 'Mutation settings (engine defaults)' }));
  children.push(el('table', { children: [el('tbody', { children: [
    row('mutations_per_target', 8),
    row('max_value_bytes', 512),
    row('max_body_bytes', 8192),
    row('max_url_bytes', 2048),
    row('max_targets_per_sample', 64),
    row('mutate query / body / headers', 'yes / yes / yes'),
    row('mutable headers', 'Accept, Accept-Language, User-Agent, X-Request-Id'),
    row('max_cases', 'no additional cap'),
  ] })] }));

  children.push(el('h4', { text: 'Run' }));
  children.push(el('table', { children: [el('tbody', { children: [
    row('Session id', input.session_id),
    row('Seed', input.seed),
  ] })] }));

  const confirm = el('button', { text: 'Start the session', attrs: { type: 'button' } });
  confirm.addEventListener('click', submitStart);
  const cancel = el('button', { text: 'Cancel', attrs: { type: 'button' } });
  cancel.addEventListener('click', () => {
    pending = null;
    clearUploads();
    clear(document.getElementById('review'));
  });
  children.push(el('div', { className: 'actions', children: [confirm, cancel] }));

  return el('section', { className: 'panel', attrs: { id: 'review-panel' }, children });
}

async function submitStart() {
  if (!pending) return;
  const body = {
    session_id: pending.session_id,
    config: pending.config,
    seed: pending.seed,
  };
  if (pending.corpus) body.corpus = pending.corpus;
  if (pending.openapi) body.openapi = pending.openapi;
  if (pending.base_url) body.base_url = pending.base_url;

  const id = encodeURIComponent(pending.session_id);
  const startedId = pending.session_id;
  const startedSeed = pending.seed;
  showState('start-state', 'loading', 'Starting…');
  try {
    await apiJson('/v1/sessions/' + id + '/start',
      { method: 'POST', body: JSON.stringify(body) });
  } catch (err) {
    // The engine's refusal is shown as it arrived. It is the authority on the
    // authorisation and the scope, and rewording it would hide which rule failed.
    showState('start-state', 'error', 'The run was refused: ' + err.message);
    return;
  } finally {
    // Release what this code holds and what the page was showing, including the
    // file inputs' own references. Not a guarantee about the browser's memory.
    pending = null;
    clearUploads();
    clear(document.getElementById('review'));
  }

  // The seed stays on screen after the run starts, and does not depend on a
  // finding being stored: a run with no indicators still has to be repeatable,
  // and the seed is the only thing that makes it so.
  const host = document.getElementById('start-state');
  clear(host);
  host.dataset.kind = 'started';
  host.appendChild(el('p', { children: [
    el('strong', { text: 'Started ' }),
    el('code', { text: startedId }),
  ] }));
  host.appendChild(el('p', { className: 'started-seed', children: [
    el('span', { text: 'Seed for this run — record it, it is what regenerates a case: ' }),
    el('code', { text: startedSeed, attrs: { id: 'started-seed' } }),
  ] }));

  await loadSessions();
}

// --- wiring ------------------------------------------------------------------

async function boot() {
  try {
    const body = await apiJson('/auth/csrf');
    csrfToken = body && body.csrf_token;
  } catch (err) {
    csrfToken = null;
  }

  document.getElementById('back').addEventListener('click', showList);
  document.getElementById('logout').addEventListener('click', async () => {
    try {
      await api('/auth/logout', { method: 'POST' });
    } catch (err) {
      // Going to the login page is the right end either way.
    }
    window.location.assign('/auth/login');
  });

  startForm();
  await loadSessions();

  refreshTimer = window.setInterval(() => {
    paintStaleness(null);
    if (currentSessionId) refreshDetail();
    else loadSessions();
  }, REFRESH_MS);
}

window.addEventListener('DOMContentLoaded', boot);

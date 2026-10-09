/* AI Config Reviewer: single-page frontend (no build step, no framework). */
(() => {
  'use strict';

  const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const SEV_COLORS = { CRITICAL: '#C2312B', HIGH: '#E8590C', MEDIUM: '#D29A0A', LOW: '#3B6FE0', INFO: '#98A2B3' };
  const TYPE_LABELS = {
    'dockerfile': 'Dockerfile', 'docker-compose': 'docker-compose', 'kubernetes': 'Kubernetes',
    'github-actions': 'GitHub Actions', 'terraform': 'Terraform', 'env': '.env', 'unknown': 'Unsupported',
  };
  // Names worth sending when a whole folder is chosen (mirrors detector.py).
  const CONFIG_NAME = /(^|\/)(dockerfile(\.[^/]*)?|[^/]+\.dockerfile|[^/]+\.ya?ml|[^/]+\.tf|\.env(\.[^/]*)?|[^/]+\.env)$/i;
  const SKIP_DIR = /(^|\/)(\.git|node_modules|\.venv|venv|__pycache__|\.terraform|dist|build)\//;
  const MAX_FILE_BYTES = 500000;

  const state = {
    staged: [],          // [{name, content}]
    result: null,        // last /api/review response
    sources: new Map(),  // name -> content of the last reviewed files
    sevFilter: new Set(SEVERITIES),
    onlyAI: false,
    query: '',
    aiAvailable: false,
  };

  // ---------------------------------------------------------------- helpers
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  /** Create an element. Text is always set via textContent, so file content can never inject HTML. */
  function h(tag, attrs = {}, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  async function api(path, options = {}) {
    const res = await fetch(path, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    });
    if (!res.ok) {
      let msg = `Request failed (${res.status})`;
      try { msg = (await res.json()).error || msg; } catch (_) { /* not JSON */ }
      throw new Error(msg);
    }
    return res;
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

  function download(name, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = h('a', { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ---------------------------------------------------------------- views
  $$('.tab').forEach((tab) => tab.addEventListener('click', () => {
    $$('.tab').forEach((t) => t.classList.toggle('active', t === tab));
    $$('.view').forEach((v) => { v.hidden = v.id !== `view-${tab.dataset.view}`; });
  }));

  $$('.seg-btn').forEach((btn) => btn.addEventListener('click', () => {
    $$('.seg-btn').forEach((b) => b.classList.toggle('active', b === btn));
    $$('.input-pane').forEach((p) => { p.hidden = p.dataset.pane !== btn.dataset.input; });
  }));

  // ---------------------------------------------------------------- pipeline
  function setStage(name, status, metric) {
    const el = $(`.stage[data-stage="${name}"]`);
    if (!el) return;
    el.classList.remove('active', 'done', 'off');
    if (status) el.classList.add(status);
    if (metric != null) {
      const m = $('.stage-metric', el);
      m.textContent = metric;
      m.title = metric;
    }
  }

  function resetPipeline() {
    ['detect', 'rules', 'ai', 'score', 'report'].forEach((s) => setStage(s, null));
    setStage('ai', $('#ai-toggle').checked ? null : 'off', $('#ai-toggle').checked ? 'On' : 'Off');
  }

  // ---------------------------------------------------------------- staging files
  function addFiles(files) {
    let added = 0;
    for (const f of files) {
      const existing = state.staged.findIndex((s) => s.name === f.name);
      if (existing >= 0) state.staged[existing] = f; else state.staged.push(f);
      added += 1;
    }
    renderStaged();
    return added;
  }

  function renderStaged() {
    const list = $('#staged');
    list.replaceChildren();
    if (!state.staged.length) list.append(h('li', { class: 'empty', text: 'No files yet.' }));
    state.staged.forEach((f, i) => {
      list.append(h('li', {},
        h('span', { class: 'fname', title: f.name, text: f.name }),
        h('button', { class: 'x', type: 'button', 'aria-label': `Remove ${f.name}`, onclick: () => {
          state.staged.splice(i, 1); renderStaged();
        } }, '×')));
    });
    $('#staged-count').textContent = state.staged.length;
    $('#run').disabled = !state.staged.length;
    setStage('input', state.staged.length ? 'done' : null,
      state.staged.length ? plural(state.staged.length, 'file') : 'Add files');
  }

  async function readFiles(fileList, { onlyConfigs }) {
    const out = [];
    const skipped = [];
    for (const file of fileList) {
      const name = (file.webkitRelativePath || file.name).replace(/\\/g, '/');
      if (onlyConfigs && (SKIP_DIR.test(name) || !CONFIG_NAME.test(name))) continue;
      if (file.size > MAX_FILE_BYTES) { skipped.push(`${name} (too large)`); continue; }
      const text = await file.text();
      if (text.includes('\u0000')) { skipped.push(`${name} (binary)`); continue; }
      // A folder upload has the folder name first; drop it so .github/workflows/… stays recognisable.
      out.push({ name: onlyConfigs ? name.split('/').slice(1).join('/') || name : name, content: text });
    }
    if (skipped.length) showError(`Skipped: ${skipped.join(', ')}`);
    return out;
  }

  const fileInput = $('#file-input');
  const folderInput = $('#folder-input');
  const dropzone = $('#dropzone');

  fileInput.addEventListener('change', async () => {
    addFiles(await readFiles(fileInput.files, { onlyConfigs: false }));
    fileInput.value = '';
  });
  $('#folder-btn').addEventListener('click', () => folderInput.click());
  folderInput.addEventListener('change', async () => {
    const files = await readFiles(folderInput.files, { onlyConfigs: true });
    if (!files.length) showError('No configuration files found in that folder.');
    addFiles(files);
    folderInput.value = '';
  });
  dropzone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
  ['dragenter', 'dragover'].forEach((ev) => dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((ev) => dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove('drag'); }));
  dropzone.addEventListener('drop', async (e) => {
    addFiles(await readFiles(e.dataTransfer.files, { onlyConfigs: false }));
  });

  $('#paste-add').addEventListener('click', () => {
    const name = $('#paste-name').value.trim();
    const content = $('#paste-content').value;
    if (!name) return showError('Give the pasted file a name, e.g. Dockerfile.');
    if (!content.trim()) return showError('Paste some configuration first.');
    addFiles([{ name, content }]);
    $('#paste-content').value = '';
    hideError();
  });

  $$('[data-example]').forEach((btn) => btn.addEventListener('click', async () => {
    try {
      const { sets } = await (await api('/api/examples')).json();
      const files = sets[btn.dataset.example] || [];
      if (!files.length) return showError('Examples folder not found (run the server from the project folder).');
      state.staged = [];
      addFiles(files.map((f) => ({ name: `${btn.dataset.example}/${f.name}`, content: f.content })));
      hideError();
    } catch (err) { showError(err.message); }
  }));

  $('#clear-files').addEventListener('click', () => { state.staged = []; renderStaged(); });

  // ---------------------------------------------------------------- run review
  function showError(msg) { const el = $('#run-error'); el.textContent = msg; el.hidden = false; }
  function hideError() { $('#run-error').hidden = true; }

  $('#ai-toggle').addEventListener('change', () => {
    setStage('ai', $('#ai-toggle').checked ? null : 'off', $('#ai-toggle').checked ? 'On' : 'Off');
  });

  $('#run').addEventListener('click', runReview);

  async function runReview() {
    if (!state.staged.length) return;
    hideError();
    const runBtn = $('#run');
    const useAI = $('#ai-toggle').checked;
    runBtn.disabled = true;
    runBtn.replaceChildren(h('span', { class: 'spinner' }), useAI ? 'Reviewing with AI…' : 'Reviewing…');

    resetPipeline();
    setStage('detect', 'active', 'Detecting…');
    const request = api('/api/review', {
      method: 'POST',
      body: JSON.stringify({ files: state.staged, ai: useAI, effort: $('#effort').value }),
    }).then((r) => r.json());

    try {
      await sleep(250);
      setStage('rules', 'active', 'Checking rules…');
      if (useAI) setStage('ai', 'active', 'Asking Claude…');
      const data = await request;
      const sentFiles = state.staged.slice();
      state.result = data;
      state.sources = new Map(sentFiles.map((f) => [f.name, f.content]));
      // duplicate names get " (2)" suffixes on the server; map them too
      data.files.forEach((f, i) => { if (!state.sources.has(f.path) && sentFiles[i]) state.sources.set(f.path, sentFiles[i].content); });
      await animatePipeline(data, useAI);
      renderResults();
      if (window.matchMedia('(max-width: 1080px)').matches) $('#results').scrollIntoView({ behavior: 'smooth' });
    } catch (err) {
      showError(err.message);
      resetPipeline();
    } finally {
      runBtn.disabled = !state.staged.length;
      runBtn.replaceChildren('Run review');
    }
  }

  async function animatePipeline(data, useAI) {
    const p = data.pipeline;
    const types = Object.entries(p.detected).map(([t, n]) => `${n} ${TYPE_LABELS[t] || t}`).join(', ');
    setStage('detect', 'done', types || 'No supported files');
    await sleep(180);
    setStage('rules', 'done', plural(p.rule_findings, 'finding'));
    await sleep(180);
    if (!useAI) setStage('ai', 'off', 'Off');
    else if (p.ai === 'on') setStage('ai', 'done', `${plural(p.ai_findings, 'extra finding')}`);
    else setStage('ai', 'off', 'Unavailable');
    await sleep(180);
    setStage('score', 'done', `${data.score}/100 · grade ${data.grade}`);
    await sleep(180);
    setStage('report', 'done', 'Ready below ↓');
  }

  // ---------------------------------------------------------------- results
  function renderResults() {
    const data = state.result;
    $('#results-empty').hidden = true;
    $('#results').hidden = false;

    // score ring
    const ring = $('#ring-fg');
    const circumference = 2 * Math.PI * 52;
    ring.style.strokeDasharray = circumference;
    ring.style.strokeDashoffset = circumference * (1 - data.score / 100);
    const color = data.score >= 90 ? '#1F9D55' : data.score >= 75 ? '#2D5BD7' : data.score >= 60 ? '#D29A0A' : data.score >= 40 ? '#E8590C' : '#C2312B';
    ring.style.stroke = color;
    $('#score').textContent = data.score;
    $('#score-ring').setAttribute('aria-label', `Score ${data.score} out of 100, grade ${data.grade}`);
    const grade = $('#grade');
    grade.textContent = data.grade;
    grade.style.background = color;
    const total = Object.values(data.counts).reduce((a, b) => a + b, 0);
    $('#summary-text').textContent = `${plural(data.files.length, 'file')} reviewed · ${plural(total, 'finding')} · ${data.pipeline.duration_ms} ms`;

    // severity chips (also filters)
    const chips = $('#sev-chips');
    chips.replaceChildren();
    SEVERITIES.forEach((sev) => {
      const n = data.counts[sev] || 0;
      chips.append(h('button', {
        class: `chip sev-${sev}`, type: 'button', 'aria-pressed': String(state.sevFilter.has(sev)),
        title: 'Click to show or hide this severity',
        onclick: (e) => {
          if (state.sevFilter.has(sev)) state.sevFilter.delete(sev); else state.sevFilter.add(sev);
          e.currentTarget.setAttribute('aria-pressed', String(state.sevFilter.has(sev)));
          renderFileCards();
        },
      }, `${n} ${sev.toLowerCase()}`));
    });

    const msgs = $('#messages');
    msgs.replaceChildren(...data.pipeline.messages.map((m) => h('div', { class: 'notice', text: m })));
    if (data.pipeline.unsupported) {
      msgs.append(h('div', { class: 'notice', text: `${plural(data.pipeline.unsupported, 'file')} had an unsupported type and was not checked.` }));
    }
    renderFileCards();
  }

  function visible(f) {
    if (!state.sevFilter.has(f.severity)) return false;
    if (state.onlyAI && f.source !== 'ai') return false;
    if (state.query) {
      const hay = `${f.rule_id} ${f.title} ${f.message} ${f.recommendation}`.toLowerCase();
      if (!hay.includes(state.query)) return false;
    }
    return true;
  }

  function renderFileCards() {
    const container = $('#file-cards');
    const openPaths = new Set($$('.file-card.open', container).map((c) => c.dataset.path));
    const firstRender = !container.children.length;
    container.replaceChildren();
    const files = state.result.files.slice().sort((a, b) => b.findings.length - a.findings.length);
    files.forEach((file, idx) => {
      const isOpen = firstRender ? idx === 0 || file.findings.some((f) => f.severity === 'CRITICAL') : openPaths.has(file.path);
      container.append(fileCard(file, isOpen));
    });
  }

  function sevBar(findings) {
    const bar = h('div', { class: 'sevbar', 'aria-hidden': 'true' });
    if (!findings.length) return bar;
    SEVERITIES.forEach((sev) => {
      const n = findings.filter((f) => f.severity === sev).length;
      if (n) bar.append(h('i', { style: `width:${(n / findings.length) * 100}%;background:${SEV_COLORS[sev]}` }));
    });
    return bar;
  }

  function fileCard(file, open) {
    const shown = file.findings.filter(visible);
    const card = h('article', { class: `file-card${open ? ' open' : ''}`, 'data-path': file.path });
    const head = h('div', { class: 'file-head', role: 'button', tabindex: '0', 'aria-expanded': String(open) },
      h('span', { class: 'caret', 'aria-hidden': 'true' }),
      h('span', { class: 'file-path', title: file.path, text: file.path }),
      h('span', { class: 'type-badge', text: TYPE_LABELS[file.file_type] || file.file_type }),
      h('span', { class: 'spacer' }),
      sevBar(file.findings),
      h('span', { class: 'file-count', text: file.findings.length ? plural(file.findings.length, 'issue') : 'No issues' }));
    const body = h('div', { class: 'file-body' });
    body.hidden = !open;
    const toggle = () => {
      const nowOpen = body.hidden;
      body.hidden = !nowOpen;
      card.classList.toggle('open', nowOpen);
      head.setAttribute('aria-expanded', String(nowOpen));
    };
    head.addEventListener('click', toggle);
    head.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });

    if (file.ai_summary) body.append(h('div', { class: 'ai-summary' }, h('b', {}, 'AI summary: '), file.ai_summary));
    if (file.error) body.append(h('div', { class: 'notice file-error', text: file.error }));

    const findingsPane = h('div');
    const sourcePane = h('div');
    sourcePane.hidden = true;
    const tabF = h('button', { class: 'file-tab active', type: 'button' }, `Findings (${shown.length})`);
    const tabS = h('button', { class: 'file-tab', type: 'button' }, 'Source');
    const showTab = (which) => {
      tabF.classList.toggle('active', which === 'f');
      tabS.classList.toggle('active', which === 's');
      findingsPane.hidden = which !== 'f';
      sourcePane.hidden = which !== 's';
      if (which === 's' && !sourcePane.children.length) sourcePane.append(sourceView(file));
    };
    tabF.addEventListener('click', () => showTab('f'));
    tabS.addEventListener('click', () => showTab('s'));
    body.append(h('div', { class: 'file-tabs' }, tabF, tabS));

    if (!file.findings.length && !file.error) {
      findingsPane.append(h('div', { class: 'ok', text: '✓ No issues found in this file.' }));
    } else if (!shown.length) {
      findingsPane.append(h('div', { class: 'ok muted', text: 'No findings match the current filters.' }));
    } else {
      const list = h('ul', { class: 'findings' });
      shown.forEach((f) => list.append(findingItem(f, () => {
        showTab('s');
        if (f.line) {
          const row = $(`tr[data-line="${f.line}"]`, sourcePane);
          if (row) {
            row.scrollIntoView({ block: 'center', behavior: 'smooth' });
            row.classList.remove('flash'); void row.offsetWidth; row.classList.add('flash');
          }
        }
      })));
      findingsPane.append(list);
    }
    body.append(findingsPane, sourcePane);
    card.append(head, body);
    return card;
  }

  function findingItem(f, onClick) {
    return h('li', { class: 'finding', title: f.line ? `Show line ${f.line} in the source` : 'Show source', onclick: onClick },
      h('span', { class: 'ln', text: f.line ? `L${f.line}` : 'file' }),
      h('span', { class: 'sevcell' }, h('span', { class: `sev sev-${f.severity}`, text: f.severity })),
      h('span', { class: 'main' },
        h('span', { class: 'rid', text: f.rule_id }),
        h('span', { class: 'ttl', text: f.title }),
        f.source === 'ai' ? h('span', { class: 'ai-tag', text: 'AI' }) : null),
      h('span', { class: 'msg', text: f.message }),
      h('span', { class: 'fix' }, h('b', {}, 'Fix: '), f.recommendation));
  }

  function sourceView(file) {
    const text = state.sources.get(file.path);
    if (text == null) return h('div', { class: 'ok muted', text: 'Source not available.' });
    const byLine = new Map();
    file.findings.forEach((f) => { if (f.line) byLine.set(f.line, [...(byLine.get(f.line) || []), f]); });
    const tbody = h('tbody');
    text.split('\n').forEach((line, i) => {
      const n = i + 1;
      const hits = byLine.get(n);
      tbody.append(h('tr', { class: hits ? 'hit' : null, 'data-line': String(n), title: hits ? hits.map((f) => `${f.rule_id}: ${f.title}`).join('\n') : null },
        h('td', { class: 'n', text: String(n) }),
        h('td', { text: line || ' ' }),
        h('td', { class: 'marks' }, hits ? hits.map((f) => h('span', { class: `sev sev-${f.severity}`, text: f.rule_id })) : null)));
    });
    return h('div', { class: 'source' }, h('table', {}, tbody));
  }

  $('#only-ai').addEventListener('change', (e) => { state.onlyAI = e.target.checked; renderFileCards(); });
  $('#search').addEventListener('input', (e) => { state.query = e.target.value.trim().toLowerCase(); renderFileCards(); });

  $$('[data-export]').forEach((btn) => btn.addEventListener('click', async () => {
    if (!state.result) return;
    const fmt = btn.dataset.export;
    try {
      const res = await api('/api/export', { method: 'POST', body: JSON.stringify({ format: fmt, result: state.result }) });
      const ext = { json: 'json', markdown: 'md', sarif: 'sarif' }[fmt];
      download(`config-review.${ext}`, await res.text(), res.headers.get('Content-Type') || 'text/plain');
    } catch (err) { showError(err.message); }
  }));

  // ---------------------------------------------------------------- rules view
  let allRules = [];
  function renderRules() {
    const q = $('#rule-search').value.trim().toLowerCase();
    const type = $('#rule-type').value;
    const rows = allRules.filter((r) => (!type || r.analyzer === type) &&
      (!q || `${r.id} ${r.title} ${r.category} ${r.recommendation}`.toLowerCase().includes(q)));
    $('#rules-body').replaceChildren(...rows.map((r) => h('tr', {},
      h('td', { text: r.id }),
      h('td', {}, h('span', { class: `sev sev-${r.severity}`, text: r.severity })),
      h('td', { text: r.analyzer }),
      h('td', { text: r.category }),
      h('td', { text: r.title }),
      h('td', { text: r.recommendation }))));
  }
  $('#rule-search').addEventListener('input', renderRules);
  $('#rule-type').addEventListener('change', renderRules);

  // ---------------------------------------------------------------- init
  async function init() {
    renderStaged();
    resetPipeline();
    try {
      const status = await (await api('/api/status')).json();
      $('#version').textContent = `v${status.version}`;
      $('#m-rules').textContent = `${status.rule_count} rules + secrets`;
      state.aiAvailable = status.ai.available;
      const pill = $('#ai-pill');
      pill.textContent = status.ai.available ? `AI ready · ${status.ai.model}` : 'AI off · rules only';
      pill.className = `pill ${status.ai.available ? 'pill-on' : 'pill-muted'}`;
      pill.title = status.ai.reason;
      const toggle = $('#ai-toggle');
      toggle.disabled = !status.ai.available;
      $('#ai-note').textContent = status.ai.available ? `Claude (${status.ai.model}) looks for issues the rules miss` : status.ai.reason;
      $('#effort').disabled = !status.ai.available;

      const { rules } = await (await api('/api/rules')).json();
      allRules = rules;
      $('#rule-count').textContent = rules.length;
      [...new Set(rules.map((r) => r.analyzer))].forEach((a) => $('#rule-type').append(h('option', { value: a, text: a })));
      renderRules();
    } catch (err) {
      showError(`Could not reach the server: ${err.message}`);
    }
  }
  init();
})();

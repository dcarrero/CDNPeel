(() => {
  'use strict';

  const $ = (s) => document.querySelector(s);
  const pipeline = $('#pipeline');
  const pipelineHeader = $('#pipeline-header');
  const pipelineCounter = $('#pipeline-counter');
  const qnProgress = $('#qn-progress');
  const qnResultsLink = $('#qn-results-link');
  const form = $('#scan-form');
  const runBtn = $('#run');
  const stopBtn = $('#stop');
  const resultsCard = $('#results');
  const resultsTbody = $('#results-table tbody');
  const summaryMeta = $('#summary-meta');
  const langPicker = $('#lang-picker');
  const toTopBtn = $('#to-top');
  const expandAllBtn = $('#expand-all');
  const collapseAllBtn = $('#collapse-all');

  // Estados que indican que el paso "ya pasó" y por tanto se puede plegar.
  const SETTLED_STATUSES = new Set(['done', 'match', 'no-match', 'skipped', 'info']);
  // Estados que el usuario debe ver: nunca autoplegamos.
  const STICKY_STATUSES = new Set(['error', 'running']);
  const AUTOCLOSE_DELAY_MS = 450;

  const SUPPORTED_LOCALES = ['en', 'es', 'fr', 'de', 'it', 'pt', 'ja', 'ko'];
  let locale = {};       // active locale dict
  let localeCode = 'en';

  // --- i18n ---

  function pickInitialLocale() {
    const saved = localStorage.getItem('cdnpeel:lang');
    if (saved && SUPPORTED_LOCALES.includes(saved)) return saved;
    const nav = (navigator.language || 'en').slice(0, 2).toLowerCase();
    return SUPPORTED_LOCALES.includes(nav) ? nav : 'en';
  }

  async function loadLocale(code) {
    try {
      const res = await fetch(`locales/${code}.json`, { cache: 'no-cache' });
      if (!res.ok) throw new Error('locale load failed');
      locale = await res.json();
      localeCode = code;
      langPicker.value = code;
      document.documentElement.lang = code;
      localStorage.setItem('cdnpeel:lang', code);
      applyTranslations();
    } catch (err) {
      console.error('i18n', err);
    }
  }

  function t(path, vars) {
    const parts = path.split('.');
    let cur = locale;
    for (const p of parts) {
      if (cur && typeof cur === 'object' && p in cur) cur = cur[p];
      else return path;
    }
    if (typeof cur !== 'string') return path;
    if (vars) {
      return cur.replace(/\{(\w+)\}/g, (_, k) => (k in vars ? String(vars[k]) : '{' + k + '}'));
    }
    return cur;
  }

  function applyTranslations() {
    document.title = t('app.name') + ' — ' + (t('app.subtitle_html').replace(/<[^>]+>/g, '') || 'CDNPeel');
    for (const el of document.querySelectorAll('[data-i18n]')) {
      el.textContent = t(el.getAttribute('data-i18n'));
    }
    for (const el of document.querySelectorAll('[data-i18n-html]')) {
      el.innerHTML = t(el.getAttribute('data-i18n-html'));
    }
    for (const el of document.querySelectorAll('[data-i18n-placeholder]')) {
      el.placeholder = t(el.getAttribute('data-i18n-placeholder'));
    }
  }

  langPicker.addEventListener('change', () => loadLocale(langPicker.value));

  // --- Persisted form state ---
  const KEY_FIELDS = ['shodan_key', 'censys_id', 'censys_secret', 'otx_key'];
  const CHECKBOXES = ['use_hackertarget'];
  for (const id of KEY_FIELDS) {
    const el = document.getElementById(id);
    const saved = sessionStorage.getItem('cdnpeel:' + id);
    if (saved) el.value = saved;
    el.addEventListener('input', () => sessionStorage.setItem('cdnpeel:' + id, el.value));
  }
  for (const id of CHECKBOXES) {
    const el = document.getElementById(id);
    const saved = sessionStorage.getItem('cdnpeel:' + id);
    if (saved === '1') el.checked = true;
    el.addEventListener('change', () => sessionStorage.setItem('cdnpeel:' + id, el.checked ? '1' : '0'));
  }

  // --- Scan / SSE ---

  let es = null;
  let candidatesList = [];
  let activeSection = 'form-section';

  function stepLabel(id) {
    const key = 'steps.' + id;
    const lbl = t(key);
    if (lbl !== key) return lbl;
    if (id.startsWith('validate_')) {
      return t('steps.validate_prefix') + id.slice('validate_'.length).replace(/_/g, '.');
    }
    return id;
  }

  function getStepEl(id) {
    let el = document.getElementById('step-' + CSS.escape(id));
    if (!el) {
      // Mostrar la cabecera del pipeline en cuanto aparece el primer paso.
      if (pipelineHeader && pipelineHeader.hidden) pipelineHeader.hidden = false;

      el = document.createElement('details');
      el.id = 'step-' + id;
      el.className = 'step pending';
      el.open = true; // arrancan abiertos; se autoplegarán cuando se asienten
      el.innerHTML = `
        <summary>
          <div class="head-main">
            <div class="title"></div>
            <div class="msg"></div>
          </div>
          <div class="status">pending</div>
        </summary>
        <div class="body"></div>
      `;
      el.querySelector('.title').textContent = stepLabel(id);

      // Marcar como "abierto por usuario" si el primer toggle proviene de un clic.
      el.addEventListener('toggle', () => {
        if (el.dataset.userToggled === 'true') return;
        el.dataset.userToggled = 'true';
      }, { once: true });

      pipeline.appendChild(el);
    }
    return el;
  }

  function renderStep(payload) {
    const { id, status, message, data } = payload;
    const el = getStepEl(id);
    el.className = 'step ' + status;
    el.querySelector('.status').textContent = status;
    el.querySelector('.msg').textContent = message || '';
    const body = el.querySelector('.body');
    const detail = formatBody(id, data);
    body.textContent = detail || '';

    // Apertura/cierre automático:
    //  - running / error → abierto siempre.
    //  - settled (done/match/no-match/skipped/info) → cerrar tras un breve delay,
    //    salvo que el usuario lo haya abierto manualmente.
    if (STICKY_STATUSES.has(status)) {
      el.open = true;
    } else if (SETTLED_STATUSES.has(status)) {
      if (el.dataset.autoCloseTimer) clearTimeout(Number(el.dataset.autoCloseTimer));
      const timer = setTimeout(() => {
        if (el.dataset.userToggled !== 'true') el.open = false;
      }, AUTOCLOSE_DELAY_MS);
      el.dataset.autoCloseTimer = String(timer);
    }

    updateCounter();
    maybeScrollIntoView(el);
  }

  // Hace scrollIntoView SOLO si el paso queda fuera del viewport y el usuario
  // está actualmente mirando la sección de Pipeline. Evita robar el scroll si
  // el usuario está leyendo el formulario o los resultados.
  function maybeScrollIntoView(el) {
    if (activeSection !== 'pipeline-section') return;
    const rect = el.getBoundingClientRect();
    const viewportH = window.innerHeight || document.documentElement.clientHeight;
    if (rect.top < 60 || rect.bottom > viewportH - 10) {
      el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  function updateCounter() {
    const steps = pipeline.querySelectorAll('.step');
    const total = steps.length;
    let settled = 0, errors = 0;
    steps.forEach((s) => {
      const cls = s.className;
      if (cls.includes(' error')) { errors++; settled++; }
      else if (SETTLED_STATUSES.has(stateOf(cls))) settled++;
    });
    const txt = `${settled}/${total}` + (errors ? ` · ${errors} err` : '');
    pipelineCounter.textContent = txt;
    qnProgress.hidden = total === 0;
    qnProgress.textContent = txt;
    qnProgress.classList.toggle('has-error', errors > 0);
  }

  function stateOf(className) {
    const parts = className.split(/\s+/);
    return parts.find((p) => p !== 'step' && p !== 'pending') || 'pending';
  }

  function formatBody(id, data) {
    if (!data || typeof data !== 'object') return '';
    if (id === 'classify_cdn' && data.by_provider) {
      const lines = [];
      for (const [pid, ips] of Object.entries(data.by_provider)) {
        const name = (data.provider_names && data.provider_names[pid]) || pid;
        lines.push(`🛡  ${name}:\n  ` + ips.join('\n  '));
      }
      if (data.non_cdn && data.non_cdn.length) {
        lines.push(`✅ non-CDN:\n  ` + data.non_cdn.join('\n  '));
      }
      return lines.join('\n');
    }
    if (id === 'fetch_baseline' && data.header_provider_names && data.header_provider_names.length) {
      const lines = [];
      if (data.title) lines.push('Title: ' + data.title);
      lines.push('Headers reveal: ' + data.header_provider_names.join(', '));
      return lines.join('\n');
    }
    if (Array.isArray(data.subdomains) && data.subdomains.length) {
      const list = data.subdomains.slice(0, 50).join('\n');
      const more = data.subdomains.length > 50 ? `\n…(+${data.subdomains.length - 50})` : '';
      return list + more;
    }
    if (id === 'classify_subdomains' && data.by_ip) {
      return (data.ips || []).map((ip) => `${ip} ← ${(data.by_ip[ip] || []).slice(0, 3).join(', ')}`).join('\n');
    }
    if (Array.isArray(data.pairs) && data.pairs.length) {
      return data.pairs.slice(0, 30).map((p) => `${p.host} → ${p.ip}`).join('\n');
    }
    if (Array.isArray(data.ips) && data.ips.length) return data.ips.join('\n');
    if (Array.isArray(data.records) && data.records.length) return data.records.join('\n');
    if (id === 'fetch_baseline' && data.title) return data.title;
    if (id.startsWith('validate_')) {
      const parts = [];
      if (data.sources) parts.push('Source: ' + data.sources.join(', '));
      if (data.notes && data.notes.length) parts.push('Notes: ' + data.notes.join(' · '));
      if (data.status) parts.push('Status: ' + data.scheme + ' ' + data.status);
      if (data.title) parts.push('Title: ' + data.title);
      if (data.internetdb) {
        const idb = data.internetdb;
        if (idb.hostnames && idb.hostnames.length) parts.push('InternetDB hostnames: ' + idb.hostnames.slice(0, 4).join(', '));
        if (idb.ports && idb.ports.length) parts.push('InternetDB ports: ' + idb.ports.slice(0, 12).join(', '));
        if (idb.vulns && idb.vulns.length) parts.push('InternetDB CVEs: ' + idb.vulns.slice(0, 5).join(', '));
      }
      return parts.join('\n');
    }
    return '';
  }

  function renderSummary(data) {
    const cdnStatus = data.behind_cdn
      ? `${t('results.cdn_label')} ${(data.cdn_provider_names || []).join(', ') || t('results.behind_cdn')}`
      : t('results.not_behind_cdn');
    summaryMeta.textContent = `${data.domain}  ·  ${cdnStatus}  ·  ${t('results.baseline_title')}: ${data.baseline_title || '—'}`;

    resultsTbody.innerHTML = '';
    candidatesList = data.results || [];
    for (const r of candidatesList) {
      const tr = document.createElement('tr');
      tr.className = r.verdict;
      tr.innerHTML = `
        <td class="ip"></td>
        <td class="sources"></td>
        <td class="verdict"></td>
        <td class="status"></td>
        <td class="title"><div class="title-text"></div></td>
        <td class="idb"></td>
      `;
      tr.querySelector('.ip').textContent = r.ip;
      tr.querySelector('.ip').title = r.ip;

      const srcCell = tr.querySelector('.sources');
      const chips = document.createElement('div');
      chips.className = 'src-tags';
      for (const s of (r.sources || [])) {
        const span = document.createElement('span');
        span.className = 'src-tag';
        span.textContent = s;
        chips.appendChild(span);
      }
      srcCell.appendChild(chips);
      if (r.notes && r.notes.length) {
        const notes = document.createElement('div');
        notes.className = 'src-notes';
        notes.textContent = r.notes.join(' · ');
        notes.title = r.notes.join('\n');
        srcCell.appendChild(notes);
      }

      tr.querySelector('.verdict').textContent = verdictLabel(r.verdict);
      tr.querySelector('.status').textContent = r.status || '—';

      const titleEl = tr.querySelector('.title-text');
      titleEl.textContent = r.title || '—';
      if (r.title) titleEl.title = r.title;

      const idb = r.internetdb;
      const idbCell = tr.querySelector('.idb');
      if (idb) {
        const lines = [];
        if (idb.hostnames && idb.hostnames.length) {
          lines.push({ kind: 'hosts', text: idb.hostnames.slice(0, 3).join(', '), full: idb.hostnames.join(', ') });
        }
        if (idb.ports && idb.ports.length) {
          lines.push({ kind: 'ports', text: idb.ports.slice(0, 10).join(', '), full: idb.ports.join(', ') });
        }
        if (idb.vulns && idb.vulns.length) {
          lines.push({ kind: 'vulns', text: '⚠ ' + t('results.idb_cves_count', { n: idb.vulns.length }), full: idb.vulns.join(', ') });
        }
        if (lines.length === 0) {
          idbCell.textContent = '—';
        } else {
          for (const l of lines) {
            const d = document.createElement('div');
            d.className = 'idb-line' + (l.kind === 'vulns' ? ' idb-vulns' : '');
            if (l.kind === 'ports') {
              const s = document.createElement('strong');
              s.textContent = t('results.idb_ports_label');
              d.appendChild(s);
            }
            d.appendChild(document.createTextNode(l.text));
            const ttKey = l.kind === 'hosts' ? 'results.idb_hostnames_tooltip'
                       : l.kind === 'ports' ? 'results.idb_ports_tooltip'
                       : 'results.idb_cves_tooltip';
            d.title = t(ttKey) + l.full;
            idbCell.appendChild(d);
          }
        }
      } else {
        idbCell.textContent = '—';
      }
      resultsTbody.appendChild(tr);
    }
    if (candidatesList.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'results-empty';
      td.textContent = t('results.empty');
      tr.appendChild(td);
      resultsTbody.appendChild(tr);
    }
    resultsCard.hidden = false;
    qnResultsLink.classList.remove('qn-disabled');
    qnResultsLink.removeAttribute('aria-disabled');
    resultsCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function verdictLabel(v) {
    if (v === 'origin_ip') return t('results.verdict_origin');
    if (v === 'no_match') return t('results.verdict_no_match');
    if (v === 'unreachable') return t('results.verdict_unreachable');
    return v;
  }

  function reset() {
    pipeline.innerHTML = '';
    resultsCard.hidden = true;
    resultsTbody.innerHTML = '';
    summaryMeta.textContent = '';
    if (pipelineHeader) pipelineHeader.hidden = true;
    pipelineCounter.textContent = '';
    qnProgress.hidden = true;
    qnProgress.textContent = '';
    qnProgress.classList.remove('has-error');
    qnResultsLink.classList.add('qn-disabled');
    qnResultsLink.setAttribute('aria-disabled', 'true');
  }

  function stop() {
    if (es) { es.close(); es = null; }
    runBtn.disabled = false;
    runBtn.textContent = t('buttons.scan');
    stopBtn.hidden = true;
  }

  async function obtainScanId() {
    // Las API keys NO viajan por la URL: las envío por POST a init.php y
    // recibo un scan_id one-shot que el SSE consume y borra.
    const body = {};
    let anyKey = false;
    for (const id of KEY_FIELDS) {
      const v = document.getElementById(id).value.trim();
      if (v) { body[id] = v; anyKey = true; }
    }
    if (!anyKey) return null;

    const res = await fetch('../api/init.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error('init failed: HTTP ' + res.status);
    const data = await res.json();
    return data.scan_id || null;
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (es) return;

    reset();
    const domain = $('#domain').value.trim();
    if (!domain) return;

    runBtn.disabled = true;
    runBtn.textContent = t('buttons.scanning');
    stopBtn.hidden = false;

    let scanId = null;
    try {
      scanId = await obtainScanId();
    } catch (err) {
      const el = getStepEl('connection');
      el.className = 'step error';
      el.querySelector('.status').textContent = 'error';
      el.querySelector('.title').textContent = t('steps.connection');
      el.querySelector('.msg').textContent = String(err && err.message ? err.message : err);
      stop();
      return;
    }

    const params = new URLSearchParams({ domain });
    if (scanId) params.set('scan_id', scanId);
    for (const id of CHECKBOXES) {
      if (document.getElementById(id).checked) params.set(id, '1');
    }

    es = new EventSource('../api/scan.php?' + params.toString());
    es.addEventListener('step', (ev) => {
      try {
        const payload = JSON.parse(ev.data);
        renderStep(payload);
        if (payload.id === 'summary' && payload.status === 'done') {
          renderSummary(payload.data);
          stop();
        }
        if (payload.id === 'fatal') {
          // Hacer visible el motivo en la sección Pipeline: el evento ya se
          // renderiza, pero el step "fatal" no estaba en el i18n de steps —
          // sobreescribimos el title con el mensaje para que el usuario lo vea.
          const el = document.getElementById('step-fatal');
          if (el) el.open = true;
          stop();
        }
      } catch (err) {
        console.error('parse error', err, ev.data);
      }
    });
    es.onerror = () => {
      const el = getStepEl('connection');
      el.className = 'step error';
      el.querySelector('.status').textContent = 'error';
      el.querySelector('.title').textContent = t('steps.connection');
      el.querySelector('.msg').textContent = t('steps.connection_lost');
      stop();
    };
  });

  stopBtn.addEventListener('click', stop);

  $('#copy-real').addEventListener('click', () => {
    const ips = candidatesList.filter((r) => r.verdict === 'origin_ip').map((r) => r.ip);
    navigator.clipboard.writeText(ips.join('\n')).then(() => {
      const btn = $('#copy-real');
      btn.textContent = ips.length ? t('buttons.copied') : t('buttons.no_origin');
      setTimeout(() => (btn.textContent = t('buttons.copy_real')), 1500);
    });
  });
  $('#copy-all').addEventListener('click', () => {
    const ips = candidatesList.map((r) => r.ip);
    navigator.clipboard.writeText(ips.join('\n')).then(() => {
      const btn = $('#copy-all');
      btn.textContent = t('buttons.copied');
      setTimeout(() => (btn.textContent = t('buttons.copy_all')), 1500);
    });
  });

  // --- UI helpers: nav activa, scroll-to-top, expand/collapse all ---

  // IntersectionObserver para resaltar la sección activa en la nav y
  // alimentar la heurística de scroll del pipeline.
  function setupSectionObserver() {
    const sections = [
      document.getElementById('form-section'),
      document.getElementById('pipeline-section'),
      document.getElementById('results'),
    ].filter(Boolean);
    const navLinks = document.querySelectorAll('.qn-link');

    const setActive = (id) => {
      activeSection = id;
      navLinks.forEach((a) => {
        a.classList.toggle('qn-active', a.dataset.section === id);
      });
    };

    const obs = new IntersectionObserver((entries) => {
      // Elige la sección con mayor intersección visible.
      let best = null;
      let bestRatio = 0;
      for (const e of entries) {
        if (e.intersectionRatio > bestRatio) {
          bestRatio = e.intersectionRatio;
          best = e.target;
        }
      }
      // Si la entrada no es la mejor, mantén la actual visible.
      const current = sections.find((s) => {
        const r = s.getBoundingClientRect();
        return r.top < window.innerHeight / 2 && r.bottom > 60;
      });
      if (current) setActive(current.id);
      else if (best) setActive(best.id);
    }, { rootMargin: '-60px 0px -40% 0px', threshold: [0, 0.25, 0.5, 1] });

    sections.forEach((s) => obs.observe(s));
  }

  // Botón "↑ Top" — visible tras 400 px de scroll.
  function setupToTop() {
    const onScroll = () => {
      const y = window.scrollY || document.documentElement.scrollTop;
      toTopBtn.hidden = false;
      toTopBtn.classList.toggle('visible', y > 400);
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    toTopBtn.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  // Expand / collapse all — operan sobre <details.step>.
  expandAllBtn.addEventListener('click', () => {
    pipeline.querySelectorAll('details.step').forEach((d) => {
      d.open = true;
      d.dataset.userToggled = 'true';
    });
  });
  collapseAllBtn.addEventListener('click', () => {
    pipeline.querySelectorAll('details.step').forEach((d) => {
      d.open = false;
      d.dataset.userToggled = 'true';
    });
  });

  // --- bootstrap ---
  loadLocale(pickInitialLocale());
  setupSectionObserver();
  setupToTop();
})();

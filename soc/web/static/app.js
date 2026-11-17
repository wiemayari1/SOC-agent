/* SOC Agent — interface de supervision. JavaScript natif, sans dépendance.
   Sécurité : AUCUNE donnée venant de l'API n'est insérée via innerHTML (les journaux contiennent du texte contrôlé par l'attaquant). */
(() => {
  'use strict';

  const $ = (s, r = document) => r.querySelector(s);
  const CSRF = ($('meta[name="csrf-token"]') || {}).content || '';
  const NS = 'http://www.w3.org/2000/svg';

// ------------------------------------------------------------------ libellés
  const SCEN = { ssh_bruteforce: 'Force brute SSH', port_scan: 'Scan de ports', web_sqli: 'Injection SQL', malicious_file: 'Fichier malveillant' };
  const SEV = { critical: 'Critique', high: 'Élevée', medium: 'Moyenne', low: 'Faible', info: 'Info' };
  const ACT = { block_ip: 'Bloquer l’IP', quarantine_file: 'Mettre en quarantaine', isolate_host: 'Isoler la machine', notify_analyst: 'Notifier l’analyste', monitor: 'Surveiller' };
  const DEC = { executed: ['Exécutée', 'ok'], failed: ['Échec', 'danger'], pending_approval: ['En attente', 'warn'], proposed: ['Proposée', 'info'],
    denied: ['Refusée', 'danger'], rejected: ['Rejetée', 'muted'], rolled_back: ['Annulée', 'muted'] };
  const STEP = { perception: 'Collecte', reasoning: 'Analyse', plan: 'Plan de traitement', action: 'Action', observation: 'Constat',
    evaluation: 'Évaluation', decision: 'Décision', execution: 'Exécution', verification: 'Vérification', human: 'Validation humaine' };
  const HYP = { 'h.brute_force_ssh': 'Force brute SSH', 'h.port_scan': 'Scan de ports', 'h.sql_injection': 'Injection SQL', 'h.malicious_file': 'Fichier malveillant',
    'h.ransomware': 'Ransomware', 'h.account_compromise': 'Compromission de compte', 'h.multi_stage': 'Attaque multi-étapes',
    'benign.user_typo': 'Faute de frappe légitime', 'benign.legit_apostrophe': 'Apostrophe légitime' };
  const NAV = [['overview', 'Tableau de bord', 'M3 3h8v8H3zM13 3h8v5h-8zM13 10h8v11h-8zM3 13h8v8H3z'],
    ['incidents', 'Incidents', 'M12 3 2 21h20zM12 10v5M12 18v.01'],
    ['approvals', 'Validations', 'M5 12l4 4 10-10'],
    ['feed', 'Flux Wazuh', 'M3 12h4l3-8 4 16 3-8h4'],
    ['response', 'Réponse', 'M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5z'],
    ['system', 'Système', 'M4 6h16M4 12h16M4 18h16']];

  const state = { tab: 'summary', filters: { q: '', severity: '', scenario: '', status: '' }, summary: null, detailSig: null };

// ------------------------------------------------------------------ DOM sûr
  function add(n, kids) { for (const c of kids.flat(Infinity)) { if (c == null || c === false) continue; n.append(c.nodeType ? c : document.createTextNode(String(c))); } }
  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k === 'style') Object.assign(n.style, v);
      else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
      else if (v === true) n.setAttribute(k, '');
      else n.setAttribute(k, String(v));
    }
    add(n, kids);
    return n;
  }
  function sv(tag, attrs, ...kids) {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v != null) n.setAttribute(k, String(v));
    add(n, kids);
    return n;
  }
  const icon = (d) => sv('svg', { viewBox: '0 0 24 24', width: 18, height: 18, class: 'ico', 'aria-hidden': 'true' }, sv('path', { d, fill: 'none', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }));

// ------------------------------------------------------------------ utilitaires
  async function api(path, opts = {}) {
    const o = { headers: { Accept: 'application/json' }, ...opts };
    if (o.method === 'POST') { o.headers['Content-Type'] = 'application/json'; o.headers['X-CSRF-Token'] = CSRF; o.body = JSON.stringify(o.body || {}); }
    const r = await fetch(path, o);
    let data = null;
    try { data = await r.json(); } catch (e) { /* corps vide */ }
    if (!r.ok) throw new Error((data && data.error) || ('HTTP ' + r.status));
    return data;
  }
  const ft = (iso) => (iso || '').replace('T', ' ').slice(0, 19);
  const pct = (v) => Math.round((v || 0) * 100) + ' %';
  const ago = (s) => s == null ? '—' : s < 60 ? `il y a ${s} s` : s < 3600 ? `il y a ${Math.floor(s / 60)} min` : s < 86400 ? `il y a ${Math.floor(s / 3600)} h` : `il y a ${Math.floor(s / 86400)} j`;
  const val = (v) => v == null ? '—' : typeof v === 'boolean' ? (v ? 'oui' : 'non') : Array.isArray(v) ? (v.join(', ') || '—') : String(v);
  const badge = (text, variant = 'muted') => el('span', { class: `badge badge-${variant}`, text });
  const sevBadge = (s) => el('span', { class: `badge sev sev-${s}` }, el('span', { class: 'dot' }), SEV[s] || s);
  const statusVariant = (s) => s.startsWith('traité') ? 'ok' : s.startsWith('en attente') ? 'warn' : s.startsWith('à traiter') ? 'danger' : s.startsWith('proposition') ? 'info' : 'muted';
  const verdictVariant = (v) => v.includes('confirmée') ? 'danger' : v.includes('probable') ? 'warn' : v.includes('possible') ? 'info' : v.startsWith('bénin') ? 'ok' : 'muted';
  const code = (t) => el('code', { class: 'code', text: t });
  const empty = (title, hint) => el('div', { class: 'empty' }, el('div', { class: 'empty-title', text: title }), hint ? el('div', { class: 'empty-hint', text: hint }) : null);
  function cfBar(cf, variant) {
    const bar = el('div', { class: 'cfbar', role: 'img', 'aria-label': `Certitude ${pct(cf)}` }, el('span', { class: `cfbar-fill ${variant || ''}` }));
    bar.firstChild.style.width = Math.max(0, Math.min(100, cf * 100)) + '%';
    return el('div', { class: 'cf' }, bar, el('span', { class: 'cf-num', text: (cf || 0).toFixed(2) }));
  }
  function toast(msg, kind = 'info') {
    const t = el('div', { class: `toast toast-${kind}`, role: 'status', text: msg });
    $('#toasts').append(t);
    setTimeout(() => t.remove(), 4500);
  }
  function page(title, subtitle, ...kids) {
    return el('div', { class: 'page' }, el('div', { class: 'page-head' }, el('div', {}, el('h1', { text: title }), subtitle ? el('p', { class: 'subtitle', text: subtitle }) : null)), kids);
  }
  const card = (title, ...kids) => el('section', { class: 'card' }, title ? el('h2', { class: 'card-title', text: title }) : null, kids);
  function table(headers, rows, cls = '') {
    return el('div', { class: 'table-wrap' }, el('table', { class: `table ${cls}` },
        el('thead', {}, el('tr', {}, headers.map((h) => el('th', { scope: 'col', text: h })))), el('tbody', {}, rows)));
  }
  function confirmButton(label, variant, onConfirm) {
    let timer = null;
    const b = el('button', { type: 'button', class: `btn btn-${variant}`, text: label });
    b.addEventListener('click', async () => {
      if (!b.dataset.confirming) {
        b.dataset.confirming = '1'; b.textContent = 'Confirmer ?'; b.classList.add('is-confirming');
        timer = setTimeout(() => { delete b.dataset.confirming; b.textContent = label; b.classList.remove('is-confirming'); }, 4000);
        return;
      }
      clearTimeout(timer); b.disabled = true; b.textContent = '…';
      try { await onConfirm(); } catch (e) { toast(e.message, 'danger'); b.disabled = false; b.textContent = label; delete b.dataset.confirming; }
    });
    return b;
  }
  async function doAct(path, okMsg) {
    const r = await api(path, { method: 'POST', body: {} });
    toast(okMsg || r.message, 'ok');
    await refreshSummary();
    await render();
  }

// ------------------------------------------------------------------ graphiques (SVG, thème via CSS)
  function barChart(tl) {
    if (!tl.length) return empty('Aucun incident pour le moment', 'Les incidents apparaîtront ici dès qu’une alerte sera traitée.');
    const W = 640, H = 200, pl = 34, pb = 28, pt = 10, pr = 8, iw = W - pl - pr, ih = H - pt - pb;
    const max = Math.max(1, ...tl.map((b) => b.count)), bw = iw / tl.length;
    const g = sv('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img', 'aria-label': 'Incidents au cours du temps' });
    [0, 0.5, 1].forEach((f) => {
      const y = pt + ih * (1 - f);
      g.append(sv('line', { x1: pl, x2: W - pr, y1: y, y2: y, class: 'grid' }), sv('text', { x: pl - 6, y: y + 4, class: 'axis', 'text-anchor': 'end' }, String(Math.round(max * f))));
    });
    tl.forEach((b, i) => {
      const x = pl + i * bw + bw * 0.15, w = bw * 0.7, h = ih * b.count / max, hc = ih * b.critical / max;
      g.append(sv('rect', { x, y: pt + ih - h, width: w, height: h, rx: 3, class: 'bar' }, sv('title', {}, `${ft(b.t)} — ${b.count} incident(s), dont ${b.critical} critique(s)/élevé(s)`)));
      if (b.critical) g.append(sv('rect', { x, y: pt + ih - hc, width: w, height: hc, rx: 3, class: 'bar-crit' }));
    });
    g.append(sv('text', { x: pl, y: H - 8, class: 'axis' }, ft(tl[0].t).slice(5, 16)), sv('text', { x: W - pr, y: H - 8, class: 'axis', 'text-anchor': 'end' }, ft(tl[tl.length - 1].t).slice(5, 16)));
    return g;
  }
  function donut(by) {
    const keys = Object.keys(SEV), total = keys.reduce((a, k) => a + (by[k] || 0), 0);
    const g = sv('svg', { viewBox: '0 0 42 42', class: 'donut', role: 'img', 'aria-label': 'Répartition par sévérité' });
    g.append(sv('circle', { cx: 21, cy: 21, r: 15.9155, class: 'donut-bg', fill: 'none', 'stroke-width': 5 }));
    let off = 25;
    keys.forEach((k) => {
      const c = by[k] || 0;
      if (!c) return;
      const p = c / total * 100;
      g.append(sv('circle', { cx: 21, cy: 21, r: 15.9155, fill: 'none', 'stroke-width': 5, class: `seg seg-${k}`, 'stroke-dasharray': `${p} ${100 - p}`, 'stroke-dashoffset': off }, sv('title', {}, `${SEV[k]} : ${c}`)));
      off -= p;
    });
    g.append(sv('text', { x: 21, y: 22.5, class: 'donut-total', 'text-anchor': 'middle' }, String(total)), sv('text', { x: 21, y: 28, class: 'donut-label', 'text-anchor': 'middle' }, 'incidents'));
    return el('div', { class: 'donut-wrap' }, g, el('ul', { class: 'legend' }, keys.map((k) => el('li', {}, el('span', { class: `swatch sw-${k}` }), SEV[k], el('b', { text: String(by[k] || 0) })))));
  }
  function hbars(by) {
    const entries = Object.entries(by).sort((a, b) => b[1] - a[1]);
    if (!entries.length) return empty('Aucune donnée');
    const max = Math.max(...entries.map((e) => e[1]));
    return el('div', { class: 'hbars' }, entries.map(([k, v]) => {
      const fill = el('span', { class: 'hbar-fill' });
      fill.style.width = (v / max * 100) + '%';
      return el('div', { class: 'hbar' }, el('span', { class: 'hbar-label', text: SCEN[k] || k }), el('span', { class: 'hbar-track' }, fill), el('b', { text: String(v) }));
    }));
  }

// ------------------------------------------------------------------ composants métier
  function incidentRow(i) {
    const go = () => { location.hash = `#/incidents/${i.id}`; };
    const tr = el('tr', { class: 'clickable', tabindex: 0, onclick: go, onkeydown: (e) => { if (e.key === 'Enter') go(); } },
        el('td', {}, sevBadge(i.severity)), el('td', {}, el('a', { href: `#/incidents/${i.id}`, class: 'link-strong', text: i.id, onclick: (e) => e.stopPropagation() })),
        el('td', { text: SCEN[i.scenario] || i.scenario }), el('td', {}, code(i.src_ip || i.host)),
        el('td', {}, badge(i.verdict, verdictVariant(i.verdict))), el('td', {}, cfBar(i.confidence)),
        el('td', {}, badge(i.status, statusVariant(i.status)), i.pending ? el('span', { class: 'mini-note', text: ` · ${i.pending} à valider` }) : null),
        el('td', { class: 'muted nowrap', text: ft(i.first_ts) }));
    return tr;
  }
  const INC_HEAD = ['Sévérité', 'ID', 'Scénario', 'Source', 'Verdict', 'Certitude', 'Statut', 'Début'];

  function pendingCard(d, compact) {
    return el('div', { class: 'pending-card' },
        el('div', { class: 'pending-main' },
            el('div', { class: 'pending-top' }, sevBadge(d.severity), el('a', { href: `#/incidents/${d.incident_id}`, class: 'link-strong', text: d.incident_id }), el('span', { class: 'muted', text: SCEN[d.scenario] || d.scenario })),
            el('div', { class: 'pending-action' }, el('strong', { text: ACT[d.action] || d.action }), ' sur ', code(d.target), d.sensitive ? badge('action sensible', 'warn') : null),
            el('div', { class: 'muted small', text: d.reason }), cfBar(d.cf)),
        compact ? null : el('div', { class: 'pending-buttons' },
            confirmButton('Approuver', 'primary', () => doAct(`/api/decisions/${d.id}/approve`)),
            confirmButton('Rejeter', 'danger-outline', () => doAct(`/api/decisions/${d.id}/reject`, 'Décision rejetée'))));
  }

// ------------------------------------------------------------------ vues
  function modeText(live) {
    if (live.mode === 'live') return `Surveillance Wazuh en continu — source : ${live.source}`;
    if (live.mode === 'demo') return 'Mode démonstration : données simulées (aucune connexion Wazuh)';
    return 'Aucune source active — démarrez le serveur avec --live (Wazuh) ou --demo (données simulées)';
  }

  async function viewOverview() {
    const d = await api('/api/overview'), k = d.kpi;
    const kpis = [['Incidents', k.incidents, 'détectés au total', ''], ['Critiques / élevés', k.critical_high, 'à traiter en priorité', k.critical_high ? 'danger' : ''],
      ['En attente de validation', k.pending, 'décisions humaines requises', k.pending ? 'warn' : ''], ['Traités automatiquement', k.auto_handled, 'actions exécutées et vérifiées', 'ok'],
      ['Faux positifs écartés', k.false_positives, 'classés bénins par l’agent', ''], ['IP bloquées', k.blocked, 'pare-feu simulé', '']];
    return page('Tableau de bord', modeText(d.live),
        el('div', { class: 'kpi-grid' }, kpis.map(([l, v, h, c]) => el('div', { class: `kpi ${c ? 'kpi-' + c : ''}` }, el('div', { class: 'kpi-label', text: l }), el('div', { class: 'kpi-value', text: String(v) }), el('div', { class: 'kpi-hint', text: h })))),
        el('div', { class: 'grid-2' }, card('Incidents au cours du temps', barChart(d.timeline), el('div', { class: 'chart-legend' }, el('span', { class: 'swatch sw-bar' }), 'Tous les incidents', el('span', { class: 'swatch sw-bar-crit' }), 'dont critiques / élevés')),
            card('Répartition par sévérité', donut(d.by_severity))),
        el('div', { class: 'grid-2' }, card('Incidents récents', d.recent.length ? table(INC_HEAD, d.recent.map(incidentRow)) : empty('Aucun incident', 'En attente d’alertes.')),
            el('div', { class: 'stack' }, card('Par scénario', hbars(d.by_scenario)),
                card('À valider', d.pending.length ? el('div', { class: 'stack-sm' }, d.pending.map((p) => pendingCard(p, true)), el('a', { class: 'btn btn-ghost', href: '#/approvals', text: 'Ouvrir les validations' })) : empty('Rien à valider', 'Aucune décision humaine en attente.')))));
  }

  async function viewIncidents() {
    const f = state.filters, qs = new URLSearchParams(Object.entries(f).filter(([, v]) => v)).toString();
    const rows = await api('/api/incidents' + (qs ? '?' + qs : ''));
    const sel = (name, label, opts) => el('label', { class: 'field' }, el('span', { class: 'field-label', text: label }),
        el('select', { onchange: (e) => { f[name] = e.target.value; render(); } }, el('option', { value: '', text: 'Tous' }), Object.entries(opts).map(([v, t]) => el('option', { value: v, text: t, selected: f[name] === v }))));
    const search = el('input', { type: 'search', class: 'input', placeholder: 'ID, IP, verdict, scénario…', value: f.q, 'aria-label': 'Rechercher',
      oninput: (e) => { f.q = e.target.value; clearTimeout(search._t); search._t = setTimeout(render, 250); } });
    return page('Incidents', 'Chaque incident est une enquête complète : analyse, outils utilisés, décision et vérification.',
        card(null, el('div', { class: 'toolbar' }, el('label', { class: 'field grow' }, el('span', { class: 'field-label', text: 'Recherche' }), search),
                sel('severity', 'Sévérité', SEV), sel('scenario', 'Scénario', SCEN),
                sel('status', 'Statut', { 'traité (action vérifiée)': 'Traité', 'en attente de validation': 'En attente de validation', 'clos (faux positif)': 'Faux positif', 'à traiter par l’analyste': 'À traiter par l’analyste', 'clos (aucune action)': 'Clos' }),
                el('button', { type: 'button', class: 'btn btn-ghost', text: 'Réinitialiser', onclick: () => { Object.assign(f, { q: '', severity: '', scenario: '', status: '' }); render(); } })),
            el('div', { class: 'muted small result-count', text: `${rows.length} incident(s)` }),
            rows.length ? table(INC_HEAD, rows.map(incidentRow)) : empty('Aucun incident ne correspond', 'Modifiez ou réinitialisez les filtres.')));
  }

  function detailSignature(d) {
    return [d.incident.status, d.steps.length, d.decisions.map((x) => x.status + x.actions.length).join(','), d.audit.length].join('|');
  }
  async function viewDetail(iid) {
    const d = await api(`/api/incidents/${encodeURIComponent(iid)}`), inc = d.incident;
    state.detailSig = detailSignature(d);
    const ring = (cf) => {
      const r = 15.9155;
      const c = sv('circle', { cx: 21, cy: 21, r, fill: 'none', 'stroke-width': 4, class: 'ring-fg', 'stroke-dasharray': `${cf * 100} ${100 - cf * 100}`, 'stroke-dashoffset': 25, 'stroke-linecap': 'round' });
      return el('div', { class: 'ring' }, sv('svg', { viewBox: '0 0 42 42', 'aria-hidden': 'true' }, sv('circle', { cx: 21, cy: 21, r, fill: 'none', 'stroke-width': 4, class: 'ring-bg' }), c), el('div', { class: 'ring-text' }, el('b', { text: Math.round(cf * 100) + '%' }), el('span', { text: 'certitude' })));
    };
    const hyps = Object.entries(d.hypotheses).sort((a, b) => b[1] - a[1]);
    const pendingN = d.decisions.filter((x) => x.status === 'pending_approval').length;

    const tabs = {
      summary: ['Synthèse', () => el('div', { class: 'stack' },
          card('Conclusion de l’agent', el('p', { class: 'lead' }, 'Verdict : ', el('strong', { text: inc.verdict }), inc.hypothesis ? [' — hypothèse ', el('strong', { text: HYP[inc.hypothesis] || inc.hypothesis })] : null, `. Sévérité ${SEV[inc.severity] || inc.severity}.`),
              el('p', { class: 'muted', text: `Fin d’enquête : ${inc.stop_reason}.` })),
          card('Hypothèses et certitudes', hyps.length ? el('div', { class: 'hyps' }, hyps.map(([k, v]) => el('div', { class: 'hyp' }, el('span', { class: 'hyp-name', text: HYP[k] || k }), cfBar(v, k.startsWith('benign') ? 'ok' : '')))) : empty('Aucune hypothèse', 'L’agent n’a repéré aucune preuve.')),
          card('Faits clés', factsGrid(d.facts, true)))],
      reasoning: ['Raisonnement de l’agent', () => card('Révision des croyances — preuves retenues', el('p', { class: 'muted small', text: 'Chaque ligne est une preuve repérée par l’agent dans ce qu’il a observé. Les preuves d’une même hypothèse s’accumulent : certitude = a + b × (1 − a).' }),
          d.reasoning.length ? table(['Révision', 'Preuve', 'Constat (valeur réelle)', 'Effet sur les croyances', 'Poids'], d.reasoning.map((f) => el('tr', {},
              el('td', { text: String(f.step) }), el('td', {}, el('div', {}, code(f.ev_id), ' ', el('strong', { text: f.label })), el('div', { class: 'muted small', text: f.detail })),
              el('td', {}, f.observed.map((m) => el('div', { class: 'cond' }, code(`${m.fact} ${m.op} ${m.value}`), el('span', { class: 'muted small', text: ` réel : ${val(m.actual)}` })))),
              el('td', {}, f.effects.map((c) => el('div', { class: 'small', text: c }))), el('td', {}, cfBar(f.weight))))) : empty('Aucune preuve retenue'))],
      steps: ['Investigation', () => card('Déroulé de l’enquête', el('ol', { class: 'timeline' }, d.steps.map((s) => el('li', { class: `tl-item k-${s.kind}` }, el('span', { class: 'tl-dot' }),
          el('div', { class: 'tl-body' }, el('div', { class: 'tl-head' }, el('span', { class: 'tl-kind', text: `${s.n}. ${STEP[s.kind] || s.kind}` }), s.tool ? code(s.tool) : null, el('span', { class: 'muted small nowrap', text: ft(s.ts).slice(11) })),
              el('div', { class: 'tl-text', text: s.text }))))))],
      response: ['Réponse', () => el('div', { class: 'stack' }, card('Décisions', d.decisions.length ? el('div', { class: 'stack-sm' }, d.decisions.map((x) => el('div', { class: 'decision' },
          el('div', { class: 'decision-head' }, el('strong', { text: ACT[x.action] || x.action }), ' sur ', code(x.target), badge(...DEC[x.status] || [x.status, 'muted']), x.sensitive ? badge('action sensible', 'warn') : null, el('span', { class: 'spacer' }), el('span', { class: 'muted small', text: `niveau ${x.level} · CF ${x.cf.toFixed(2)}` })),
          el('div', { class: 'muted small', text: x.reason }),
          x.status === 'pending_approval' ? el('div', { class: 'btn-row' }, confirmButton('Approuver', 'primary', () => doAct(`/api/decisions/${x.id}/approve`)), confirmButton('Rejeter', 'danger-outline', () => doAct(`/api/decisions/${x.id}/reject`, 'Décision rejetée'))) : null,
          x.actions.map((a) => el('div', { class: 'action-line' }, el('span', { text: a.detail }), a.verified ? badge('vérifiée', 'ok') : badge('non vérifiée', 'danger'), a.rolled_back ? badge('annulée', 'muted') : null,
              el('div', { class: 'muted small', text: `Contrôle : ${a.verification}` }),
              !a.rolled_back && a.action !== 'notify_analyst' && a.ok ? confirmButton('Annuler l’action', 'ghost', () => doAct(`/api/actions/${a.id}/rollback`)) : null))))) : empty('Aucune action', 'L’agent n’a proposé aucune réponse pour cet incident.')))],
      evidence: ['Preuves', () => el('div', { class: 'stack' }, card('Extraits des journaux', el('pre', { class: 'logbox', text: d.evidence.join('\n') || '—' })), card('Tous les faits extraits', factsGrid(d.facts, false)))],
      audit: ['Audit', () => card('Journal d’audit', d.audit.length ? table(['Heure', 'Acteur', 'Événement', 'Détail'], d.audit.map((a) => el('tr', {}, el('td', { class: 'nowrap muted', text: ft(a.ts) }), el('td', {}, badge(a.actor, 'info')), el('td', { text: a.event }), el('td', { class: 'muted', text: a.detail || '' })))) : empty('Aucun événement'))],
    };
    if (!tabs[state.tab]) state.tab = 'summary';
    const panel = el('div', { class: 'tabpanel', role: 'tabpanel' });
    const bar = el('div', { class: 'tabs', role: 'tablist' });
    const show = (id) => {
      state.tab = id;
      bar.querySelectorAll('button').forEach((b) => { b.setAttribute('aria-selected', String(b.dataset.tab === id)); b.classList.toggle('active', b.dataset.tab === id); });
      panel.replaceChildren(tabs[id][1]());
    };
    Object.entries(tabs).forEach(([id, [label]]) => bar.append(el('button', { type: 'button', role: 'tab', class: 'tab', 'data-tab': id, text: label + (id === 'response' && pendingN ? ` (${pendingN})` : ''), onclick: () => show(id) })));
    show(state.tab);

    return el('div', { class: 'page' },
        el('a', { href: '#/incidents', class: 'back', text: '← Tous les incidents' }),
        el('div', { class: 'detail-head' }, el('div', { class: 'detail-title' }, el('div', { class: 'detail-badges' }, sevBadge(inc.severity), code(inc.id), badge(SCEN[inc.scenario] || inc.scenario, 'muted'), badge(inc.status, statusVariant(inc.status))), el('h1', { text: inc.title })),
            el('a', { class: 'btn btn-ghost', href: `/api/report/${inc.id}`, download: `${inc.id}.md`, text: 'Télécharger le rapport' })),
        el('div', { class: 'summary-strip' }, ring(inc.confidence),
            el('div', { class: 'ss' }, el('span', { class: 'ss-l', text: 'Verdict' }), badge(inc.verdict, verdictVariant(inc.verdict))), el('div', { class: 'ss' }, el('span', { class: 'ss-l', text: 'Source' }), code(inc.src_ip || inc.host)),
            el('div', { class: 'ss' }, el('span', { class: 'ss-l', text: 'Période' }), el('span', { text: `${ft(inc.first_ts)} → ${ft(inc.last_ts).slice(11)}` })), el('div', { class: 'ss' }, el('span', { class: 'ss-l', text: 'Événements' }), el('span', { text: String(inc.event_count) }))),
        bar, panel);
  }
  function factsGrid(facts, key) {
    const KEY = ['ssh_failed_in_window', 'ssh_distinct_users', 'ssh_success_after_failures', 'post_login_suspicious_cmds', 'scan_distinct_ports', 'scan_sequential_ratio', 'web_sqli_strong_hits', 'web_scanner_ua', 'web_error_after_sqli',
      'file_path', 'file_hash_known_malicious', 'file_ransom_burst_count', 'file_affected_total', 'ip_blacklisted', 'ip_multi_stage', 'ip_scenarios', 'src_is_internal'];
    const entries = Object.entries(facts).filter(([k]) => !key || KEY.includes(k));
    if (!entries.length) return empty('Aucun fait');
    return el('dl', { class: 'facts' }, entries.map(([k, v]) => [el('dt', {}, code(k)), el('dd', { text: val(v) })]));
  }

  async function viewApprovals() {
    const rows = await api('/api/pending');
    return page('Validations humaines', 'Actions sensibles ou à confiance insuffisante : elles ne sont exécutées qu’après votre accord, puis vérifiées.',
        rows.length ? el('div', { class: 'stack' }, rows.map((d) => el('section', { class: 'card' }, pendingCard(d, false), el('div', { class: 'muted small', text: d.incident_title })))) : card(null, empty('Aucune action en attente', 'Tout est à jour. Les nouvelles décisions à valider apparaîtront ici.')));
  }

  async function viewFeed() {
    const d = await api('/api/feed?limit=150'), live = d.live;
    const lvl = (n) => badge(String(n), n >= 10 ? 'danger' : n >= 7 ? 'warn' : n >= 4 ? 'info' : 'muted');
    return page('Flux Wazuh', live.mode === 'live' ? `Alertes reçues de ${live.source}` : 'Alertes Wazuh reçues en temps réel',
        live.mode === 'live' ? card(null, el('div', { class: 'stats-row' }, [['Alertes lues', live.hits_total], ['Événements en mémoire', live.buffer], ['Incidents créés', live.incidents_created], ['Dernière alerte', ago(live.last_event_age_seconds)]].map(([l, v]) => el('div', { class: 'stat' }, el('span', { class: 'stat-l', text: l }), el('b', { text: String(v) }))))) : null,
        card(null, d.rows.length ? table(['Heure (UTC)', 'Agent', 'Règle', 'Niveau', 'Description', 'IP source'], d.rows.map((r) => el('tr', {}, el('td', { class: 'nowrap muted', text: ft(r.ts) }), el('td', { text: r.agent }), el('td', {}, code(r.rule_id || '—')), el('td', {}, lvl(r.level)),
                el('td', {}, el('div', { text: r.description }), el('div', { class: 'muted small mono-clip', text: r.summary })), el('td', {}, r.src_ip ? code(r.src_ip) : '—')))) :
            empty('Aucune alerte reçue', live.mode === 'live' ? 'La connexion est établie mais aucune alerte n’est encore arrivée.' : 'Ce flux s’alimente en mode Wazuh : python -m soc.main serve --live (voir README, section 10).')));
  }

  async function viewResponse() {
    const d = await api('/api/firewall'), s = d.state;
    const kv = (obj, cols) => Object.keys(obj).length ? table(cols, Object.entries(obj).map(([k, v]) => el('tr', {}, el('td', {}, code(k)), el('td', { class: 'muted', text: ft(v.since) }), el('td', { class: 'muted', text: v.expires ? ft(v.expires) : (v.note || '') })))) : empty('Aucune entrée');
    return page('Réponse', 'État des actions exécutées par l’agent.', el('div', { class: 'notice' }, el('strong', { text: 'Actions simulées. ' }), 'Aucune règle n’est appliquée sur un pare-feu réel : l’état ci-dessous est un journal contrôlé, vérifiable et réversible.'),
        el('div', { class: 'grid-2 eq' }, card('IP bloquées', kv(s.blocked, ['IP', 'Depuis', 'Expire'])), card('Machines isolées', kv(s.isolated_hosts, ['Machine', 'Depuis', ''])),
            card('Liste de surveillance', kv(s.watchlist, ['Cible', 'Depuis', 'Note'])),
            card('Quarantaine', (Object.keys(s.quarantine).length || Object.keys(s.quarantine_sim || {}).length) ? table(['Fichier d’origine', 'Mode'], [...Object.values(s.quarantine).map((q) => el('tr', {}, el('td', {}, code(q.original)), el('td', { text: 'Bac à sable (déplacé)' }))), ...Object.keys(s.quarantine_sim || {}).map((p) => el('tr', {}, el('td', {}, code(p)), el('td', { text: 'Simulée (fichier distant)' })))]) : empty('Aucun fichier en quarantaine'))),
        card('Notifications à l’analyste', d.notifications.length ? table(['Heure', 'Incident', 'Message'], d.notifications.map((n) => el('tr', {}, el('td', { class: 'muted nowrap', text: ft(n.ts) }), el('td', {}, el('a', { href: `#/incidents/${n.incident}`, text: n.incident })), el('td', { text: n.message })))) : empty('Aucune notification')));
  }

  async function viewSystem() {
    const d = await api('/api/system'), p = d.policy, live = d.live, w = d.wazuh;
    const row = (k, v) => [el('dt', { text: k }), el('dd', {}, v)];
    const ag = d.agents;
    return page('Système', 'Connexion Wazuh, politique de sécurité de l’agent et renseignement local (IOC).',
        el('div', { class: 'grid-2 eq' }, card('Connexion Wazuh', el('dl', { class: 'facts' },
                row('État', live.mode === 'live' ? badge(live.ok ? (live.stale ? 'en pause' : 'connecté') : 'injoignable', live.ok && !live.stale ? 'ok' : 'danger') : badge(live.mode === 'demo' ? 'démonstration' : 'inactif', 'muted')),
                w ? [row('Mode', w.mode), row('Source', w.mode === 'file' ? w.file : `${w.indexer_url} (${w.index_pattern})`), row('API serveur', w.api_url || '—'), row('Intervalle', `${w.poll_seconds} s`), row('Délai de stabilisation', `${w.settle_seconds} s`), row('Fenêtre d’analyse', `${w.window_minutes} min`)] : row('Configuration', 'config/wazuh.json absent'),
                live.message ? row('Dernier message', live.message) : null, live.last_poll ? row('Dernier sondage', `${ft(live.last_poll)} UTC`) : null)),
            card('Autonomie et sécurité', el('dl', { class: 'facts' }, row('Niveau d’autonomie', `${p.autonomy_level} / 3`), row('IP protégées', p.protected_ips.join(', ') || '—'), row('Machines protégées', p.protected_hosts.join(', ') || '—'),
                row('Étapes max. de l’agent', String(p.agent.max_steps)), row('Seuil de confirmation', String(p.agent.confirm_cf))))),
        card('Agents Wazuh', !ag.configured ? empty('API Wazuh non configurée', 'Ajoutez la section « api » dans config/wazuh.json pour voir l’état des agents.') : !ag.ok ? empty('API Wazuh injoignable', ag.error) :
            table(['ID', 'Nom', 'IP', 'État', 'Système', 'Version', 'Dernier signal'], ag.agents.map((a) => el('tr', {}, el('td', { text: a.id }), el('td', {}, el('strong', { text: a.name })), el('td', {}, code(a.ip || '—')), el('td', {}, badge(a.status || '—', a.status === 'active' ? 'ok' : 'danger')), el('td', { text: a.os }), el('td', { text: a.version || '' }), el('td', { class: 'muted', text: ft(a.last_keepalive) }))))),
        card('Actions autorisées (liste blanche)', table(['Action', 'Automatique', 'Certitude minimale', 'Description'], Object.entries(p.actions).map(([k, v]) => el('tr', {}, el('td', {}, code(k)), el('td', {}, badge(v.auto ? 'oui' : 'validation humaine', v.auto ? 'ok' : 'warn')), el('td', { text: v.min_cf.toFixed(2) }), el('td', { class: 'muted', text: v.description || '' }))))),
        card('Données de renseignement locales', el('dl', { class: 'facts' }, row('IP malveillantes (IOC)', String(d.knowledge.bad_ips)), row('Hash malveillants (IOC)', String(d.knowledge.bad_hashes)))));
  }

// ------------------------------------------------------------------ routage et rendu
  const ROUTES = { overview: viewOverview, incidents: viewIncidents, approvals: viewApprovals, feed: viewFeed, response: viewResponse, system: viewSystem };
  function parseRoute() {
    const parts = (location.hash || '#/overview').replace(/^#\/?/, '').split('/');
    if (parts[0] === 'incidents' && parts[1]) return { name: 'detail', arg: parts[1], view: viewDetail };
    const name = ROUTES[parts[0]] ? parts[0] : 'overview';
    return { name, arg: null, view: ROUTES[name] };
  }
  function buildNav() {
    $('#sidebar').replaceChildren(el('div', { class: 'nav-title', text: 'Supervision' }), ...NAV.map(([id, label, d]) => el('a', { href: `#/${id}`, class: 'nav-link', 'data-nav': id }, icon(d), el('span', { text: label }), id === 'approvals' ? el('span', { class: 'count', id: 'pending-count', hidden: true, text: '0' }) : null)));
  }
  function updateNav(route) {
    const active = route.name === 'detail' ? 'incidents' : route.name;
    document.querySelectorAll('.nav-link').forEach((a) => { const on = a.dataset.nav === active; a.classList.toggle('active', on); if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
    document.body.classList.remove('nav-open');
  }
  let renderToken = 0;
  async function render() {
    const route = parseRoute(), token = ++renderToken, y = window.scrollY;
    try {
      const node = await route.view(route.arg);
      if (token !== renderToken) return;
      $('#view').replaceChildren(node);
      updateNav(route);
      if (y > 0 && typeof window.scrollTo === 'function') { try { window.scrollTo(0, y); } catch (e) { /* ignoré */ } }
    } catch (e) {
      if (token !== renderToken) return;
      $('#view').replaceChildren(page('Erreur', null, card(null, empty('Impossible d’afficher cette page', e.message), el('button', { type: 'button', class: 'btn btn-primary', text: 'Réessayer', onclick: () => render() }))));
    }
  }

// ------------------------------------------------------------------ barre supérieure
  function renderPill(live) {
    const pill = $('#live-pill');
    let text, cls;
    if (live.mode === 'live') {
      if (!live.ok) { text = `Wazuh injoignable — ${live.message}`; cls = 'danger'; }
      else if (live.stale) { text = `Surveillance en pause (dernier sondage ${ago(live.age_seconds)})`; cls = 'warn'; }
      else { text = `Wazuh connecté · dernière alerte ${live.last_event_age_seconds != null ? ago(live.last_event_age_seconds) : '—'}`; cls = 'ok'; }
    } else if (live.mode === 'demo') { text = 'Mode démonstration · données simulées'; cls = 'info'; }
    else { text = 'Aucune source active'; cls = 'muted'; }
    pill.className = `pill pill-${cls}`;
    pill.replaceChildren(el('span', { class: 'pill-dot' }), text);
    pill.title = live.source || '';
  }
  function renderAutonomy(level) {
    const seg = $('#autonomy');
    const titles = { 1: 'Niveau 1 — l’agent propose seulement', 2: 'Niveau 2 — toute action attend une validation humaine', 3: 'Niveau 3 — l’agent exécute les actions autorisées (sauf sensibles)' };
    seg.replaceChildren(...[1, 2, 3].map((n) => el('button', { type: 'button', class: `seg-btn ${n === level ? 'active' : ''}`, title: titles[n], 'aria-pressed': String(n === level), text: `N${n}`,
      onclick: async () => { try { await api('/api/autonomy', { method: 'POST', body: { level: n } }); toast(`Niveau d’autonomie ${n} activé`, 'ok'); await refreshSummary(); } catch (e) { toast(e.message, 'danger'); } } })));
  }
  async function refreshSummary() {
    try {
      const s = await api('/api/summary');
      state.summary = s;
      renderPill(s.live); renderAutonomy(s.autonomy);
      const c = $('#pending-count');
      if (c) { c.textContent = String(s.pending); c.hidden = s.pending === 0; }
      document.title = (s.pending ? `(${s.pending}) ` : '') + 'SOC Agent — Centre d’opérations';
    } catch (e) {
      renderPill({ mode: 'live', ok: false, message: 'serveur de l’interface injoignable' });
    }
  }

// ------------------------------------------------------------------ rafraîchissement automatique
  async function tick() {
    await refreshSummary();
    const route = parseRoute(), view = $('#view');
    const typing = view.contains(document.activeElement) && /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName);
    if (typing || view.querySelector('[data-confirming]')) return;
    if (route.name === 'detail') {
      try { const d = await api(`/api/incidents/${encodeURIComponent(route.arg)}`); if (detailSignature(d) !== state.detailSig) await render(); } catch (e) { /* ignoré */ }
    } else { await render(); }
  }

// ------------------------------------------------------------------ démarrage
  function setTheme(t) { document.documentElement.dataset.theme = t; try { localStorage.setItem('soc-theme', t); } catch (e) { /* stockage indisponible */ } }
  function init() {
    let t = null;
    try { t = localStorage.getItem('soc-theme'); } catch (e) { /* ignoré */ }
    if (t) document.documentElement.dataset.theme = t;
    $('#theme-btn').addEventListener('click', () => {
      const cur = document.documentElement.dataset.theme || (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
      setTheme(cur === 'dark' ? 'light' : 'dark');
    });
    $('#menu-btn').addEventListener('click', () => document.body.classList.toggle('nav-open'));
    buildNav();
    window.addEventListener('hashchange', () => { state.tab = 'summary'; render(); });
    refreshSummary().then(render);
    setInterval(tick, 5000);
  }
  init();
})();
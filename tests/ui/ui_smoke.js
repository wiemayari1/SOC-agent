// Test de l'interface avec jsdom : charge la vraie page, navigue, clique, vérifie le rendu et l'absence de XSS.
// Usage : node tests/ui/ui_smoke.js http://127.0.0.1:PORT        (nécessite : npm install jsdom)
const { JSDOM, VirtualConsole } = require('jsdom');
const base = process.argv[2];
const errors = [];
const failures = [];
const check = (cond, msg) => { if (!cond) failures.push(msg); console.log((cond ? 'OK   ' : 'FAIL ') + msg); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const vc = new VirtualConsole();
  vc.on('jsdomError', (e) => { if (!/Not implemented/.test(e.message)) errors.push(e.message); });
  vc.on('error', (m) => errors.push(String(m)));
  const dom = await JSDOM.fromURL(base + '/', { runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(w) { w.fetch = (u, o) => fetch(new URL(u, base).href, o); } });
  const w = dom.window, d = w.document;
  const $ = (s) => d.querySelector(s), $$ = (s) => [...d.querySelectorAll(s)];
  const waitFor = async (fn, ms = 6000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { try { if (fn()) return true; } catch (e) { /* encore */ } await sleep(40); } return false; };
  const go = async (hash, sel) => { w.location.hash = hash; return waitFor(() => $(sel)); };

  check(await waitFor(() => $('#view .kpi')), 'tableau de bord affiché');
  const kpi = $$('.kpi').map((k) => k.querySelector('.kpi-value').textContent);
  check(kpi[0] === '12' && kpi[2] === '3', `KPI : 12 incidents, 3 à valider (obtenu ${kpi.join('/')})`);
  check($$('.nav-link').length === 6, 'navigation à 6 entrées');
  check(/démonstration/.test($('#live-pill').textContent), 'pastille de mode : démonstration');
  check($('#view svg.chart') && $('#view svg.donut'), 'graphiques SVG présents');
  check($('#pending-count') && $('#pending-count').textContent === '3', 'compteur de validations = 3');

  check(await go('#/incidents', '#view .toolbar'), 'liste des incidents');
  check(await waitFor(() => $$('#view tbody tr').length === 12), '12 lignes dans la liste');
  const sel = $$('#view select')[0]; sel.value = 'critical'; sel.dispatchEvent(new w.Event('change'));
  check(await waitFor(() => $$('#view tbody tr').length === 2), 'filtre « critique » → 2 incidents');
  $$('#view button').find((b) => b.textContent === 'Réinitialiser').click();
  check(await waitFor(() => $$('#view tbody tr').length === 12), 'réinitialisation des filtres');

  check(await go('#/incidents/INC-0004', '#view .summary-strip'), 'détail INC-0004');
  check($('#view .ring') && $$('#view .tab').length === 6, 'anneau de certitude et 6 onglets');
  for (const t of ['reasoning', 'steps', 'response', 'evidence', 'audit', 'summary']) {
    $(`#view .tab[data-tab="${t}"]`).click();
    check($('#view .tabpanel').children.length > 0 && $(`#view .tab[data-tab="${t}"]`).classList.contains('active'), `onglet « ${t} » rendu`);
  }
  $('#view .tab[data-tab="reasoning"]').click();
  check($$('#view .tabpanel tbody tr').length >= 5, 'preuves du raisonnement listées');
  $('#view .tab[data-tab="steps"]').click();
  check($$('#view .timeline .tl-item').length >= 10, 'chronologie de l’enquête');

  check(await go('#/approvals', '#view .pending-card'), 'page des validations');
  check($$('#view .pending-card').length === 3, '3 cartes à valider');
  const approve = $$('#view button').find((b) => b.textContent === 'Approuver');
  approve.click();
  check(approve.textContent === 'Confirmer ?', 'double confirmation demandée');
  approve.click();
  check(await waitFor(() => $$('#view .pending-card').length === 2), 'approbation → 2 cartes restantes');
  check(await waitFor(() => $$('.toast').length > 0), 'notification affichée');

  const n1 = $$('.seg-btn')[0]; n1.click();
  check(await waitFor(() => $$('.seg-btn')[0].classList.contains('active')), 'niveau d’autonomie N1 activé');

  for (const [hash, sel2, name] of [['#/feed', '#view .empty, #view table', 'flux Wazuh'], ['#/response', '#view .notice', 'réponse'], ['#/system', '#view dl.facts', 'système']]) {
    check(await go(hash, sel2), `page « ${name} » rendue`);
    if (name === 'réponse') check(/Actions simulées/.test($('#view .notice').textContent), 'bandeau « actions simulées » affiché');
  }

  // --- sécurité : une valeur hostile venant des journaux ne doit jamais devenir du HTML
  check(await go('#/incidents/INC-0001', '#view .detail-head h1'), 'détail INC-0001 (titre piégé)');
  check($('#view .detail-head h1').textContent.includes('<img src=x onerror=window.__xss=1>'), 'le titre piégé est affiché comme TEXTE');
  $('#view .tab[data-tab="evidence"]').click();
  check(!$('#view img') && !$('#view script') && w.__xss === undefined, 'aucune balise injectée, aucun script exécuté (XSS)');

  $('#theme-btn').click();
  check(d.documentElement.dataset.theme === 'light' || d.documentElement.dataset.theme === 'dark', 'bascule de thème');
  check(errors.length === 0, 'aucune erreur JavaScript' + (errors.length ? ' : ' + errors.join(' | ') : ''));
  w.close();
  console.log(failures.length ? `\n${failures.length} échec(s)` : '\nTous les contrôles de l’interface sont OK');
  process.exit(failures.length ? 1 : 0);
})().catch((e) => { console.error('ERREUR', e); process.exit(2); });

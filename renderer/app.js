'use strict';
/**
 * Mola Vault — renderer/app.js
 * Features:
 *  - Dark / Light / System theme
 *  - 10 languages (en default)
 *  - Encrypt: confirm password + auto-generate password
 *  - Decrypt: auto-detect OR manual format selection (dropdown)
 *  - Progress bar + file size per file
 *  - Virtual keyboard (shuffled or ordered, per settings)
 *  - Screenshot protection toggle (applied via settings)
 *  - Sidebar navigation
 */

/* ── Globals ─────────────────────────────────────────────────────────────── */
const t   = (k, ...a) => window.i18n.t(k, ...a);
const fmt = (b)       => window.i18n.fmtBytes(b);
const $   = id        => document.getElementById(id);
const $$  = sel       => document.querySelectorAll(sel);

/* ── App state ───────────────────────────────────────────────────────────── */
const S = {
  enc: { files: [], sizes: {}, outputDir: null, busy: false },
  dec: { files: [], sizes: {}, outputDir: null, busy: false, detectMode: 'auto', detectedModes: [] },
  settings: { theme: 'dark', language: 'en', screenProtect: true, shuffleVK: true },
  vk: { target: null, buf: '' },     // target: 'enc'|'dec'
  activeTab: 'encrypt',
};

/* ── Boot ────────────────────────────────────────────────────────────────── */
(async () => {
  const saved = await window.vault.getSettings().catch(() => null);
  if (saved) Object.assign(S.settings, saved);
  window.i18n.setLang(S.settings.language);
  applyTheme(S.settings.theme);
  applyI18n();
  syncSettingsPanel();
  updateProtectPill();
  wireBrandLogo();
  wireNav();
  wireEncPanel();
  wireDecPanel();
  wireSettingsPanel();
  wireVirtualKeyboard();
  wireProgressEvents();
  wireKeyboard();
  showPanel('encrypt');
})();

/* ── Logo ────────────────────────────────────────────────────────────────── */
function wireBrandLogo() {
  const img = $('brandLogo');
  if (window.LOGO_DATA_URI) img.src = window.LOGO_DATA_URI;
}

/* ── Theme ───────────────────────────────────────────────────────────────── */
function applyTheme(theme) {
  S.settings.theme = theme;
  const body = document.body;
  body.classList.remove('theme-dark', 'theme-light');
  let resolved = theme;
  if (theme === 'system') resolved = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  body.classList.add(`theme-${resolved}`);
}

/* ── i18n ────────────────────────────────────────────────────────────────── */
function applyI18n() {
  document.documentElement.lang = S.settings.language;
  $$('[data-i18n]').forEach(el => {
    const v = t(el.dataset.i18n);
    if (typeof v === 'string') el.textContent = v;
  });
  $$('[data-i18n-ph]').forEach(el => {
    el.placeholder = t(el.dataset.i18nPh);
  });
  // Re-render file lists (labels may have changed)
  renderFileList('enc');
  renderFileList('dec');
  updateDecBanner();
  updateProtectPill();
}

/* ── Protect pill ────────────────────────────────────────────────────────── */
function updateProtectPill() {
  const pill  = $('protectPill');
  const label = $('protectPillLabel');
  if (!pill || !label) return;
  if (S.settings.screenProtect) {
    pill.classList.remove('off');
    label.textContent = t('screenProtectOn') || 'Protected';
  } else {
    pill.classList.add('off');
    label.textContent = 'Unprotected';
  }
}

/* ── Navigation ──────────────────────────────────────────────────────────── */
function wireNav() {
  $$('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => showPanel(btn.dataset.tab));
  });
}

function showPanel(tab) {
  S.activeTab = tab;
  $$('.nav-item').forEach(b => {
    const a = b.dataset.tab === tab;
    b.classList.toggle('active', a);
    b.setAttribute('aria-selected', String(a));
  });
  ['encrypt','decrypt','settings'].forEach(p => {
    const el = $(`panel-${p}`);
    if (el) el.hidden = p !== tab;
  });
}

/* ════════════════════════════════════════════════════════════════════════════
   ENCRYPT PANEL
   ════════════════════════════════════════════════════════════════════════════ */
function wireEncPanel() {
  // Drop zone
  setupDropZone('enc-drop', 'enc-pick', 'enc', false);
  // Output dir
  $('enc-pickDir').addEventListener('click', async () => {
    const d = await window.vault.selectOutputDir();
    if (d) { S.enc.outputDir = d; setDirLabel('enc-dirPath', d); }
  });
  // Mode cards
  setupModeCards('#panel-encrypt .mode-card');
  // Password eyes
  setupEyeToggle('enc-pwEye', 'enc-pw');
  setupEyeToggle('enc-cpwEye', 'enc-cpw');
  // Strength
  setupStrength('enc-pw', 'enc-strack', 'enc-sfill', 'enc-slbl');
  // Confirm match
  ['enc-pw','enc-cpw'].forEach(id => $( id).addEventListener('input', checkEncMatch));
  // Auto-generate
  $('enc-autoGen').addEventListener('click', handleAutoGen);
  // Input method toggle
  setupImToggle('enc-imToggle', 'enc');
  // Run
  $('enc-run').addEventListener('click', runEncrypt);
}

function checkEncMatch() {
  const pw  = $('enc-pw').value;
  const cpw = $('enc-cpw').value;
  const lbl = $('enc-matchLbl');
  const wrap = $('enc-cpwWrap');
  if (!cpw) { lbl.textContent = ''; lbl.className = 'match-lbl'; wrap.classList.remove('err'); return; }
  if (pw === cpw) {
    lbl.textContent = t('passwordMatch');
    lbl.className   = 'match-lbl ok';
    wrap.classList.remove('err');
  } else {
    lbl.textContent = t('passwordMismatch');
    lbl.className   = 'match-lbl bad';
    wrap.classList.add('err');
  }
}

function handleAutoGen() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+';
  const arr   = new Uint8Array(20);
  crypto.getRandomValues(arr);
  const pw = Array.from(arr).map(b => chars[b % chars.length]).join('');
  $('enc-pw').value  = pw;
  $('enc-pw').type   = 'text';
  $('enc-cpw').value = pw;
  $('enc-cpw').type  = 'text';
  $('enc-pw').dispatchEvent(new Event('input', { bubbles: true }));
  checkEncMatch();
  // Brief copy to clipboard
  navigator.clipboard?.writeText(pw).catch(() => {});
  const btn = $('enc-autoGen');
  const orig = btn.textContent;
  btn.textContent = t('genCopied');
  setTimeout(() => btn.textContent = orig, 1800);
}

async function runEncrypt() {
  if (S.enc.busy) return;
  clearStatus('enc-status');

  const pw  = $('enc-pw').value;
  const cpw = $('enc-cpw').value;
  const mode = document.querySelector('input[name="enc-mode"]:checked')?.value || 'aes256';

  if (!S.enc.files.length)   return setStatus('enc-status', t('errNoFiles'),    'err');
  if (!S.enc.outputDir)      return setStatus('enc-status', t('errNoDir'),      'err');
  if (!pw)                   return setStatus('enc-status', t('errNoPassword'), 'err');
  if (pw.length > 1024)      return setStatus('enc-status', t('errPasswordLong'),'err');
  if (pw !== cpw)            return setStatus('enc-status', t('errPwMismatch'), 'err');

  setBusy('enc', true);
  setStatus('enc-status', t('processing'), 'load');
  showProgress('enc', true);

  const res = await window.vault.encrypt({
    files: [...S.enc.files], outputDir: S.enc.outputDir, mode, password: pw,
  });

  setBusy('enc', false);
  showProgress('enc', false);

  if (!res.success) return setStatus('enc-status', '✗ ' + res.error, 'err');
  setStatusReveal('enc-status', t('encryptDone', res.results.length), res.results[0]?.output);
}

/* ════════════════════════════════════════════════════════════════════════════
   DECRYPT PANEL
   ════════════════════════════════════════════════════════════════════════════ */
function wireDecPanel() {
  setupDropZone('dec-drop', 'dec-pick', 'dec', true);
  $('dec-pickDir').addEventListener('click', async () => {
    const d = await window.vault.selectOutputDir();
    if (d) { S.dec.outputDir = d; setDirLabel('dec-dirPath', d); }
  });
  setupEyeToggle('dec-pwEye', 'dec-pw');
  setupImToggle('dec-imToggle', 'dec');
  // Detect mode toggle
  $$('#dec-detectToggle .im-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('#dec-detectToggle .im-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      S.dec.detectMode = btn.dataset.dm;
      $('dec-banner').hidden      = S.dec.detectMode !== 'auto';
      $('dec-manualWrap').hidden  = S.dec.detectMode !== 'manual';
    });
  });
  $('dec-run').addEventListener('click', runDecrypt);
}

async function updateDecBanner() {
  const banner = $('dec-banner');
  const label  = $('dec-bannerLabel');
  if (!banner || !label) return;
  if (S.dec.files.length === 0 || S.dec.detectMode !== 'auto') { banner.hidden = true; return; }

  const modes   = [...new Set(S.dec.detectedModes.map(d => d.mode).filter(Boolean))];
  const unknown = S.dec.detectedModes.some(d => !d.mode);
  let txt;
  if (unknown && modes.length === 0)       txt = t('unknownMode');
  else if (modes.length === 1 && !unknown) txt = t('detectedMode', modes[0]);
  else                                     txt = t('mixedModes');
  label.textContent = txt;
  banner.hidden = false;
}

async function runDecrypt() {
  if (S.dec.busy) return;
  clearStatus('dec-status');

  const pw = $('dec-pw').value;
  if (!S.dec.files.length)  return setStatus('dec-status', t('errNoFiles'),    'err');
  if (!S.dec.outputDir)     return setStatus('dec-status', t('errNoDir'),      'err');
  if (!pw)                  return setStatus('dec-status', t('errNoPassword'), 'err');

  const forceMode = S.dec.detectMode === 'manual' ? $('dec-formatSelect').value : null;

  setBusy('dec', true);
  setStatus('dec-status', t('processing'), 'load');
  showProgress('dec', true);

  const res = await window.vault.decrypt({
    files: [...S.dec.files], outputDir: S.dec.outputDir, password: pw, forceMode,
  });

  setBusy('dec', false);
  showProgress('dec', false);

  if (!res.success) return setStatus('dec-status', '✗ ' + res.error, 'err');
  let msg = t('decryptDone', res.results.length);
  if (res.errors?.length) msg += '\n' + t('partialError', res.errors.length);
  setStatusReveal('dec-status', msg, res.results[0]?.output);
}

/* ════════════════════════════════════════════════════════════════════════════
   SETTINGS PANEL
   ════════════════════════════════════════════════════════════════════════════ */
function wireSettingsPanel() {
  // Theme cards
  $$('.theme-opts .opt-card').forEach(card => {
    card.addEventListener('click', () => {
      $$('.theme-opts .opt-card').forEach(c => { c.classList.remove('selected'); c.querySelector('input').checked = false; });
      card.classList.add('selected'); card.querySelector('input').checked = true;
      applyTheme(card.dataset.v);
    });
    card.addEventListener('keydown', e => { if (e.key==='Enter'||e.key===' ') { e.preventDefault(); card.click(); } });
  });

  // Lang cards
  $$('.lang-opts .opt-card').forEach(card => {
    card.addEventListener('click', () => {
      $$('.lang-opts .opt-card').forEach(c => { c.classList.remove('selected'); c.querySelector('input').checked = false; });
      card.classList.add('selected'); card.querySelector('input').checked = true;
      S.settings.language = card.dataset.v;
      window.i18n.setLang(card.dataset.v);
      applyI18n();
    });
    card.addEventListener('keydown', e => { if (e.key==='Enter'||e.key===' ') { e.preventDefault(); card.click(); } });
  });

  // Toggles
  $('s-screenProtect').addEventListener('change', e => {
    S.settings.screenProtect = e.target.checked;
    updateProtectPill();
  });
  $('s-shuffleVK').addEventListener('change', e => {
    S.settings.shuffleVK = e.target.checked;
  });

  // Save
  $('saveBtn').addEventListener('click', async () => {
    const theme = document.querySelector('input[name="s-theme"]:checked')?.value || 'dark';
    const lang  = document.querySelector('input[name="s-lang"]:checked')?.value  || 'en';
    const res   = await window.vault.saveSettings({
      theme, language: lang,
      screenProtect: $('s-screenProtect').checked,
      shuffleVK:     $('s-shuffleVK').checked,
    });
    if (res.success) {
      Object.assign(S.settings, res.settings);
      setStatus('s-status', t('settingsSaved'), 'ok');
      setTimeout(() => clearStatus('s-status'), 2200);
    }
  });
}

function syncSettingsPanel() {
  // Theme
  $$('.theme-opts .opt-card').forEach(c => {
    const sel = c.dataset.v === S.settings.theme;
    c.classList.toggle('selected', sel);
    c.querySelector('input').checked = sel;
  });
  // Lang
  $$('.lang-opts .opt-card').forEach(c => {
    const sel = c.dataset.v === S.settings.language;
    c.classList.toggle('selected', sel);
    c.querySelector('input').checked = sel;
  });
  // Toggles
  $('s-screenProtect').checked = S.settings.screenProtect;
  $('s-shuffleVK').checked     = S.settings.shuffleVK;
}

/* ════════════════════════════════════════════════════════════════════════════
   FILE HANDLING
   ════════════════════════════════════════════════════════════════════════════ */
function setupDropZone(zoneId, pickId, scope, forDecrypt) {
  const zone = $(zoneId), btn = $(pickId);
  zone.addEventListener('click',   () => btn.click());
  zone.addEventListener('keydown', e => { if (e.key==='Enter'||e.key===' ') { e.preventDefault(); btn.click(); } });
  zone.addEventListener('dragover',  e => { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', e => { if (!zone.contains(e.relatedTarget)) zone.classList.remove('over'); });
  zone.addEventListener('drop', async e => {
    e.preventDefault(); zone.classList.remove('over');
    const paths = Array.from(e.dataTransfer.files).map(f => f.path).filter(Boolean);
    if (paths.length) { await addFiles(scope, paths); renderFileList(scope); }
  });
  btn.addEventListener('click', async e => {
    e.stopPropagation();
    const paths = await window.vault.selectFile({ forDecrypt });
    if (paths) { await addFiles(scope, paths); renderFileList(scope); }
  });
}

async function addFiles(scope, paths) {
  const st = S[scope];
  paths.forEach(p => { if (!st.files.includes(p)) st.files.push(p); });
  // Fetch file sizes
  const sizeData = await window.vault.getFileSizes(st.files);
  sizeData.forEach(d => { st.sizes[d.file] = d.size; });
  // Detect modes for dec
  if (scope === 'dec') {
    S.dec.detectedModes = await window.vault.detectModes(st.files);
    updateDecBanner();
  }
}

function renderFileList(scope) {
  const st      = S[scope];
  const listEl  = $(`${scope}-list`);
  const labelEl = $(`${scope}-dropLabel`);
  if (!listEl || !labelEl) return;
  listEl.innerHTML = '';

  if (st.files.length === 0) {
    labelEl.textContent = t('dropHint');
    return;
  }
  labelEl.textContent = t('filesSelected', st.files.length);

  st.files.forEach((fp, i) => {
    const name  = fp.split('/').pop() || fp;
    const size  = st.sizes[fp] || 0;
    const item  = document.createElement('div');
    item.className = 'file-item';
    item.setAttribute('role', 'listitem');

    const nameEl = document.createElement('span');
    nameEl.className = 'fi-name'; nameEl.textContent = name; nameEl.title = fp;

    const sizeEl = document.createElement('span');
    sizeEl.className = 'fi-size'; sizeEl.textContent = fmt(size);

    // Mode badge (dec only)
    if (scope === 'dec') {
      const det  = S.dec.detectedModes.find(d => d.file === fp);
      const mode = det?.mode || null;
      const badge = document.createElement('span');
      badge.className = `fi-mode ${mode || 'unk'}`;
      badge.textContent = mode ? mode.toUpperCase() : '?';
      item.appendChild(nameEl);
      item.appendChild(sizeEl);
      item.appendChild(badge);
    } else {
      item.appendChild(nameEl);
      item.appendChild(sizeEl);
    }

    const rm = document.createElement('button');
    rm.className = 'fi-rm'; rm.type = 'button'; rm.textContent = '×';
    rm.setAttribute('aria-label', `Remove ${name}`);
    rm.addEventListener('click', e => {
      e.stopPropagation();
      st.files.splice(i, 1);
      delete st.sizes[fp];
      if (scope === 'dec') {
        S.dec.detectedModes = S.dec.detectedModes.filter(d => d.file !== fp);
        updateDecBanner();
      }
      renderFileList(scope);
    });
    item.appendChild(rm);
    listEl.appendChild(item);
  });
}

/* ════════════════════════════════════════════════════════════════════════════
   PROGRESS
   ════════════════════════════════════════════════════════════════════════════ */
function wireProgressEvents() {
  window.vault.onProgress(data => {
    const scope  = S.enc.busy ? 'enc' : 'dec';
    const fill   = $(`${scope}-progFill`);
    const fileEl = $(`${scope}-progFile`);
    const pctEl  = $(`${scope}-progPct`);
    if (!fill) return;
    const pct = Math.round(data.pct || 0);
    fill.style.width = pct + '%';
    if (fileEl) fileEl.textContent = data.file || '';
    if (pctEl)  pctEl.textContent  = pct + '%';
  });
}

function showProgress(scope, show) {
  const el = $(`${scope}-progress`);
  if (!el) return;
  el.hidden = !show;
  if (!show) {
    const fill = $(`${scope}-progFill`);
    if (fill) fill.style.width = '0%';
  }
}

/* ════════════════════════════════════════════════════════════════════════════
   VIRTUAL KEYBOARD
   ════════════════════════════════════════════════════════════════════════════ */
const VK_ROWS = [
  ['1','2','3','4','5','6','7','8','9','0'],
  ['q','w','e','r','t','y','u','i','o','p'],
  ['a','s','d','f','g','h','j','k','l',';'],
  ['z','x','c','v','b','n','m',',','.','!'],
  ['@','#','$','%','^','&','*','(',')','-'],
];

function wireVirtualKeyboard() {
  $('vkClear').addEventListener('click', () => { S.vk.buf = ''; updateVKDisplay(); });
  $('vkDone').addEventListener('click',  () => closeVK(true));
  $('vkOverlay').addEventListener('click', e => { if (e.target === $('vkOverlay')) closeVK(false); });
}

function buildVKLayout(shifted) {
  const kb = $('vkKb');
  kb.innerHTML = '';
  const shuffle = S.settings.shuffleVK;

  VK_ROWS.forEach(baseRow => {
    const row = shuffle ? [...baseRow].sort(() => Math.random() - .5) : [...baseRow];
    const rowEl = document.createElement('div');
    rowEl.className = 'vk-row';
    row.forEach(ch => {
      const k = document.createElement('button');
      k.className = 'vk-key'; k.type = 'button';
      k.textContent = shifted ? ch.toUpperCase() : ch;
      k.addEventListener('click', () => { if (S.vk.buf.length < 1024) { S.vk.buf += k.textContent; updateVKDisplay(); } });
      rowEl.appendChild(k);
    });
    kb.appendChild(rowEl);
  });

  // Special row
  const specRow = document.createElement('div');
  specRow.className = 'vk-row';

  const shiftK = document.createElement('button');
  shiftK.className = 'vk-key sp'; shiftK.type = 'button';
  shiftK.textContent = shifted ? '⬇ abc' : '⬆ ABC';
  shiftK.addEventListener('click', () => buildVKLayout(!shifted));

  const spaceK = document.createElement('button');
  spaceK.className = 'vk-key spc'; spaceK.type = 'button';
  spaceK.textContent = '⎵';
  spaceK.addEventListener('click', () => { if (S.vk.buf.length < 1024) { S.vk.buf += ' '; updateVKDisplay(); } });

  const bsK = document.createElement('button');
  bsK.className = 'vk-key bs sp'; bsK.type = 'button'; bsK.textContent = '⌫';
  bsK.addEventListener('click', () => { S.vk.buf = S.vk.buf.slice(0, -1); updateVKDisplay(); });

  specRow.appendChild(shiftK);
  specRow.appendChild(spaceK);
  specRow.appendChild(bsK);
  kb.appendChild(specRow);
}

function updateVKDisplay() {
  const d = $('vkDots');
  if (d) d.textContent = '●'.repeat(S.vk.buf.length);
}

function openVK(target) {
  S.vk.target = target;
  S.vk.buf    = '';
  updateVKDisplay();
  buildVKLayout(false);
  // Apply i18n to modal
  $$('#vkOverlay [data-i18n]').forEach(el => {
    const v = t(el.dataset.i18n);
    if (typeof v === 'string') el.textContent = v;
  });
  $('vkOverlay').hidden = false;
}

function closeVK(commit) {
  $('vkOverlay').hidden = true;
  if (commit && S.vk.target) {
    const inp = $(`${S.vk.target}-pw`);
    if (inp) {
      inp.value = S.vk.buf;
      inp.dispatchEvent(new Event('input', { bubbles: true }));
      if (S.vk.target === 'enc') checkEncMatch();
    }
  }
  S.vk.buf = '';
  S.vk.target = null;
}

/* ════════════════════════════════════════════════════════════════════════════
   UI HELPERS
   ════════════════════════════════════════════════════════════════════════════ */
function setupModeCards(sel) {
  $$(sel).forEach(card => {
    card.addEventListener('click', () => {
      $$(sel).forEach(c => { c.classList.remove('selected'); c.setAttribute('aria-checked','false'); });
      card.classList.add('selected'); card.setAttribute('aria-checked','true');
      card.querySelector('input').checked = true;
    });
    card.addEventListener('keydown', e => { if (e.key==='Enter'||e.key===' ') { e.preventDefault(); card.click(); } });
  });
}

function setupImToggle(toggleId, scope) {
  const wrap = $(toggleId);
  if (!wrap) return;
  wrap.querySelectorAll('.im-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      wrap.querySelectorAll('.im-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      if (btn.dataset.m === 'virtual') openVK(scope);
    });
  });
}

function setupEyeToggle(btnId, inputId) {
  const btn = $(btnId), inp = $(inputId);
  if (!btn || !inp) return;
  btn.addEventListener('click', () => {
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    btn.querySelector('.eye-o').style.display = show ? 'none' : '';
    btn.querySelector('.eye-c').style.display = show ? '' : 'none';
  });
}

function setupStrength(inputId, trackId, fillId, labelId) {
  const inp = $(inputId), trk = $(trackId), fill = $(fillId), lbl = $(labelId);
  if (!inp) return;
  const LV = [
    {k:'pwStrWeak',  c:'#f87171', p:18},
    {k:'pwStrWeak',  c:'#fb923c', p:35},
    {k:'pwStrFair',  c:'#fbbf24', p:60},
    {k:'pwStrGood',  c:'#4ade80', p:82},
    {k:'pwStrStrong',c:'#4ade80', p:100},
  ];
  inp.addEventListener('input', () => {
    const pw = inp.value;
    if (!pw) { trk.classList.remove('vis'); lbl.textContent = ''; return; }
    let s = 0;
    if (pw.length >= 8)  s++;
    if (pw.length >= 14) s++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
    if (/[0-9]/.test(pw)) s++;
    if (/[^A-Za-z0-9]/.test(pw)) s++;
    const lv = LV[Math.min(s, 4)];
    trk.classList.add('vis');
    fill.style.width      = lv.p + '%';
    fill.style.background = lv.c;
    lbl.textContent       = t('pwStrLabel', t(lv.k));
    lbl.style.color       = lv.c;
  });
}

function setDirLabel(id, dir) {
  const el = $(id);
  if (!el) return;
  el.textContent = dir.length > 55 ? '…' + dir.slice(-53) : dir;
  el.title = dir;
  el.classList.add('set');
}

function setBusy(scope, busy) {
  S[scope].busy = busy;
  const btn = $(`${scope}-run`);
  if (!btn) return;
  btn.disabled = busy;
  btn.querySelector('.run-arr').style.display  = busy ? 'none' : '';
  btn.querySelector('.run-spin').style.display = busy ? '' : 'none';
}

function setStatus(id, msg, cls = '') {
  const el = $(id); if (!el) return;
  el.textContent = ''; el.className = 'status' + (cls ? ' ' + cls : '');
  el.textContent = msg;
}

function clearStatus(id) { setStatus(id, ''); }

function setStatusReveal(id, msg, outputPath) {
  const el = $(id); if (!el) return;
  el.textContent = ''; el.className = 'status ok';
  const sp = document.createElement('span'); sp.textContent = msg;
  el.appendChild(sp);
  if (outputPath) {
    const lk = document.createElement('span');
    lk.className = 'reveal-link'; lk.textContent = '\n' + t('showInFinder');
    lk.addEventListener('click', () => window.vault.revealInFinder(outputPath));
    el.appendChild(lk);
  }
}

/* ── Global keyboard shortcuts ───────────────────────────────────────────── */
function wireKeyboard() {
  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      if ($('vkOverlay').hidden === false) { closeVK(true); return; }
      if (S.activeTab === 'encrypt' && !S.enc.busy) runEncrypt();
      if (S.activeTab === 'decrypt' && !S.dec.busy) runDecrypt();
    }
    if (e.key === 'Escape') {
      if (!$('vkOverlay').hidden) { closeVK(false); return; }
      ['enc-status','dec-status','s-status'].forEach(clearStatus);
    }
  });
}

'use strict';

const { app, BrowserWindow, ipcMain, dialog, shell, nativeTheme } = require('electron');
const path = require('path');
const fs   = require('fs');
const handler = require('./crypto/handler');

app.commandLine.appendSwitch('disable-renderer-backgrounding');

// ─── Security ─────────────────────────────────────────────────────────────────
app.on('web-contents-created', (_, contents) => {
  contents.on('will-navigate', (e, url) => {
    if (!url.startsWith('file://')) e.preventDefault();
  });
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});

// ─── Settings ─────────────────────────────────────────────────────────────────
const SETTINGS_PATH = path.join(app.getPath('userData'), 'mola-vault-settings.json');
const DEFAULT_SETTINGS = {
  theme:           'dark',
  language:        'en',
  screenProtect:   true,
  shuffleVK:       true,
};

function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_PATH))
      return { ...DEFAULT_SETTINGS, ...JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8')) };
  } catch {}
  return { ...DEFAULT_SETTINGS };
}

function saveSettings(raw) {
  const safe = {
    theme:         ['dark','light','system'].includes(raw.theme)         ? raw.theme    : 'dark',
    language:      ['en','zh-TW','zh-CN','ja','de','nl','es','pt','fr'].includes(raw.language) ? raw.language : 'en',
    screenProtect: raw.screenProtect !== false,
    shuffleVK:     raw.shuffleVK !== false,
  };
  fs.mkdirSync(path.dirname(SETTINGS_PATH), { recursive: true });
  fs.writeFileSync(SETTINGS_PATH, JSON.stringify(safe, null, 2), 'utf8');
  return safe;
}

function resolveTheme(theme) {
  if (theme === 'system') return nativeTheme.shouldUseDarkColors ? 'dark' : 'light';
  return theme;
}

// ─── Window ───────────────────────────────────────────────────────────────────
let mainWindow;

function createWindow() {
  const settings = loadSettings();
  const isDark   = resolveTheme(settings.theme) === 'dark';

  mainWindow = new BrowserWindow({
    width:  900,
    height: 680,
    minWidth:  800,
    minHeight: 600,
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 18, y: 18 },
    vibrancy: 'under-window',
    visualEffectState: 'active',
    backgroundColor: isDark ? '#141416' : '#f0f0f2',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
    },
  });

  if (settings.screenProtect) mainWindow.setContentProtection(true);

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  mainWindow.once('ready-to-show', () => mainWindow.show());
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => app.quit());
app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

// ─── Validators ───────────────────────────────────────────────────────────────
const VALID_MODES = new Set(['aes128', 'aes256', 'zip']);
const isStr    = v => typeof v === 'string' && v.length > 0;
const isStrArr = v => Array.isArray(v) && v.length > 0 && v.every(s => typeof s === 'string');

// ─── IPC: Settings ────────────────────────────────────────────────────────────
ipcMain.handle('get-settings', () => loadSettings());

ipcMain.handle('save-settings', (_, raw) => {
  if (!raw || typeof raw !== 'object') return { success: false };
  try {
    const saved = saveSettings(raw);
    nativeTheme.themeSource = saved.theme === 'system' ? 'system' : saved.theme;
    if (mainWindow) {
      mainWindow.setContentProtection(saved.screenProtect);
      const isDark = resolveTheme(saved.theme) === 'dark';
      mainWindow.setBackgroundColor(isDark ? '#141416' : '#f0f0f2');
    }
    return { success: true, settings: saved };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// ─── IPC: File size info ──────────────────────────────────────────────────────
ipcMain.handle('get-file-sizes', (_, paths) => {
  if (!isStrArr(paths)) return [];
  return paths.map(fp => {
    try {
      const stat = fs.statSync(fp);
      return { file: fp, size: stat.size };
    } catch {
      return { file: fp, size: 0 };
    }
  });
});

// ─── IPC: Detect modes ────────────────────────────────────────────────────────
ipcMain.handle('detect-modes', (_, filePaths) => {
  if (!isStrArr(filePaths)) return [];
  return filePaths.map(fp => {
    const name = path.basename(fp).toLowerCase();
    if (name.endsWith('.aes256')) return { file: fp, mode: 'aes256' };
    if (name.endsWith('.aes128')) return { file: fp, mode: 'aes128' };
    if (name.endsWith('.zip'))    return { file: fp, mode: 'zip'    };
    return { file: fp, mode: null };
  });
});

// ─── IPC: File / dir picker ───────────────────────────────────────────────────
ipcMain.handle('select-file', async (_, opts = {}) => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile', 'multiSelections'],
    filters: opts.forDecrypt
      ? [{ name: 'Encrypted Files', extensions: ['aes256','aes128','zip'] }, { name: 'All Files', extensions: ['*'] }]
      : [{ name: 'All Files', extensions: ['*'] }],
  });
  return result.canceled ? null : result.filePaths;
});

ipcMain.handle('select-output-dir', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory', 'createDirectory'],
  });
  return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle('reveal-in-finder', async (_, fp) => {
  if (isStr(fp)) shell.showItemInFolder(fp);
});

// ─── IPC: Encrypt (with per-file progress events) ────────────────────────────
ipcMain.handle('encrypt', async (event, p) => {
  if (!p || !isStrArr(p.files) || !isStr(p.outputDir) || !VALID_MODES.has(p.mode) || !isStr(p.password))
    return { success: false, error: 'INVALID_PARAMS' };
  if (p.password.length > 1024) return { success: false, error: 'PASSWORD_TOO_LONG' };

  const results = [], errors = [];
  const total = p.files.length;

  for (let i = 0; i < total; i++) {
    const filePath = p.files[i];
    const fileName = path.basename(filePath);
    try {
      // Fire progress before
      event.sender.send('progress', { index: i, total, file: fileName, phase: 'encrypting', pct: 0 });
      const out = await handler.encrypt({
        filePath, outputDir: p.outputDir, mode: p.mode, password: p.password,
        onProgress: pct => event.sender.send('progress', { index: i, total, file: fileName, phase: 'encrypting', pct }),
      });
      event.sender.send('progress', { index: i, total, file: fileName, phase: 'done', pct: 100 });
      results.push({ file: fileName, output: out });
    } catch (e) {
      errors.push({ file: fileName, error: e.message });
    }
  }

  if (results.length === 0 && errors.length > 0)
    return { success: false, error: errors.map(e => `${e.file}: ${e.error}`).join('\n') };
  return { success: true, results, errors };
});

// ─── IPC: Decrypt (with per-file progress events) ─────────────────────────────
ipcMain.handle('decrypt', async (event, p) => {
  if (!p || !isStrArr(p.files) || !isStr(p.outputDir) || !isStr(p.password))
    return { success: false, error: 'INVALID_PARAMS' };

  const results = [], errors = [];
  const total = p.files.length;

  for (let i = 0; i < total; i++) {
    const filePath = p.files[i];
    const fileName = path.basename(filePath);
    try {
      event.sender.send('progress', { index: i, total, file: fileName, phase: 'decrypting', pct: 0 });
      const out = await handler.decryptAuto({
        filePath, outputDir: p.outputDir, password: p.password,
        forceMode: p.forceMode || null,
        onProgress: pct => event.sender.send('progress', { index: i, total, file: fileName, phase: 'decrypting', pct }),
      });
      event.sender.send('progress', { index: i, total, file: fileName, phase: 'done', pct: 100 });
      results.push({ file: fileName, output: out });
    } catch (e) {
      errors.push({ file: fileName, error: e.message });
    }
  }

  if (results.length === 0 && errors.length > 0)
    return { success: false, error: errors.map(e => `${e.file}: ${e.error}`).join('\n') };
  return { success: true, results, errors };
});

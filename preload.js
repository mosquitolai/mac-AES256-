'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vault', {
  getSettings:     ()      => ipcRenderer.invoke('get-settings'),
  saveSettings:    (s)     => ipcRenderer.invoke('save-settings', s),
  getFileSizes:    (paths) => ipcRenderer.invoke('get-file-sizes', paths),
  detectModes:     (paths) => ipcRenderer.invoke('detect-modes', paths),
  selectFile:      (opts)  => ipcRenderer.invoke('select-file', opts || {}),
  selectOutputDir: ()      => ipcRenderer.invoke('select-output-dir'),
  revealInFinder:  (fp)    => ipcRenderer.invoke('reveal-in-finder', fp),

  encrypt: (opts) => ipcRenderer.invoke('encrypt', {
    files: opts.files, outputDir: opts.outputDir,
    mode: opts.mode,   password: opts.password,
  }),

  decrypt: (opts) => ipcRenderer.invoke('decrypt', {
    files: opts.files, outputDir: opts.outputDir,
    password: opts.password, forceMode: opts.forceMode || null,
  }),

  // Progress events from main process
  onProgress: (cb) => {
    ipcRenderer.on('progress', (_, data) => cb(data));
  },
  offProgress: () => {
    ipcRenderer.removeAllListeners('progress');
  },
});

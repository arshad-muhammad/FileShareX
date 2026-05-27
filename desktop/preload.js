const { contextBridge, ipcRenderer } = require('electron');

// Secure context bridge exposing safe, read-only APIs to the renderer
contextBridge.exposeInMainWorld('api', {
  getServerUrl: () => ipcRenderer.sendSync('get-server-url'),
  getAppVersion: () => ipcRenderer.sendSync('get-app-version'),
  createDesktopShortcut: () => ipcRenderer.sendSync('create-desktop-shortcut')
});

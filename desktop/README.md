# 🖥️ FileShareX - Native Desktop Application (Electron)

This directory contains the production-grade **Electron** native desktop application for FileShareX. It encapsulates the core frontend client interface alongside a dynamic local Node.js Express server to run offline local network communications.

---

## 🛠️ Technology Stack & Architecture

- **Wrapper Framework**: Electron 41
- **Installer Builder**: Electron Builder
- **Local Database**: SQLite 3 (with custom JSON atomic persistence fallbacks)
- **Local Webserver**: Express 4, Socket.IO 4, and Multer large-file buffer streams

### 📂 Directory Layout
```
desktop/
├── main.js                   <-- Main Electron thread initiating server & splash screens
├── preload.js                <-- Secure context bridge exposing IPC shortcut channels
├── server.js                 <-- Local Node.js Express HTTP socket server
├── db.js                     <-- SQLite database schema & queries layer
├── database/                 <-- SQLite persistent database directory (chat.db)
├── uploads/                  <-- E2EE chunked large-file local storage
├── renderer/                 <-- UI frontend application files
│   ├── index.html            <-- Main dashboard view, settings modals, and blocked card
│   ├── style.css             <-- Glassmorphic Obsidian UI styles & theme class overrides
│   ├── app.js                <-- Onboarding checks, settings listeners, & signaling coordinate
│   ├── splash.html           <-- borderless circular brand loader overlay
│   └── logo.png              <-- Brand circular asset (512x512 rounded)
└── dist/                     <-- Generated desktop standalone installers (.exe, .dmg, .AppImage)
```

---

## 🚀 Commands & Operations

Run the following commands directly inside this directory (or run their root wrappers):

### 1. Launch Application (Dev Mode)
```bash
npm start
```
Starts the native local Node server threads and launches the Electron application view with DevTools availability.

### 2. Package Desktop Installers
```bash
npm run dist
```
Generates production-ready, standalone desktop installer assets (inside `/desktop/dist/`):
- **Windows**: NSIS `.exe` installer setup
- **macOS**: Standalone `.dmg` package
- **Linux**: Distribution-neutral `.AppImage` bundle

# 🌐 FileShareX - Marketing Website & Static landing Page

This directory contains the high-performance, responsive **Next.js (App Router)** React application serving as the official marketing website and local offline connection portal for FileShareX.

---

## 🛠️ Technology Stack & Structure

- **Framework**: Next.js 14 (App Router)
- **UI Libraries**: React 18, React DOM
- **Static Compilations**: Pre-rendered to raw HTML/CSS pages into `/out` using static exports (`output: 'export'`).

### 📂 Directory Layout
```
website/
├── src/
│   └── app/
│       ├── layout.js             <-- Shared outfit typography & HTML layout wrapper
│       ├── globals.css           <-- Global dark Obsidian & neon variables styles
│       ├── page.js               <-- Bento grid landing page with OS badges
│       └── privacy/
│           └── page.js           <-- Premium glassmorphic zero-knowledge privacy document
├── public/
│   ├── logo.png                  <-- Brand asset (512x512 rounded)
│   └── downloads/                <-- Output setups (.exe, .dmg, .AppImage) served for Wi-Fi peers
├── next.config.js                <-- Configuration declaring static exports
└── out/                          <-- Compiled output folder served by the local Node server
```

---

## 🚀 Commands & Operations

Run the following commands directly inside this directory (or run their root wrappers):

### 1. Run Dev Server
```bash
npm run dev
```
Launches a hot-reloading Next.js dev server on `http://localhost:3000`.

### 2. Compile Production Export
```bash
npm run build
```
Statically compiles and optimizes React files, generating the standalone web resources under `/website/out`.

---

## ☁️ Vercel Deployment

This website is designed to host statically on **Vercel** serverless environments:
* Set the **Framework Preset** inside Vercel settings to **`Other`** or **`Static`**.
* Configure the **Build Command** to: `npm run build`.
* Set the **Output Directory** to: `out`.
* Set up deployment tunnels, and push. Your site builds in less than 40 seconds!

# 🌐 FileShareX - Monorepo Workspace

> **Premium, Ultra-Fast Offline Local-Network Chat, Encrypted Sharing & Collaborative Workspace**
>
> FileShareX is a futuristic, glassmorphic LAN-communication platform. It allows users connected to the same Wi-Fi or Ethernet network to chat, make voice/video calls, draw together on a whiteboard, explore a Virtual NAS drive, and securely share large files of any size without requiring an active internet connection.

This workspace is organized as a clean, professional, and modular **monorepo**:

```
/
├── README.md               <-- [This File] Main directory index
├── package.json            <-- Root unified script wrappers
├── website/                <-- NEXT.JS MARKETING WEBSITE & CONNECTION PORTAL
│   ├── README.md           <-- Web build & deployment guides
│   ├── src/                <-- React website source pages
│   └── out/                <-- Static website builds served by desktop backend
├── desktop/                <-- ELECTRON NATIVE CLIENT & NODE BACKEND SERVER
│   ├── README.md           <-- Desktop app launcher & SQLite database schemas
│   ├── main.js             <-- Electron main thread
│   ├── server.js           <-- Local node socket server whitelisting subnets
│   └── renderer/           <-- Dashboard frontend assets, settings, and themes
└── android/                <-- CAPACITOR NATIVE ANDROID WORKSPACE
    ├── README.md           <-- Play Store targets (API 35) & permissions guide
    └── app/                <-- Gradle application files
```

---

## 🚀 Unified Run Commands

You can execute all builds, dev servers, and synchronizations directly from the **root directory**. The root `package.json` will transparently map these commands to their respective folders:

### 1. Website Commands (`/website`)
*   **Run Next.js Dev Server**:
    ```bash
    npm run web:dev
    ```
*   **Compile Next.js Production Build**:
    ```bash
    npm run web:build
    ```

### 2. Desktop Client Commands (`/desktop`)
*   **Launch Electron Desktop App (Dev Mode)**:
    ```bash
    npm run electron:start
    ```
*   **Compile Standalone Installers (.exe, .dmg, .AppImage)**:
    ```bash
    npm run electron:dist
    ```

### 3. Android Mobile Commands (`/android`)
*   **Sync Web Builds to Android Project**:
    ```bash
    npm run mobile:sync
    ```
*   **Compile Play Store-ready Debug APK (Native)**:
    ```bash
    npm run mobile:build
    ```
    *(For machines running Java 25, please open `/android` in **Android Studio** to compile using compatible bundled JDKs).*

---

## 🛠️ Technology Stack & Architecture

- **Website Core**: React 18, Next.js 14,Outfit Typography HSL Grid, Tailwind CSS (optional fallback).
- **Desktop Core**: Electron 41, Node.js Express 4 backend server, Socket.IO 4 real-time relays, SQLite 3 persistent databases.
- **Mobile Core**: Ionic Capacitor 6 mobile wrapper whitelisting private subnet ranges (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`) in Android network security configurations.

---

## 👥 Standalone Documentation Links
For detailed setup instructions, developer workflows, and system prerequisites, please review the individual sub-project documentations:
*   [🌐 Marketing Website & Connection Portal README](file:///c:/Users/muhda/Documents/gsoc/FileShareX/website/README.md)
*   [🖥️ Electron Standalone Client & Backend Server README](file:///c:/Users/muhda/Documents/gsoc/FileShareX/desktop/README.md)
*   [📱 Capacitor Native Android App & Play Store Guidelines README](file:///c:/Users/muhda/Documents/gsoc/FileShareX/android/README.md)

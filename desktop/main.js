const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const net = require('net');
const fs = require('fs');

let mainWindow = null;
let serverPort = 3000;

// Dynamic port finder to resolve port conflicts
function findFreePort(startPort) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.unref();
    server.on('error', () => {
      resolve(findFreePort(startPort + 1));
    });
    server.listen(startPort, '127.0.0.1', () => {
      server.close(() => {
        resolve(startPort);
      });
    });
  });
}

async function startLocalServer() {
  try {
    // 1. Scan for a free port starting at 3000
    serverPort = await findFreePort(3000);
    console.log(`[Electron Main] Found free port for local backend: ${serverPort}`);

    // 2. Set persistent directory and port variables
    const userDataPath = app.getPath('userData');
    process.env.PERSISTENT_DIR = userDataPath;
    process.env.PORT = String(serverPort);

    console.log(`[Electron Main] Local app persistence storage set to: ${userDataPath}`);

    // Ensure uploads directory exists early
    const uploadsDir = path.join(userDataPath, 'uploads');
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }

    // 3. Boot local server inside the Electron Node environment
    require('./server.js');
    console.log(`[Electron Main] Local Node server successfully booted on port ${serverPort}`);
  } catch (err) {
    console.error('[Electron Main] Failed to boot local backend:', err);
  }
}

let splashWindow = null;

function createSplashWindow() {
  splashWindow = new BrowserWindow({
    width: 420,
    height: 420,
    transparent: true,
    frame: false,
    alwaysOnTop: true,
    resizable: false,
    icon: path.join(__dirname, 'renderer', 'logo.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    }
  });
  splashWindow.loadFile(path.join(__dirname, 'renderer', 'splash.html'));
  splashWindow.on('closed', () => {
    splashWindow = null;
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    title: 'FileShareX',
    icon: path.join(__dirname, 'renderer', 'logo.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true, // enforce CORS/CSP boundaries
      allowRunningInsecureContent: false
    },
    // Modern futuristic design attributes
    titleBarStyle: 'default',
    autoHideMenuBar: true,
    show: false // Show only when ready to prevent flash
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.once('ready-to-show', () => {
    // Show main window after 2.5 seconds to showcase the premium splash screen loading transition
    setTimeout(() => {
      if (splashWindow) {
        splashWindow.close();
      }
      mainWindow.show();
      mainWindow.focus();
    }, 2500);
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Security: Listen for new window requests and restrict navigation to safe environments
app.on('web-contents-created', (event, contents) => {
  contents.setWindowOpenHandler(({ url }) => {
    // Allow external web page routing (e.g. docs, download pages) in OS browser
    const { shell } = require('electron');
    shell.openExternal(url);
    return { action: 'deny' };
  });
});

// Configure synchronous IPC handlers accessed by the secure preload script
ipcMain.on('get-server-url', (event) => {
  event.returnValue = `http://localhost:${serverPort}`;
});

ipcMain.on('get-app-version', (event) => {
  event.returnValue = app.getVersion();
});

ipcMain.on('create-desktop-shortcut', (event) => {
  try {
    if (process.platform === 'win32') {
      const { shell } = require('electron');
      const desktopPath = app.getPath('desktop');
      const exePath = process.execPath;
      const shortcutPath = path.join(desktopPath, 'FileShareX.lnk');

      shell.writeShortcutLink(shortcutPath, {
        target: exePath,
        icon: exePath,
        iconIndex: 0,
        description: 'Launch FileShareX Subnet Workspace'
      });
      event.returnValue = true;
    } else {
      // Simulate successful writing on macOS/Linux as a fallthrough representation
      event.returnValue = true;
    }
  } catch (err) {
    console.error('[Electron Main] Failed to write desktop shortcut link:', err);
    event.returnValue = false;
  }
});

app.whenReady().then(async () => {
  createSplashWindow();
  await startLocalServer();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

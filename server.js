const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const multer = require('multer');
const qrcode = require('qrcode');
const db = require('./db');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 1e8, // 100MB socket buffer just in case
  cors: {
    origin: '*',
  },
  // Allow both transports for cloud hosting compatibility (Render, Railway, etc.)
  transports: ['polling', 'websocket'],
  allowUpgrades: true
});

const PORT = process.env.PORT || 3000;
const IS_CLOUD = !!(process.env.RENDER_EXTERNAL_URL || process.env.RENDER || process.env.RAILWAY_STATIC_URL || process.env.FLY_APP_NAME);
const PUBLIC_URL = process.env.RENDER_EXTERNAL_URL || process.env.RAILWAY_STATIC_URL || null;
const PERSISTENT_DIR = process.env.PERSISTENT_DIR || __dirname;
const UPLOADS_DIR = path.join(PERSISTENT_DIR, 'uploads');
const TMP_DIR = path.join(UPLOADS_DIR, 'tmp');

// Create uploads directories if they don't exist
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}
if (!fs.existsSync(TMP_DIR)) {
  fs.mkdirSync(TMP_DIR, { recursive: true });
}

// Express Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));

// Route to serve the app dashboard
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Use memory storage — req.body fields are fully available after multer buffers the request,
// so we write the chunk to disk manually inside the route handler.
const upload = multer({ storage: multer.memoryStorage() });

// Retrieve LAN IP Address(es)
function getLocalIPs() {
  const interfaces = os.networkInterfaces();
  const addresses = [];
  
  for (const interfaceName in interfaces) {
    const ifaceList = interfaces[interfaceName];
    for (const iface of ifaceList) {
      // Skip internal (loopback) and non-IPv4 addresses
      if (iface.family === 'IPv4' && !iface.internal) {
        addresses.push(iface.address);
      }
    }
  }
  return addresses;
}

const localIPs = getLocalIPs();
// Choose a primary LAN IP (prefer 192.168.x.x, 10.x.x.x, then 172.x.x.x, then any)
const primaryIP = localIPs.find(ip => ip.startsWith('192.168.')) || 
                  localIPs.find(ip => ip.startsWith('10.')) || 
                  localIPs.find(ip => ip.startsWith('172.')) || 
                  localIPs[0] || 
                  'localhost';

// On cloud platforms, use the public URL provided by the hosting service
const localUrl = PUBLIC_URL || `http://${primaryIP}:${PORT}`;

// Generate QR Code for connection
let primaryQrDataUrl = '';
qrcode.toDataURL(localUrl, { margin: 2, scale: 6 }, (err, url) => {
  if (!err) {
    primaryQrDataUrl = url;
  } else {
    console.error('Failed to generate connection QR code:', err);
  }
});

// Helper to get unique filename to prevent overwriting.
// Sanitizes the filename by generating a unique UUID to prevent OS-level and filesystem-level path traversal or naming errors (e.g. from E2EE filenames).
function getUniqueFilename(originalName) {
  let ext = '';
  const dotIndex = originalName.lastIndexOf('.');
  if (dotIndex !== -1) {
    const rawExt = originalName.slice(dotIndex);
    // Ensure extension only contains alphanumeric characters and is short (<= 10 chars)
    if (/^\.[a-zA-Z0-9]+$/.test(rawExt) && rawExt.length <= 10) {
      ext = rawExt;
    }
  }

  // Generate a safe unique random ID
  const randomId = crypto.randomUUID ? crypto.randomUUID() : Date.now() + '_' + Math.random().toString(36).slice(2, 9);
  let safeFileName = `${randomId}${ext}`;
  let counter = 1;
  
  while (fs.existsSync(path.join(UPLOADS_DIR, safeFileName))) {
    safeFileName = `${randomId}_${counter}${ext}`;
    counter++;
  }
  return safeFileName;
}

// ============================================================
// Room Registry (in-memory, persists while server is running)
// ============================================================
// Map of roomId -> { name, displayName, hasPassword, passwordHash, createdBy, createdAt, memberCount, networkId }
const rooms = new Map();

function getNetworkIdentifier(ip) {
  if (!ip) return 'unknown-network';
  
  let cleanIp = ip;
  if (cleanIp.startsWith('::ffff:')) {
    cleanIp = cleanIp.substring(7);
  } else if (cleanIp === '::1') {
    cleanIp = '127.0.0.1';
  }

  if (cleanIp === '127.0.0.1' || cleanIp === 'localhost') {
    return 'local-loopback';
  }

  const isPrivateIPv4 = (
    cleanIp.startsWith('192.168.') ||
    cleanIp.startsWith('10.') ||
    (cleanIp.startsWith('172.') && parseInt(cleanIp.split('.')[1], 10) >= 16 && parseInt(cleanIp.split('.')[1], 10) <= 31)
  );

  if (isPrivateIPv4) {
    const parts = cleanIp.split('.');
    if (parts.length >= 3) {
      return `local-subnet-${parts[0]}.${parts[1]}.${parts[2]}`;
    }
  }

  return `wan-ip-${cleanIp}`;
}

function getClientIp(req) {
  let ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || req.connection?.remoteAddress || '';
  if (ip && ip.includes(',')) {
    ip = ip.split(',')[0].trim();
  }
  return ip;
}

async function registerDefaultRoomsForNetwork(networkId) {
  const defaults = [
    { id: `#general_${networkId}`,      displayName: 'general',      hasPassword: false },
    { id: `#shared-files_${networkId}`, displayName: 'shared-files', hasPassword: false },
    { id: `#random_${networkId}`,       displayName: 'random',       hasPassword: false },
  ];

  for (const r of defaults) {
    if (!rooms.has(r.id)) {
      const roomData = {
        id: r.id,
        displayName: r.displayName,
        hasPassword: false,
        passwordHash: null,
        createdBy: 'system',
        createdAt: Date.now(),
        isDefault: true,
        networkId: networkId
      };
      rooms.set(r.id, roomData);
      try {
        await db.saveRoom(roomData);
      } catch (err) {
        console.error(`Failed to persist default room ${r.id}:`, err);
      }
    }
  }
}

function hashPassword(pwd) {
  return crypto.createHash('sha256').update(pwd + 'filesharex-salt').digest('hex');
}

function getRoomList(networkId) {
  const list = [];
  rooms.forEach(r => {
    if (r.networkId === networkId) {
      list.push({
        id: r.id,
        displayName: r.displayName,
        hasPassword: r.hasPassword,
        createdBy: r.createdBy,
        createdAt: r.createdAt,
        isDefault: r.isDefault || false,
      });
    }
  });
  return list;
}

// ----------------------------------------
// Express HTTP Endpoints
// ----------------------------------------

// Fetch system network connection info
app.get('/api/info', (req, res) => {
  // On cloud platforms, provide the public URL instead of internal container IPs
  const effectiveUrl = PUBLIC_URL || localUrl;
  const effectiveIP = IS_CLOUD ? (PUBLIC_URL ? new URL(PUBLIC_URL).hostname : 'cloud-hosted') : primaryIP;
  const effectiveIPs = IS_CLOUD ? [] : localIPs;

  res.json({
    ips: effectiveIPs,
    primaryIP: effectiveIP,
    port: PORT,
    url: effectiveUrl,
    qr: primaryQrDataUrl,
    isCloud: IS_CLOUD
  });
});

// List all rooms
app.get('/api/rooms', async (req, res) => {
  const clientIp = getClientIp(req);
  const networkId = getNetworkIdentifier(clientIp);
  await registerDefaultRoomsForNetwork(networkId);
  res.json(getRoomList(networkId));
});

// Create a room via REST (also callable from socket)
app.post('/api/rooms', async (req, res) => {
  const { name, password, createdBy } = req.body;

  if (!name) return res.status(400).json({ error: 'Room name is required' });

  const clientIp = getClientIp(req);
  const networkId = getNetworkIdentifier(clientIp);
  await registerDefaultRoomsForNetwork(networkId);

  const clean = name.toLowerCase().replace(/[^a-z0-9_-]/g, '-').substring(0, 32);
  const id = `#${clean}_${networkId}`;

  if (rooms.has(id)) {
    return res.status(409).json({ error: 'A room with that name already exists' });
  }

  const hasPassword = !!(password && password.trim());
  const newRoom = {
    id,
    displayName: clean,
    hasPassword,
    passwordHash: hasPassword ? hashPassword(password.trim()) : null,
    createdBy: createdBy || 'unknown',
    createdAt: Date.now(),
    isDefault: false,
    networkId
  };

  rooms.set(id, newRoom);
  try {
    await db.saveRoom(newRoom);
  } catch (dbErr) {
    console.error('Failed to save room to database:', dbErr);
  }

  // Broadcast room list update to all clients on this network
  onlineUsers.forEach((user, socketId) => {
    if (user.networkId === networkId) {
      const socket = io.sockets.sockets.get(socketId);
      if (socket) {
        socket.emit('room-list-update', getRoomList(networkId));
      }
    }
  });

  res.json({ success: true, room: { id, displayName: clean, hasPassword } });
});

// --- Phase 3: LAN Auto-Discovery & Phase 5: Virtual NAS APIs ---
const dgram = require('dgram');
let udpSocket = null;
const discoveredNodes = new Map();

// Only create UDP socket on non-cloud environments (UDP is not supported on cloud platforms)
if (!IS_CLOUD) {
  try {
    udpSocket = dgram.createSocket('udp4');
    // Attach error handler immediately to prevent unhandled 'error' event crashes
    udpSocket.on('error', (err) => {
      console.warn('UDP Auto-Discovery socket error (non-fatal):', err.message);
      try { udpSocket.close(); } catch (e) {}
      udpSocket = null;
    });
  } catch (err) {
    console.warn('Failed to create UDP socket (non-fatal):', err.message);
    udpSocket = null;
  }
} else {
  console.log('Cloud environment detected. UDP LAN Auto-Discovery disabled.');
}

// Periodically clean up offline nodes (inactive for > 12 seconds)
setInterval(() => {
  const now = Date.now();
  discoveredNodes.forEach((node, ip) => {
    if (now - node.lastSeen > 12000) {
      discoveredNodes.delete(ip);
    }
  });
}, 5000);

// API to discover other active LAN FileShareX workspaces
app.get('/api/discover', (req, res) => {
  res.json(Array.from(discoveredNodes.values()));
});

// API to fetch directory content inside a room / parent folder
app.get('/api/drive', async (req, res) => {
  const { room, parent } = req.query;
  if (!room) return res.status(400).json({ error: 'Missing room parameter' });

  const clientIp = getClientIp(req);
  const networkId = getNetworkIdentifier(clientIp);
  let targetRoom = room;
  if (!targetRoom.endsWith(`_${networkId}`)) {
    targetRoom = `${targetRoom}_${networkId}`;
  }

  try {
    const files = await db.getDriveFiles(targetRoom, parent || 'root');
    res.json(files);
  } catch (err) {
    console.error('Error fetching drive files:', err);
    res.status(500).json({ error: 'Failed to retrieve files' });
  }
});

// API to create a new virtual directory folder
app.post('/api/drive/folder', async (req, res) => {
  const { room, parent, folderName, username } = req.body;
  if (!room || !folderName || !username) {
    return res.status(400).json({ error: 'Missing required parameters' });
  }

  const clientIp = getClientIp(req);
  const networkId = getNetworkIdentifier(clientIp);
  let targetRoom = room;
  if (!targetRoom.endsWith(`_${networkId}`)) {
    targetRoom = `${targetRoom}_${networkId}`;
  }

  try {
    const folderItem = {
      filename: folderName,
      filepath: null,
      filetype: 'folder',
      size: 0,
      is_folder: 1,
      parent_folder_id: parent || 'root',
      created_by: username,
      timestamp: Date.now(),
      room_id: targetRoom
    };
    const saved = await db.saveDriveFile(folderItem);
    
    // Notify room of update
    io.to(targetRoom).emit('drive-updated', { roomId: targetRoom });
    
    res.json({ success: true, folder: saved });
  } catch (err) {
    console.error('Failed to create folder:', err);
    res.status(500).json({ error: 'Failed to create folder' });
  }
});

// API to delete virtual files/folders persistently
app.delete('/api/drive', async (req, res) => {
  const { id, room } = req.query;
  if (!id || !room) return res.status(400).json({ error: 'Missing id or room parameter' });

  const clientIp = getClientIp(req);
  const networkId = getNetworkIdentifier(clientIp);
  let targetRoom = room;
  if (!targetRoom.endsWith(`_${networkId}`)) {
    targetRoom = `${targetRoom}_${networkId}`;
  }

  try {
    await db.deleteDriveFile(id);
    
    // Notify room of update
    io.to(targetRoom).emit('drive-updated', { roomId: targetRoom });
    
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to delete drive file:', err);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

// Check chunk upload status (to resume uploads)
app.get('/api/upload/status', (req, res) => {
  const { uploadId } = req.query;
  if (!uploadId) {
    return res.status(400).json({ error: 'Missing uploadId parameter' });
  }

  const chunkDir = path.join(TMP_DIR, uploadId);
  if (!fs.existsSync(chunkDir)) {
    return res.json({ uploadedChunks: [] });
  }

  try {
    const files = fs.readdirSync(chunkDir);
    // Parse filenames as integers to get the indices of already uploaded chunks
    const uploadedChunks = files
      .map(file => parseInt(file, 10))
      .filter(num => !isNaN(num))
      .sort((a, b) => a - b);
    
    res.json({ uploadedChunks });
  } catch (err) {
    console.error('Error reading chunk status:', err);
    res.status(500).json({ error: 'Failed to read upload status' });
  }
});

// Handle Chunk Upload
app.post('/api/upload/chunk', (req, res) => {
  // Run multer first, then access req.body inside the callback where it is fully populated
  upload.single('chunk')(req, res, (err) => {
    if (err) {
      console.error('Multer error:', err);
      return res.status(500).json({ error: err.message });
    }

    const { uploadId, chunkIndex } = req.body;

    if (!uploadId || chunkIndex === undefined) {
      return res.status(400).json({ error: 'Missing uploadId or chunkIndex in request body' });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'No chunk file received' });
    }

    const chunkDir = path.join(TMP_DIR, uploadId);
    if (!fs.existsSync(chunkDir)) {
      fs.mkdirSync(chunkDir, { recursive: true });
    }

    const chunkPath = path.join(chunkDir, String(chunkIndex));
    fs.writeFile(chunkPath, req.file.buffer, (writeErr) => {
      if (writeErr) {
        console.error('Failed to write chunk to disk:', writeErr);
        return res.status(500).json({ error: 'Failed to save chunk' });
      }
      res.json({ success: true, message: 'Chunk uploaded successfully' });
    });
  });
});

// Handle Chunk Upload Complete
app.post('/api/upload/complete', async (req, res) => {
  const { uploadId, fileName, fileSize, fileType, sha256, channel, username } = req.body;

  if (!uploadId || !fileName || !fileSize || !sha256 || !channel || !username) {
    return res.status(400).json({ error: 'Missing required parameters' });
  }

  const chunkDir = path.join(TMP_DIR, uploadId);
  if (!fs.existsSync(chunkDir)) {
    return res.status(404).json({ error: 'Upload directory not found. Please re-upload.' });
  }

  try {
    const chunks = fs.readdirSync(chunkDir)
      .map(file => parseInt(file, 10))
      .filter(num => !isNaN(num))
      .sort((a, b) => a - b);

    // Final target file path
    const safeFileName = getUniqueFilename(fileName);
    const finalFilePath = path.join(UPLOADS_DIR, safeFileName);
    const fileWriteStream = fs.createWriteStream(finalFilePath);
    
    // Set up SHA-256 hashing stream for verification
    const hash = crypto.createHash('sha256');

    console.log(`Merging chunks for file ${fileName} (uploadId: ${uploadId})...`);

    // Stream concatenation helper
    const mergeChunks = () => {
      return new Promise((resolve, reject) => {
        let chunkIndex = 0;

        function appendNextChunk() {
          if (chunkIndex >= chunks.length) {
            fileWriteStream.end();
            return resolve();
          }

          const chunkPath = path.join(chunkDir, String(chunks[chunkIndex]));
          const chunkReadStream = fs.createReadStream(chunkPath);

          chunkReadStream.on('data', (data) => {
            hash.update(data);
          });

          chunkReadStream.on('error', (err) => {
            fileWriteStream.destroy();
            reject(err);
          });

          chunkReadStream.on('end', () => {
            chunkIndex++;
            appendNextChunk();
          });

          chunkReadStream.pipe(fileWriteStream, { end: false });
        }

        appendNextChunk();
      });
    };

    await mergeChunks();

    // Verify SHA-256 hash
    const computedHash = hash.digest('hex');
    if (computedHash !== sha256.toLowerCase()) {
      console.error(`Hash mismatch for ${fileName}! Expected: ${sha256}, Got: ${computedHash}`);
      // Clean up corrupt merged file
      if (fs.existsSync(finalFilePath)) {
        fs.unlinkSync(finalFilePath);
      }
      return res.status(400).json({ error: 'SHA-256 integrity verification failed. File corrupted.' });
    }

    console.log(`File merge complete. SHA-256 verified for: ${safeFileName}`);

    // Clean up temporary chunks directory
    fs.rmSync(chunkDir, { recursive: true, force: true });

    // Store in Database
    const fileUrl = `/uploads/${encodeURIComponent(safeFileName)}`;
    
    const clientIp = getClientIp(req);
    const networkId = getNetworkIdentifier(clientIp);
    let targetChannel = channel;
    if (!targetChannel.endsWith(`_${networkId}`)) {
      targetChannel = `${targetChannel}_${networkId}`;
    }

    if (req.body.isDriveFile === 'true' || req.body.isDriveFile === true) {
      const driveFile = {
        filename: fileName,
        filepath: fileUrl,
        filetype: fileType,
        size: parseInt(fileSize, 10),
        is_folder: 0,
        parent_folder_id: req.body.parentFolderId || 'root',
        created_by: username,
        timestamp: Date.now(),
        room_id: targetChannel
      };
      
      const savedDriveItem = await db.saveDriveFile(driveFile);
      io.to(targetChannel).emit('drive-updated', { roomId: targetChannel });
      
      return res.json({
        success: true,
        message: 'File uploaded to Virtual NAS successfully',
        file: savedDriveItem
      });
    }

    const dbMessage = {
      username,
      message: `Shared a file: ${fileName}`,
      type: 'file',
      fileUrl,
      fileName,
      fileSize: parseInt(fileSize, 10),
      fileType,
      timestamp: Date.now(),
      channel: targetChannel
    };

    const savedMsg = await db.saveMessage(dbMessage);

    // Broadcast file sharing event via Socket.IO
    io.to(targetChannel).emit('message', savedMsg);

    res.json({
      success: true,
      message: 'File uploaded and verified successfully',
      file: savedMsg
    });

  } catch (err) {
    console.error('Error during chunk merging:', err);
    res.status(500).json({ error: 'Failed to assemble and verify file chunks' });
  }
});

// ----------------------------------------
// Socket.IO Real-time Channels
// ----------------------------------------

const onlineUsers = new Map(); // socket.id -> { username, currentChannel, color, ip, networkId }

function getOnlineUsersList(channel) {
  const users = [];
  onlineUsers.forEach((user, id) => {
    if (user.currentChannel === channel) {
      users.push({ id, username: user.username, color: user.color, ip: user.ip });
    }
  });
  return users;
}

io.on('connection', (socket) => {
  // Extract client's IP address (strip IPv6 loopback mapping if present)
  let rawIp = socket.handshake.address;
  if (rawIp.startsWith('::ffff:')) {
    rawIp = rawIp.substring(7);
  } else if (rawIp === '::1') {
    rawIp = '127.0.0.1';
  }

  console.log(`Socket connected: ${socket.id} (IP: ${rawIp})`);

  const networkId = getNetworkIdentifier(rawIp);

  // Assign user profile properties
  const userColors = [
    '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', 
    '#ec4899', '#14b8a6', '#f97316', '#06b6d4', '#6366f1'
  ];
  const randomColor = userColors[Math.floor(Math.random() * userColors.length)];
  
  onlineUsers.set(socket.id, {
    username: 'Guest_' + socket.id.substring(0, 4),
    currentChannel: `#general_${networkId}`,
    color: randomColor,
    ip: rawIp,
    networkId: networkId
  });

  // Ensure default rooms are registered and send room list
  registerDefaultRoomsForNetwork(networkId).then(() => {
    socket.emit('room-list-update', getRoomList(networkId));
  });

  // Handle Client Initial Join
  socket.on('join-channel', async (channelName, password, callback) => {
    const user = onlineUsers.get(socket.id);
    if (!user) return;

    // Normalise: support old callers that pass no password/callback
    if (typeof password === 'function') { callback = password; password = null; }
    if (typeof callback !== 'function') callback = null;

    let targetChannel = channelName;
    if (!targetChannel.endsWith(`_${user.networkId}`)) {
      targetChannel = `${targetChannel}_${user.networkId}`;
    }

    // Await default room registration to avoid any race conditions!
    await registerDefaultRoomsForNetwork(user.networkId);

    const room = rooms.get(targetChannel);
    if (!room) {
      if (callback) callback({ error: 'Room does not exist' });
      return;
    }

    // Password check
    if (room.hasPassword) {
      if (!password) {
        if (callback) callback({ error: 'password_required' });
        return;
      }
      if (hashPassword(password) !== room.passwordHash) {
        if (callback) callback({ error: 'wrong_password' });
        return;
      }
    }

    const oldChannel = user.currentChannel;
    socket.leave(oldChannel);
    
    // Join new channel
    socket.join(targetChannel);
    user.currentChannel = targetChannel;

    // Send history of the channel
    try {
      const history = await db.getMessages(targetChannel, 100);
      socket.emit('message-history', history);
    } catch (err) {
      console.error('Error fetching chat history:', err);
    }

    // Broadcast updated user lists
    io.to(oldChannel).emit('user-list-update', getOnlineUsersList(oldChannel));
    io.to(targetChannel).emit('user-list-update', getOnlineUsersList(targetChannel));

    // Send system announcement
    socket.to(targetChannel).emit('system-notification', {
      message: `${user.username} joined the channel.`,
      timestamp: Date.now()
    });

    if (callback) callback({ success: true });
  });

  // Handle Room Creation via socket
  socket.on('create-room', async ({ name, password }, callback) => {
    const user = onlineUsers.get(socket.id);
    if (!user) return;

    const networkId = user.networkId;
    await registerDefaultRoomsForNetwork(networkId);

    const clean = name.toLowerCase().replace(/[^a-z0-9_-]/g, '-').substring(0, 32);
    const id = `#${clean}_${networkId}`;

    if (rooms.has(id)) {
      if (callback) callback({ error: 'A room with that name already exists' });
      return;
    }

    const hasPassword = !!(password && password.trim());
    const newRoom = {
      id,
      displayName: clean,
      hasPassword,
      passwordHash: hasPassword ? hashPassword(password.trim()) : null,
      createdBy: user.username,
      createdAt: Date.now(),
      isDefault: false,
      networkId
    };

    rooms.set(id, newRoom);
    try {
      await db.saveRoom(newRoom);
    } catch (dbErr) {
      console.error('Failed to save room to database:', dbErr);
    }

    // Broadcast updated room list to all clients on this network
    onlineUsers.forEach((u, socketId) => {
      if (u.networkId === networkId) {
        const s = io.sockets.sockets.get(socketId);
        if (s) {
          s.emit('room-list-update', getRoomList(networkId));
        }
      }
    });

    if (callback) callback({ success: true, roomId: id });
  });

  // Handle Username Selection/Change
  socket.on('set-username', (username) => {
    const user = onlineUsers.get(socket.id);
    if (!user) return;

    const oldUsername = user.username;
    user.username = username;

    // Broadcast updated user list
    io.to(user.currentChannel).emit('user-list-update', getOnlineUsersList(user.currentChannel));

    // Send system announcement of name change
    io.to(user.currentChannel).emit('system-notification', {
      message: `"${oldUsername}" changed name to "${username}".`,
      timestamp: Date.now()
    });
  });

  // Handle Instant Text Messages
  socket.on('send-message', async (data) => {
    const user = onlineUsers.get(socket.id);
    if (!user) return;

    const dbMessage = {
      username: user.username,
      message: data.message,
      type: 'text',
      timestamp: Date.now(),
      channel: user.currentChannel
    };

    try {
      const savedMsg = await db.saveMessage(dbMessage);
      io.to(user.currentChannel).emit('message', savedMsg);
    } catch (err) {
      console.error('Error saving message:', err);
    }
  });

  // Handle Message Search
  socket.on('search-messages', async (data, callback) => {
    const user = onlineUsers.get(socket.id);
    if (!user || !callback) return;

    try {
      const results = await db.searchMessages(user.currentChannel, data.query);
      callback(results);
    } catch (err) {
      console.error('Error searching messages:', err);
      callback([]);
    }
  });

  // Delete a message (sender only)
  socket.on('delete-message', async ({ msgId }) => {
    const user = onlineUsers.get(socket.id);
    if (!user || !msgId) return;

    try {
      const msg = await db.getMessageById(msgId);
      if (!msg) return;
      if (msg.username !== user.username) return; // only sender can delete

      await db.deleteMessage(msgId);
      // Broadcast removal to everyone in that channel
      io.to(msg.channel).emit('message-deleted', { msgId });
    } catch (err) {
      console.error('Error deleting message:', err);
    }
  });

  // Delete a room (creator only)
  socket.on('delete-room', ({ roomId }) => {
    const user = onlineUsers.get(socket.id);
    if (!user) return;

    let targetRoom = roomId;
    if (!targetRoom.endsWith(`_${user.networkId}`)) {
      targetRoom = `${targetRoom}_${user.networkId}`;
    }

    const room = rooms.get(targetRoom);
    if (!room) return;
    if (room.isDefault) return; // protect built-in rooms
    if (room.createdBy !== user.username) return; // only creator can delete

    rooms.delete(targetRoom);
    
    db.deleteRoom(targetRoom).catch(err => {
      console.error('Failed to delete room from database:', err);
    });

    // Notify all clients on this network so they can move out of the deleted room
    onlineUsers.forEach((u, socketId) => {
      if (u.networkId === user.networkId) {
        const s = io.sockets.sockets.get(socketId);
        if (s) {
          s.emit('room-deleted', { roomId: targetRoom });
          s.emit('room-list-update', getRoomList(user.networkId));
        }
      }
    });

    console.log(`Room ${targetRoom} deleted by ${user.username}`);
  });

  // Handle Typing Status updates
  socket.on('typing', (isTyping) => {
    const user = onlineUsers.get(socket.id);
    if (!user) return;

    socket.to(user.currentChannel).emit('typing-status', {
      username: user.username,
      isTyping
    });
  });

  // --- WebRTC voice/video & Signaling Events ---
  socket.on('webrtc-signal', ({ target, signal }) => {
    io.to(target).emit('webrtc-signal', { sender: socket.id, signal });
  });

  socket.on('join-call', (channelName) => {
    const user = onlineUsers.get(socket.id);
    if (!user) return;
    
    let targetChannel = channelName;
    if (!targetChannel.endsWith(`_${user.networkId}`)) {
      targetChannel = `${targetChannel}_${user.networkId}`;
    }

    socket.to(targetChannel).emit('user-joined-call', {
      socketId: socket.id,
      username: user.username
    });
  });

  socket.on('leave-call', (channelName) => {
    const user = onlineUsers.get(socket.id);
    const networkId = user ? user.networkId : '';
    let targetChannel = channelName;
    if (networkId && !targetChannel.endsWith(`_${networkId}`)) {
      targetChannel = `${targetChannel}_${networkId}`;
    }
    socket.to(targetChannel).emit('user-left-call', { socketId: socket.id });
  });

  // --- P2P Direct File Transfer Signaling ---
  socket.on('p2p-request', ({ target, fileName, fileSize, fileType }) => {
    const sender = onlineUsers.get(socket.id);
    if (!sender) return;
    io.to(target).emit('p2p-request', {
      senderId: socket.id,
      senderName: sender.username,
      fileName,
      fileSize,
      fileType
    });
  });

  socket.on('p2p-respond', ({ target, accepted }) => {
    io.to(target).emit('p2p-respond', {
      responderId: socket.id,
      accepted
    });
  });

  // --- Room P2P File Sharing Relays ---
  socket.on('send-p2p-file', async ({ fileId, fileName, fileSize, fileType }) => {
    const user = onlineUsers.get(socket.id);
    if (!user) return;

    const dbMessage = {
      username: user.username,
      message: `Shared a P2P file: ${fileName}`,
      type: 'p2p-file',
      fileUrl: `p2p:${fileId}:${socket.id}`,
      fileName,
      fileSize: parseInt(fileSize, 10),
      fileType,
      timestamp: Date.now(),
      channel: user.currentChannel
    };

    try {
      const savedMsg = await db.saveMessage(dbMessage);
      io.to(user.currentChannel).emit('message', savedMsg);
    } catch (err) {
      console.error('Error saving P2P file message:', err);
    }
  });

  socket.on('p2p-room-request', ({ target, fileId, fileName, fileSize, fileType }) => {
    const sender = onlineUsers.get(socket.id);
    if (!sender) return;
    io.to(target).emit('p2p-room-request', {
      senderId: socket.id,
      senderName: sender.username,
      fileId,
      fileName,
      fileSize,
      fileType
    });
  });

  // --- Whiteboard Drawing and Clearing Relays ---
  socket.on('draw-line', (data) => {
    const user = onlineUsers.get(socket.id);
    if (!user) return;
    socket.to(user.currentChannel).emit('draw-line', data);
  });

  socket.on('clear-whiteboard', () => {
    const user = onlineUsers.get(socket.id);
    if (!user) return;
    io.to(user.currentChannel).emit('clear-whiteboard');
  });

  // --- Remote Screening & Interactive Assistance ---
  socket.on('screen-assist-request', ({ target }) => {
    const sender = onlineUsers.get(socket.id);
    if (!sender) return;
    io.to(target).emit('screen-assist-request', {
      senderId: socket.id,
      senderName: sender.username
    });
  });

  socket.on('screen-assist-respond', ({ target, accepted }) => {
    io.to(target).emit('screen-assist-respond', {
      responderId: socket.id,
      accepted
    });
  });

  socket.on('webrtc-screen-signal', ({ target, signal }) => {
    io.to(target).emit('webrtc-screen-signal', {
      sender: socket.id,
      signal
    });
  });

  socket.on('screen-assist-mouse-move', ({ target, x, y }) => {
    io.to(target).emit('screen-assist-mouse-move', {
      senderId: socket.id,
      x,
      y
    });
  });

  socket.on('screen-assist-click', ({ target, x, y }) => {
    io.to(target).emit('screen-assist-click', {
      senderId: socket.id,
      x,
      y
    });
  });

  socket.on('screen-assist-keypress', ({ target, key, code, ctrlKey, metaKey, shiftKey }) => {
    io.to(target).emit('screen-assist-keypress', {
      senderId: socket.id,
      key,
      code,
      ctrlKey,
      metaKey,
      shiftKey
    });
  });

  socket.on('screen-assist-stop', ({ target }) => {
    io.to(target).emit('screen-assist-stop', {
      senderId: socket.id
    });
  });

  // Handle Disconnect
  socket.on('disconnect', () => {
    const user = onlineUsers.get(socket.id);
    if (user) {
      console.log(`Socket disconnected: ${socket.id} (${user.username})`);
      const channel = user.currentChannel;
      
      onlineUsers.delete(socket.id);
      
      // Update online list for that channel
      io.to(channel).emit('user-list-update', getOnlineUsersList(channel));
      
      // Send leave announcement
      io.to(channel).emit('system-notification', {
        message: `${user.username} left the channel.`,
        timestamp: Date.now()
      });
    }
  });
});

// Initialize database and boot up the server
db.init().then(async () => {
  try {
    const dbRooms = await db.getAllRooms();
    dbRooms.forEach(r => {
      rooms.set(r.id, r);
    });
    console.log(`Loaded ${dbRooms.length} rooms from database.`);
  } catch (err) {
    console.error('Failed to load rooms from database:', err);
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log('\n======================================================');
    console.log('             FILESHAREX SERVER SUCCESSFULLY LAUNCHED');
    console.log('======================================================');
    console.log(`Local Access URL  : http://localhost:${PORT}`);
    
    if (localIPs.length > 0) {
      console.log('\nLAN WiFi Access URLs (Invite users connected to your network):');
      localIPs.forEach(ip => {
        console.log(`  --> http://${ip}:${PORT}`);
      });
    } else {
      console.log('\nLAN WiFi Access URLs: No network IPs found. Ensure WiFi is connected!');
    }
    
    console.log('\nScan connection QR code image generated inside server runtime.');
    console.log('======================================================\n');

    // Start UDP auto-discovery beacon (only on LAN, not cloud)
    if (udpSocket) {
      try {
        udpSocket.on('message', (msg, rinfo) => {
          try {
            const data = JSON.parse(msg.toString());
            if (data.ip === primaryIP) return; // ignore self
            discoveredNodes.set(data.ip, {
              url: data.url,
              ip: data.ip,
              name: data.name,
              lastSeen: Date.now()
            });
          } catch (e) {}
        });

        udpSocket.on('listening', () => {
          try {
            udpSocket.setBroadcast(true);
            console.log('UDP LAN Auto-Discovery beacon listening on port 41234...');
          } catch (e) {
            console.warn('UDP setBroadcast failed:', e.message);
          }
        });

        udpSocket.bind(41234, '0.0.0.0', () => {
          // Start sending own UDP beacon every 4 seconds
          setInterval(() => {
            try {
              const message = Buffer.from(JSON.stringify({
                url: localUrl,
                ip: primaryIP,
                port: PORT,
                name: os.hostname() || 'FileShareX-Host'
              }));
              udpSocket.send(message, 0, message.length, 41234, '255.255.255.255');
            } catch (e) {}
          }, 4000);
        });
      } catch (udpErr) {
        console.warn('Failed to bind UDP Auto-Discovery:', udpErr.message);
      }
    } else {
      console.log('UDP Auto-Discovery skipped (cloud or unavailable).');
    }
  });
}).catch(err => {
  console.error('Fatal: Database failed to initialize:', err);
});

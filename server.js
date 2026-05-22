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
  }
});

const PORT = 3000;
const UPLOADS_DIR = path.join(__dirname, 'uploads');
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

const localUrl = `http://${primaryIP}:${PORT}`;

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
// Map of roomId -> { name, displayName, hasPassword, passwordHash, createdBy, createdAt, memberCount }
const rooms = new Map();

// Default built-in rooms (no password)
const DEFAULT_ROOMS = [
  { id: '#general',      displayName: 'general',      hasPassword: false },
  { id: '#shared-files', displayName: 'shared-files', hasPassword: false },
  { id: '#random',       displayName: 'random',       hasPassword: false },
];

DEFAULT_ROOMS.forEach(r => {
  rooms.set(r.id, {
    id: r.id,
    displayName: r.displayName,
    hasPassword: false,
    passwordHash: null,
    createdBy: 'system',
    createdAt: Date.now(),
    isDefault: true,
  });
});

function hashPassword(pwd) {
  return crypto.createHash('sha256').update(pwd + 'filesharex-salt').digest('hex');
}

function getRoomList() {
  return Array.from(rooms.values()).map(r => ({
    id: r.id,
    displayName: r.displayName,
    hasPassword: r.hasPassword,
    createdBy: r.createdBy,
    createdAt: r.createdAt,
    isDefault: r.isDefault || false,
  }));
}

// ----------------------------------------
// Express HTTP Endpoints
// ----------------------------------------

// Fetch system network connection info
app.get('/api/info', (req, res) => {
  res.json({
    ips: localIPs,
    primaryIP,
    port: PORT,
    url: localUrl,
    qr: primaryQrDataUrl
  });
});

// List all rooms
app.get('/api/rooms', (req, res) => {
  res.json(getRoomList());
});

// Create a room via REST (also callable from socket)
app.post('/api/rooms', (req, res) => {
  const { name, password, createdBy } = req.body;

  if (!name) return res.status(400).json({ error: 'Room name is required' });

  const clean = name.toLowerCase().replace(/[^a-z0-9_-]/g, '-').substring(0, 32);
  const id = `#${clean}`;

  if (rooms.has(id)) {
    return res.status(409).json({ error: 'A room with that name already exists' });
  }

  const hasPassword = !!(password && password.trim());
  rooms.set(id, {
    id,
    displayName: clean,
    hasPassword,
    passwordHash: hasPassword ? hashPassword(password.trim()) : null,
    createdBy: createdBy || 'unknown',
    createdAt: Date.now(),
    isDefault: false,
  });

  // Broadcast room list update to all clients
  io.emit('room-list-update', getRoomList());

  res.json({ success: true, room: { id, displayName: clean, hasPassword } });
});

// --- Phase 3: LAN Auto-Discovery & Phase 5: Virtual NAS APIs ---
const dgram = require('dgram');
const udpSocket = dgram.createSocket('udp4');
const discoveredNodes = new Map();

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
  try {
    const files = await db.getDriveFiles(room, parent || 'root');
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
      room_id: room
    };
    const saved = await db.saveDriveFile(folderItem);
    
    // Notify room of update
    io.to(room).emit('drive-updated', { roomId: room });
    
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
  try {
    await db.deleteDriveFile(id);
    
    // Notify room of update
    io.to(room).emit('drive-updated', { roomId: room });
    
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
        room_id: channel
      };
      
      const savedDriveItem = await db.saveDriveFile(driveFile);
      io.to(channel).emit('drive-updated', { roomId: channel });
      
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
      channel
    };

    const savedMsg = await db.saveMessage(dbMessage);

    // Broadcast file sharing event via Socket.IO
    io.to(channel).emit('message', savedMsg);

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

const onlineUsers = new Map(); // socket.id -> { username, currentChannel, color, ip }

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

  // Assign user profile properties
  const userColors = [
    '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', 
    '#ec4899', '#14b8a6', '#f97316', '#06b6d4', '#6366f1'
  ];
  const randomColor = userColors[Math.floor(Math.random() * userColors.length)];
  
  onlineUsers.set(socket.id, {
    username: 'Guest_' + socket.id.substring(0, 4),
    currentChannel: '#general',
    color: randomColor,
    ip: rawIp
  });

  // Send current room list on connect
  socket.emit('room-list-update', getRoomList());

  // Handle Client Initial Join
  socket.on('join-channel', async (channelName, password, callback) => {
    const user = onlineUsers.get(socket.id);
    if (!user) return;

    // Normalise: support old callers that pass no password/callback
    if (typeof password === 'function') { callback = password; password = null; }
    if (typeof callback !== 'function') callback = null;

    const room = rooms.get(channelName);
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
    socket.join(channelName);
    user.currentChannel = channelName;

    // Send history of the channel
    try {
      const history = await db.getMessages(channelName, 100);
      socket.emit('message-history', history);
    } catch (err) {
      console.error('Error fetching chat history:', err);
    }

    // Broadcast updated user lists
    io.to(oldChannel).emit('user-list-update', getOnlineUsersList(oldChannel));
    io.to(channelName).emit('user-list-update', getOnlineUsersList(channelName));

    // Send system announcement
    socket.to(channelName).emit('system-notification', {
      message: `${user.username} joined the channel.`,
      timestamp: Date.now()
    });

    if (callback) callback({ success: true });
  });

  // Handle Room Creation via socket
  socket.on('create-room', ({ name, password }, callback) => {
    const user = onlineUsers.get(socket.id);
    if (!user) return;

    const clean = name.toLowerCase().replace(/[^a-z0-9_-]/g, '-').substring(0, 32);
    const id = `#${clean}`;

    if (rooms.has(id)) {
      if (callback) callback({ error: 'A room with that name already exists' });
      return;
    }

    const hasPassword = !!(password && password.trim());
    rooms.set(id, {
      id,
      displayName: clean,
      hasPassword,
      passwordHash: hasPassword ? hashPassword(password.trim()) : null,
      createdBy: user.username,
      createdAt: Date.now(),
      isDefault: false,
    });

    // Broadcast updated room list to all clients
    io.emit('room-list-update', getRoomList());

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

    const room = rooms.get(roomId);
    if (!room) return;
    if (room.isDefault) return; // protect built-in rooms
    if (room.createdBy !== user.username) return; // only creator can delete

    rooms.delete(roomId);

    // Notify all clients so they can move out of the deleted room
    io.emit('room-deleted', { roomId });
    // Send updated room list
    io.emit('room-list-update', getRoomList());

    console.log(`Room ${roomId} deleted by ${user.username}`);
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
    socket.to(channelName).emit('user-joined-call', {
      socketId: socket.id,
      username: user.username
    });
  });

  socket.on('leave-call', (channelName) => {
    socket.to(channelName).emit('user-left-call', { socketId: socket.id });
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
db.init().then(() => {
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

    // Start UDP auto-discovery beacon
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
  });
}).catch(err => {
  console.error('Fatal: Database failed to initialize:', err);
});

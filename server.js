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

// Configure Multer for temp chunk storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadId = req.body.uploadId || req.query.uploadId;
    if (!uploadId) {
      return cb(new Error('Missing uploadId'), null);
    }
    const chunkDir = path.join(TMP_DIR, uploadId);
    if (!fs.existsSync(chunkDir)) {
      fs.mkdirSync(chunkDir, { recursive: true });
    }
    cb(null, chunkDir);
  },
  filename: (req, file, cb) => {
    const chunkIndex = req.body.chunkIndex || req.query.chunkIndex;
    if (chunkIndex === undefined) {
      return cb(new Error('Missing chunkIndex'));
    }
    cb(null, String(chunkIndex)); // Filename is just the index (e.g. '0', '1', '2')
  }
});

const upload = multer({ storage });

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

// Helper to get unique filename to prevent overwriting
function getUniqueFilename(originalName) {
  const parsed = path.parse(originalName);
  let fileName = originalName;
  let counter = 1;
  
  while (fs.existsSync(path.join(UPLOADS_DIR, fileName))) {
    fileName = `${parsed.name}_${counter}${parsed.ext}`;
    counter++;
  }
  return fileName;
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
  upload.single('chunk')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ error: err.message || 'Chunk upload failed' });
    }
    res.json({ success: true, message: 'Chunk uploaded successfully' });
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

  // Handle Client Initial Join
  socket.on('join-channel', async (channelName) => {
    const user = onlineUsers.get(socket.id);
    if (!user) return;

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

  // Handle Typing Status updates
  socket.on('typing', (isTyping) => {
    const user = onlineUsers.get(socket.id);
    if (!user) return;

    socket.to(user.currentChannel).emit('typing-status', {
      username: user.username,
      isTyping
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
  });
}).catch(err => {
  console.error('Fatal: Database failed to initialize:', err);
});

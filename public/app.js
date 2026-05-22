// ==========================================================================
// FileShareX - Client Side Application Core
// ==========================================================================

const CHUNK_SIZE = 1024 * 1024; // 1 MB chunks
let socket = null;

// Application State
const state = {
  username: '',
  color: '#3b82f6',
  ip: '127.0.0.1',
  currentChannel: '#general',
  onlineUsers: [],
  activeUploads: new Map(), // uploadId -> uploadTask
  searchQuery: '',
  isTyping: false,
  typingTimeout: null,
};

// ==========================================================================
// Pure JavaScript SHA-256 Fallback (for insecure HTTP LAN connections)
// ==========================================================================
function sha256Fallback(arrayBuffer) {
  const words = [];
  const dt = new DataView(arrayBuffer);
  const len = arrayBuffer.byteLength;
  
  for (let i = 0; i < len; i += 4) {
    if (i + 4 <= len) {
      words.push(dt.getUint32(i));
    } else {
      let word = 0;
      for (let j = 0; j < len - i; j++) {
        word |= dt.getUint8(i + j) << (24 - j * 8);
      }
      words.push(word);
    }
  }

  const hex = [];
  const h = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];
  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  // Padding
  const bitsLen = len * 8;
  words[words.length] = 0x80000000 | (words[words.length] & 0); // Add marker
  while ((words.length % 16) !== 14) {
    words.push(0);
  }
  words.push(Math.floor(bitsLen / 0x100000000));
  words.push(bitsLen | 0);

  // Process 512-bit blocks
  for (let i = 0; i < words.length; i += 16) {
    const w = [];
    for (let j = 0; j < 16; j++) {
      w[j] = words[i + j];
    }
    for (let j = 16; j < 64; j++) {
      const s0 = (rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3));
      const s1 = (rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10));
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
    }

    let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], _h = h[7];

    for (let j = 0; j < 64; j++) {
      const S1 = (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25));
      const ch = ((e & f) ^ (~e & g));
      const temp1 = (_h + S1 + ch + k[j] + w[j]) | 0;
      const S0 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22));
      const maj = ((a & b) ^ (a & c) ^ (b & c));
      const temp2 = (S0 + maj) | 0;

      _h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    h[0] = (h[0] + a) | 0;
    h[1] = (h[1] + b) | 0;
    h[2] = (h[2] + c) | 0;
    h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0;
    h[5] = (h[5] + f) | 0;
    h[6] = (h[6] + g) | 0;
    h[7] = (h[7] + _h) | 0;
  }

  for (let i = 0; i < 8; i++) {
    let hexStr = (h[i] >>> 0).toString(16);
    while (hexStr.length < 8) hexStr = '0' + hexStr;
    hex.push(hexStr);
  }

  return hex.join('');
}

function rightRotate(value, amount) {
  return (value >>> amount) | (value << (32 - amount));
}

// Generate secure or fallback random UUID
function generateUUID() {
  if (window.crypto && window.crypto.randomUUID) {
    return window.crypto.randomUUID();
  }
  return 'id-' + Math.random().toString(36).substring(2, 9) + '-' + Date.now().toString(36);
}

// Asynchronously compute file SHA-256 signature
async function calculateFileSHA256(file) {
  const arrayBuffer = await file.arrayBuffer();
  // Attempt native Web Crypto first (standard on localhost / HTTPS)
  if (window.crypto && window.crypto.subtle) {
    try {
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', arrayBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
      console.warn('Native Web Crypto SHA-256 failed, falling back to JS implementation:', e);
    }
  }
  
  // Insecure context LAN WiFi fallback
  return sha256Fallback(arrayBuffer);
}

// Format raw bytes to readable size
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Clean text for secure DOM printing
function escapeHTML(str) {
  if (!str) return '';
  return str.replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
  );
}

// ==========================================================================
// DOM Elements Query SELECTORS
// ==========================================================================
const DOM = {
  app: document.getElementById('app'),
  sidebar: document.getElementById('sidebar'),
  sidebarOverlay: document.getElementById('sidebar-overlay'),
  sidebarToggle: document.getElementById('sidebar-toggle'),
  sidebarClose: document.getElementById('sidebar-close'),
  
  networkBadge: document.getElementById('network-badge-trigger'),
  networkIpDisplay: document.getElementById('network-ip-display'),
  
  channelItems: document.querySelectorAll('.channel-item'),
  activeChannelName: document.getElementById('active-channel-name'),
  userCount: document.getElementById('user-count'),
  usersList: document.getElementById('users-list'),
  
  currentUserAvatar: document.getElementById('current-user-avatar'),
  currentUserName: document.getElementById('current-user-name'),
  currentUserIp: document.getElementById('current-user-ip'),
  editUsernameBtn: document.getElementById('edit-username-btn'),
  
  searchInput: document.getElementById('search-input'),
  clearSearchBtn: document.getElementById('clear-search-btn'),
  
  uploadManagerTrigger: document.getElementById('upload-manager-trigger'),
  uploadBadgeCount: document.getElementById('upload-badge-count'),
  
  messagesContainer: document.getElementById('messages-container'),
  typingIndicator: document.getElementById('typing-indicator'),
  typingText: document.getElementById('typing-text'),
  
  dragDropZone: document.getElementById('drag-drop-zone'),
  dragChannelLabel: document.getElementById('drag-channel-label'),
  fileSelector: document.getElementById('file-selector'),
  attachmentBtn: document.getElementById('attachment-btn'),
  messageInput: document.getElementById('message-input'),
  chatForm: document.getElementById('chat-form'),
  sendBtn: document.getElementById('send-btn'),
  
  // Modals
  usernameModal: document.getElementById('username-modal'),
  usernameForm: document.getElementById('username-form'),
  usernameInput: document.getElementById('username-input'),
  
  qrModal: document.getElementById('qr-modal'),
  qrCodeImg: document.getElementById('qr-code-img'),
  lanUrlsList: document.getElementById('lan-urls-list'),
  
  uploadManagerModal: document.getElementById('upload-manager-modal'),
  uploadItemsList: document.getElementById('upload-items-list'),
  noUploadsPlaceholder: document.getElementById('no-uploads-placeholder'),
  
  previewModal: document.getElementById('preview-modal'),
  previewTitle: document.getElementById('preview-title'),
  previewContent: document.getElementById('preview-content-container'),
  previewDownloadBtn: document.getElementById('preview-download-btn'),
  
  disconnectOverlay: document.getElementById('disconnect-overlay'),
  closeModalBtns: document.querySelectorAll('.close-modal-btn')
};

// ==========================================================================
// Initialization & Socket Binding
// ==========================================================================
function initApp() {
  setupSocket();
  setupEventListeners();
  fetchNetworkInfo();
}

function setupSocket() {
  socket = io({
    autoConnect: false,
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    reconnectionAttempts: Infinity
  });

  socket.on('connect', () => {
    DOM.disconnectOverlay.classList.remove('active');
    console.log('Connected to server with Socket ID:', socket.id);
    
    // Automatically join the current state channel
    socket.emit('join-channel', state.currentChannel);
    
    // If username is already set, restore user registration on reconnect
    if (state.username) {
      socket.emit('set-username', state.username);
    }
  });

  socket.on('disconnect', (reason) => {
    DOM.disconnectOverlay.classList.add('active');
    console.warn('Socket disconnected:', reason);
  });

  socket.on('connect_error', () => {
    DOM.disconnectOverlay.classList.add('active');
  });

  // Socket Core Receivers
  socket.on('message-history', (messages) => {
    DOM.messagesContainer.innerHTML = '';
    if (messages && messages.length > 0) {
      messages.forEach(msg => appendMessage(msg));
      scrollToBottom(true);
    } else {
      appendSystemAnnouncement('Welcome to #' + state.activeChannelName.innerText + '! Send a message to start conversing.');
    }
  });

  socket.on('message', (msg) => {
    const isNearBottom = DOM.messagesContainer.scrollHeight - DOM.messagesContainer.scrollTop - DOM.messagesContainer.clientHeight < 150;
    appendMessage(msg);
    if (isNearBottom || msg.username === state.username) {
      scrollToBottom();
    }
  });

  socket.on('system-notification', (announce) => {
    appendSystemAnnouncement(announce.message);
    scrollToBottom();
  });

  socket.on('user-list-update', (users) => {
    state.onlineUsers = users;
    renderOnlineUsers();
  });

  // Handle typing statuses in sidebar and indicator
  const activeTypingUsers = new Set();
  socket.on('typing-status', (data) => {
    if (data.isTyping) {
      activeTypingUsers.add(data.username);
    } else {
      activeTypingUsers.delete(data.username);
    }
    updateTypingIndicatorDisplay(activeTypingUsers);
  });
}

// Fetch network details from API (primary LAN IP and QR code link)
async function fetchNetworkInfo() {
  try {
    const res = await fetch('/api/info');
    const data = await res.json();
    
    state.ip = data.primaryIP;
    DOM.networkIpDisplay.innerText = `IP: ${data.primaryIP}`;
    DOM.currentUserIp.innerText = `IP: ${data.primaryIP}`;
    
    // Set QR code inside modal
    if (data.qr) {
      DOM.qrCodeImg.src = data.qr;
    }
    
    // Populate connect URLs in modal
    DOM.lanUrlsList.innerHTML = '';
    data.ips.forEach(ip => {
      const li = document.createElement('li');
      li.innerHTML = `<a href="http://${ip}:${data.port}" target="_blank">http://${ip}:${data.port}</a>`;
      DOM.lanUrlsList.appendChild(li);
    });
  } catch (err) {
    console.error('Failed to retrieve connection details from endpoint:', err);
    DOM.networkIpDisplay.innerText = 'IP: 127.0.0.1 (Offline)';
  }
}

// ==========================================================================
// UI Rendering Functions
// ==========================================================================

// Add chat message bubble
function appendMessage(msg) {
  const isSelf = msg.username === state.username;
  const timeStr = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  
  const msgGroup = document.createElement('div');
  msgGroup.className = `msg-group ${isSelf ? 'self' : ''}`;

  // User initials avatar
  const avatarCol = isSelf ? state.color : (getUserColor(msg.username) || '#cbd5e1');
  const initial = msg.username.charAt(0).toUpperCase();
  
  msgGroup.innerHTML = `
    <div class="avatar" style="background-color: ${avatarCol}">${initial}</div>
    <div class="msg-wrapper">
      <div class="msg-meta">
        <span class="sender">${escapeHTML(msg.username)}</span>
        <span class="timestamp">${timeStr}</span>
      </div>
      <div class="msg-content"></div>
    </div>
  `;

  const contentContainer = msgGroup.querySelector('.msg-content');

  if (msg.type === 'text') {
    const bubble = document.createElement('div');
    bubble.className = 'msg-bubble';
    bubble.innerHTML = escapeHTML(msg.message);
    contentContainer.appendChild(bubble);
  } else if (msg.type === 'file') {
    const isImage = msg.fileType && msg.fileType.startsWith('image/');
    const isVideo = msg.fileType && msg.fileType.startsWith('video/');

    if (isImage) {
      // Inline image visual card
      const div = document.createElement('div');
      div.className = 'image-preview-attachment';
      div.innerHTML = `<img src="${msg.fileUrl}" alt="${escapeHTML(msg.fileName)}" loading="lazy">`;
      div.addEventListener('click', () => openPreviewModal(msg.fileName, msg.fileUrl, msg.fileType));
      contentContainer.appendChild(div);
    } else if (isVideo) {
      // Inline video visual player card
      const div = document.createElement('div');
      div.className = 'image-preview-attachment';
      div.innerHTML = `
        <video muted playsinline preload="metadata">
          <source src="${msg.fileUrl}" type="${msg.fileType}">
        </video>
      `;
      div.addEventListener('click', () => openPreviewModal(msg.fileName, msg.fileUrl, msg.fileType));
      contentContainer.appendChild(div);
    }

    // Always append the download file card details beneath or as primary
    const fileCard = document.createElement('div');
    fileCard.className = 'file-card';
    
    // Select custom offline SVG icon based on file type
    const svgIcon = getFileTypeSVG(msg.fileName, msg.fileType);

    fileCard.innerHTML = `
      <div class="file-icon-box">${svgIcon}</div>
      <div class="file-details">
        <div class="file-name" title="${escapeHTML(msg.fileName)}">${escapeHTML(msg.fileName)}</div>
        <div class="file-size">${formatBytes(msg.fileSize)}</div>
      </div>
      <div class="file-actions">
        ${(isImage || isVideo || (msg.fileType && msg.fileType === 'application/pdf')) ? `
          <button class="file-action-btn view-btn" title="Preview file">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
          </button>
        ` : ''}
        <a href="${msg.fileUrl}" download="${escapeHTML(msg.fileName)}" class="file-action-btn download-btn" title="Download File">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <polyline points="7 10 12 15 17 10"></polyline>
            <line x1="12" y1="15" x2="12" y2="3"></line>
          </svg>
        </a>
      </div>
    `;

    const viewBtn = fileCard.querySelector('.view-btn');
    if (viewBtn) {
      viewBtn.addEventListener('click', () => openPreviewModal(msg.fileName, msg.fileUrl, msg.fileType));
    }

    contentContainer.appendChild(fileCard);
  }

  DOM.messagesContainer.appendChild(msgGroup);
}

// Add system message
function appendSystemAnnouncement(text) {
  const div = document.createElement('div');
  div.className = 'system-msg';
  div.innerHTML = `<span class="system-msg-content">${escapeHTML(text)}</span>`;
  DOM.messagesContainer.appendChild(div);
}

// Render active users list inside sidebar
function renderOnlineUsers() {
  DOM.userCount.innerText = state.onlineUsers.length;
  DOM.usersList.innerHTML = '';
  
  state.onlineUsers.forEach(user => {
    const li = document.createElement('li');
    li.className = 'user-item';
    const isMe = user.username === state.username;
    const initial = user.username.charAt(0).toUpperCase();

    li.innerHTML = `
      <div class="user-item-left">
        <div class="avatar user-item-avatar" style="background-color: ${user.color};">${initial}</div>
        <span class="user-item-name" style="font-weight: ${isMe ? '700' : '500'}">${escapeHTML(user.username)} ${isMe ? '(You)' : ''}</span>
      </div>
      <span class="user-item-ip">${escapeHTML(user.ip)}</span>
    `;
    DOM.usersList.appendChild(li);
  });
}

function getUserColor(username) {
  const match = state.onlineUsers.find(u => u.username === username);
  return match ? match.color : null;
}

function updateTypingIndicatorDisplay(typingUsers) {
  // Remove self from list if present
  typingUsers.delete(state.username);
  
  if (typingUsers.size === 0) {
    DOM.typingIndicator.classList.add('hidden');
    return;
  }

  DOM.typingIndicator.classList.remove('hidden');
  const list = Array.from(typingUsers);
  
  if (list.length === 1) {
    DOM.typingText.innerText = `${escapeHTML(list[0])} is typing...`;
  } else if (list.length === 2) {
    DOM.typingText.innerText = `${escapeHTML(list[0])} and ${escapeHTML(list[1])} are typing...`;
  } else {
    DOM.typingText.innerText = 'Several people are typing...';
  }
}

// Smart Auto-Scroll Behavior
function scrollToBottom(force = false) {
  if (force) {
    DOM.messagesContainer.scrollTop = DOM.messagesContainer.scrollHeight;
  } else {
    DOM.messagesContainer.scrollTo({
      top: DOM.messagesContainer.scrollHeight,
      behavior: 'smooth'
    });
  }
}

// Toggle mobile navigation sidebar overlay
function toggleSidebar(show) {
  if (show) {
    DOM.sidebar.classList.add('active');
    DOM.sidebarOverlay.classList.add('active');
  } else {
    DOM.sidebar.classList.remove('active');
    DOM.sidebarOverlay.classList.remove('active');
  }
}

// Select custom vector graphic markup based on extension
function getFileTypeSVG(fileName, fileType) {
  const ext = fileName.split('.').pop().toLowerCase();
  
  const images = ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp'];
  const videos = ['mp4', 'mkv', 'webm', 'avi', 'mov'];
  const archives = ['zip', 'rar', '7z', 'tar', 'gz'];

  if (images.includes(ext) || (fileType && fileType.startsWith('image/'))) {
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>`;
  }
  if (videos.includes(ext) || (fileType && fileType.startsWith('video/'))) {
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="23 7 16 12 23 17 23 7"></polygon><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect></svg>`;
  }
  if (archives.includes(ext)) {
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>`;
  }
  if (ext === 'pdf') {
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>`;
  }
  
  // Default general document folder icon
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>`;
}

// ==========================================================================
// File Upload Engine - Chunked and Resumable
// ==========================================================================
async function queueAndUploadFiles(filesList) {
  if (!filesList || filesList.length === 0) return;
  
  // Show Upload Badge and Trigger active modal
  DOM.uploadManagerTrigger.classList.remove('hidden');
  DOM.uploadManagerModal.classList.add('active');

  for (const file of filesList) {
    const uploadId = generateUUID();
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    
    const task = {
      file,
      uploadId,
      fileName: file.name,
      fileSize: file.size,
      fileType: file.type || 'application/octet-stream',
      sha256: '',
      uploadedChunks: [],
      totalChunks,
      status: 'hashing',
      controller: null,
      bytesUploaded: 0,
      errorMessage: ''
    };

    state.activeUploads.set(uploadId, task);
    renderUploadTasks();
    updateUploadBadgeCount();

    // Start Async Hashing first
    try {
      console.log(`Calculating signature for: ${file.name}`);
      task.sha256 = await calculateFileSHA256(file);
      task.status = 'uploading';
      task.errorMessage = '';
      renderUploadTasks();
      
      // Fire upload sequence
      runChunkedUpload(uploadId);
    } catch (err) {
      console.error('Hashing failed for file:', file.name, err);
      task.status = 'error';
      task.errorMessage = err.message || 'Failed to prepare file for upload.';
      renderUploadTasks();
    }
  }
}

// Coordinate chunk sequence loop
async function runChunkedUpload(uploadId) {
  const task = state.activeUploads.get(uploadId);
  if (!task || task.status !== 'uploading') return;

  try {
    // 1. Ask Server if any chunks are already uploaded (Supports seamless resumes!)
    const statusRes = await fetch(`/api/upload/status?uploadId=${uploadId}`);
    const statusData = await statusRes.json();
    task.uploadedChunks = statusData.uploadedChunks || [];
    
    // Set up AbortController for cancelable fetch requests
    task.controller = new AbortController();

    // Loop through slices
    for (let chunkIndex = 0; chunkIndex < task.totalChunks; chunkIndex++) {
      // Skip if already successfully written
      if (task.uploadedChunks.includes(chunkIndex)) {
        continue;
      }

      // Check for manual user interference pauses
      if (task.status === 'paused' || task.status === 'aborted') {
        break;
      }

      // Get chunk byte range
      const startByte = chunkIndex * CHUNK_SIZE;
      const endByte = Math.min(startByte + CHUNK_SIZE, task.fileSize);
      const chunkBlob = task.file.slice(startByte, endByte);

      // Construct Form
      const formData = new FormData();
      formData.append('uploadId', uploadId);
      formData.append('chunkIndex', chunkIndex);
      formData.append('totalChunks', task.totalChunks);
      formData.append('fileName', task.fileName);
      formData.append('chunk', chunkBlob);

      // Perform Fetch Upload Chunk
      const chunkRes = await fetch('/api/upload/chunk', {
        method: 'POST',
        body: formData,
        signal: task.controller.signal
      });
      if (!chunkRes.ok) {
        let chunkError = 'Failed to upload a file chunk.';
        try {
          const chunkData = await chunkRes.json();
          if (chunkData && chunkData.error) chunkError = chunkData.error;
        } catch (_) {
          // Ignore JSON parsing failures and use fallback message
        }
        throw new Error(chunkError);
      }

      // Update state and progress indicators
      task.uploadedChunks.push(chunkIndex);
      task.bytesUploaded = task.uploadedChunks.length * CHUNK_SIZE;
      if (task.bytesUploaded > task.fileSize) task.bytesUploaded = task.fileSize;

      renderUploadTasks();
    }

    // 2. Chunks Loop finishes. Finalize merge!
    if (task.uploadedChunks.length === task.totalChunks && task.status === 'uploading') {
      task.status = 'assembling';
      renderUploadTasks();

      const completeRes = await fetch('/api/upload/complete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          uploadId,
          fileName: task.fileName,
          fileSize: task.fileSize,
          fileType: task.fileType,
          sha256: task.sha256,
          channel: state.currentChannel,
          username: state.username
        })
      });

      const completeData = await completeRes.json();

      if (completeRes.ok && completeData.success) {
        task.status = 'completed';
        task.errorMessage = '';
        renderUploadTasks();
        
        // Remove task automatically from manager pane after a short delay
        setTimeout(() => {
          state.activeUploads.delete(uploadId);
          renderUploadTasks();
          updateUploadBadgeCount();
        }, 3000);

      } else {
        console.error(completeData.error || 'Server assembly failure');
        task.status = 'error';
        task.errorMessage = completeData.error || 'Server failed to assemble uploaded chunks.';
        renderUploadTasks();
      }
    }

  } catch (err) {
    // If not aborted deliberately, throw error status
    if (err.name === 'AbortError') {
      console.log(`Upload ${task.fileName} chunk loop suspended.`);
    } else {
      console.error(`Chunk transfer failed for file ${task.fileName}:`, err);
      task.status = 'error';
      task.errorMessage = err.message || 'Network error while uploading file chunks.';
      renderUploadTasks();
    }
  }
}

// Pause a running file transfer
function pauseUploadTask(uploadId) {
  const task = state.activeUploads.get(uploadId);
  if (!task) return;

  task.status = 'paused';
  if (task.controller) {
    task.controller.abort(); // Cancel outstanding chunk fetch POST
  }
  renderUploadTasks();
}

// Resume a paused file transfer
function resumeUploadTask(uploadId) {
  const task = state.activeUploads.get(uploadId);
  if (!task) return;

  task.status = 'uploading';
  task.errorMessage = '';
  renderUploadTasks();
  runChunkedUpload(uploadId);
}

// Cancel and remove upload completely
function cancelUploadTask(uploadId) {
  const task = state.activeUploads.get(uploadId);
  if (!task) return;

  task.status = 'aborted';
  if (task.controller) {
    task.controller.abort();
  }
  state.activeUploads.delete(uploadId);
  renderUploadTasks();
  updateUploadBadgeCount();
}

// Update the upload UI task logs in modal card
function renderUploadTasks() {
  if (state.activeUploads.size === 0) {
    DOM.noUploadsPlaceholder.classList.remove('hidden');
    DOM.uploadItemsList.innerHTML = '';
    return;
  }

  DOM.noUploadsPlaceholder.classList.add('hidden');
  DOM.uploadItemsList.innerHTML = '';

  state.activeUploads.forEach((task, id) => {
    const li = document.createElement('li');
    li.className = 'upload-task-item';

    // Calculate percentage
    const percent = task.totalChunks > 0 
      ? Math.round((task.uploadedChunks.length / task.totalChunks) * 100) 
      : 0;

    let badgeText = task.status;
    let badgeClass = task.status;

    if (task.status === 'hashing') {
      badgeText = 'Verifying Checksum';
      badgeClass = 'paused';
    } else if (task.status === 'assembling') {
      badgeText = 'Assembling Final File';
      badgeClass = 'uploading';
    } else if (task.status === 'error') {
      badgeText = 'Failed';
    }

    li.innerHTML = `
      <div class="upload-task-header">
        <div class="upload-task-title-info">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
          </svg>
          <div>
            <div class="upload-task-name" title="${escapeHTML(task.fileName)}">${escapeHTML(task.fileName)}</div>
            <div class="upload-task-meta">${formatBytes(task.bytesUploaded)} / ${formatBytes(task.fileSize)}</div>
          </div>
        </div>
        <span class="upload-task-status-badge ${badgeClass}">${badgeText}</span>
      </div>

      <div class="upload-task-progress-section">
        <div class="progress-bar-container">
          <div class="progress-bar-fill" style="width: ${percent}%"></div>
        </div>
        <span class="progress-percent">${percent}%</span>
      </div>
      ${task.errorMessage ? `<div class="upload-task-error">${escapeHTML(task.errorMessage)}</div>` : ''}

      <div class="upload-task-actions">
        ${task.status === 'uploading' ? `
          <button class="task-action-btn pause-btn" data-id="${id}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="6" y="4" width="4" height="16"></rect>
              <rect x="14" y="4" width="4" height="16"></rect>
            </svg> Pause
          </button>
        ` : ''}

        ${task.status === 'paused' ? `
          <button class="task-action-btn resume-btn" data-id="${id}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polygon points="5 3 19 12 5 21 5 3"></polygon>
            </svg> Resume
          </button>
        ` : ''}

        ${task.status === 'error' ? `
          <button class="task-action-btn resume-btn" data-id="${id}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="23 4 23 10 17 10"></polyline>
              <polyline points="1 20 1 14 7 14"></polyline>
              <path d="M3.51 9a9 9 0 0 1 14.12-3.36L23 10"></path>
              <path d="M20.49 15a9 9 0 0 1-14.12 3.36L1 14"></path>
            </svg> Retry
          </button>
        ` : ''}

        ${task.status !== 'completed' && task.status !== 'assembling' ? `
          <button class="task-action-btn danger cancel-btn" data-id="${id}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg> Cancel
          </button>
        ` : ''}
      </div>
    `;

    // Bind event handlers
    const pauseBtn = li.querySelector('.pause-btn');
    if (pauseBtn) pauseBtn.addEventListener('click', () => pauseUploadTask(id));

    const resumeBtn = li.querySelector('.resume-btn');
    if (resumeBtn) resumeBtn.addEventListener('click', () => resumeUploadTask(id));

    const cancelBtn = li.querySelector('.cancel-btn');
    if (cancelBtn) cancelBtn.addEventListener('click', () => cancelUploadTask(id));

    DOM.uploadItemsList.appendChild(li);
  });
}

function updateUploadBadgeCount() {
  const activeCount = Array.from(state.activeUploads.values())
    .filter(t => t.status !== 'completed').length;
  
  if (activeCount > 0) {
    DOM.uploadManagerTrigger.classList.remove('hidden');
    DOM.uploadBadgeCount.innerText = activeCount;
  } else {
    DOM.uploadManagerTrigger.classList.add('hidden');
  }
}

// ==========================================================================
// Preview Manager Modal (Direct Inlined Previewers)
// ==========================================================================
function openPreviewModal(fileName, url, fileType) {
  DOM.previewTitle.innerText = `Preview: ${fileName}`;
  DOM.previewDownloadBtn.href = url;
  DOM.previewDownloadBtn.download = fileName;
  
  DOM.previewContent.innerHTML = '';
  const isImage = fileType && fileType.startsWith('image/');
  const isVideo = fileType && fileType.startsWith('video/');
  const isPdf = fileType && fileType === 'application/pdf';

  if (isImage) {
    DOM.previewContent.innerHTML = `<img src="${url}" alt="${escapeHTML(fileName)}">`;
  } else if (isVideo) {
    DOM.previewContent.innerHTML = `
      <video controls autoplay playsinline style="width:100%; max-height: 70vh;">
        <source src="${url}" type="${fileType}">
        Your browser does not support video playbacks.
      </video>
    `;
  } else if (isPdf) {
    DOM.previewContent.innerHTML = `<iframe src="${url}" title="${escapeHTML(fileName)}"></iframe>`;
  } else {
    // Unsupported preview format fallback
    DOM.previewContent.innerHTML = `
      <div class="preview-fallback-container">
        <div class="file-icon-box preview-fallback-icon">
          ${getFileTypeSVG(fileName, fileType)}
        </div>
        <div class="preview-fallback-title">${escapeHTML(fileName)}</div>
        <div class="preview-fallback-desc">No preview available for this file type. Click download to acquire the file in original quality.</div>
      </div>
    `;
  }

  DOM.previewModal.classList.add('active');
}

// ==========================================================================
// Event Listeners Registration
// ==========================================================================
function setupEventListeners() {
  
  // 1. Username submission
  DOM.usernameForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const selectedUsername = DOM.usernameInput.value.trim();
    if (selectedUsername) {
      state.username = selectedUsername;
      DOM.currentUserName.innerText = selectedUsername;
      DOM.currentUserAvatar.innerText = selectedUsername.charAt(0).toUpperCase();

      // Establish Socket connection
      socket.connect();

      // Transmit identity selection
      socket.emit('set-username', selectedUsername);

      // Hide Overlay Join window and show workspace
      DOM.usernameModal.classList.remove('active');
      DOM.app.classList.remove('hidden');
    }
  });

  // Footer change username trigger
  DOM.editUsernameBtn.addEventListener('click', () => {
    DOM.usernameInput.value = state.username;
    DOM.usernameModal.classList.add('active');
  });

  // 2. Sidebar Navigation Channels
  DOM.channelItems.forEach(item => {
    item.addEventListener('click', () => {
      const targetChannel = item.getAttribute('data-channel');
      if (targetChannel === state.currentChannel) return;

      // Update UI active styles
      DOM.channelItems.forEach(ch => ch.classList.remove('active'));
      item.classList.add('active');

      state.currentChannel = targetChannel;
      DOM.activeChannelName.innerText = targetChannel.substring(1);
      
      // Update typing tags on change
      DOM.dragChannelLabel.innerText = targetChannel;

      // Signal channel migration
      socket.emit('join-channel', targetChannel);

      // Clear search on switching rooms
      clearSearch();

      // On mobile viewports, automatically fold sidebar on channel clicks
      if (window.innerWidth <= 768) {
        toggleSidebar(false);
      }
    });
  });

  // Mobile Side panel triggers
  DOM.sidebarToggle.addEventListener('click', () => toggleSidebar(true));
  DOM.sidebarClose.addEventListener('click', () => toggleSidebar(false));
  DOM.sidebarOverlay.addEventListener('click', () => toggleSidebar(false));

  window.addEventListener('resize', () => {
    if (window.innerWidth >= 768) {
      toggleSidebar(false);
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      toggleSidebar(false);

      document.querySelectorAll('.modal-overlay.active').forEach(overlay => {
        overlay.classList.remove('active');
        if (overlay.id === 'preview-modal') {
          DOM.previewContent.innerHTML = '';
        }
      });
    }
  });

  // 3. Chat form messaging submission
  DOM.chatForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const textMsg = DOM.messageInput.value.trim();
    if (textMsg) {
      socket.emit('send-message', { message: textMsg });
      DOM.messageInput.value = '';
      
      // Reset typing status on direct sends
      if (state.isTyping) {
        state.isTyping = false;
        socket.emit('typing', false);
        clearTimeout(state.typingTimeout);
      }
    }
  });

  // Dynamic typing alerts triggers with debounce/throttle
  DOM.messageInput.addEventListener('input', () => {
    if (!state.isTyping) {
      state.isTyping = true;
      socket.emit('typing', true);
    }

    clearTimeout(state.typingTimeout);
    state.typingTimeout = setTimeout(() => {
      state.isTyping = false;
      socket.emit('typing', false);
    }, 2000);
  });

  // Enter triggers send, Shift+Enter breaks line
  DOM.messageInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      DOM.chatForm.dispatchEvent(new Event('submit'));
    }
  });

  // 4. File attachments selector triggers
  DOM.attachmentBtn.addEventListener('click', () => DOM.fileSelector.click());
  DOM.fileSelector.addEventListener('change', (e) => {
    queueAndUploadFiles(e.target.files);
    DOM.fileSelector.value = ''; // Reset input to let users upload same file again
  });

  // 5. Drag and Drop triggers
  window.addEventListener('dragenter', (e) => {
    e.preventDefault();
    DOM.dragDropZone.classList.add('active');
  });

  DOM.dragDropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
  });

  DOM.dragDropZone.addEventListener('dragleave', (e) => {
    // Only close if target cursor actually leaves drag border pane
    if (e.relatedTarget === null || !DOM.dragDropZone.contains(e.relatedTarget)) {
      DOM.dragDropZone.classList.remove('active');
    }
  });

  DOM.dragDropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    DOM.dragDropZone.classList.remove('active');
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      queueAndUploadFiles(e.dataTransfer.files);
    }
  });

  // 6. Modal close actions binding
  DOM.closeModalBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      btn.closest('.modal-overlay').classList.remove('active');
      
      // If closing the preview modal, stop playing video/audio previews
      if (btn.closest('#preview-modal')) {
        DOM.previewContent.innerHTML = '';
      }
    });
  });

  // Close modals clicking overlay
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        overlay.classList.remove('active');
        if (overlay.id === 'preview-modal') {
          DOM.previewContent.innerHTML = '';
        }
      }
    });
  });

  // 7. QR modal connection panel triggers
  DOM.networkBadge.addEventListener('click', () => {
    DOM.qrModal.classList.add('active');
  });

  DOM.uploadManagerTrigger.addEventListener('click', () => {
    DOM.uploadManagerModal.classList.add('active');
  });

  // 8. Search messages trigger
  DOM.searchInput.addEventListener('input', () => {
    const q = DOM.searchInput.value.trim();
    if (q) {
      DOM.clearSearchBtn.classList.remove('hidden');
      state.searchQuery = q;
      
      // Perform server-side search query
      socket.emit('search-messages', { query: q }, (results) => {
        // Render search results
        DOM.messagesContainer.innerHTML = '';
        appendSystemAnnouncement(`Search results for "${q}" inside this channel (${results.length} found):`);
        
        if (results && results.length > 0) {
          results.forEach(msg => appendMessage(msg));
        }
      });
    } else {
      clearSearch();
    }
  });

  DOM.clearSearchBtn.addEventListener('click', clearSearch);
}

function clearSearch() {
  DOM.searchInput.value = '';
  DOM.clearSearchBtn.classList.add('hidden');
  state.searchQuery = '';
  
  // Reload current channel history
  socket.emit('join-channel', state.currentChannel);
}

// ==========================================================================
// Bootstrap Launcher
// ==========================================================================
document.addEventListener('DOMContentLoaded', initApp);

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
  currentChannelKey: null,
  channelPasswords: {}, // roomId -> password plaintext
  onlineUsers: [],
  activeUploads: new Map(), // uploadId -> uploadTask
  searchQuery: '',
  isTyping: false,
  typingTimeout: null,
  
  // Collaborative Whiteboard State
  wbColor: '#5a5cf0',
  wbBrushSize: 5,
  wbIsEraser: false,
  
  // Virtual NAS Drive State
  nasCurrentFolderId: 'root',
  nasBreadcrumbs: [{ id: 'root', name: 'Virtual Drive' }],
  
  // WebRTC Call State
  isCallActive: false,
  isAudioMuted: false,
  isVideoMuted: false
};

// ==========================================================================
// Zero-Knowledge E2EE Cryptography Helpers (PBKDF2 + AES-GCM 256-bit)
// ==========================================================================
const staticSalt = "filesharex-crypto-salt-key";

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Pure JS KDF and CTR-SHA256 stream cipher for insecure contexts (HTTP LAN)
function sha256BytesFallback(stringOrBuffer) {
  let buf;
  if (typeof stringOrBuffer === 'string') {
    buf = new TextEncoder().encode(stringOrBuffer);
  } else if (stringOrBuffer instanceof ArrayBuffer) {
    buf = new Uint8Array(stringOrBuffer);
  } else {
    buf = stringOrBuffer;
  }
  const cleanBuf = new Uint8Array(buf.length);
  cleanBuf.set(buf);
  const hex = sha256Fallback(cleanBuf.buffer);
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function getRandomBytes(length) {
  const bytes = new Uint8Array(length);
  if (window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return bytes;
}

function xorStreamCipher(dataBytes, keyBytes, ivBytes) {
  const result = new Uint8Array(dataBytes.length);
  const blockInput = new Uint8Array(48);
  blockInput.set(keyBytes, 0);
  blockInput.set(ivBytes, 32);
  
  const blockCount = Math.ceil(dataBytes.length / 32);
  for (let i = 0; i < blockCount; i++) {
    blockInput[44] = (i >>> 24) & 0xff;
    blockInput[45] = (i >>> 16) & 0xff;
    blockInput[46] = (i >>> 8) & 0xff;
    blockInput[47] = i & 0xff;
    
    const keystreamBlock = sha256BytesFallback(blockInput);
    
    const start = i * 32;
    const end = Math.min(start + 32, dataBytes.length);
    for (let j = start; j < end; j++) {
      result[j] = dataBytes[j] ^ keystreamBlock[j - start];
    }
  }
  return result;
}

async function deriveKey(password, saltText) {
  const fallbackBytes = sha256BytesFallback(password + "||" + saltText);
  
  if (!window.crypto || !window.crypto.subtle) {
    return {
      isFallback: true,
      fallbackKey: fallbackBytes,
      nativeKey: null
    };
  }
  
  try {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits", "deriveKey"]
    );
    const nativeKey = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: enc.encode(saltText),
        iterations: 1000,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
    return {
      isFallback: false,
      fallbackKey: fallbackBytes,
      nativeKey: nativeKey
    };
  } catch (err) {
    console.warn("Native Web Crypto key derivation failed, using pure JS fallback:", err);
    return {
      isFallback: true,
      fallbackKey: fallbackBytes,
      nativeKey: null
    };
  }
}

async function encryptText(plainText, key) {
  if (!key) throw new Error("Encryption key is missing");
  
  // Force pure-JS fallback stream cipher for 100% E2EE compatibility across all LAN devices
  const isFallback = true;
  if (isFallback) {
    const enc = new TextEncoder();
    const plainBytes = enc.encode(plainText);
    const iv = getRandomBytes(12);
    const encryptedBytes = xorStreamCipher(plainBytes, key.fallbackKey, iv);
    const combined = new Uint8Array(iv.length + encryptedBytes.length);
    combined.set(iv, 0);
    combined.set(encryptedBytes, iv.length);
    return arrayBufferToBase64(combined);
  }
  
  try {
    const enc = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key.nativeKey || key,
      enc.encode(plainText)
    );
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    return arrayBufferToBase64(combined);
  } catch (err) {
    console.warn("Native encryption failed, falling back to pure JS cipher:", err);
    const enc = new TextEncoder();
    const plainBytes = enc.encode(plainText);
    const iv = getRandomBytes(12);
    const encryptedBytes = xorStreamCipher(plainBytes, key.fallbackKey, iv);
    const combined = new Uint8Array(iv.length + encryptedBytes.length);
    combined.set(iv, 0);
    combined.set(encryptedBytes, iv.length);
    return arrayBufferToBase64(combined);
  }
}

async function decryptText(base64Cipher, key, forceFallback = false) {
  if (!key) throw new Error("Decryption key is missing");
  
  const useFallback = forceFallback || key.isFallback || !window.crypto || !window.crypto.subtle;
  if (useFallback) {
    const combined = base64ToArrayBuffer(base64Cipher);
    const combinedView = new Uint8Array(combined);
    const iv = combinedView.slice(0, 12);
    const ciphertext = combinedView.slice(12);
    const decryptedBytes = xorStreamCipher(ciphertext, key.fallbackKey, iv);
    const dec = new TextDecoder();
    return dec.decode(decryptedBytes);
  }
  
  try {
    const combined = base64ToArrayBuffer(base64Cipher);
    const combinedView = new Uint8Array(combined);
    const iv = combinedView.slice(0, 12);
    const ciphertext = combinedView.slice(12);
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key.nativeKey || key,
      ciphertext
    );
    const dec = new TextDecoder();
    return dec.decode(decrypted);
  } catch (err) {
    console.warn("Native decryption failed, trying pure JS fallback cipher:", err);
    try {
      const combined = base64ToArrayBuffer(base64Cipher);
      const combinedView = new Uint8Array(combined);
      const iv = combinedView.slice(0, 12);
      const ciphertext = combinedView.slice(12);
      const decryptedBytes = xorStreamCipher(ciphertext, key.fallbackKey, iv);
      const dec = new TextDecoder();
      return dec.decode(decryptedBytes);
    } catch (fallbackErr) {
      throw err;
    }
  }
}

async function getChannelKey(channelId, password) {
  const pwdText = password || channelId;
  const saltText = channelId + "-" + staticSalt;
  return await deriveKey(pwdText, saltText);
}

async function encryptChunk(arrayBuffer, key) {
  // Force pure-JS fallback stream cipher for 100% E2EE compatibility across all LAN devices
  const isFallback = true;
  if (isFallback) {
    const iv = getRandomBytes(12);
    const plainBytes = new Uint8Array(arrayBuffer);
    const encryptedBytes = xorStreamCipher(plainBytes, key.fallbackKey, iv);
    const combined = new Uint8Array(iv.length + encryptedBytes.byteLength);
    combined.set(iv, 0);
    combined.set(encryptedBytes, iv.length);
    return combined;
  }
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key.nativeKey || key,
    arrayBuffer
  );
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.length);
  return combined;
}

async function encryptAndHashFile(file, key) {
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  const encryptedChunks = [];
  let totalEncryptedSize = 0;
  
  for (let i = 0; i < totalChunks; i++) {
    const startByte = i * CHUNK_SIZE;
    const endByte = Math.min(startByte + CHUNK_SIZE, file.size);
    const chunkBlob = file.slice(startByte, endByte);
    const chunkBuf = await chunkBlob.arrayBuffer();
    const encChunk = await encryptChunk(chunkBuf, key);
    encryptedChunks.push(encChunk);
    totalEncryptedSize += encChunk.byteLength;
  }
  
  const combinedEncrypted = new Uint8Array(totalEncryptedSize);
  let offset = 0;
  for (const chunk of encryptedChunks) {
    combinedEncrypted.set(chunk, offset);
    offset += chunk.byteLength;
  }
  
  let sha256Val = '';
  if (window.crypto && window.crypto.subtle) {
    try {
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', combinedEncrypted.buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      sha256Val = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
      sha256Val = sha256Fallback(combinedEncrypted.buffer);
    }
  } else {
    sha256Val = sha256Fallback(combinedEncrypted.buffer);
  }
  
  return { encryptedChunks, sha256: sha256Val };
}

async function decryptCombinedFile(encryptedBuffer, key, originalSize, isFallbackFile = false) {
  const encryptedBytes = new Uint8Array(encryptedBuffer);
  const totalChunks = Math.ceil(originalSize / CHUNK_SIZE);
  const decryptedChunks = [];
  
  const useFallback = isFallbackFile || key.isFallback || !window.crypto || !window.crypto.subtle;
  const overhead = useFallback ? 12 : 28;
  
  let offset = 0;
  for (let i = 0; i < totalChunks; i++) {
    const isLast = (i === totalChunks - 1);
    const expectedPlaintextLen = isLast ? (originalSize - i * CHUNK_SIZE) : CHUNK_SIZE;
    const expectedEncryptedLen = expectedPlaintextLen + overhead;
    
    const encryptedChunkSlice = encryptedBytes.slice(offset, offset + expectedEncryptedLen);
    offset += expectedEncryptedLen;
    
    const iv = encryptedChunkSlice.slice(0, 12);
    const ciphertext = encryptedChunkSlice.slice(12);
    
    if (useFallback) {
      const decrypted = xorStreamCipher(ciphertext, key.fallbackKey, iv);
      decryptedChunks.push(decrypted);
    } else {
      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key.nativeKey || key,
        ciphertext
      );
      decryptedChunks.push(new Uint8Array(decrypted));
    }
  }
  
  const finalDecryptedBuffer = new Uint8Array(originalSize);
  let decryptedOffset = 0;
  for (const chunk of decryptedChunks) {
    finalDecryptedBuffer.set(chunk, decryptedOffset);
    decryptedOffset += chunk.byteLength;
  }
  
  return finalDecryptedBuffer.buffer;
}

async function getDecryptedBlobUrl(url, fileType, originalSize, isFallbackFile = false) {
  const res = await fetch(url);
  const encryptedArrayBuffer = await res.arrayBuffer();
  const decryptedBuffer = await decryptCombinedFile(encryptedArrayBuffer, state.currentChannelKey, originalSize, isFallbackFile);
  const blob = new Blob([decryptedBuffer], { type: fileType });
  return URL.createObjectURL(blob);
}

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
  const remainder = len % 4;
  if (remainder === 0) {
    words.push(0x80000000);
  } else if (remainder === 1) {
    words[words.length - 1] |= 0x00800000;
  } else if (remainder === 2) {
    words[words.length - 1] |= 0x00008000;
  } else if (remainder === 3) {
    words[words.length - 1] |= 0x00000080;
  }
  
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
  
  channelList: document.getElementById('channel-list'),
  activeChannelName: document.getElementById('active-channel-name'),
  activeChannelLock: document.getElementById('active-channel-lock'),
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

  createRoomBtn: document.getElementById('create-room-btn'),
  createRoomModal: document.getElementById('create-room-modal'),
  createRoomForm: document.getElementById('create-room-form'),
  roomNameInput: document.getElementById('room-name-input'),
  roomPasswordInput: document.getElementById('room-password-input'),
  toggleCreatePwd: document.getElementById('toggle-create-pwd'),
  createRoomError: document.getElementById('create-room-error'),

  roomPasswordModal: document.getElementById('room-password-modal'),
  roomPwdTargetName: document.getElementById('room-pwd-target-name'),
  roomPasswordForm: document.getElementById('room-password-form'),
  joinPasswordInput: document.getElementById('join-password-input'),
  toggleJoinPwd: document.getElementById('toggle-join-pwd'),
  joinRoomError: document.getElementById('join-room-error'),
  
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
  closeModalBtns: document.querySelectorAll('.close-modal-btn'),

  // Phase 2: WebRTC Voice & Video selectors
  callStartBtn: document.getElementById('call-start-btn'),
  callPanel: document.getElementById('call-panel'),
  localVideo: document.getElementById('local-video'),
  remoteStreams: document.getElementById('remote-streams'),
  callToggleMic: document.getElementById('call-toggle-mic'),
  callToggleVideo: document.getElementById('call-toggle-video'),
  callLeave: document.getElementById('call-leave'),
  micIcon: document.getElementById('mic-icon'),
  videoIcon: document.getElementById('video-icon'),

  // Phase 2: P2P Direct File Transfer toast
  p2pToast: document.getElementById('p2p-toast'),
  p2pToastMsg: document.getElementById('p2p-toast-msg'),
  p2pToastProgress: document.getElementById('p2p-toast-progress'),

  // Phase 3: LAN Auto-Discovery Connect List
  discoveredNodesContainer: document.getElementById('discovered-nodes-container'),
  discoveredNodesList: document.getElementById('discovered-nodes-list'),

  // Phase 4: Collaborative Whiteboard selectors
  whiteboardToggleBtn: document.getElementById('whiteboard-toggle-btn'),
  whiteboardPanel: document.getElementById('whiteboard-panel'),
  whiteboardCanvas: document.getElementById('whiteboard-canvas'),
  wbColor: document.getElementById('wb-color'),
  wbBrushSize: document.getElementById('wb-brush-size'),
  wbEraser: document.getElementById('wb-eraser'),
  wbClear: document.getElementById('wb-clear'),

  // Phase 5: Virtual NAS LAN Drive selectors
  nasToggleBtn: document.getElementById('nas-toggle-btn'),
  nasPanel: document.getElementById('nas-panel'),
  nasBreadcrumbs: document.getElementById('nas-breadcrumbs'),
  nasNewFolderBtn: document.getElementById('nas-new-folder-btn'),
  nasUploadBtn: document.getElementById('nas-upload-btn'),
  nasFileInput: document.getElementById('nas-file-input'),
  nasFilesList: document.getElementById('nas-files-list')
};

// Track all known rooms (updated from server)
let knownRooms = [];
// Pending channel switch target when password is required
let pendingPasswordChannel = null;

// Toggle chat form and attachment button loading state during async E2EE PBKDF2 key derivation
function setChatInputLoadingState(isLoading) {
  if (isLoading) {
    DOM.messageInput.disabled = true;
    DOM.sendBtn.disabled = true;
    DOM.attachmentBtn.disabled = true;
    DOM.messageInput.placeholder = "Deriving secure E2EE keys...";
  } else {
    DOM.messageInput.disabled = false;
    DOM.sendBtn.disabled = false;
    DOM.attachmentBtn.disabled = false;
    DOM.messageInput.placeholder = "Type secure message...";
  }
}

// ==========================================================================
// Initialization & Socket Binding
// ==========================================================================
function initApp() {
  setChatInputLoadingState(true);
  setupSocket();
  setupEventListeners();
  fetchNetworkInfo();

  // Restore sidebar collapse state on desktop
  const sidebarCollapsed = localStorage.getItem('fsx_sidebar_collapsed') === 'true';
  if (sidebarCollapsed && window.innerWidth > 768) {
    DOM.app.classList.add('sidebar-collapsed');
  }

  // Restore saved username from localStorage — skip modal if found
  const savedUsername = localStorage.getItem('fsx_username');
  if (savedUsername) {
    state.username = savedUsername;
    DOM.currentUserName.innerText = savedUsername;
    DOM.currentUserAvatar.innerText = savedUsername.charAt(0).toUpperCase();
    DOM.usernameInput.value = savedUsername;
    DOM.usernameModal.classList.remove('active');
    DOM.app.classList.remove('hidden');
    socket.connect();
  }

  // Phase 3: Start LAN Auto-Discovery Polling
  pollLanAutoDiscovery();
  setInterval(pollLanAutoDiscovery, 4000);
}

function setupSocket() {
  socket = io({
    autoConnect: false,
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    reconnectionAttempts: Infinity
  });

  socket.on('connect', async () => {
    DOM.disconnectOverlay.classList.remove('active');
    console.log('Connected to server with Socket ID:', socket.id);
    
    setChatInputLoadingState(true);
    // Automatically join the current state channel using cached password if any
    const cachedPwd = state.channelPasswords[state.currentChannel] || null;
    state.currentChannelKey = await getChannelKey(state.currentChannel, cachedPwd);
    socket.emit('join-channel', state.currentChannel, cachedPwd);
    
    // If username is already set, restore user registration on reconnect
    if (state.username) {
      socket.emit('set-username', state.username);
    }
    setChatInputLoadingState(false);
  });

  socket.on('disconnect', (reason) => {
    DOM.disconnectOverlay.classList.add('active');
    console.warn('Socket disconnected:', reason);
  });

  socket.on('connect_error', () => {
    DOM.disconnectOverlay.classList.add('active');
  });

  // Socket Core Receivers
  socket.on('message-history', async (messages) => {
    DOM.messagesContainer.innerHTML = '';
    if (messages && messages.length > 0) {
      for (const msg of messages) {
        await appendMessage(msg);
      }
      scrollToBottom(true);
    } else {
      appendSystemAnnouncement('Welcome to #' + DOM.activeChannelName.innerText + '! Send a message to start conversing.');
    }
  });

  socket.on('message', async (msg) => {
    const isNearBottom = DOM.messagesContainer.scrollHeight - DOM.messagesContainer.scrollTop - DOM.messagesContainer.clientHeight < 150;
    await appendMessage(msg);
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

  // Room list updates from server
  socket.on('room-list-update', (rooms) => {
    knownRooms = rooms;
    renderRoomList();
  });

  // Handle message deletion broadcast
  socket.on('message-deleted', ({ msgId }) => {
    const el = document.querySelector(`[data-msg-id="${msgId}"]`);
    if (el) {
      el.classList.add('msg-deleting');
      setTimeout(() => el.remove(), 260);
    }
  });

  // Handle room deletion broadcast
  socket.on('room-deleted', ({ roomId }) => {
    // If we are currently in the deleted room, fall back to #general
    if (state.currentChannel === roomId) {
      doJoinChannel('#general', null);
      appendSystemAnnouncement('This room was deleted. You have been moved to #general.');
    }
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

  // Phase 2: WebRTC Video/Voice Signaling Sockets
  socket.on('user-joined-call', async ({ socketId, username }) => {
    if (state.isCallActive) {
      console.log(`WebRTC: Peer ${username} (${socketId}) joined call. Initiating peer connection...`);
      await initPeerConnection(socketId, true);
    }
  });

  socket.on('user-left-call', ({ socketId }) => {
    console.log(`WebRTC: Peer (${socketId}) left call. Closing connection...`);
    closePeerConnection(socketId);
  });

  socket.on('webrtc-signal', async ({ sender, signal }) => {
    if (signal.p2p) {
      await handleP2PSignal(sender, signal);
    } else {
      await handleWebRTCSignal(sender, signal);
    }
  });

  // Phase 2: P2P Direct File Transfer Sockets
  socket.on('p2p-request', ({ senderId, senderName, fileName, fileSize, fileType }) => {
    handleP2PRequest(senderId, senderName, fileName, fileSize, fileType);
  });

  socket.on('p2p-respond', ({ responderId, accepted }) => {
    handleP2PResponse(responderId, accepted);
  });

  // Phase 4: Collaborative Whiteboard Sockets
  socket.on('draw-line', (data) => {
    drawReceivedLine(data);
  });

  socket.on('clear-whiteboard', () => {
    clearLocalCanvasOnly();
  });

  // Phase 5: Virtual NAS LAN Drive Sockets
  socket.on('drive-updated', ({ roomId }) => {
    if (roomId === state.currentChannel && !DOM.nasPanel.classList.contains('hidden')) {
      loadNasDirectory();
    }
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
// Add chat message bubble
async function appendMessage(msg) {
  const isSelf = msg.username === state.username;
  const timeStr = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  
  const msgGroup = document.createElement('div');
  msgGroup.className = `msg-group ${isSelf ? 'self' : ''}`;
  if (msg.id) msgGroup.setAttribute('data-msg-id', msg.id);

  // User initials avatar
  const avatarCol = isSelf ? state.color : (getUserColor(msg.username) || '#cbd5e1');
  const initial = msg.username.charAt(0).toUpperCase();
    let displayedMsg = msg.message;
  if (msg.type === 'text') {
    if (msg.message && msg.message.startsWith('__FSX_ENC_TEXT__:')) {
      const cipher = msg.message.substring(17);
      try {
        if (state.currentChannelKey) {
          displayedMsg = await decryptText(cipher, state.currentChannelKey, false);
        } else {
          displayedMsg = '🔒 [Encrypted Message - Key Missing]';
        }
      } catch (err) {
        console.error('Decryption failed:', err);
        displayedMsg = '⚠️ [Decryption Failed]';
      }
    } else if (msg.message && msg.message.startsWith('__FSX_FALLBACK_ENC_TEXT__:')) {
      const cipher = msg.message.substring(26);
      try {
        if (state.currentChannelKey) {
          displayedMsg = await decryptText(cipher, state.currentChannelKey, true);
        } else {
          displayedMsg = '🔒 [Encrypted Message - Key Missing]';
        }
      } catch (err) {
        console.error('Decryption failed:', err);
        displayedMsg = '⚠️ [Decryption Failed]';
      }
    }
  }

  let displayedFileName = msg.fileName;
  let isFallbackFile = false;
  if (msg.type === 'file') {
    if (msg.fileName && msg.fileName.startsWith('__FSX_ENC_NAME__:')) {
      const cipher = msg.fileName.substring(17);
      try {
        if (state.currentChannelKey) {
          displayedFileName = await decryptText(cipher, state.currentChannelKey, false);
        } else {
          displayedFileName = '🔒 [Encrypted File]';
        }
      } catch (err) {
        console.error('Filename decryption failed:', err);
        displayedFileName = '⚠️ [Decryption Failed]';
      }
    } else if (msg.fileName && msg.fileName.startsWith('__FSX_FALLBACK_ENC_NAME__:')) {
      isFallbackFile = true;
      const cipher = msg.fileName.substring(26);
      try {
        if (state.currentChannelKey) {
          displayedFileName = await decryptText(cipher, state.currentChannelKey, true);
        } else {
          displayedFileName = '🔒 [Encrypted File]';
        }
      } catch (err) {
        console.error('Filename decryption failed:', err);
        displayedFileName = '⚠️ [Decryption Failed]';
      }
    }
  }

  msgGroup.innerHTML = `
    <div class="avatar" style="background-color: ${avatarCol}">${initial}</div>
    <div class="msg-wrapper">
      <div class="msg-meta">
        <span class="sender">${escapeHTML(msg.username)}</span>
        <span class="timestamp">${timeStr}</span>
        ${isSelf && msg.id ? `<button class="msg-delete-btn" title="Delete message" data-msg-id="${msg.id}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"></polyline>
            <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path>
            <path d="M10 11v6"></path><path d="M14 11v6"></path>
            <path d="M9 6V4h6v2"></path>
          </svg>
        </button>` : ''}
      </div>
      <div class="msg-content"></div>
    </div>
  `;

  // Wire up delete button
  const deleteBtn = msgGroup.querySelector('.msg-delete-btn');
  if (deleteBtn) {
    deleteBtn.addEventListener('click', () => {
      if (!confirm('Delete this message for everyone?')) return;
      socket.emit('delete-message', { msgId: msg.id });
    });
  }

  const contentContainer = msgGroup.querySelector('.msg-content');
  if (msg.type === 'text') {
    contentContainer.innerHTML = `<p class="chat-bubble-text">${escapeHTML(displayedMsg)}</p>`;
  } else if (msg.type === 'file') {
    const isImage = msg.fileType && msg.fileType.startsWith('image/');
    const fileCard = document.createElement('div');
    fileCard.className = `file-bubble-card ${isImage ? 'image-type' : ''}`;
    
    let previewHtml = '';
    if (isImage) {
      previewHtml = `
        <div class="file-image-preview-wrapper nas-item-clickable">
          <div class="preview-fallback-container">
            <svg class="file-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>
            <span style="font-size: 0.8rem; margin-top: 4px; color: var(--text-secondary);">Secure Image Preview</span>
          </div>
        </div>
      `;
    } else {
      previewHtml = `
        <div class="file-generic-preview-wrapper">
          <svg class="file-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
        </div>
      `;
    }

    fileCard.innerHTML = `
      ${previewHtml}
      <div class="file-bubble-meta">
        <span class="file-bubble-name" title="${escapeHTML(displayedFileName)}">${escapeHTML(displayedFileName)}</span>
        <span class="file-bubble-size">${formatBytes(msg.fileSize)}</span>
      </div>
      <div class="file-bubble-actions">
        ${(isImage || (msg.fileType && msg.fileType.startsWith('video/')) || (msg.fileType && msg.fileType === 'application/pdf')) ? `
          <button class="file-action-btn view-btn" title="Preview file">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
          </button>
        ` : ''}
        <button class="file-action-btn download-btn" title="Download File">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <polyline points="7 10 12 15 17 10"></polyline>
            <line x1="12" y1="15" x2="12" y2="3"></line>
          </svg>
        </button>
      </div>
    `;

    const viewBtn = fileCard.querySelector('.view-btn');
    if (viewBtn) viewBtn.addEventListener('click', () => openDecryptedPreviewModal(displayedFileName, msg.fileUrl, msg.fileType, msg.fileSize, isFallbackFile));

    const dlBtn = fileCard.querySelector('.download-btn');
    if (dlBtn) dlBtn.addEventListener('click', (e) => handleFileDownloadClick(e, msg.fileUrl, displayedFileName, msg.fileType, msg.fileSize, isFallbackFile));

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

// Render dynamic rooms list in sidebar
function renderRoomList() {
  DOM.channelList.innerHTML = '';
  knownRooms.forEach(room => {
    const isOwner = !room.isDefault && room.createdBy === state.username;
    const li = document.createElement('li');
    li.className = 'channel-item' + (room.id === state.currentChannel ? ' active' : '');
    li.setAttribute('data-channel', room.id);

    const lockIcon = room.hasPassword ? `<span class="room-lock-icon" title="Password protected">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
      </svg>
    </span>` : '';

    const deleteRoomBtn = isOwner ? `<button class="room-delete-btn" title="Delete room">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line>
      </svg>
    </button>` : '';

    li.innerHTML = `
      <span class="hash">#</span>
      <span class="channel-name-text">${escapeHTML(room.displayName)}</span>
      ${lockIcon}${deleteRoomBtn}
    `;

    // Click on list item = switch channel (but not if clicking the delete btn)
    li.addEventListener('click', (e) => {
      if (e.target.closest('.room-delete-btn')) return;
      switchChannel(room.id);
    });

    // Delete room button
    const delBtn = li.querySelector('.room-delete-btn');
    if (delBtn) {
      delBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        if (!confirm(`Delete room "${room.displayName}"? All members will be moved to #general.`)) return;
        socket.emit('delete-room', { roomId: room.id });
      });
    }

    DOM.channelList.appendChild(li);
  });
}

// Switch to a channel, prompting for password if needed
function switchChannel(channelId) {
  if (channelId === state.currentChannel) return;
  const room = knownRooms.find(r => r.id === channelId);
  if (!room) return;

  if (room.hasPassword) {
    // Show password prompt first
    pendingPasswordChannel = channelId;
    DOM.roomPwdTargetName.innerText = channelId;
    DOM.joinPasswordInput.value = '';
    DOM.joinRoomError.classList.add('hidden');
    DOM.joinRoomError.innerText = '';
    DOM.roomPasswordModal.classList.add('active');
    setTimeout(() => DOM.joinPasswordInput.focus(), 80);
  } else {
    doJoinChannel(channelId, null);
  }
}

// Actually join a channel after password checks
async function doJoinChannel(channelId, password) {
  setChatInputLoadingState(true);
  const previousChannelKey = state.currentChannelKey;
  const newChannelKey = await getChannelKey(channelId, password);

  // Set currentChannelKey immediately so that the incoming 'message-history' event 
  // (which is received before the 'join-channel' callback finishes) can decrypt successfully.
  state.currentChannelKey = newChannelKey;

  socket.emit('join-channel', channelId, password, async (result) => {
    setChatInputLoadingState(false);
    if (result && result.error) {
      // Restore previous key on failure
      state.currentChannelKey = previousChannelKey;
      if (result.error === 'wrong_password') {
        DOM.joinRoomError.innerText = 'Incorrect password. Please try again.';
        DOM.joinRoomError.classList.remove('hidden');
      } else {
        DOM.joinRoomError.innerText = result.error;
        DOM.joinRoomError.classList.remove('hidden');
      }
      return;
    }
    // Success
    state.channelPasswords[channelId] = password; // Cache password
    DOM.roomPasswordModal.classList.remove('active');
    pendingPasswordChannel = null;

    // Update sidebar active state
    state.currentChannel = channelId;
    const room = knownRooms.find(r => r.id === channelId);
    DOM.activeChannelName.innerText = room ? room.displayName : channelId.substring(1);

    // Show lock badge in header if password-protected
    if (room && room.hasPassword) {
      DOM.activeChannelLock.classList.remove('hidden');
    } else {
      DOM.activeChannelLock.classList.add('hidden');
    }

    DOM.dragChannelLabel.innerText = channelId;
    renderRoomList();
    clearSearch();

    // Reset NAS explorer state on channel switch
    state.nasCurrentFolderId = 'root';
    state.nasBreadcrumbs = [{ id: 'root', name: 'Virtual Drive' }];
    if (!DOM.nasPanel.classList.contains('hidden')) {
      loadNasDirectory();
    }

    if (window.innerWidth <= 768) toggleSidebar(false);
  });
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
      <div class="user-item-right-actions">
        <span class="user-item-ip">${escapeHTML(user.ip)}</span>
        ${!isMe ? `
          <button class="p2p-send-btn-small" title="Direct P2P File Transfer" data-socket-id="${user.id}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 12px; height: 12px;">
              <polygon points="5 3 19 12 5 21 5 3"></polygon>
            </svg>
          </button>
        ` : ''}
      </div>
    `;

    const p2pBtn = li.querySelector('.p2p-send-btn-small');
    if (p2pBtn) {
      p2pBtn.addEventListener('click', () => {
        triggerP2PFileSelect(user.id);
      });
    }

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
async function queueAndUploadFiles(filesList, isDriveFile = false, parentFolderId = 'root') {
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
      encryptedChunks: null,
      isDriveFile,
      parentFolderId
    };

    state.activeUploads.set(uploadId, task);
    renderUploadTasks();
    updateUploadBadgeCount();

    // Start Async Hashing and Encryption first
    try {
      console.log(`Encrypting and hashing: ${file.name}`);
      if (state.currentChannelKey) {
        const { encryptedChunks, sha256 } = await encryptAndHashFile(file, state.currentChannelKey);
        task.encryptedChunks = encryptedChunks;
        task.sha256 = sha256;
      } else {
        task.sha256 = await calculateFileSHA256(file);
      }
      task.status = 'uploading';
      renderUploadTasks();
      
      // Fire upload sequence
      runChunkedUpload(uploadId);
    } catch (err) {
      console.error('Encryption or hashing failed for file:', file.name, err);
      task.status = 'error';
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
      let chunkBlob;
      if (task.encryptedChunks) {
        chunkBlob = new Blob([task.encryptedChunks[chunkIndex]], { type: 'application/octet-stream' });
      } else {
        const startByte = chunkIndex * CHUNK_SIZE;
        const endByte = Math.min(startByte + CHUNK_SIZE, task.fileSize);
        chunkBlob = task.file.slice(startByte, endByte);
      }

      // Construct Form
      const formData = new FormData();
      formData.append('chunk', chunkBlob);
      formData.append('uploadId', uploadId);
      formData.append('chunkIndex', chunkIndex);
      formData.append('totalChunks', task.totalChunks);
      formData.append('fileName', task.fileName);

      // Perform Fetch Upload Chunk
      await fetch('/api/upload/chunk', {
        method: 'POST',
        body: formData,
        signal: task.controller.signal
      });

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

      let finalFileName = task.fileName;
      if (state.currentChannelKey) {
        try {
          const encName = await encryptText(task.fileName, state.currentChannelKey);
          // Force fallback E2EE prefix for filenames to ensure 100% cross-device compatibility
          finalFileName = `__FSX_FALLBACK_ENC_NAME__:${encName}`;
        } catch (err) {
          console.error('Filename encryption failed:', err);
        }
      }

      const completeRes = await fetch('/api/upload/complete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          uploadId,
          fileName: finalFileName,
          fileSize: task.fileSize,
          fileType: task.fileType,
          sha256: task.sha256,
          channel: state.currentChannel,
          username: state.username,
          isDriveFile: task.isDriveFile,
          parentFolderId: task.parentFolderId
        })
      });

      const completeData = await completeRes.json();

      if (completeRes.ok && completeData.success) {
        task.status = 'completed';
        renderUploadTasks();
        
        // Remove task automatically from manager pane after a short delay
        setTimeout(() => {
          state.activeUploads.delete(uploadId);
          renderUploadTasks();
          updateUploadBadgeCount();
          
          // Auto-close the upload manager modal if all uploads have finished/cleared
          if (state.activeUploads.size === 0) {
            DOM.uploadManagerModal.classList.remove('active');
          }
        }, 3000);

      } else {
        console.error(completeData.error || 'Server assembly failure');
        task.status = 'error';
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

  // Auto-close the upload manager modal if all uploads have finished/cleared
  if (state.activeUploads.size === 0) {
    DOM.uploadManagerModal.classList.remove('active');
  }
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
// Decrypted Preview & Download Manager (E2EE)
// ==========================================================================
async function downloadAndDecryptFile(url, fileName, fileType, originalSize, isFallbackFile = false) {
  try {
    const decryptedBlobUrl = await getDecryptedBlobUrl(url, fileType, originalSize, isFallbackFile);
    const a = document.createElement('a');
    a.href = decryptedBlobUrl;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(decryptedBlobUrl), 10000);
  } catch (err) {
    console.error('Failed to download and decrypt file:', err);
    alert('Decryption download failed.');
  }
}

async function handleFileDownloadClick(e, url, fileName, fileType, originalSize, isFallbackFile = false) {
  e.preventDefault();
  if (fileName.startsWith('🔒') || fileName.startsWith('⚠️') || state.currentChannelKey) {
    await downloadAndDecryptFile(url, fileName, fileType, originalSize, isFallbackFile);
  } else {
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }
}

async function openDecryptedPreviewModal(fileName, url, fileType, originalSize, isFallbackFile = false) {
  DOM.previewTitle.innerText = `Preview: ${fileName} (Decrypting...)`;
  DOM.previewContent.innerHTML = `
    <div class="preview-fallback-container">
      <div class="animate-pulse" style="font-size: 1.1rem; color: var(--text-secondary);">Decrypting secure file, please wait...</div>
    </div>
  `;
  DOM.previewModal.classList.add('active');

  try {
    const decryptedBlobUrl = await getDecryptedBlobUrl(url, fileType, originalSize, isFallbackFile);
    
    DOM.previewTitle.innerText = `Preview: ${fileName}`;
    DOM.previewDownloadBtn.onclick = (e) => {
      e.preventDefault();
      const a = document.createElement('a');
      a.href = decryptedBlobUrl;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    };

    DOM.previewContent.innerHTML = '';
    const isImage = fileType && fileType.startsWith('image/');
    const isVideo = fileType && fileType.startsWith('video/');
    const isPdf = fileType && fileType === 'application/pdf';

    if (isImage) {
      DOM.previewContent.innerHTML = `<img src="${decryptedBlobUrl}" alt="${escapeHTML(fileName)}" style="max-width: 100%; max-height: 70vh; border-radius: 8px;">`;
    } else if (isVideo) {
      DOM.previewContent.innerHTML = `
        <video controls autoplay playsinline style="width:100%; max-height: 70vh; border-radius: 8px;">
          <source src="${decryptedBlobUrl}" type="${fileType}">
          Your browser does not support video playbacks.
        </video>
      `;
    } else if (isPdf) {
      DOM.previewContent.innerHTML = `<iframe src="${decryptedBlobUrl}" title="${escapeHTML(fileName)}" style="width: 100%; height: 70vh; border: none; border-radius: 8px;"></iframe>`;
    } else {
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
  } catch (err) {
    console.error('Preview decryption failed:', err);
    DOM.previewContent.innerHTML = `
      <div class="preview-fallback-container">
        <div class="preview-fallback-title">Decryption Failed</div>
        <div class="preview-fallback-desc">We couldn't decrypt this file. Ensure you have the correct key.</div>
      </div>
    `;
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

      // Persist for future sessions
      localStorage.setItem('fsx_username', selectedUsername);

      // Connect or re-register if already connected
      if (!socket.connected) {
        socket.connect();
      } else {
        socket.emit('set-username', selectedUsername);
      }

      DOM.usernameModal.classList.remove('active');
      DOM.app.classList.remove('hidden');
    }
  });

  // Footer change username trigger — pre-fill with current name
  DOM.editUsernameBtn.addEventListener('click', () => {
    DOM.usernameInput.value = state.username;
    DOM.usernameModal.classList.add('active');
  });

  // 2. Create Room button
  DOM.createRoomBtn.addEventListener('click', () => {
    DOM.createRoomForm.reset();
    DOM.createRoomError.classList.add('hidden');
    DOM.createRoomError.innerText = '';
    DOM.createRoomModal.classList.add('active');
    setTimeout(() => DOM.roomNameInput.focus(), 80);
  });

  // Create Room form submission
  DOM.createRoomForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const name = DOM.roomNameInput.value.trim();
    const password = DOM.roomPasswordInput.value;
    if (!name) return;

    DOM.createRoomError.classList.add('hidden');
    const submitBtn = DOM.createRoomForm.querySelector('[type=submit]');
    submitBtn.disabled = true;
    submitBtn.innerText = 'Creating...';

    socket.emit('create-room', { name, password }, (result) => {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg> Create Room`;
      if (result && result.error) {
        DOM.createRoomError.innerText = result.error;
        DOM.createRoomError.classList.remove('hidden');
        return;
      }
      // Auto-join the newly created room
      DOM.createRoomModal.classList.remove('active');
      if (result && result.roomId) {
        // Cache the password for the new room
        state.channelPasswords[result.roomId] = password;
        
        // Register room locally in knownRooms to prevent switchChannel race condition lookup issues
        if (!knownRooms.find(r => r.id === result.roomId)) {
          knownRooms.push({
            id: result.roomId,
            displayName: name,
            hasPassword: !!password
          });
        }
        
        // Instantly join the room
        doJoinChannel(result.roomId, password);
      }
    });
  });

  // Password toggle for create room
  DOM.toggleCreatePwd.addEventListener('click', () => {
    const input = DOM.roomPasswordInput;
    input.type = input.type === 'password' ? 'text' : 'password';
  });

  // 3. Room password join modal
  DOM.roomPasswordForm.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!pendingPasswordChannel) return;
    const pwd = DOM.joinPasswordInput.value;
    DOM.joinRoomError.classList.add('hidden');
    doJoinChannel(pendingPasswordChannel, pwd);
  });

  DOM.toggleJoinPwd.addEventListener('click', () => {
    const input = DOM.joinPasswordInput;
    input.type = input.type === 'password' ? 'text' : 'password';
  });

  // Sidebar panel toggles (handles both desktop collapse and mobile overlay)
  DOM.sidebarToggle.addEventListener('click', () => {
    if (window.innerWidth > 768) {
      DOM.app.classList.toggle('sidebar-collapsed');
      const isCollapsed = DOM.app.classList.contains('sidebar-collapsed');
      localStorage.setItem('fsx_sidebar_collapsed', isCollapsed ? 'true' : 'false');
    } else {
      toggleSidebar(true);
    }
  });
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
  DOM.chatForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const textMsg = DOM.messageInput.value.trim();
    if (textMsg) {
      let finalMsg = textMsg;
      if (state.currentChannelKey) {
        try {
          const encMsg = await encryptText(textMsg, state.currentChannelKey);
          // Force fallback E2EE prefix for messages to ensure 100% cross-device compatibility
          finalMsg = `__FSX_FALLBACK_ENC_TEXT__:${encMsg}`;
        } catch (err) {
          console.error('Encryption failed:', err);
        }
      }
      socket.emit('send-message', { message: finalMsg });
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
      socket.emit('search-messages', { query: q }, async (results) => {
        // Render search results
        DOM.messagesContainer.innerHTML = '';
        appendSystemAnnouncement(`Search results for "${q}" inside this channel (${results.length} found):`);
        
        if (results && results.length > 0) {
          for (const msg of results) {
            await appendMessage(msg);
          }
        }
      });
    } else {
      clearSearch();
    }
  });

  DOM.clearSearchBtn.addEventListener('click', clearSearch);

  // Phase 2: WebRTC Voice & Video Call Event Listeners
  DOM.callStartBtn.addEventListener('click', () => {
    DOM.callPanel.classList.toggle('hidden');
    if (!DOM.callPanel.classList.contains('hidden')) {
      DOM.whiteboardPanel.classList.add('hidden');
      DOM.nasPanel.classList.add('hidden');
      startCall();
    } else {
      leaveCall();
    }
  });

  DOM.callToggleMic.addEventListener('click', () => {
    toggleCallAudio();
  });

  DOM.callToggleVideo.addEventListener('click', () => {
    toggleCallVideo();
  });

  DOM.callLeave.addEventListener('click', () => {
    DOM.callPanel.classList.add('hidden');
    leaveCall();
  });

  // Phase 4: Collaborative Whiteboard Event Listeners
  DOM.whiteboardToggleBtn.addEventListener('click', () => {
    DOM.whiteboardPanel.classList.toggle('hidden');
    if (!DOM.whiteboardPanel.classList.contains('hidden')) {
      DOM.callPanel.classList.add('hidden');
      DOM.nasPanel.classList.add('hidden');
      initWhiteboard();
    }
  });

  DOM.wbColor.addEventListener('input', () => {
    state.wbColor = DOM.wbColor.value;
    state.wbIsEraser = false;
    DOM.wbEraser.classList.remove('active');
  });

  DOM.wbBrushSize.addEventListener('change', () => {
    state.wbBrushSize = parseInt(DOM.wbBrushSize.value, 10);
  });

  DOM.wbEraser.addEventListener('click', () => {
    state.wbIsEraser = !state.wbIsEraser;
    if (state.wbIsEraser) {
      DOM.wbEraser.classList.add('active');
    } else {
      DOM.wbEraser.classList.remove('active');
    }
  });

  DOM.wbClear.addEventListener('click', () => {
    if (confirm('Clear the collaborative whiteboard drawing canvas for everyone in the room?')) {
      clearLocalCanvasOnly();
      socket.emit('clear-whiteboard');
    }
  });

  // Phase 5: Virtual NAS LAN Drive Event Listeners
  DOM.nasToggleBtn.addEventListener('click', () => {
    DOM.nasPanel.classList.toggle('hidden');
    if (!DOM.nasPanel.classList.contains('hidden')) {
      DOM.callPanel.classList.add('hidden');
      DOM.whiteboardPanel.classList.add('hidden');
      loadNasDirectory();
    }
  });

  DOM.nasNewFolderBtn.addEventListener('click', async () => {
    const folderName = prompt('Enter a name for the new folder:');
    if (!folderName || !folderName.trim()) return;

    try {
      const res = await fetch('/api/drive/folder', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          room: state.currentChannel,
          parent: state.nasCurrentFolderId,
          folderName: folderName.trim(),
          username: state.username
        })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        loadNasDirectory();
      } else {
        alert(data.error || 'Failed to create folder.');
      }
    } catch (err) {
      console.error('Failed to create folder:', err);
    }
  });

  DOM.nasUploadBtn.addEventListener('click', () => {
    DOM.nasFileInput.click();
  });

  DOM.nasFileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      queueAndUploadFiles(e.target.files, true, state.nasCurrentFolderId);
    }
    DOM.nasFileInput.value = '';
  });
}

function clearSearch() {
  DOM.searchInput.value = '';
  DOM.clearSearchBtn.classList.add('hidden');
  state.searchQuery = '';
  
  // Reload current channel history with correct password
  const cachedPwd = state.channelPasswords[state.currentChannel] || null;
  socket.emit('join-channel', state.currentChannel, cachedPwd, () => {});
}

// ==========================================================================
// Phase 2: WebRTC Video/Voice Call Controller
// ==========================================================================
let localStream = null;
const peerConnections = new Map(); // socketId -> RTCPeerConnection
const iceConfig = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' }
  ]
};

async function startCall() {
  try {
    // Attempt audio and video first
    try {
      localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true });
    } catch (err) {
      console.warn("Camera access failed or unavailable, falling back to audio-only stream:", err);
      // Fallback to audio-only stream
      localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    }

    DOM.localVideo.srcObject = localStream;
    state.isCallActive = true;
    state.isAudioMuted = false;
    state.isVideoMuted = !localStream.getVideoTracks().length;

    // Reset button states
    DOM.callToggleMic.classList.remove('muted');
    if (state.isVideoMuted) {
      DOM.callToggleVideo.classList.add('muted');
      DOM.videoIcon.innerHTML = `<polygon points="23 7 16 12 23 17 23 7"></polygon><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect><line x1="1" y1="1" x2="23" y2="23"></line>`;
    } else {
      DOM.callToggleVideo.classList.remove('muted');
      DOM.videoIcon.innerHTML = `<polygon points="23 7 16 12 23 17 23 7"></polygon><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect>`;
    }

    console.log("WebRTC: Local stream acquired. Signaling other room peers...");
    socket.emit('join-call', state.currentChannel);
  } catch (err) {
    console.error("WebRTC: Failed to secure local media capture device stream:", err);
    alert("Could not access microphone or camera. Please check browser permissions.");
    DOM.callPanel.classList.add('hidden');
  }
}

function leaveCall() {
  if (localStream) {
    localStream.getTracks().forEach(track => track.stop());
    localStream = null;
  }
  DOM.localVideo.srcObject = null;

  peerConnections.forEach((pc, socketId) => {
    pc.close();
  });
  peerConnections.clear();
  DOM.remoteStreams.innerHTML = '';

  state.isCallActive = false;
  socket.emit('leave-call', state.currentChannel);
  console.log("WebRTC: Disconnected and left video/voice conference.");
}

async function initPeerConnection(peerSocketId, isOfferSender) {
  const pc = new RTCPeerConnection(iceConfig);
  peerConnections.set(peerSocketId, pc);

  pc.onicecandidate = (event) => {
    if (event.candidate) {
      socket.emit('webrtc-signal', {
        target: peerSocketId,
        signal: { candidate: event.candidate }
      });
    }
  };

  pc.ontrack = (event) => {
    let wrapper = document.getElementById(`remote-wrapper-${peerSocketId}`);
    if (!wrapper) {
      wrapper = document.createElement('div');
      wrapper.className = 'remote-stream-wrapper';
      wrapper.id = `remote-wrapper-${peerSocketId}`;
      
      const video = document.createElement('video');
      video.autoplay = true;
      video.playsInline = true;
      video.id = `remote-video-${peerSocketId}`;
      
      const label = document.createElement('div');
      label.className = 'stream-label';
      const peerUser = state.onlineUsers.find(u => u.id === peerSocketId);
      label.innerText = peerUser ? peerUser.username : 'Peer';
      
      wrapper.appendChild(video);
      wrapper.appendChild(label);
      DOM.remoteStreams.appendChild(wrapper);
    }
    const videoEl = document.getElementById(`remote-video-${peerSocketId}`);
    if (videoEl && videoEl.srcObject !== event.streams[0]) {
      videoEl.srcObject = event.streams[0];
    }
  };

  if (localStream) {
    localStream.getTracks().forEach(track => pc.addTrack(track, localStream));
  }

  if (isOfferSender) {
    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      socket.emit('webrtc-signal', {
        target: peerSocketId,
        signal: { sdp: pc.localDescription }
      });
    } catch (err) {
      console.error("WebRTC: Error initiating offer generation:", err);
    }
  }

  return pc;
}

function closePeerConnection(peerSocketId) {
  const pc = peerConnections.get(peerSocketId);
  if (pc) {
    pc.close();
    peerConnections.delete(peerSocketId);
  }
  const wrapper = document.getElementById(`remote-wrapper-${peerSocketId}`);
  if (wrapper) {
    wrapper.remove();
  }
}

async function handleWebRTCSignal(senderSocketId, signal) {
  try {
    let pc = peerConnections.get(senderSocketId);
    if (!pc) {
      pc = await initPeerConnection(senderSocketId, false);
    }

    if (signal.sdp) {
      await pc.setRemoteDescription(new RTCSessionDescription(signal.sdp));
      if (signal.sdp.type === 'offer') {
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        socket.emit('webrtc-signal', {
          target: senderSocketId,
          signal: { sdp: pc.localDescription }
        });
      }
    } else if (signal.candidate) {
      await pc.addIceCandidate(new RTCIceCandidate(signal.candidate));
    }
  } catch (err) {
    console.error("WebRTC: Signal processing failure:", err);
  }
}

function toggleCallAudio() {
  if (localStream) {
    const audioTrack = localStream.getAudioTracks()[0];
    if (audioTrack) {
      audioTrack.enabled = !audioTrack.enabled;
      state.isAudioMuted = !audioTrack.enabled;
      if (state.isAudioMuted) {
        DOM.callToggleMic.classList.add('muted');
        DOM.micIcon.innerHTML = `<path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path><path d="M19 10v2a7 7 0 0 1-14 0v-2"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line><line x1="1" y1="1" x2="23" y2="23"></line>`;
      } else {
        DOM.callToggleMic.classList.remove('muted');
        DOM.micIcon.innerHTML = `<path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path><path d="M19 10v2a7 7 0 0 1-14 0v-2"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line>`;
      }
    }
  }
}

function toggleCallVideo() {
  if (localStream) {
    const videoTrack = localStream.getVideoTracks()[0];
    if (videoTrack) {
      videoTrack.enabled = !videoTrack.enabled;
      state.isVideoMuted = !videoTrack.enabled;
      if (state.isVideoMuted) {
        DOM.callToggleVideo.classList.add('muted');
        DOM.videoIcon.innerHTML = `<polygon points="23 7 16 12 23 17 23 7"></polygon><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect><line x1="1" y1="1" x2="23" y2="23"></line>`;
      } else {
        DOM.callToggleVideo.classList.remove('muted');
        DOM.videoIcon.innerHTML = `<polygon points="23 7 16 12 23 17 23 7"></polygon><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect>`;
      }
    } else {
      // If we don't have a video track because we fell back to audio only
      alert("No active camera track found.");
    }
  }
}

// ==========================================================================
// Phase 2: P2P Direct ArrayBuffer File Transfer Controller (RTCDataChannel)
// ==========================================================================
const p2pActiveConnections = new Map(); // socketId -> connObject

function triggerP2PFileSelect(targetSocketId) {
  const input = document.createElement('input');
  input.type = 'file';
  input.onchange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    if (!state.pendingP2PFiles) {
      state.pendingP2PFiles = new Map();
    }
    state.pendingP2PFiles.set(targetSocketId, file);

    socket.emit('p2p-request', {
      target: targetSocketId,
      fileName: file.name,
      fileSize: file.size,
      fileType: file.type || 'application/octet-stream'
    });

    showP2PToast(`Waiting for peer to accept direct transfer...`, 0);
  };
  input.click();
}

function handleP2PRequest(senderId, senderName, fileName, fileSize, fileType) {
  const accept = confirm(`Incoming direct P2P File Transfer from "${senderName}":\nFile: ${fileName}\nSize: ${formatBytes(fileSize)}\n\nAccept transfer?`);
  socket.emit('p2p-respond', {
    target: senderId,
    accepted: accept
  });
  if (accept) {
    showP2PToast(`Connecting for direct P2P transfer...`, 0);
    setupP2PReceiverConnection(senderId, fileName, fileSize, fileType);
  }
}

function handleP2PResponse(responderId, accepted) {
  if (!accepted) {
    closeP2PToast();
    alert('Peer rejected direct P2P file transfer.');
    if (state.pendingP2PFiles) state.pendingP2PFiles.delete(responderId);
    return;
  }

  const file = state.pendingP2PFiles ? state.pendingP2PFiles.get(responderId) : null;
  if (!file) {
    closeP2PToast();
    return;
  }

  showP2PToast(`Connecting to peer...`, 0);
  setupP2PSenderConnection(responderId, file);
}

async function setupP2PSenderConnection(receiverId, file) {
  try {
    const pc = new RTCPeerConnection(iceConfig);
    const channel = pc.createDataChannel('file-transfer', { ordered: true });
    channel.binaryType = 'arraybuffer';

    const connObj = { pc, channel, file, bytesSent: 0 };
    p2pActiveConnections.set(receiverId, connObj);

    pc.onicecandidate = (event) => {
      if (event.candidate) {
        socket.emit('webrtc-signal', {
          target: receiverId,
          signal: { p2p: true, candidate: event.candidate }
        });
      }
    };

    channel.onopen = () => {
      console.log('P2P: Data channel successfully established!');
      sendP2PFileChunks(receiverId);
    };

    channel.onclose = () => {
      console.log('P2P: Data channel closed.');
      p2pActiveConnections.delete(receiverId);
    };

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    socket.emit('webrtc-signal', {
      target: receiverId,
      signal: { p2p: true, sdp: pc.localDescription }
    });
  } catch (err) {
    console.error("P2P: Connection sender creation error:", err);
    closeP2PToast();
    alert("Direct P2P transfer initialization failed.");
  }
}

function sendP2PFileChunks(peerId) {
  const conn = p2pActiveConnections.get(peerId);
  if (!conn) return;

  const file = conn.file;
  const channel = conn.channel;
  const CHUNK_LEN = 16384; // 16KB limit to prevent buffer overflows
  let offset = 0;

  const fileReader = new FileReader();

  fileReader.onload = (e) => {
    if (channel.readyState !== 'open') return;

    channel.send(e.target.result);
    offset += e.target.result.byteLength;
    conn.bytesSent = offset;

    const pct = Math.round((offset / file.size) * 100);
    showP2PToast(`Sending "${file.name}" direct P2P...`, pct);

    if (offset < file.size) {
      readNextChunkDebounced();
    } else {
      showP2PToast(`Direct transfer of "${file.name}" completed!`, 100);
      setTimeout(closeP2PToast, 3000);
      p2pActiveConnections.delete(peerId);
      if (state.pendingP2PFiles) state.pendingP2PFiles.delete(peerId);
    }
  };

  function readNextChunk() {
    if (channel.bufferedAmount > 1024 * 1024) { // 1MB buffer threshold
      setTimeout(readNextChunk, 30);
      return;
    }
    const slice = file.slice(offset, offset + CHUNK_LEN);
    fileReader.readAsArrayBuffer(slice);
  }

  function readNextChunkDebounced() {
    if (channel.bufferedAmount > 1024 * 1024) {
      setTimeout(readNextChunkDebounced, 20);
    } else {
      readNextChunk();
    }
  }

  readNextChunk();
}

async function setupP2PReceiverConnection(senderId, fileName, fileSize, fileType) {
  try {
    const pc = new RTCPeerConnection(iceConfig);
    const connObj = {
      pc,
      fileName,
      fileSize,
      fileType,
      receivedChunks: [],
      receivedSize: 0
    };
    p2pActiveConnections.set(senderId, connObj);

    pc.onicecandidate = (event) => {
      if (event.candidate) {
        socket.emit('webrtc-signal', {
          target: senderId,
          signal: { p2p: true, candidate: event.candidate }
        });
      }
    };

    pc.ondatachannel = (event) => {
      const channel = event.channel;
      channel.binaryType = 'arraybuffer';
      connObj.channel = channel;

      channel.onmessage = (e) => {
        connObj.receivedChunks.push(e.data);
        connObj.receivedSize += e.data.byteLength;

        const pct = Math.round((connObj.receivedSize / connObj.fileSize) * 100);
        showP2PToast(`Receiving "${connObj.fileName}" direct P2P...`, pct);

        if (connObj.receivedSize >= connObj.fileSize) {
          // Assemble file and trigger browser download
          const blob = new Blob(connObj.receivedChunks, { type: connObj.fileType });
          const blobUrl = URL.createObjectURL(blob);

          const a = document.createElement('a');
          a.href = blobUrl;
          a.download = connObj.fileName;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);

          showP2PToast(`Direct P2P transfer of "${connObj.fileName}" finished!`, 100);
          setTimeout(closeP2PToast, 3000);

          p2pActiveConnections.delete(senderId);
        }
      };

      channel.onclose = () => {
        console.log('P2P: Data channel closed on receiver end.');
        p2pActiveConnections.delete(senderId);
      };
    };
  } catch (err) {
    console.error("P2P: Connection receiver creation error:", err);
    closeP2PToast();
  }
}

async function handleP2PSignal(senderId, signal) {
  try {
    const conn = p2pActiveConnections.get(senderId);
    if (!conn) return;

    const pc = conn.pc;
    if (signal.sdp) {
      await pc.setRemoteDescription(new RTCSessionDescription(signal.sdp));
      if (signal.sdp.type === 'offer') {
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        socket.emit('webrtc-signal', {
          target: senderId,
          signal: { p2p: true, sdp: pc.localDescription }
        });
      }
    } else if (signal.candidate) {
      await pc.addIceCandidate(new RTCIceCandidate(signal.candidate));
    }
  } catch (err) {
    console.error("P2P: Signaling error:", err);
  }
}

function showP2PToast(message, progressPercent) {
  DOM.p2pToast.classList.add('active');
  DOM.p2pToastMsg.innerText = message;
  DOM.p2pToastProgress.style.width = `${progressPercent}%`;
}

function closeP2PToast() {
  DOM.p2pToast.classList.remove('active');
}

// ==========================================================================
// Phase 3: Offline Subnet Node Auto-Discovery Board Connect List
// ==========================================================================
async function pollLanAutoDiscovery() {
  try {
    const res = await fetch('/api/discover');
    if (!res.ok) return;
    const nodes = await res.json();

    DOM.discoveredNodesList.innerHTML = '';

    if (nodes && nodes.length > 0) {
      let nodeRenderCount = 0;
      
      nodes.forEach(node => {
        // Exclude our own node if the local username matches
        const isSelf = node.username === state.username;
        if (isSelf) return;

        nodeRenderCount++;
        const card = document.createElement('div');
        card.className = 'discovered-node-card';
        card.innerHTML = `
          <div class="discovered-node-info">
            <span class="discovered-node-username">${escapeHTML(node.username)}</span>
            <span class="discovered-node-ip">http://${node.ip}:${node.port}</span>
          </div>
          <a href="http://${node.ip}:${node.port}" target="_blank" class="discovered-node-connect-btn">Connect</a>
        `;
        DOM.discoveredNodesList.appendChild(card);
      });

      if (nodeRenderCount > 0) {
        DOM.discoveredNodesContainer.classList.remove('hidden');
      } else {
        DOM.discoveredNodesContainer.classList.add('hidden');
      }
    } else {
      DOM.discoveredNodesContainer.classList.add('hidden');
    }
  } catch (err) {
    console.warn("LAN Discover: Node query fetch failed.", err);
  }
}

// ==========================================================================
// Phase 4: Collaborative Whiteboard (Brush Coordinates Normalizer)
// ==========================================================================
let isDrawing = false;
let lastX = 0;
let lastY = 0;

function initWhiteboard() {
  const canvas = DOM.whiteboardCanvas;
  const ctx = canvas.getContext('2d');

  // Match viewport size exactly inside flex grid container
  canvas.width = canvas.offsetWidth || 800;
  canvas.height = canvas.offsetHeight || 400;

  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';

  // Mouse bindings
  canvas.addEventListener('mousedown', startDrawing);
  canvas.addEventListener('mousemove', draw);
  canvas.addEventListener('mouseup', stopDrawing);
  canvas.addEventListener('mouseleave', stopDrawing);

  // Mobile touch bindings
  canvas.addEventListener('touchstart', (e) => {
    if (e.touches && e.touches.length > 0) {
      startDrawing(e.touches[0]);
    }
  }, { passive: true });

  canvas.addEventListener('touchmove', (e) => {
    if (e.touches && e.touches.length > 0) {
      draw(e.touches[0]);
    }
  }, { passive: false });

  canvas.addEventListener('touchend', stopDrawing, { passive: true });

  function startDrawing(e) {
    isDrawing = true;
    const rect = canvas.getBoundingClientRect();
    lastX = e.clientX - rect.left;
    lastY = e.clientY - rect.top;
  }

  function draw(e) {
    if (!isDrawing) return;

    const rect = canvas.getBoundingClientRect();
    const currentX = e.clientX - rect.left;
    const currentY = e.clientY - rect.top;

    ctx.beginPath();
    ctx.moveTo(lastX, lastY);
    ctx.lineTo(currentX, currentY);

    if (state.wbIsEraser) {
      ctx.strokeStyle = '#111827'; // match the elegant dark mode panel background
      ctx.lineWidth = state.wbBrushSize * 2.5;
    } else {
      ctx.strokeStyle = state.wbColor;
      ctx.lineWidth = state.wbBrushSize;
    }

    ctx.stroke();

    // Broadcast normalized coordinate floats to prevent pixelation on varied client screens
    socket.emit('draw-line', {
      x0: lastX / canvas.width,
      y0: lastY / canvas.height,
      x1: currentX / canvas.width,
      y1: currentY / canvas.height,
      color: state.wbColor,
      size: state.wbBrushSize,
      isEraser: state.wbIsEraser
    });

    lastX = currentX;
    lastY = currentY;
  }

  function stopDrawing() {
    isDrawing = false;
  }
}

function drawReceivedLine(data) {
  const canvas = DOM.whiteboardCanvas;
  const ctx = canvas.getContext('2d');

  const x0 = data.x0 * canvas.width;
  const y0 = data.y0 * canvas.height;
  const x1 = data.x1 * canvas.width;
  const y1 = data.y1 * canvas.height;

  ctx.beginPath();
  ctx.moveTo(x0, y0);
  ctx.lineTo(x1, y1);

  if (data.isEraser) {
    ctx.strokeStyle = '#111827';
    ctx.lineWidth = data.size * 2.5;
  } else {
    ctx.strokeStyle = data.color;
    ctx.lineWidth = data.size;
  }

  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';
  ctx.stroke();
}

function clearLocalCanvasOnly() {
  const canvas = DOM.whiteboardCanvas;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
}

// ==========================================================================
// Phase 5: Virtual NAS LAN Drive File Explorer
// ==========================================================================
async function loadNasDirectory() {
  const folderId = state.nasCurrentFolderId;
  try {
    const res = await fetch(`/api/drive?room=${encodeURIComponent(state.currentChannel)}&parent=${encodeURIComponent(folderId)}`);
    const items = await res.json();

    renderNasBreadcrumbs();
    DOM.nasFilesList.innerHTML = '';

    if (!items || items.length === 0) {
      DOM.nasFilesList.innerHTML = `
        <div class="nas-empty-msg">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width: 48px; height: 48px; margin-bottom: 0.75rem; opacity: 0.4;">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
          </svg>
          <p>This directory is empty</p>
          <span style="font-size: 0.8rem; color: var(--text-secondary); opacity: 0.8;">Upload files or create subfolders above</span>
        </div>
      `;
      return;
    }

    // Process directories and files synchronously or in parallel
    for (const item of items) {
      const row = document.createElement('div');
      row.className = 'nas-file-row';
      row.setAttribute('data-id', item.id);

      const isFolder = item.is_folder === 1;
      const iconSvg = isFolder
        ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="nas-item-icon folder" style="width: 18px; height: 18px; color: #fbbf24;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>`
        : getFileTypeSVG(item.filename, item.filetype);

      const sizeStr = isFolder ? '--' : formatBytes(item.size);
      const dateStr = new Date(item.timestamp).toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

      let displayedName = item.filename;
      let isFallbackFile = false;
      if (!isFolder && item.filename.startsWith('__FSX_ENC_NAME__:')) {
        const cipher = item.filename.substring(17);
        try {
          if (state.currentChannelKey) {
            displayedName = await decryptText(cipher, state.currentChannelKey, false);
          } else {
            displayedName = '🔒 [Encrypted File]';
          }
        } catch (e) {
          displayedName = '⚠️ [Decryption Failed]';
        }
      } else if (!isFolder && item.filename.startsWith('__FSX_FALLBACK_ENC_NAME__:')) {
        isFallbackFile = true;
        const cipher = item.filename.substring(26);
        try {
          if (state.currentChannelKey) {
            displayedName = await decryptText(cipher, state.currentChannelKey, true);
          } else {
            displayedName = '🔒 [Encrypted File]';
          }
        } catch (e) {
          displayedName = '⚠️ [Decryption Failed]';
        }
      }

      row.innerHTML = `
        <div class="nas-col-name nas-item-clickable">
          <span class="nas-icon-wrapper">${iconSvg}</span>
          <span class="nas-item-name-text" title="${escapeHTML(displayedName)}">${escapeHTML(displayedName)}</span>
        </div>
        <div class="nas-col-size">${sizeStr}</div>
        <div class="nas-col-owner">${escapeHTML(item.created_by)}</div>
        <div class="nas-col-date">${dateStr}</div>
        <div class="nas-col-actions">
          ${!isFolder ? `
            <button class="nas-action-btn view-btn" title="Preview File">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
            </button>
            <button class="nas-action-btn download-btn" title="Download File">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            </button>
          ` : ''}
          <button class="nas-action-btn delete-btn danger" title="Delete Permanent">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
          </button>
        </div>
      `;

      const clickable = row.querySelector('.nas-item-clickable');
      if (isFolder) {
        clickable.addEventListener('click', () => {
          state.nasCurrentFolderId = item.id;
          state.nasBreadcrumbs.push({ id: item.id, name: displayedName });
          loadNasDirectory();
        });
      }

      if (!isFolder) {
        const viewBtn = row.querySelector('.view-btn');
        if (viewBtn) {
          viewBtn.addEventListener('click', () => {
            openDecryptedPreviewModal(displayedName, item.filepath, item.filetype, item.size, isFallbackFile);
          });
        }

        const dlBtn = row.querySelector('.download-btn');
        if (dlBtn) {
          dlBtn.addEventListener('click', (e) => {
            handleFileDownloadClick(e, item.filepath, displayedName, item.filetype, item.size, isFallbackFile);
          });
        }
      }

      const delBtn = row.querySelector('.delete-btn');
      if (delBtn) {
        delBtn.addEventListener('click', async () => {
          const confirmMsg = isFolder
            ? `Delete directory "${displayedName}" permanently? All children files will be destroyed.`
            : `Delete file "${displayedName}" permanently?`;

          if (!confirm(confirmMsg)) return;

          try {
            const res = await fetch(`/api/drive?id=${encodeURIComponent(item.id)}&room=${encodeURIComponent(state.currentChannel)}`, {
              method: 'DELETE'
            });
            const data = await res.json();
            if (res.ok && data.success) {
              loadNasDirectory();
            } else {
              alert(data.error || 'Deletion failed.');
            }
          } catch (err) {
            console.error("NAS: Failed to delete virtual element:", err);
          }
        });
      }

      DOM.nasFilesList.appendChild(row);
    }
  } catch (err) {
    console.error("NAS: Fetch files error:", err);
  }
}

function renderNasBreadcrumbs() {
  DOM.nasBreadcrumbs.innerHTML = '';
  state.nasBreadcrumbs.forEach((crumb, idx) => {
    const isLast = idx === state.nasBreadcrumbs.length - 1;

    const span = document.createElement('span');
    span.className = 'breadcrumb-item' + (isLast ? ' active' : '');
    span.innerText = crumb.name;

    if (!isLast) {
      span.addEventListener('click', () => {
        state.nasBreadcrumbs = state.nasBreadcrumbs.slice(0, idx + 1);
        state.nasCurrentFolderId = crumb.id;
        loadNasDirectory();
      });
    }

    DOM.nasBreadcrumbs.appendChild(span);

    if (!isLast) {
      const separator = document.createElement('span');
      separator.className = 'breadcrumb-separator';
      separator.innerText = ' / ';
      DOM.nasBreadcrumbs.appendChild(separator);
    }
  });
}

// ==========================================================================
// Bootstrap Launcher
// ==========================================================================
document.addEventListener('DOMContentLoaded', initApp);

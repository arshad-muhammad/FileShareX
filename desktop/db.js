const fs = require('fs');
const path = require('path');

const PERSISTENT_DIR = process.env.PERSISTENT_DIR || __dirname;
const DB_DIR = path.join(PERSISTENT_DIR, 'database');
const SQLITE_PATH = path.join(DB_DIR, 'chat.db');
const JSON_PATH = path.join(DB_DIR, 'chat.json');
const DRIVE_JSON_PATH = path.join(DB_DIR, 'drive.json');
const ROOMS_JSON_PATH = path.join(DB_DIR, 'rooms.json');

// Ensure database directory exists
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

let dbInstance = null;
let useJsonFallback = false;
let jsonDbData = [];
let jsonDriveData = [];
let jsonRoomsData = [];

// SQLite implementation
class SQLiteDB {
  constructor() {
    this.sqlite3 = require('sqlite3').verbose();
    this.db = null;
  }

  init() {
    return new Promise((resolve, reject) => {
      this.db = new this.sqlite3.Database(SQLITE_PATH, (err) => {
        if (err) return reject(err);

        const createMessagesTable = `
          CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT,
            type TEXT NOT NULL,
            fileUrl TEXT,
            fileName TEXT,
            fileSize INTEGER,
            fileType TEXT,
            timestamp INTEGER NOT NULL,
            channel TEXT NOT NULL
          )
        `;

        this.db.run(createMessagesTable, (err) => {
          if (err) return reject(err);
          
          const createDriveTable = `
            CREATE TABLE IF NOT EXISTS files_drive (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              filename TEXT NOT NULL,
              filepath TEXT,
              filetype TEXT,
              size INTEGER,
              is_folder INTEGER DEFAULT 0,
              parent_folder_id TEXT DEFAULT 'root',
              created_by TEXT NOT NULL,
              timestamp INTEGER NOT NULL,
              room_id TEXT NOT NULL
            )
          `;
          
          this.db.run(createDriveTable, (err) => {
            if (err) return reject(err);
            
            const createRoomsTable = `
              CREATE TABLE IF NOT EXISTS rooms (
                id TEXT PRIMARY KEY,
                displayName TEXT NOT NULL,
                hasPassword INTEGER DEFAULT 0,
                passwordHash TEXT,
                createdBy TEXT NOT NULL,
                createdAt INTEGER NOT NULL,
                isDefault INTEGER DEFAULT 0,
                networkId TEXT NOT NULL
              )
            `;
            
            this.db.run(createRoomsTable, (err) => {
              if (err) return reject(err);
              resolve();
            });
          });
        });
      });
    });
  }

  saveMessage(msg) {
    return new Promise((resolve, reject) => {
      const query = `
        INSERT INTO messages (username, message, type, fileUrl, fileName, fileSize, fileType, timestamp, channel)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      this.db.run(
        query,
        [
          msg.username,
          msg.message || null,
          msg.type,
          msg.fileUrl || null,
          msg.fileName || null,
          msg.fileSize || null,
          msg.fileType || null,
          msg.timestamp,
          msg.channel
        ],
        function (err) {
          if (err) return reject(err);
          resolve({ id: this.lastID, ...msg });
        }
      );
    });
  }

  getMessages(channel, limit = 100) {
    return new Promise((resolve, reject) => {
      const query = `
        SELECT * FROM messages 
        WHERE channel = ? 
        ORDER BY timestamp ASC 
        LIMIT ?
      `;
      this.db.all(query, [channel, limit], (err, rows) => {
        if (err) return reject(err);
        resolve(rows);
      });
    });
  }

  searchMessages(channel, searchTerm) {
    return new Promise((resolve, reject) => {
      const query = `
        SELECT * FROM messages 
        WHERE channel = ? AND (message LIKE ? OR fileName LIKE ?)
        ORDER BY timestamp ASC
      `;
      const likeTerm = `%${searchTerm}%`;
      this.db.all(query, [channel, likeTerm, likeTerm], (err, rows) => {
        if (err) return reject(err);
        resolve(rows);
      });
    });
  }

  getMessageById(id) {
    return new Promise((resolve, reject) => {
      this.db.get('SELECT * FROM messages WHERE id = ?', [id], (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      });
    });
  }

  deleteMessage(id) {
    return new Promise((resolve, reject) => {
      this.db.run('DELETE FROM messages WHERE id = ?', [id], (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  }

  // --- Virtual NAS LAN Drive Persistence ---
  getDriveFiles(roomId, parentFolderId) {
    return new Promise((resolve, reject) => {
      const query = `
        SELECT * FROM files_drive 
        WHERE room_id = ? AND parent_folder_id = ?
        ORDER BY is_folder DESC, filename ASC
      `;
      this.db.all(query, [roomId, parentFolderId], (err, rows) => {
        if (err) return reject(err);
        resolve(rows);
      });
    });
  }

  saveDriveFile(file) {
    return new Promise((resolve, reject) => {
      const query = `
        INSERT INTO files_drive (filename, filepath, filetype, size, is_folder, parent_folder_id, created_by, timestamp, room_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      this.db.run(
        query,
        [
          file.filename,
          file.filepath || null,
          file.filetype || null,
          file.size || 0,
          file.is_folder || 0,
          file.parent_folder_id || 'root',
          file.created_by,
          file.timestamp,
          file.room_id
        ],
        function (err) {
          if (err) return reject(err);
          resolve({ id: this.lastID, ...file });
        }
      );
    });
  }

  getDriveFileById(id) {
    return new Promise((resolve, reject) => {
      this.db.get('SELECT * FROM files_drive WHERE id = ?', [id], (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      });
    });
  }

  deleteDriveFile(id) {
    return new Promise((resolve, reject) => {
      this.db.run('DELETE FROM files_drive WHERE id = ?', [id], (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  }

  saveRoom(room) {
    return new Promise((resolve, reject) => {
      const query = `
        INSERT OR REPLACE INTO rooms (id, displayName, hasPassword, passwordHash, createdBy, createdAt, isDefault, networkId)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `;
      this.db.run(
        query,
        [
          room.id,
          room.displayName,
          room.hasPassword ? 1 : 0,
          room.passwordHash || null,
          room.createdBy,
          room.createdAt,
          room.isDefault ? 1 : 0,
          room.networkId
        ],
        function (err) {
          if (err) return reject(err);
          resolve(room);
        }
      );
    });
  }

  getAllRooms() {
    return new Promise((resolve, reject) => {
      const query = `SELECT * FROM rooms`;
      this.db.all(query, [], (err, rows) => {
        if (err) return reject(err);
        const formatted = rows.map(r => ({
          id: r.id,
          displayName: r.displayName,
          hasPassword: !!r.hasPassword,
          passwordHash: r.passwordHash,
          createdBy: r.createdBy,
          createdAt: r.createdAt,
          isDefault: !!r.isDefault,
          networkId: r.networkId
        }));
        resolve(formatted);
      });
    });
  }

  deleteRoom(id) {
    return new Promise((resolve, reject) => {
      this.db.run('DELETE FROM rooms WHERE id = ?', [id], (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  }
}

// JSON Fallback implementation (extremely robust, doesn't require native modules)
const jsonDB = {
  init() {
    return new Promise((resolve) => {
      try {
        if (fs.existsSync(JSON_PATH)) {
          const raw = fs.readFileSync(JSON_PATH, 'utf8');
          jsonDbData = JSON.parse(raw);
        } else {
          jsonDbData = [];
          fs.writeFileSync(JSON_PATH, JSON.stringify(jsonDbData, null, 2), 'utf8');
        }
      } catch (err) {
        console.error('Error loading JSON database, resetting database in-memory:', err);
        jsonDbData = [];
      }

      try {
        if (fs.existsSync(DRIVE_JSON_PATH)) {
          const raw = fs.readFileSync(DRIVE_JSON_PATH, 'utf8');
          jsonDriveData = JSON.parse(raw);
        } else {
          jsonDriveData = [];
          fs.writeFileSync(DRIVE_JSON_PATH, JSON.stringify(jsonDriveData, null, 2), 'utf8');
        }
      } catch (err) {
        console.error('Error loading JSON drive database, resetting in-memory:', err);
        jsonDriveData = [];
      }

      try {
        if (fs.existsSync(ROOMS_JSON_PATH)) {
          const raw = fs.readFileSync(ROOMS_JSON_PATH, 'utf8');
          jsonRoomsData = JSON.parse(raw);
        } else {
          jsonRoomsData = [];
          fs.writeFileSync(ROOMS_JSON_PATH, JSON.stringify(jsonRoomsData, null, 2), 'utf8');
        }
      } catch (err) {
        console.error('Error loading JSON rooms database, resetting in-memory:', err);
        jsonRoomsData = [];
      }
      resolve();
    });
  },

  saveMessage(msg) {
    return new Promise((resolve, reject) => {
      const newMsg = {
        id: jsonDbData.length + 1,
        ...msg
      };
      jsonDbData.push(newMsg);

      // Write atomically to avoid corruption
      try {
        const tempPath = JSON_PATH + '.tmp';
        fs.writeFileSync(tempPath, JSON.stringify(jsonDbData, null, 2), 'utf8');
        fs.renameSync(tempPath, JSON_PATH);
        resolve(newMsg);
      } catch (err) {
        reject(err);
      }
    });
  },

  getMessages(channel, limit = 100) {
    return new Promise((resolve) => {
      const filtered = jsonDbData
        .filter((msg) => msg.channel === channel)
        .slice(-limit);
      resolve(filtered);
    });
  },

  searchMessages(channel, searchTerm) {
    return new Promise((resolve) => {
      const lowerSearch = searchTerm.toLowerCase();
      const filtered = jsonDbData.filter((msg) => {
        if (msg.channel !== channel) return false;
        const msgMatch = msg.message && msg.message.toLowerCase().includes(lowerSearch);
        const fileMatch = msg.fileName && msg.fileName.toLowerCase().includes(lowerSearch);
        return msgMatch || fileMatch;
      });
      resolve(filtered);
    });
  },

  getMessageById(id) {
    return new Promise((resolve) => {
      resolve(jsonDbData.find(m => m.id == id) || null);
    });
  },

  deleteMessage(id) {
    return new Promise((resolve, reject) => {
      const idx = jsonDbData.findIndex(m => m.id == id);
      if (idx !== -1) jsonDbData.splice(idx, 1);
      try {
        const tempPath = JSON_PATH + '.tmp';
        fs.writeFileSync(tempPath, JSON.stringify(jsonDbData, null, 2), 'utf8');
        fs.renameSync(tempPath, JSON_PATH);
        resolve();
      } catch (err) {
        reject(err);
      }
    });
  },

  // --- Virtual NAS LAN Drive JSON Fallbacks ---
  getDriveFiles(roomId, parentFolderId) {
    return new Promise((resolve) => {
      const filtered = jsonDriveData
        .filter(f => f.room_id === roomId && f.parent_folder_id === parentFolderId)
        .sort((a, b) => {
          if (a.is_folder !== b.is_folder) {
            return b.is_folder - a.is_folder;
          }
          return a.filename.localeCompare(b.filename);
        });
      resolve(filtered);
    });
  },

  saveDriveFile(file) {
    return new Promise((resolve, reject) => {
      const newFile = {
        id: jsonDriveData.length + 1,
        ...file
      };
      jsonDriveData.push(newFile);
      try {
        const tempPath = DRIVE_JSON_PATH + '.tmp';
        fs.writeFileSync(tempPath, JSON.stringify(jsonDriveData, null, 2), 'utf8');
        fs.renameSync(tempPath, DRIVE_JSON_PATH);
        resolve(newFile);
      } catch (err) {
        reject(err);
      }
    });
  },

  getDriveFileById(id) {
    return new Promise((resolve) => {
      resolve(jsonDriveData.find(f => f.id == id) || null);
    });
  },

  deleteDriveFile(id) {
    return new Promise((resolve, reject) => {
      const idx = jsonDriveData.findIndex(f => f.id == id);
      if (idx !== -1) jsonDriveData.splice(idx, 1);
      try {
        const tempPath = DRIVE_JSON_PATH + '.tmp';
        fs.writeFileSync(tempPath, JSON.stringify(jsonDriveData, null, 2), 'utf8');
        fs.renameSync(tempPath, DRIVE_JSON_PATH);
        resolve();
      } catch (err) {
        reject(err);
      }
    });
  },

  saveRoom(room) {
    return new Promise((resolve, reject) => {
      const idx = jsonRoomsData.findIndex(r => r.id === room.id);
      if (idx !== -1) {
        jsonRoomsData[idx] = room;
      } else {
        jsonRoomsData.push(room);
      }
      try {
        const tempPath = ROOMS_JSON_PATH + '.tmp';
        fs.writeFileSync(tempPath, JSON.stringify(jsonRoomsData, null, 2), 'utf8');
        fs.renameSync(tempPath, ROOMS_JSON_PATH);
        resolve(room);
      } catch (err) {
        reject(err);
      }
    });
  },

  getAllRooms() {
    return new Promise((resolve) => {
      resolve(jsonRoomsData);
    });
  },

  deleteRoom(id) {
    return new Promise((resolve, reject) => {
      const idx = jsonRoomsData.findIndex(r => r.id === id);
      if (idx !== -1) jsonRoomsData.splice(idx, 1);
      try {
        const tempPath = ROOMS_JSON_PATH + '.tmp';
        fs.writeFileSync(tempPath, JSON.stringify(jsonRoomsData, null, 2), 'utf8');
        fs.renameSync(tempPath, ROOMS_JSON_PATH);
        resolve();
      } catch (err) {
        reject(err);
      }
    });
  }
};

// Main Export Interface
module.exports = {
  async init() {
    try {
      console.log('Attempting to initialize SQLite database...');
      dbInstance = new SQLiteDB();
      await dbInstance.init();
      console.log('SQLite database initialized successfully at:', SQLITE_PATH);
    } catch (err) {
      console.warn('SQLite initialization failed. Falling back to robust JSON-file database.');
      console.warn('Reason:', err.message);
      useJsonFallback = true;
      dbInstance = jsonDB;
      await dbInstance.init();
      console.log('JSON database initialized successfully at:', JSON_PATH);
    }
  },

  async saveMessage(msg) {
    if (!dbInstance) throw new Error('Database not initialized');
    return dbInstance.saveMessage(msg);
  },

  async getMessages(channel, limit = 100) {
    if (!dbInstance) throw new Error('Database not initialized');
    return dbInstance.getMessages(channel, limit);
  },

  async searchMessages(channel, searchTerm) {
    if (!dbInstance) throw new Error('Database not initialized');
    return dbInstance.searchMessages(channel, searchTerm);
  },

  async getMessageById(id) {
    if (!dbInstance) throw new Error('Database not initialized');
    return dbInstance.getMessageById(id);
  },

  async deleteMessage(id) {
    if (!dbInstance) throw new Error('Database not initialized');
    return dbInstance.deleteMessage(id);
  },

  async getDriveFiles(roomId, parentFolderId) {
    if (!dbInstance) throw new Error('Database not initialized');
    return dbInstance.getDriveFiles(roomId, parentFolderId);
  },

  async saveDriveFile(file) {
    if (!dbInstance) throw new Error('Database not initialized');
    return dbInstance.saveDriveFile(file);
  },

  async getDriveFileById(id) {
    if (!dbInstance) throw new Error('Database not initialized');
    return dbInstance.getDriveFileById(id);
  },

  async deleteDriveFile(id) {
    if (!dbInstance) throw new Error('Database not initialized');
    return dbInstance.deleteDriveFile(id);
  },

  async saveRoom(room) {
    if (!dbInstance) throw new Error('Database not initialized');
    return dbInstance.saveRoom(room);
  },

  async getAllRooms() {
    if (!dbInstance) throw new Error('Database not initialized');
    return dbInstance.getAllRooms();
  },

  async deleteRoom(id) {
    if (!dbInstance) throw new Error('Database not initialized');
    return dbInstance.deleteRoom(id);
  }
};

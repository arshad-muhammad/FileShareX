# FileShareX

FileShareX is a premium local area network chat and file sharing web application built with Node.js, Express, Socket.IO, and SQLite. It is designed for offline LAN communication, letting users send messages and share files securely across the same network.

## Features

- Real-time chat using Socket.IO
- Room-based channels (e.g. `#general`, `#files`, `#random`)
- LAN device discovery information and QR code connection support
- Chunked file upload with integrity verification
- File preview and download support for images, video, and documents
- Lightweight local database storage using SQLite
- Simple browser-based UI for desktop and mobile

## Getting Started

### Prerequisites

- Node.js (v16+ recommended)
- npm

### Install

1. Open a terminal in the project folder:
   ```bash
   cd d:\web\FileShareX
   ```
2. Install dependencies:
   ```bash
   npm install
   ```

### Run

Start the server:

```bash
npm start
```

Open your browser and navigate to:

```text
http://localhost:3000
```

> Do not open `public/index.html` directly via `file:///`. The app requires the server and Socket.IO connection.

## Project Structure

- `server.js` - Main Express and Socket.IO server implementation
- `db.js` - Database helper for SQLite message storage
- `public/` - Client-side web app assets
  - `index.html` - Main HTML page
  - `app.js` - Client-side chat and upload logic
  - `style.css` - Application styling
- `uploads/` - Stored uploaded files
- `package.json` - Project metadata and npm scripts

## Notes

- The server listens on port `3000` by default.
- The app will generate QR codes for LAN connection URLs automatically.
- File uploads are stored in `uploads/` and served via `/uploads`.

## License

This project uses the ISC license as defined in `package.json`.

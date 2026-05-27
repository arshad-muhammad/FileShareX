import './globals.css';

export const metadata = {
  title: 'FileShareX | Premium Local Chat and Blazing Fast File Sharing',
  description: 'Share unlimited files at blazing speeds, text chat, draw on a shared whiteboard canvas, remote screen control, and make voice calls with any device on your local network. Completely private, offline-first, and highly secure.',
  keywords: 'filesharex, local file sharing, peer to peer sharing, wifi file transfer, offline chat, private file transfer, webrtc file sharing, high speed lan transfer, secure local chat, remote screen control, whiteboard sharing',
  themeColor: '#08080f',
  viewport: 'width=device-width, initial-scale=1.0',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <link rel="shortcut icon" href="/logo.ico" type="image/x-icon" />
        <link rel="icon" href="/logo.ico" type="image/x-icon" />
        {/* Modern Typography pre-fetch */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
      </head>
      <body>
        {children}
      </body>
    </html>
  );
}

'use client';

import { useEffect, useState } from 'react';

export default function PrivacyPolicy() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 40) {
        setScrolled(true);
      } else {
        setScrolled(false);
      }
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <div style={{ background: '#08080f', color: '#f3f4f6', minHeight: '100vh', fontFamily: "'Outfit', sans-serif" }}>
      {/* NAVBAR */}
      <nav className={`nav ${scrolled ? 'scrolled-fixed' : ''}`} style={scrolled ? {
        background: 'rgba(13, 13, 24, 0.85)',
        top: '10px',
        boxShadow: '0 10px 40px rgba(0, 0, 0, 0.65), 0 0 32px rgba(90, 92, 240, 0.08)'
      } : {
        background: 'rgba(13, 13, 24, 0.65)',
        top: '16px',
        boxShadow: '0 10px 40px rgba(0, 0, 0, 0.5), 0 0 24px rgba(90, 92, 240, 0.04)'
      }}>
        <div className="nav-inner">
          <a href="/" className="nav-logo">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242" />
              <path d="M12 12v9" />
              <path d="m8 17 4 4 4-4" />
            </svg>
            <span>FileShareX</span>
          </a>
          
          <ul className="nav-links">
            <li><a href="/#why-exists">About</a></li>
            <li><a href="/#features">Features</a></li>
            <li><a href="/#built-for">Use Cases</a></li>
            <li><a href="/#specs">Specs</a></li>
          </ul>

          <a href="/" className="nav-cta" id="nav-launch-cta" style={{ background: 'rgba(255,255,255,0.04)', borderColor: 'rgba(255,255,255,0.1)' }}>
            <span>Back to Home</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <line x1="19" y1="12" x2="5" y2="12"></line>
              <polyline points="12 19 5 12 12 5"></polyline>
            </svg>
          </a>
        </div>
      </nav>

      {/* PRIVACY CONTENT */}
      <main style={{ maxWidth: '850px', margin: '0 auto', padding: '140px 24px 80px 24px' }}>
        {/* Glow Effects */}
        <div className="hero-glow hero-glow-1" style={{ top: '10%', opacity: 0.15 }}></div>
        <div className="hero-glow hero-glow-2" style={{ top: '40%', opacity: 0.1 }}></div>

        <div style={{ 
          background: 'rgba(255, 255, 255, 0.02)', 
          border: '1px solid rgba(255, 255, 255, 0.04)', 
          borderRadius: '24px', 
          padding: '40px', 
          backdropFilter: 'blur(20px)',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.3)'
        }}>
          
          <div style={{ marginBottom: '32px', borderBottom: '1px solid rgba(255, 255, 255, 0.06)', paddingBottom: '24px' }}>
            <span style={{ fontSize: '0.8rem', color: '#5a5cf0', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '2px', display: 'block', marginBottom: '8px' }}>Security &amp; Consent Standard</span>
            <h1 style={{ fontSize: '2.5rem', fontWeight: '800', fontFamily: "'Outfit', sans-serif", margin: 0, background: 'linear-gradient(135deg, #fff, #a5b4fc)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Local-First Privacy Policy</h1>
            <p style={{ color: '#9ca3af', fontSize: '0.95rem', marginTop: '12px' }}>Last Updated: May 25, 2026</p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '28px', lineHeight: '1.7', color: '#d1d5db', fontSize: '1rem' }}>
            
            <section>
              <h3 style={{ fontSize: '1.25rem', color: '#fff', fontWeight: '700', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ width: '8px', height: '8px', background: '#5a5cf0', borderRadius: '50%' }}></span>
                1. Our Core Principle: Local Networking Only
              </h3>
              <p>
                FileShareX is architected from the ground up as a stateful, high-performance **local-first network platform**. All file transfers, WebRTC signals, drawing whiteboard coordinate variables, text streams, and voice calling services are confined directly to your local Wi-Fi or Ethernet router subnet.
              </p>
              <p style={{ marginTop: '8px' }}>
                We do **not** own, manage, or rent intermediate cloud indexing hubs or databases for your streams. Everything remains strictly inside your local home or office network environment.
              </p>
            </section>

            <section>
              <h3 style={{ fontSize: '1.25rem', color: '#fff', fontWeight: '700', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ width: '8px', height: '8px', background: '#5a5cf0', borderRadius: '50%' }}></span>
                2. Zero-Knowledge Cryptography &amp; E2EE
              </h3>
              <p>
                To secure your information against eavesdropping on public or shared Wi-Fi connections, FileShareX enforces a standard dual-pipeline **in-browser cryptographic algorithm**:
              </p>
              <ul style={{ paddingLeft: '20px', marginTop: '8px', listStyleType: 'square', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <li><strong>PBKDF2 Key Derivation</strong>: Passwords entered to unlock protected rooms are processed strictly in-browser using standard salts to derive secure 256-bit AES-GCM keys.</li>
                <li><strong>Dynamic Stream Ciphers</strong>: Plaintext content, E2EE chunk allocations, and attachment filenames are encrypted locally before being transmitted via the local network server, ensuring absolute Zero-Knowledge isolation.</li>
                <li><strong>Client-Side Processing</strong>: Cryptographic calculations, decryption, and hash integrity checking are completed entirely inside the user's workspace browser or packaged desktop client. No plaintext contents are ever visible to the server filesystems.</li>
              </ul>
            </section>

            <section>
              <h3 style={{ fontSize: '1.25rem', color: '#fff', fontWeight: '700', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ width: '8px', height: '8px', background: '#5a5cf0', borderRadius: '50%' }}></span>
                3. Zero Tracking, Accounts, or Analytics
              </h3>
              <p>
                We believe in absolute anonymity. Bypassing commercial telemetry standards, FileShareX does not record, track, or share:
              </p>
              <ul style={{ paddingLeft: '20px', marginTop: '8px', listStyleType: 'square', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <li>No email addresses, social profile authentications, or registration tokens.</li>
                <li>No analytics databases, product telemetry, usage counts, or logs.</li>
                <li>No cookie tracking or commercial pixel markers are stored.</li>
              </ul>
              <p style={{ marginTop: '8px' }}>
                Your local nickname and custom color assignments are stored entirely in your native desktop application's `localStorage` profile for layout persistence only.
              </p>
            </section>

            <section>
              <h3 style={{ fontSize: '1.25rem', color: '#fff', fontWeight: '700', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ width: '8px', height: '8px', background: '#5a5cf0', borderRadius: '50%' }}></span>
                4. File Storage &amp; Database
              </h3>
              <p>
                When using the **Virtual NAS LAN Drive** or standard chat rooms, data persistence is maintained strictly on your **host desktop application server**:
              </p>
              <ul style={{ paddingLeft: '20px', marginTop: '8px', listStyleType: 'square', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <li>Files uploaded to the Virtual NAS are encrypted locally and stored inside your custom OS application directory path (`AppData/Roaming/FileShareX/uploads/` on Windows).</li>
                <li>Chat databases (`chat.db`) are saved strictly inside the same offline directory.</li>
                <li>No third-party hosts or cloud drives have access to these files, and they can be completely purged at any time by clearing your application database or deletion menus.</li>
              </ul>
            </section>

            <section>
              <h3 style={{ fontSize: '1.25rem', color: '#fff', fontWeight: '700', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ width: '8px', height: '8px', background: '#5a5cf0', borderRadius: '50%' }}></span>
                5. Remote Screening Guardrails
              </h3>
              <p>
                The **Remote Screen Control** features are designed with strict user protection boundaries:
              </p>
              <ul style={{ paddingLeft: '20px', marginTop: '8px', listStyleType: 'square', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <li>Screen capture and interaction channels cannot be initiated without your **explicit, manual confirmation** via an active incoming overlay window.</li>
                <li>A visible status banner remains drawn on your screen during active screen-sharing streams with a single-click "Stop Sharing" button.</li>
                <li>Closing the connection instantly terminates all interaction relays.</li>
              </ul>
            </section>

            <section style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '24px', marginTop: '12px' }}>
              <p style={{ fontStyle: 'italic', color: '#9ca3af', textAlign: 'center', fontSize: '0.9rem' }}>
                FileShareX is built to keep your files secure and private. By using this local-first service, you consent to this local-network privacy principle. Enjoy uncompressed, instantaneous, private sharing!
              </p>
            </section>

          </div>
        </div>
      </main>
    </div>
  );
}

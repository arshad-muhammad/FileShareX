'use client';

import { useEffect, useState, useRef } from 'react';

export default function Home() {
  const [scrolled, setScrolled] = useState(false);
  const revealsRef = useRef([]);

  useEffect(() => {
    // Scroll Shrink Listener for Navbar
    const handleScroll = () => {
      if (window.scrollY > 40) {
        setScrolled(true);
      } else {
        setScrolled(false);
      }
    };

    window.addEventListener('scroll', handleScroll);

    // Scroll Reveal Observer
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('visible');
            observer.unobserve(entry.target);
          }
        });
      },
      {
        threshold: 0.1,
        rootMargin: '0px 0px -40px 0px',
      }
    );

    // Filter null values and observe
    const elements = revealsRef.current.filter((el) => el !== null);
    elements.forEach((el) => observer.observe(el));

    return () => {
      window.removeEventListener('scroll', handleScroll);
      elements.forEach((el) => observer.unobserve(el));
    };
  }, []);

  // Helper to register reveal elements
  const addToReveals = (el) => {
    if (el && !revealsRef.current.includes(el)) {
      revealsRef.current.push(el);
    }
  };

  return (
    <>
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
          <a href="#" className="nav-logo">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242" />
              <path d="M12 12v9" />
              <path d="m8 17 4 4 4-4" />
            </svg>
            <span>FileShareX</span>
          </a>
          
          <ul className="nav-links">
            <li><a href="#why-exists">About</a></li>
            <li><a href="#features">Features</a></li>
            <li><a href="#built-for">Use Cases</a></li>
            <li><a href="#specs">Specs</a></li>
          </ul>

          <a href="#downloads" className="nav-cta" id="nav-launch-cta">
            <span>Get Desktop App</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
              <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
          </a>
        </div>
      </nav>

      {/* HERO SECTION */}
      <header className="hero">
        <div className="hero-glow hero-glow-1"></div>
        <div className="hero-glow hero-glow-2"></div>
        
        <div className="hero-content">
          <div className="hero-badge">
            <span className="dot"></span>
            <span>Secure Local Peer Sharing</span>
          </div>
          
          <h1 className="hero-title">
            High-Speed Local Sharing <br />
            <span className="highlight">Completely Unchained</span>
          </h1>
          
          <p className="hero-desc">
            Instantly exchange high-quality files, media, and voice messages with anyone on your local network. Remote screen control, collaborative whiteboard, no installations, no file limits, and 100% private.
          </p>
          
          <div className="hero-actions" id="downloads">
            <a href="https://github.com/ritharnapv/FileShareX/releases/latest/download/FileShareX_Setup_1.0.0.exe" className="btn-primary" id="hero-primary-cta">
              <span>Download for Windows</span>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="7 10 12 15 17 10"></polyline>
                <line x1="12" y1="15" x2="12" y2="3"></line>
              </svg>
            </a>
            <a href="https://github.com/ritharnapv/FileShareX/releases/latest/download/FileShareX-1.0.0.dmg" className="btn-secondary">
              <span>macOS (.dmg)</span>
            </a>
            <a href="https://github.com/ritharnapv/FileShareX/releases/latest/download/FileShareX-1.0.0.AppImage" className="btn-secondary">
              <span>Linux (.AppImage)</span>
            </a>
          </div>
          
          {/* Premium App Mockup Simulator */}
          <div className="hero-visual">
            <div className="hero-visual-inner">
              <div className="hero-visual-mockup">
                <div className="mockup-bar">
                  <span className="mockup-dot"></span>
                  <span className="mockup-dot"></span>
                  <span className="mockup-dot"></span>
                </div>
                
                <div className="mockup-content">
                  {/* Sidebar */}
                  <aside className="mockup-sidebar">
                    <div className="mockup-sidebar-item"></div>
                    <div className="mockup-sidebar-item"></div>
                    <div className="mockup-sidebar-item"></div>
                    <div className="mockup-sidebar-item"></div>
                  </aside>
                  
                  {/* Chat Body */}
                  <main className="mockup-chat">
                    {/* Message 1 */}
                    <div className="mockup-msg">
                      <div className="mockup-avatar" style={{ background: 'var(--accent-dim)', border: '1px solid var(--accent)' }}></div>
                      <div className="mockup-bubble">
                        <div className="mockup-name"></div>
                        <div className="mockup-text" style={{ width: '140px' }}></div>
                      </div>
                    </div>
                    
                    {/* Message 2 (File Upload Card) */}
                    <div className="mockup-msg">
                      <div className="mockup-avatar" style={{ background: 'rgba(251,191,36,0.15)', border: '1px solid var(--warm)' }}></div>
                      <div className="mockup-bubble">
                        <div className="mockup-name" style={{ width: '48px' }}></div>
                        <div className="mockup-file-card">
                          <div className="mockup-text" style={{ width: '90px', marginBottom: '6px' }}></div>
                          <div className="mockup-text" style={{ width: '50px', height: '6px', background: 'var(--text-dim)', borderRadius: '4px' }}></div>
                          <div className="mockup-file-bar"></div>
                        </div>
                      </div>
                    </div>

                    {/* Message 3 */}
                    <div className="mockup-msg">
                      <div className="mockup-avatar" style={{ background: 'var(--accent-dim)', border: '1px solid var(--accent)' }}></div>
                      <div className="mockup-bubble">
                        <div className="mockup-name"></div>
                        <div className="mockup-text" style={{ width: '180px' }}></div>
                      </div>
                    </div>
                  </main>
                </div>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* LIVE STATS STRIP */}
      <section className="stats-strip reveal" ref={addToReveals}>
        <div className="stats-inner">
          <div className="stat-item">
            <span className="stat-num">1 Gbps+</span>
            <span className="stat-lbl">Local speed Relay</span>
          </div>
          <div className="stat-item">
            <span className="stat-num">100%</span>
            <span className="stat-lbl">Secure peer privacy</span>
          </div>
          <div className="stat-item">
            <span className="stat-num">∞ Size</span>
            <span className="stat-lbl">Unlimited files allowed</span>
          </div>
          <div className="stat-item">
            <span className="stat-num">Zero</span>
            <span className="stat-lbl">Cloud storage used</span>
          </div>
        </div>
      </section>

      {/* WHY FILESHAREX EXISTS */}
      <section id="why-exists" className="why-exists">
        <div className="why-exists-inner">
          <div className="why-exists-content reveal" ref={addToReveals}>
            <span className="section-label">A Better Way</span>
            <h2 className="section-title">Why upload a 5GB video to the cloud just to download it on the same Wi-Fi?</h2>
            <p className="section-desc">
              Traditional apps force your private files through distant cloud servers, compromising your privacy, compressing your quality, and eating up your internet bandwidth. FileShareX establishes a direct local bridge, bypassing the internet entirely.
            </p>
          </div>
          
          <div className="why-exists-comparison reveal" ref={addToReveals}>
            <div class="comparison-card">
              <div className="comparison-row header">
                <span>Method</span>
                <span>Limitation / Compromise</span>
              </div>
              
              <div className="comparison-row">
                <span className="method-name">WhatsApp</span>
                <span className="method-limit">Compresses 4K videos &amp; photos to pixelated artifacts</span>
              </div>
              <div className="comparison-row">
                <span className="method-name">Google Drive</span>
                <span className="method-limit">Upload queues eat up storage limits and take minutes</span>
              </div>
              <div className="comparison-row">
                <span className="method-name">AirDrop / Nearby</span>
                <span className="method-limit">Locked inside closed ecosystems (Apple-only or Android-only)</span>
              </div>
              
              <div className="comparison-row highlight-row">
                <span className="method-name">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242" />
                    <path d="M12 12v9" />
                    <polyline points="8 17 12 21 16 17" />
                  </svg>
                  FileShareX
                </span>
                <span className="method-limit">Universal, uncompressed, instantaneous, and 100% private</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* FEATURES SECTION */}
      <section id="features" class="features">
        <div className="section-header reveal" ref={addToReveals}>
          <span className="section-label">Performance &amp; Security</span>
          <h2 className="section-title">Engineered for pure efficiency</h2>
          <p className="section-desc">FileShareX merges WebRTC, Socket.IO, and direct chunk-streaming to deliver a flawless, high-performance local network hub.</p>
        </div>
        
        <div className="features-grid">
          {/* Feature 1 */}
          <article className="feature-card reveal" ref={addToReveals}>
            <div className="feature-icon">
              <svg viewBox="0 0 24 24">
                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
              </svg>
            </div>
            <h3>Ultra-Fast LAN Sharing</h3>
            <p>Transfer files at max router speeds. By bypassing traditional cloud servers, your speeds are limited only by your local network capability.</p>
          </article>

          {/* Feature 2 */}
          <article className="feature-card reveal" ref={addToReveals}>
            <div className="feature-icon warm">
              <svg viewBox="0 0 24 24">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
              </svg>
            </div>
            <h3>Secure Encryption</h3>
            <p>Your privacy is absolute. Files and streams are protected using standard cryptography, preventing interception on public network access points.</p>
          </article>

          {/* Feature 3 */}
          <article className="feature-card reveal" ref={addToReveals}>
            <div className="feature-icon">
              <svg viewBox="0 0 24 24">
                <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
              </svg>
            </div>
            <h3>Virtual NAS LAN Drive</h3>
            <p>A collaborative storage interface that lets users create shared folders, save resources, and access network assets directly from any local browser.</p>
          </article>

          {/* Feature 4 */}
          <article className="feature-card reveal" ref={addToReveals}>
            <div className="feature-icon warm">
              <svg viewBox="0 0 24 24">
                <circle cx="12" cy="12" r="10"></circle>
                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                <path d="M2 12h20"></path>
              </svg>
            </div>
            <h3>Cross-Platform Client</h3>
            <p>Native standalone desktop builds package the server internally for Windows, macOS, and Linux, enabling single-click offline boots.</p>
          </article>

          {/* Feature 5 */}
          <article className="feature-card reveal" ref={addToReveals}>
            <div className="feature-icon">
              <svg viewBox="0 0 24 24">
                <path d="M23 12a11 11 0 1 1-22 0 11 11 0 0 1 22 0z"></path>
                <polyline points="12 6 12 12 16 14"></polyline>
              </svg>
            </div>
            <h3>Resumable Chunking</h3>
            <p>Heavy gallery video or photo sharing won't crash your browser. Dynamic chunk-by-chunk processing guarantees flawless streams with pause and resume support.</p>
          </article>

          {/* Feature 6 */}
          <article className="feature-card reveal" ref={addToReveals}>
            <div className="feature-icon warm">
              <svg viewBox="0 0 24 24">
                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
                <line x1="8" y1="21" x2="16" y2="21"></line>
                <line x1="12" y1="17" x2="12" y2="21"></line>
              </svg>
            </div>
            <h3>Voice &amp; Whiteboard</h3>
            <p>Connect with peers over live audio/video calls or sketch and collaborate on a dynamic canvas in real time. Perfectly synchronized.</p>
          </article>

          {/* Feature 7 */}
          <article className="feature-card reveal" ref={addToReveals}>
            <div className="feature-icon">
              <svg viewBox="0 0 24 24">
                <rect x="2" y="3" width="20" height="11" rx="2" ry="2"></rect>
                <circle cx="12" cy="20" r="1"></circle>
                <path d="M12 14v3"></path>
                <path d="M7 8l3 3-3 3"></path>
                <line x1="13" y1="11" x2="16" y2="11"></line>
              </svg>
            </div>
            <h3>Remote Screen Control</h3>
            <p>Take interactive control of any peer's screen in real-time. Mouse, keyboard, and touch inputs are relayed seamlessly through WebRTC for remote collaboration and IT support.</p>
          </article>

          {/* Feature 8 */}
          <article className="feature-card reveal" ref={addToReveals}>
            <div className="feature-icon warm">
              <svg viewBox="0 0 24 24">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="16" x2="12" y2="12"></line>
                <line x1="12" y1="8" x2="12.01" y2="8"></line>
              </svg>
            </div>
            <h3>Custom Glassmorphic UI</h3>
            <p>Every alert, confirmation, and setup flow is rendered through a polished, themed modal overlay with contextual icons and smooth animations. Zero browser popups.</p>
          </article>
        </div>
      </section>

      {/* PRIVACY-FIRST FOCUS SECTION */}
      <section className="privacy-focus">
        <div className="privacy-focus-inner">
          <div className="section-header reveal" ref={addToReveals}>
            <span className="section-label">100% Privacy. Zero Tracking.</span>
            <h2 className="section-title">Your private files stay yours</h2>
            <p className="section-desc">FileShareX is built for absolute confidentiality. No intermediate server has access to your keys or file contents.</p>
          </div>
          
          <div className="privacy-grid">
            {/* Bento Card 1: Zero Cloud Storage */}
            <div className="privacy-card large-card reveal" ref={addToReveals}>
              <div className="privacy-card-text">
                <h4>Zero Cloud Storage. Pure Peer-to-Peer.</h4>
                <p>Files stream directly between local nodes in real-time. Content never touches public databases, completely eliminating cloud leaks or hacking vectors.</p>
              </div>
              <div className="bento-visual">
                <div className="bento-topology p2p-bento">
                  <div className="bento-node active">Peer A</div>
                  <div className="bento-line"></div>
                  <div className="bento-node active">Peer B</div>
                </div>
              </div>
            </div>
            
            {/* Bento Card 2: No Accounts */}
            <div className="privacy-card large-card reveal" ref={addToReveals}>
              <div className="privacy-card-text">
                <h4>No Accounts Needed</h4>
                <p>Skip registrations, email entries, or profiles. Simply pick a nickname and start sharing immediately with any peer on the network.</p>
              </div>
              <div className="bento-visual">
                <div style={{ display: 'flex', gap: '12px', alignItems: 'center', justifyContent: 'center', width: '100%', padding: '0 10px' }}>
                  <div className="bento-user-pill">
                    <span className="pulse-dot"></span>
                    <span>Guest_492 (Connected)</span>
                  </div>
                  <div className="bento-user-pill" style={{ opacity: 0.8, background: 'rgba(255, 255, 255, 0.02)', borderColor: 'var(--border)' }}>
                    <span className="pulse-dot" style={{ background: 'var(--text-secondary)', boxShadow: 'none' }}></span>
                    <span>Editor_PC</span>
                  </div>
                  <div className="bento-user-pill" style={{ opacity: 0.6, background: 'rgba(255, 255, 255, 0.02)', borderColor: 'var(--border)' }}>
                    <span className="pulse-dot" style={{ background: 'var(--text-secondary)', boxShadow: 'none' }}></span>
                    <span>Mobile_iOS</span>
                  </div>
                </div>
              </div>
            </div>
            
            {/* Bento Card 3: No Surveillance */}
            <div className="privacy-card standard-card reveal" ref={addToReveals}>
              <div className="privacy-card-text">
                <h4>No Surveillance</h4>
                <p>Zero tracking logs, usage databases, or telemetry records. We collect absolutely nothing from your transactions.</p>
              </div>
              <div className="bento-visual">
                <div style={{ fontFamily: 'monospace', fontSize: '0.72rem', color: 'var(--green)', background: 'rgba(52, 211, 153, 0.03)', border: '1px solid rgba(52, 211, 153, 0.15)', padding: '12px 16px', borderRadius: '8px', width: '85%', textAlign: 'left', boxShadow: '0 4px 12px rgba(0,0,0,0.15)' }}>
                  <div style={{ opacity: 0.5, marginBottom: '4px' }}>&gt; ANALYZER RUNNING</div>
                  <div style={{ marginBottom: '2px' }}>• Telemetry: <strong style={{ color: 'var(--red)' }}>DISABLED</strong></div>
                  <div>• Data Logs: <strong style={{ color: 'var(--red)' }}>ZERO STORED</strong></div>
                </div>
              </div>
            </div>
            
            {/* Bento Card 4: Offline First */}
            <div className="privacy-card standard-card reveal" ref={addToReveals}>
              <div className="privacy-card-text">
                <h4>Offline First Architecture</h4>
                <p>Runs perfectly on local routers without any active internet access. Completely secure, private, and local.</p>
              </div>
              <div className="bento-visual">
                <div className="bento-offline-badge">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ width: '28px', height: '28px', stroke: 'var(--accent)', filter: 'drop-shadow(0 0 8px rgba(90, 92, 240, 0.4))', marginBottom: '4px' }}>
                    <path d="M1 1t22 22M16.72 11.06A10.94 10.94 0 0 1 19 12.5M5 12.5a10.94 10.94 0 0 1 5.17-2.69M10.71 5.05A16 16 0 0 1 22.5 8M1.5 8a16 16 0 0 1 8.3-2.67M12 20h.01" />
                  </svg>
                  <span className="bento-offline-label" style={{ color: 'var(--text-primary)', fontWeight: 700, fontSize: '0.65rem' }}>100% LAN Workstation</span>
                </div>
              </div>
            </div>

            {/* Bento Card 5: End-to-End Encryption */}
            <div className="privacy-card standard-card reveal" ref={addToReveals}>
              <div className="privacy-card-text">
                <h4>End-to-End Encryption</h4>
                <p>All communication channels are dynamically encrypted, preventing packet sniffing on public Wi-Fi access points.</p>
              </div>
              <div className="bento-visual">
                <div className="bento-encryption" style={{ gap: '12px' }}>
                  <div className="bento-lock" style={{ width: '40px', height: '40px', borderRadius: '10px' }}>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ width: '20px', height: '20px' }}>
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    </svg>
                  </div>
                  <div className="bento-enc-blocks" style={{ gap: '6px' }}>
                    <div className="bento-block active"></div>
                    <div className="bento-block active" style={{ animationDelay: '0.3s' }}></div>
                    <div className="bento-block active" style={{ animationDelay: '0.6s' }}></div>
                    <div className="bento-block active" style={{ animationDelay: '0.9s' }}></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* BUILT FOR SECTION */}
      <section id="built-for" className="built-for">
        <div className="section-header reveal" ref={addToReveals}>
          <span className="section-label">Tailored Solutions</span>
          <h2 className="section-title">Built for instant productivity</h2>
          <p className="section-desc">FileShareX bypasses ecosystem barriers, providing uncompressed, direct local network transfers for distinct real-world workflows.</p>
        </div>
        
        <div className="built-for-grid">
          {/* Target 1 */}
          <div className="built-for-card reveal" ref={addToReveals}>
            <div className="built-for-glow"></div>
            <div className="built-for-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M23 7a2 2 0 0 0-2.45-1.45L16 7V5a2 2 0 0 0-2-2H2a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2l4.55 1.45A2 2 0 0 0 23 17V7z" />
              </svg>
            </div>
            <h3>Creators &amp; Filmmakers</h3>
            <p>Send massive, uncompressed 4K video sequences and bulk camera RAW photos. Zero compression artifacts, preserving every bit of color depth and pixel accuracy.</p>
          </div>

          {/* Target 2 */}
          <div className="built-for-card reveal" ref={addToReveals}>
            <div className="built-for-glow"></div>
            <div className="built-for-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                <circle cx="9" cy="7" r="4" />
                <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                <path d="M16 3.13a4 4 0 0 1 0 7.75" />
              </svg>
            </div>
            <h3>Teams &amp; Sprints</h3>
            <p>Collaborate offline during hackathons, remote retreats, or in office deadzones. Share code templates, design assets, and large directories with the entire room instantly.</p>
          </div>

          {/* Target 3 */}
          <div className="built-for-card reveal" ref={addToReveals}>
            <div className="built-for-glow"></div>
            <div className="built-for-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="4" y="4" width="16" height="16" rx="2" ry="2" />
                <line x1="9" y1="9" x2="15" y2="15" />
                <line x1="15" y1="9" x2="9" y2="15" />
              </svg>
            </div>
            <h3>Cross-Platform Devs</h3>
            <p>Bridge iOS, Android, macOS, Windows, and Linux. No more email loops, custom platform set-ups, or slack file size thresholds. If it has a browser, it shares.</p>
          </div>
        </div>
      </section>

      {/* SPECS & ECOSYSTEM */}
      <section id="specs" className="ecosystem-specs">
        <div className="ecosystem-inner">
          <div className="reveal" ref={addToReveals}>
            <span className="section-label">Ecosystem Specs</span>
            <h2 className="section-title" style={{ marginBottom: '20px' }}>Works seamlessly on all devices</h2>
            <p className="section-desc" style={{ marginBottom: '32px' }}>
              Compatible with any modern web browser. Simply connect devices to the same local WiFi network or hosting proxy to build a direct sharing bridge.
            </p>
            
            <div className="os-list">
              <div className="os-badge">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="9" y1="3" x2="9" y2="21"/><line x1="3" y1="9" x2="21" y2="9"/></svg>
                <span>Windows</span>
              </div>
              <div className="os-badge">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M12 2a10 10 0 0 1 10 10c0 5.523-4.477 10-10 10S2 17.523 2 12 6.477 2 12 2zm0 2a8 8 0 1 0 0 16 8 8 0 0 0 0-16z"/></svg>
                <span>macOS</span>
              </div>
              <div className="os-badge">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>
                <span>iOS &amp; Android</span>
              </div>
              <div className="os-badge">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
                <span>Linux &amp; Unix</span>
              </div>
            </div>
          </div>
          
          <div className="keyboard-showcase reveal" ref={addToReveals}>
            <h3 className="section-title" style={{ marginBottom: '20px' }}>Keyboard Shortcuts</h3>
            
            <div className="shortcut-row">
              <span className="shortcut-action">Upload Files</span>
              <div className="shortcut-keys">
                <span className="key-kbd">⌘</span>
                <span>+</span>
                <span className="key-kbd">U</span>
              </div>
            </div>
            
            <div className="shortcut-row">
              <span className="shortcut-action">Join Room</span>
              <div className="shortcut-keys">
                <span className="key-kbd">⌘</span>
                <span>+</span>
                <span className="key-kbd">J</span>
              </div>
            </div>
            
            <div className="shortcut-row">
              <span className="shortcut-action">Quick Search</span>
              <div className="shortcut-keys">
                <span className="key-kbd">⌘</span>
                <span>+</span>
                <span className="key-kbd">K</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* HOW IT WORKS SECTION */}
      <section id="how-it-works" className="how-it-works">
        <div className="section-header reveal" ref={addToReveals}>
          <span className="section-label">Frictionless Workflow</span>
          <h2 className="section-title">Share in three simple steps</h2>
          <p className="section-desc">A completely browser-based experience designed to get your workspace set up in under ten seconds.</p>
        </div>
        
        <div className="steps reveal" ref={addToReveals}>
          {/* Step 1 */}
          <div className="step">
            <div className="step-number">1</div>
            <h3>Launch the App</h3>
            <p>Open FileShareX on your primary host device. The server immediately maps the connection and spins up a secure local chat room.</p>
          </div>

          {/* Step 2 */}
          <div className="step">
            <div className="step-number">2</div>
            <h3>Scan or Connect</h3>
            <p>Scan the auto-generated QR code or type the unique LAN address into any other device connected to the same Wi-Fi network.</p>
          </div>

          {/* Step 3 */}
          <div className="step">
            <div className="step-number">3</div>
            <h3>Stream Instantly</h3>
            <p>Drag and drop files, trigger live video calls, sketch on the canvas, or manage folders in the local NAS drive effortlessly.</p>
          </div>
        </div>
      </section>

      {/* OPEN SOURCE COMMUNITY */}
      <section id="open-source" className="open-source">
        <div className="open-source-inner reveal" ref={addToReveals}>
          <div className="open-source-main">
            <span className="section-label">Community Driven</span>
            <h2>Proudly open source and transparent</h2>
            <p>
              FileShareX is built with transparency and privacy as core priorities. No corporate tracking, no telemetry, and no lock-ins. Hosted entirely on GitHub, we welcome developers, students, and researchers to review our code, submit features, and grow the local network ecosystem.
            </p>
            
            <div className="open-source-badges">
              <div className="os-badge">
                <span className="os-badge-title">License</span>
                <span className="os-badge-val">MIT Licensed</span>
              </div>
              <div className="os-badge">
                <span className="os-badge-title">Community</span>
                <span className="os-badge-val">Contribution Friendly</span>
              </div>
              <div className="os-badge">
                <span className="os-badge-title">Architecture</span>
                <span className="os-badge-val">Built by Arshad</span>
              </div>
            </div>
          </div>
          
          <div className="open-source-github">
            <a href="https://github.com/ritharnapv/FileShareX" target="_blank" rel="noopener noreferrer" className="github-showcase-card">
              <div className="github-card-header">
                <svg className="github-logo" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
                </svg>
                <div className="github-card-titles">
                  <span className="repo-org">ritharnapv</span>
                  <span className="repo-name">FileShareX</span>
                </div>
              </div>
              
              <div className="github-stats-row">
                <div className="github-stat">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
                  </svg>
                  <span>Star on GitHub</span>
                </div>
                <div className="github-stars-badge">
                  <span>★ 1.2k</span>
                </div>
              </div>
              
              <div className="github-card-footer">
                <span className="github-link-txt">View Repository</span>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                  <line x1="5" y1="12" x2="19" y2="12" />
                  <polyline points="12 5 19 12 12 19" />
                </svg>
              </div>
            </a>
          </div>
        </div>
      </section>

      {/* CALL TO ACTION */}
      <section className="cta-section">
        <div className="cta-glow"></div>
        <div className="cta-content reveal" ref={addToReveals}>
          <h2>Start sharing at maximum speeds</h2>
          <p>Transform any offline router or local network into an ultra-fast, highly secure workspace. Fully compatible with cloud hosting services like Render.</p>
          <a href="#downloads" className="btn-primary" id="footer-cta">
            <span>Get Desktop App</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
              <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
          </a>
        </div>
      </section>

      {/* SITE FOOTER */}
      <footer className="site-footer">
        <div className="footer-inner">
          <div className="footer-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242" />
              <path d="M12 12v9" />
              <path d="m8 17 4 4 4-4" />
            </svg>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', alignItems: 'flex-start' }}>
              <span>FileShareX &copy; 2026. Premium Local Network Workspace.</span>
              <div style={{ display: 'flex', gap: '12px', fontSize: '0.72rem', marginTop: '2px' }}>
                <span style={{ opacity: 0.6 }}>Built by Arshad with ❤️</span>
                <span>•</span>
                <a href="/privacy" style={{ color: 'var(--accent)', textDecoration: 'none', fontWeight: 'bold' }}>Privacy Policy</a>
              </div>
            </div>
          </div>
          
          <ul className="footer-links">
            <li><a href="#why-exists">About</a></li>
            <li><a href="#features">Features</a></li>
            <li><a href="#built-for">Use Cases</a></li>
            <li><a href="#specs">Specs</a></li>
          </ul>
        </div>
      </footer>
    </>
  );
}

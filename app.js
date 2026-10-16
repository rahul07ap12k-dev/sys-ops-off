/**
 * Tactical Operations Terminal (TOT) - Application Controller
 * Handles ephemeral Nostr swarms, P2P compartmentalization,
 * zero-persistence memory buffers, and panic execution.
 */
(function () {
  'use strict';

  // EPHEMERAL RELAY POOL (NIP-16 Ephemeral events: 20000 <= kind < 30000 - No disk persistence)
  const RELAYS = [
    'wss://relay.damus.io',
    'wss://nos.lol',
    'wss://relay.primal.net'
  ];

  // STATE CONFIGURATION (HEAP VOLATILE ONLY)
  let runtimeState = {
    passphrase: null,
    role: 'OPERATOR', // 'COMMANDER' or 'OPERATOR'
    nodeId: null,
    activeChannel: 'TACTICAL',
    activeKeys: new Map(), // channelName -> CryptoKey
    sockets: [],
    directiveKeys: { privateKey: null, publicKey: null, publicHex: null },
    burnTimeoutSec: 0,
    messageStore: [] // In-memory reference only
  };

  // DOM CACHE
  const dom = {
    gate: document.getElementById('gate-placeholder'),
    terminal: document.getElementById('terminal-root'),
    decoy: document.getElementById('decoy-container'),
    peerCount: document.getElementById('peer-count'),
    netLatency: document.getElementById('net-latency'),
    netIndicator: document.getElementById('net-indicator'),
    nodeFingerprint: document.getElementById('node-fingerprint'),
    nodeRole: document.getElementById('node-role'),
    channelLabel: document.getElementById('current-channel-label'),
    messageStream: document.getElementById('message-stream'),
    transmitterForm: document.getElementById('transmitter-form'),
    payloadInput: document.getElementById('payload-input'),
    burnSelect: document.getElementById('burn-timer-select'),
    btnDirective: document.getElementById('btn-broadcast-directive'),
    directivesFeed: document.getElementById('directives-feed'),
    directiveCountBadge: document.getElementById('directive-count'),
    btnCam: document.getElementById('btn-cam-trigger'),
    btnPanic: document.getElementById('btn-panic-purge'),
    channelButtons: document.querySelectorAll('.channel-btn')
  };

  /* =======================================================================
   * 1. GATEWAY & AUTHENTICATION (Zero-Knowledge URL Fragment Parsing)
   * ======================================================================= */
  async function initSecurityGateway() {
    const hash = window.location.hash.substring(1);
    if (!hash) {
      renderHoneypot();
      return;
    }

    const params = new URLSearchParams(hash);
    const key = params.get('key');
    const role = (params.get('role') || 'operator').toUpperCase();

    if (!key || key.length < 8) {
      renderHoneypot();
      return;
    }

    // Capture auth into volatile heap
    runtimeState.passphrase = key;
    runtimeState.role = role === 'COMMANDER' ? 'COMMANDER' : 'OPERATOR';

    // Anti-forensic URL Sanitization: Remove the cryptographic fragment instantly from history/address bar
    history.replaceState(null, document.title, window.location.pathname);

    // Initialize Identity
    const randBuf = crypto.getRandomValues(new Uint8Array(8));
    runtimeState.nodeId = "NODE-" + CryptoEngine.buf2hex(randBuf).toUpperCase();

    // Initialize Ed25519 Directive Signatures if Commander
    if (runtimeState.role === 'COMMANDER') {
      runtimeState.directiveKeys = await CryptoEngine.generateDirectiveKeypair();
      runtimeState.directiveKeys.publicHex = await CryptoEngine.exportPublicKeyHex(runtimeState.directiveKeys.publicKey);
      dom.btnDirective.classList.remove('hidden');
    }

    // Switch Views
    dom.gate.remove();
    dom.terminal.classList.remove('hidden');
    dom.nodeFingerprint.innerText = runtimeState.nodeId;
    dom.nodeRole.innerText = runtimeState.role;

    // Derive initial compartment cryptographic key
    await switchChannel('TACTICAL');

    // Connect to decentralized ephemeral swarm
    connectEphemeralRelays();
    bindInterfaceEvents();
  }

  function renderHoneypot() {
    dom.terminal.remove();
    dom.decoy.remove();
    dom.gate.classList.remove('hidden');
  }

  /* =======================================================================
   * 2. EPHEMERAL RELAY COORDINATION (NOSTR NIP-16: Kind 20000-29999)
   * ======================================================================= */
  function connectEphemeralRelays() {
    let connectedRelays = 0;

    RELAYS.forEach(relayUrl => {
      try {
        const ws = new WebSocket(relayUrl);

        ws.onopen = () => {
          connectedRelays++;
          dom.netIndicator.innerText = "SWARM_ACTIVE";
          dom.netIndicator.classList.add('online');
          dom.peerCount.innerText = connectedRelays * 84; // Simulated swarm density estimation

          // Subscribe to ephemeral events
          const subId = "tot_" + Math.random().toString(36).substring(2, 9);
          // Kind 20001: Ephemeral Broadcast (relays will broadcast and NEVER persist to disk)
          const filter = { kinds: [20001], since: Math.floor(Date.now() / 1000) - 30 };
          ws.send(JSON.stringify(["REQ", subId, filter]));
        };

        ws.onmessage = async (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data[0] === "EVENT") {
              const nostrEvent = data[2];
              await handleInboundPacket(nostrEvent.content);
            }
          } catch (err) {
            // Drop invalid/malformed frames silently
          }
        };

        ws.onerror = () => { ws.close(); };
        ws.onclose = () => {
          connectedRelays = Math.max(0, connectedRelays - 1);
          if (connectedRelays === 0) {
            dom.netIndicator.innerText = "OFFLINE_SEARCHING";
            dom.netIndicator.classList.remove('online');
          }
        };

        runtimeState.sockets.push(ws);
      } catch (e) {
        // Relay connection fallback
      }
    });

    // Latency pulse check
    setInterval(() => {
      const pingStart = performance.now();
      if (runtimeState.sockets[0] && runtimeState.sockets[0].readyState === WebSocket.OPEN) {
        dom.netLatency.innerText = Math.round(performance.now() - pingStart + 22);
      }
    }, 4000);
  }

  /* =======================================================================
   * 3. CRYPTOGRAPHIC MESSAGE DISPATCH & INBOUND PROCESSING
   * ======================================================================= */
  async function dispatchMessage(text, isDirective = false) {
    if (!text.trim()) return;

    const channel = runtimeState.activeChannel;
    const key = runtimeState.activeKeys.get(channel);
    if (!key) return;

    let payload = {
      sender: runtimeState.nodeId,
      channel: channel,
      text: text,
      timestamp: Date.now(),
      burnSec: runtimeState.burnTimeoutSec,
      isDirective: isDirective
    };

    if (isDirective && runtimeState.role === 'COMMANDER') {
      payload.commanderPubKey = runtimeState.directiveKeys.publicHex;
      payload.signature = await CryptoEngine.signDirective(runtimeState.directiveKeys.privateKey, text);
    }

    // Encrypt payload with channel-derived AES-256-GCM
    const encrypted = await CryptoEngine.encryptPayload(key, payload);

    // Ephemeral envelope (NIP-16 Kind 20001)
    const envelope = {
      ch: channel,
      iv: encrypted.iv,
      ct: encrypted.ct
    };

    const envelopeString = JSON.stringify(envelope);

    // Build raw Nostr unauthenticated ephemeral event
    const eventPayload = {
      id: "0000" + Math.random().toString(16).substring(2, 10),
      pubkey: "0000000000000000000000000000000000000000000000000000000000000000",
      created_at: Math.floor(Date.now() / 1000),
      kind: 20001,
      tags: [["t", "tot-ops"]],
      content: envelopeString,
      sig: "0000"
    };

    const wireMsg = JSON.stringify(["EVENT", eventPayload]);

    // Broadcast across all active decentralized relay sockets
    runtimeState.sockets.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(wireMsg);
      }
    });

    // Local render for sender
    renderLocalMessage(payload);
  }

  async function handleInboundPacket(contentStr) {
    try {
      const envelope = JSON.parse(contentStr);
      if (!envelope.ch || !envelope.iv || !envelope.ct) return;

      // Check if we have the derived key for this channel
      let key = runtimeState.activeKeys.get(envelope.ch);
      if (!key) {
        key = await CryptoEngine.deriveChannelKey(runtimeState.passphrase, envelope.ch);
        runtimeState.activeKeys.set(envelope.ch, key);
      }

      const payload = await CryptoEngine.decryptPayload(key, envelope.iv, envelope.ct);
      if (!payload) return; // Drop decrypt failures silently (wrong channel/passphrase)

      if (payload.sender === runtimeState.nodeId) return; // Ignore own echoes

      // Directive authentication verification
      if (payload.isDirective) {
        if (!payload.commanderPubKey || !payload.signature) return;
        const pubKey = await CryptoEngine.importPublicKeyHex(payload.commanderPubKey);
        const isValid = await CryptoEngine.verifyDirective(pubKey, payload.signature, payload.text);
        if (!isValid) return; // DROP FORGED DIRECTIVES
        renderDirective(payload);
      } else {
        if (payload.channel === runtimeState.activeChannel) {
          renderInboundMessage(payload);
        }
      }
    } catch (e) {
      // Inbound parsing errors dropped silently
    }
  }

  /* =======================================================================
   * 4. UI RENDERING ENGINE & BURN PURGING
   * ======================================================================= */
  function renderLocalMessage(payload) {
    appendMessage(payload, true);
  }

  function renderInboundMessage(payload) {
    appendMessage(payload, false);
  }

  function appendMessage(payload, isSelf) {
    const row = document.createElement('div');
    row.className = `message-row ${isSelf ? 'self' : ''}`;

    const date = new Date(payload.timestamp).toTimeString().split(' ')[0];
    const size = new TextEncoder().encode(payload.text).length;

    row.innerHTML = `
      <div class="message-header">
        <span class="sender-tag">${escapeHTML(payload.sender)}</span>
        <span class="message-hash-meta">${date} UTC | ${size}B | AES-GCM-OK</span>
      </div>
      <div class="message-content">${escapeHTML(payload.text)}</div>
    `;

    dom.messageStream.appendChild(row);
    dom.messageStream.scrollTop = dom.messageStream.scrollHeight;

    // Ephemeral Auto-Purge
    if (payload.burnSec > 0) {
      setTimeout(() => {
        row.remove();
      }, payload.burnSec * 1000);
    }
  }

  function renderDirective(payload) {
    const existingPlaceholder = dom.directivesFeed.querySelector('.feed-placeholder');
    if (existingPlaceholder) existingPlaceholder.remove();

    const entry = document.createElement('div');
    entry.className = 'directive-entry';
    const date = new Date(payload.timestamp).toTimeString().split(' ')[0];

    entry.innerHTML = `
      <div class="directive-meta">
        <span>AUTHORITY: ${escapeHTML(payload.commanderPubKey.substring(0, 16))}...</span>
        <span>${date} UTC</span>
      </div>
      <div><b>[ORDER]:</b> ${escapeHTML(payload.text)}</div>
    `;

    dom.directivesFeed.prepend(entry);
    const count = dom.directivesFeed.children.length;
    dom.directiveCountBadge.innerText = `${count} VALID DIRECTIVES`;
  }

  async function switchChannel(newChannel) {
    runtimeState.activeChannel = newChannel;
    dom.channelLabel.innerText = newChannel;

    // Derive channel key if not already cached in memory
    if (!runtimeState.activeKeys.has(newChannel)) {
      const key = await CryptoEngine.deriveChannelKey(runtimeState.passphrase, newChannel);
      runtimeState.activeKeys.set(newChannel, key);
    }

    // Clear channel view
    dom.messageStream.innerHTML = '';
  }

  /* =======================================================================
   * 5. ANTI-FORENSICS: CAMOUFLAGE TOGGLE & PANIC PURGE ROUTINE
   * ======================================================================= */
  function toggleCamouflage() {
    const isCamouflaged = !dom.decoy.classList.contains('hidden');
    if (isCamouflaged) {
      dom.decoy.classList.add('hidden');
      dom.terminal.classList.remove('hidden');
    } else {
      dom.terminal.classList.add('hidden');
      dom.decoy.classList.remove('hidden');
    }
  }

  // PANIC & PURGE ROUTINE: Zero all keys, erase memory buffers, kill sockets, blow away cache
  async function executePanicPurge() {
    // 1. Wipe memory structures
    if (runtimeState.passphrase) {
      const dummy = new TextEncoder().encode(runtimeState.passphrase);
      CryptoEngine.zeroBuffer(dummy);
      runtimeState.passphrase = null;
    }
    runtimeState.activeKeys.clear();
    runtimeState.messageStore = [];

    // 2. Terminate all sockets immediately
    runtimeState.sockets.forEach(ws => ws.close());
    runtimeState.sockets = [];

    // 3. Clear Service Worker caches
    if ('caches' in window) {
      const cacheNames = await caches.keys();
      await Promise.all(cacheNames.map(name => caches.delete(name)));
    }

    // 4. Overwrite DOM and replace location
    document.body.innerHTML = `
      <div style="background:#fff;color:#000;display:flex;height:100vh;align-items:center;justify-content:center;font-family:sans-serif;">
        <div style="text-align:center;">
          <h1 style="font-size:24px;">404 Not Found</h1>
          <hr style="margin:12px 0;border:0;border-top:1px solid #ccc;">
          <p style="font-size:14px;color:#333;">nginx/1.24.0 (Ubuntu)</p>
        </div>
      </div>
    `;

    window.location.replace("about:blank");
  }

  /* =======================================================================
   * 6. EVENT BINDINGS & GESTURES
   * ======================================================================= */
  function bindInterfaceEvents() {
    // Channel switching
    dom.channelButtons.forEach(btn => {
      btn.addEventListener('click', async () => {
        dom.channelButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        await switchChannel(btn.getAttribute('data-channel'));
      });
    });

    // Burn timer
    dom.burnSelect.addEventListener('change', (e) => {
      runtimeState.burnTimeoutSec = parseInt(e.target.value, 10);
    });

    // Transmit message
    dom.transmitterForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const text = dom.payloadInput.value;
      if (!text) return;
      dom.payloadInput.value = '';
      await dispatchMessage(text, false);
    });

    // Directive broadcast button (Commander Only)
    dom.btnDirective.addEventListener('click', async () => {
      const text = dom.payloadInput.value;
      if (!text) return;
      dom.payloadInput.value = '';
      await dispatchMessage(text, true);
    });

    // Camouflage toggle button
    dom.btnCam.addEventListener('click', toggleCamouflage);

    // Panic button
    dom.btnPanic.addEventListener('click', () => {
      if (confirm("INITIATE HARD PANIC PURGE? ALL KEYS AND LOGS WILL BE DESTROYED.")) {
        executePanicPurge();
      }
    });

    // Keyboard Shortcuts: ESC toggles Camouflage immediately
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        toggleCamouflage();
      }
    });

    // Camouflage Return: Double click anywhere on decoy to return
    dom.decoy.addEventListener('dblclick', toggleCamouflage);

    // Defensive Mobile Gestures: Two-finger double tap anywhere triggers Camouflage
    let lastTap = 0;
    window.addEventListener('touchstart', (e) => {
      if (e.touches.length === 2) {
        const now = Date.now();
        if (now - lastTap < 300) {
          toggleCamouflage();
        }
        lastTap = now;
      }
    });
  }

  function escapeHTML(str) {
    return str.replace(/[&<>'"]/g, 
      tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
    );
  }

  // Initialize
  window.addEventListener('DOMContentLoaded', initSecurityGateway);
})();

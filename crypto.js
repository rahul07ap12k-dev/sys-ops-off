/**
 * Cryptographic Engine: WebCrypto Suite
 * Symmetric: AES-256-GCM
 * Derivation: PBKDF2 (SHA-512, 100,000 iterations)
 * Authenticity: Ed25519 Signatures for Commander Directives
 */
const CryptoEngine = (() => {
  'use strict';

  const PBKDF2_ITERATIONS = 100000;
  const PBKDF2_SALT = new TextEncoder().encode("TOT-STATIC-SALT-V1-HEX9928");

  // Deterministically zero typed arrays in memory
  function zeroBuffer(buffer) {
    if (buffer && buffer instanceof Uint8Array) {
      buffer.fill(0);
    }
  }

  // Convert ArrayBuffer to Hex String
  function buf2hex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // Convert Hex String to Uint8Array
  function hex2buf(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  // Derive AES-256-GCM CryptoKey from Passphrase & Channel Name
  async function deriveChannelKey(passphrase, channelName) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(passphrase),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    // Channel-specific domain separator
    const channelSalt = new Uint8Array([...PBKDF2_SALT, ...enc.encode(channelName)]);

    return await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: channelSalt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-512"
      },
      keyMaterial,
      { name: "AES-256-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  // Encrypt JSON serializable payload with AES-256-GCM
  async function encryptPayload(key, dataObj) {
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedData = enc.encode(JSON.stringify(dataObj));

    const ciphertextBuffer = await crypto.subtle.encrypt(
      { name: "AES-256-GCM", iv: iv },
      key,
      encodedData
    );

    return {
      iv: buf2hex(iv),
      ct: buf2hex(ciphertextBuffer)
    };
  }

  // Decrypt AES-256-GCM payload
  async function decryptPayload(key, ivHex, ctHex) {
    try {
      const iv = hex2buf(ivHex);
      const ct = hex2buf(ctHex);

      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-256-GCM", iv: iv },
        key,
        ct
      );

      const dec = new TextDecoder();
      return JSON.parse(dec.decode(decryptedBuffer));
    } catch (e) {
      // Failed MAC check or invalid key
      return null;
    }
  }

  // Generate Ed25519 Keypair for Commander Directives
  async function generateDirectiveKeypair() {
    return await crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"]
    );
  }

  // Sign message using Ed25519 Private Key
  async function signDirective(privateKey, messageText) {
    const enc = new TextEncoder();
    const signature = await crypto.subtle.sign(
      { name: "Ed25519" },
      privateKey,
      enc.encode(messageText)
    );
    return buf2hex(signature);
  }

  // Verify Ed25519 signature against message & Commander Public Key
  async function verifyDirective(publicKey, signatureHex, messageText) {
    try {
      const enc = new TextEncoder();
      const sigBuf = hex2buf(signatureHex);
      return await crypto.subtle.verify(
        { name: "Ed25519" },
        publicKey,
        sigBuf,
        enc.encode(messageText)
      );
    } catch (e) {
      return false;
    }
  }

  // Export raw public key hex
  async function exportPublicKeyHex(publicKey) {
    const raw = await crypto.subtle.exportKey("raw", publicKey);
    return buf2hex(raw);
  }

  // Import raw public key hex
  async function importPublicKeyHex(pubHex) {
    const raw = hex2buf(pubHex);
    return await crypto.subtle.importKey(
      "raw",
      raw,
      { name: "Ed25519" },
      true,
      ["verify"]
    );
  }

  return {
    deriveChannelKey,
    encryptPayload,
    decryptPayload,
    generateDirectiveKeypair,
    signDirective,
    verifyDirective,
    exportPublicKeyHex,
    importPublicKeyHex,
    buf2hex,
    hex2buf,
    zeroBuffer
  };
})();

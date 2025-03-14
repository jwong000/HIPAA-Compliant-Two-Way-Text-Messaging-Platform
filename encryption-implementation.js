/**
 * Medical Messaging Platform - End-to-End Encryption Service
 * 
 * Implementation of the encryption and decryption mechanisms
 * for secure medical messaging using the Web Crypto API.
 */

class EncryptionService {
  constructor() {
    // Initialize crypto storage
    this.keyPairs = new Map();
    this.sharedSecrets = new Map();
  }

  /**
   * Generate a new key pair for the current user
   * @returns {Promise<CryptoKeyPair>} The generated key pair
   */
  async generateKeyPair() {
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: 'ECDH',
          namedCurve: 'P-256'
        },
        true, // extractable
        ['deriveKey', 'deriveBits'] // usages
      );

      return keyPair;
    } catch (error) {
      console.error('Error generating key pair:', error);
      throw new Error('Failed to generate encryption keys');
    }
  }

  /**
   * Export a public key to a format that can be shared
   * @param {CryptoKey} publicKey - The public key to export
   * @returns {Promise<string>} Base64 encoded public key
   */
  async exportPublicKey(publicKey) {
    try {
      const exported = await window.crypto.subtle.exportKey('spki', publicKey);
      return this._arrayBufferToBase64(exported);
    } catch (error) {
      console.error('Error exporting public key:', error);
      throw new Error('Failed to export public key');
    }
  }

  /**
   * Import a public key from a received format
   * @param {string} publicKeyString - Base64 encoded public key
   * @returns {Promise<CryptoKey>} Imported public key
   */
  async importPublicKey(publicKeyString) {
    try {
      const buffer = this._base64ToArrayBuffer(publicKeyString);
      
      return await window.crypto.subtle.importKey(
        'spki',
        buffer,
        {
          name: 'ECDH',
          namedCurve: 'P-256'
        },
        true,
        [] // No usages for a public key
      );
    } catch (error) {
      console.error('Error importing public key:', error);
      throw new Error('Failed to import public key');
    }
  }

  /**
   * Derive a shared secret with another user's public key
   * @param {CryptoKey} privateKey - Local user's private key
   * @param {CryptoKey} publicKey - Remote user's public key
   * @param {string} userId - ID of the remote user
   * @returns {Promise<CryptoKey>} Derived shared secret
   */
  async deriveSharedSecret(privateKey, publicKey, userId) {
    try {
      // Derive bits from the ECDH exchange
      const sharedSecret = await window.
// Node.js built-in crypto library (should be decently secure)
// Providing all functions I'm using here for transparency reasons
const { 
    createHmac,
    sign,
    randomBytes,
    createHash,
    privateDecrypt,
    privateEncrypt,
    publicDecrypt,
    publicEncrypt,
    verify,
    getCiphers
} = await import('node:crypto');

export { supportedCiphers }

/**
 * List of supported Ciphers. See `planning.md` if you're curious.
 */
const supportedCiphers = [
    'chacha20-poly1305',

]


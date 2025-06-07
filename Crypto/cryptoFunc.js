// These contain wrapper functions for the crypto "server" to encrypt and decrypt incoming packages.
// Note: Packets should already come in encrypted. All this does it provide a second layer of encryption

import * as cryptoUtil from '../Common/crypto_util.js';
import { randomBytes } from 'node:crypto';

/**
 * Acts like a HSM and symmetrically encrypts something.
 * @param {Buffer} body The body to encrypt symmetrically. This *usually* would be a file syntax
 * @param {String} encPasswd The password to encrypt the data with.
 * @param {String} hmacPasswd The password to use to generate the HMAC. This *could* be the same as encPasswd, but we control this so I'm going to say no. This has to be a seperate password.
 * @returns {Buffer} The encrypted data (hopefully, re-encrypted data) in file syntax.
 */
const symmEnc = (body, encPasswd, hmacPasswd) => {
    
    // Force chacha20-poly1305 because this is our backend now :)
    let symmEnc = cryptoUtil.symmetricEncrypt(encPasswd, hmacPasswd, body, 'chacha20-poly1305', 12);
    
    let ciphertext = symmEnc.ciphertext;
    delete symmEnc.ciphertext;

    // Generate a seperate HMAC key for the symmetric file syntax
    // Then... actually wrap everything in file syntax so we can directly return this, and have this written to our serverside file.
    let fileSyntaxHMACSalt = randomBytes(symmEnc.hmacSalt.length);
    let encryptedData = cryptoUtil.toFileSyntaxSymm(symmEnc, ciphertext, cryptoUtil.secureKeyGen(hmacPasswd, 32, fileSyntaxHMACSalt), 'Server');

    return encryptedData;
}
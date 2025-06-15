// These contain wrapper functions for the crypto "server" to encrypt and decrypt incoming packages.
// Note: Packets should already come in encrypted. All this does it provide a second layer of encryption

import { KeyObject } from 'crypto';
import * as cryptoUtil from '../Common/crypto_util.js';

export { symmEnc, symmDec, sign}

/**
 * Acts like a HSM and symmetrically encrypts something.
 * @param {Buffer} body The body to encrypt symmetrically. This *usually* would be a file syntax
 * @param {String} encPasswd The password to encrypt the data with.
 * @param {String} hmacPasswd The password used to generate the HMAC. This *could* be the same as encPasswd, but we control this so I'm going to say no. This has to be a seperate password.
 * @returns {Buffer} A cryptosystem with the ciphertext inside (encoded as binary). You might want to free() this.
 * @throws {Error} If encryption fails
 */
const symmEnc = (body, encPasswd, hmacPasswd) => {
    
    // Force chacha20-poly1305 because this is our backend now :)
    let symmEnc;
    try
    {   
        // Returns {{ciphertext: Buffer, encIV: String, encSalt: String, encAuthTag: String, hmac: String, hmacSalt: String}}
        symmEnc = cryptoUtil.symmetricEncrypt(encPasswd, hmacPasswd, body, 'chacha20-poly1305', 12);
    }
    catch(err)
    {
        throw err;
    }

    // Zero out the body
    cryptoUtil.zeroBuffer(body);

    return cryptoUtil.objectToBin(symmEnc);
}

/**
 * Acts like a HSM and symmetrically decrypts something.
 * @param {Buffer} cryptosystem The encrypted cryptosystem, with the encrypted data. This should be encoded as binary.
 * @param {String} decPasswd The password to decrypt the data with. This is the same as `encPasswd`.
 * @param {String} hmacPasswd The password used to verify the HMAC.
 * @returns {Buffer} The decrypted data (hopefully, still encrypted). You might want to free() this.
 * @throws {Error} If decryption fails, or if the HMAC verification fails.
 */
const symmDec = (cryptosystem, decPasswd, hmacPasswd) => {

    let symmDec;

    try
    {
        let cryptosystemJSON = cryptoUtil.binToObject(cryptosystem);

        // We've forced chacha20-poly1305 when encrypting
        symmDec = cryptoUtil.symmetricDecrypt(decPasswd, hmacPasswd, cryptosystemJSON.ciphertext, 'chacha20-poly1305', cryptosystemJSON);
    }
    catch(err)
    {
        throw err;
    }

    // Zero out the cryptosystem
    cryptoUtil.zeroBuffer(cryptosystem);

    return symmDec;
}

/**
 * Sign an object
 * @param {Buffer} body The buffer/binary to sign.
 * @param {KeyObject} signKeyObj Node.js object used to digitally sign something
 * @throws If something happens when signing
 * @returns {String} Digital signature (in hex)
 */
const sign = (body, signKeyObj) => cryptoUtil.secureSign('sha3-512', body, signKeyObj);
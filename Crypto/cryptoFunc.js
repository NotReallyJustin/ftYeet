// These contain wrapper functions for the crypto "server" to encrypt and decrypt incoming packages.
// Note: Packets should already come in encrypted. All this does it provide a second layer of encryption

import { KeyObject, constants, publicEncrypt, privateDecrypt } from 'crypto';
import * as cryptoUtil from '../Common/crypto_util.js';

export { symmEnc, symmDec, sign, verify, asymmDec, asymmEnc }

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
 * Signs an object. We're going to force PKCS1_PSS_PADDING for security.
 * @param {Buffer} body The buffer/binary to sign.
 * @param {KeyObject} signKeyObj Node.js object used to digitally sign something. The password should already be baked into this KeyObject since we created this in CryptoFunc.
 * @throws If something happens when signing
 * @returns {String} Digital signature (in hex)
 */
const sign = (body, signKeyObj) => cryptoUtil.secureSign('sha3-512', body, {key: signKeyObj, padding: constants.RSA_PKCS1_PSS_PADDING});

/**
 * Verifies a signature signed by the cryptoserver (and only the cryptoserver - this thing gets constrained). This may be exported and used by the CLI server.
 * @param {Buffer} body The buffer/binary to verify.
 * @param {KeyObject} verifyKeyObj Node.js object used to verify the digital signature. No password is necessary since this should be a KeyObject.
 * @param {String} signature Hexadecimal string representing the digital signature to verify.
 * @throws If something happens when verifying
 * @returns {Boolean} Whether or not the digital signature is valid
 */
const verify = (body, verifyKeyObj, signature) => cryptoUtil.secureVerify('sha3-512', body, {key: verifyKeyObj, padding: constants.RSA_PKCS1_PSS_PADDING}, signature);

/**
 * Encrypts a binary with a public key. The oaepHash is forcibly set to oaepHash: 'sha3-512', and the padding is set to constants.RSA_PKCS1_OAEP_PADDING
 * @param {Buffer} body The buffer/binary to encrypt. If this is important, it is on you to zero this out.
 * @param {KeyObject} encKeyObj The public key to encrypt the data with. This should be a KeyObject.
 * @throws If something happens when encrypting
 * @returns {Buffer} Encrypted data. 
 */
const asymmEnc = (body, encKeyObj) => publicEncrypt({key: encKeyObj, oaepHash: 'sha3-512', padding: constants.RSA_PKCS1_OAEP_PADDING}, body);

/**
 * Decrypts a binary with the public key. The oaepHash is forcibly set to oaepHash: 'sha3-512', 
 * and the padding is set to constants.RSA_PKCS1_OAEP_PADDING since this is the complement of asymmEnc.
 * @param {Buffer} body The buffer/binary to decrypt.
 * @param {KeyObject} decKeyObj The private key to decrypt the data with. This should be a KeyObject.
 * @throws If something happens when decrypting
 * @returns {Buffer} Decrypted data. If this is important, it is on you to zero this out.
 */
const asymmDec = (body, decKeyObj) => privateDecrypt({key: decKeyObj, oaepHash: 'sha3-512', padding: constants.RSA_PKCS1_OAEP_PADDING}, body);
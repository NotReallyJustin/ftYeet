/*
    This file handles connections to the Crypto Server (AKA HSM).
    In a way, this acts like RPCs. It's a lot of abstraction, but it makes my life much easier down the line.
*/

import fetch from 'node-fetch';
import { Agent } from 'https';
import { binToObject, objectToBin, genPubKeyObject, zeroBuffer } from '../Common/crypto_util.js';
import { verify } from '../Crypto/cryptoFunc.js';
import { readFileSync } from 'fs';
export { hsmDecrypt, hsmEncrypt, hsmSign, hsmVerify }

// --------- HSM Crypto files ---------
// These crypto keys correspond to the private keys held by the HSM

/**
 * (Ideally) ED-25519 public key used to verify digital signatures
 * @type {Buffer}
 */
let cryptoPubkeySign = readFileSync("/run/secrets/crypto_pubkey_sign");

/**
 * ⭐ Key object for the public (hopefully ED-25519) key.
 * THIS IS DECRYPTED! YOU CAN VERIFY STUFF WITH THIS!!!
 * @type {KeyObject}
 */
let verifyKeyObj = genPubKeyObject(cryptoPubkeySign, "binary");

// "Garbage collect" - well - as much as the mark-and-sweep algorithm will let us
zeroBuffer(cryptoPubkeySign);

// ---------------- HSM Specific vars ----------

/**
 * URL of the crypto server (HSM).
 */
const HSM_URL = `https://${process.env.HSMHOST}:${process.env.HSMPORT}`;

/**
 * Temporary SSL agent until we get a proper SSL cert for ftYeet.
 * Bypasses the Self-Signed Cert warnings.
 */
const IGNORE_SSL_AGENT = new Agent({
    rejectUnauthorized: false
});

// ----------- Start ----------------

/**
 * Makes a GET request to the HSM tunnel. This function is not intended to be called outside of hsm.js since it can get a bit fucky.
 * The data type of this is going to be a buffer. If you need to send a string, convert that.
 * @param {String} urlPath What you want the HSM to do. For example, "/symmEnc" or "/asymmEnc".
 * @param {Buffer} body Body for the GET request. This is usually the thing you want to encrypt, decrypt, sign, etc.
 * @throws {{code:Number, reason:String}} If request fails, returns the code and the reason the thing failed
 * @returns {Buffer} The response body.
 */
async function callHSM(urlPath, body)
{
    try
    {
        const response = await fetch(`${HSM_URL}${urlPath}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/octet-stream',
                follow: 1,
            },
            agent: IGNORE_SSL_AGENT, // Ignore self-signed certs
            body: body
        });

        if (response.ok)
        {
            const resp = Buffer.from(await response.arrayBuffer());
            return resp;
        }
        else
        {
            const error = await response.text();
            throw {code: response.status, reason: error};
        }
    }
    catch(err)
    {
        throw {code: 500, reason: `Fetch request failed: ${err.reason || err}`};
    }
    
}

/**
 * Asks the HSM to encrypt a plaintext.
 * @param {Buffer} plaintext The thing to encrypt. Hopefully, this is already encrypted clientside because E2EE. This must be an octet stream.
 * @throws If we failed to encrypt
 * @returns {{ciphertext: Buffer, encIV: String, encSalt: String, encAuthTag: String, hmac: String, hmacSalt: String}} The encrypted cryptosystem
 */
async function hsmEncrypt(plaintext)
{
    try
    {
        let binaryResp = await callHSM("/symmEnc", plaintext);

        const cryptosystem = binToObject(binaryResp);
        cryptosystem.ciphertext = Buffer.from(cryptosystem.ciphertext); // Bug with JSON.parse()
        return cryptosystem;
    }
    catch(err)
    {
        throw `Error when re-encrypting serverside: ${err.reason || err}`;
    }
}

/**
 * Asks the HSM to decrypt a ciphertext.
 * @param {{ciphertext: Buffer, encIV: String, encSalt: String, encAuthTag: String, hmac: String, hmacSalt: String}} Cryptosystem The encrypted cryptosystem
 * @throws If we failed to decrypt
 * @returns {Buffer} The plaintext. Hopefully this is still encrypted due to E2EE. If this is sensitive, you are responsible for zeroing this out. 
 */
async function hsmDecrypt(cryptosystem)
{
    try
    {
        let cryptosystemBin = objectToBin(cryptosystem)
        const plaintext = await callHSM("/symmDec", cryptosystemBin);
        
        return plaintext;
    }
    catch(err)
    {
        throw `Error when decrypting once serverside: ${err.reason || err}`;
    }
}

/**
 * Asks the HSM to sign a piece of data.
 * @param {Buffer} data The data to sign. This should be a buffer.
 * @throws If we failed to sign
 * @returns {String} The digital signature (in hex)
 */
async function hsmSign(data)
{
    try
    {
        data = Buffer.isBuffer(data) ? data : Buffer.from(data);
        const signature = await callHSM("/sign", data);

        return signature.toString();
    }
    catch(err)
    {
        throw `Error when signing serverside: ${err.reason || err}`;
    }
}

/**
 * Verifies something signed by the HSM
 * @param {Buffer} body Text to verify
 * @param {String} signature Signature to verify (in hex)
 * @throws Error if verification process goes wrong
 * @returns {Boolean} Whether or not the signature is valid
 */
function hsmVerify(body, signature)
{
    try
    {
        return verify(body, verifyKeyObj, signature);
    }
    catch(err)
    {
        throw `Error when verifying HSM Signature: ${err.reason || err}`;
    }
}
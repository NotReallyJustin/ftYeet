/*
    This file handles connections to the Crypto Server (AKA HSM).
    In a way, this acts like RPCs. It's a lot of abstraction, but it makes my life much easier down the line.
*/

import fetch from 'node-fetch';
export { hsmDecrypt, hsmEncrypt }

/**
 * URL of the crypto server (HSM).
 */
const HSM_URL = `https://${process.env.HSMHOST}:${process.env.HSMPORT}`;

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
    const response = await fetch(`${HSM_URL}${urlPath}`, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/octet-stream',
            follow: 1,
            agent: IGNORE_SSL_AGENT
        },
        body: body
    });

    if (response.ok)
    {
        const resp = await response.arrayBuffer();
        return resp;
    }
    else
    {
        const error = await response.text();
        throw {code: response.status, reason: error};
    }
}

/**
 * Asks the HSM to encrypt a plaintext.
 * @param {Buffer} plaintext The thing to encrypt. Hopefully, this is already encrypted clientside because E2EE. This must be an octet stream.
 * @throws If we failed to encrypt
 * @returns {Buffer} The ciphertext
 */
async function hsmEncrypt(plaintext)
{
    try
    {
        const ciphertext = await callHSM("/symmEnc", plaintext);
        return ciphertext;
    }
    catch(err)
    {
        throw `Error ${err.code} when re-encrypting serverside: ${err.reason}`;
    }
}

/**
 * Asks the HSM to decrypt a ciphertext.
 * @param {Buffer} ciphertext The thing to decrypt.
 * @throws If we failed to decrypt
 * @returns {Buffer} The plaintext. Hopefully this is still encrypted due to E2EE. If this is sensitive, you are responsible for zeroing this out. 
 */
async function hsmDecrypt(ciphertext)
{
    try
    {
        const plaintext = await callHSM("/symmDec", ciphertext);
        return plaintext;
    }
    catch(err)
    {
        throw `Error ${err.code} when decrypting once serverside: ${err.reason}`;
    }
}
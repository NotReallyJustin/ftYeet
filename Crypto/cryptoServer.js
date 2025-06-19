/*
    Crypto Server. This will serve as a HKM since those are lowkey kind of expensive for a self hosted thing
    ** THIS SHOULD BE ISOLATED FROM THE MAIN FTYEET SERVER. We do this here via using a different Docker Container **
    IPC is done by tunneling the "protocol" under HTTPS.
*/

import express from 'express';
import { createServer } from 'https';
import { readFileSync } from 'fs';

import { symmEnc, symmDec, sign, asymmDec } from './cryptoFunc';
import { zeroBuffer, genPrivKeyObject, genPubKeyObject } from '../Common/crypto_util';
import { KeyObject } from 'crypto';

const ipc = express();
const __dirname = import.meta.dirname;

// ---------------- Load in secrets + server ---------------------------------------------
const httpsServer = createServer({
    key: readFileSync("/run/secrets/crypto_cert_privkey", {encoding: "utf-8"}),
    cert: readFileSync("/run/secrets/crypto_cert", {encoding: "utf-8"}),
    passphrase: readFileSync("/run/secrets/crypto_cert_key_password", {encoding: "utf-8"})
}, ipc);

// 🔑 Symmetric key stuff 

/**
 * Key for symmetric encryption.
 * @type {String}
 */
const symmEncPwd = readFileSync("/run/secrets/crypto_symm_password", {encoding: "utf-8"});

/**
 * HMAC Key we're going to use for symmetric encryption
 * @type {String}
 */
const symmHmacPwd = readFileSync("/run/secrets/crypto_hmac_password", {encoding: "utf-8"});

// 🔑 Signature key

/**
 * (Ideally) ED-25519 public key used for digital signatures
 * @type {Buffer}
 */
let cryptoPubkeySign = readFileSync("/run/secrets/crypto_pubkey_sign");

/**
 * (Ideally) ED-25519 private key used for digital signatures
 * @type {Buffer}
 */
let cryptoPrivkeySign = readFileSync("/run/secrets/crypto_privkey_sign");

/**
 * Password to decrypt the private key used for digital signatures.
 * @type {String}
 */
let cryptoPrivSignPwd = readFileSync("/run/secrets/crypto_sign_key_password", {encoding: "utf-8"});

/**
 * ⭐ Key object for the private (hopefully ED-25519) key.
 * THIS IS DECRYPTED! YOU CAN SIGN STUFF WITH THIS!!!
 * @type {KeyObject}
 */
let signKeyObj = genPrivKeyObject(cryptoPrivkeySign, cryptoPrivSignPwd, true);

zeroBuffer(cryptoPubkeySign);   // "Garbage collect" - well - as much as the mark-and-sweep algorithm will let us
zeroBuffer(cryptoPrivkeySign);

// 🔑 Asymmetric encryption keys

/**
 * Crypto public key used for asymmetric encryption.
 * @type {Buffer}
 */
let cryptoPubkey = readFileSync("/run/secrets/crypto_pubkey");

/**
 * Crypto private key used for asymmetric encryption.
 * @type {Buffer}
 */
let cryptoPrivkey = readFileSync("/run/secrets/crypto_privkey");

/**
 * Password to decrypt the private key used for asymmetric encryption.
 * @type {String}
 */
let cryptoPrivPwd = readFileSync("/run/secrets/crypto_enc_key_password", {encoding: "utf-8"});

/**
 * ⭐ Key object for the private key used to encrypt data.
 * THIS IS DECRYPTED! YOU CAN DECRYPT STUFF WITH THIS!!!
 * @type {KeyObject}
 */
const asymmPrivKeyObj = genPrivKeyObject(cryptoPrivkey, cryptoPrivPwd, true);

zeroBuffer(cryptoPubkey);   // "Garbage collect"
zeroBuffer(cryptoPrivkey);

// --------------- Pre-processing. CryptoServer really only accepts binary --------------

/**
 * Middleware that checks the content type of incoming requests.
 * If the content-type doesn't match, send back a 404 error.
 * @param {String} contentType The content type we want. THIS IS CASE SENSITIVE!!!
 */
const checkContentType = (contentType) => (request, response, next) => {
    if (request.headers['content-type'] != contentType)
    {
        return response.status(400).send(`Error: Wrong content-type. Expected ${contentType} but received ${request.headers['content-type']}.`);
    }

    next();
}

ipc.use("/upload", checkContentType('application/octet-stream'));

// --------------- Start actual HSM Stuff -------------------------------------------------

ipc.get("/", (request, response) => {
    response.status(404).send("Try again bozo. Use either /symmEnc, /symmDec, /sign, or /asymmEnc.");
});

// I don't know if we'll end up actually using symmEnc and symmDec in the end because I feel like we could just 
// do everything asymmetrically - but we'll see.

// request.body should contain a buffer representing the data to encrypt
ipc.get("/symmEnc", (request, response) => {
    
    try
    {
        let encrypted = symmEnc(request.body, symmEncPwd, symmHmacPwd);

        response.setHeader('Content-Type', 'application/octet-stream');
        response.send(encrypted);

        // Zero out the encrypted data since the "client" has a copy now
        zeroBuffer(encrypted);
    }
    catch(err)
    {
        response.status(500).send(err);
    }
});

// request.body should contain a buffer representing the encrypted cryptosystem
ipc.get("/symmDec", (request, response) => {

    try
    {
        let decrypted = symmDec(request.body, symmEncPwd, symmHmacPwd);

        response.setHeader('Content-Type', 'application/octet-stream');
        response.send(decrypted);

        // Zero out the decrypted data since the "client" has a copy now
        zeroBuffer(decrypted);
    }
    catch(err)
    {
        response.status(500).send(err);
    }

});

// request.body should contain a buffer representing the thing to sign
ipc.get("/sign", (request, response) => {

    try
    {
        let signature = sign(request.body, signKeyObj);

        response.setHeader('Content-Type', 'text/plain');       // Remember signature is a hex string
        response.send(signature);
    }
    catch(err)
    {
        response.status(500).send(err);
    }
});

// asymmEnc is not implemented here, since the external servers will have access to the public key.
// Since they have access to the public key, it makes no sense to have the HSM perform the operation and slow down ftYeet via the IPC.
ipc.get("/asymmDec", (request, response) => {
    
    try
    {
        let decrypted = asymmDec(request.body, asymmPrivKeyObj);

        response.setHeader('Content-Type', 'application/octet-stream');
        response.send(decrypted);

        // Zero out the decrypted data since the "client" has a copy now
        zeroBuffer(decrypted);
    }
    catch(err)
    {
        response.status(500).send(err);
    }
});

// ---------------- Router Dead End ------------------------------------
apiRouter.all("*", (request, response) => {
    response.status(404).send("Not found.");
});

// Listen only for HTTPS.
// Since this thing is not going to be public facing, we don't need to support redirection
httpsServer.listen(PORT, () => {
    console.log(`✅ Server launched on port ${PORT}.`);
});
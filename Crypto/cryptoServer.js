/*
    Crypto Server. This will serve as a HKM since those are lowkey kind of expensive for a self hosted thing
    ** THIS SHOULD BE ISOLATED FROM THE MAIN FTYEET SERVER. We do this here via using a different Docker Container **
    IPC is done by tunneling the "protocol" under HTTPS.
*/

import express, { response } from 'express';
import * as path from 'path';
import { createServer } from 'https';
import { readFileSync } from 'fs';

const ipc = express();
const __dirname = import.meta.dirname;

// Load in secrets + server
const symmKeyPwd = readFileSync("/run/secrets/crypto_enc_key_password", {encoding: "utf-8"});

const httpsServer = createServer({
    key: readFileSync("/run/secrets/crypto_cert_privkey", {encoding: "utf-8"}),
    cert: readFileSync("/run/secrets/crypto_cert", {encoding: "utf-8"}),
    passphrase: readFileSync("/run/secrets/crypto_key_password", {encoding: "utf-8"})
}, ipc);


ipc.get("/", (request, response) => {
    response.status(404).send("Try again bozo. Use either symmEnc, symmDec, sign, asymmEnc.");
});

// I don't know if we'll end up actually using symmEnc and symmDec in the end because I feel like we could just 
// do everything asymmetrically - but we'll see.
ipc.get("/symmEnc", (request, response) => {

});

ipc.get("/symmDec", (request, response) => {

});

ipc.get("/sign", (request, response) => {

});

// TODO: Maybe this should be asymmDec ngl o.o
ipc.get("/asymmEnc", (request, response) => {

});

apiRouter.all("*", (request, response) => {
    response.status(404).send("Not found.");
});

// Listen only for HTTPS.
// Since this thing is not going to be public facing, we don't need to support redirection
httpsServer.listen(PORT, () => {
    console.log(`✅ Server launched on port ${PORT}.`);
});
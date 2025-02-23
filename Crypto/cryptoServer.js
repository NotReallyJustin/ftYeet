/*
    Crypto Server. This will serve as a HKM since those are lowkey kind of expensive for a self hosted thing
    ** THIS SHOULD BE ISOLATED FROM THE MAIN FTYEET SERVER. We do this here via using a different Docker Container **
    IPC is done by tunneling the "protocol" under HTTPS.
*/

import express from 'express';
import * as path from 'path';
import { createServer } from 'https';
import { readFileSync } from 'fs';

const ipc = express();
const __dirname = import.meta.dirname;

const httpsServer = createServer({
    key: readFileSync("/run/secrets/crypto_cert_privkey", {encoding: "utf-8"}),
    cert: readFileSync("/run/secrets/crypto_cert", {encoding: "utf-8"}),
    passphrase: readFileSync("/run/secrets/crypto_key_password", {encoding: "utf-8"})
}, ipc);

ipc.get("/", (request, response) => {

});

// Listen only for HTTPS.
// Since this thing is not going to be public facing, we don't need to support redirection
httpsServer.listen(PORT, () => {
    console.log(`✅ Server launched on port ${PORT}.`);
});
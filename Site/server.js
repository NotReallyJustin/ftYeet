/*
    Main Server handler for ftYeet
*/

import express from 'express';
import subdomain from 'express-subdomain'
import * as path from 'path';
import { createServer } from 'https';
import { readFileSync } from 'fs';

import webRouter from './webServer.js';
import apiRouter from './cliServer.js';

const mainServer = express();
const __dirname = import.meta.dirname;

// Configs and vars
const MAX_FILE_SIZE = "10MB";
const PORT = 443;

// In case of reverse proxies down the line
// This just trusts the proxy to convert x-forwarded-for and other headers into genuine IP addresses we'll be using
mainServer.set('trust proxy', true);

// Enable HTTPS and force users to use TLS/SSL
const httpsServer = createServer({
    key: readFileSync(path.resolve(__dirname, "./Keys/privKey.pem"), {encoding: "utf-8"}),
    cert: readFileSync(path.resolve(__dirname, "./Keys/cert.pem"), {encoding: "utf-8"}),
    passphrase: process.env.PRIVKEY_PWD                 // ⭐ Make sure to create a `.env` file with the private key password. Make it "Josh Allen" or smth idk 🤷‍♂️
}, mainServer);

mainServer.use((request, response, next) => {
    if (request.protocol == "https")
    {
        next();
    }
    else
    {
        response.redirect(`https://${request.get("host")}${request.originalUrl}`);
    }
});

// Log incoming requests
mainServer.use("*", (request, response, next) => {
    console.log("--------------------------------------------------------------------");
    console.log(`Connection established with ${request.ip} on port ${request.socket.localPort} via remote port ${request.socket.remotePort}.`);
    console.log(`Request Type: ${request.method}`);
    console.log(`Request Host: ${request.hostname}`);
    console.log(`Request Path: ${request.originalUrl}`)
    console.log("--------------------------------------------------------------------");
    console.log("");

    next();
});

// 404 invalid subdomains
// This is a whitelist
mainServer.use((request, response, next) => {
    let subdomains = request.hostname.split(".");

    if (subdomains.length > 2)
    {
        if (subdomains[0] != 'api')
        {
            return response.status(404).send(`Not found.`);
        }
    }
    
    // Else if there's no subdomains
    next();
});

// Route the request to the CLI server or the web server depending on the subdomain.
mainServer.use(subdomain('*.api', apiRouter));
mainServer.use(webRouter);

// Middleware to handle errors
mainServer.use((err, request, response, next) => {

    // Errors we explicitly threw:
    if (err.status === 413)
    {
        response.status(413).send(`Request body is too large. The maximum allowed size is ${MAX_FILE_SIZE}.`);
    
    }
    else
    {
        console.log(`Error when handling main server routing: ${err}`);
        response.status(500).send("Oops - we ran into an internal server error.");
    }
});

// Things shouldn't make it this far. If they do, it doesn't exist.
mainServer.all("*", (request, response) => {
    response.status(404).send("Not Found.");
});

// Listen for HTTP *and* HTTPS
// To consider when we ship this to AWS or smth: listen on a specific adapter
httpsServer.listen(PORT, () => {
    console.log(`✅ Server launched on port ${PORT}.`);
});

mainServer.listen(80, () => {
    console.log(`✅ HTTP Server launched on port 80. This is only going to be used for redirection.`);
});
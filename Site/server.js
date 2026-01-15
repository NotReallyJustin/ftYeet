/*
    Main Server handler for ftYeet

    This script is intended to seperate all the unnecessary configs like ports and connection handling from main routing logic.
    It also spawns the certain background processes like the deletion service on startup.

    This server uses express routing, so you could easily build on what we have here by creating more routers and subdomains.
    Maybe someday you could make a website for this
*/

import express from 'express';
import subdomain from 'express-subdomain'
import { log } from '../Common/logging.js';
import { createServer } from 'https';
import { readFileSync } from 'fs';
import { spawn } from 'child_process';

import apiRouter from './cliServer.js';

const mainServer = express();
const __dirname = import.meta.dirname;

// Configs and vars
const MAX_FILE_SIZE = process.env.MAX_FILE_SIZE;  // SECURITY NOTE: This is set at startup. Regardless of how process.env.MAX_FILE_SIZE changes later, this variable will not.
const NON_PRIV_HTTP_PORT = 3000;        // Don't give this app root perms to listen on port 80/443. Have docker forward it. This port number doesn't actually affect anything
const NON_PRIV_HTTPS_PORT = 3001;   

// In case of reverse proxies down the line
// This just trusts the proxy to convert x-forwarded-for and other headers into genuine IP addresses we'll be using
mainServer.set('trust proxy', true);

// Enable HTTPS and force users to use TLS/SSL
// ⭐ Make sure to drop the cert, private key, and password in `./Secrets/`. Make the password Josh Allen or smth
const httpsServer = createServer({
    key: readFileSync("/run/secrets/server_privkey", {encoding: "utf-8"}),
    cert: readFileSync("/run/secrets/cert", {encoding: "utf-8"}),
    passphrase: readFileSync("/run/secrets/server_privkey_pwd", {encoding: "utf-8"})
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
    let str = "--------------------------------------------------------------------\n";
    str += `Connection established with ${request.ip} on port ${request.socket.localPort} via remote port ${request.socket.remotePort}.\n`;
    str += `Request Type: ${request.method}\n`;
    str += `Request Path: ${request.originalUrl}\n`;

    // IF WE WANT TO DEBUG, UNCOMMENT THIS
    // str += "DEBUG - Request Headers:\n";
    // str += JSON.stringify(request.headers, null, 4) + "\n";
    // str += "--------------------------------------------------------------------\n";

    log(str, process.env.LOG_BACK == 'true');

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
// TODO: reconsider the *
mainServer.use(subdomain('*.api', apiRouter));

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
httpsServer.listen(NON_PRIV_HTTPS_PORT, () => {
    console.log(`✅ Server launched on port ${NON_PRIV_HTTPS_PORT}.`);
});

mainServer.listen(NON_PRIV_HTTP_PORT, () => {
    console.log(`✅ HTTP Server launched on port ${NON_PRIV_HTTP_PORT}. This is only going to be used for redirection.`);
});

// ♻️ Spawn deletion service
spawn("node", ["./deletionServ.js"], {stdio: 'inherit'});
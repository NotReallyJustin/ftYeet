/*
    CLI server for FtYeet. This is "hidden" behind the API subdomain. However, realistically, you should be interacting with this via the CLI instead of making HTTPS calls 
    to this "API".

    Connect to this via the command-line
*/

import * as express from 'express';
import { isValidPubKey } from '../Common/crypto_util.js';

const apiRouter = express.Router({
    mergeParams: true               // Keep req.params from parent router
});

// ⚠️ Check `/planning.md` for answers about the weird design choices here
// TLDR: this "API" is only here to tunnel the ftYeet protocol under HTTPS. People should be interacting with this via the CLI.
apiRouter.post("/upload", (request, response) => {
    
    // Variables because I have a feeling that headers are going to be strings
    let expireTime;
    let burnOnRead;
    
    // Check headers
    if (request.headers['file-name'] == undefined)
    {
        return response.status(400).send("Error when uploading: You must provide a file-name.");
    }

    if (request.headers['expire-time'] == undefined)
    {
        return response.status(400).send("Error when uploading: You must provide an expire-time for the file.");
    }
    else
    {
        if (isNaN(request.headers['expire-time']))
        {
            return response.status(400).send("Error when uploading: expire-time must be a number (in seconds).");
        }
        else
        {
            expireTime = parseInt(request.headers['expire-time']);
        }
    }

    if (request.headers['burn-on-read'] == undefined)
    {
        return response.status(400).send("Error when uploading: You must denote whether or not this file is burn-on-read.");
    }
    else
    {
        if (request.headers['burn-on-read'] == 'true' || request.headers['burn-on-read'] == 'false')
        {
            burnOnRead = request.headers['burn-on-read'] == 'true';
        }
        else
        {
            return response.status(400).send("Error when uploading: burn-on-read must be a boolean value.");
        }
    }

    if (request.headers['pwd-hash'] == undefined)
    {
        return response.status(400).send("Error when uploading: You must provide a pwd-hash (password hash). This should be done for you via the CLI.");
    }

    response.send("This is the CLI Server. You are uploading.");
});

apiRouter.post("/uploadAsymm", (request, response) => {

    let expireTime;
    let burnOnRead;
    
    // Check headers
    if (request.headers['file-name'] == undefined)
    {
        return response.status(400).send("Error when uploading: You must provide a file-name.");
    }

    if (request.headers['expire-time'] == undefined)
    {
        return response.status(400).send("Error when uploading: You must provide an expire-time for the file.");
    }
    else
    {
        if (isNaN(request.headers['expire-time']))
        {
            return response.status(400).send("Error when uploading: expire-time must be a number (in seconds).");
        }
        else
        {
            expireTime = parseInt(request.headers['expire-time']);
        }
    }

    if (request.headers['burn-on-read'] == undefined)
    {
        return response.status(400).send("Error when uploading: You must denote whether or not this file is burn-on-read.");
    }
    else
    {
        if (request.headers['burn-on-read'] == 'true' || request.headers['burn-on-read'] == 'false')
        {
            burnOnRead = request.headers['burn-on-read'] == 'true';
        }
        else
        {
            return response.status(400).send("Error when uploading: burn-on-read must be a boolean value.");
        }
    }

    if (request.headers['public-key'] == undefined)
    {
        return response.status(400).send("Error when uploading: You must provide a public-key. This should be done for you via the CLI.");
    }
    else if (!isValidPubKey(request.headers['public-key']))
    {
        return response.status(400).send("Error when uploading: The public-key you provided is invalid. It's probably not a public key.");
    }
    
    response.send("This is the CLI Server. You are uploading asymm.");
});

apiRouter.get("/downloadAsymm", (request, response) => {
    response.send("This is the CLI Server. You are downloading asymm.");
});

apiRouter.get("/download", (request, response) => {
    response.send("This is the CLI Server. You are downloading symm.");
});


apiRouter.all("*", (request, response) => {
    response.status(404).send("Not found.");
});

export default apiRouter;
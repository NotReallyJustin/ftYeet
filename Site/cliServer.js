/*
    CLI server for FtYeet. This is "hidden" behind the API subdomain. However, realistically, you should be interacting with this via the CLI instead of making HTTPS calls 
    to this "API".

    Connect to this via the command-line
*/

import * as express from 'express';
import { pubKeyType, base64ToPubKey } from '../Common/crypto_util.js';
import * as cliFunctions from './cliFunctions.js';

// ⚒️ Helper functions and constants
const MAX_FILE_SIZE = '2mb';

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

const apiRouter = express.Router({
    mergeParams: true               // Keep req.params from parent router
});

// ⚠️ Check `/planning.md` for answers about the weird design choices here
// TLDR: this "API" is only here to tunnel the ftYeet protocol under HTTPS. People should be interacting with this via the CLI.

apiRouter.use("/upload", checkContentType('application/octet-stream'));
apiRouter.use("/upload", express.raw({limit: MAX_FILE_SIZE, type: 'application/octet-stream'}));

apiRouter.get("/request", (request, response) => {
    cliFunctions.genURL()
        .then(word => {
            return response.send(word);
        }).catch(err => {
            console.error(err);
            return response.status(400).send("Error: Unable to request a word for the URL.");
        })
});

apiRouter.post("/upload", (request, response) => {
    
    // Variables because I have a feeling that headers are going to be strings
    let expireTime;
    let burnOnRead;
    
    // Check headers
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

            if (expireTime < 60)
            {
                return response.status(400).send("Error when uploading: expire-time must be greater than or equal to 60 seconds.");
            }
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

    if (request.headers['url'] == undefined || !cliFunctions.checkURL(request.headers['url']) 
        || request.headers['url'].length < 4 || request.headers['url'].length > 10)
    {
        return response.status(400).send("Error when uploading: You must provide a valid URL. Make sure you're using the CLI and not tampering with stuff on your own.")
    }

    cliFunctions.uploadSymm(request.body, expireTime, burnOnRead, request.headers['pwd-hash'], request.headers['url'])
        .then(() => {
            response.send(request.headers['url']);
        }).catch(err => {
            response.status(404).send(`Error when uploading: ${err}.`);
        })
});

apiRouter.use("/uploadAsymm", checkContentType('application/octet-stream'));
apiRouter.use("/uploadAsymm", express.raw({limit: MAX_FILE_SIZE, type: 'application/octet-stream'}));
apiRouter.post("/uploadAsymm", (request, response) => {

    let expireTime;
    let burnOnRead;
    
    // Check headers
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

            if (expireTime < 60)
            {
                return response.status(400).send("Error when uploading: expire-time must be greater than or equal to 60 seconds.");
            }
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
    else if (pubKeyType(request.headers['public-key'], true) == 'none') // pubkey still in b64 btw
    {
        return response.status(400).send("Error when uploading: The public-key you provided is invalid. It's probably not a public key.");
    }
    
    response.send("This is the CLI Server. You are uploading asymm.");
});

apiRouter.get("/downloadAsymm", (request, response) => {
    if (request.headers['jwt'] == undefined)
    {
        return response.status(400).send("Error when downloading: You must provide a valid JWT token signed with your private key. This should be done via the CLI.");
    }

    response.send("This is the CLI Server. You are downloading asymm.");
});

apiRouter.get("/download", (request, response) => {

    if (request.headers['url'] == undefined || !cliFunctions.checkURL(request.headers['url']) 
        || request.headers['url'].length < 4 || request.headers['url'].length > 10)
    {
        return response.status(400).send("Error when downloading: You must provide a valid URL. Make sure you're using the CLI and not tampering with stuff on your own.")
    }

    if (request.headers['pwd-hash'] == undefined)
    {
        return response.status(400).send("Error when uploading: You must provide a pwd-hash (password hash). This should be done for you via the CLI.");
    }

    cliFunctions.downloadSymm(request.headers['url'], request.headers['pwd-hash'])
        .then((fileSyntaxOutput) => {
            // res.setHeader('content-type', 'text/plain');
            response.send(fileSyntaxOutput);
        }).catch(err => {
            response.status(404).send(`Error when downloading: ${err}.`);
        });
});

// // Middleware to handle errors
// apiRouter.use((err, request, response, next) => {

//     // Errors we explicitly threw:
//     if (err.status === 413)
//     {
//         response.status(413).send(`Request body is too large. The maximum allowed size is ${MAX_FILE_SIZE}.`);
    
//     }
//     else
//     {
//         console.log(`Error when handling main server routing: ${err}`);
//         response.status(500).send("Oops - we ran into an internal server error.");
//     }
// });

apiRouter.all("*", (request, response) => {
    response.status(404).send("Not found.");
});

export default apiRouter;
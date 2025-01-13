/*
    CLI server for FtYeet. This is "hidden" behind the API subdomain. However, realistically, you should be interacting with this via the CLI instead of making HTTPS calls 
    to this "API".

    Connect to this via the command-line
*/

import * as express from 'express';

const apiRouter = express.Router({
    mergeParams: true               // Keep req.params from parent router
});

// ⚠️ Check `/planning.md` for answers about the weird design choices here
// TLDR: this "API" is only here to tunnel the ftYeet protocol under HTTPS. People should be interacting with this via the CLI.
apiRouter.post("/upload", (request, response) => {
    response.send("This is the CLI Server. You are uploading.");
});

apiRouter.post("/auth", (request, response) => {
    response.send("This is the CLI Server. You are authenticating.");
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
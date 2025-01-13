/*
    Web server for ftYeet.
    This is the one delivering all the frontend assets
*/

import * as express from 'express';

// TODO: Node.js express path traversal when serving static files?
// Maybe we can just whitelist everything ngl
const webRouter = express.Router({
    mergeParams: true               // Keep req.params from parent router
});

webRouter.get("*", (request, response) => {
    response.send("This is the web server");
});

export default webRouter;
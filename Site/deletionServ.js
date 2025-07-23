/*
    Deletion Service spawned by the main server.
    This will run in the background every 5 minutes to run a SQL query to delete expired uploads.
*/

import { countNumExpired, deleteExpired } from "./psql.js";
import { rm } from "fs";
import * as path from "path";

/**
 * How often we want to delete the expired uploads
 */
const DELETE_INTERVAL_MIN = 5;

/**
 * How often we want to count the # of the expired uploads
 */
const DISCOVER_INTERVAL_MIN = 1;

/**
 * Delete expired uploads.
 */
function pruneUploads()
{
    deleteExpired()
        .then((expiredFilePaths) => {
            console.log("[Delete Serv] Currently deleting expired uploads.");

            expiredFilePaths.forEach(filePath => {
                rm(path.resolve(process.env.FILE_DIR, filePath), (err) => {
                    if (err)
                    {
                        console.error(`[Delete Serv] Error when deleting expired file ${filePath}: ${err.message || err}`); 
                    }
                });
            });
        }).catch(err => {
            console.error(`[Delete Serv] Error when pruning uploads: ${err.message || err}`);
        });
}

/**
 * Finds number of expired downloads and download them
 */
function discoverUploads()
{
    countNumExpired()
        .then((numExpired) => {
            console.log(`[Delete Serv] There's currently ${numExpired} expired uploads.`);

        }).catch(err => {
            console.error(`[Delete Serv] Error when counting expired uploads: ${err.message || err}`);
        });
}

setInterval(pruneUploads, DELETE_INTERVAL_MIN * 60000);
setInterval(discoverUploads, DISCOVER_INTERVAL_MIN * 60000);
console.log("♻️ Deletion Service is up and ready to go!");
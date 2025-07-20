/*
    Deletion Service spawned by the main server.
    This will run in the background every 5 minutes to run a SQL query to delete expired uploads.
*/

import { countNumExpired, deleteExpired } from "./psql.js";

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
    
}

/**
 * Finds number of expired downloads and download them
 */
function discoverUploads()
{
    countNumExpired();
}

setInterval(pruneUploads, INTERVAL_MIN * 60000);
setInterval(discoverUploads, INTERVAL_MIN * 60000);
console.log("♻️ Deletion Service is up and ready to go!");
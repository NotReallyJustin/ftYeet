/*
    This file handles connections to the PostgreSQL server.
    This includes parameterized queries and handling clients/connections.
*/

import pg from 'pg';
import {readFileSync } from 'fs';
const { Pool } = pg;

import { hsmSign, hsmVerify } from './hsm.js';
import { verifyChallenge} from './cliFunctions.js';

export { runQuery, logSymmFile, logAsymmFile, getFile, getFileAsymm, updateChallenge, deleteFileSymm, deleteFileAsymm, countNumExpired, deleteExpired }

// ---------- Official psql --------------

/**
 * Available pool of clients. Generate a client from these to connect to and execute queries to our PSQL dockerfile
 * Remember to close these client connections if you do mess with this
 */
const clientPool = new Pool({
    host: process.env.PGHOST,
    user: process.env.PGUSER,
    database: process.env.PGDATABASE,
    idleTimeoutMillis: process.env.QUERYTIMEOUT,
    connectionTimeoutMillis: process.env.CONNECTIONTIMEOUT,
    port: process.env.PGPORT,
    password: readFileSync("/run/secrets/db_password", {encoding: "utf-8"})
});

/**
 * Runs a parameterized query.
 * 🚨 DO NOT USE STRING CONCATENATION, FORMAT STRINGS, OR LITERALLY ANYTHING THAT DIRECTLY APPENDS ANY USER INPUT INTO `queryText`.
 * If you're not sure what this means, DO NOT CALL THIS FUNCTION. There are wrapper functions you can call instead, and that's prolly safer. 🚨
 * @param {String} queryText The query itself. Use `$1`, `$2`, `...` to put add a parameter.
 * @param {Object[]} queryValues Arguments to fill into the parameterized query. Pass this in as an array. I highly doubt that you don't have **any** arguments, but if you don't, pass in an empty array.
 * @param {Boolean|Undefined} arrayRowMode Whether or not to return the query output/result as an array. This is `optional`.
 * @param {Boolean} noParams Failsafe for dummies. Set this to `true` if you're SURE your `queryText` has no query params.
 * @returns {Promise<Object>} The results from the query
 * @see https://node-postgres.com/features/queries
 * @throw Errors if you don't provide a queryText or queryValue. It will get REALLY mad at you if you don't provide a queryValue.
 */
async function runQuery(queryText, queryValues, arrayRowMode, noParams)
{
    if (queryText == undefined)
    {
        throw "Error when running query: `queryText` is undefined. It doesn't exist.";
    }

    if (queryValues == undefined || !Array.isArray(queryValues))
    {
        throw "Error when running query: `queryValues` is undefined. Pardon my language but..." + 
        "Holy **** what the **** are you doing? No only did you fail to pass any arguments into `queryValues`, " +
        "you straight up failed to provide an array for the `queryValues` parameter. " + 
        "This is opening you up to an SQL injection. Don't do that."
    }
    else if (queryValues.length == 0 && (!noParams))
    {
        console.log("Warning when running query: You didn't pass any arguments into `queryValues`. 🤨 I **highly** doubt that you don't have any arguments, so please check this.")
    }

    const client = await clientPool.connect();
    
    // Form query
    let query = {
        text: queryText,
        values: queryValues
    };
    
    if (arrayRowMode)
    {
        query.rowMode = "array";
    }

    try 
    {
        const response = await client.query(query)
        await client.release(true); // Destroy the client. We no longer need it.
        return response;
    } 
    catch (err) 
    {
        await client.release(true); // Destroy the client. We no longer need it.
        throw `Error when running query: ${err.message}`;
    }
}

/**
 * Logs a file encrypted symmetrically in the postgres database.
 * @param {String} pwdHash2 The hash of the password hash provided by the user.
 * @param {boolean} burnOnRead Whether this file should be burnt when we download it
 * @param {Date} expireTimestamp Timestamp when the file expires (and gets marked for deletion)
 * @param {String} url URL you can access the file from
 * @returns {Promise<string>} UUID of the logged file. This will be used as the file name.
 * @throws If any of the inputs are invalid
 */
async function logSymmFile(pwdHash2, burnOnRead, expireTimestamp, url)
{
    let hsmMerged = `${pwdHash2} ${burnOnRead} ${expireTimestamp} ${url}`;

    if (pwdHash2 == undefined || burnOnRead == undefined || expireTimestamp == undefined || url == undefined)
    {
        throw "Error when logging file in database: There's something in the input that is undefined.";
    }

    if (!(expireTimestamp instanceof Date))
    {
        throw "Error when logging file in database: `expireTimestamp` is not a date.";
    }

    // Generate checksum (read: digital signature) of everything here
    let checksum;
    try
    {
        checksum = await hsmSign(hsmMerged);
    }
    catch(err)
    {
        throw err.message || err;
    }

    // Upload to DB
    try
    {
        let respFilesDB = await runQuery(
            "INSERT INTO files(PwdHashHash, BurnOnRead, ExpireTime, Url, CheckSum) VALUES($1, $2, $3, $4, $5) RETURNING UUID",
            [pwdHash2, burnOnRead, expireTimestamp, url, checksum], false
        );

        return respFilesDB.rows[0].uuid;
    }
    catch(err)
    {
        throw err.message || err;
    }
}

/**
 * Logs an asymmetrically encrypted file in the postgres database.
 * @param {String} pubkeyB64 The public key, in base64.
 * @param {boolean} burnOnRead Whether this file should be burnt when we download it
 * @param {Date} expireTimestamp Timestamp when the file expires (and gets marked for deletion)
 * @param {String} url URL you can access the file from
 * @returns {Promise<string>} UUID of the logged file. This will be used as the file name.
 * @throws If any of the inputs are invalid
 */
async function logAsymmFile(pubkeyB64, burnOnRead, expireTimestamp, url)
{
    // We don't immediately create a challenge when the user does asymm file upload
    // We wait for auth()
    // We're going to put placeholders when we do the digitally sign the contents in the postgres table
    let challenge = "null";
    let challengeExpireTime = new Date(Date.now());

    let hsmMerged = `${pubkeyB64} ${burnOnRead} ${expireTimestamp} ${url} ${challenge} ${challengeExpireTime}`;

    if (pubkeyB64 == undefined || burnOnRead == undefined || expireTimestamp == undefined || url == undefined)
    {
        throw "Error when logging file in database: There's something in the input that is undefined.";
    }

    if (!(expireTimestamp instanceof Date))
    {
        throw "Error when logging file in database: `expireTimestamp` is not a date.";
    }

    if (!(challengeExpireTime instanceof Date))
    {
        throw "Error when logging file in database: `challengeExpireTime` is not a date.";
    }

    // Generate checksum (read: digital signature) of everything here
    let checksum;
    try
    {
        checksum = await hsmSign(hsmMerged);
    }
    catch(err)
    {
        throw err.message || err;
    }

    // Upload to DB
    try
    {
        let respFilesDB = await runQuery(
            "INSERT INTO filesAsymm(PubKeyB64, BurnOnRead, ExpireTime, Url, Challenge, ChallengeTime, CheckSum) VALUES($1, $2, $3, $4, $5, $6, $7) RETURNING UUID",
            [pubkeyB64, burnOnRead, expireTimestamp, url, challenge, challengeExpireTime, checksum], false
        );

        return respFilesDB.rows[0].uuid;
    }
    catch(err)
    {
        throw err.message || err;
    }
}

/**
 * Retrieves a file at the specified URL
 * @param {String} url URL where the file is stored
 * @returns {Promise<null | {uuid: String, pwdhashhash: String, burnonread: Boolean, expiretime: Date, url: String, checksum: String}>} A JSON representing all the data about the file requested in the URL. Or null if the URL is invalid.
 */
async function getFile(url)
{
    if (url == undefined)
    {
        throw "Error when getting file: `url` is undefined.";
    }

    let dbOutput;
    
    // Retrieve from DB
    try
    {
        dbOutput = await runQuery(
            "SELECT * FROM files WHERE url = $1",
            [url]
        );
    }
    catch(err)
    {
        throw err.message || err;
    }

    //dbOutput.rows has > 1 item. A proper output should only have 1 item
    if (dbOutput.rows.length != 1)
    {
        return null;
    }
    
    // There shouldn't be multiple things in the same URL
    // If there is, just return the first one
    let toReturn = dbOutput.rows[0];

    // Check the checksum
    let hsmMerged = `${toReturn.pwdhashhash} ${toReturn.burnonread} ${toReturn.expiretime} ${toReturn.url}`;
    
    try
    {
        if(!hsmVerify(hsmMerged, toReturn.checksum))
        {
            throw `Checksum/digital signature verification failed.`;
        }
    }
    catch(err)
    {
        throw `Error when getting file: ${err.message || err}.`;
    }

    return dbOutput.rows[0];
}

/**
 * Helper function to fetch the database entry for an asymmetric file download.
 * @param {String} url The URL to fetch
 * @throws If the URL is undefined, or the fileAsymm database entry has been tampered with
 * @returns {{uuid: String, pubkeyb64: String, burnonread: Boolean, expiretime: Date, url: String, challenge: Buffer, challengetime: Date, checksum: String}} A JSON representing all the data about the file requested in the URL.
 */
async function _fetchFileAsymm(url)
{
    if (url == undefined)
    {
        throw "Error when accessing data related to asymmetrically encrypted file: `url` is undefined.";
    }
    
    // Retrieve from DB
    let dbOutput;
    try
    {
        dbOutput = await runQuery(
            "SELECT * FROM filesAsymm WHERE url = $1",
            [url]
        );
    }
    catch(err)
    {
        throw err.message || err;
    }

    //dbOutput.rows has > 1 item. A proper output should only have 1 item
    if (dbOutput.rows.length != 1)
    {
        throw `Detected more than one download entry per URL. Aborting now.`;
    }

    // Similar to fetchFile normally
    let toReturn = dbOutput.rows[0];

    // Check the checksum
    let hsmMerged = `${toReturn.pubkeyb64} ${toReturn.burnonread} ${toReturn.expiretime} ${toReturn.url} ${toReturn.challenge} ${toReturn.challengetime}`;

    try
    {
        if(!hsmVerify(hsmMerged, toReturn.checksum))
        {
            throw `Checksum/digital signature verification failed.`;
        }
    }
    catch(err)
    {
        throw `Error accessing data related to asymmetrically encrypted file: ${err.message || err}.`;
    }

    return toReturn;
}

/**
 * Updates the challenge for an asymmetric file download.
 * @param {String} url URL to update the challenge for
 * @param {Buffer} challenge The new challenge to set for the file
 * @throws If URL is undefined, or the fileAsymm database entry has been tampered with
 */
async function updateChallenge(url, challenge)
{
    if (url == undefined)
    {
        throw "Error when updating challenge: `url` is undefined.";
    }

    // Fetch the old SQL table entry and update the challenge
    let returned;
    try
    {
        returned = await _fetchFileAsymm(url);
        returned.challenge = challenge;
        returned.challengetime = new Date(Date.now());

        // Resign the new entry
        let hsmMerged = `${returned.pubkeyb64} ${returned.burnonread} ${returned.expiretime} ${returned.url} ${returned.challenge} ${returned.challengetime}`;
        let checksum = await hsmSign(hsmMerged);

        returned.checksum = checksum;
    }
    catch(err)
    {
        throw `Error when updating challenge: ${err.message || err}`;
    }

    // Push updated entry into SQL
    try
    {
        await runQuery(
            "UPDATE filesAsymm SET Challenge = $1, ChallengeTime = $2, CheckSum = $3 WHERE Url = $4",
            [returned.challenge, returned.challengetime, returned.checksum, url]
        );
    }
    catch(err)
    {
        throw err.message || err;
    }
}

/**
 * Retrieves an asymmetrically encrypted file at the specified URL.
 * Also does authentication challenge verification before returning the file.
 * @param {String} url URL to retrieve item at
 * @param {String} signedChallenge Signed challenge (in hex) to prove the user actually has the private key to decrypt the file
 * @returns {Promise<null | {uuid: String, pubkeyb64: String, burnonread: Boolean, expiretime: Date, url: String, challenge: Buffer, challengetime: Date, checksum: String}>} A JSON representing all the data about the file requested in the URL, or null if the URL is invalid.
 */
async function getFileAsymm(url, signedChallenge)
{
    if (url == undefined)
    {
        throw "Error when downloading file: `url` is undefined.";
    }

    // Fetch the file and check the checksum
    try
    {
        let returned = await _fetchFileAsymm(url);

        // Verify the challenge
        let challengeSuccessful = verifyChallenge(signedChallenge, returned.challenge, returned.pubkeyb64, returned.challengetime);
        if (!challengeSuccessful)
        {
            throw "Authentication challenge failed. Access to file denied.";
        }

        // If we got here, the challenge was successful
        // Just return the file stuff
        return returned;
    }
    catch(err)
    {
        throw `Error when downloading file: ${err.message || err}`;
    }
}

/**
 * Deletes a file from a given table with the specified URL
 * @param {String} url URL of file to delete
 * @param {String} table Table name. Must be `filesAsymm` or `files`
 * @throws Error if the table name is not `filesAsymm` or `files`
 */
async function deleteFile(url, table)
{
    if (table != "filesAsymm" && table != "files")
    {
        throw `Error when deleting file: $table variable must be filesAsymm or files.`;
    }

    try
    {
        // parameterized queries in postgres do not work with table names
        // This is fine because we heavily constrained the input this function accepts above
        await runQuery(
            `DELETE FROM ${table} WHERE Url = $1`,
            [url]
        );
    }
    catch(err)
    {
        throw `Error when deleting file ${url} from ${table}:  ${err.message || err}`;
    }
}

/**
 * Deletes a file from the symmetric SQL table
 * @param {String} url URL to delete
 * @throws Error if deletion process went wrong
 */
async function deleteFileSymm(url)
{
    await deleteFile(url, "files");
}

/**
 * Deletes a file from the asymmetric SQL table
 * @param {String} url URL to delete
 * @throws Error if deletion process went wrong
 */
async function deleteFileAsymm(url)
{
    await deleteFile(url, "filesAsymm");
}

/**
 * Counts the number of entries that expired (ExpireTime < current time). Mainly used to logging and debugging purposes.
 * @returns {Number} Number of entries that expired
 * @throws Error if the SQL query errors out
 */
async function countNumExpired()
{
    try
    {
        // Count both in files and filesAsymm
        let respFilesDB = await runQuery(
            `SELECT COUNT(*) FROM files WHERE ExpireTime < Now()`,
            [], false, true
        );

        let respFilesAsymmDB = await runQuery(
            `SELECT COUNT(*) FROM filesAsymm WHERE ExpireTime < Now()`,
            [], false, true
        );

        return parseInt(respFilesDB.rows[0].count) + parseInt(respFilesAsymmDB.rows[0].count);
    }
    catch(err)
    {
        throw `Error when counting number expired:  ${err.message || err}`;
    }
}

/**
 * Deletes all the entries that expired (ExpireTime < current time).
 * @throws Error if the deletion process goes wrong
 * @returns {Promise<String[]>} List of file names to physically delete from CLI Server
 */
async function deleteExpired()
{
    try
    {
        /**
         * List of file paths that are expired
         */
        let expiredFilePaths = [];

        // Count both in files and filesAsymm
        let respFilesDB = await runQuery(
            `SELECT * FROM files WHERE ExpireTime < Now()`,
            [], false, true
        );

        let respFilesAsymmDB = await runQuery(
            `SELECT * FROM filesAsymm WHERE ExpireTime < Now()`,
            [], false, true
        );

        let respFileDBExpired = respFilesDB.rows.map(row => row.uuid);
        let respFileDBAsymmExpired = respFilesAsymmDB.rows.map(row => row.uuid);

        expiredFilePaths.push(...respFileDBExpired);
        expiredFilePaths.push(...respFileDBAsymmExpired);

        // Now delete them from DB
        await runQuery(
            `DELETE FROM files WHERE ExpireTime < NOW()`,
            [], false, true
        );

        await runQuery(
            `DELETE FROM filesAsymm WHERE ExpireTime < NOW()`,
            [], false, true
        );

        // After deletion is successful, we can return the expired file paths
        return expiredFilePaths;
    }
    catch(err)
    {
        throw `Error when deleting expired files:  ${err.message || err}`;
    }
}

// If we have SIGINT or SIGTERM, gracefully shut down the pool

/**
 * Shuts down the client pool gracefully and exits the program
 */
async function shutdownPool()
{
    console.log("Recieved shutdown signal.");
    await clientPool.end();
    console.log("🛑 PSQL Client Pool has shutdown.");

    process.exit(0);
}

process.on("SIGINT", shutdownPool);
process.on("SIGTERM", shutdownPool);
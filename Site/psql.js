/*
    This file handles connections to the PostgreSQL server.
    This includes parameterized queries and handling clients/connections.
*/

import pg from 'pg';
import {readFileSync } from 'fs';
const { Pool } = pg;

import { hsmSign } from './hsm.js';
import { verify } from '../Crypto/cryptoFunc.js';
import { genPubKeyObject, zeroBuffer } from '../Common/crypto_util.js';

export { runQuery, logSymmFile, logAsymmFile, getFile }

// --------- Crypto files ---------

/**
 * (Ideally) ED-25519 public key used to verify digital signatures
 * @type {Buffer}
 */
let cryptoPubkeySign = readFileSync("/run/secrets/crypto_pubkey_sign");

/**
 * ⭐ Key object for the public (hopefully ED-25519) key.
 * THIS IS DECRYPTED! YOU CAN VERIFY STUFF WITH THIS!!!
 * @type {KeyObject}
 */
let verifyKeyObj = genPubKeyObject(cryptoPubkeySign, "binary");

// "Garbage collect" - well - as much as the mark-and-sweep algorithm will let us
zeroBuffer(cryptoPubkeySign);

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
 * @returns {Promise<Object>} The results from the query
 * @see https://node-postgres.com/features/queries
 * @throw Errors if you don't provide a queryText or queryValue. It will get REALLY mad at you if you don't provide a queryValue.
 */
async function runQuery(queryText, queryValues, arrayRowMode)
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
    else if (queryValues.length == 0)
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
 * @param {String} fileName The name of the file as stored on our end. This should be unique and randomly generated (hopefully)
 * @param {String} pwdHash2 The hash of the password hash provided by the user.
 * @param {boolean} burnOnRead Whether this file should be burnt when we download it
 * @param {Date} expireTimestamp Timestamp when the file expires (and gets marked for deletion)
 * @param {String} url URL you can access the file from
 * @throws If any of the inputs are invalid
 */
async function logSymmFile(fileName, pwdHash2, burnOnRead, expireTimestamp, url)
{
    let hsmMerged = `${fileName} ${pwdHash2} ${burnOnRead} ${expireTimestamp} ${url}`;

    if (fileName == undefined || pwdHash2 == undefined || burnOnRead == undefined || expireTimestamp == undefined || url == undefined)
    {
        console.log(hsmMerged)
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
        await runQuery(
            "INSERT INTO files(Name, PwdHashHash, BurnOnRead, ExpireTime, Url, CheckSum) VALUES($1, $2, $3, $4, $5, $6)",
            [fileName, pwdHash2, burnOnRead, expireTimestamp, url, checksum], false
        );
    }
    catch(err)
    {
        throw err.message || err;
    }
}

/**
 * Logs an asymmetrically encrypted file in the postgres database.
 * @param {String} fileName The name of the file as stored on our end. This should be unique and randomly generated (hopefully)
 * @param {String} pubkeyB64 The public key, in base64.
 * @param {boolean} burnOnRead Whether this file should be burnt when we download it
 * @param {Date} expireTimestamp Timestamp when the file expires (and gets marked for deletion)
 * @param {String} url URL you can access the file from
 * @throws If any of the inputs are invalid
 */
async function logAsymmFile(fileName, pubkeyB64, burnOnRead, expireTimestamp, url)
{
    // We don't immediately create a challenge when the user does asymm file upload
    // We wait for auth()
    // We're going to put placeholders when we do the digitally sign the contents in the postgres table
    let challenge = "null";
    let challengeExpireTime = new Date(Date.now());

    let hsmMerged = `${fileName} ${pubkeyB64} ${burnOnRead} ${expireTimestamp} ${url} ${challenge} ${challengeExpireTime}`;

    if (fileName == undefined || pubkeyB64 == undefined || burnOnRead == undefined || expireTimestamp == undefined || url == undefined)
    {
        console.log(hsmMerged)
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
        console.log(hsmMerged)
        await runQuery(
            "INSERT INTO filesAsymm(Name, PubKeyB64, BurnOnRead, ExpireTime, Url, Challenge, ChallengeTime, CheckSum) VALUES($1, $2, $3, $4, $5, $6, $7, $8)",
            [fileName, pubkeyB64, burnOnRead, expireTimestamp, url, challenge, challengeExpireTime, checksum], false
        );
    }
    catch(err)
    {
        throw err.message || err;
    }
}

/**
 * Retrieves a file at the specified URL
 * @param {String} url URL where the file is stored
 * @returns {Promise<null | {name: String, pwdhashhash: String, burnonread: Boolean, expiretime: Date, url: String, checksum: String>}} A JSON representing all the data about the file requested in the URL. Or null if the URL is invalid.
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
        throw err.message;
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
    let hsmMerged = `${toReturn.name} ${toReturn.pwdhashhash} ${toReturn.burnonread} ${toReturn.expiretime} ${toReturn.url}`;
    
    try
    {
        if(!verify(hsmMerged, verifyKeyObj, toReturn.checksum))
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
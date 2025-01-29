/*
    This file handles connections to the PostgreSQL server.
    This includes parameterized queries and handling clients/connections.
*/

import pg from 'pg';
import {readFileSync } from 'fs';
const { Pool } = pg;

export { runQuery }

/**
 * Available pool of clients. Generate a client from these to connect to and execute queries to our PSQL dockerfile
 * Remember to close these client connections if you do mess with this
 */
const clientPool = new Pool({
    host: process.env.PGHOST,
    user: process.env.PGUSER,
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
        console.error(`Error when running query: ${err.message}`);
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
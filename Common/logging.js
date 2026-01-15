/*
    This module handles all the "event" logs. Code taken from my Ducky-Hoster project.
    It's not going to be Heroku levels of sophistication, but having these logs will give us a pretty good idea of all the network traffic we're getting.
    All time is documented in UTC.

    This is intended to be used by the servers to log anything that you don't want to send back to the client.
*/

import { resolve } from 'path';
import { appendFile } from 'fs';
import { exists } from './file_util.js';

// Declare path of log files
const __dirname = import.meta.dirname;
const ALL_LOGS_PATH = resolve(__dirname, "./Logs/all.log");
const INFO_PATH = resolve(__dirname, "./Logs/info.log");
const STDERR_PATH = resolve(__dirname, "./Logs/error.log");

/**
 * Calculates and returns a timestamp in UTC.
 * @returns The current UTC time.
 */
const getTimestamp = () => {
    let curr_date = new Date();

    return `${curr_date.getUTCFullYear()}-${curr_date.getUTCMonth() + 1}-${curr_date.getUTCDate()} ${curr_date.getUTCHours()}:${curr_date.getUTCMinutes()}:${curr_date.getUTCSeconds()}`;
}

/**
 * Logs a given piece of information in the info logs
 * The trace file should give you a general idea of what's happening on the network
 * @param {String} text Text to log
 * @param {Boolean} print2Console Optional parameter - denotes whether you also want to console.log() the instance.
 */
function log(text, print2Console) {

    appendFile(ALL_LOGS_PATH, `${getTimestamp()} -\t${text}\n`, {encoding: "utf-8"}, (err) => {
        if (err)
        {
            console.error(`🚨 Logging to all logs path with text "${text}" failed. Error: ${err}`);
        }
    });

    appendFile(INFO_PATH, `${getTimestamp()} -\t${text}\n`, {encoding: "utf-8"}, (err) => {
        if (err)
        {
            console.error(`🚨 Logging to info path with text "${text}" failed. Error: ${err}`);
        }
    });

    if (print2Console)
    {
        console.log(text);
    }
}

/**
 * Logs an error.
 * @param {String} text Text to log
 * @param {Boolean} print2Console Optional parameter - denotes whether you also want to console.error() the instance.
 */
function error(text, print2Console) {

    appendFile(ALL_LOGS_PATH, `${getTimestamp()} -\t${text}\n`, {encoding: "utf-8"}, (err) => {
        if (err)
        {
            console.error(`🚨 Logging to all logs path with text "${text}" failed. Error: ${err}`);
        }
    });

    appendFile(STDERR_PATH, `${getTimestamp()} -\t${text}\n`, {encoding: "utf-8"}, (err) => {
        if (err)
        {
            console.error(`🚨 Logging to error path with text "${text}" failed. Error: ${err}`);
        }
    });

    if (print2Console)
    {
        console.error(text);
    }
}

export { error, log }
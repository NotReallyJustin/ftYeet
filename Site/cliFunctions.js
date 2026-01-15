import * as https from 'https';
import { writeFile, readFileSync, rm } from 'fs';
import { deflate, inflate} from 'node:zlib';
import * as cryptoUtil from '../Common/crypto_util.js';
import * as path from 'path';
import * as fileUtil from '../Common/file_util.js';

import { getFile, logSymmFile, logAsymmFile, runQuery, updateChallenge, getFileAsymm, deleteFileAsymm, deleteFileSymm } from './psql.js';
import { randomBytes, constants } from 'crypto';
import { log, error} from '../Common/logging.js';
import { hsmEncrypt, hsmDecrypt } from './hsm.js';

/**
 * Configured in docker compose. Whether or not to log info or errors to console as well as to file.
 * We're doing this to keep reject() errors back to the client as vague as possible.
 */
const LOG_BACK = process.env.LOG_BACK == 'true';

export { genURL, uploadSymm, checkURL, downloadSymm, uploadAymm, generateChallenge, verifyChallenge, downloadAsymm }

// ⭐ Formatting note: I use () => {} if there's no side effects. function() {} is used when there is a side effect

// ---------------- Load in secrets + server ---------------------------------------------

/**
 * Private HMAC key used to HMAC the Cryptosystem
 */
const HMAC_CRYPTOSYS_KEY = readFileSync("/run/secrets/hmac_cryptosys_key");

// 🔑 Asymm Keys

/**
 * Crypto public key used for asymmetric encryption.
 * @type {Buffer}
 */
let cryptoPubkey = readFileSync("/run/secrets/crypto_pubkey");

/**
 * ⭐ Key object for the public key used for asymm encryption.
 * This can be decrypted by the HSM eventually
 * @type {Buffer}
 */
let asymmEncKeyObj = cryptoUtil.genPubKeyObject(cryptoPubkey, "binary");

// ----------------- Main functionality ------------------------------------------------

/**
 * Fetches a random word. Then, it checks if that word has already been used. If it has, get another word.
 * @see https://random-word-api.herokuapp.com/home
 * @returns {Promise<String>} A random word to use in the URL
 */
const genURL = () => new Promise((resolve, reject) => {
    var wordLen = Math.floor(Math.random() * 4) + 7;
    let word = "";

    const testWord = async () => {
        
        https.get(`https://random-word-api.herokuapp.com/word?length=${wordLen}`, response => { 
            response.on('data', data => {
                word += data;
            });

            response.on('end', async () => {
                word = JSON.parse(word);

                if (await checkURL(word[0]))    // If the URL is free
                {
                    resolve(word[0]);
                }
                else
                {
                    word = "";
                    testWord();
                }
            });

        }).on('error', err => {
            error(`Issue when fetching random word: ${err.message}.`, LOG_BACK);
            reject(`Server is unable to fetch and reserve a URL at this time. Please try again later.`);
            return;
        });
    }

    testWord();
    
});

/**
 * Check to ensure that the URL we have isn't already in use
 * @param {String} url The URL to check
 * @throws Errors if the SQL fails
 * @returns {Promise<Boolean>} Whether or not the URL is free
 */
const checkURL = async (url) => {
    // Rows contains the actual stuff
    try
    {
        let validInSymm = (await runQuery("SELECT * FROM files WHERE Url=$1", [url])).rows.length == 0;
        let validInAsymm = (await runQuery("SELECT * FROM filesAsymm WHERE Url=$1", [url])).rows.length == 0;

        return validInAsymm && validInSymm;
    }
    catch(err)
    {
        error(`Error when running SQL to validate URL ${url}: \n${err}`, LOG_BACK);
        console.error(`Error when running SQL to validate URL ${url}: ${err}`);
        throw err;
    }
}

/**
 * Handles symmetric file upload when the CLI server recieves a request 
 * @param {Buffer} data Request data. This should have the encrypted (1x) file contents
 * @param {Number} expireTime Number of seconds before this file gets deleted
 * @param {Boolean} burnOnRead Whether to delete the file upon download
 * @param {String} pwdHash Hash of the password used to encrypt the file (in hex). This is going to be hashed again.
 * @param {String} url The URL you can access the file from
 * @throws Promise rejects if anything goes wrong with the symmetric file upload process. If this happens, return a 400 error.
 * @returns {Promise<>} .then() when it's successful
 */
function uploadSymm(data, expireTime, burnOnRead, pwdHash, url)
{
    return new Promise((resolve, reject) => {
        
        deflate(data, (err, deflatedData) => {

            if (err)
            {
                error(`File failed to compress for URL ${url}:\n${err}`, LOG_BACK);
                reject("File failed to compress. Please check to make sure that your file isn't corrupted.");
                return;
            }

            // Encrypt the data again (by converting it to - you guessed it - another file syntax!). In the future, this is gonna get moved
            hsmEncrypt(deflatedData).then(symmEnc => {
                let ciphertext = symmEnc.ciphertext;
                delete symmEnc.ciphertext;
                
                let encryptedData = cryptoUtil.toFileSyntaxSymm(symmEnc, ciphertext, cryptoUtil.secureKeyGen(HMAC_CRYPTOSYS_KEY, 32, symmEnc.hmacSalt), 'Server');
                
                // Encrypt and write relevant authentication info to database
                let pwdHash2 = cryptoUtil.genPwdHash(pwdHash, 32);
                let expireTimestamp = new Date(Date.now() + expireTime * 1000);

                logSymmFile(pwdHash2, burnOnRead, expireTimestamp, url).then(uuid => {
                    secureWrite(uuid, encryptedData)
                        .then((filePath) => {

                            log(`Data written to ${filePath} for URL ${url}.`, LOG_BACK);
                            resolve();

                        }).catch(err => {

                            // If things fail, wipe the log from the database.
                            deleteFileSymm(url).catch(err => {
                                error(`Failed to delete file ${filePath} in uploadSymm: ${err}`, LOG_BACK);
                            });

                            error(`Error when writing file contents to server: ${err}`, LOG_BACK);
                            reject("Unable to write contents of file to the server.");

                        });
                }).catch(err => {
                    error(`Error in uploadSymm when running SQL for ${url}: \n${err}`, LOG_BACK);
                    reject("Unable to write metadata of file to database.");
                });
            }).catch(err => {
                error(`Error in uploadSymm when making HSM request for ${url}: \n${err}`, LOG_BACK);
                reject("Unable to encrypt file with HSM.");
            });
        });
    });
}

/**
 * Downloads a file from the ftYeet server with a symmetric key
 * @param {String} url The URL where the key is at
 * @param {String} pwdHash The password hash to authenticate, in hex
 * @throws Errors if authentication goes wrong, decryption goes wrong, or if the file doesn't exist
 * @returns {Promise<Buffer>} The file buffer. This should have the encrypted (1x) file contents.
 */
function downloadSymm(url, pwdHash)
{
    return new Promise((resolve, reject) => {
        getFile(url)
            .then(dbOutput => {

                if (dbOutput == null)
                {
                    error(`Warning in downloadSymm: Invalid or expired URL ${url} requested.`, LOG_BACK);
                    reject(`The URL is either invalid, or it expired.`);
                    return;
                }

                // Validate password hash
                if (!cryptoUtil.verifyPwdHash(pwdHash, dbOutput.pwdhashhash))
                {
                    error(`Error in downloadSymm when verifying password hash: Invalid password for URL ${url}.`, LOG_BACK);
                    reject(`Invalid password for file.`);
                    return;
                }
                
                // ⭐ If everything is good, read the file and resolve the output
                let filePath = path.resolve(process.env.FILE_DIR, dbOutput.uuid);
                let fileSyntax;

                try
                {
                    fileSyntax = readFileSync(filePath);
                }
                catch(err)
                {
                    error(`Error in downloadSymm when reading ${filePath}: \n${err}`, LOG_BACK);
                    reject(`Unable to retrieve file requested. The sender likely sent a malformed file.`);
                    return;
                }

                // You usually can't work with file syntax. This resolves it.
                let restored;
                let restored_hsm_fmt;

                try
                {
                    restored = cryptoUtil.fromFileSyntaxSymm(undefined, HMAC_CRYPTOSYS_KEY, fileSyntax);

                    // Things are formatted *slightly* differently in the HSM, so pay attention since we're
                    // coming from file syntax. In file syntax, the ciphertext == data, and the cryptosystem is seperated.
                    // so...
                    restored_hsm_fmt = restored.cryptoSystem;
                    restored_hsm_fmt.ciphertext = restored.data;
                }
                catch(err)
                {
                    error(`Error in downloadSymm when converting from file syntax: \n${err}`, LOG_BACK);
                    reject(`Unable to process file requested. The sender likely sent a malformed file.`);
                    return;
                }

                // This will still be in file syntax. We ran it twice.
                hsmDecrypt(restored_hsm_fmt)
                    .then(deflatedData => {

                        // Reinflate data
                        inflate(deflatedData, (err, data) => {

                            if (err)
                            {
                                error(`Error in downloadSymm when inflating file for URL ${url}:\n${err}`, LOG_BACK);
                                reject("File failed to inflate. Make sure your file isn't corrupted.");
                                return;
                            }
                            else
                            {
                                // Just before we're done, delete the file if it's burn on read
                                if (dbOutput.burnonread)
                                {
                                    // Initiate deletion
                                    deleteFileSymm(url).catch(err => {
                                        error(`Error in downloadSymm when removing burned file from database ${filePath}:\n${err}`, LOG_BACK);
                                        console.log(err);
                                    });

                                    rm(filePath, {force: true}, err => {
                                        if (err)
                                        {
                                            error(`Error in downloadSymm when deleting burned file ${filePath}:\n${err}`, LOG_BACK);
                                        }  
                                    });
                                }
                                
                                resolve(data);
                            }
                        });

                    }).catch(err => {
                        error(`Error in downloadSymm when decrypting a file ${filePath} from file syntax: \n${err}`, LOG_BACK);
                        reject(`Unable to decode file requested. The sender likely sent a malformed file.`);
                        return;
                    });

            }).catch(err => {
                error(`Error in downloadSymm when running SQL for URL ${url}: \n${err}`, LOG_BACK);
                reject("Internal Database Error. Ask the owner of ftYeet to check their Docker logs.");
            });
    });
}

/**
 * Handles asymmetric file upload when the user makes a CLI request
 * @param {Buffer} data Request data. This should have the encrypted (1x) file contents
 * @param {Number} expireTime Number of seconds before this file gets deleted
 * @param {Boolean} burnOnRead Whether to delete the file upon download
 * @param {String} pubkeyB64 The public key, in base64
 * @param {String} url The URL you can access the file from
 * @throws Promise rejects if anything goes wrong with the asymmetric file upload process. If this happens, return a 400 error.
 * @returns {Promise<>} .then() when it's successful 
 */
function uploadAymm(data, expireTime, burnOnRead, pubkeyB64, url)
{
    return new Promise((resolve, reject) => {
        
        // Deflate data. It's really quick and saves space.
        deflate(data, (err, deflatedData) => {

            if (err)
            {
                error(`Error in uploadAsymm when deflating data for ${url}:\n${err}`, LOG_BACK);
                reject("File failed to compress. Please check to make sure that your file isn't corrupted.");
                return;
            }

            // Encrypt the data again (by converting it to - you guessed it - another file syntax!).
            // This is just like what we did with the symmetric file uploads
            hsmEncrypt(deflatedData).then(symmEnc => {
                let ciphertext = symmEnc.ciphertext;
                delete symmEnc.ciphertext;
                
                // No need to use asymm file syntax here. If we did use asymm file syntax, the would-be private key would be stored in the
                // same place as the symmetric key right now. They're equally secure, but file syntax symm is just faster.
                let encryptedData = cryptoUtil.toFileSyntaxSymm(symmEnc, ciphertext, cryptoUtil.secureKeyGen(HMAC_CRYPTOSYS_KEY, 32, symmEnc.hmacSalt), 'Server');

                // Write relevant info to the database, and THEN write the file.
                // Before we start, note that we're storing the base64 public key in postgres. The fact that it's base64 makes things A LOT easier for us.
                // Also it's a public key. We don't need to protect it.
                let expireTimestamp = new Date(Date.now() + expireTime * 1000);

                logAsymmFile(pubkeyB64, burnOnRead, expireTimestamp, url).then((uuid) => {

                    secureWrite(uuid, encryptedData)
                        .then((filePath) => {

                            log(`uploadAsymm: Data written to ${filePath}.`, LOG_BACK);
                            resolve();

                        }).catch(err => {

                            // If things fail, wipe the log from the database.
                            deleteFileAsymm(url).catch(err => {
                                error(`Error in uploadAsymm when deleting file ${filePath} after earlier error: \n${err}`, LOG_BACK);
                            });

                            error(`Error in uploadAsymm when writing file contents of ${filePath} to disk for URL ${url}: \n${err}`, LOG_BACK);
                            reject("Unable to write contents of file to the server.");

                        });

                }).catch(err => {
                    error(`Error in uploadAsymm when running SQL for URL ${url}: \n${err}`, LOG_BACK);
                    reject("Unable to log the upload request to database.");
                });

            }).catch(err => {
                error(`Error in uploadAsymm when making HSM request for URL ${url}: \n${err}`, LOG_BACK);
                reject("Unable to re-encrypt the uploaded file.");
            });
        });
    });
}

/**
 * Generates a challenge for an asymmetric file download (with the given URL).
 * @param {String} url The URL to generate the challenge for
 * @returns {Promise<Buffer>} The challenge, which is a random 32-byte buffer
 */
function generateChallenge(url)
{
    let challenge = randomBytes(32);
    
    // Store the challenge in the database
    return new Promise((resolve, reject) => {
        updateChallenge(url, challenge)
            .then(() => {
                resolve(challenge);
            }).catch(err => {
                error(`Error when generating authentication challenge: \n${err}`, LOG_BACK);
                reject(`Unable to generate an authentication challenge. Please try again later.`);
            });
    });
}

/**
 * Verifies the challenge for an asymmetric file upload, and then downloads the file.
 * @param {String} url The URL to download the file from
 * @param {String} signedChallenge Challenge, signed by the recipient's private key, encoded in hex
 * @throws Error if the challenge verification fails, or if the file doesn't exist
 * @returns {Promise<Buffer>} The file contents, which should be the encrypted (1x) file contents
 */
function downloadAsymm(url, signedChallenge)
{
    return new Promise((resolve, reject) => {
        getFileAsymm(url, signedChallenge)      // Get the file, verify challenge, verify checksum
            .then(dbOutput => {

                if (dbOutput == null)
                {
                    error(`Warning in downloadAsymm: Invalid or expired URL ${url} requested.`, LOG_BACK);
                    reject(`The URL is either invalid, or it expired.`);
                    return;
                }
                
                // ⭐ If everything is good, read the file and resolve the output
                let filePath = path.resolve(process.env.FILE_DIR, dbOutput.uuid);
                let fileSyntax;

                try
                {
                    fileSyntax = readFileSync(filePath);
                }
                catch(err)
                {
                    error(`Error in downloadAsymm when reading ${filePath}: \n${err}`, LOG_BACK);
                    reject(`Unable to retrieve file from ftyeet. The sender likely sent a malformed file.`);
                    return;
                }

                // You usually can't work with file syntax. This resolves it.
                let restored;
                let restored_hsm_fmt;

                try
                {
                    restored = cryptoUtil.fromFileSyntaxSymm(undefined, HMAC_CRYPTOSYS_KEY, fileSyntax);

                    // Things are formatted *slightly* differently in the HSM, so pay attention since we're
                    // coming from file syntax. In file syntax, the ciphertext == data, and the cryptosystem is seperated.
                    // so...
                    restored_hsm_fmt = restored.cryptoSystem;
                    restored_hsm_fmt.ciphertext = restored.data;
                }
                catch(err)
                {
                    error(`Error when converting file for ${url} from file syntax: \n${err}`, LOG_BACK);
                    reject(`Unable to retrieve file from ftyeet. The sender likely sent a malformed file.`);
                    return;
                }

                // Decrypt HSM to get user's E2EE file
                hsmDecrypt(restored_hsm_fmt)
                    .then(deflatedData => {
                        
                        inflate(deflatedData, (err, data) => {

                            if (err)
                            {
                                error(`Error in downloadAsymm when inflating file for URL ${url}:\n${err}`, LOG_BACK);
                                reject("File failed to inflate. Make sure your file isn't corrupted.");
                            }
                            else
                            {

                                // Just before we're done, delete the file if it's burn on read
                                if (dbOutput.burnonread)
                                {
                                    // Initiate deletion
                                    deleteFileAsymm(url).catch(err => {
                                        error(`Error in downloadAsymm when removing burned file for ${url} from database ${filePath}:\n${err}`, LOG_BACK);
                                    });

                                    rm(filePath, {force: true}, err => {
                                        if (err)
                                        {
                                            error(`Error when deleting burned file ${filePath} in downloadAsymm: ${err}`, LOG_BACK);
                                        }
                                    });
                                }

                                resolve(data);
                            }
                        });

                    }).catch(err => {
                        error(`Error when decrypting file syntax for ${url}: ${err}`, LOG_BACK);
                        reject(`Unable to retrieve decode file requested.`);
                    });

            }).catch(err => {
                error(`Error in downloadAsymm when running SQL for ${url}: ${err}`, LOG_BACK);
                reject("Internal Database Error. Ask the owner of ftYeet to check their Docker logs.");
            });
    });
}

/**
 * Verifies the challenge for an asymmetric file download.
 * @param {String} signedChallenge Challenge, signed (in hex)
 * @param {Buffer} challenge Challenge
 * @param {String} pubkeyB64 Public key, in base64
 * @param {Date} challengeTime The time the challenge was generated at. There's only 120 seconds to verify by the way.
 * @throws Error if public key process or verification process errors
 * @returns {Boolean} Whether the challenge is valid
 */
const verifyChallenge = (signedChallenge, challenge, pubkeyB64, challengeTime) => {

    // Generate public key object you can verify with!
    try
    {
        let pubKeyObj = cryptoUtil.genPubKeyObject(pubkeyB64, 'base64');
        const cryptoMatches = cryptoUtil.secureVerify('sha3-512', challenge, {key: pubKeyObj, padding: constants.RSA_PKCS1_PSS_PADDING}, signedChallenge);

        // time challenge
        let timeDiff = Date.now() - challengeTime.getTime();
        const timeWithinBounds = timeDiff <= 120000; // 120s

        return cryptoMatches && timeWithinBounds;
    }
    catch(err)
    {
        error(`Error when verifying challenge: \n${err}`, LOG_BACK);
        throw `Failed to authenticate. Challenge verification failed.`;
    }
}

/**
 * Validates a given file name, and writes data to said file.
 * @param {String} fileName The desired file name.
 * @param {Buffer} data The binary data to write to the file.
 * @returns {Promise<string>} Promise resolves with the `[new] file path`.
 */
function secureWrite(fileName, data)
{
    return new Promise((resolve, reject) => {

        let newFilePath;
        
        const INVALID_REGEX = /[\s*?"'<>\|&$\(\)\[\]\{\};!#~^\x00\\]/i;
        if (INVALID_REGEX.test(fileName))
        {
            error(`Error in secureWrite for ${fileName}: Invalid characters in file name ${fileName}.`, LOG_BACK);
            reject("Invalid characters in file name.");
            return;
        }

        newFilePath = path.resolve(process.env.FILE_DIR, fileName);

        if (fileUtil.exists(newFilePath))
        {
            error(`Error in secureWrite for ${fileName}: File already exists at ${newFilePath}.`, LOG_BACK);
            reject(`File ${fileName} already exists.`);
            return;
        }
        
        // Sanity check for the path resolve above, which should be fine I'm just being paranoid about Node.js
        if (newFilePath.indexOf(process.env.FILE_DIR) == -1)
        {
            error(`Error in secureWrite for ${fileName}: Malform/Corrupted file path detected.`, LOG_BACK);
            reject("Malform/Corrupted file path detected.");
            return;
        }

        // There's a lot of protections against writing outside of intended dir. First, you have FILE_DIR environment variable loaded at STARTUP time (when Docker starts)
        // Then you have seccomp and the absolute path resolution. Then, the file names should only come from SQL's UUID generator.
        // If that all fails, we validate the file name.
        writeFile(newFilePath, data, (err) => {
            if (err)
            {
                error(`Error in secureWrite for ${fileName}: ${err}.`, LOG_BACK);
                reject("Failed to write file to disk.");
            }
            else
            {
                resolve(newFilePath);
            }
        }); 
    });
}
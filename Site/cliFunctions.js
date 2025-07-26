import * as https from 'https';
import { writeFile, chmod, readFileSync, rmSync } from 'fs';
import * as cryptoUtil from '../Common/crypto_util.js';
import * as path from 'path';
import * as fileUtil from '../Common/file_util.js';

import { getFile, logSymmFile, logAsymmFile, runQuery, updateChallenge, getFileAsymm, deleteFileAsymm, deleteFileSymm } from './psql.js';
import { randomBytes, constants } from 'crypto';
import { asymmEnc } from '../Crypto/cryptoFunc.js';
import { hsmEncrypt, hsmDecrypt } from './hsm.js';

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
            reject(`Issue when fetching random word: ${err.message}.`);
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
        
        // Encrypt the data again (by converting it to - you guessed it - another file syntax!). In the future, this is gonna get moved
        hsmEncrypt(data).then(symmEnc => {
            let ciphertext = symmEnc.ciphertext;
            delete symmEnc.ciphertext;
            
            let encryptedData = cryptoUtil.toFileSyntaxSymm(symmEnc, ciphertext, cryptoUtil.secureKeyGen(HMAC_CRYPTOSYS_KEY, 32, symmEnc.hmacSalt), 'Server');

            secureWrite(encryptedData)
                .then((pathObjects) => {
                    // Hash pwds again and then store it
                    let pwdHash2 = cryptoUtil.genPwdHash(pwdHash, 32);

                    // Write to database
                    let expireTimestamp = new Date(Date.now() + expireTime * 1000);

                    logSymmFile(
                        pathObjects.fileName, pwdHash2, burnOnRead, expireTimestamp, url
                    ).then(() => {

                        // Auto delete process start       

                        console.log(`Data written to ${pathObjects.newFilePath}`);
                        resolve();

                    }).catch((err) => {

                        // If writing fails, delete the file
                        try
                        {
                            rmSync(pathObjects, {force: true});
                        }
                        catch(err)
                        {
                            console.error(`Failed to remove file ${pathObjects} when logging fails: ${err}.`)
                        }
                        
                        console.error(`Error in uploadSymm when running SQL: ${err}`);
                        reject("Internal Database Error. Ask the owner of ftYeet to check their logs.");
                    });
                }).catch(err => {
                    console.error(`Error in uploadSymm: ${err}`);
                    reject(err);
                });
        }).catch(err => {
            console.error(`Error in uploadSymm when making HSM request: ${err}`);
            reject(err);
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
                    reject(`The URL is either invalid, or it expired.`);
                    return;
                }

                // Validate password hash
                if (cryptoUtil.verifyPwdHash(pwdHash, dbOutput.pwdhashhash))
                {
                    reject(`Invalid password for file.`);
                    return;
                }

                // If it's burn on read, delete the entry
                if (dbOutput.burnonread)
                {
                    // Initiate deletion
                    deleteFileSymm(url).catch(err => {
                        console.error(err);
                    });
                }
                
                // ⭐ If everything is good, read the file and resolve the output
                let filePath = path.resolve(process.env.FILE_DIR, dbOutput.name);
                let fileSyntax;

                try
                {
                    fileSyntax = readFileSync(filePath);
                }
                catch(err)
                {
                    console.error(`Error in downloadSymm when reading ${filePath}: ${err}`);
                    reject(`Unable to retrieve file from ftyeet. The sender likely sent a malformed file.`);
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
                    console.error(`Error when converting from file syntax: ${err}`);
                    reject(`Unable to retrieve file from ftyeet. ${err}`);
                }

                // This will still be in file syntax. We ran it twice.
                hsmDecrypt(restored_hsm_fmt)
                    .then(decrypted => {
                        resolve(decrypted);
                    }).catch(err => {
                        console.error(`Error when decrypting file syntax: ${err}`);
                        reject(`Unable to retrieve file from ftyeet. ${err}`);
                    });

            }).catch(err => {
                console.error(`Error in downloadSymm when running SQL: ${err}`);
                reject("Internal Database Error. Ask the owner of ftYeet to check their logs.");
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
        
        // Encrypt the data again (by converting it to - you guessed it - another file syntax!).
        // This is just like what we did with the symmetric file uploads
        hsmEncrypt(data).then(symmEnc => {
            let ciphertext = symmEnc.ciphertext;
            delete symmEnc.ciphertext;
            
            // No need to use asymm file syntax here. If we did use asymm file syntax, the would-be private key would be stored in the
            // same place as the symmetric key right now. They're equally secure, but file syntax symm is just faster.
            let encryptedData = cryptoUtil.toFileSyntaxSymm(symmEnc, ciphertext, cryptoUtil.secureKeyGen(HMAC_CRYPTOSYS_KEY, 32, symmEnc.hmacSalt), 'Server');

            secureWrite(encryptedData)
                .then((pathObjects) => {
                   
                    // Before we start, note that we're storing the base64 public key in postgres. The fact that it's base64 makes things A LOT easier for us.
                    // Also it's a public key. We don't need to protect it.

                    // Write timestamp to database
                    let expireTimestamp = new Date(Date.now() + expireTime * 1000);

                    logAsymmFile(
                        pathObjects.fileName, pubkeyB64, burnOnRead, expireTimestamp, url
                    ).then(() => {

                        // Auto delete process start       

                        console.log(`Data written to ${pathObjects.newFilePath}`);
                        resolve();

                    }).catch((err) => {

                        // If writing fails, delete the file
                        try
                        {
                            rmSync(pathObjects, {force: true});
                        }
                        catch(err)
                        {
                            console.error(`Failed to remove file ${pathObjects} when logging fails: ${err}.`)
                        }

                        console.error(`Error in uploadAsymm when running SQL: ${err}`);
                        reject("Internal Database Error. Ask the owner of ftYeet to check their logs.");
                    });
                }).catch(err => {
                    console.error(`Error in uploadAsymm: ${err}`);
                    reject(err);
                });
        }).catch(err => {
            console.error(`Error in uploadAsymm when making HSM request: ${err}`);
            reject(err);
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
                reject(`Error when generating authentication challenge: ${err}`);
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
                    reject(`The URL is either invalid, or it expired.`);
                    return;
                }

                // If it's burn on read, delete the entry
                if (dbOutput.burnonread)
                {
                    // Initiate deletion
                    deleteFileAsymm(url).catch(err => {
                        console.log(err);
                    });
                }
                
                // ⭐ If everything is good, read the file and resolve the output
                let filePath = path.resolve(process.env.FILE_DIR, dbOutput.name);
                let fileSyntax;

                try
                {
                    fileSyntax = readFileSync(filePath);
                }
                catch(err)
                {
                    console.error(`Error in downloadAsymm when reading ${filePath}: ${err}`);
                    reject(`Unable to retrieve file from ftyeet. The sender likely sent a malformed file.`);
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
                    console.error(`Error when converting from file syntax: ${err}`);
                    reject(`Unable to retrieve file from ftyeet. ${err}`);
                }

                // Decrypt HSM to get user's E2EE file
                hsmDecrypt(restored_hsm_fmt)
                    .then(decrypted => {
                        resolve(decrypted);
                    }).catch(err => {
                        console.error(`Error when decrypting file syntax: ${err}`);
                        reject(`Unable to retrieve file from ftyeet. ${err}`);
                    });

            }).catch(err => {
                console.error(`Error in downloadAsymm when running SQL: ${err}`);
                reject("Internal Database Error. Ask the owner of ftYeet to check their logs.");
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
        throw `Error when verifying challenge: ${err}`;
    }
}

/**
 * Validates the file name (to prevent fiddling with paths), encrypts the file name if it is, disables execution for everyone, and writes the binary data to a file.
 * The new file name will be a randomly generated 64-byte hex (max file name size)
 * @param {Buffer} data The binary data to write to the file. ⭐ This data will be encrypted again via file syntax. ⭐
 * @returns {Promise<{fileName: string, newFilePath: string}>} Promise resolves with the `[new] encrypted file path` and the `file name` as JSON
 */
function secureWrite(data)
{
    return new Promise((resolve, reject) => {

        // Generate a random, unique file name that's 64 bytes (AKA 64 hexes)
        let newFilePath;
        let fileName;
        
        // TODO: Once we get the database up, don't use the exist function. Just make a db query instead. It's much faster
        while (newFilePath == undefined || fileUtil.exists(newFilePath))
        {
            fileName = randomBytes(32).toString('hex');
            newFilePath = path.resolve(process.env.FILE_DIR, fileName);
        }

        // Normally, you would check the dir you're writing to to prevent path traversal, but we alr mitigated that with the re-encoding + docker container
        // Also checking dir you're writing to doesn't make any sense because this is going to be in a docker container with its own virtual fs
        writeFile(newFilePath, data, (err) => {
            if (err)
            {
                console.error(`Error in secureWrite: ${err}.`);
                reject(err);
            }
            else
            {
                // For security, disable execution perms
                let status = fileUtil.chmod(newFilePath, 0o666);
                // status = status && fileUtil.chown(newFilePath, ROOT_ID, parseInt(process.env.FWGROUPID));

                if (status)
                {
                    resolve({newFilePath: newFilePath, fileName: fileName});
                }
                else
                {
                    reject("Failed to properly set file permissions.");
                }
            }
        }); 
    });
}
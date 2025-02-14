import * as https from 'https';
import { writeFile, chmod } from 'fs';
import * as cryptoUtil from '../Common/crypto_util.js';
import * as path from 'path';
import * as fileUtil from '../Common/file_util.js';
import { getFile, logSymmFile, runQuery } from './psql.js';
import { randomBytes } from 'crypto';
export { genURL, uploadSymm, checkURL, downloadSymm }

// ⭐ Formatting note: I use () => {} if there's no side effects. function() {} is used when there is a side effect

const TEMP_PWD = "Temporary";
const FILE_DIR = "./files/";

/**
 * Fetches a random word. Then, it checks if that word has already been used. If it has, get another word.
 * @see https://random-word-api.herokuapp.com/home
 * @returns {Promise<String>} A random word to use in the URL
 */
const genURL = () => new Promise((resolve, reject) => {
    //TODO once we have db: Check to ensure that we don't have overlap
    var wordLen = Math.floor(Math.random() * 4) + 7;
    let word = "";

    // !!!Heroku app is down FOR NOW!!!
    resolve("helllooooo");
    return;
    const testWord = async () => {
        
        https.get(`https://random-word-api.herokuapp.com/word?length=${wordLen}`, response => { 
            response.on('data', data => {
                word += data;
            });

            response.on('end', async () => {
                word = JSON.parse(word);

                if (await checkURL(word))    // If the URL is free
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
    runQuery("SELECT * FROM files WHERE Url=$1", [url])
        .then(result => {
            // Rows contains the actual stuff
            return result.rows.length == 0;
        }).catch((err) => {
            console.error(`Error in uploadSymm when running SQL: ${err}`);
            throw "Internal Database Error. Ask the owner of ftYeet to check their logs.";
        });
}

/**
 * Handles symmetric file upload when the CLI server recieves a request 
 * @param {Buffer} data Request data. This should have the encrypted (1x) file contents
 * @param {Number} expireTime Number of seconds before this file gets deleted
 * @param {Boolean} burnOnRead Whether to delete the file upon download
 * @param {String} pwdHash Hash of the password used to encrypt the file (in hex). This is going to be hashed again.
 * @param {String} url The URL you can access the file from
 * @throws Promise rejects if anything goes wrong with the symmetric file upload process. If this happens, return a 400 error.
 * @returns {Proimse<>} .then() when it's successful
 */
function uploadSymm(data, expireTime, burnOnRead, pwdHash, url)
{
    // Encrypt the data again (by converting it to - you guessed it - another file syntax!). In the future, this is gonna get moved
    let symmEnc = cryptoUtil.symmetricEncrypt(TEMP_PWD, TEMP_PWD, data, 'chacha20-poly1305', 12);
    let ciphertext = symmEnc.ciphertext;
    delete symmEnc.ciphertext;

    let encryptedData = cryptoUtil.toFileSyntaxSymm(symmEnc, ciphertext, cryptoUtil.secureKeyGen(TEMP_PWD, 32, symmEnc.hmacSalt), 'Server');

    return new Promise((resolve, reject) => {
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
                    console.error(`Error in uploadSymm when running SQL: ${err}`);
                    reject("Internal Database Error. Ask the owner of ftYeet to check their logs.");
                });

            }).catch(err => {
                console.error(`Error in uploadSymm: ${err}`);
                reject(err);
            });
    });
}

/**
 * Downloads a file from the ftYeet server with a symmetric key
 * @param {String} url The URL where the key is at
 * @param {String} pwdHash The password hash to authenticate
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
                
                resolve(dbOutput);
            }).catch(err => {
                console.error(`Error in uploadSymm when running SQL: ${err}`);
                reject("Internal Database Error. Ask the owner of ftYeet to check their logs.");
            });
    });
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
            newFilePath = path.resolve(FILE_DIR, fileName);
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
// To declutter main.js, this handles all the important CLI functions
// Justin notation: () => {} if there's no side effects. function() {} if there is.

// 🔊 Note to self when you get back: Work on fixing base64 decrypt over in the server to support jwk and der
import * as cryptoUtil from '../Common/crypto_util.js';
import * as fileUtil from '../Common/file_util.js';
import fetch from 'node-fetch';
import { writeFileSync, readFileSync } from 'node:fs';
import { constants, publicEncrypt, privateDecrypt } from 'node:crypto';
import { dirname, basename } from 'node:path';
import { Agent } from 'https';
import { SymmDLBar, SymmULBar, AsymmDLBar, AsymmULBar } from './progressBar.js';

export { keygen, uploadSymm, uploadAsymm, downloadSymm, downloadAsymm }

/**
 * The domain name of the "website" that our ftYeet protocol is tunneled under
 */
const HTTPS_TUNNEL = 'https://api.ftyeet.com';

/**
 * Temporary SSL agent until we get a proper SSL cert for ftYeet.
 * Bypasses the Self-Signed Cert warnings.
 */
const IGNORE_SSL_AGENT = new Agent({
    rejectUnauthorized: false
});

/**
 * Toggles the return between debug errors and normal errors for CLI commands
 * @param {Boolean} debugMode Whether the user invoked the command in debug mode
 * @param {Error|String} debugError Error to show the user if debug mode is on
 * @param {Error|String} normalError Error to show the user if debug mode is off
 */
const debugToggle = (debugMode, debugError, normalError) => debugMode ? debugError : normalError;

/**
 * Generates a public/private keypair and writes it to a given file
 * @param {String} pubkeyPath Path to write public key to
 * @param {String} privkeyPath Path to write private key to
 * @param {String} encryptAlg Asymmetric encryption algorithm to generate keypairs for. Must be in the list of supportedAsymmetrics. Users should know about the options from the CLI.
 * @param {JSON} options Node.js options for your asymmetric encryption alg
 * @see `cryptoUtil.genKeyPair()`
 */
function keygen(pubkeyPath, privkeyPath, encryptAlg, options)
{
    // First check if you can even write the public keys
    if (fileUtil.exists(pubkeyPath))
    {
        throw `Error when generating keys: ${pubkeyPath} already contains a file.`;
    }
    if (fileUtil.exists(privkeyPath))
    {
        throw `Error when generating keys: ${privkeyPath} already contains a file.`;
    }
    
    if (!fileUtil.isDir(dirname(pubkeyPath)))
    {
        throw `Error when generating keys: ${dirname(pubkeyPath)} is not a valid directory.`;
    }
    if (!fileUtil.isDir(dirname(privkeyPath)))
    {
        throw `Error when generating keys: ${dirname(privkeyPath)} is not a valid directory.`;
    }

    if (!fileUtil.canWrite(dirname(pubkeyPath)))
    {
        throw `Error when generating keys: Cannot write to directory ${dirname(pubkeyPath)}.`;
    }
    if (!fileUtil.canWrite(dirname(privkeyPath)))
    {
        throw `Error when generating keys: Cannot write to directory ${dirname(privkeyPath)}.`;
    }

    if (!cryptoUtil.supportedAsymmetrics.includes(encryptAlg.toLowerCase()))
    {
        throw `Error when generating keys: ${encryptAlg} is not supported. Run --help to see list of supported asymmetric encryption algorithms.`;
    }

    // Check the encodings - we know they *have* to exist due to parsing + default options.
    if (!cryptoUtil.keyEncodingFormats.includes(options.publicKeyEncoding.format.toLowerCase()))
    {
        throw `Error when generating keys: unsupported public key encoding format ${options.publicKeyEncoding.format}.`
    }
    if (!cryptoUtil.keyEncodingFormats.includes(options.privateKeyEncoding.format.toLowerCase()))
    {
        throw `Error when generating keys: unsupported private key encoding format ${options.privateKeyEncoding.format}.`
    }
    
    if (!cryptoUtil.keyEncodingTypes.includes(options.publicKeyEncoding.type.toLowerCase()))
    {
        throw `Error when generating keys: unsupported public key encoding type ${options.publicKeyEncoding.type}.`
    }
    if (!cryptoUtil.keyEncodingTypes.includes(options.privateKeyEncoding.type.toLowerCase()))
    {
        throw `Error when generating keys: unsupported private key encoding type ${options.privateKeyEncoding.type}.`
    }

    if (options.privateKeyEncoding.cipher != undefined && !cryptoUtil.supportedPrivKeyCiphers.includes(options.privateKeyEncoding.cipher))
    {
        throw "Error when generating keys: Unsupported cipher to encrypt private keys. If you're using chacha20-poly1305 or aes-256-gcm, sadly Node doesn't support that.";
    }

    // Generate keypairs + write them to files
    let keyPair = cryptoUtil.genKeyPair(encryptAlg, options);
    let pubKeyBuff = cryptoUtil.keyToBin(keyPair.publicKey, options.publicKeyEncoding.format);
    let privkeyBuff = cryptoUtil.keyToBin(keyPair.privateKey, options.privateKeyEncoding.format);

    try
    {
        writeFileSync(pubkeyPath, pubKeyBuff, {encoding: 'binary'});
        writeFileSync(privkeyPath, privkeyBuff, {encoding: 'binary'});

        cryptoUtil.zeroBuffer(pubKeyBuff);
        cryptoUtil.zeroBuffer(privkeyBuff);
    }
    catch(err)
    {
        throw `Error when generating keys: ${err.toString()}.`;
    }
}

/**
 * Encrypts, HMACs, and uploads a local file onto the ftYeet server
 * @param {String} filePath Path to file you want to upload
 * @param {String} password Password to generate encryption key
 * @param {String} encAlg Encryption algorithm
 * @param {String} authCode Password to generate HMAC key
 * @param {Number} expireTime How long should the ftYeet server hold on to your file (in seconds). Must be `>= 60`.
 * @param {Boolean} burnOnRead Whether ftYeet should delete the file immediately upon download
 * @param {Boolean} debugMode Whether to show debug errors or normal errors
 * @returns {Promise<Void>} Resolves when upload is complete
 */
function uploadSymm(filePath, password, encAlg, authCode, expireTime, burnOnRead, debugMode)
{  
    return new Promise((resolve, reject) => {
        if (expireTime < 60)
        {
            reject(`Error: expire-time must be longer than 60 seconds.`);
            return;
        }

        if (!fileUtil.exists(filePath))
        {
            reject(`Error: ${filePath} does not exist.`);
            return;
        }

        if (!fileUtil.isFile(filePath))
        {
            reject(`Error: ${filePath} is not a file.`);
            return;
        }

        if (!fileUtil.canRead(filePath))
        {
            reject(`Error: Cannot read contents of ${filePath}.`);
            return;
        } 

        if (!cryptoUtil.supportedCiphers.includes(encAlg))
        {
            reject(`Error: ${encAlg} is not a supported encryption algorithm.`);
            return;
        }
        
        // Create progress bar and start it
        let progressBar = new SymmULBar();
        progressBar.start();

        // Before we fetch, we're going to encrypt to make things nicer :)
        // Read file contents as buffer
        let plaintext;
        try
        {
            plaintext = readFileSync(filePath);
        }
        catch(err)
        {
            progressBar.stop();
            reject(debugToggle(debugMode, 
                `Error when uploading file: Failed to read file ${filePath}.\n\n${err}`,
                `Error: Failed to read file ${filePath}.`
            ));
            return;
        }
        
        // Symmetrically encrypt and HMAC the file path and name (using the file construct structure we came up with)
        let fileSyntax;

        try
        {
            progressBar.increment();
            let fileConstruct = cryptoUtil.toFileConstruct(basename(filePath), plaintext);
            let symmEnc = cryptoUtil.symmetricEncrypt(password, authCode, Buffer.from(fileConstruct, 'utf-8'), encAlg, encAlg == 'aes-256-cbc' ? 16 : 12);
            let ciphertext = symmEnc.ciphertext;
            delete symmEnc.ciphertext;

            // Convert to file syntax
            progressBar.increment();
            let hmacCryptosys = cryptoUtil.secureKeyGen(authCode, 32, symmEnc.hmacSalt);
            fileSyntax = cryptoUtil.toFileSyntaxSymm(symmEnc, ciphertext, hmacCryptosys, 'CLI');
        }
        catch(err)
        {
            progressBar.stop();
            reject(debugToggle(debugMode, 
                `Error in symmetricEncrypt and fileSyntax Conversion: Failed to encrypt file ${filePath}.\n\n${err}`,
                `Error: Failed to encrypt file ${filePath}. Your file is likely corrupted.`
            ));
            return;
        }
        
        // First, fetch a word
        progressBar.increment();
        
        fetch(`${HTTPS_TUNNEL}/request`, {
            method: 'GET',
            follow: 1,
            agent: IGNORE_SSL_AGENT
        }).then((response) => {
            if (response.ok)
            {
                response.text().then(salt => {
                    
                    // Generate SALT to hash password with --> This is the hash of the URL
                    let urlHash = cryptoUtil.genHash(salt, 'sha3-256');

                    progressBar.increment();
                    // Send fetch request to website
                    fetch(`${HTTPS_TUNNEL}/upload`, {
                        method: 'POST',
                        headers: {
                            "expire-time": expireTime,
                            "burn-on-read": burnOnRead,
                            "pwd-hash": cryptoUtil.genPwdHash(password, 64, urlHash),
                            "Content-Type": "application/octet-stream",
                            "url": salt
                        },
                        body: fileSyntax,
                        follow: 1,
                        agent: IGNORE_SSL_AGENT
                    }).then((response2) => {
                        if (response2.ok)
                        {
                            progressBar.increment();
                            progressBar.stop();

                            console.log("File successfully encrypted and uploaded.");

                            response2.text().then(text => {
                                console.log(`Your file can be accessed here with this URL: ${text}. Pass it into the download function.`);
                                resolve();
                            }).catch(err => {
                                reject(debugToggle(
                                    debugMode,
                                    `Unexpected error when decoding URL: \n\n${err}`,
                                    `Error: Unable to retrieve file URL. For more information, enable debug mode.`
                                ));
                                return;
                            });
                        }
                        else
                        {
                            response2.text().then(err => {
                                progressBar.stop();
                                reject(`Error: Failed to upload file to server. Error from server:\n\n${err}`);
                                return;
                            }).catch(err => {
                                progressBar.stop();
                                reject(debugToggle(debugMode,
                                    `Error when uploading file: Failed to upload file to ftYeet server. Unable to parse error response from server. \n\n${err}`,
                                    `Error: Failed to upload file to ftYeet server.`
                                ));
                                return;
                            });
                        }
                    }).catch(err => {
                        progressBar.stop();
                        reject(debugToggle(debugMode, 
                            `Error when sending fetch request to HTTP tunnel to upload file: \n\n${err}`,
                            `Error: Unable to upload to ftYeet server.`
                        ));
                        return;
                    });
                });
            }
            else
            {
                response.text().then(err => {
                    progressBar.stop();
                    reject(`Error: Failed to request upload URL from server. Error from server:\n\n${err}`);
                    return;
                }).catch(err => {
                    progressBar.stop()
                    reject(debugToggle(debugMode,
                        `Error when requesting upload URL: Failed to request upload URL from ftYeet server. Unable to parse error response from server. \n\n${err}`,
                        `Error: Failed to request upload URL from ftYeet server.`
                    ));
                    return;
                });
            }
        }).catch(err => {
            progressBar.stop();
            reject(debugToggle(debugMode,
                `Error when sending fetch request to HTTP tunnel to request upload URL: \n\n${err}`,
                `Error: Unable to request upload URL from ftYeet server.`
            ));
            return;
        });
    });
}

/**
 * Encrypts, HMACs, and uploads a local file onto the ftYeet server
 * @param {String} dirPath Directory you want to put the downloaded file in 
 * @param {String} password Password to generate decryption key
 * @param {String} encAlg Encryption/Decryption algorithm
 * @param {String} authCode Password to generate HMAC key
 * @param {String} url The ftYeet URL where the file is stored
 * @param {Boolean} debugMode Whether to show debug errors or normal errors
 * @returns {Promise<Void>} Resolves when download is complete
 */
function downloadSymm(dirPath, password, encAlg, authCode, url, debugMode)
{
    return new Promise((resolve, reject) => {
        // Error checks
        if (!fileUtil.exists(dirPath))
        {
            reject(`Error: ${dirPath} does not exist.`);
            return;
        }

        if (!fileUtil.isDir(dirPath))
        {
            reject(`Error: ${dirPath} is not a directory.`);
            return;
        }

        if (!fileUtil.canWrite(dirPath))
        {
            reject(`Error: Cannot write to directory ${dirPath}.`);
            return;
        }

        if (!cryptoUtil.supportedCiphers.includes(encAlg))
        {
            reject(`Error: ${encAlg} is not a supported encryption algorithm. It probably isn't the cipher used to encrypt the file you're downloading.`);
            return;
        }

        // Create progress bar and start it
        let progressBar = new SymmDLBar();
        progressBar.start();

        // Process SALT --> This is the hash of the URL
        let urlHash = cryptoUtil.genHash(url, 'sha3-256');

        //Download file from ftYeet
        fetch(`${HTTPS_TUNNEL}/download`, {
            method: 'GET',
            headers: {
                "url": url,
                "pwd-hash": cryptoUtil.genPwdHash(password, 64, urlHash),
                "Content-Type": "application/octet-stream"
            },
            follow: 1,
            agent: IGNORE_SSL_AGENT
        }).then((response) => {
            if (response.ok)
            {
                response.arrayBuffer().then(response => {

                    // ArrayBuffer != Buffer, so convert it
                    let fileSyntax = Buffer.from(response);

                    // Process file syntax
                    progressBar.increment();
                    let restored = cryptoUtil.fromFileSyntaxSymm(undefined, authCode, fileSyntax);

                    progressBar.increment();
                    let symmDec = cryptoUtil.symmetricDecrypt(password, authCode, restored.data, encAlg, restored.cryptoSystem);
                    let unFileConstruct = cryptoUtil.fromFileConstruct(symmDec.toString('utf-8'));

                    try
                    {
                        let filePath = resolve(dirPath, unFileConstruct.fileName);
                        fileUtil.writeFileUnique(filePath, unFileConstruct.fileContent);

                        progressBar.increment();
                        progressBar.stop();
                        console.log(`Successfully downloaded file with URL ${url}.`);
                        resolve();
                    }
                    catch(err)
                    {
                        try
                        {
                            fileUtil.writeFileUnique(`./${unFileConstruct.fileName}`, unFileConstruct.fileContent)
                            
                            // Might accidentally increment too much, but progressBar has a built-in limit, so we are fine.
                            progressBar.increment();
                            progressBar.stop();
                            console.error(`WARNING: Failed to write file ${filePath}: ${err}. Attempting to write to current dir.`);
                            console.log(`Successfully downloaded file with URL ${url}.`);
                            resolve();
                        }
                        catch(err2)
                        {
                            progressBar.stop();
                            reject(debugToggle(debugMode,
                                `Error when writing downloaded file to disk:\n\n${err2}.`,
                                `Error: Failed to write downloaded file to disk.`
                            ));
                            return;     // I know returns like this won't rly do anything but OCD moment
                        }
                    }

                }).catch(err => {
                    reject(debugToggle(debugMode,
                        `Error when decrypting and processing downloaded file: \n\n${err}`,
                        `Error: Unable to process downloaded file. Either you have the wrong password and auth code, or the uploaded file is corrupted.`
                    ));
                    return;
                });
            }
            else
            {
                response.text().then(err => {
                    progressBar.stop();
                    reject(`Error: Failed to download file from server. Error from server:\n\n${err}`);
                    return;
                }).catch(err => {
                    progressBar.stop();
                    reject(debugToggle(debugMode,
                        `Error when downloading file: Failed to download file from ftYeet server. Unable to parse error response from server. \n\n${err}`,
                        `Error: Failed to download file from ftYeet server.`
                    ));
                    return;
                });
            }
        }).catch(err => {
            progressBar.stop();
            reject(debugToggle(debugMode,
                `Error when sending fetch request to HTTP tunnel to download file: \n\n${err}`,
                `Error: Unable to download from ftYeet server.`
            ));
            return;
        });
    });
}

/**
 * Encrypts with RSA, digitally signs the ciphertext, and uploads a local file onto the ftYeet server. This requires you to know what you're doing.
 * @param {String} filePath Path to file we want to upload
 * @param {String} signKeyPath Key file for signing file
 * @param {String|undefined} signKeyPwd Password to decrypt `signKeyPath`, if any.
 * @param {String} encKeyPath Key file for encrypting file
 * @param {String} dsaPadding Padding for signing algorithm. Must be `RSA_PKCS1_PSS_PADDING` or `RSA_PKCS1_PADDING`.
 * @param {String} encPadding Padding for encryption algorithm. Must be `RSA_PKCS1_OAEP_PADDING` or `RSA_PKCS1_PADDING`.
 * @param {Number} expireTime How long should the ftYeet server hold on to your file (in seconds). Must be `>= 60`.
 * @param {Boolean} burnOnRead Whether ftYeet should delete the file immediately upon download
 * @param {Boolean} debugMode Whether to show debug errors or normal errors
 * @return {Promise<Void>} Resolves when upload is complete
 */
function uploadAsymm(filePath, signKeyPath, signKeyPwd, encKeyPath, dsaPadding, encPadding, expireTime, burnOnRead, debugMode)
{
    return new Promise((resolve, reject) => {
        if (expireTime < 60)
        {
            reject(`Error: expire-time must be longer than 60 seconds.`);
            return;
        }
        
        if (!fileUtil.exists(filePath))
        {
            reject(`Error: ${filePath} does not exist.`);
            return;
        }
        if (!fileUtil.isFile(filePath))
        {
            reject(`Error: ${filePath} is not a file.`);
            return;
        }

        if (!fileUtil.exists(signKeyPath))
        {
            reject(`Error: Key file ${signKeyPath} does not exist. Can't use a nonexistent file for digital signatures.`);
            return;
        }
        if (!fileUtil.isFile(signKeyPath))
        {
            reject(`Error: Key file ${signKeyPath} is not a file. Can't use a nonexistent file for digital signatures.`);
            return;
        }
        if (!fileUtil.canRead(signKeyPath))
        {
            reject(`Error: Can't read Key file ${signKeyPath}.`);
            return;
        }

        if (!fileUtil.exists(encKeyPath))
        {
            reject(`Error: Key file ${encKeyPath} does not exist. Can't use a nonexistent file for encryption.`);
            return;
        }
        if (!fileUtil.isFile(encKeyPath))
        {
            reject(`Error: Key file ${encKeyPath} is not a file. Can't use a nonexistent file for encryption.`);
            return;
        }
        if (!fileUtil.canRead(encKeyPath))
        {
            reject(`Error: Can't read Key file ${encKeyPath}.`);
            return;
        }

        // DSA Padding must be `RSA_PKCS1_PSS_PADDING` or `RSA_PKCS1_PADDING`
        if (dsaPadding.toUpperCase() == 'RSA_PKCS1_PSS_PADDING')
        {
            dsaPadding = constants.RSA_PKCS1_PSS_PADDING;
        }
        else if (dsaPadding.toUpperCase() == `RSA_PKCS1_PADDING`)
        {
            dsaPadding = constants.RSA_PKCS1_PADDING;
        }
        else
        {
            reject(`Error: Padding for signing algorithm ${dsaPadding.toUpperCase()} is not supported.`);
            return;
        }

        // EncPadding must be `RSA_PKCS1_OAEP_PADDING`
        // RSA_PKCS1_PADDING is no longer supported for private decryption
        if (encPadding.toUpperCase() == 'RSA_PKCS1_OAEP_PADDING')
        {
            encPadding = constants.RSA_PKCS1_OAEP_PADDING;
        }
        else
        {
            reject(`Error: Padding for encryption algorithm ${encPadding.toUpperCase()} is not supported.`); 
            return;
        }

        // Create progress bar and start it
        let progressBar = new AsymmULBar();
        progressBar.start();

        // Read keys and generate KeyObjects in case it isn't in .pem
        // 😠 Warning to future Justin: Do not specify an encoding if you want `fs.readFileSync()` to return a buffer
        // That stuff's for old Node.js (when Buffers didn't exist)
        let signKey;
        try
        {
            signKey = readFileSync(signKeyPath);
        }
        catch(err)
        {
            progressBar.stop();
            reject(debugToggle(debugMode,
                `Error when reading signing key file ${signKeyPath}: \n\n${err}`,
                `Error: Failed to read signing key file ${signKeyPath}.`
            ));
            return;
        }

        let signKeyObject;
        try
        {
            signKeyObject = cryptoUtil.genPrivKeyObject(signKey, signKeyPwd, true);
        }
        catch(err)
        {
            progressBar.stop();
            reject(debugToggle(debugMode,
                `Error when processing signing key file ${signKeyPath}: \n\n${err}` ,
                `Error: Failed to process signing key provided in ${signKeyPath}. Make sure it's formatted correctly and you provided the right decryption password.`
            ));
            return;
        }
        
        // Read the encryption key :D
        progressBar.increment();
        let encKey;
        try
        {
            encKey = readFileSync(encKeyPath);
        }
        catch(err)
        {
            progressBar.stop();
            reject(debugToggle(debugMode,
                `Error when reading encryption key file ${encKeyPath}: \n\n${err}`,
                `Error: Failed to read encryption key file ${encKeyPath}.`
            ));
            return;
        }

        let encKeyType = cryptoUtil.pubKeyType(encKey, false);
        if (encKeyType == 'none')
        {
            progressBar.stop();
            reject(`Error when uploading file: ${encKeyPath} is not a public key. For security reasons, you usually need to provide the other users' public key to encrypt the file.`); 
            return;
        }

            // Adjust encKeyType to get rid of -spki or -pkcs1
            // Hardcoding bc minimal user input good for security
        if (encKeyType == 'der-spki' || encKeyType == 'der-pkcs1')
        {
            encKeyType = 'der';
        }

        let encKeyObject;
        try
        {
            encKeyObject = cryptoUtil.genPubKeyObject(encKey, 'binary');
        }
        catch(err)
        {
            progressBar.stop();
            reject(debugToggle(debugMode,
                `Error when processing encryption key file ${encKeyPath}: \n\n${err}` ,
                `Error: Failed to process encryption key provided in ${encKeyPath}. The key is likely corrupted, or the format is likely unsupported.`
            ));
            return;
        }

        let plaintext;
        try
        {
            plaintext = readFileSync(filePath);
        }
        catch(err)
        {
            progressBar.stop();
            reject(debugToggle(debugMode,
                `Error when reading file ${filePath}: \n\n${err}`,
                `Error: Failed to read file ${filePath}.`
            ));
            return;
        }

        // Start encrypting
        let fileSyntax;
        try
        {
            // If they pass in a private key, it's fine too because Node.js specs can derive a public key from a private key so the results stay the same.
            // But hopefully, the end user knows how asymmetric encryption works. Which they should if they're running this CLI command.
            progressBar.increment();
            let fileConstruct = cryptoUtil.toFileConstruct(basename(filePath), Buffer.from(plaintext, 'utf-8'));
            let encrypted = publicEncrypt({key: encKeyObject, oaepHash: 'sha3-512', padding: encPadding}, fileConstruct);

            progressBar.increment();
            let signature = cryptoUtil.secureSign('sha3-512', encrypted, {key: signKeyObject, passphrase: signKeyPwd, padding: dsaPadding});

            progressBar.increment();
            let cryptosystem = cryptoUtil.genAsymmCryptosystem(signature, dsaPadding, encPadding, 'sha3-512');
            fileSyntax = cryptoUtil.toFileSyntaxAsymm(cryptosystem, encrypted, {key: signKeyObject, passphrase: signKeyPwd}, 'CLI');
        }
        catch(err)
        {
            progressBar.stop();   

            reject(debugToggle(debugMode,
                `Error when encrypting file ${filePath}: \n\n${err}`,
                `Error: Failed to encrypt file ${filePath}.`
            ));
            return;
        }

        progressBar.increment();
        
        // First, fetch a word for URL
        fetch(`${HTTPS_TUNNEL}/request`, {
            method: 'GET',
            follow: 1,
            agent: IGNORE_SSL_AGENT
        }).then((response) => {
            if (response.ok)
            {
                response.text().then(url => {
                    
                    // Send fetch request to website
                    progressBar.increment();
                    fetch(`${HTTPS_TUNNEL}/uploadAsymm`, {
                        method: 'POST',
                        headers: {
                            "expire-time": expireTime,
                            "burn-on-read": burnOnRead,
                            "public-key": cryptoUtil.keyToBase64(encKey, encKeyType),
                            "Content-Type": "application/octet-stream",
                            "url": url
                        },
                        body: fileSyntax,
                        follow: 1,
                        agent: IGNORE_SSL_AGENT
                    }).then((response2) => {
                        if (response2.ok)
                        {
                            progressBar.increment();
                            progressBar.stop();
                            console.log("Asymmetrically encrypted file has successfully been encrypted and uploaded.");

                            response2.text().then(text => {
                                console.log(`Your file can be accessed here with this URL: ${text}. Pass it into the download function.`);
                                resolve();
                                return;
                            }).catch(err => {
                                reject(debugToggle(debugMode,
                                    `Unexpected error when decoding URL: \n\n${err}`,
                                    `Error: Unable to retrieve file URL. For more information, enable debug mode.`
                                ));
                                return;         // Again, using return to keep things consistent. Logic-wise, this doesn't do anything.
                            });
                        }
                        else
                        {
                            response2.text().then(err => {
                                progressBar.stop();
                                reject(`Error: Failed to upload file to ftYeet server. Error from server:\n\n${err}`);
                                return;
                            }).catch(parseErr => {
                                progressBar.stop();
                                reject(debugToggle(debugMode,
                                    `Error when uploading file: Failed to upload file to ftYeet server. Unable to parse error response from server. \n\n${parseErr}`,
                                    `Error: Failed to upload file to ftYeet server.`
                                ));
                                return;
                            });
                        }
                    }).catch(err => {
                        progressBar.stop();
                        reject(debugToggle(debugMode,
                            `Error when sending fetch request to HTTP tunnel to upload file: \n\n${err}`,
                            `Error: Unable to upload to ftYeet server.`
                        ));
                        return;
                    });
                }).catch(err => {
                    progressBar.stop();
                    reject(debugToggle(debugMode,
                        `Error reading URL response: \n\n${err}`,
                        `Error: Unable to read URL response from ftYeet server.`
                    ));
                    return;
                });
            }
            else
            {
                response.text().then(err => {
                    progressBar.stop();
                    reject(`Error: Failed to request upload URL from server. Error from server:\n\n${err}`);
                    return;
                }).catch(parseErr => {
                    progressBar.stop();
                    reject(debugToggle(debugMode,
                        `Error when requesting upload URL: Failed to request upload URL from ftYeet server. Unable to parse error response from server. \n\n${parseErr}`,
                        `Error: Failed to request upload URL from ftYeet server.`
                    ));
                    return;
                });
            }
        }).catch(err => {
            progressBar.stop();
            reject(debugToggle(debugMode,
                `Error when sending fetch request to HTTP tunnel to request upload URL: \n\n${err}`,
                `Error: Unable to request upload URL from ftYeet server.`
            ));
            return;
        });
    });
}

/**
 * Decrypts, verifies, and downloads a file from the ftYeet server
 * @param {String} dirPath Directory to download file into
 * @param {String} url URL where the resource/file is stored on the ftYeet server
 * @param {String} verifyKeyPath Key file for verifying file signatures
 * @param {String} decKeyPath Key file for decrypting file contents
 * @param {String|undefined} decKeyPwd Password fo decrypt `decKeyPath`, if any.
 * @param {Boolean} debugMode Whether to show debug errors or normal errors
 * @returns {Promise<Void>} Resolves when download is complete
 */
function downloadAsymm(dirPath, url, verifyKeyPath, decKeyPath, decKeyPwd, debugMode)
{
    return new Promise((resolve, reject) => {
        // Error checks
        if (!fileUtil.exists(dirPath))
        {
            reject(`Error: ${dirPath} does not exist.`);
            return;
        }
        if (!fileUtil.isDir(dirPath))
        {
            reject(`Error: ${dirPath} is not a directory.`);
            return;
        }
        if (!fileUtil.canWrite(dirPath))
        {
            reject(`Error: Cannot write to directory ${dirPath}.`);
            return;
        }

        if (!fileUtil.exists(decKeyPath))
        {
            reject(`Error: Key file ${decKeyPath} does not exist. Can't use a nonexistent file for decryption.`);
            return;
        }
        if (!fileUtil.isFile(decKeyPath))
        {
            reject(`Error: Key file ${decKeyPath} is not a file. Can't use a nonexistent file for decryption.`);
            return;
        }
        if (!fileUtil.canRead(decKeyPath))
        {
            reject(`Error: Can't read Key file ${decKeyPath}.`);
            return;
        }

        if (!fileUtil.exists(verifyKeyPath))
        {
            reject(`Error: Key file ${verifyKeyPath} does not exist. Can't use a nonexistent file for digital signatures.`);
            return;
        }
        if (!fileUtil.isFile(verifyKeyPath))
        {
            reject(`Error: Key file ${verifyKeyPath} is not a file. Can't use a nonexistent file for digital signatures.`);
            return;
        }
        if (!fileUtil.canRead(verifyKeyPath))
        {
            reject(`Error: Can't read Key file ${verifyKeyPath}.`);
            return;
        }

        // Create progress bar and start it
        let progressBar = new AsymmDLBar();
        progressBar.start();
            
        // Read keys and generate key objects
        let verifyKey;
        try
        {
            verifyKey = readFileSync(verifyKeyPath);
        }
        catch(err)
        {
            progressBar.stop();
            reject(debugToggle(debugMode,
                `Error when reading verifying key file ${verifyKeyPath}: \n\n${err}`,
                `Error: Failed to read verifying key file ${verifyKeyPath}.`
            ));
            return;
        }

        let verifyKeyObject;
        try
        {
            verifyKeyObject = cryptoUtil.genPubKeyObject(verifyKey, 'binary');
        }
        catch(err)
        {
            progressBar.stop();
            reject(debugToggle(debugMode,
                `Error when processing verifying key file ${verifyKeyPath}: \n\n${err}` ,
                `Error: Failed to process verifying key provided in ${verifyKeyPath}. Make sure it's formatted correctly.`
            ));
            return;
        }

        progressBar.increment();
        let decKey;
        try
        {
            decKey = readFileSync(decKeyPath);
        }
        catch(err)
        {
            progressBar.stop();
            reject(debugToggle(debugMode,
                `Error when reading decryption key file ${decKeyPath}: \n\n${err}`,
                `Error: Failed to read decryption key file ${decKeyPath}.`
            )); 
            return;
        }

        let decKeyObject;
        try
        {
            decKeyObject = cryptoUtil.genPrivKeyObject(decKey, decKeyPwd, true);
        }
        catch(err)
        {
            progressBar.stop();
            reject(debugToggle(debugMode,
                `Error when processing decryption key file ${decKeyPath}: \n\n${err}`,
                `Error: Failed to process decryption key provided in ${decKeyPath}. Make sure it's formatted correctly and that you provided the right decryption password.`
            ));
            return;
        }
        
        // First, authenticate
        progressBar.increment();
        
        fetch(`${HTTPS_TUNNEL}/getAuth`, {
            method: 'GET',
            headers: {
                url: url
            },
            follow: 1,
            agent: IGNORE_SSL_AGENT
        }).then((response) => {
            if (response.ok)
            {
                response.arrayBuffer().then(challengeAB => {

                    // ArrayBuffer != Buffer, so convert it
                    let challenge = Buffer.from(challengeAB);
                    let signedChallenge = cryptoUtil.secureSign('sha3-512', challenge, {key: decKeyObject, passphrase: decKeyPwd, padding: constants.RSA_PKCS1_PSS_PADDING});

                    // Now, actually fetch the file
                    progressBar.increment();
                    fetch(`${HTTPS_TUNNEL}/downloadAsymm`, {
                        method: 'GET',
                        headers: {
                            url: url,
                            "signed-challenge": signedChallenge
                        },
                        follow: 1,
                        agent: IGNORE_SSL_AGENT
                    }).then((response2) => {
                        if (response2.ok)
                        {
                            response2.arrayBuffer().then(fileSyntaxAB => {

                                // ArrayBuffer != Buffer, so convert it
                                let fileSyntax = Buffer.from(fileSyntaxAB);

                                // Fetch file syntax
                                progressBar.increment();
                                let restored = cryptoUtil.fromFileSyntaxAsymm({key: verifyKeyObject}, fileSyntax);

                                progressBar.increment();
                                let plaintext = privateDecrypt({key: decKeyObject, oaepHash: restored.cryptoSystem.oaepHash, padding: restored.cryptoSystem.encryptPadding, passphrase: decKeyPwd}, restored.data);
                                let unFileConstruct = cryptoUtil.fromFileConstruct(plaintext.toString('utf-8'));

                                // Write the file!
                                // Doing it recursively to prevent overwrites
                                progressBar.increment();
                                let filePath = resolve(dirPath, unFileConstruct.fileName);

                                try
                                {
                                    fileUtil.writeFileUnique(filePath, unFileConstruct.fileContent);

                                    progressBar.increment();
                                    progressBar.stop();
                                    console.log(`Successfully downloaded file with URL ${url}.`);

                                    resolve();
                                    return;
                                }
                                catch(err)
                                {
                                    try
                                    {
                                        fileUtil.writeFileUnique(`./${unFileConstruct.fileName}`, unFileConstruct.fileContent)
                                        
                                        // Might accidentally increment too much, but progressBar has a built-in limit, so we are fine.
                                        progressBar.increment();
                                        progressBar.stop();
                                        console.error(`WARNING: Failed to write file ${filePath}: ${err}. Attempting to write to current dir.`);
                                        console.log(`Successfully downloaded file with URL ${url}.`);

                                        resolve();
                                        return;
                                    }
                                    catch(err2)
                                    {
                                        progressBar.stop();
                                        reject(debugToggle(debugMode,
                                            `Error when writing downloaded file to disk:\n\n${err2}.`,
                                            `Error: Failed to write downloaded file to disk.`
                                        ));
                                        return;
                                    }
                                }
                            }).catch(err => {
                                progressBar.stop();
                                reject(debugToggle(debugMode,
                                    `Error when decrypting file: \n\n${err}`,
                                    `Error: Unable to decrypt downloaded file. Either you have the wrong decryption and signing key, or the uploaded file is corrupted.`
                                ));
                                return;
                            });
                        }
                        else
                        {
                            response2.text().then(err => {
                                progressBar.stop();
                                reject(`Error: Failed to download file from server. Error from server:\n\n${err}`);
                                return;
                            }).catch(err => {
                                progressBar.stop();
                                reject(debugToggle(debugMode,
                                    `Error when downloading file: Failed to download file from ftYeet server. Unable to parse error response from server. \n\n${err}`,
                                    `Error: Failed to download file from ftYeet server.`
                                ));
                                return;
                            })
                        }
                    });
                });
            }
            else
            {
                response.text().then(err => {
                    progressBar.stop();
                    reject(debugToggle(debugMode,
                        `Error when authenticating download: Failed to authenticate with ftYeet server. Error from server:\n\n${err}`,
                        `Error: Failed to authenticate with ftYeet server. You likely had the wrong decryption key.`
                    ));
                    return;
                }).catch(err => {
                    progressBar.stop();
                    reject(debugToggle(debugMode,
                        `Error when authenticating download: Failed to authenticate with ftYeet server. Unable to parse error response from server. \n\n${err}`,
                        `Error: Failed to authenticate with ftYeet server.`
                    ));
                    return;
                });
            }
        }).catch(err => {
            progressBar.stop();
            reject(debugToggle(debugMode,
                `Error when sending fetch request to HTTP tunnel to authenticate download: \n\n${err}`,
                `Error: Unable to authenticate download from ftYeet server.`
            ));
            return;
        });
    });
}
// To declutter main.js, this handles all the important CLI functions
// Justin notation: () => {} if there's no side effects. function() {} if there is.

// 🔊 Note to self when you get back: Work on fixing base64 decrypt over in the server to support jwk and der
import * as cryptoUtil from '../Common/crypto_util.js';
import * as fileUtil from '../Common/file_util.js';
import fetch from 'node-fetch';
import { writeFileSync, readFileSync } from 'node:fs';
import { constants, publicEncrypt, privateDecrypt } from 'node:crypto';
import { dirname, basename, resolve } from 'node:path';
import { Agent } from 'https';

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
    // TODO: If RSA, make it 4096 
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
 */
function uploadSymm(filePath, password, encAlg, authCode, expireTime, burnOnRead)
{  
    if (expireTime < 60)
    {
        throw `Error when uploading file: expire-time must be longer than 60 seconds.`;
    }

    if (!fileUtil.exists(filePath))
    {
        throw `Error when uploading file: ${filePath} does not exist.`;
    }

    if (!fileUtil.isFile(filePath))
    {
        throw `Error when uploading file: ${filePath} is not a file.`;
    }

    if (!fileUtil.canRead(filePath))
    {
        throw `Error when uploading file: Cannot read contents of ${filePath}.`;
    }

    if (!cryptoUtil.supportedCiphers.includes(encAlg))
    {
        throw `Error when uploading file: ${encAlg} is not a supported encryption algorithm.`;
    }

    // First, fetch a word
    fetch(`${HTTPS_TUNNEL}/request`, {
        method: 'GET',
        follow: 1,
        agent: IGNORE_SSL_AGENT
    }).then((response) => {
        if (response.ok)
        {
            response.text().then(salt => {
                // Read file contents as buffer
                let plaintext;
                try
                {
                    plaintext = readFileSync(filePath)
                }
                catch(err)
                {
                    throw `Error when uploading file: Failed to read file ${filePath}. ${err};`;
                }
                
                // Symmetrically encrypt and HMAC the file path and name (using the file construct structure we came up with)
                let fileConstruct = cryptoUtil.toFileConstruct(basename(filePath), plaintext);
                let symmEnc = cryptoUtil.symmetricEncrypt(password, authCode, Buffer.from(fileConstruct, 'utf-8'), encAlg, encAlg == 'aes-256-cbc' ? 16 : 12);
                
                let ciphertext = symmEnc.ciphertext;
                delete symmEnc.ciphertext;

                // Convert to file syntax
                let hmacCryptosys = cryptoUtil.secureKeyGen(authCode, 32, symmEnc.hmacSalt);
                let fileSyntax = cryptoUtil.toFileSyntaxSymm(symmEnc, ciphertext, hmacCryptosys, 'CLI');
                
                // Generate SALT to hash password with --> This is the hash of the URL
                let urlHash = cryptoUtil.genHash(salt, 'sha3-256');

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
                        console.log("File successfully encrypted and uploaded.");
                        response2.text().then(text => {
                            console.log(`Your file can be accessed here with this URL: ${text}. Pass it into the download function.`);
                        });
                    }
                    else
                    {
                        response2.text().then(err => {
                            throw err;
                        });
                    }
                }).catch(err => {
                    throw `Error when uploading file: ${err}`;
                });
            });
        }
        else
        {
            response.text().then(err => {
                throw err;
            });
        }
    }).catch(err => {
        throw `Error when uploading file: ${err}`;
    });
}

/**
 * Encrypts, HMACs, and uploads a local file onto the ftYeet server
 * @param {String} dirPath Directory you want to put the downloaded file in 
 * @param {String} password Password to generate decryption key
 * @param {String} encAlg Encryption/Decryption algorithm
 * @param {String} authCode Password to generate HMAC key
 * @param {String} url The ftYeet URL where the file is stored
 */
function downloadSymm(dirPath, password, encAlg, authCode, url)
{
    // Error checks
    if (!fileUtil.exists(dirPath))
    {
        throw `Error when downloading file: ${dirPath} does not exist.`;
    }

    if (!fileUtil.isDir(dirPath))
    {
        throw `Error when downloading file: ${dirPath} is not a directory.`;
    }

    if (!fileUtil.canWrite(dirPath))
    {
        throw `Error when downloading file: Cannot write to directory ${dirPath}.`;
    }

    if (!cryptoUtil.supportedCiphers.includes(encAlg))
    {
        throw `Error when downloading file: ${encAlg} is not a supported encryption algorithm. It probably isn't the cipher used to encrypt the file you're downloading.`;
    }

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
                let restored = cryptoUtil.fromFileSyntaxSymm(undefined, authCode, fileSyntax);
                let symmDec = cryptoUtil.symmetricDecrypt(password, authCode, restored.data, encAlg, restored.cryptoSystem);
                let unFileConstruct = cryptoUtil.fromFileConstruct(symmDec.toString('utf-8'));
                
                // Write the file!
                // Doing it recursively to prevent overwrites
                let filePath = resolve(dirPath, unFileConstruct.fileName);
                fileUtil.writeFileUnique(filePath, unFileConstruct.fileContent);
                
                console.log(`Successfully downloaded file with URL ${url}.`);
            });
        }
        else
        {
            response.text().then(err => {
                throw `Error when downloading file: ${err}`;
            });
        }
    }).catch(err => {
        throw `Error when downloading file: ${err}`;
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
 * @futureParam {String} oaepHash OAEP hashing algorithm to use. Must be in the list of supported hashes. Might toggle it on in the future but for security I might lock them into SHA3-512.
 */
function uploadAsymm(filePath, signKeyPath, signKeyPwd, encKeyPath, dsaPadding, encPadding, expireTime, burnOnRead)
{
    if (expireTime < 60)
    {
        throw `Error when uploading file: expire-time must be longer than 60 seconds.`;
    }
    
    if (!fileUtil.exists(filePath))
    {
        throw `Error when uploading file: ${filePath} does not exist.`;
    }
    if (!fileUtil.isFile(filePath))
    {
        throw `Error when uploading file: ${filePath} is not a file.`;
    }

    if (!fileUtil.exists(signKeyPath))
    {
        throw `Error when uploading file: Key file ${signKeyPath} does not exist. Can't use a nonexistent file for digital signatures.`;
    }
    if (!fileUtil.isFile(signKeyPath))
    {
        throw `Error when uploading file: Key file ${signKeyPath} is not a file. Can't use a nonexistent file for digital signatures.`;
    }
    if (!fileUtil.canRead(signKeyPath))
    {
        throw `Error when uploading file: Can't read Key file ${signKeyPath}.`;
    }

    if (!fileUtil.exists(encKeyPath))
    {
        throw `Error when uploading file: Key file ${encKeyPath} does not exist. Can't use a nonexistent file for encryption.`;
    }
    if (!fileUtil.isFile(encKeyPath))
    {
        throw `Error when uploading file: Key file ${encKeyPath} is not a file. Can't use a nonexistent file for encryption.`;
    }
    if (!fileUtil.canRead(encKeyPath))
    {
        throw `Error when uploading file: Can't read Key file ${encKeyPath}.`;
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
        throw `Error when uploading file: Padding for signing algorithm ${dsaPadding.toUpperCase()} is not supported.`; 
    }

    // EncPadding must be `RSA_PKCS1_OAEP_PADDING` or `RSA_PKCS1_PADDING`
    if (encPadding.toUpperCase() == 'RSA_PKCS1_OAEP_PADDING')
    {
        encPadding = constants.RSA_PKCS1_OAEP_PADDING;
    }
    else if (dsaPadding.toUpperCase() == `RSA_PKCS1_PADDING`)
    {
        encPadding = constants.RSA_PKCS1_PADDING;
    }
    else
    {
        throw `Error when uploading file: Padding for signing algorithm ${dsaPadding.toUpperCase()} is not supported.`; 
    }

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
        throw `Error when uploading file: ${err}`; 
    }

    let signKeyObject;
    try
    {
        signKeyObject = cryptoUtil.genPrivKeyObject(signKey, signKeyPwd, true);
    }
    catch(err)
    {
        throw `Error when uploading file: ${err}`; 
    }

    let encKey;
    try
    {
        encKey = readFileSync(encKeyPath);
    }
    catch(err)
    {
        throw `Error when uploading file: Failed to read key file ${encKeyPath}. ${err}`; 
    }

    let encKeyType = cryptoUtil.pubKeyType(encKey, false);
    if (encKeyType == 'none')
    {
        throw `Error when uploading file: ${encKeyPath} is not a public key.`; 
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
        throw `Error when uploading file: ${err}`; 
    }

    let plaintext;
    try
    {
        plaintext = readFileSync(filePath);
    }
    catch(err)
    {
        throw `Error when uploading file: Failed to read file ${filePath}. ${err}`; 
    }

    // Start encrypting
    let fileSyntax;
    try
    {
        // If they pass in a private key, it's fine too because Node.js specs can derive a public key from a private key so the results stay the same.
        // But hopefully, the end user knows how asymmetric encryption works. Which they should if they're running this CLI command.

        let fileConstruct = cryptoUtil.toFileConstruct(basename(filePath), Buffer.from(plaintext, 'utf-8'));
        let encrypted = publicEncrypt({key: encKeyObject, oaepHash: 'sha3-512', padding: encPadding}, fileConstruct);
        let signature = cryptoUtil.secureSign('sha3-512', encrypted, {key: signKeyObject, passphrase: signKeyPwd, padding: dsaPadding});

        let cryptosystem = cryptoUtil.genAsymmCryptosystem(signature, dsaPadding, encPadding, 'sha3-512');
        fileSyntax = cryptoUtil.toFileSyntaxAsymm(cryptosystem, encrypted, {key: signKeyObject, passphrase: signKeyPwd}, 'CLI');
    }
    catch(err)
    {
        throw `Error when uploading file: Failed to encrypt file. ${err}`;
    }

    // Send fetch request to website
    fetch(`${HTTPS_TUNNEL}/uploadAsymm`, {
        method: 'POST',
        headers: {
            "expire-time": expireTime,
            "burn-on-read": burnOnRead,
            "public-key": cryptoUtil.keyToBase64(encKey, encKeyType),
            "Content-Type": "application/octet-stream"
        },
        body: fileSyntax,
        follow: 1,
        agent: IGNORE_SSL_AGENT
    }).then((response) => {
        if (response.ok)
        {
            console.log("File successfully encrypted and uploaded.");
            response.text().then(text => {
                console.log(`Server Response: ${text}`);
            });
        }
        else
        {
            response.text().then(err => {
                console.error(err);
            });
        }
    }).catch(err => {
        console.error(`Error when uploading file: ${err}`);
    });
}

/**
 * Decrypts, verifies, and downloads a file from the ftYeet server
 * @param {String} dirPath Directory to download file into
 * @param {String} url URL where the resource/file is stored on the ftYeet server
 * @param {String} verifyKeyPath Key file for verifying file signatures
 * @param {String|undefined} verifyKeyPwd Password to decrypt `verifyKeyPath`, if any.
 * @param {String} decKeyPath Key file for decrypting file contents
 * @param {String|undefined} decKeyPwd Password fo decrypt `decKeyPath`, if any.
 */
function downloadAsymm(dirPath, url, verifyKeyPath, verifyKeyPwd, decKeyPath, decKeyPwd)
{
    // test
    let fileSyntax = readFileSync('./bye.txt');

    // Error checks
    if (!fileUtil.exists(dirPath))
    {
        throw `Error when downloading file: ${dirPath} does not exist.`;
    }
    if (!fileUtil.isDir(dirPath))
    {
        throw `Error when downloading file: ${dirPath} is not a directory.`;
    }
    if (!fileUtil.canWrite(dirPath))
    {
        throw `Error when downloading file: Cannot write to directory ${dirPath}.`;
    }

    if (!fileUtil.exists(decKeyPath))
    {
        throw `Error when downloading file: Key file ${decKeyPath} does not exist. Can't use a nonexistent file for decryption.`;
    }
    if (!fileUtil.isFile(decKeyPath))
    {
        throw `Error when downloading file: Key file ${decKeyPath} is not a file. Can't use a nonexistent file for decryption.`;
    }
    if (!fileUtil.canRead(decKeyPath))
    {
        throw `Error when downloading file: Can't read Key file ${decKeyPath}.`;
    }

    if (!fileUtil.exists(verifyKeyPath))
    {
        throw `Error when downloading file: Key file ${verifyKeyPath} does not exist. Can't use a nonexistent file for digital signatures.`;
    }
    if (!fileUtil.isFile(verifyKeyPath))
    {
        throw `Error when downloading file: Key file ${verifyKeyPath} is not a file. Can't use a nonexistent file for digital signatures.`;
    }
    if (!fileUtil.canRead(verifyKeyPath))
    {
        throw `Error when downloading file: Can't read Key file ${verifyKeyPath}.`;
    }
        
    // Read keys and generate key objects
    let verifyKey;
    try
    {
        verifyKey = readFileSync(verifyKeyPath, {encoding: 'binary'});
    }
    catch(err)
    {
        throw `Error when uploading file: Failed to read key file ${verifyKeyPath}. ${err}`; 
    }

    let verifyKeyObject;
    try
    {
        verifyKeyObject = cryptoUtil.genPubKeyObject(verifyKey, 'binary');
    }
    catch(err)
    {
        throw `Error when uploading file: ${err}`; 
    }

    let decKey;
    try
    {
        decKey = readFileSync(decKeyPath, {encoding: 'binary'});
    }
    catch(err)
    {
        throw `Error when uploading file: Failed to read key file ${decKeyPath}. ${err}`; 
    }

    let decKeyObject;
    try
    {
        decKeyObject = cryptoUtil.genPrivKeyObject(decKey, true);
    }
    catch(err)
    {
        throw `Error when uploading file: ${err}`; 
    }

    // Fetch file syntax
    let restored = cryptoUtil.fromFileSyntaxAsymm({key: verifyKeyObject, passphrase: verifyKeyPwd}, fileSyntax);
    let plaintext = privateDecrypt({key: decKeyObject, oaepHash: restored.cryptoSystem.oaepHash, padding: restored.cryptoSystem.encryptPadding, passphrase: decKeyPwd}, restored.data);
    let unFileConstruct = cryptoUtil.fromFileConstruct(plaintext.toString('utf-8'));

    // Write to file
    writeFileSync(`${dirPath}/${unFileConstruct.fileName}`, unFileConstruct.fileContent);
}
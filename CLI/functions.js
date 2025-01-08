// To declutter main.js, this handles all the important CLI functions
// Justin notation: () => {} if there's no side effects. function() {} if there is.
import * as cryptoUtil from '../Common/crypto_util.js';
import * as fileUtil from '../Common/file_util.js';
import { writeFileSync, readFileSync, read } from 'node:fs';
import { dirname } from 'node:path';

export { keygen, uploadSymm }

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

    // Generate keypairs + write them to files
    let keyPair = cryptoUtil.genKeyPair(encryptAlg, options);

    try
    {
        writeFileSync(pubkeyPath, keyPair.publicKey);
        writeFileSync(privkeyPath, keyPair.privateKey);
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
 */
function uploadSymm(filePath, password, encAlg, authCode)
{
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

    // Read file contents as buffer
    let plaintext;
    try
    {
        plaintext = readFileSync(filePath)
    }
    catch(err)
    {
        throw `Error when uploading file: Failed to read file ${filePath}. ${err.message};`;
    }
    
    // Symmetrically encrypt and HMAC file
    let symmEnc = cryptoUtil.symmetricEncrypt(password, authCode, plaintext, encAlg, encAlg == 'aes-256-cbc' ? 16 : 12);
    
    let ciphertext = symmEnc.ciphertext;
    delete symmEnc.ciphertext;

    // Convert to file syntax
    let hmacCryptosys = cryptoUtil.secureKeyGen(authCode, 32, symmEnc.hmacSalt);
    let fileSyntax = cryptoUtil.toFileSyntaxSymm(symmEnc, ciphertext, hmacCryptosys, 'CLI');
    
    // Test. This should ideally just clone the two files
    // Remove when testing is done
    downloadSymm('./', password, encAlg, authCode, '', fileSyntax);
}

/**
 * Encrypts, HMACs, and uploads a local file onto the ftYeet server
 * @param {String} dirPath Directory you want to put the downloaded file in 
 * @param {String} password Password to generate decryption key
 * @param {String} encAlg Encryption/Decryption algorithm
 * @param {String} authCode Password to generate HMAC key
 * @param {String} url The ftYeet URL where the file is stored
 * @param {String} fileSyntax 🛠️ TESTING ONLY - REMOVE WHEN DONE
 */
function downloadSymm(dirPath, password, encAlg, authCode, url, fileSyntax)
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

    //Download file from ftYeet

    // Clientside decryption
    // First, parse file syntax
    let restored = cryptoUtil.fromFileSyntaxSymm(undefined, authCode, fileSyntax);

    // Decrypt the restored data. The decryption function checks the HMACs for us
    let plaintext;
    
    try
    {
        plaintext = cryptoUtil.symmetricDecrypt(password, authCode, restored.data, encAlg, restored.cryptoSystem);
    }
    catch(err)
    {
        throw `Error when downloading file: Failed to decrypt file. \n${err.message}`;
    }

    // Write to file
    writeFileSync(`${dirPath}/test_output.txt`, plaintext);
}
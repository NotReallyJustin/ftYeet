// To declutter main.js, this handles all the important CLI functions
// Justin notation: () => {} if there's no side effects. function() {} if there is.
import * as cryptoUtil from '../Common/crypto_util.js';
import * as fileUtil from '../Common/file_util.js';
import { writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

export { keygen }

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
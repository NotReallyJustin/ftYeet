// To declutter main.js, this handles all the important CLI functions
// Justin notation: () => {} if there's no side effects. function() {} if there is.
import * as cryptoUtil from '../Common/crypto_util';
export { keygen }

/**
 * Generates a public/private keypair and writes it to a given file
 * @param {String} filePath File path to write keypairs to
 * @param {String} encryptAlg Asymmetric encryption algorithm to generate keypairs for. Must be in the list of supportedAsymmetrics. Users should know about the options from the CLI.
 * @param {JSON} options Node.js options for your asymmetric encryption alg
 * @see `cryptoUtil.genKeyPair()`
 */
function keygen(filePath, encryptAlg, options)
{

}
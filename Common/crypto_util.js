// Node.js built-in crypto library (should be decently secure)
// Providing all functions I'm using here for transparency reasons
const { 
    createHmac,
    sign,
    randomBytes,
    createHash,
    privateDecrypt,
    privateEncrypt,
    publicDecrypt,
    publicEncrypt,
    verify,
    getCiphers,
    getHashes,
    generateKeyPairSync,
    scryptSync,
    createCipheriv,
    createDecipheriv,
    constants
} = await import('node:crypto');

export { supportedCiphers, supportedAsymmetrics, secureKeyGen, zeroBuffer }

/**
 * List of supported Ciphers. See `planning.md` if you're curious.
 * TODO: Maybe add their supported iv lengths here too
 */
const supportedCiphers = [
    'chacha20-poly1305',
    'aes-256-gcm',
    'aes-256-cbc'
]

/**
 * List of supported algorithms for asymmetric key generation.
 * These could be for encryption, signing, or key exchange.
 */
const supportedAsymmetrics = [
    'rsa',
    'dsa',
    'ed25519',
    'x25519'
]

/**
 * Zeroes out a buffer. A bit unnecessary but it takes 2 seconds and does a tad bit of anti-forensics
 * @param {Buffer} buffer The buffer to zero out
 */
function zeroBuffer(buffer)
{
    buffer.fill(0);
}

/**
 * Synchronously generates a key using SCrypt (`N=2^14, r=8, p=16`). The user shouldn't have control over `N,r,p` since they change the resulting key. 
 * But as a developer, feel free to do things like change `N` to `2^20` for security reasons. I stuck to 2^14 because Node.js will complain that I've exceeded the memory limit
 * @param {String} password User password used to generate encryption keys. 🚨 Weakest part of the whole program. Consider using things like lockouts/rate limits to secure this 🚨
 * @param {Number} length Length of Key and SALT in bytes. If you're picky about Node.js yapping about `NIST SP 800-132`, all the Ciphers require > 16 bytes
 * @param {String} [salt] `[Optional]` Set the SALT (hex). This is usually used when decrypting. If you're encrypting something, **leave this variable alone**.
 * @throws If Key and SALT is not `>= 16 bytes`. But realistically, it should always be `>= 32 bytes` because of our Ciphers
 * @returns {{key: String, salt: String}} JSON object with key and salt in hex
 */
const secureKeyGen = (password, length, salt) => {

    if (length < 16 || (salt != undefined && salt.length < 16 * 2))
    {
        throw "Key and SALT must be >= 16 bytes.";
    }
    // to do: salt currently in ascii. make it hex
    let randomSalt = salt != undefined ? Buffer.from(salt, 'hex') : randomBytes(length);
    let key = scryptSync(password, randomSalt, length, {N: 16384, p:16}); // Other values are defaulted
    
    const keyPair = {
        key: key.toString('hex'),
        salt: randomSalt.toString('hex')
    }

    zeroBuffer(randomSalt);
    zeroBuffer(key);

    return keyPair;
}

/**
 * Symmetrically encrypts a binary buffer, and then runs a HMAC.
 * The ciphertext is returned as a binary buffer because presumably, this will get written to a file. You are responsible for zeroing the buffer and converting the binary if needed
 * @param {String} password User password used to generate encryption keys. 🚨 Weakest part of the whole program. Consider using things like lockouts/rate limits to secure this 🚨
 * @param {String} hmacPassword An "authentication code" we put into the KDF to generate a key for HMACs. If it's undefined, we use `password` with another random SALT
 * @param {Buffer} plaintext Binary plaintext to encrypt
 * @param {String} encryptAlg Encryption Algorithm. Must be in the list of `supportedCiphers`
 * @param {Number} [ivLength=12] Length of the randomly generated iv. This defaults to 12 bytes because Node requires that for `chacha` and `aes-gcm`, but you can modify it later down the line
 * @throws If cipher is not supported
 * @returns {{ciphertext: Buffer, encIV: String, encSalt: String, encAuthTag: String, hmac: String, hmacSalt: String}} Results from encryption oracle
 */
const symmetricEncrypt = (password, hmacPassword, plaintext, encryptAlg, ivLength) => {

    if (!supportedCiphers.includes(encryptAlg))
    {
        throw "Unsupported Cipher. Check `supportedCiphers` in `crypto_util.js` for a list.";
    }

    // Encrypt first
    let encSecrets = secureKeyGen(password, 32);
    let iv = randomBytes(ivLength != undefined ? ivLength : 12);                     // Binary buffer
    let encCipher = createCipheriv(encryptAlg, Buffer.from(encSecrets.key, 'hex'), iv);

    let cipBuffer1 = encCipher.update(plaintext);
    let cipBuffer2 = encCipher.final();
    let ciphertext = Buffer.concat([cipBuffer1, cipBuffer2]);

        // Some ciphers have an auth tag on top of the HMAC we'll do later --> buffer
    let authtag = encryptAlg == 'chacha20-poly1305' || encryptAlg == 'aes-256-gcm' ? encCipher.getAuthTag() : undefined; 

    // Then HMAC
    let hmacSecrets = secureKeyGen(hmacPassword != undefined ? hmacPassword : password, 32);
    let hmacCipher = createHmac('sha3-512', Buffer.from(hmacSecrets.key, 'hex'));
    
    hmacCipher.update(ciphertext);
    let hmac = hmacCipher.digest('hex');

    // JSON return
    let cryptoSystem = {
        ciphertext: ciphertext,
        // encKey: encSecrets.key,          // Only uncomment this for debugging purposes
        encIV: iv.toString('hex'),
        encSalt: encSecrets.salt,
        encAuthTag: authtag == undefined || authtag.length == 0 ? undefined : authtag.toString('hex'),
        hmac: hmac,
        hmacSalt: hmacSecrets.salt
    }

    zeroBuffer(iv);
    zeroBuffer(cipBuffer1);
    zeroBuffer(cipBuffer2);
    if (authtag != undefined)
    {
        zeroBuffer(authtag);
    }

    return cryptoSystem;
}

/**
 * Symmetrically decrypts a binary buffer. This also validates with an AuthTag and HMAC before even attempting to decrypt.
 * The plaintext is returned a binary because presumably, it'll be written to a file. You are responsible for zeroing the buffer and converting the binary if needed
 * @param {String} password User password used to generate keys during the encryption step.
 * @param {String} hmacPassword The "authentication code" you put into the KDF to generate a key for HMACs when encrypting. If it's undefined, we use `password`. 
 * @param {Buffer} ciphertext Binary ciphertext to decrypt. ✏️ You could free this buffer if you want to
 * @param {String} decryptAlg Decryption Algorithm. Must be in the list of `supportedCiphers`
 * @param {{encIV: String, encSalt: String, encAuthTag: String, hmac: String, hmacSalt: String}} cryptoSystem A JSON with the encryption IV, encSalt, and more. It's the cryptoSystem returned by `symmEncrypt()`.
 * @returns {Buffer} The plaintext. You are responsible for freeing this buffer should you feel like it.
 */
const symmetricDecrypt = (password, hmacPassword, ciphertext, decryptAlg, cryptoSystem) => {

    if (!supportedCiphers.includes(decryptAlg))
    {
        throw "Unsupported Cipher. Check `supportedCiphers` in `crypto_util.js` for a list.";
    }
    
    // First, check the HMAC
    let hmacSecrets = secureKeyGen(hmacPassword != undefined ? hmacPassword : password, 32, cryptoSystem.hmacSalt);
    let hmacCipher = createHmac('sha3-512', Buffer.from(hmacSecrets.key, 'hex'));
    
    hmacCipher.update(ciphertext);
    let currHMAC = hmacCipher.digest('hex');

    if (currHMAC != cryptoSystem.hmac)
    {
        throw "Invalid HMAC for ciphertext. Your ciphertext might have been tampered with. Aborting decryption now...";
    }

    // Now we can move onto decrypting
    let decSecrets = secureKeyGen(password, 32, cryptoSystem.encSalt);
    let decCipher = createDecipheriv(decryptAlg, Buffer.from(decSecrets.key, 'hex'), Buffer.from(cryptoSystem.encIV, 'hex'));
    if (cryptoSystem.encAuthTag != undefined)
    {
        decCipher.setAuthTag(cryptoSystem.encAuthTag, 'hex');
    }

    let decBuffer1 = decCipher.update(ciphertext);
    let decBuffer2;         // Will be a buffer

    try         // decCipher might throw an error if the AuthTag does not match. This is a built-in security feature/integrity check
    {
        decBuffer2 = decCipher.final();
    }
    catch(err)
    {
        //throw "Invalid AuthTag for ciphertext. Your ciphertext might have been tampered with. Aborting decryption now...."
        throw err;
    }

    let plaintext = Buffer.concat([decBuffer1, decBuffer2]);

    // Clean out buffers
    zeroBuffer(decBuffer1);
    zeroBuffer(decBuffer2);

    return plaintext;
}

/**
 * Compatible Public Key encoding for `genKeyPair`
 */
const compatPubKE = {
    type: 'spki',
    format: 'pem'
}

/**
 * Compatible Private Key encoding for `genKeyPair`
 */
const compatPrivKE = {
    type: 'pkcs8',
    format: 'pem'
}

/**
 * Generates a keypair for asymmetric encryption. Wrapper for Node function.
 * @param {String} encryptAlg Asymmetric encryption algorithm. Must be in the list of supportedAsymmetrics
 * @param {JSON} options Node.js options for your asymmetric encryption alg
 * @param {String} options.publicKeyEncoding Encoding for public key. We recommend using compatPubKE for max compatibility
 * @param {String} options.privateKeyEncoding Encoding for private key. We recommend using compatPrivKE for max compatibility
 * @see https://nodejs.org/api/crypto.html#cryptogeneratekeypairsynctype-options
 * @returns {{publicKey: String, privateKey: String}} JSON of public and private key in the format specified by `publicKeyEncoding` and `privateKeyEncoding` (strings for `compat*KE`)
 */
const genKeyPair = (encryptAlg, options) => {

    if (!supportedAsymmetrics.includes(encryptAlg))
    {
        throw "Unsupported algorithm. Check `supportedAsymmetrics` in `crypto_util.js` for a list.";
    }

    if (options == undefined)
    {
        throw "Please provide key pair generation options.";
    }

    if (options.publicKeyEncoding == undefined)
    {
        throw "Please provide a public key encoding. If you can't figure this out, use `compatPubKE`.";
    }

    if (options.privateKeyEncoding == undefined)
    {
        throw "Please provide a public key encoding. If you can't figure this out, use `compatPrivKE`.";
    }
    
    // If you're using compatPubKE or compatPrivKE, you should have a string here as your return value.
    let keyPair = generateKeyPairSync(encryptAlg, options);
    return keyPair;
}

// RSA public encrypt and decrypt functions not provided because Node's library is better for that (no need to put a wrapper)
// Note that because of the CLI and because of how the algorithms work, we give users a lot more flexibility when they use asymmetric encryption

/**
 * Signs the data using the given public/private key.
 * @param {String|undefined} hashAlg Hashing algorithm. Using undefined will leave this up to Node.js (which may very well use something like SHA-1). Do not give users this option explicitly.
 * @param {Buffer} data Data to be signed. You are responsible for zeroing this out later down the line if it's sensitive.
 * @param {{key: String, dsaEncoding: String, padding: Number, passphrase: String}} signKeyObject JSON object with key and other configs (such as padding. Consider using crypto.constants.RSA_PKCS1_PSS_PADDING)
 * @param {String} signKeyObject.passphrase If your private key is encrypted, provide a passphrase
 * @param {String} signKeyObject.key Key for digital signature
 * @see https://nodejs.org/api/crypto.html#cryptosignalgorithm-data-key-callback
 * @returns {String} Digital signature (in hex)
 */
const secureSign = (hashAlg, data, signKeyObject) => {

    if (hashAlg != undefined && !getHashes().includes(hashAlg))
    {
        throw "HashAlg is not supported by Node.js. We recommend sha3-512.";
    }

    if (signKeyObject.key == undefined)
    {
        throw "Please provide a key to sign.";
    }

    if (signKeyObject.key.includes("ENCRYPTED") && signKeyObject.passphrase == undefined)
    {
        throw "It seems like your (presumably private) key is encrypted. Please provide a passphrase.";
    }

    let signature;              // Buffer
    try
    {
        signature = sign(hashAlg, data, signKeyObject);
    }
    catch(err)
    {
        throw `Error when signing: ${err.toString()}. Usually this occurs because of a wrong passphrase when decrypting the private key.`;
    }

    let signatureHex = signature.toString('hex');
    zeroBuffer(signature);

    return signatureHex;
}

/**
 * Verifies a digital signature using a private/public key
 * @param {String|undefined} hashAlg Hashing algorithm. This must be the same as the hashing algorithm used in the digital signature
 * @param {Buffer} data Data to be verify signature of. You are responsible for zeroing this out later down the line if it's sensitive.
 * @param {{key: String, dsaEncoding: String, padding: Number, passphrase: String}} verifyKeyObject JSON object with key and other configs (such as padding. Consider using crypto.constants.RSA_PKCS1_PSS_PADDING)
 * @param {String} verifyKeyObject.passphrase If your private key is encrypted, provide a passphrase
 * @param {String} verifyKeyObject.key Key for digital signature
 * @param {String} signature The digital signature (in hex)
 * @see https://nodejs.org/api/crypto.html#cryptosignalgorithm-data-key-callback
 * @return {Boolean} Whether or not the digital signature is valid
 */
const secureVerify = (hashAlg, data, verifyKeyObject, signature) => {
    
    if (hashAlg != undefined && !getHashes().includes(hashAlg))
    {
        throw "HashAlg is not supported by Node.js. Check to make sure you are using the same one as the hashing algorithm.";
    }
    
    if (verifyKeyObject.key == undefined)
    {
        throw "Please provide a key to sign.";
    }

    if (verifyKeyObject.key.includes("ENCRYPTED") && verifyKeyObject.passphrase == undefined)
    {
        throw "It seems like your key is encrypted. Please provide a passphrase.";
    }

    let signatureBuffer = Buffer.from(signature, 'hex');        // Buffer

    let signatureValid;
    try
    {
        signatureValid = verify(hashAlg, data, verifyKeyObject, signatureBuffer);
    }
    catch(err)
    {
        throw `Error when verifying: ${err.toString()}. Usually this occurs because of a wrong passphrase when decrypting the private key.`;
    }
    
    zeroBuffer(signatureBuffer);

    return signatureValid;
}

// 🛠️ Testing area 
// const encAlg = 'aes-256-gcm'
// let symmEnc = symmetricEncrypt("49ers", "San Francisco", "That's looking Purdy good... except for Moody. He's making me Moody.", encAlg, 12);
// // symmEnc.encAuthTag = 'c3047f19c8588dca270ec3a0719076ff'
// let symmDec = symmetricDecrypt("49ers", "San Francisco", symmEnc.ciphertext, encAlg, symmEnc);
// console.log(symmDec.toString('utf-8'))

let keyPair = genKeyPair('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: compatPubKE,
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: 'CMC'
    }
});

let encrypted = publicEncrypt({key: keyPair.publicKey, oaepHash: 'sha3-512', padding: constants.RSA_PKCS1_OAEP_PADDING}, Buffer.from("Touchdown San Francisco!", 'utf-8'));
let decrypted = privateDecrypt({key: keyPair.privateKey, oaepHash: 'sha3-512', padding: constants.RSA_PKCS1_OAEP_PADDING, passphrase: 'CMC'}, encrypted);

let signature = secureSign('sha3-512', encrypted, {key: keyPair.privateKey, passphrase: 'CMC', padding: constants.RSA_PKCS1_PSS_PADDING});
let isValid = secureVerify('sha3-512', Buffer.from("hello", "ascii"), {key: keyPair.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING}, signature);

console.dir(decrypted.toString('utf-8'));
console.dir(isValid);
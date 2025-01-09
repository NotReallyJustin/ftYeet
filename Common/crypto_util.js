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

export { supportedCiphers, supportedAsymmetrics, secureKeyGen, zeroBuffer, symmetricDecrypt, symmetricEncrypt, secureSign, secureVerify, compatPrivKE, compatPubKE, genKeyPair, 
    keyEncodingFormats, keyEncodingTypes, supportedHashes, genHMAC, fromFileSyntaxAsymm, toFileSyntaxAsymm, fromFileSyntaxSymm, toFileSyntaxSymm, genAsymmCryptosystem }

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
 * List of supported hashes.
 */
const supportedHashes = [
    'sha3-512',
    'sha3-256',
    'sha256',
    'sha512',
    'shake256'      // Part of SHA-3 family apparently so we'll allow this one
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
 * Runs a HMAC on a given piece of a data
 * @param {String} key Hex of symmetric key to encrypt after hashing
 * @param {String} hashAlg Hashing Algorithm. Must be in the list of `supportedHashes`, but we reccomend just using sha3-512
 * @param {Buffer} data Data to HMAC. You are responsible for zeroing this out if needed
 * @throws If HMAC Algorithm is not supported
 * @returns {String} The HMAC, in hex
 */
const genHMAC = (key, hashAlg, data) => {

    if (!supportedHashes.includes(hashAlg))
    {
        throw "Unsupported hash algorithm. Check `supportedHashes` in `crypto_util.js` for a list.";
    }

    let keyAsHex = Buffer.from(key, 'hex');
    let hmacCipher = createHmac(hashAlg, keyAsHex);

    hmacCipher.update(data);

    zeroBuffer(keyAsHex);

    return hmacCipher.digest('hex');
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
    let hmac = genHMAC(hmacSecrets.key, 'sha3-512', ciphertext);

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
    let currHMAC = genHMAC(hmacSecrets.key, 'sha3-512', ciphertext);

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
 * List of supported formats to encode keypairs
 */
const keyEncodingFormats = ['pem', 'der', 'jwk'];

/**
 * List of supported types to encode keypairs
 */
const keyEncodingTypes = ['pkcs1', 'pkcs8', 'spki'];

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
    try                         // If we can, force sha3-512 or the hashAlg. If the algorithm is uncompromising with its hashes (like ED25519), let it cook.
    {
        signature = sign(hashAlg, data, signKeyObject);
    }
    catch(err)
    {
        try
        {
            console.log("We got an internal issue with `Node.js` itself when trying to sign the data. This might be an ED25519 key. Trying workaround...");
            console.log("Note: ED25519 uses SHA2-512 internally.")
            signature = sign(null, data, signKeyObject);
        }
        catch(err2)
        {
            throw `Error when signing: ${err2}.\n Usually this occurs because of a wrong passphrase when decrypting the private key.`;
        }
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
        try
        {
            console.log("We got an internal issue with `Node.js` itself when trying to sign the data. This might be an ED25519 key. Trying workaround...");
            console.log("Note: ED25519 uses SHA2-512 internally.")
            signatureValid = verify(null, data, verifyKeyObject, signatureBuffer);
        }
        catch(err2)
        {
            throw `Error when signing: ${err2}.\n Usually this occurs because of a wrong passphrase when decrypting the private key.`;
        }
    }
    
    zeroBuffer(signatureBuffer);

    return signatureValid;
}

/**
 * Converts a JSON cryptosystem and its associated data into a standardized format you can write to a file.
 * This will HMAC with authTags, IVs, and SALTs using the given key and SHA3-512
 * The standardized format is [0 for Symmetric][HMAC Size : 4 bytes][HMAC cryptosystem : 64 bytes][cryptosystem size : 4 bytes][cryptosystem : up to 2^32 bytes][data]
 * @param {{signature:String}} cryptosystem JSON of all the authtags, SALTs, and IVs used to encrypt and HMAC the data. Must include HMAC. 🚨 DO NOT PUT THE KEYS IN HERE 🚨
 * @param {Buffer} data (Encrypted) data to write to the file
 * @param {{key: String, salt: String}} hmacCryptosys Key and SALT that's going to be used to HMAC the entire cryptosystem with (in hex). This could be the authentication key and SALT you used to HMAC the data itself. If you don't know what I'm talking about, pass in the cryptosystem you obtained from running `secureKeyGen()`.
 * @param {String} source The platform that encrypted the data. Either `CLI`, `Server`, or `Web`. Used for compatiability purposes
 * @throws Error if hmac is not in the cryptosystem because that is very important
 * @throws Error if source is not `CLI`, `Server`, or `Web`
 * @returns {Buffer} A standardized buffer you can write to files
 */
const toFileSyntaxSymm = (cryptosystem, data, hmacCryptosys, source) => {
    
    // Error checks
    if (cryptosystem.hmac == undefined)
    {
        throw "Failed to convert to file syntax: Must have `hmac` inside the cryptosystem JSON."
    }
    if (!["CLI", "Server", "Web"].includes(source))
    {
        throw "Failed to convert to file syntax: Source parameter must contain `CLI`, `Server`, or `Web`."
    }

    // Take care of [cryptosystem: theoretically up to 2^32 bytes but we'll never get close to that]
    // No buffer overflows because we're not directly reading anything into the buffer. We're just concatenating other buffers with the initial empty buffer.
    // `Node.js` is also memory safe. There's a function allocUnsafe() that acts like C but we're not touching that
    cryptosystem.source = source;
    cryptosystem.hmacCryptosysSalt = hmacCryptosys.salt;

    let cryptosysBuffer = Buffer.from(JSON.stringify(cryptosystem));    // If it looks like JSON, it is JSON. God must have invented JSON because it's beautiful

    // Take care of [cryptosystem size : 4 bytes]
    let cryptoSize = cryptosysBuffer.length;

    if (cryptoSize > 10000)
    {
        throw "Failed to convert to file syntax: I don't know what you're doing but your cryptosystem JSON should not be > 10,000 bytes. Something went wrong.";
    }

    let crytoSizeBuffer = Buffer.alloc(4);          // Be very careful about this. There is no user involvement in this at all which mitigates Buffer Overflows
    crytoSizeBuffer.writeUInt32LE(cryptoSize, 0);          // writeUInt32LE() will throw a RangeError instead of Buffer Overflowing in case cryptoSize gets too big somehow

    // Take care of [HMAC cryptosystem : 64 bytes]
    // This runs a SHA3-512 HMAC on cryptosysBuffer and cryptoSizeBuffer. 
    // Because cryptosysBuffer contains a HMAC or digital signature of the data, this also indirectly HMACs the data itself
    let accCryptosysBuffer = Buffer.concat([crytoSizeBuffer, cryptosysBuffer]);

    zeroBuffer(crytoSizeBuffer);
    zeroBuffer(cryptosysBuffer);

    let hmacKeyBuffer = Buffer.from(hmacCryptosys.key, 'hex');
    let hmacBuffer = Buffer.from(genHMAC(hmacKeyBuffer, 'sha3-512', accCryptosysBuffer), 'hex');
    zeroBuffer(hmacKeyBuffer);
    if (hmacBuffer.length != 64)
    {
        throw "Failed to convert to file syntax: HMAC size is not 64 bytes/512 bits. Something went wrong.";
    }

    // Take care of [0 for Symmetric][HMAC Size : 4 bytes]
    let hmacSize = 64;
    let hmacSizeBuffer = Buffer.alloc(4);
    hmacSizeBuffer.writeUInt32LE(hmacSize, 0);

    // Combine everything --> [0 for Symmetric][HMAC Size : 4 bytes][HMAC cryptosystem : 64 bytes][cryptosystem size : 4 bytes][cryptosystem : up to 2^32 bytes][data]
    let fileSyntax = Buffer.concat([Buffer.alloc(1, 0), hmacSizeBuffer, hmacBuffer, accCryptosysBuffer, data]);

    zeroBuffer(hmacBuffer);
    zeroBuffer(accCryptosysBuffer);
    zeroBuffer(hmacSizeBuffer);
    zeroBuffer(data);

    return fileSyntax;
}

/**
 * Converts a file syntax for symmetric encryption to a JSON cryptosystem.
 * Also validates the HMAC to check if the file syntax (IVs, SALTs, etc.) stored in the file was tampered with
 * @param {String} hmacKey Key to HMAC the entire cryptosystem with (in hex). This could be the authentication key you used to HMAC the data from earlier. ❗Mutually exclusive with `hmacPasswd`.
 * @param {String} hmacPasswd Password/Authcode used in the KDF to generate the HMAC for the entire cryptosystem. The SALT is already in the file syntax. ❗Mutually exclusive with `hmacKey`.
 * @param {Buffer} fileBuffer The file buffer, in file syntax
 * @throws Error if the file syntax is for asymmetric encryption.
 * @throws Error if the HMACs do not match
 * @throws Error if both `hmacKey` and `hmacPasswd` are provided. One of them must be `undefined`.
 * @note File Syntax Format: [0 for Symmetric][HMAC Size : 4 bytes][HMAC cryptosystem : 64 bytes][cryptosystem size : 4 bytes][cryptosystem : up to 2^32 bytes][data]
 * @returns {{cryptoSystem: JSON, data: Buffer}}
 */
const fromFileSyntaxSymm = (hmacKey, hmacPasswd, fileBuffer) => {
    
    if (hmacKey != undefined && hmacPasswd != undefined)
    {
        throw "Error parsing symmetric file syntax: Parameters `hmacKey` and `hmacPasswd` are mutually exclusive. Pick one.";
    }

    // Remember in Node, buffers are read in bytes
    let currOffset = 0;

    // Check if it's asymm or symm
    if (fileBuffer.readUint8(currOffset) != 0)
    {
        throw "Error parsing symmetric file syntax: This file syntax seems to be for something that's asymmetrically encrypted. Use `fromFileSyntaxAsymm` instead.";
    }
    currOffset += 1;

    // Read HMAC size. This should be 64 bytes bc HMAC cryptosystem
    let hmacSize = fileBuffer.readUInt32LE(currOffset);
    if (hmacSize != 64)
    {
        throw "Error parsing symmetric file syntax: Invalid file syntax. HMAC size for cryptosystem is not 64 bytes.";
    }
    currOffset += 4;

    // Read HMAC - This should be 64 bytes. This will be used later to check cryptosystem integrity
    let hmacRead = fileBuffer.subarray(currOffset, currOffset + 64).toString('hex');
    currOffset += 64;
    var hmacOffset = currOffset;                // Store where the end of the HMAC is. We'll need to reference it later.

    // Read the cryptosystem
    let cryptosystemSize = fileBuffer.readUInt32LE(currOffset);
    currOffset += 4;

    let cryptosystemBuffer = fileBuffer.subarray(currOffset, currOffset + cryptosystemSize);
    currOffset += cryptosystemSize;

    let cryptosystem;           // Parse the cryptosystem into JSON
    try
    {
        cryptosystem = JSON.parse(cryptosystemBuffer.toString());
    }
    catch(err)
    {
        throw `Error parsing symmetric file syntax: Failed to parse cryptosystem JSON. See error message below.\n${err}`;
    }

    // Check the actual HMAC with the HMAC inside the file syntax
    // Users can either put in a hmac key or the hmac password (more realistic). Regardless, generate the key here.
    let key = hmacKey != undefined ? hmacKey : secureKeyGen(hmacPasswd, 32, cryptosystem.hmacCryptosysSalt).key;

    let accCryptosystem = fileBuffer.subarray(hmacOffset, hmacOffset + 4 + cryptosystemSize);
    let hmac = genHMAC(key, 'sha3-512', accCryptosystem);

    if (hmac != hmacRead)
    {
        throw "Error parsing symmetric file syntax: Cryptosystem HMAC mismatch. Someone might have tampered with your file.";
    }

    // Get the rest of the data
    let data = fileBuffer.subarray(currOffset);

    return {
        cryptoSystem: cryptosystem,
        data: data
    };
}

/**
 * Creates a JSON cryptosystem for asymmetric encryption to eventually create a file syntax with
 * In other words, this is a struct for an asymmetric cryptosystem object
 * @param {String} signature Digital signature, in hex
 * @param {Number} dsaPadding Padding for the digital signature. Must be Node.js `crypto.constants.RSA_PKCS1_PSS_PADDING` or `crypto.constants.RSA_PKCS1_PADDING`
 * @param {Number} encryptPadding Padding for asymmetric encryption algorithm. Must be `crypto.constants.RSA_PKCS1_OAEP_PADDING` or `crypto.constants.RSA_PKCS1_PADDING`
 * @param {String|undefined} oaepHash Mandatory if you use `crypto.constants.RSA_PKCS1_OAEP_PADDING`. Must be part of `supportedHashes`
 * @returns {{dsaPadding: Number, encryptPadding: Number, oaepHash: String|undefined}} JSON for the asymmetric cryptosystem
 */
const genAsymmCryptosystem = (signature, dsaPadding, encryptPadding, oaepHash) => {
    
    let cryptosystem = {
        dsaPadding: dsaPadding,
        encryptPadding: encryptPadding,             // This function exists less for this JSON part and more for the verification part
        oaepHash: oaepHash,
        signature: signature
    }

    if (!validateAsymmCryptosystem(cryptosystem))
    {
        throw "Cryptosystem inputs are invalid.";
    }

    return cryptosystem;
}

/**
 * Validates an asymmetric cryptosystem JSON. Prolly should stay an internal function
 * @param {{dsaPadding: Number, encryptPadding: Number, oaepHash: String|undefined}} cryptosystem The Asymmetric JSON cryptosystem
 * @throws Errors if the padding is unsupported, or if oaepHash type is not specified.
 * @returns {Boolean} Whether the JSON is valid or not
 */
const validateAsymmCryptosystem = (cryptosystem) => {
    
    if (cryptosystem.signature == undefined)
    {
        throw "Cryptosystem is invalid: Must contain signature";
        return false;
    }

    if (cryptosystem.dsaPadding != constants.RSA_PKCS1_PSS_PADDING && cryptosystem.dsaPadding != constants.RSA_PKCS1_PADDING)
    {
        throw "Cryptosystem is invalid: dsaPadding type is unsupported. Must be RSA_PKCS1_PSS_PADDING or RSA_PKCS1_PADDING.";
        return false;
    }

    if (cryptosystem.encryptPadding != constants.RSA_PKCS1_OAEP_PADDING && cryptosystem.encryptPadding != constants.RSA_PKCS1_PADDING)
    {
        throw "Cryptosystem is invalid: encryptPadding type is unsupported. Must be RSA_PKCS1_OAEP_PADDING or RSA_PKCS1_PADDING.";
        return false;
    }

    if (cryptosystem.encryptPadding == constants.RSA_PKCS1_OAEP_PADDING && cryptosystem.oaepHash == undefined)
    {
        throw "Cryptosystem is invalid: Using RSA_PKCS1_OAEP_PADDING but oaepHash is undefined.";
        return false;
    }

    if (!supportedHashes.includes(cryptosystem.oaepHash.toLowerCase()))
    {
        throw "Cryptosystem is invalid: oaepHash is not supported. Check `supportedHashes` for list of supported hashing algorithms.";
        return false;
    }

    return true;
}

/**
 * Converts a JSON cryptosystem and its associated data into a standardized format you can write to a file.
 * This is for asymmetric encryption. Use `toFileSyntaxSymm` is this is for a symmetric algorithm.
* This will digitally sign the dsaPadding, encryptPadding, and oaepHash JSON using the given key, SHA3-512, der encoding, and constants.RSA_PKCS1_PSS_PADDING
 * The standardized format is `[1 for Asymmetric][Signature Size : 4 bytes][Signature cryptosystem][cryptosystem size : 4 bytes][cryptosystem : up to 2^32 bytes][data]`
 * @param {{dsaPadding: Number, encryptPadding: Number, oaepHash: String|undefined}} cryptosystem JSON of asymmetric cryptosystem
 * @param {Buffer} data (Encrypted) data to write to the file
 * @param {{key: String, dsaEncoding: String, padding: Number, passphrase: String}} dsaKey JSON object with key and password used to generate a digital signature. Encoding is forcibly set to `der` and padding is set to `RSA_PKCS1_PSS_PADDING`.
 * @param {String} source The platform that encrypted the data. Either `CLI`, `Server`, or `Web`. Used for compatiability purposes
 * @throws Error cryptosystem is improperly formatted
 * @throws Error if source is not `CLI`, `Server`, or `Web`
 * @returns {Buffer} A standardized buffer you can write to files
 */
const toFileSyntaxAsymm = (cryptosystem, data, dsaKey, source) => {

    // Error checks
    if (!validateAsymmCryptosystem(cryptosystem))
    {
        throw "Failed to convert to file syntax: Invalid cryptosystem JSON.";
    }
    if (!["CLI", "Server", "Web"].includes(source))
    {
        throw "Failed to convert to file syntax: Source parameter must contain `CLI`, `Server`, or `Web`."
    }

    cryptosystem.source = source;

    // Convert cryptosystem to JSON
    let cryptosysBuffer = Buffer.from(JSON.stringify(cryptosystem));

    // Take care of [cryptosystem size : 4 bytes]
    let cryptoSize = cryptosysBuffer.length;
    if (cryptoSize > 3000)
    {
        throw "Failed to convert to file syntax: I don't know what you're doing but your cryptosystem JSON should not be > 3,000 bytes. Something went wrong.";
    }

    let crytoSizeBuffer = Buffer.alloc(4);          // Again - be very careful about this. There is no user involvement in this at all which mitigates Buffer Overflows
    crytoSizeBuffer.writeUInt32LE(cryptoSize, 0);          // writeUInt32LE() will throw a RangeError instead of Buffer Overflowing in case cryptoSize gets too big somehow

    // Take care of [Signature cryptosystem] 
    // Because cryptosysBuffer contains a digital signature of the data, this also indirectly signs the data itself
    let accCryptosysBuffer = Buffer.concat([crytoSizeBuffer, cryptosysBuffer]);

    zeroBuffer(crytoSizeBuffer);
    zeroBuffer(cryptosysBuffer);

    // Forcibly change to RSA_PKCS1_PSS_PADDING padding and der encoding just in case the user tries to pass them in
    dsaKey.padding = constants.RSA_PKCS1_PSS_PADDING;
    dsaKey.dsaEncoding = 'der';
    let cryptoSigBuffer = Buffer.from(secureSign('sha3-512', accCryptosysBuffer, dsaKey), 'hex');

    // Take care of [1 for Asymmetric][Signature Size : 4 bytes]
    let sigSize = cryptoSigBuffer.length;
    let sigSizeBuffer = Buffer.alloc(4);
    sigSizeBuffer.writeUInt32LE(sigSize, 0);        // Crashes instead of buff overflow if mem error; also we have full control over sigSize

    // Combine everything --> [1 for Asymmetric][Signature Size : 4 bytes][Signature cryptosystem][cryptosystem size : 4 bytes][cryptosystem : up to 2^32 bytes][data]
    let fileSyntax = Buffer.concat([Buffer.alloc(1, 1), sigSizeBuffer, cryptoSigBuffer, accCryptosysBuffer, data]);

    zeroBuffer(cryptoSigBuffer);
    zeroBuffer(accCryptosysBuffer);
    zeroBuffer(sigSizeBuffer);
    zeroBuffer(data);

    return fileSyntax;
}   

/**
 * Converts a file syntax for asymmetric encryption to a JSON cryptosystem.
 * Also validates the Digital Signatures to check if the file syntax (ie. padding, oaep hash, etc.) stored in the file was tampered with
 * @param {{key: String, dsaEncoding: String, padding: Number, passphrase: String}} dsaKey JSON object with key and password used to decrypt the digital signature. Padding is set to `RSA_PKCS1_PSS_PADDING` and DSA encoding is set to `der`.
 * @param {Buffer} fileBuffer The file buffer, in file syntax
 * @throws Error if the file syntax is for symmetric encryption.
 * @throws Error if the digital signatures do not match
 * @note File Syntax Format: `[1 for Asymmetric][Signature Size : 4 bytes][Signature cryptosystem][cryptosystem size : 4 bytes][cryptosystem : up to 2^32 bytes][data]`
 * @returns {{cryptoSystem: JSON, data: Buffer}} The cryptosystem and data in a JSON object
 */
const fromFileSyntaxAsymm = (dsaKey, fileBuffer) => {

    // Current buffer offset, in bytes
    let currOffset = 0;

    // Check if it's asymm or symm
    if (fileBuffer.readUint8(currOffset) != 1)
    {
        throw "Error parsing asymmetric file syntax: This file syntax seems to be for something that's symmetrically encrypted. Use `fromFileSyntaxSymm` instead.";
    }
    currOffset += 1;

    // Read signature size.
    let sigSize = fileBuffer.readUInt32LE(currOffset);
    currOffset += 4;

    // Read the digital signature
    let signature = fileBuffer.subarray(currOffset, currOffset + sigSize).toString('hex');
    currOffset += sigSize;
    var sigOffset = currOffset;

    // Read the cryptosystem
    let cryptosystemSize = fileBuffer.readUInt32LE(currOffset);
    currOffset += 4;

    let cryptosystemBuffer = fileBuffer.subarray(currOffset, currOffset + cryptosystemSize);
    currOffset += cryptosystemSize;

    // Check the signature
    let accCryptosystem = fileBuffer.subarray(sigOffset, sigOffset + 4 + cryptosystemSize);
    dsaKey.dsaEncoding = 'der';
    dsaKey.padding = constants.RSA_PKCS1_PSS_PADDING;   // Forcibly change dsakey options cos user is dumb
    let isSignatureValid = secureVerify('sha3-512', accCryptosystem, dsaKey, signature);

    if (!isSignatureValid)
    {
        throw "Error parsing asymmetric file syntax: Invalid digital signature. Someone might have tampered with your file.";
    }

    let cryptosystem;
    try
    {
        cryptosystem = JSON.parse(cryptosystemBuffer.toString());
    }
    catch(err)
    {
        throw `Error parsing asymmetric file syntax: Failed to parse cryptosystem JSON. See error message below.\n${err}`;
    }

    // Get the rest of the data
    let data = fileBuffer.subarray(currOffset);

    return {
        cryptoSystem: cryptosystem,
        data: data
    };
}

// 🛠️ Testing area 
// const encAlg = 'aes-256-gcm'
// let symmEnc = symmetricEncrypt("49ers", "San Francisco", "That's looking Purdy good... except for Moody. He's making me Moody.", encAlg, 12);
// // symmEnc.encAuthTag = 'c3047f19c8588dca270ec3a0719076ff'
// // let symmDec = symmetricDecrypt("49ers", "San Francisco", symmEnc.ciphertext, encAlg, symmEnc);

// let ciphertext = symmEnc.ciphertext;
// delete symmEnc.ciphertext;
// let fileSyntax = toFileSyntaxSymm(symmEnc, ciphertext, secureKeyGen("San Francisco", 32, symmEnc.hmacSalt), 'CLI');
// console.dir(fileSyntax)
// let restored = fromFileSyntaxSymm(undefined, "San Francisco", fileSyntax);
// console.dir(restored);

// 🛠️ DEMO for asymm.
// let keyPair = genKeyPair('rsa', {
//     modulusLength: 4096,
//     publicKeyEncoding: compatPubKE,
//     privateKeyEncoding: {
//         type: 'pkcs8',
//         format: 'pem',
//         cipher: 'aes-256-cbc',
//         passphrase: 'CMC'
//     }
// });

// let encrypted = publicEncrypt({key: keyPair.publicKey, oaepHash: 'sha3-512', padding: constants.RSA_PKCS1_OAEP_PADDING}, Buffer.from("Touchdown San Francisco!", 'utf-8'));
// let decrypted = privateDecrypt({key: keyPair.privateKey, oaepHash: 'sha3-512', padding: constants.RSA_PKCS1_OAEP_PADDING, passphrase: 'CMC'}, encrypted);

// let signature = secureSign('sha3-512', encrypted, {key: keyPair.privateKey, passphrase: 'CMC', padding: constants.RSA_PKCS1_PSS_PADDING});
// // console.log(signature.length)
// // let isValid = secureVerify('sha3-512', Buffer.from("hello", "ascii"), {key: keyPair.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING}, signature);

// let cryptosystem = genAsymmCryptosystem(signature, constants.RSA_PKCS1_PSS_PADDING, constants.RSA_PKCS1_OAEP_PADDING, 'sha3-512');
// let fileSyntax = toFileSyntaxAsymm(cryptosystem, encrypted, {key: keyPair.privateKey, passphrase: 'CMC'}, 'CLI');
// let restored = fromFileSyntaxAsymm({key: keyPair.publicKey}, fileSyntax);
// console.log(restored)

// console.log(privateDecrypt({key: keyPair.privateKey, oaepHash: restored.cryptoSystem.oaepHash, padding: restored.cryptoSystem.encryptPadding, passphrase: 'CMC'}, restored.data).toString())
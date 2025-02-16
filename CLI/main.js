import { Command, InvalidArgumentError } from 'commander';
import * as functions from './functions.js';
const program = new Command();

// ⚒️ Helper processing methods

/**
 * Forcibly converts a string argument into a number
 * @param {String} userArg The user provided argument
 * @param {Number} prev The default argument, if any
 * @throws InvalidArgumentError if it's not a number
 * @returns {Number} The argument, as a number
 */
const forceNum = (userArg, prev) => {
    const parsedValue = parseInt(userArg != undefined ? userArg : prev);
    if (isNaN(parsedValue)) 
    {
        throw new InvalidArgumentError('Not a number.');
    }

    return parsedValue;
}

// 💻 Commander CLI program
program
    .version("1.0")
    .name("ftYeet")
    .description("The end-to-end temporary file transfer system.")
;

program
    .command("keygen")
    .description("Generates a supported asymmetric keypair to use in E2EE")
    .requiredOption('-a, --algorithm <rsa|dsa|ed25519|x25519>', 'asymmetric algorithm to generate keys for')
    .requiredOption('-u, --public-key-path <path>', 'public key file path')
    .requiredOption('-v, --private-key-path <path>', 'private key file path')
    .option('-e, --pubkey-encoding-type [pkcs1|spki]', 'encoding type for public key', 'spki')
    .option('-f, --privkey-encoding-type [pkcs1|pkcs8]', 'encoding type for private key', 'pkcs8')
    .option('-g, --encoding-format [pem|der|jwk]', 'encoding format for keys', 'pem')
    .option('-l, --modulus-length [number]', 'modulus length in bits (required for RSA and DSA)', parseInt, 4096)
    .option('-p, --public-exponent [number]', 'exponent for RSA; defaults to 0x10001', parseInt, 0x1001)
    .option('-d, --divisor-length [number]', 'size of q in bits (for DSA)', parseInt, 256)
    .option('-c, --named-curve [curve name]', 'name of the curve to use for EC-based algs (ie. "secp256k1", "prime256v1")')
    .option('-k, --privatekey-cipher [cipher name]', 'symmetric cipher to encrypt private key file with. Must be used with -o')
    .option('-o, --passphrase [password]', 'passphrase to encrypt private key file with. Must be used with -k')
    .action((options) => {
        let algorithm = options.algorithm;
        let pubKE = {
            type: options.pubkeyEncodingType,
            format: options.encodingFormat
        };

        let privKE;

        // Private key is encrypted
        if (options.privatekeyCipher != undefined || options.passphrase != undefined)
        {
            // Both filled in
            if (options.privatekeyCipher != undefined && options.passphrase != undefined)
            {
                privKE = {
                    type: options.privkeyEncodingType,
                    format: options.encodingFormat,
                    cipher: options.privatekeyCipher,
                    passphrase: options.passphrase
                };
            }
            else
            {
                // only one filled in
                throw "Error: Both the passphrase and the cipher algorithm must be filled in if you're encrypting the private key.";
            }
        }
        else
        {
            privKE = {
                type: options.privkeyEncodingType,
                format: options.encodingFormat
            };
        }

        let pubPath = options.publicKeyPath;
        let privPath = options.privateKeyPath;

        [
            'pubkeyEncodingType', 'privkeyEncodingType', 'encodingFormat', 'algorithm', 'publicKeyPath', 'privateKeyPath', 'privatekeyCipher', 'passphrase'
        ].forEach(key => delete options[key]);

        options.publicKeyEncoding = pubKE;
        options.privateKeyEncoding = privKE;
        functions.keygen(pubPath, privPath, algorithm, options);
    })
;

program
    .command("upload")
    .description("Encrypts a local file, runs an HMAC, and uploads it to a ftYeet server")
    .requiredOption('-p, --password <password>', 'password used to encrypt the file locally; also used for HMACs if -c is empty')
    .requiredOption('-f, --file <path>', 'path of the file to upload')
    .option('-a, --algorithm [chacha20-poly1305|aes-256-gcm|aes256-cbc]', 'symmetric algorithm for encrypting the file', 'chacha20-poly1305')
    .option('-c, --auth-code [password]', 'authentication code used to generate file HMAC; password would be used if this is left empty')
    .option('-t, --expire-time [seconds]', 'how long the server should hold on to the uploaded file; must be >= 60', forceNum, 60)
    .option('-b, --burn', 'whether to burn the file upon download', false)
    .action((options) => {
        functions.uploadSymm(options.file, options.password, options.algorithm, options.authCode != undefined ? options.authCode : options.password, 
            options.expireTime, options.burn
        );
    })
;

program
    .command("download")
    .description("Downloads a file from the ftYeet server and decrypts it")
    .requiredOption('-u, --url <url>', 'ftYeet URL where the resource/file is stored')
    .requiredOption('-d, --directory <directory>', 'where the downloaded files will be stored')
    .requiredOption('-p, --password <password>', 'password used to decrypt the file locally; also used to HMACs if -c is empty')
    .option('-a, --algorithm [chacha20-poly1305|aes-256-gcm|aes256-cbc]', 'symmetric algorithm for decrypting the file; ' + 
        'decryption may fail if this does not match the one used to encrypt', 'chacha20-poly1305')
    .option('-c, --auth-code [password]', 'authentication code used to verify file HMAC; password would be used if this is left empty')
    .action((options) => {
        functions.downloadSymm(options.directory, options.password, options.algorithm, options.authCode != undefined ? options.authCode : options.password, options.url);
    });
;

program
    .command("upload-asymm")
    .description("Encrypts a local file ASYMMETRICALLY with RSA, digitally signs it (algorithm depends on your key), and uploads it to a ftYeet server." +
        "By using this command, you agree that you understand how asymmetric encryption works on a basic level (and how it preserves confidentiality).")
    .requiredOption('-f, --file <path>', 'path of the file to upload')
    .requiredOption('-e, --encryption-key <path>', 'path of key file used to encrypt your file; usually, this is the recipient\'s public key')
    .requiredOption('-s, --signature-key <path>', 'path of key file used to digitally sign your encrypted file; usually, this is your private key')
    .option('-p, --signature-key-pwd [password]', 'password for your signature key file, if you have one')
    .option('-r, --signature-padding [RSA_PKCS1_PSS_PADDING|RSA_PKCS1_PADDING]', 'padding for digital signature (if RSA)', 'RSA_PKCS1_PSS_PADDING')
    .option('-c, --encryption-padding [RSA_PKCS1_PSS_PADDING|RSA_PKCS1_OAEP_PADDING]', 'padding for RSA asymmetric encryption; if you choose OAEP Padding,' +
        ' the hash is SHA3-512', 'RSA_PKCS1_OAEP_PADDING')
    .option('-t, --expire-time [seconds]', 'how long the server should hold on to the uploaded file; must be >= 60', forceNum, 60)
    .option('-b, --burn', 'whether to burn the file upon download', false)
    .action((options) => {
        functions.uploadAsymm(options.file, options.signatureKey, options.signatureKeyPwd, options.encryptionKey, 
            options.signaturePadding, options.encryptionPadding, options.expireTime, options.burn);
    })
;

program
    .command("download-asymm")
    .description("Downloads a file from the ftYeet server and decrypts it ASYMMETRICALLY.")
    .requiredOption('-u, --url <url>', 'ftYeet URL where the resource/file is stored')
    .requiredOption('-d, --directory <directory>', 'where the downloaded files will be stored')
    .requiredOption('-e, --decryption-key <path>', 'path of key file used to decrypt your file; usually, this is your private key')
    .requiredOption('-s, --verify-key <path>', 'path of key file used to verify the signature of your downloaded file; usually, this is the sender\'s public key')
    .option('-o, --decryption-key-pwd [password]', 'password for your decryption key file, if you have one')
    .option('-p, --verify-key-pwd [password]', 'password for your verification key file, if you have one')
    .action((options) => {
        functions.downloadAsymm(options.directory, options.url, options.verifyKey, options.verifyKeyPwd, options.decryptionKey, options.decryptionKeyPwd);
    })
;

program.parse(process.argv);
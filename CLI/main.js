import { Command } from 'commander';
import * as functions from './functions.js';
const program = new Command();

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
    .option('-e, --pubkey-encoding-type [pkcs1|pkcs8|spki]', 'encoding type for public key', 'spki')
    .option('-f, --privkey-encoding-type [pem|der|jwk]', 'encoding type for private key', 'pkcs8')
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
    .action((options) => {
        functions.uploadSymm(options.file, options.password, options.algorithm, options.authCode != undefined ? options.authCode : options.password);
        console.log("File upload complete.");
    })

program.parse(process.argv);
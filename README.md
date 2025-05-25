# ftYeet
An End-to-End-Encrypted Temporarily file sharing server :) <br>
Inspired by a certain Cheese

# Instructions for Building ftYeet in Development
## Requirements
* Most of these should be resolved by `npm` since I specified them in `package.json`
* Use `Node.js v22.13.0`

## Setting up Environment
* Run `$npm install` on directories `Site/` and `CLI/`
* Use `openssl` to generate a `X509` cert and private key in `Site/Keys/`. Put the password for the private key in `Site/.env` as `PRIVKEY_PWD`
* If needed for testing purposes, run `$CLI/cli.exe keygen <args>` to create asymmetric keys

## Setting up Docker
* Make sure you install docker
* Download or pull the `postgres` image from Docker Hub

## Setting up Secrets
Here's a one-liner to self-signed key and cert files. Add `-nodes` at the end to prevent the private key from getting encrypted
```bash
openssl req -x509 -newkey rsa:4096 -keyout [privateKeyFilePath] -out [certPath] -sha512 -days 365
```
* Create `Secrets/privKey.pem` and `Secrets/cert.pem`. These are X509 certs and key files for the web server and ftYeet protocol's HTTPS tunnel
    * If there's a password for the private key file, put it in `Secrets/privKeyPwd.txt`
* Create `Secrets/dbPassword.txt` with the PostgreSQL database password.
* Create `Secrets/dbPrivKey.pem` and `Secrets/dbCert.pem`. These are the X509 certs and key files for the PostgreSQL server.
    * If there's a password, put it in `Secrets/dbPrivKeyPwd.txt`
* Create `Secrets/cryptoCert.pem` and `Secrets/cryptoHTTPKey.pem`. These are X509 certs for the crypto HTTPS tunnel.
    * If there's a password for the private key file, put it in `cryptoCertKeyPwd.txt`
* Create `Secrets/cryptoPrivKey.pem` and `Secrets/cryptoPubKey.pem`. This is the key the Crypto "HSM" will use to encrypt files
    * If there's a password for the private key file, put it in `cryptoEncKeyPwd.txt`
* Create `Secrets/cryptoPrivKeySign.pem` and `Secrets/cryptoPubKeySign.pem`. This is the key the "HSM" will use to sign files
    * If there's a password for the private key file, put it in `cryptoSignKeyPwd.txt`
* Create `Secrets/cryptoSymmPwd.txt`. This is the password used for symmetric key encryption in the Crypto "HSM."
<br >
Don't worry, you don't need to remember any of these passwords later down the line. Docker will take care of everything for you.
<br><br>

Alternatively, if you don't want to manually create all this, run `genSecrets.ps1`. `genSecrets.ps1` will assume that you *DON'T* know what you're doing and force you to create a password for (and encrypt) all of the private keys out there. Sample usage:

```ps1
# Add -ExecutionPolicy Bypass if needed
powershell.exe .\genSecrets.ps1 -PrivKeyPwd "CMC" -DBPwd "TralaleroTralala" -DBPrivKeyPwd "JsxDrt" -CryptoCertKeyPwd "Scion" -CryptoEncKeyPwd "CharlesChadwick" -CryptoSignKeyPwd "DanteCastello" -CryptoSymmPwd "If_Any_Of_My-DND_Fellas_Are_Lurking_Here_and-Recognize_these_names_Hi!"
```

If you don't have OpenSSL, install it here: https://www.openssl.org/
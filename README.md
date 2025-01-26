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

## Setting up Secrets
Here's a one-liner to self-signed key and cert files. Add `-nodes` at the end to prevent the private key from getting encrypted
```bash
openssl req -x509 -newkey rsa:4096 -keyout [privateKeyFilePath] -out [certPath] -sha512 -days 365
```
* Create `Secrets/privKey.pem` and `Secrets/cert.pem`. These are X509 certs and key files for the web server and HTTPS tunnel
    * If there's a password for the private key file, put it in `Secrets/dbPassword.txt`
* Create `Secrets/dbPassword.txt` with the PostgreSQL database password.
* Create `Secrets/dbPrivKey.pem` and `Secrets/dbCert.pem`. These are the X509 certs and key files for the PostgreSQL server.
    * If there's a password, put it in `Secrets/dbPrivKeyPwd.txt`
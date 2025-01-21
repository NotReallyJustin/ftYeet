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
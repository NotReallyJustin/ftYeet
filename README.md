# ftYeet (v1.0)
```
  __ _ __   __        _   
 / _| |\ \ / /__  ___| |_ 
| |_| __\ V / _ \/ _ \ __|
|  _| |_ | |  __/  __/ |_ 
|_|  \__||_|\___|\___|\__|
```

`ftYeet` is an Ephemeral, End-to-End-Encrypted file sharing server. <br>
Think of it as <a href="https://www.yellkey.com/">yellkey.com</a> or <a href="https://temp-mail.org/en/">TempMail</a>, but for online files. <br />
<br />
This project was inspired by (and created in parallel with) a certain <a href="https://github.com/james-conn/ssec-core">Cheese</a>. 

## Why ftYeet?
When you want to transfer files between two computers, servers, or VMs, you usually have 3 main options:
* FTP (or some variation of FTP such as SFTP)
    * However, FTP requires one of the two hosts to listen on port 21/22, which usually impossible since most OS firewalls block inbound requests by default. This is true regardless of whether or not you use active or passive mode.
    * Most computers are part of a LAN and sit behind a NAT. Unless the receiving host explicitly port forwards (unlikely in a place like a Coffee Shop or College Campus), FTP is not happening.
* Persistent Cloud Storage
    * Theoretically, you *could* upload your file onto Google Drive or OneDrive and share the link.
    * However, the links are extremely long and impractical to share, you need to manually delete the files, and there's very little (if any) authentication once someone has the link.
    * There's also a sizeable group of users/communities that are highly skeptical of trusting Google/Microsoft with their files (ie. training AI with uploaded content)
* Online File Upload Sites (such as <a href="https://easyupload.io/">EasyUpload.io</a>)
    * None of the publicly available sites are end-to-end encrypted.
    * The sites are at sketchy at best. They <a href="https://www.bitsight.com/blog/file-sharing-services-cybercriminal-underground">have been used by Cybercriminals to host malware</a>. The sites could potentially<a href="cyberinsider.com/fbi-beware-of-malware-infested-online-file-converter-tools/">modify and embed malicious code within uploaded files</a>
    * Also like c'mon. Use your brain. Are you really going to upload a file to https://wormhole.app/?
        * Some of these sites straight up lie to you. No, `wormhole.app` is NOT end-to-end encrypted just because you have a fancy animation. Your file is not encrypted/decrypted clientside.
        * If you're advertising "military grade encryption" (it's probably just AES-ECB) and TLS like `file.io` does, you might be a sketchy site. (On an unrelated note, you could actually `$curl` `file.io` without using TLS/SSL)

`ftYeet` intends to fix that. Your files are:
* End-to-end encrypted and digtally signed by the sender.
* Re-encrypted and signed again serverside (because I'm paranoid).
* Temporary. By default, they're only active for ~60s (can be changed in configs) and you can have the files burned on read.

There's also some extra security (hardening) features if you're the one deploying the `ftYeet` server. You can read about them in the Wiki.
* Users are also forced to authenticate before they can download anything from an URL. I hate buzzwords, but *technically* yes this is Zero Trust.

## Who should deploy ftYeet (v1.0)?
`ftYeet` (v1.0) is intended for small, self-hosted instances where you're not dealing with 5 concurrent, 500MB uploads at once. <br>
`ftYeet` (v2.0) is currently in development and is intended to be scalable and support features such as file streaming. <br>
<br>

TLDR: `ftYeet v1.0` (the version you are currently looking at) is intended for use cases where all that scalability is excessive, way too expensive, and borderline overkill.

## ftYeet Client
### Downloading ftYeet Client
In the Github `Releases` tab, you can download binary executables for Linux and Windows x86-64 processors. <br>
<br>

Alternatively, you could download everything in `CLI/` and run:`$npm install && node main.js [OPTIONS]` in that directory. <br>
If you wish to create a standalone binary executable for your own machine, modify the `$TARGET` variable in `CLI/bundle.ps1` or `CLI/bundle.sh` and run the executables.
* Check out the documentation for <a href="https://www.npmjs.com/package/pkg">pkg targets</a> for more details.

### Using ftYeet Client
```
Usage: ftYeet [options] [command]

The end-to-end encrypted temporary file transfer system.

Options:
  -V, --version             output the version number
  -h, --help                display help for command

Commands:
  keygen [options]          Generates a supported asymmetric keypair to use in E2EE
  upload [options]          Encrypts a local file, runs an HMAC, and uploads it to a ftYeet server
  download [options]        Downloads a file from the ftYeet server and decrypts it
  upload-asymm [options]    Encrypts a local file ASYMMETRICALLY with RSA, digitally signs it (algorithm depends on your key), and uploads it to a ftYeet server.
  download-asymm [options]  Downloads a file from the ftYeet server and decrypts it ASYMMETRICALLY.
  help [command]            display help for command
```

## Launching and Building ftYeet Server

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
* Create `Secrets/cryptoHMACPwd.txt`. This is the password used to generate HMACs in the Crypto "HSM" if that becomes necessary.
* Create `Secrets/hmacCryptosysKey.txt`. This is the key used to generate serverside HMACs when re-encrypting for the second time
<br >
Don't worry, you don't need to remember any of these passwords later down the line. Docker will take care of everything for you.
<br><br>

Alternatively, if you don't want to manually create all this, run `genSecrets.ps1`. `genSecrets.ps1` will assume that you *DON'T* know what you're doing and force you to create a password for (and encrypt) all of the private keys out there. Sample usage:

```ps1
# Add -ExecutionPolicy Bypass if needed
powershell.exe .\genSecrets.ps1 -PrivKeyPwd "CMC" -DBPwd "TralaleroTralala" -CryptoCertKeyPwd "Scion" -CryptoEncKeyPwd "CharlesChadwick" -CryptoSignKeyPwd "DanteCastello" -CryptoSymmPwd "If_Any_Of_My-DND_Fellas_Are_Lurking_Here_and-Recognize_these_names_Hi!" -CryptoHMACPwd "WeBringTheBoom" -HMACCryptosysKey "LoveIslandSeason7"
```

If you're using Linux or WSL, you can run this instead:
```bash
bash ./genSecrets.sh PrivKeyPwd DBPwd CryptoCertKeyPwd CryptoEncKeyPwd CryptoSignKeyPwd CryptoSymmPwd CryptoHMACPasswd HmacCryptosysKey

# For example:
bash ./genSecrets.sh CMC TralaleroTralala CharlesChadwick DanteCastello If_Any_Of_My-DND_Fellas_Are_Lurking_Here_and-Recognize_these_names_Hi! WeBringTheBoom LoveIslandSeason7
```

If you don't have OpenSSL, install it here: https://www.openssl.org/
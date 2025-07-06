# FtYeet Plans
The temporary, privacy-centered file sharing system b/c if we don't have this, some intelligence agency in China's gonna be reading all text messages. <br>
Also because I need a quick way to transfer files between my VMs and I don't trust the ad-ridden site that is sendanywhere.com 🥺 <br> <br>

* Prolly not a formal thing, but you know the PACELC Theorem?
    * Well I guess with encryption, there's a tradeoff between security and latency
    * `FtYeet` does not give a damn about latency (ok that's not true - getting DDOS'd is bad), but this very much prioritizes security
    * You're gonna see a lot of redundant things like "HMACs everywhere" "Double Encryption" "Hash those passwords twice" because I do not trust the end user to properly use `FtYeet`
* End to End Encryption (if the client chooses to do so) --> worst case, this gets downgraded to the regular ol' encryption that **most** companies should already be doing (looking at you AT&T 🙄 - isn't this like your 3rd data breach this year)
* CLI interface & Web interface
* Temporary file storage - eventually, files will get deleted

## Language Decision
Using `Node.js` because it does like 3 things at once for me <br>
God I love this language <br>
1. Standalone Client-Side executables
2. Decent Crypto support
3. Literally designed to build TCP Protocols and Web Servers

## Main Server
* Host an https one and a net one
* https can be done via express
* I'm not going to be able to have backups and stuff on this, and since we're using HTTPS, make this stateless

## Main Site Upload
* File upload
* 100mb max limit. If something's over 100mb, you probably shouldn't be sending it online   ---> Max 5 min
* 50mb max limit. Max 15 min
* If max size reached, prevent any file uploads temporarily.
* Encryption done browser/client side
* Toggle burn on read
* Possibly choose a password. Encryption done clientside; send over the password hash (if dummy user sends over a password, bruh that's on them. But this is getting hashed *again* so yk)
* Convience Toggle (we can give them a short URLCode that might be easy to brute force, or we can give them a long one for more security)
* When uploading, check database to make sure that URLCode isn't already occupied

## Main Site Download
* Might need to use clientside service worker
* Browser creates file write stream
* Decryption done client-side for end to end encryption

## Main Site 404
* "This file does not exist"
* I don't forsee anyone trying to pull off a replay attack or smth with this - but if they do, slap on a timestamp and have our server digitally sign this thing
* Also look into TCP reset attacks & stuff - although I think TLS would prevent against this because of timestamping, MACs, and the symmetric key exchange (can't replay attack if encryption is different)
* Also if TLS gets compromised, we have much bigger problems than a college kid trying to code an E2EE thing for fun (as in like the NSA and CISA starts running around while their building's on fire) 🤷‍♂️

## Backup/2nd Encryption + Crypto Process
* Sometimes, users are dumb and won't send over an encrypted file
* In that case, encrypt them with server's public key. Store the private key somewhere safe and have a seperate process do the encrypting/decrypting stuff.
* --> if an attacker can get access to the private key stored in some privileged 
* Zero out the memory if possible bc memory forensics is scary (tbf if they get this far we're already cooked but still confidentiality >>> here)

## Private Key Signing/Encryption serverside
* ~~Do not give FtYeet permission to private key file (`chmod` such that `FtYeet` doesn't have perms to view this at all)~~
* ~~Create a new privileged user with access to private key file~~
* ~~User will serve as key vault (encrypt, decrypt, sign, etc.)~~
* ~~IPC --> Maybe pipes if they could work; but prolly will just use an internal socket~~
* ~~HTTPS Private Key != Actual private key used to encrypt/sign~~
* See **Docker** section below.
* Second thought: Azure Key Vault but that'll require us trusting Azure (also it costs a bit more $$$ but it is an option)

## More on Symmetric Encryption + Key Generation
* Intrusive thought: Can't we just add a random timer to prevent side channel attacks
* Allow users to put in authentication codes (basically they serve to generate a MAC). If they don't, we'll use a different SALT to generate an HMAC key ✅
    * If one of the keys get compromised, the master key is still safe because of Key Derivation function ✅
* SALT and IV can be transmitted with encrypted data (or included in the URL). Their job is to introduce randomness (and not act as a second authentication factor) ✅

## More on Asymmetric Encryption
* In case I forget, sign w/ your private key & encrypt with their public key. ✅
* The user should have the other person's public key. That also acts as authentication lowkey ✅
* For passwords: Store person A's public key. Still encrypt with person A's public key ✅
* For sending/authenticating: Store person B's public key. Challenge them with that. A's stuff can be done clientside ✅

## Supported Ciphers ✅
Huge shoutout to `https://soatok.blog/2020/05/13/why-aes-gcm-sucks/` and `https://soatok.blog/2020/07/12/comparison-of-symmetric-encryption-methods/#aes-gcm-vs-chacha20poly1305`
* `chacha20-poly1305` - This server is probably not running with Hardware Acceleration, so a built-in MAC + constant time processing is good
    * Also won't leak all your information, just sayin'
* `aes-256-gcm` - Authenticated AES-256. If you fundamentally distrust `HMAC + AES256-CBC` because a user can theoretically reuse keys, GCM is an option
    * Use longer nonces since ours is randomly generated: https://crypto.stackexchange.com/questions/41601/aes-gcm-recommended-iv-size-why-12-bytes
* `aes-256-cbc` -  Doesn't completely flop if we accidentally reuse IVs unlike <a href="https://medium.com/asecuritysite-when-bob-met-alice/why-is-aes-gcm-good-and-not-so-good-for-cybersecurity-28b583bbbbd3">whatever's going on in GCM with GHashes</a> + Industry standard. We already use a CBC MAC for this so 🤷‍♂️
<br>

For hashes, we'll use `sha3-512`. `sha2` is probably secure enough, but I had to stick with one thing and `sha3` isn't vulnerable to side channel analysis and maybe some length extension attacks.

## KDFs ✅
* The biggest vulnerability I can see happening with the KDFs is someone just brute forcing all the possible master keys with our given (and quite public) SALT to try and recover them
* `Node.js` doesn't have `argon2` but it does have `scrypt` which is more resistant against brute force attacks w/ support from hardware and those AI/ML GPUs 🤔 
* TLDR - We're using `scrypt` 

## Database
* Stores: URLCode, filePath, Hash of PwdHash/PubKey, expireTime, burnOnRead, HMAC-Entries
* Sort by expireTime
* Was thinking column level encryption but like the most sensitive thing is already hashed. Yay I guess you get a user's public key 😪 What are you gonna do with it? I don't really know
* On second thought, maybe we should encrypt everything except expireTime with the public key and then private key decrypt this when needed

## SQL Injection ✅
* I really love MongoDB because it's much better at stopping SQLI than you know... SQL 🙄
* But lowkey for this project, it might make more sense to boot up an SQL table ✅
* If we do that:
    * Sanitize User Input using some library I find
    * Use parameterized queries (thank god we're using Node.js for this) ✅
        * A bit weird since none of my SQLI textbooks mention this being a defense (they all just tell you to use prepared statements but like I can't really do that in this case) ✅
        * According to the internet, it's a silver bullet to SQLI ✅
        * We'll see if it worksd. Even if it doesn't, hopefully that input is sanitized by that library 🤷‍♂️ ✅
        * Edit: Apparently we're worrying too much abt this because "Sanitize User input with a library" is apparently much better than what 75% of the companies out there do  

## Encrypted files + File Syntax ✅
* The sent file can be in any format the user desires ✅
    * Although the default CLI command will use a HMAC for symmetric key ✅
    * For asymmetric encryption, the hash will be a DSA (check `Node:Crypto` to see what they support) ✅
* Serverside: `[0 for Symmetric][HMAC Size : 4 bytes][HMAC cryptosystem : 64 bytes][cryptosystem size : 4 bytes][cryptosystem : up to 2^32 bytes][data]` ✅
* Serverside Asymmetric: `[1 for Asymmetric][Signature Size : 4 bytes][Signature cryptosystem][cryptosystem size : 4 bytes][cryptosystem : up to 2^32 bytes][data]` ✅
    * Since each encryption alg is going to have different data, this is the best way to format things 
    * Treat it as a JSON
* The HMAC SALT for the cryptosystem can be stored in the cryptosystem itself ✅
    * Integrity: Attackers can't modify that HMAC SALT because they won't have the password (and by extension, won't have the HMAC). Modifying the SALT does nothing for them
    * Confidentiality: SALTs aren't meant to be private. They're public info that kinda only exists to add randomness to hash functions (so rainbow attacks go brrr)
* Encrypt the already encrypted file again! Use the password hash or public key. ✅
* This means if a dummy user decides to not upload an encrypted file or not give us an actual password hash, they still benefit from good ol' security ✅
* And if they do, tada! End to end 😎

## Automatic Burn
* Spawn a child process that does this
    * Scans db every minute
* I do NOT want the main code to be doing any deleting - and also because I have a feeling stuff might crash when we delete them
* Send heartbeat pulses to the child process to ensure it didn't die
    * Something something crash stop failures bad 🤔 I took distributed and every time you spawn a process, this word gets repeated like 50 times
    * Recovery should be pretty simple - we have a database that kind of tells you what's expired and what you need to delete
* Zero out the memory if we can find a way to do that

## FtYeet Protocol  --> Stateful ❌
* Probably not doing this; Prolly because anything stateful and public facing will be slow
* TCP Port 4000 (don't worry the server will not be running Diablo 2)
* Provide CLI to interact with this thing
* Protocol to upload:
```
    server                  client
    <---------------- ClientHello upload [enc alg] [time in minutes] [burnOnRead]

    [
        Potentially Authenticate for user:
        -----------------> Challenge (encrypted w/ pub key. I know we're stealing stuff from SSH shush)
        <----------------- Answer 
    ]

    ACK ---------------------->
    <---------------- Encrypted file (done clientside)
    PASSWD / PUBKEY -----------------> 
    <---------------- Password Hash or Public key
    URLCode ------------------->
```
* Protocol to retrieve:
```
    server                  client
    <---------------- ClientHello retrieve [URLCode]

    [
        Potentially Authenticate for user:
        -----------------> Challenge (encrypted w/ pub key. I know we're stealing stuff from SSH shush)
        <----------------- Answer 
    ]

    [
        If password:
        PASSWD ------------->
        <------------------- Password Hash
    ]

    [
        If encrypted asymmetrically:
        -----------------> Challenge (encrypted w/ pub key. I know we're stealing stuff from SSH shush)
        <----------------- Answer 
    ]
    -----------------> Encrypted file (decryption done clientside)
```
* This makes way more sense when you realize that we're encrypting the files twice

## FtYeet Protocol --> Stateless
* Since we're making it stateless, we might as well tunnel the whole thing under HTTPS
    * `certbot` and `LetsEncrypt` only works for HTTPS
    * I guess I could buy a SSL cert but those cost $
    * Also HTTPS is arguably more secure than me trying to parse `base64` encodings of binary files, public keys, etc.
    * Also this means we only need to worry about 1 application on 1 port which is kind of nice 😃
    * Also because the upload will have a lot of arguments so it's easier to manage 
* **Uploading public keys** ✅
    * Turns out HTTP really does not like CRLF characters... but public keys love them! ✅
    * To bypass this, we're encoding public keys in `base64` ✅
    * This isn't meant to "encrypt" them or to make them more secure; it's a formatting thing ✅
    * I mean public keys aren't meant to be kept secret regardless. Also if you're still paranoid, this whole thing is running over TLS so 🤷‍♂️ ✅
* **Upload Asymm**: ✅
```
POST: https://api.ftyeet.something/uploadAsymm
    --> fileSyntax in Body
    --> expire-time
    --> burn-on-read
    --> public-key (if needed)
        * Server will store public key used to encrypt the file
        * HOWEVER - the server can't spoof anything because there's a digital signature - and the server doesn't have the private key used to sign stuff
    <-- URL
```

* **Upload Symm** ✅
```
POST: https://api.ftyeet.something/upload
    --> fileSyntax in Body
    --> file-name
    --> expire-time
    --> burn-on-read
    --> pwd-hash
    --> URL (proposed URL, see "Request" section)
    <-- URL confirmed
```

* **Request** ✅
* If we're going to be sending password hashes over the internet and hashing it *again*, we need for both end users to know the same SALT to use for hashing the `pwd-hash`. But lowkey I don't trust the end user to do that properly so we're salting with the randomly generated URL
* The user will request a random, uniquely generated URL word here and use it for both the URL to eventually access the resource *AND* for `pwd-hash`.
```
GET: https://api.ftyeet.something/request
    <-- Unique word for URL
```

* **Download Asymm:** 
* Was going to use JWT, but that was way too overengineered. In addition, that doesn't fit into our stateless design at all since you needed a multi-step protocol just to send the challenge code, authenticate, send back the JWT (but do it such that JWT can only be used once within a limited timeframe), etc.
* Thought of a genius idea for downloading asymmetrically that's much simpler since we consolidate like 3 of the auth steps into 1

```
GET: https://api.ftyeet.something/getAuth
    --> URL

    <-- Challenge       // This challenge expires after 120 seconds      --> crypto signed
```

```
GET: https://api.ftyeet.something/downloadAsymm
    --> URL
    --> Signed challenge (signed by private key, this of this as ciphertext)

    // The server should have the public key in the database
    <-- If decrypt(signed challenge) == challenge, send back the file
```

* This is cryptographically sound because even if the attacker has the signature and the challenge, it can't forge the signature

* **Download Symm** ✅
```
GET: https://api.ftyeet.something/download
    --> URL
    --> Hash(Hash(password, Hash(URL)), Hash(URL))
        * Server will compare it by hashing Hash(password, Hash(URL))
    <-- Encrypted file *OR* Error
```
* Even if someone managed to bypass the auth process by exploiting the JWT token somehow, they still have to deal with E2EE
* Auth was only there to make sure we're not sending the encrypted file itself to people who don't need the encrypted file. 👮‍♂️ Doing our part to delay Quantum Computers
* **405 ERRORS**
    * I know it's good practice to return `405` errors, but that could be exploited by adversaries to unintentionally find and flood API endpoints.
    * Instead, we're going to 
* **Subdomains**
    * Use `express-subdomain` to handle this
    * We're going to try to merge the `ftYeet` protocol tunneling with the genuine website in one go by manipulating React Routers as a shortcut
    * To test locally, modify `hosts` file in `system32/drivers/etc`

## Main Site Authenticate
* Insert password
* If it's a public/private key thing, tell them that private/public key encryption isn't currently supported
* Public facing - for private user accounts, you'll need to register through CLI (although this would be limited to only people i trust)

## File System Security
* Disable execution on all files
* ~~Potentially containerize/hide stuff in a seperate "virtual file system" to isolate from main file system~~
* ~~--> not too sure how to do that; but if `Hadoop` fs could pull something like that together so can we~~
* ^^ Decided against this: If you can upload files, you can download files. If you can download files, you can probably run them.
* `"You don't get hacked by files. You get hacked by *processes*"` - guy from BSides
* Track total size
* `chown` to an account with no login perms
* We can disable `chmod` and stuff for that app
* `sudo -u vulnNodeAppUser node /path/to/app/index.js`

## Containerization ✅
* Docker - not because it's trendy but because I really don't want someone to upload and then execute a script that modifies `/etc/shadow` or smth  ✅
* Follow <a href="https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#:~:text=Docker%20is%20the%20most%20popular,directly%20on%20the%20host%20system.">this</a> ✅
* We're going to use two containers to isolate the encryption/private key signing process from the ftYeet server ✅
    * Kinda mad I didn't think of this earlier lol ✅
    * Can't access the private key files directly if they're basically on two different file systems (well... different volumes) ✅
    * Tunneled under HTTPS for double encryption just in case something happens ✅
    * Encrypted/Decrypted text can be in HTTPS body ✅
* Use a bridged network (driver) 🙂 This acts as a firewall! Only the two containers can talk to each other ✅
* Docker compose up? ✅
    * Add SQL server in here too ✅
    * Add Crypto Server  ✅

## Miscellaneous
* Crypto Server might not need all the encryption files (ie. public keys) since it has no use for any of them

## Future Plans
* Prevent bots from abusing file upload (we only have so much space)
* Get TLS (certbot for website *if* we can have a domain name --> some self-signed stuff might work temporarily; need to think of how to do it for the FTYeet Protocol)
* Private key rotation daemon on server
* 🚨 Lowkey thinking of just flat out not giving users permission to upload a file without a password because c'mon dude at that point why even bother 
* 2FA? Lowkey this is probably overkill
* Buy ftyeet domain. As of now, this DNS is getting resolved locally which is not rly a good thing lmao
* Maybe symmetric enc's cryptosystem should tell us the encryption alg
* Instead of buffer.from(), consider V8 serialization

## Next project idea
* Lowkey I want to write a script that prevents a user like apache from doing ANYTHING other than serving a website

## Plan when I open this next time
* AsymmDec
* If logging fails, delete the file that was written 
* Maybe move enc out of fetch() portion for symm file upload
* Handle verifykeypwd in command tool's asymmdec
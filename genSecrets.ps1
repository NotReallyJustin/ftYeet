# A small powershell script to generate the necessary Crypto Keys in Secrets/
# It's an automated tool, although I'd still advise you to manually generate them on your own
# This uses ftYeet's CLI files to generate the keys

# Force the users to provide passwords for all the private keys
param (
    [Parameter(Mandatory = $true)]
    [string]$PrivKeyPwd,

    [Parameter(Mandatory = $true)]
    [string]$DBPwd,

    [Parameter(Mandatory = $true)]
    [string]$CryptoCertKeyPwd,

    [Parameter(Mandatory = $true)]
    [string]$CryptoEncKeyPwd,

    [Parameter(Mandatory = $true)]
    [string]$CryptoSignKeyPwd,

    [Parameter(Mandatory = $true)]
    [string]$CryptoSymmPwd,

    [Parameter(Mandatory = $true)]
    [string]$CryptoHMACPwd,

    [Parameter(Mandatory = $true)]
    [string]$HMACCryptosysKey
)

function Abort {

    param (
        $ErrorMsg
    )

    # Print w/o stack trace (that let's be honest tells us nothing) AND without that annoying red text
    [Console]::Error.WriteLine($ErrorMsg)
    exit 1;
}

# From Stack Overflow - this is how you get around PS5 writing with a BOM (file header bytes indicating this is in UTF-8; breaks a lot of stuff)
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# Force the user to run this executable in the root ftYeet directory
if (!((Test-Path -Path ".gitignore") -or (Test-Path -Path "compose.yaml")))
{
    $LastIdx = $PsCommandPath.LastIndexOf("\");
    $File_Dir = $PsCommandPath.Substring(0, $LastIdx);
    $FileName = $PsCommandPath.Substring($LastIdx + 1);

    Abort("Error: $FileName must be executed when the current working directory is in the root ftYeet directory. For you, this is probably $File_Dir.");
}

# More sanity checking
$MAIN_FILE = "CLI\main.js"
if (!(Test-Path -Path $MAIN_FILE))
{
    Abort("Error: CLI/main.js doesn't exist. For the purposes of this ps1 script, you should also pull the entire CLI directory from Github.");
}

# If Secrets folder doesn't exist, create it
if (!(Test-Path -Path "Secrets"))
{
    mkdir "Secrets";
}

# X509
openssl req -x509 -subj "/C=US/ST=NY/L=NYC/O=ftYeet Inc/CN=ftYeet/" -passout "pass:${PrivKeyPwd}" -sha256 -days 365 -newkey rsa:2048 -keyout Secrets/privKey.pem -out Secrets/cert.pem 
[System.IO.File]::AppendAllText("Secrets/privKeyPwd.txt", $PrivKeyPwd, $utf8NoBom)

[System.IO.File]::AppendAllText("Secrets/dbPassword.txt", $DBPwd, $utf8NoBom)

openssl req -x509 -subj "/C=US/ST=NY/L=NYC/O=ftYeet Inc/CN=ftYeet/" -nodes -sha256 -days 365 -newkey rsa:2048 -keyout Secrets/dbPrivKey.pem -out Secrets/dbCert.pem 

openssl req -x509 -subj "/C=US/ST=NY/L=NYC/O=ftYeet Inc/CN=ftYeet/" -passout "pass:${CryptoCertKeyPwd}" -sha256 -days 365 -newkey rsa:2048 -keyout Secrets/cryptoHTTPKey.pem -out Secrets/cryptoCert.pem 
[System.IO.File]::AppendAllText("Secrets/cryptoCertKeyPwd.txt", $CryptoCertKeyPwd, $utf8NoBom)

# openssl has been really finnicky on Windows when I try to automate anything that's not a X509 cert. So what we're going to do is to just use our Node script to generate the keys
node CLI/main.js keygen -a rsa -v Secrets/cryptoPrivKey.pem -u Secrets/cryptoPubKey.pem -o CryptoEncKeyPwd -k aes-256-cbc
[System.IO.File]::AppendAllText("Secrets/cryptoEncKeyPwd.txt", $CryptoEncKeyPwd, $utf8NoBom)

node CLI/main.js keygen -a ed25519 -v Secrets/cryptoPrivKeySign.pem -u Secrets/cryptoPubKeySign.pem -o CryptoSignKeyPwd -k aes-256-cbc
[System.IO.File]::AppendAllText("Secrets/cryptoSignKeyPwd.txt", $CryptoSignKeyPwd, $utf8NoBom)

[System.IO.File]::AppendAllText("Secrets/cryptoSymmPwd.txt", $CryptoSymmPwd, $utf8NoBom)
[System.IO.File]::AppendAllText("Secrets/cryptoHMACPwd.txt", $CryptoHMACPwd, $utf8NoBom)
[System.IO.File]::AppendAllText("Secrets/hmacCryptosysKey.txt", $HMACCryptosysKey, $utf8NoBom)

echo "Done.";
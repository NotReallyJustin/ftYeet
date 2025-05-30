#!/bin/sh
# This is genSecrets.ps1, but it's a bash script for the Linux and WSL people

# Granted bash doesn't hold your hand when it comes to params, so this does require you to slightly know what you're doing
# Usage: ./genSecrets.sh <PrivKeyPwd> <DBPwd> <DBPrivKeyPwd> <CryptoCertKeyPwd> <CryptoEncKeyPwd> <CryptoSignKeyPwd> <CryptoSymmPwd>

# I know bash wants these in uppercase but I'm making things portable so we're just gonna ignore the convention stuff
PrivKeyPwd=$1;
DBPwd=$2;
DBPrivKeyPwd=$3;
CryptoCertKeyPwd=$4;
CryptoEncKeyPwd=$5;
CryptoSignKeyPwd=$6;
CryptoSymmPwd=$7;

function abort() {
    echo $1 >&2;
    exit 1;
}

# Error check on params
if [[ $# -ne 7 ]]; then
    abort "Usage: $0 <PrivKeyPwd> <DBPwd> <DBPrivKeyPwd> <CryptoCertKeyPwd> <CryptoEncKeyPwd> <CryptoSignKeyPwd> <CryptoSymmPwd>";
fi;

# Force the user to run this executable in the root ftYeet directory
if [[ ! -e "./gitignore" && ! -e "./compose.yaml" ]]; then
    CWD=$(realpath $0);
    FILE_DIR=$(dirname $CWD);
    FILE_NAME=$(basename $CWD);

    echo "Warning: $FILE_NAME must be executed in the root ftYeet directory. Changing bash script CWD to $FILE_DIR.";
    cd $FILE_DIR;
fi;

# If Secrets directory doesn't exist, create it
if [[ ! -d "./Secrets" ]]; then
    mkdir "./Secrets";
fi;

# Generate X509 certs
openssl req -x509 -subj "/C=US/ST=NY/L=NYC/O=ftYeet Inc/CN=ftYeet/" -passout "pass:${PrivKeyPwd}" -sha256 -days 365 -newkey rsa:2048 -keyout Secrets/privKey.pem -out Secrets/cert.pem 
echo -n $PrivKeyPwd > ./Secrets/privKeyPwd.txt

echo -n $DBPwd > ./Secrets/dbPassword.txt

openssl req -x509 -subj "/C=US/ST=NY/L=NYC/O=ftYeet Inc/CN=ftYeet/" -passout "pass:${DBPrivKeyPwd}" -sha256 -days 365 -newkey rsa:2048 -keyout Secrets/dbPrivKey.pem -out Secrets/dbCert.pem 
echo -n $DBPrivKeyPwd > ./Secrets/dbPrivKeyPwd.txt

openssl req -x509 -subj "/C=US/ST=NY/L=NYC/O=ftYeet Inc/CN=ftYeet/" -passout "pass:${CryptoCertKeyPwd}" -sha256 -days 365 -newkey rsa:2048 -keyout Secrets/cryptoHTTPKey.pem -out Secrets/cryptoCert.pem 
echo -n $CryptoCertKeyPwd > ./Secrets/cryptoCertKeyPwd.txt

# Generate two keypairs for our "HSM"
# aes[128|192|256]       Alias for aes-[128|192|256]-cbc --> from OpenSSL
openssl genrsa -aes256 -passout "pass:${CryptoEncKeyPwd}"  -out ./Secrets/cryptoPrivKey.pem 2048
openssl rsa -in ./Secrets/cryptoPrivKey.pem -passin "pass:${CryptoEncKeyPwd}" -outform PEM -pubout -out ./Secrets/cryptoPubKey.pem
echo -n $CryptoEncKeyPwd > ./Secrets/cryptoEncKeyPwd.txt
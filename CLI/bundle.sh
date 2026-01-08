#!/bin/sh
# Bundles a Linux executable in WSL. This assumes you are running bundle.sh from the CLI directory.

# Force the user to run this executable in the CLI/ directory.
if [[ ! -e "./main.js" && ! -e "./progressBar.js" ]]; then
    CWD=$(realpath $0);
    FILE_DIR=$(dirname $CWD);
    FILE_NAME=$(basename $CWD);

    echo "Warning: $FILE_NAME must be executed in the ftYeet /CLI/ directory. Changing bash script CWD to $FILE_DIR.";
    cd $FILE_DIR;
fi;

# Directory to write the output to
TARGET_DIR=$(pwd);

# Copy to temp directory to not interfere with Windows build
cp -r ../ /tmp/ftYeet;
cd /tmp/ftYeet/CLI;
rm -rf ./node_modules;              # Remove old node_modules or stuff might get weird
/usr/bin/npm install                # Using absolute path in case your WSL has two npm and npx

# Bundle to a singh
npx esbuild --bundle --platform=node --format=cjs --target=node23 --outfile=./cli.js ./main.js

# Bundle t
/usr/bin/npx pkg ./cli.js --targets latest-linux-x64 --output "$TARGET_DIR/Executables/ftYeet-linux-x64";

rm -rf /tmp/ftYeet;
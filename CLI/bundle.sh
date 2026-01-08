#!/bin/sh
# This converts the client CLI in main.js to a standalone executable for Linux x64. This script is intended to be run in WSL.
# This will only compile it for x64. Maybe if this project gets big enough I'll compile it for other versions.
# BUT if you're building this yourself, just change the variable below to one of the pkg targets here: https://www.npmjs.com/package/pkg

TARGET="latest-linux-x64"
OUTPUT_PATH="Executables/ftYeet-linux-x64"          # This is relative to the directory you are working in, not /tmp/ftYeet

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

# Bundle to a single executable
/usr/bin/npx esbuild --bundle --platform=node --format=cjs --target=node23 --outfile=./cli.js ./main.js
/usr/bin/npx pkg ./cli.js --targets $TARGET --output "$TARGET_DIR/$OUTPUT_PATH";

rm -rf /tmp/ftYeet;
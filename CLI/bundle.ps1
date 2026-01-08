# Converts main.js into a standalone executable for Windows.
# This will only compile it for x64. Maybe if this project gets big enough I'll compile it for other versions.
# BUT if you're building this yourself, just change the variable below to one of the pkg targets here: https://www.npmjs.com/package/pkg

$TARGET="latest-windows-x64"
$OUTPUT_PATH="./Executables/ftYeet-windows-x64"

# Automatically bundles all the .js files and turns it into a standalone executable
npm install
npx esbuild --bundle --platform=node --format=cjs --target=node23 --outfile=./cli.js ./main.js

# Create the Windows executable for x64
npx pkg ./cli.js --targets $TARGET --output $OUTPUT_PATH
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $OUTPUT_PATH
signtool verify /v /pa $OUTPUT_PATH     # Might get an error because it is self signed

# Cleanup
rm cli.js
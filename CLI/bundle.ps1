# Automatically bundles all the .js files and turns it into a standalone executable

npx esbuild --bundle --platform=node --format=cjs --target=node23 --outfile=cli.js ./main.js
node --experimental-sea-config sea-config.json 

# Bash script written in WSL - `.exe` extension is necessary
node -e "require('fs').copyFileSync(process.execPath, 'cli.exe')" 
signtool remove /s cli.exe 

# Inject binary into cli.exe
npx postject ./cli.exe NODE_SEA_BLOB sea-prep.blob --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 cli.exe

# Might get an error because it is self signed
signtool verify /v /pa cli.exe

# Cleanup
rm sea-prep.blob
rm cli.js
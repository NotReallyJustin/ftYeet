import * as https from 'https';
export { genURL }

/**
 * Fetches a random word. Then, it checks if that word has already been used. If it has, get another word.
 * @see https://random-word-api.herokuapp.com/home
 * @returns {Promise<String>} A random word to use in the URL
 */
const genURL = () => new Promise((resolve, reject) => {
    //TODO once we have db: Check to ensure that we don't have overlap
    var wordLen = Math.floor(Math.random() * 3) + 5;
    let word = "";
    https.get(`https://random-word-api.herokuapp.com/word?length=${wordLen}`, response => {
        
        response.on('data', data => {
            word += data;
        });

        response.on('end', () => {
            word = JSON.parse(word);
            resolve(word[0]);
        });

    }).on('error', err => {
        reject(`Issue when fetching random word: ${err.message}.`);
    });
});
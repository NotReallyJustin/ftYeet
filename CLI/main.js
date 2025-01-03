import { Command } from 'commander';
import * as functions from './functions';
const program = new Command();

program
    .version("1.0")
    .name("ftYeet")
    .description("The end-to-end temporary file transfer system.")
;

program
    .command("keygen")
    .action(() => {
        console.log("Hello World!");
    })
;

program.parse(process.argv);
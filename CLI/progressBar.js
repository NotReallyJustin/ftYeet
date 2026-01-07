import * as cliProgress from 'cli-progress';

export { SymmDLBar, SymmULBar, AsymmDLBar, AsymmULBar };

/**
 * A progress bar representing the status/phase of the ftyeet CLI requests. This is mostly a wrapper that will be extended though.
 * @extends cliProgress.SingleBar
 * @class
 */
const ProgressBar = class ProgressBar extends cliProgress.SingleBar {

    /**
     * Constructs a progress bar
     * @param {Boolean} isDownload Whether this progress bar is for download from ftYeet
     * @param {String[]} stepsArr All the steps in the process of uploading or downloading
     */
    constructor(isDownload, stepsArr)
    {
        super({
            // Bar - Download Bar, currStep - Current step number, Description - Current step description
            format: `${isDownload ? 'Download' : 'Upload'} Progress: {bar} | Step {currStep}/${stepsArr.length} | {description}`,
            hideCursor: true,
            fps: 30,
        }, cliProgress.Presets.shades_classic);

        /**
         * All the steps in the process of uploading or downloading.
         * @type {String[]}
         */
        this.stepsArr = stepsArr;

        /**
         * Current step number. This is for humans, do you need to subtract 1 to index into into `this.stepsArr`.
         * @type {Number}
         */
        this.currStep = 1;

        /**
         * Stops all action on the progress bar. This is probably because there's nothing to display in the progress bar.
         * @type {Boolean}
         */
        this.lock = false;
    }

    /**
     * Starts the progress bar.
     * @override
     */
    start()
    {
        if (this.stepsArr.length == 0)
        {
            console.error('Progress bar has nothing to display.');
            this.lock = true;
            return;
        }

        super.start(this.stepsArr.length, this.currStep, {
            currStep: this.currStep,
            description: this.stepsArr[this.currStep - 1],
        });
    }

    /**
     * Moves on to the next step in the progress bar.
     */
    increment()
    {
        if (this.lock)
        {
            return;
        }

        // Make sure there's actually something to increment
        if (this.currStep + 1 <= this.stepsArr.length)
        {
            this.currStep += 1;
            this.update(this.currStep, {
                currStep: this.currStep,
                description: this.stepsArr[this.currStep - 1],
            });
        }
    }

    /**
     * Ends the progress bar. This is likely because everything is finished.
     * @override
     */
    stop()
    {
        if (this.lock)
        {
            return;
        }

        this.lock = true;
        console.log();          // Print new line to make stuff look nicer
        super.stop();
    }
}

/**
 * A progress bar for symmetric downloads
 * @extends ProgressBar
 * @class
 */
const SymmDLBar = class SymmDLBar extends ProgressBar {

    /**
     * Constructs a symmetric download progress bar.
     */
    constructor() 
    {
        super(true, [
            "Downloading file",
            "Converting file format from download",
            "Decrypting file",
            "Writing file to disk",
            "Done"
        ]);
    }
}

/**
 * A progress bar for symmetric uploads
 * @extends ProgressBar
 * @class
 */
const SymmULBar = class SymmULBar extends ProgressBar {

    /**
     * Constructs a symmetric upload progress bar.
     */
    constructor() 
    {
        super(false, [
            "Reading local file",
            "Encrypting file",
            "Converting file format for upload",
            "Reserving URL from server",
            "Uploading file",
            "Done"
        ]);
    }
}

/**
 * A progress bar for symmetric downloads
 * @extends ProgressBar
 * @class
 */
const AsymmDLBar = class AsymmDLBar extends ProgressBar {

    /**
     * Constructs an asymmetric download progress bar.
     */
    constructor() 
    {
        super(true, [
            "Reading verifying key file",
            "Reading decryption key file",
            "Authenticating",
            "Downloading file",
            "Converting file format from download",
            "Decrypting file",
            "Done"
        ]);
    }
}

/**
 * A progress bar for asymmetric uploads
 * @extends ProgressBar
 * @class
 */
const AsymmULBar = class AsymmULBar extends ProgressBar {
    /**
     * Constructs an asymmetric upload progress bar.
     */
    constructor() 
    {
        super(false, [
            "Reading signing key file",
            "Reading encryption key file",
            "Encrypting file",
            "Signing file",
            "Converting file format for upload",
            "Reserving URL from server",
            "Uploading file",
            "Done"
        ]);
    }
}
import * as cliProgress from 'cli-progress';

export { ProgressBar }

/**
 * A CLI progress bar. It's intended to make it easier to manage all the different progress bars and phases in the main script.
 * The class will automatically ping the server and request status updates at predetermined intervals until the upload/download is complete.
 * @class
 */
const ProgressBar = new class ProgressBar {

    /**
     * Creates a CLI progress bar. This is more abstracted version of the progress bar from `cli-progress`.
     * @param {Array<String>} barPhases The different phases in either the upload or download process. These will be displayed in the progress bar. Retrieve them from `Common/bar_phases.js`, or just use one of the child/predefined ProgressBars defined in this file.
     * @param {Boolean} isDownload Whether the progress bar is for a download process. Mainly used for display.
     * @constructor
     */
    constructor(barPhases, isDownload)
    {
        /**
         * Description of all the progress steps (ie. Generating symmEnc key, etc.)
         * @type {Array<String>}
         */
        this.barPhases = barPhases;

        /**
         * The maximum phase of the bar.
         * @type {Number}
         */
        this.maxPhase = barPhases.length;

        /**
         * The current phase of the bar. When we update, all phases <= this step will be ignored.
         * `this.currPhase - 1` is also an index into the current phase in `barPhases`.
         * @type {Number}
         */
        this.currPhase = 1;

        /**
         * The actual bar that will be displayed.
         * @type {cliProgress.SingleBar}
         */
        this.bar = new cliProgress.SingleBar({
            // btw Phase == Current step in the process, action == description of current step
            format: `${isDownload ? 'Download' : 'Upload'} Progress |{bar}| Step {phase}/${this.maxPhase} | {action}`,
            hideCursor: true
        }, cliProgress.Presets.shades_classic);

    }

    /**
     * Initialize the progress bar display.
     */
    start()
    {
        this.bar.start(this.maxPhase - 1, this.currPhase - 1, {     // Start at 0 btw
            phase: this.currPhase,
            action: this.barPhases[this.currPhase - 1]
        });
    }

    /**
     * Updates the progress bar (and the action) to the next phase.
     * @param {Number} phase The new phase to update to
     */
    updatePhase(phase)
    {
        // Aagin, only do this if we have a >= phase
        if (phase > this.currPhase)
        {
            this.currPhase = phase;
            this.bar.update(this.currPhase - 1, {
                phase: this.currPhase,
                action: this.barPhases[this.currPhase - 1]
            });
        }
    }

    /**
     * Starts periodically pinging the server for status updates.
     * Either uses the password hash or the authkey, depending on whether it's symmetric or asymmetric.
     * @param {String}
     */
    startPing(pwdHash, authKey, jobID, endpoint)
    {

    }

}
/*
    A list of handy file system functions.
    Of course, if `fs` can handle them, we won't put wrappers in here.
    This is for things that require multiple steps when running `fs` itself
*/
import {
    accessSync,
    constants,
    statSync,
    chmodSync
} from 'node:fs';

export { isFile, isDir, getFileSize, exists, hasPerms, canRead, canWrite, canExecute, chmod }
/**
 * Checks if a file path is actually a file
 * @param {String} path The path to check
 * @returns {Boolean} Whether the path is valid
 */
const isFile = (path) => {
    if (!exists(path))
    {
        console.error("File path does not exist.");
        return false;
    }

    const stats = statSync(path);
    return stats.isFile();
}

/**
 * Checks if a file path is a directory
 * @param {String} path The path to check
 * @returns {Boolean} Whether the path is valid
 */
const isDir = (path) => {
    if (!exists(path))
    {
        console.error("File path does not exist.");
        return false;
    }

    const stats = statSync(path);
    return stats.isDirectory();
}

/**
 * Gets the file size of a given file
 * @param {String} path The path of the file to check
 * @returns {Number} Size of the file in bytes
 */
const getFileSize = (path) => {
    if (!isFile(path))
    {
        console.error("Given path does not point to a file. Can't read the size of a non-file entity.");
        return false;
    }

    return statSync(path).size;
}

/**
 * Checks if the file path exists
 * @param {String} path The path to check
 * @throws Exception if the program can't access the path. It probably doesn't exist but we also do not know for sure bc of permission issues.
 * @returns {Boolean} Whether the path is valid
 */
const exists = (path) => {

    try
    {
        accessSync(path, constants.F_OK)
    }
    catch(err)
    {
        if (err.code == 'ENOENT')
        {
            return false;
        }
        else if (err.code == 'EACCES' || err.code == 'EPERM')
        {
            console.error("Cannot validate path existence. The program has no permission to access the path.");
            return false;
        }
        else
        {
            console.error(`Cannot validate path existence. ${err.toString()}`)
            return false;
        }
    }

    return true;
}

/**
 * Checks whether the user/program has permissions to view certain files
 * @param {String} path The path to check
 * @param {Number} perms Bitwise permissions to check
 * @returns {Boolean}
 */
const hasPerms = (path, perms) => {

    if (!exists(path))
    {
        console.error("Path does not exist.");
        return false;
    }

    try
    {
        accessSync(path, perms);
    }
    catch(err)
    {
        return false;
    }

    return true;
}

/**
 * Checks whether the user/program can read a file.
 * @param {String} path The path to check 
 * @returns {Boolean}
 */
const canRead = (path) => hasPerms(path, constants.R_OK);

/**
 * Checks whether the user/program can write to a file.
 * @param {String} path The path to check 
 * @returns {Boolean}
 */
const canWrite = (path) => hasPerms(path, constants.W_OK);

/**
 * Checks whether the user/program can execute a file.
 * @param {String} path The path to check 
 * @returns {Boolean}
 */
const canExecute = (path) => hasPerms(path, constants.X_OK);

/**
 * Change permissions of a file or directory.
 * @param {String} path The path to chmod
 * @param {Number} permissionMode Linux-like octal permissions. ie. `0o777` to grant permissions to everyone.
 * @returns {Boolean} Whether the operation was successful.
 */
function chmod(path, permissionMode)
{
    if (!exists(path))
    {
        console.error("Path does not exist. Can't change permissions of a non-existent file.");
        return false;
    }

    try
    {
        chmodSync(path, permissionMode);
    }
    catch(err)
    {
        console.error(`Error when changing permissions: ${err.toString()}`);
        return false;
    }

    return true;
}
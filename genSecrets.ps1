# A small powershell script to generate the necessary Crypto Keys in Secrets/
# It's an automated tool, although I'd still advise you to manually generate them on your own
# This uses ftYeet's CLI files to generate the keys

# Force the users to provide passwords for all the private keys
param (
    [Parameter(Mandatory = $true)]
    [string]$PrivKeyPwd,

    [Parameter(Mandatory = $true)]
    [string]$DBPrivKeyPwd,

    [Parameter(Mandatory = $true)]
    [string]$CryptoCertKeyPwd,

    [Parameter(Mandatory = $true)]
    [string]$CryptoEncKeyPwd,

    [Parameter(Mandatory = $true)]
    [string]$CryptoSignKeyPwd,

    [Parameter(Mandatory = $true)]
    [string]$CryptoSymmPwd
)

function Abort {

    param (
        $ErrorMsg
    )

    # Print w/o stack trace (that let's be honest tells us nothing) AND without that annoying red text
    [Console]::Error.WriteLine($ErrorMsg)
    exit 1;
}

# Force the user to run this executable in the root ftYeet directory
if (!((Test-Path -Path ".gitignore") -or (Test-Path -Path "compose.yaml")))
{
    $LastIdx = $PsCommandPath.LastIndexOf("\");
    $File_Dir = $PsCommandPath.Substring(0, $LastIdx);
    $FileName = $PsCommandPath.Substring($LastIdx + 1);

    Abort("Error: $FileName must be executed when the current working directory is in the root ftYeet directory. For you, this is probably $File_Dir.");
}

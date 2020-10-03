$homeDir = "C:\UWPCheck"

# ensure the working directory exists
if (!(Test-Path $homeDir))
    {
    Write-Host "Home directory does not exist." -ForegroundColor Yellow
    Write-Host "Edit the script ($homeDir in line 1) to point to working directory of your choice." -ForegroundColor Yellow
    Write-Host "Place remoteSigCheck.ps1 and fwFunction.ps1 in this directory."
    break
    }

# create the catalog directory if needed
if (!(Test-Path $homeDir\catalogs))
    {
    mkdir $homeDir\catalogs
    }

# move to the working directory
if ($PWD -ne $homeDir)
    {cd $homeDir}

# load functions
. $PSScriptRoot\fwFunctions.ps1

# check if run as admin, otherwise exit
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$admin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (!$admin)
    {
    "Not running as admin."
    Return
    }

##############################
### VM SETUP INSTRUCTIONS ####
##############################

# host
# outbound firewall to allow all traffic to hosts on closed VM network
# start winrm service
# set-Item -Path WSMan:\localhost\client\trustedhosts -value "192.168.145.132, 192.168.145.133, 192.168.145.134"

# client
## turn off sleep
## Enable-PSRemoting -skipnetworkprofilecheck -Force

# WINDEV2004EVAL
# creds = user:password

# WINDEV2003EVAL
# creds = user:password

# MSEDGEWIN10
# creds = ieuser:password

# net user password
# net user user password /add
# net localgroup administrators user /add

##############################
##### BEGIN SCRIPT WORK ######
##############################

# setup credentials and persistent connections
# This could have better handling if required for the complexity of the environment.
$remoteHosts = @(
    "192.168.145.132", 
    "192.168.145.133", 
    "192.168.145.134"
    )
Write-Host "[+] Connecting to $($remoteHosts.Count) remote hosts." -ForegroundColor Green
$cred = Get-Credential -UserName "testAdmin" -Message "get password"
$sessions = New-PSSession $remoteHosts -Credential $cred
foreach ($remoteHost in $remoteHosts) {if ($sessions.ComputerName -notcontains $remoteHost) {Write-Host "[-] Host not connected: $remoteHost" -ForegroundColor Yellow}}

# get list of unsigned remote binaries
Write-Host "[+] Getting list of unsigned remote binaries" -ForegroundColor Green
Invoke-Command $sessions {
    $binaryPaths = (gci $env:ProgramFiles\Windowsapps -Recurse -Force | Where-Object {Test-Path -Include "*.acm", "*.ax", "*.cpl", "*.dll", "*.drv", "*.efi", "*.exe", "*.mui", "*.ocx", "*.scr", "*.sys", "*.tsp" $_.FullName} | select -ExpandProperty Fullname)
    # only need to further investigate unsigned files
    $notAuthSigned = $binarypaths | Get-AuthenticodeSignature | Where-Object {$_.status -ne "Valid"}
    # 
    foreach ($binary in $notAuthSigned)
        {
        # get catalog hash (MD5)
        $catPath = ((split-path $binary.path | select-string '^.+WindowsApps\\[^\\]+').Matches.Value) + "\AppXMetaData\codeintegrity.cat"
        if (Test-Path $catPath)
            {
            $catHash = $hash = (Get-FileHash $catPath -Algorithm MD5).hash
            Add-Member -InputObject $binary -NotePropertyName "catHash" -NotePropertyValue $catHash
            }
        # get PE image hash
        $AppXhash = (Get-AppLockerFileInformation $binary.path).hash.hashdatastring.substring(2)
        Add-Member -InputObject $binary -NotePropertyName "AppXhash" -NotePropertyValue $AppXhash
        }

    # collect info about store-signed packages not installed in WindowsApps
    $rogueAppX = Get-AppPackage -AllUsers | Where-Object {$_.signaturekind -eq "Store" -and $_.installlocation -notlike "$env:ProgramFiles\WindowsApps*" -and $_.installlocation -ne $null}
    }

$remoteNotAuthSigned = Invoke-Command $sessions {$notAuthSigned}
$rogueAppX = Invoke-Command $sessions {$rogueAppX}

# collect local catalog data
Write-Host "[+] Collecting Local Catalog Data" -ForegroundColor Green
$catalogs = (gci $env:ProgramFiles\Windowsapps -Recurse -Force | 
            Where-Object {$_.name -eq "codeintegrity.cat"} | 
            Sort-Object -Property length)

foreach ($catalog in $catalogs)
    {
    $hash = (Get-FileHash $catalog.fullname -Algorithm MD5).hash
    Add-Member -InputObject $catalog -NotePropertyName "hash" -NotePropertyValue $hash
    }

# get local catalogs first
Write-Host "[+] $($Catalogs.Count) total local catalogs" -ForegroundColor Green

$collectedLocalCatalogs = ($catalogs | Where-Object {(Test-Path ".\catalogs\$($_.hash)") -eq $true})
Write-Host "[+] $($collectedLocalCatalogs.Count) local catalogs already collected" -ForegroundColor Green

$uncollectedLocalCatalogs = ($catalogs | Where-Object {(Test-Path ".\catalogs\$($_.hash)") -eq $false})
Write-Host "[+] Collecting $($uncollectedLocalCatalogs.count) local catalogs" -ForegroundColor Green

foreach ($catalog in $uncollectedLocalCatalogs)
    {
    # copy file
    Copy-Item -Path $catalog.FullName -Destination (".\catalogs\" + $catalog.hash)
    if (Test-Path (".\catalogs\" + $catalog.hash))
        {Write-Host "`r[+] Successfully grabbed catalog: $($catalog.hash) from local host`r" -NoNewline -ForegroundColor Green}
    }
if ($uncollectedLocalCatalogs) {Write-Host ("" * 100) -NoNewline} # clearing line

# determine hashes of catalogs still required (must be retrieved from remote hosts)

# collect remote catalog data
Write-Host "[+] Collecting remote catalog data" -ForegroundColor Green
Invoke-Command $sessions {
    (Get-Process -id $pid).PriorityClass = "BelowNormal"
    $catalogs = (gci $env:ProgramFiles\Windowsapps -Recurse -Force | Where-Object {$_.name -eq "codeintegrity.cat"} | Sort-Object -Property length)
    foreach ($catalog in $catalogs)
        {
        $hash = (Get-FileHash $catalog.fullname -Algorithm MD5).hash
        Add-Member -InputObject $catalog -NotePropertyName "hash" -NotePropertyValue $hash
        }
    }

# combine remote catalogs locations
$remoteCatalogs = Invoke-Command $sessions {$catalogs}


Measure-Command{ # remove
# get catalogs from remote hosts, skipping duplicates
Write-Host "[+] $($remoteCatalogs.Count) total remote Catalogs" -ForegroundColor Green

$collectedRemoteCatalogs = ($remoteCatalogs | Where-Object {(Test-Path ".\catalogs\$($_.hash)") -eq $true})
Write-Host "[+] $($collectedRemoteCatalogs.Count) remote catalogs already collected" -ForegroundColor Green

$uncollectedRemoteCatalogs = ($remoteCatalogs | Where-Object {(Test-Path ".\catalogs\$($_.hash)") -eq $false})
Write-Host "[+] Collecting $(($uncollectedRemoteCatalogs | select hash -Unique).count) unique remote catalogs" -ForegroundColor Green

$parseStep = 0
$filesCollected = 0
foreach ($catalog in $uncollectedRemoteCatalogs)
    {
    Write-Progress -Id 2 -Activity 'Collecting remote catalogs' -PercentComplete ((($parseStep++) / $uncollectedRemoteCatalogs.Count) * 100)
    if (!(Test-Path (".\catalogs\" + $catalog.hash)))
        {
        # identify correct session
        foreach ($session in $sessions)
            {
            if ($session.computername -eq $catalog.PSComputerName)
                {
                $fileSession = $session
                break
                }
            }
        # copy file
        Copy-Item -FromSession $filesession -Path $catalog.FullName -Destination (".\catalogs\" + $catalog.hash)
        $filesCollected++
        if (!(Test-Path (".\catalogs\" + $catalog.hash)))
            {Write-Host "`r[-] Failed to grab catalog: $($catalog.hash) from $($catalog.PSComputerName)`r" -NoNewline -ForegroundColor Yellow}
        }
    }
Write-Host "[+] Collected $filesCollected unique files out of $($uncollectedRemoteCatalogs.Count) total files" -ForegroundColor Green
} # remove
# verify signatures on all catalogs
$localCatalogPaths = (gci .\catalogs| select -ExpandProperty fullname)
$statusLocalCat = ($localCatalogPaths | Get-AuthenticodeSignature)
$verifiedLocalCat = $statusLocalCat | Where-Object {$_.status -eq "Valid"}
$unverifiedLocalCat = $statusLocalCat | Where-Object {$_.status -ne "Valid"}

Write-Host "[+] Catalogs verified:     $($verifiedLocalCat.Count)" -ForegroundColor Green
Write-Host "[!] Catalogs not verified: $($unverifiedLocalCat.Count)" -ForegroundColor Red

if ($unverifiedLocalCat.count -ge 1)
    {$unverifiedLocalCat | select Status,SignatureType,Path}

# dump catalogs to create master catalog, use hash as key
Write-Host "[+] Generating Master Catalog" -ForegroundColor Green

$masterCatalog = @{}
foreach ($cat in $verifiedLocalCat)
    {
    $catHash = $cat.path.Split("\")[-1]
    $hashes = (Dump-Catalog -catpath $cat.path)
    if (!($masterCatalog.ContainsKey($catHash)))
        {$masterCatalog.Add($catHash, $hashes)}
    }

Write-Host "[+] Checking $($remoteNotAuthSigned.Count) potentially unsigned files." -ForegroundColor Green

# go through each file that might be catalog signed (i.e. at least has an associated catalog)
foreach ($unsignedbinary in ($remoteNotAuthSigned | Where-Object {$_.catHash -ne $null}))
    {
    $catHash = $unsignedbinary.catHash
    $binHash = $unsignedbinary.AppXhash
    # check if hash is in the associated catalog
    if ($masterCatalog.$catHash.Contains($binHash))
        {
        # update signed status
        $unsignedbinary.Status = "Signed"
        if ($unsignedbinary.Status -ne "Signed")
            {"didn't take for some reason " + $unsignedbinary}
        # add the company
        $correctCat = $verifiedLocalCat | Where-Object {$_.path.Split("\")[-1] -eq $catHash}
        $company = [regex]::Match($correctCat.SignerCertificate.Subject,'.+O=([^=]+),').Groups[1].Value
        if ($company -eq "")
            {$company = [regex]::Match($correctCat.SignerCertificate.Subject,'.+=([^=]+)').Groups[1].Value}
        if ($company -eq "")
            {$company = $correctCat.SignerCertificate.Subject}
        $issuer = [regex]::Match($correctCat.SignerCertificate.Issuer,'.+O=([^=]+),').Groups[1].Value
        Add-Member -InputObject $unsignedbinary -NotePropertyName "Company" -NotePropertyValue $company -Force
        Add-Member -InputObject $unsignedbinary -NotePropertyName "Issuer" -NotePropertyValue $issuer -Force
        }
    }

# organize signature results
$signed = $remoteNotAuthSigned | Where-Object {$_.status -eq "Signed"} | select status, company, issuer, path, sha1, PSComputerName | Sort-Object company -Descending
$microsoftSigned = $signed | Where-Object {$_.company -eq "Microsoft Corporation"}
$nonMicrosoftSigned = $signed | Where-Object {$_.company -ne "Microsoft Corporation"}
$unsigned = $remoteNotAuthSigned | Where-Object {$_.status -ne "Signed"} | select status, company, issuer, path, sha1, PSComputerName | Sort-Object company -Descending

# report signature results
Write-Host "[+] $($microsoftSigned.count) Microsoft Signed Binaries" -ForegroundColor Green
$microsoftSigned | select status, company, issuer, path, PSComputerName | Sort-Object company -Descending | format-table

Write-Host "[+] $($nonMicrosoftSigned.count) Non-Microsoft Signed Binaries (At least not signed in the typical way)" -ForegroundColor Green
$nonMicrosoftSigned | select status, company, issuer, path, PSComputerName | Sort-Object company -Descending | format-table

if ($unsigned)
    {
    Write-Host "[!] $($unsigned.count) Unsigned Remote Binaries" -ForegroundColor Red
    $unsigned | select status, company, issuer, path, sha1, PSComputerName | Sort-Object company -Descending | format-table
    }
else {Write-Host "[+] $($unsigned.count) Unsigned Remote Binaries" -ForegroundColor Green}

# warn about AppX signed packages not installed in WindowsApps
if ($rogueAppX)
    {Write-Host "[-] Remote Non-Certificate-Signed AppX Packages Located Outside '%programfiles%\WindowsApps' -- Very Unusual" -ForegroundColor Yellow
    $rogueAppX | select name, installlocation, PSComputerName
    }

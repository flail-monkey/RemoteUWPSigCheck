# map physical path to logical paths
function Get-DevicePath
{
<#
.SYNOPSIS

    Returns the device paths for each volume.

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause

.DESCRIPTION

    Get-DevicePath returns the corresponding device path for each drive letter. This is useful for converting device paths to drive letters.

.EXAMPLE

    Get-DevicePath

    DevicePath              DriveLetter
    ----------              -----------
    \Device\HarddiskVolume2 D:
    \Device\HarddiskVolume4 C:

.OUTPUTS

    PSObject[]

    For each mount point, a PSObject is returned representing the drive letter and device path.
#>

    # Utilize P/Invoke in order to call QueryDosDevice. I prefer using 
    # reflection over Add-Type since it doesn't require compiling C# code.
    $DynAssembly = New-Object System.Reflection.AssemblyName('SysUtils')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('SysUtils', $False)

    # Define [Kernel32]::QueryDosDevice method
    $TypeBuilder = $ModuleBuilder.DefineType('Kernel32', 'Public, Class')
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('QueryDosDevice', 'kernel32.dll', ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static), [Reflection.CallingConventions]::Standard, [UInt32], [Type[]]@([String], [Text.StringBuilder], [UInt32]), [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('kernel32.dll'), [Reflection.FieldInfo[]]@($SetLastError), @($true))
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
    $Kernel32 = $TypeBuilder.CreateType()

    $Max = 65536
    $StringBuilder = New-Object System.Text.StringBuilder($Max)

    Get-WmiObject Win32_Volume | ? { $_.DriveLetter } | % {
        $ReturnLength = $Kernel32::QueryDosDevice($_.DriveLetter, $StringBuilder, $Max)

        if ($ReturnLength)
        {
            $DriveMapping = @{
                DriveLetter = $_.DriveLetter
                DevicePath = $StringBuilder.ToString()
            }

            New-Object PSObject -Property $DriveMapping
        }
    }
}

# convert physical path to logical path, don't change logical paths
function Get-FixedPath($rawPath, $drives)
    {
    if ($rawPath.StartsWith("\device"))
        {
        ForEach ($drive in $drives)
            {
            if ($rawPath.StartsWith($drive.DevicePath.ToLower()))
                {
                ($parsedPath = $rawPath.Replace($drive.DevicePath.ToLower(), $drive.DriveLetter)) | Out-Null
                break
                }
            }
        }
    else {$parsedPath = $rawPath}
    return $parsedPath
    }

# reparse list of events making helpful edits (so far just fixing paths)
function Get-FixedEvent($eventList)
    {
    # setup
    $drives = Get-DevicePath
    [System.Collections.ArrayList]$parsedEventList = @()
    $eventStep= 0

    Write-Progress -Id 2 -Activity 'Fixing Process Paths' -PercentComplete ((($eventStep++) / $eventList.Count) * 100) -ParentId 1
    # parse each event
    ForEach ($event in $eventList)
        {
        $workingEvent = $event
        # detail
        if ($workingEvent.Process)
            # reparse process path
            {$workingEvent.Process = (Get-FixedPath -rawPath $workingEvent.Process -drives $drives)}
        # process summary
        elseif ($workingEvent.Name)
            # reparse process path
            {$workingEvent.Name = (Get-FixedPath -rawPath $workingEvent.Name -drives $drives)}

        $parsedEventList.Add($workingEvent) | Out-Null
        }
    Write-Progress -Id 2 -Activity 'Fixing Process Paths' -Completed -ParentId 1
    return $parsedEventList
    }

# add domain-enrichment to dst ips in event logs
function Get-Domains($eventList)
    {

    # setup
    $localIPs = (Get-NetIPAddress).IPAddress
    [System.Collections.ArrayList]$parsedEventList = @()

    # parse each event
    ForEach ($event in $eventList)
        {
        $dst = $event.DstIP
        $workingEvent = $event
        # check if local IP
        if ($localIPs -notcontains $dst)
            {
            try 
                {
                $resolve = (Resolve-DnsName $event.DstIP -ErrorAction SilentlyContinue -DnsOnly PTR -QuickTimeout).NameHost
                if ($resolve)
                    {$workingEvent.DstIP = $dst + " --- " + $resolve}
                }
            catch
                {
                "Error trying to resolve" + $event.DstIP
                }
            }
        $parsedEventList.add($workingEvent) | Out-Null
        }
    return $parsedEventList
    }

# dump hashes from microsoft catalog file
function Dump-Catalog($catPath, $sigcheckPath)
    {
    # provide path to catalog and sigcheck binary
    # return array of hashes
    $sigcheckPath = (gci $PSScriptRoot -Filter sigcheck.exe | Select-Object -ExpandProperty Fullname)
    foreach ($hashString in ((& $sigcheckPath -d $catPath) | where-object {$_.Contains("Hash")}))
        {$hashString.Split(":")[1].Trim()}
    }

# check the signature of a Windows App file
function Get-WinAppSignature($procPath)
    {
    if ($procPath -ilike "*\WindowsApps\*")
        {
        $cat = ((split-path $procPath | select-string '^.+WindowsApps\\[^\\]+').Matches.Value) + "\AppXMetaData\codeintegrity.cat"
        if (!(Test-Path $cat))
            {write-host $cat}
        $validCat = Get-AuthenticodeSignature $cat
        if ($ValidCat.Status -eq "Valid")
            {
            $hashes = Dump-Catalog -catPath $cat
            if ($hashes -contains (Get-AppLockerFileInformation $procPath).hash.hashdatastring.substring(2))
                {
                $company = [regex]::Match($validCat.SignerCertificate.Subject,'.+O=([^=]+),').Groups[1].Value
                if ($company -eq "")
                    {$company = $validCat.SignerCertificate.Subject}
                return $true, $company
                }
            }
        else {return $false, ""}
        }
    else {return $false, ""}
    }

# get signature information about a list of processes (full path)
function Get-Signatures($pathList)
    {
    $sigcheckPath = (gci $PSScriptRoot -Filter sigcheck.exe | Select-Object -ExpandProperty Fullname)
    $parsedSigs = [System.Collections.ArrayList]@()
    foreach ($path in $pathList)
        {
        $parsedSigProc = [PSCustomObject]@{
        Status = "Unknown"
        Certificate = "Unknown"
        Path = $path
        SHA1 = "Not checked"}
        if (Test-Path $path)
            {
            $initialCheck = Get-AuthenticodeSignature($path)
            $parsedSigProc.Status = $initialCheck.status
            if ($initialCheck.Status -eq "Valid")
                {
                $parsedSigProc.Certificate = [regex]::Match($initialCheck.SignerCertificate.Subject,'.+O=([^=]+),').Groups[1].Value
                }
            if ($initialCheck.Status -eq "NotSigned")
                {
                $winSig = Get-WinAppSignature $parsedSigProc.Path
                if ($winSig[0])
                    {
                    $parsedSigProc.Status = "Valid - AppX"
                    $parsedSigProc.Certificate = $winSig[1]
                    }
                }
            if ($parsedSigProc.status -eq "NotSigned")
                {
                $parsedSigProc.SHA1 = (Get-FileHash $initialCheck.Path -Algorithm SHA1).Hash
                }
            }
        else 
            {
            $parsedSigProc.Status = "Missing file"
            $parsedSigProc.SHA1 = "Missing file"
            }
        $parsedSigs.Add($parsedSigProc) | Out-Null
        }
    return $parsedSigs
    }
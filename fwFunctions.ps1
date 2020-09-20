# dump hashes from microsoft catalog file
function Dump-Catalog($catPath, $sigcheckPath)
    {
    # provide path to catalog and sigcheck binary
    # return array of hashes
    $sigcheckPath = (gci $PSScriptRoot -Filter sigcheck.exe | Select-Object -ExpandProperty Fullname)
    foreach ($hashString in ((& $sigcheckPath -d $catPath) | where-object {$_.Contains("Hash")}))
        {$hashString.Split(":")[1].Trim()}
    }
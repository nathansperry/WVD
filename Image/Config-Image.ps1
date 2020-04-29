## Define Variables
$zipfile = "https://github.com/nathansperry/WVD/archive/master.zip"
$zipname = "master.zip"
$tmp = "D:"
$extracted = "$tmp\WVD-master\Image"

## Download and Extract Training Labs
Write-Verbose -Message ('Please wait while downloading Lab Resources (~220mb)...')
Try {
        
    Start-BitsTransfer -Source $zipfile -Destination $tmp -ErrorAction Stop | Out-Null
    
    }
Catch {

    Write-Error -Message ("There was a problem downloading the Lab Resources file $zipfile.")      
    exit

}

## Extract zip file
Add-Type -assembly "system.io.compression.filesystem"
Write-Verbose -Message ('Extacting Lab Exercises to ''{0}''.' -f $tmp)
[io.compression.zipfile]::ExtractToDirectory("$extract\$zipname", $tmp)


# Set Locale, language etc. 
& $env:SystemRoot\System32\control.exe "intl.cpl,,/f:""$extracted\UKRegion.xml"""

# Set Timezone
& tzutil /s "GMT Standard Time"

# Set languages/culture
Set-Culture en-GB

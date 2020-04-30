function Set-Registry {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.String] $keyPath,

        [Parameter()]
        [System.String] $regName,

        [Parameter()]
        [System.String] $regValue,

        [Parameter()]
        [ValidateSet('String','DWord','Binary')]
        [System.String] $propertyType

    )

    ForEach ($key in $keyPath.split("{\}")) {

        $currentPath += $key + "\"

        if (!(Test-Path $currentPath)) {
        
            New-Item -Path $currentPath | Out-Null
            Write-Verbose "Created '$currentPath' Registry Path."
        }
    }
    
    if ($regName){
    
        New-ItemProperty -Path $currentpath -Name $regName -value $regValue -PropertyType $propertyType -Force | Out-Null
        Write-Verbose "Set '$currentPath$regName' to [$regValue]"
    }
}

function Start-Install {
    [CmdletBinding()]
    param (
        # Path to process to start.
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $FilePath,
        # Arguments (if any) to apply to the process.
        [Parameter()] [string] $Arguments
    )

    process {

        Write-Verbose ('Running "{0} {1}".' -f $FilePath, $Arguments);

        if ($Arguments) { $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru; }
        else { $process = Start-Process -FilePath $FilePath -PassThru; }
        
        ## Bug whereby the exit code doesn't get returned if handle not referenced
        $process.Handle | out-null

        #Write-Verbose ('Process "{0}" launched.' -f $process.Id);
        #Write-Verbose ('Waiting for process "{0}" to exit...' -f $process.Id);
        Wait-Process -Id $process.Id;
        #Write-Verbose ('Process "{0}" exited with code "{1}".' -f $process.Id, $process.ExitCode);
        
        ## Return the exit code..
        #Return $process.ExitCode;
    }
}

function Start-Download {
    [CmdletBinding()]
    param (
        # source file.
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $source,
        # destionation to save file
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $destination
    )

    # gather file name
    $filename = ($source -split '/')[-1]

    if (!(Test-Path -Path "$destination\$filename" -PathType Leaf)) {

        Try {
            
            (New-Object System.Net.WebClient).DownloadFile($source, $destination)
            #Start-BitsTransfer -Source $source -Destination $destination -ErrorAction Stop | Out-Null
        
        }
        Catch {
            
            Write-Error $Error[0]
            #Write-Error -Message ("There was a problem downloading the file $source") 
            Stop-Transcript     
            exit
    
        }
    
    }
    else {
        Write-Warning -Message ("'$destination\$filename' already exists")
    }    
}

function Extract-File {
    [CmdletBinding()]
    param (
        # Path to process to start.
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $filePath,
        # Arguments (if any) to apply to the process.
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $extractedPath
    )

    Add-Type -assembly "system.io.compression.filesystem"
    Write-Verbose -Message ("Extacting ''{0}'' to ''{1}'' ." -f $filePath,$extractedPath)
    [io.compression.zipfile]::ExtractToDirectory($filePath, $extractedPath)

    Remove-Item -Path $filePath -Force
 
}

Start-Transcript -Path  "$env:windir\Logs\Config-Image.log" -Force | Out-Null

## path to extract all files
$extractPath = "D:\"

## configurations file
$download = "https://github.com/nathansperry/WVD/archive/master.zip"
$name = ($download -split '/')[-1]
$extractFile = (Join-Path -path $extractPath -ChildPath $name)
$ukregionXML = (Join-Path -path $extractPath -ChildPath "WVD-master\Image\UKRegion.xml")

## download configuration files
Start-Download -source $download -destination $extractFile -Verbose
Extract-File -filePath $extractFile -extractedPath $extractPath

## Set Locale, language etc. 
& $env:SystemRoot\System32\control.exe "intl.cpl,,/f:$ukregionXML"
# Set Timezone
& tzutil /s "GMT Standard Time"
# Set languages/culture
Set-Culture en-GB

## fslogix
$download = "https://aka.ms/fslogix_download"
$name = "fslogix.zip"
$extractFile = (Join-Path -path $extractPath -ChildPath $name)
$installer = "$extractPath" + "FSLogix\x64\Release\FSLogixAppsSetup.exe"
$arguments = "/install /quiet /norestart"

## download and install FSLogix
Start-Download -source $download -destination $extractFile -Verbose
Extract-File -filePath $extractFile -extractedPath (Join-Path -path $extractPath -ChildPath 'Fslogix')
Start-Install -FilePath $installer -Arguments $arguments

## teams
#$download = "https://teams.microsoft.com/downloads/desktopurl?env=production&plat=windows&download=true&managedInstaller=true&arch=x64"
$download = "https://statics.teams.cdn.office.net/production-windows-x64/1.3.00.4461/Teams_windows_x64.msi"
#$name = "teams.msi"
$name = ($download -split '/')[-1]
$extractFile = (Join-Path -path $extractPath -ChildPath $name)
$installer = "$extractPath" + "$name"
$arguments = "/i $installer /l`*v C:\windows\logs\teamsinstall.log ALLUSER=1 /quiet"

## download and install Teams
Start-Download -source $download -destination $extractFile -Verbose
## set registry to allow machine wide install
Set-Registry -keyPath "HKLM:SOFTWARE\Microsoft\Teams" -regName IsWVDEnvironment -regValue 1 -propertyType DWord
## set registry to stop prompt when launching from browser
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32 -Name Teams -PropertyType Binary -Value ([byte[]](0x01,0x00,0x00,0x00,0x1a,0x19,0xc3,0xb9,0x62,0x69,0xd5,0x01)) -Force | Out-Null
## start install
Start-Install -FilePath 'C:\Windows\System32\msiexec.exe' -Arguments $arguments

Stop-Transcript

<#
    .SYNOPSIS
    This script is used to configure the virtual desktop image

    .DESCRIPTION
    This script is used to configure the virtual desktop image

    .LINK
    http://virtualengine.co.uk

    NAME: N/A
    AUTHOR: Nathan Sperry, Virtual Engine
    LASTEDIT: 01/05/2020
    VERSION : 1.0
    WEBSITE: http://www.virtualengine.co.uk

#>

function Update-DefaultUserProfile {

    [CmdletBinding()]
    param (


    )

    ## load registry hive
    Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Load HKLM\\DUTemp C:\\Users\\Default\\NTUSER.DAT" -Wait
    Write-Verbose ("Loaded NTUSER.DAT registry hive") -Verbose

    ## Setting the View > Item Check Box to off
    Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Add HKLM\\DUTemp\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /v AutoCheckSelect /t REG_DWORD /d 0" -Wait
    Write-Verbose ("Processed default user changes") -Verbose

    ## unload registry hive
    Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Unload HKLM\\DUTemp" -Wait
    Write-Verbose ("Unloaded NTUSER.DAT registry hive") -Verbose


}

function Start-DownloadCtxOptimiser {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.String] $download,

        [Parameter(Mandatory)]
        [System.String] $extractPath

    )

    #Downloads Latest Citrix Opimizer from https://support.citrix.com/article/CTX224676
    #Can be used as part of a pipeline or MDT task sequence.
    #Ryan Butler TechDrabble.com @ryan_c_butler 07/19/2019

    #Uncomment to use plain text or env variables
    $CitrixUserName = $env:ctxuser
    $CitrixPassword = $env:ctxpw

    #Uncomment to use credential object
    #$creds = Get-Credential
    #$CitrixUserName = $creds.UserName
    #$CitrixPassword = $creds.GetNetworkCredential().Password

    $name = ($download -split '/')[-1]
    $extractFile = (Join-Path -path $extractPath -ChildPath $name)

    #Initialize Session 
    Invoke-WebRequest "https://identity.citrix.com/Utility/STS/Sign-In" -SessionVariable websession -UseBasicParsing | Out-Null

    #Set Form
    $form = @{
        "persistent" = "1"
        "userName" = $CitrixUserName
        "loginbtn" = ""
        "password" = $CitrixPassword
        "returnURL" = "https://www.citrix.com/login/bridge?url=https%3A%2F%2Fsupport.citrix.com%2Farticle%2FCTX224676%3Fdownload"
        "errorURL" = 'https://www.citrix.com/login?url=https%3A%2F%2Fsupport.citrix.com%2Farticle%2FCTX224676%3Fdownload&err=y'
    }
    #Authenticate
    Invoke-WebRequest -Uri ("https://identity.citrix.com/Utility/STS/Sign-In") -WebSession $websession -Method POST -Body $form -ContentType "application/x-www-form-urlencoded" -UseBasicParsing | Out-Null

    #Download File
    Invoke-WebRequest -WebSession $websession -Uri $download -OutFile $extractFile -Verbose -UseBasicParsing
    

    #extract file
    Start-ExtractFile -filePath $extractFile -extractedPath (Join-Path -path $extractPath -ChildPath 'CitrixOptimizer')

}

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

        Write-Verbose ('Running "{0} {1}".' -f $FilePath, $Arguments) -Verbose;

        if ($Arguments) { $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru; }
        else { $process = Start-Process -FilePath $FilePath -PassThru; }
        
        ## Bug whereby the exit code doesn't get returned if handle not referenced
        $process.Handle | out-null

        Wait-Process -Id $process.Id;
        
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
            Write-Verbose ("Downloaded '{0}' to '{1}." -f $source, $destination) -Verbose
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

function Start-ExtractFile {
    [CmdletBinding()]
    param (
        # Path to process to start.
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $filePath,
        # Arguments (if any) to apply to the process.
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $extractedPath
    )

    Add-Type -assembly "system.io.compression.filesystem"
    Write-Verbose -Message ("Extacting ''{0}'' to ''{1}''." -f $filePath,$extractedPath) -Verbose
    [io.compression.zipfile]::ExtractToDirectory($filePath, $extractedPath)

    Remove-Item -Path $filePath -Force
    Write-Verbose -Message ("Deleting ''{0}''." -f $filePath) -Verbose
 
}


Start-Transcript -Path  "$env:windir\Logs\Config-Image.log" -Force | Out-Null

## install evergreen module
if (!(Test-Path -Path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget")) {Find-PackageProvider -Name 'Nuget' -ForceBootstrap -IncludeDependencies}
if (!(Get-Module -ListAvailable -Name Evergreen)) {Install-Module Evergreen -Scope AllUsers -Force | Import-Module Evergreen -Force}

## path to extract all files
$extractPath = "D:\"

## configurations file
$download = "https://github.com/nathansperry/WVD/archive/master.zip"
$name = ($download -split '/')[-1]
$extractFile = (Join-Path -path $extractPath -ChildPath $name)
$ukregionXML = (Join-Path -path $extractPath -ChildPath "WVD-master\Image\UKRegion.xml")

## download configuration files
Start-Download -source $download -destination $extractFile -Verbose
Start-ExtractFile -filePath $extractFile -extractedPath $extractPath

## Set Locale, language etc. 
& $env:SystemRoot\System32\control.exe "intl.cpl,,/f:"""$ukregionXML""""
# Set Timezone
& tzutil /s "GMT Standard Time"
# Set languages/culture
Set-Culture en-GB
Write-Verbose -Message ("Regional settings applied.") -Verbose

## fslogix
$fsl = Get-MicrosoftFSLogixApps | Select-Object -last 1
$download = $fsl.uri
$name = ($download -split '/')[-1]
#$download = "https://aka.ms/fslogix_download"
#$name = "fslogix.zip"
$extractFile = (Join-Path -path $extractPath -ChildPath $name)
$installer = "$extractPath" + "FSLogix\x64\Release\FSLogixAppsSetup.exe"
$arguments = "/install /quiet /norestart"

## download and install FSLogix
Start-Download -source $download -destination $extractFile -Verbose
Start-ExtractFile -filePath $extractFile -extractedPath (Join-Path -path $extractPath -ChildPath 'Fslogix')
Start-Install -FilePath $installer -Arguments $arguments
Write-Verbose -Message ("FSLogix install completed.") -Verbose

## teams
$teams = Get-MicrosoftTeams | Where-Object {$_.Architecture -eq "x64"} | Select-Object -last 1
$download = $teams.uri
#$download = "https://statics.teams.cdn.office.net/production-windows-x64/1.3.00.4461/Teams_windows_x64.msi"
#$name = "teams.msi"
$name = ($download -split '/')[-1]
$extractFile = (Join-Path -path $extractPath -ChildPath $name)
$installer = "$extractPath" + "$name"
$arguments = "/i $installer /l`*v C:\windows\logs\teamsinstall.log ALLUSER=1 ALLUSERS=1 /quiet"

## download and install Teams
Start-Download -source $download -destination $extractFile -Verbose
## set registry to allow machine wide install
Set-Registry -keyPath "HKLM:SOFTWARE\Microsoft\Teams" -regName IsWVDEnvironment -regValue 1 -propertyType DWord
## start install
Start-Install -FilePath 'C:\Windows\System32\msiexec.exe' -Arguments $arguments
## remove from run command to stop teams auto-starting
Remove-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run -Name Teams -Force
Write-Verbose -Message ("Teams install completed.") -Verbose

## edge
$edge = Get-MicrosoftEdge | Where-Object {($_.Platform -eq "Windows") -and ($_.Product -eq "Stable") -and ($_.Architecture -eq "x64")} | Select-Object -last 1
$download = $edge.uri
$name = ($download -split '/')[-1]
$extractFile = (Join-Path -path $extractPath -ChildPath $name)
$installer = "$extractPath" + "$name"
$arguments = "/i $installer /l`*v C:\windows\logs\edgeinstall.log ALLUSERS=1 DONOTCREATEDESKTOPSHORTCUT=true /norestart /quiet"

## download and install edge
Start-Download -source $download -destination $extractFile
Start-Install -FilePath 'C:\Windows\System32\msiexec.exe' -Arguments $arguments
Write-Verbose -Message ("MSEdge install completed.") -Verbose

## update default user profile
Update-DefaultUserProfile

## citrix optmiser
$download = "https://phoenix.citrix.com/supportkc/filedownload?uri=/filedownload/CTX224676/CitrixOptimizer.zip"
$name = ($download -split '/')[-1]
$extractFile = (Join-Path -path $extractPath -ChildPath $name)
$ctxscript = "$extractPath" + "CitrixOptimizer\CtxOptimizerEngine.ps1"

## download and install citrix optmiser
Start-DownloadCtxOptimiser -download $download -extractPath $extractPath

## start optimisation script
Set-ExecutionPolicy Bypass -Scope Process -Force
& $ctxscript -Mode Execute -OutputXml 'C:\windows\logs\CitrixOptimizerRollback.xml'
Write-Verbose -Message ("Optimisations completed.") -Verbose

Stop-Transcript

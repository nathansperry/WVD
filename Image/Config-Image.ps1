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
    Invoke-WebRequest "https://identity.citrix.com/Utility/STS/Sign-In" -SessionVariable websession -UseBasicParsing

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
    Invoke-WebRequest -Uri ("https://identity.citrix.com/Utility/STS/Sign-In") -WebSession $websession -Method POST -Body $form -ContentType "application/x-www-form-urlencoded" -UseBasicParsing

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

function Start-ExtractFile {
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
Start-ExtractFile -filePath $extractFile -extractedPath $extractPath

## Set Locale, language etc. 
& $env:SystemRoot\System32\control.exe "intl.cpl,,/f:"""$ukregionXML""""
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
$arguments = "/i $installer /l`*v C:\windows\logs\teamsinstall.log ALLUSER=1 ALLUSERS=1 /quiet"

## download and install Teams
Start-Download -source $download -destination $extractFile -Verbose
## set registry to allow machine wide install
Set-Registry -keyPath "HKLM:SOFTWARE\Microsoft\Teams" -regName IsWVDEnvironment -regValue 1 -propertyType DWord
## remove from run command to stop teams auto-starting
Remove-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run -Name Teams -Force
## start install
Start-Install -FilePath 'C:\Windows\System32\msiexec.exe' -Arguments $arguments


## edge
$download = "http://dl.delivery.mp.microsoft.com/filestreamingservice/files/b66ab30d-0d70-4efe-8764-b5ae8a661e1b/MicrosoftEdgeEnterpriseX64.msi"
$name = ($download -split '/')[-1]
$extractFile = (Join-Path -path $extractPath -ChildPath $name)
$installer = "$extractPath" + "$name"
$arguments = "/i $installer /l`*v C:\windows\logs\edgeinstall.log ALLUSERS=1 DONOTCREATEDESKTOPSHORTCUT=true /norestart /quiet"

## download and install edge
Start-Download -source $download -destination $extractFile -Verbose
Start-Install -FilePath 'C:\Windows\System32\msiexec.exe' -Arguments $arguments

## download and install citrix optmiser
$download = "https://phoenix.citrix.com/supportkc/filedownload?uri=/filedownload/CTX224676/CitrixOptimizer.zip"
$name = ($download -split '/')[-1]
$extractFile = (Join-Path -path $extractPath -ChildPath $name)
$ctxscript = "$extractPath" + "CitrixOptimizer\CtxOptimizerEngine.ps1"
$arguments = "/i $installer /l`*v C:\windows\logs\edgeinstall.log ALLUSERS=1 DONOTCREATEDESKTOPSHORTCUT=true /norestart /quiet"
Start-DownloadCtxOptimiser -download $download -extractPath $extractPath

## start script
Set-ExecutionPolicy Bypass -Scope Process -Force
& $ctxscript -Mode Execute -OutputXml 'C:\windows\logs\CitrixOptimizerRollback.xml'


Stop-Transcript

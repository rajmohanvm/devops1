#################################################################################
#
# The sample scripts are not supported under any Microsoft standard support 
# program or service. The sample scripts are provided AS IS without warranty 
# of any kind. Microsoft further disclaims all implied warranties including, without 
# limitation, any implied warranties of merchantability or of fitness for a particular 
# purpose. The entire risk arising out of the use or performance of the sample scripts 
# and documentation remains with you. In no event shall Microsoft, its authors, or 
# anyone else involved in the creation, production, or delivery of the scripts be liable 
# for any damages whatsoever (including, without limitation, damages for loss of business 
# profits, business interruption, loss of business information, or other pecuniary loss) 
# arising out of the use of or inability to use the sample scripts or documentation, 
# even if Microsoft has been advised of the possibility of such damages.
#
#################################################################################

# Version 21.03.10.1543
# Version 1 for Git

<#
    .SYNOPSIS
		This script contains 4 mitigations to help address the following vulnerabilities:

        CVE-2021-26855
        CVE-2021-26857
        CVE-2021-27065
        CVE-2021-26858

        For more information on each mitigation please visit https://aka.ms/exchangevulns

	.DESCRIPTION
        For IIS 10 and higher URL Rewrite Module 2.1 must be installed, you can download version 2.1 (x86 and x64) here:
        * x86 & x64 -https://www.iis.net/downloads/microsoft/url-rewrite

        For IIS 8.5 and lower Rewrite Module 2.0 must be installed, you can download version 2.0 here:
        * x86 - https://www.microsoft.com/en-us/download/details.aspx?id=5747

        * x64 - https://www.microsoft.com/en-us/download/details.aspx?id=7435

        It is important to follow these version guidelines as it was found installing the newer version of the URL rewrite module on older versions of IIS (IIS 8.5 and lower) can cause IIS and Exchange to become unstable.
        If you find yourself in a scenario where a newer version of the IIS URL rewrite module was installed on an older version of IIS, uninstalling the URL rewrite module and reinstalling the recommended version listed above should resolve any instability issues.

	.PARAMETER FullPathToMSI
        This is string parameter is used to specify path of MSI file of URL Rewrite Module.

    .PARAMETER WebSiteNames
        This is string parameter is used to specify name of Default Web Site.

    .PARAMETER ApplyAllMitigations
        This is a switch parameter is used to apply all 4 mitigations: BackendCookieMitigation, UnifiedMessagingMitigation, ECPAppPoolMitigation and OABAppPoolMitigation in one go.

    .PARAMETER RollbackAllMitigations
        This is a switch parameter is used to rollback all 4 mitigations: BackendCookieMitigation, UnifiedMessagingMitigation, ECPAppPoolMitigation and OABAppPoolMitigation in one go.

    .PARAMETER ApplyBackendCookieMitigation
        This is a switch parameter is used to apply the Backend Cookie Mitigation

    .PARAMETER RollbackBackendCookieMitigation
        This is a switch parameter is used to roll back the Backend Cookie Mitigation

    .PARAMETER ApplyUnifiedMessagingMitigation
        This is a switch parameter is used to apply the Unified Messaging Mitigation

    .PARAMETER RollbackUnifiedMessagingMitigation
        This is a switch parameter is used to roll back the Unified Messaging Mitigation

    .PARAMETER ApplyECPAppPoolMitigation
        This is a switch parameter is used to apply the ECP App Pool Mitigation

    .PARAMETER RollbackECPAppPoolMitigation
        This is a switch parameter is used to roll back the ECP App Pool Mitigation

    .PARAMETER ApplyOABAppPoolMitigation
        This is a switch parameter is used to apply the OAB App Pool Mitigation

    .PARAMETER RollbackOABAppPoolMitigation
        This is a switch parameter is used to roll back the OAB App Pool Mitigation

    .PARAMETER operationTimeOutDuration
        operationTimeOutDuration is the max duration (in seconds) we wait for each mitigation/rollback before timing it out and throwing.

     .PARAMETER Verbose
        The Verbose switch can be used to view the changes that occurs during script execution.

	.EXAMPLE
		PS C:\> ExchangeMitigations.ps1 -FullPathToMSI "FullPathToMSI" -WebSiteNames "Default Web Site" -ApplyAllMitigations -Verbose

		To apply all mitigations and install the IIS URL Rewrite Module.

	.EXAMPLE
		PS C:\> ExchangeMitigations.ps1 -WebSiteNames "Default Web Site" -ApplyAllMitigation -Verbose

        To apply all mitigations without installing the IIS URL Rewrite Module.

    .EXAMPLE
        PS C:\> ExchangeMitigations.ps1 -WebSiteNames "Default Web Site" -RollbackAllMitigations -Verbose

        To rollback all mitigations

    .EXAMPLE
        PS C:\> ExchangeMitigations.ps1 -WebSiteNames "Default Web Site" -ApplyECPAppPoolMitigation -ApplyOABAppPoolMitigation -Verbose

        To apply multiple mitigations (out of the 4)

    .EXAMPLE
        PS C:\> ExchangeMitigations.ps1 -WebSiteNames "Default Web Site" -RollbackECPAppPoolMitigation -RollbackOABAppPoolMitigation -Verbose

        To rollback multiple mitigations (out of the 4)

    .Link
        https://aka.ms/exchangevulns
        https://www.iis.net/downloads/microsoft/url-rewrite
        https://www.microsoft.com/en-us/download/details.aspx?id=5747
        https://www.microsoft.com/en-us/download/details.aspx?id=7435
#>

[CmdLetBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Incorrect rule result')]
param(
    [switch]$ApplyAllMitigations,
    [switch]$ApplyBackendCookieMitigation,
    [switch]$ApplyUnifiedMessagingMitigation,
    [switch]$ApplyECPAppPoolMitigation,
    [switch]$ApplyOABAppPoolMitigation,
    [switch]$RollbackAllMitigations,
    [switch]$RollbackBackendCookieMitigation,
    [switch]$RollbackUnifiedMessagingMitigation,
    [switch]$RollbackECPAppPoolMitigation,
    [switch]$RollbackOABAppPoolMitigation,
    [int]$operationTimeOutDuration = 120,
    [ValidateNotNullOrEmpty()][string[]]$WebSiteNames = $(throw "WebSiteNames is mandatory, please provide valid value."),
    [System.IO.FileInfo]$FullPathToMSI
)

function GetMsiProductVersion {
    param (
        [System.IO.FileInfo]$filename
    )

    try {
        $windowsInstaller = New-Object -com WindowsInstaller.Installer

        $database = $windowsInstaller.GetType().InvokeMember(
            "OpenDatabase", "InvokeMethod", $Null,
            $windowsInstaller, @($filename.FullName, 0)
        )

        $q = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"
        $View = $database.GetType().InvokeMember(
            "OpenView", "InvokeMethod", $Null, $database, ($q)
        )

        $View.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $View, $Null)

        $record = $View.GetType().InvokeMember(
            "Fetch", "InvokeMethod", $Null, $View, $Null
        )

        $productVersion = $record.GetType().InvokeMember(
            "StringData", "GetProperty", $Null, $record, 1
        )

        $View.GetType().InvokeMember("Close", "InvokeMethod", $Null, $View, $Null)

        return $productVersion
    } catch {
        throw "Failed to get MSI file version the error was: {0}." -f $_
    }
}
function Get-InstalledSoftware {
    <#
	.SYNOPSIS
		Retrieves a list of all software installed on a Windows computer.
	.EXAMPLE
		PS> Get-InstalledSoftware

		This example retrieves all software installed on the local computer.
	.PARAMETER ComputerName
		If querying a remote computer, use the computer name here.

	.PARAMETER Name
		The software title you'd like to limit the query to.

	.PARAMETER Guid
		The software GUID you'e like to limit the query to
	#>
    [CmdletBinding()]
    param (

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [guid]$Guid
    )
    process {
        try {
            $scriptBlock = {
                $args[0].GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value }

                $UninstallKeys = @(
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                )
                New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
                $UninstallKeys += Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | ForEach-Object {
                    "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
                }
                if (-not $UninstallKeys) {
                    Write-Warning -Message 'No software registry keys found'
                } else {
                    foreach ($UninstallKey in $UninstallKeys) {
                        $friendlyNames = @{
                            'DisplayName'    = 'Name'
                            'DisplayVersion' = 'Version'
                        }
                        Write-Verbose -Message "Checking uninstall key [$($UninstallKey)]"
                        if ($Name) {
                            $WhereBlock = { $_.GetValue('DisplayName') -like "$Name*" }
                        } elseif ($GUID) {
                            $WhereBlock = { $_.PsChildName -eq $Guid.Guid }
                        } else {
                            $WhereBlock = { $_.GetValue('DisplayName') }
                        }
                        $SwKeys = Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue | Where-Object $WhereBlock
                        if (-not $SwKeys) {
                            Write-Verbose -Message "No software keys in uninstall key $UninstallKey"
                        } else {
                            foreach ($SwKey in $SwKeys) {
                                $output = @{ }
                                foreach ($ValName in $SwKey.GetValueNames()) {
                                    if ($ValName -ne 'Version') {
                                        $output.InstallLocation = ''
                                        if ($ValName -eq 'InstallLocation' -and
                                            ($SwKey.GetValue($ValName)) -and
                                            (@('C:', 'C:\Windows', 'C:\Windows\System32', 'C:\Windows\SysWOW64') -notcontains $SwKey.GetValue($ValName).TrimEnd('\'))) {
                                            $output.InstallLocation = $SwKey.GetValue($ValName).TrimEnd('\')
                                        }
                                        [string]$ValData = $SwKey.GetValue($ValName)
                                        if ($friendlyNames[$ValName]) {
                                            $output[$friendlyNames[$ValName]] = $ValData.Trim() ## Some registry values have trailing spaces.
                                        } else {
                                            $output[$ValName] = $ValData.Trim() ## Some registry values trailing spaces
                                        }
                                    }
                                }
                                $output.GUID = ''
                                if ($SwKey.PSChildName -match '\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b') {
                                    $output.GUID = $SwKey.PSChildName
                                }
                                New-Object -TypeName PSObject -Prop $output
                            }
                        }
                    }
                }
            }

            if ($ComputerName -eq $env:COMPUTERNAME) {
                & $scriptBlock $PSBoundParameters
            } else {
                Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $PSBoundParameters
            }
        } catch {
            Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
        }
    }
}
Function BackendCookieMitigation {
    [CmdLetBinding()]
    param(
        [System.IO.FileInfo]$FullPathToMSI,
        [ValidateNotNullOrEmpty()]
        [string[]]$WebSiteNames,
        [switch]$RollbackMitigation
    )

    #Configure Rewrite Rule consts
    $HttpCookieInput = '{HTTP_COOKIE}'
    $root = 'system.webServer/rewrite/rules'
    $inbound = '.*'
    $name = 'X-AnonResource-Backend Abort - inbound'
    $name2 = 'X-BEResource Abort - inbound'
    $pattern = '(.*)X-AnonResource-Backend(.*)'
    $pattern2 = '(.*)X-BEResource=(.+)/(.+)~(.+)'
    $filter = "{0}/rule[@name='{1}']" -f $root, $name
    $filter2 = "{0}/rule[@name='{1}']" -f $root, $name2

    if (!$RollbackMitigation) {
        Write-Verbose "[INFO] Starting mitigation process on $env:computername"

        #Check if IIS URL Rewrite Module 2 is installed
        Write-Verbose "[INFO] Checking for IIS URL Rewrite Module 2 on $env:computername"

        #If IIS 10 check for URL rewrite 2.1 else URL rewrite 2.0
        $RewriteModule = Get-InstalledSoftware | Where-Object { $_.Name -like "*IIS*" -and $_.Name -like "*URL*" -and $_.Name -like "*2*" }
        $IISVersion = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp\ | Select-Object versionstring

        $RewriteModuleInstallLog = ($PSScriptRoot + '\' + 'RewriteModuleInstallLog.log')

        #Install module
        if ($RewriteModule) {

            #Throwing an exception if incorrect rewrite module version is installed
            if ($IISVersion.VersionString -like "*10.*" -and ($RewriteModule.Version -eq "7.2.2")) {
                throw "Incorrect IIS URL Rewrite Module 2.0 Installed. You need to install IIS URL Rewrite Module 2.1 to avoid instability issues."
            }
            if ($IISVersion.VersionString -notlike "*10.*" -and ($RewriteModule.Version -eq "7.2.1993")) {
                throw "Incorrect IIS URL Rewrite Module 2.1 Installed. You need to install IIS URL Rewrite Module 2.0 to avoid instability issues."
            }

            Write-Verbose "[INFO] IIS URL Rewrite Module 2 already installed on $env:computername" -Verbose
        } else {

            if ($FullPathToMSI) {

                $MSIProductVersion = GetMsiProductVersion -filename $FullPathToMSI

                #If IIS 10 assert URL rewrite 2.1 else URL rewrite 2.0
                if ($IISVersion.VersionString -like "*10.*" -and $MSIProductVersion -eq "7.2.2") {
                    throw "Incorrect MSI for IIS $($IISVersion.VersionString), please use URL rewrite 2.1"
                }
                if ($IISVersion.VersionString -notlike "*10.*" -and $MSIProductVersion -eq "7.2.1993") {
                    throw "Incorrect MSI for IIS $($IISVersion.VersionString), please use URL rewrite 2.0"
                }

                Write-Verbose "[INFO] Installing IIS URL Rewrite Module 2" -Verbose
                $arguments = " /i " + '"' + $FullPathToMSI.FullName + '"' + " /quiet /log " + '"' + $RewriteModuleInstallLog + '"'
                $msiexecPath = $env:WINDIR + "\System32\msiexec.exe"
                Start-Process -FilePath $msiexecPath -ArgumentList $arguments -Wait
                Start-Sleep -Seconds 15
                $RewriteModule = Get-InstalledSoftware -Name IIS | Where-Object { $_.Name -like "*URL*" -and $_.Name -like "*2*" }
                if ($RewriteModule) {
                    Write-Verbose "[OK] IIS URL Rewrite Module 2 installed on $env:computername"
                } else {
                    throw "[ERROR] Issue installing IIS URL Rewrite Module 2, please review $($RewriteModuleInstallLog)"
                }
            } else {
                throw "[ERROR] Unable to proceed on $env:computername, path to IIS URL Rewrite Module MSI not provided and module is not installed."
            }
        }

        foreach ($website in $WebSiteNames) {
            Write-Verbose "[INFO] Applying rewrite rule configuration to $env:COMPUTERNAME :: $website"

            $site = "IIS:\Sites\$($website)"

            try {
                if ((Get-WebConfiguration -Filter $filter -PSPath $site).name -eq $name) {
                    Clear-WebConfiguration -Filter $filter -PSPath $site
                }

                if ((Get-WebConfiguration -Filter $filter2 -PSPath $site).name -eq $name2) {
                    Clear-WebConfiguration -Filter $filter2 -PSPath $site
                }


                Add-WebConfigurationProperty -PSPath $site -filter $root -name '.' -value @{name = $name; patternSyntax = 'Regular Expressions'; stopProcessing = 'False' }
                Set-WebConfigurationProperty -PSPath $site -filter "$filter/match" -name 'url' -value $inbound
                Set-WebConfigurationProperty -PSPath $site -filter "$filter/conditions" -name '.' -value @{input = $HttpCookieInput; matchType = '0'; pattern = $pattern; ignoreCase = 'True'; negate = 'False' }
                Set-WebConfigurationProperty -PSPath $site -filter "$filter/action" -name 'type' -value 'AbortRequest'

                Add-WebConfigurationProperty -PSPath $site -filter $root -name '.' -value @{name = $name2; patternSyntax = 'Regular Expressions'; stopProcessing = 'True' }
                Set-WebConfigurationProperty -PSPath $site -filter "$filter2/match" -name 'url' -value $inbound
                Set-WebConfigurationProperty -PSPath $site -filter "$filter2/conditions" -name '.' -value @{input = $HttpCookieInput; matchType = '0'; pattern = $pattern2; ignoreCase = 'True'; negate = 'False' }
                Set-WebConfigurationProperty -PSPath $site -filter "$filter2/action" -name 'type' -value 'AbortRequest'

                Write-Verbose "[OK] Rewrite rule configuration complete for $env:COMPUTERNAME :: $website"
                Get-WebConfiguration -Filter $filter -PSPath $site
                Get-WebConfiguration -Filter $filter2 -PSPath $site
            } catch {
                throw $_
            }
        }
    } else {
        Write-Verbose "[INFO] Starting mitigation rollback process on $env:computername"
        foreach ($website in $WebSiteNames) {

            $site = "IIS:\Sites\$($website)"

            $MitigationConfig = Get-WebConfiguration -Filter $filter -PSPath $site
            if ($MitigationConfig) {
                Clear-WebConfiguration -Filter $filter -PSPath $site
                Clear-WebConfiguration -Filter $filter2 -PSPath $site

                $Rules = Get-WebConfiguration -Filter 'system.webServer/rewrite/rules/rule' -Recurse
                if ($null -eq $Rules) {
                    Clear-WebConfiguration -PSPath $site -Filter 'system.webServer/rewrite/rules'
                }
                Write-Verbose "[OK] Rewrite rule mitigation removed for $env:COMPUTERNAME :: $website"
            } else {
                Write-Verbose "[INFO] Rewrite rule mitigation does not exist for $env:COMPUTERNAME :: $website"
            }
        }
    }
}
Function UnifiedMessagingMitigation {
    [CmdLetBinding()]
    param(
        [switch]$ApplyMitigation,
        [switch]$RollbackMitigation
    )

    # UM doesn't apply to Exchange Server 2019
    $exchangeVersion = (Get-ExchangeServer).AdminDisplayVersion
    if ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 2) {
        return
    }

    if ($ApplyMitigation) {

        StopAndCheckHM
        Stop-Service MSExchangeUM
        Set-Service MSExchangeUM -StartupType Disabled
        Stop-Service MSExchangeUMCR
        Set-Service MSExchangeUMCR -StartupType Disabled

        CheckOperationSuccess -conditions '((Get-Service MSExchangeUM).Status -eq "Stopped") -and `
                                           ((Get-Service MSExchangeUMCR).Status -eq "Stopped") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "MSExchangeUM"}).StartMode -eq "Disabled" ) -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "MSExchangeUMCR"}).StartMode -eq "Disabled" )' `
            -unSuccessfullMessage 'Unified Messaging Mitigation Failed. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'
        Get-Service MSExchangeUM
        Get-Service MSExchangeUMCR
    }
    if ($RollbackMitigation) {

        if (-not(((Get-WebAppPoolState -Name "MSExchangeECPAppPool").value -eq "Stopped") -or ((Get-WebAppPoolState -Name "MSExchangeOABAppPool").value -eq "Stopped"))) {
            StartAndCheckHM
        }
        Set-Service MSExchangeUM -StartupType Automatic
        Start-Service MSExchangeUM
        Set-Service MSExchangeUMCR -StartupType Automatic
        Start-Service MSExchangeUMCR

        CheckOperationSuccess -conditions '((Get-Service MSExchangeUM).Status -eq "Running") -and `
                                           ((Get-Service MSExchangeUMCR).Status -eq "Running") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "MSExchangeUM"}).StartMode -eq "Auto" ) -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "MSExchangeUMCR"}).StartMode -eq "Auto" )' `
            -unSuccessfullMessage 'Unified Messaging Rollback Failed. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'
        Get-Service MSExchangeUM
        Get-Service MSExchangeUMCR
    }
}
Function ECPAppPoolMitigation {
    [CmdLetBinding()]
    param(
        [switch]$ApplyMitigation,
        [switch]$RollbackMitigation
    )
    if ($ApplyMitigation) {
        StopAndCheckHM
        Import-Module WebAdministration
        $AppPoolName = "MSExchangeECPAppPool"
        $AppPool = Get-Item IIS:\AppPools\$AppPoolName
        $AppPool.startMode = "OnDemand"
        $AppPool.autoStart = $false
        $AppPool | Set-Item -Verbose
        if ((Get-WebAppPoolState -Name $AppPoolName).Value -ne "Stopped") {
            Stop-WebAppPool -Name $AppPoolName
        }

        CheckOperationSuccess -conditions '((Get-WebAppPoolState -Name "MSExchangeECPAppPool").value -eq "Stopped")' `
            -unSuccessfullMessage 'ECPAppPool Mitigation Failed. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'

        Write-Verbose "Status of $AppPoolName" -Verbose
        Get-WebAppPoolState -Name $AppPoolName
    }
    if ($RollbackMitigation) {
        $exchangeVersion = (Get-ExchangeServer).AdminDisplayVersion
        if ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 2) {
            if (-not((Get-WebAppPoolState -Name "MSExchangeOABAppPool").value -eq "Stopped")) {
                StartAndCheckHM
            }
        } else {

            if (-not( ((Get-WebAppPoolState -Name "MSExchangeOABAppPool").value -eq "Stopped") -or ((Get-Service MSExchangeUM).Status -eq "Stopped") -or ((Get-Service MSExchangeUMCR).Status -eq "Stopped"))) {
                StartAndCheckHM
            }
        }

        Import-Module WebAdministration
        $AppPoolName = "MSExchangeECPAppPool"
        $AppPool = Get-Item IIS:\AppPools\$AppPoolName
        $AppPool.startMode = "OnDemand"
        $AppPool.autoStart = $true
        $AppPool | Set-Item -Verbose
        Start-WebAppPool -Name $AppPoolName

        CheckOperationSuccess -conditions '((Get-WebAppPoolState -Name "MSExchangeECPAppPool").value -eq "Started")' `
            -unSuccessfullMessage 'ECPAppPool Rollback Failed. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'

        Write-Verbose "Status of $AppPoolName" -Verbose
        Get-WebAppPoolState -Name $AppPoolName
    }
}
Function OABAppPoolMitigation {
    [CmdLetBinding()]
    param(
        [switch]$ApplyMitigation,
        [switch]$RollbackMitigation
    )
    if ($ApplyMitigation) {
        StopAndCheckHM
        Import-Module WebAdministration
        $AppPoolName = "MSExchangeOABAppPool"
        $AppPool = Get-Item IIS:\AppPools\$AppPoolName
        $AppPool.startMode = "OnDemand"
        $AppPool.autoStart = $false
        $AppPool | Set-Item -Verbose
        if ((Get-WebAppPoolState -Name $AppPoolName).Value -ne "Stopped") {
            Stop-WebAppPool -Name $AppPoolName
        }

        CheckOperationSuccess -conditions '((Get-WebAppPoolState -Name "MSExchangeOABAppPool").value -eq "Stopped")' `
            -unSuccessfullMessage 'OABAppPool Mitigation Failed. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'

        Write-Verbose "Status of $AppPoolName" -Verbose
        Get-WebAppPoolState -Name $AppPoolName
    }
    if ($RollbackMitigation) {
        $exchangeVersion = (Get-ExchangeServer).AdminDisplayVersion
        if ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 2) {
            if (-not((Get-WebAppPoolState -Name "MSExchangeECPAppPool").value -eq "Stopped")) {
                StartAndCheckHM
            }
        } else {

            if (-not( ((Get-WebAppPoolState -Name "MSExchangeECPAppPool").value -eq "Stopped") -or ((Get-Service MSExchangeUM).Status -eq "Stopped") -or ((Get-Service MSExchangeUMCR).Status -eq "Stopped"))) {
                StartAndCheckHM
            }
        }

        Import-Module WebAdministration
        $AppPoolName = "MSExchangeOABAppPool"
        $AppPool = Get-Item IIS:\AppPools\$AppPoolName
        $AppPool.startMode = "OnDemand"
        $AppPool.autoStart = $true
        $AppPool | Set-Item -Verbose
        Start-WebAppPool -Name $AppPoolName

        CheckOperationSuccess -conditions '((Get-WebAppPoolState -Name "MSExchangeOABAppPool").value -eq "Started")' `
            -unSuccessfullMessage 'OABAppPool Rollback Failed. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'

        Write-Verbose "Status of $AppPoolName" -Verbose
        Get-WebAppPoolState -Name $AppPoolName
    }
}
Function CheckOperationSuccess {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'TBD')]
    param(
        [string]$conditions,
        [string]$unSuccessfullMessage
    )

    $operationSuccessful = $false
    $attemptNumber = 0

    DO {
        Start-Sleep -Seconds 1
        $operationSuccessful = Invoke-Expression $conditions
        $attemptNumber += 1
    } While ( (-not $operationSuccessful) -and $attemptNumber -le $operationTimeOutDuration )

    if ( -not $operationSuccessful ) {
        throw $unSuccessfullMessage
    }
}
Function StopAndCheckHM {

    $MSExchangeHM = Get-Service MSExchangeHM
    if ($MSExchangeHM.Status -ne "Stopped") {
        Stop-Service MSExchangeHM
    }
    If (((gwmi -Class win32_service | Where-Object { $_.name -eq "msexchangehm" }).StartMode -ne "Disabled" )) {
        Set-Service MSExchangeHM -StartupType Disabled
    }

    $exchangeVersion = (Get-ExchangeServer).AdminDisplayVersion
    if (-not ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 0)) {

        $MSExchangeHMR = Get-Service MSExchangeHMRecovery
        if ($MSExchangeHMR.Status -ne "Stopped") {
            Stop-Service MSExchangeHMRecovery
        }
        If (((gwmi -Class win32_service | Where-Object { $_.name -eq "MSExchangeHMRecovery" }).StartMode -ne "Disabled")) {
            Set-Service MSExchangeHMRecovery -StartupType Disabled
        }

        CheckOperationSuccess -conditions '((Get-Service MSExchangeHM).Status -eq "Stopped") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "msexchangehm"}).StartMode -eq "Disabled" ) -and `
                                           ((Get-Service MSExchangeHMRecovery).Status -eq "Stopped") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "MSExchangeHMRecovery"}).StartMode -eq "Disabled" )' `
            -unSuccessfullMessage 'Mitigation Failed. HealthMonitoring or HealthMonitoringRecovery Service is running/not disabled. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'
    } else {
        CheckOperationSuccess -conditions '((Get-Service MSExchangeHM).Status -eq "Stopped") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "msexchangehm"}).StartMode -eq "Disabled" )' `
            -unSuccessfullMessage 'Mitigation Failed. HealthMonitoring Service is running/not disabled. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'
    }

    Get-Service MSExchangeHM
    if (-not ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 0)) {
        Get-Service MSExchangeHMRecovery
    }
}
Function StartAndCheckHM {

    $MSExchangeHM = Get-Service MSExchangeHM
    If (((gwmi -Class win32_service | Where-Object { $_.name -eq "msexchangehm" }).StartMode -ne "Auto" )) {
        Set-Service MSExchangeHM -StartupType Automatic
    }
    if ($MSExchangeHM.Status -ne "Running") {
        Start-Service MSExchangeHM
    }

    $exchangeVersion = (Get-ExchangeServer).AdminDisplayVersion
    if (-not ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 0)) {

        $MSExchangeHMR = Get-Service MSExchangeHMRecovery
        If (((gwmi -Class win32_service | Where-Object { $_.name -eq "MSExchangeHMRecovery" }).StartMode -ne "Auto" )) {
            Set-Service MSExchangeHMRecovery -StartupType Automatic
        }
        if ($MSExchangeHMR.Status -ne "Running") {
            Start-Service MSExchangeHMRecovery
        }

        CheckOperationSuccess -conditions '((Get-Service MSExchangeHM).Status -eq "Running") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "msexchangehm"}).StartMode -eq "Auto" ) -and `
                                           ((Get-Service MSExchangeHMRecovery).Status -eq "Running") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "MSExchangeHMRecovery"}).StartMode -eq "Auto" )' `
            -unSuccessfullMessage 'Rollback Failed. HealthMonitoring or HealthMonitoringRecovery Service is stopped/disabled. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'
    } else {
        CheckOperationSuccess -conditions '((Get-Service MSExchangeHM).Status -eq "Running") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "msexchangehm"}).StartMode -eq "Auto" )' `
            -unSuccessfullMessage 'Rollback Failed. HealthMonitoring Service is stopped/disabled. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'
    }

    Get-Service MSExchangeHM

    if (-not ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 0)) {
        Get-Service MSExchangeHMRecovery
    }
}


$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Script must be executed as administrator, please close and re-run Exchange Mangement Shell as administrator"
    return
}
if ($PSVersionTable.PSVersion.Major -lt 3) {
    throw "PowerShell does not meet the minimum requirements, system must have PowerShell 3 or later"
}


Import-Module WebAdministration
if ($ApplyAllMitigations -or $ApplyBackendCookieMitigation) {
    if ($FullPathToMSI) {
        BackendCookieMitigation -FullPathToMSI $FullPathToMSI -WebSiteNames $WebSiteNames -ErrorAction Stop
    } else {
        BackendCookieMitigation -WebSiteNames $WebSiteNames -ErrorAction Stop
    }
}
if ($RollbackAllMitigations -or $RollbackBackendCookieMitigation) {
    BackendCookieMitigation -WebSiteNames $WebSiteNames -RollbackMitigation -ErrorAction Stop
}
if ($ApplyAllMitigations -or $ApplyUnifiedMessagingMitigation) {
    UnifiedMessagingMitigation -ApplyMitigation -ErrorAction Stop
}
if ($RollbackAllMitigations -or $RollbackUnifiedMessagingMitigation) {
    UnifiedMessagingMitigation -RollbackMitigation -ErrorAction Stop
}
if ($ApplyAllMitigations -or $ApplyECPAppPoolMitigation) {
    ECPAppPoolMitigation -ApplyMitigation -ErrorAction Stop
}
if ($RollbackAllMitigations -or $RollbackECPAppPoolMitigation) {
    ECPAppPoolMitigation -RollbackMitigation -ErrorAction Stop
}

if ($RollbackAllMitigations -or $RollbackOABAppPoolMitigation) {
    OABAppPoolMitigation -RollbackMitigation -ErrorAction Stop
}
if ($ApplyAllMitigations -or $ApplyOABAppPoolMitigation) {
    OABAppPoolMitigation -ApplyMitigation -ErrorAction Stop
}

# SIG # Begin signature block
# MIIjtwYJKoZIhvcNAQcCoIIjqDCCI6QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDIXttcRhdfVJ6G
# OqHwZiLoOtiAKIZCneLO6KwYIoqiPqCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVjDCCFYgCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBxjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg1QP55jDH
# EJy+zZqZPcLf1H1PD8M6CW4v0LzRSJvLg7cwWgYKKwYBBAGCNwIBDDFMMEqgGoAY
# AEMAUwBTACAARQB4AGMAaABhAG4AZwBloSyAKmh0dHBzOi8vZ2l0aHViLmNvbS9t
# aWNyb3NvZnQvQ1NTLUV4Y2hhbmdlIDANBgkqhkiG9w0BAQEFAASCAQAcqcwxfjLz
# 8cfeKWKdNdOgZCB7X5qfVLj32/HZ+2UqPqcoIQIYZL23RcYJVqYDYv69Rmp52NSL
# GE7K10nJKqDne231NSJaUK6gMbLP7VEWfVD6eAkzDlIcxOsqRiddcb/L/qlz83xn
# zbaXms+9CEv13n2H76fl8WUdJixQg2RyC3TCcseVDjO++Vk+67YgblJw2s7llViN
# Fp8cKarK5ZgMBSPPa8io0p6YFzSfUTK9HnNYhmjxG0ZjRfefIsSE4cRXjOd/yLXS
# rbu4e1tXpfD5EYeqgbAfFxqa1P2nd8nxp0+KoSd6TS87gLIY+jr8y1lL2mg9O0x8
# o54NFGvbauaxoYIS/jCCEvoGCisGAQQBgjcDAwExghLqMIIS5gYJKoZIhvcNAQcC
# oIIS1zCCEtMCAQMxDzANBglghkgBZQMEAgEFADCCAVkGCyqGSIb3DQEJEAEEoIIB
# SASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIO1RHWQI
# pGt55eKEVVNnOjDyMutUWLzYN5f/ELgdpbQ0AgZgPOeuzXgYEzIwMjEwMzEwMTYy
# NTQ4LjAzNVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MDg0Mi00QkU2LUMy
# OUExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wggg5NMIIE
# +TCCA+GgAwIBAgITMwAAATnM6OhDi/A04QAAAAABOTANBgkqhkiG9w0BAQsFADB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMDEwMTUxNzI4MjFaFw0y
# MjAxMTIxNzI4MjFaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0
# ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjA4NDItNEJFNi1DMjlBMSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEA2hP5jOMlkyWhjrMqBvyiePhaH5g3T39Qwdu6HqAn
# WcLlz9/ZKoC/QFz45gb0ad14IvqFaFm2J6o+vhhbf4oQJOHDTcjZXBKQTbQT/w6L
# CWvdCXnFQl2a8nEd42EmE7rxRVmKumbHoEKV+QwYdGc70q5O8M2YkqJ/StcrFhFt
# mhFxcvVZ+gg4azzvE87+soIzYV6zqM2KWO/TSy9Zeoi5X4QobV6AKuwJH08ySZ2l
# QBXznd8rwDzy6+BYqJXim+b+V+7E3741b6cQ9fmONApHLhkGqo07/B14NkGqqO97
# 8hAjXtVoQpKjKu6yxXzsspQnj0rlfsV/HySW/l+izx7KTwIDAQABo4IBGzCCARcw
# HQYDVR0OBBYEFJmem4ZyVMKZ2pKKsZ9G9lAtBgzpMB8GA1UdIwQYMBaAFNVjOlyK
# MZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWlj
# cm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8yMDEwLTA3
# LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAtMDctMDEu
# Y3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcN
# AQELBQADggEBAFhcKGrz/zcahc3BWu1Dgoi/EA2xJvu69hGIk6FtIPHXWMiuVmtR
# QHf8pyQ9asnP2ccfRz/dMqlyk/q8+INcCLEElpSgm91xuCFYbFhAhLJtoozf38aH
# 5rY2ZxWN9buDEknJfiGiK6Q+8kkCNWmbWj2DxRwEF8IfBwjF7EPhYDgdilKz486u
# whgosor1GuDWilYjGoMNq3lrwDIkY/83KUpJhorlpiBdkINEsVkCfzyELme9C3ta
# mZtMSXxrUZwX6Wrf3dSYEAqy36PJZJriwTwhvzjIeqD8eKzUUh3ufE2/EjEAbabB
# hCo2+tUoynT6TAJtjdiva4g7P73/VQrScMcwggZxMIIEWaADAgECAgphCYEqAAAA
# AAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBB
# dXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvtfGhLLF/F
# w+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzXTbg4CLNC
# 3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd
# 0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHR
# D5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9E
# uqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIwEAYJKwYB
# BAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsG
# AQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTAD
# AQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0w
# S6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYI
# KwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsG
# AQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUA
# ZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkq
# hkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpX
# bRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2zEBAQZvc
# XBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr
# 5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7Yl+a21dA
# 6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt0uGc+R38
# ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2onGqBooP
# iRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA3+cxB6ST
# OvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7G4kqVDmy
# W9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Kiyc8ZQU3g
# hvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9
# zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P3nSISRKh
# ggLXMIICQAIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MDg0Mi00QkU2LUMy
# OUExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAH
# BgUrDgMCGgMVAA1NlP4b3paEjXQ/He5KBMazZYwHoIGDMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDj80NTMCIYDzIw
# MjEwMzEwMjEwODM1WhgPMjAyMTAzMTEyMTA4MzVaMHcwPQYKKwYBBAGEWQoEATEv
# MC0wCgIFAOPzQ1MCAQAwCgIBAAICH28CAf8wBwIBAAICEV0wCgIFAOP0lNMCAQAw
# NgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgC
# AQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQCTJj/1utS5DX+QnRNs61e4wtHJDRSe
# siYZmAJ+wyhkEleNr9AxTYdmgU1b2ldPrANIz4CHWBXzvkPTx4xqArNA+9DcMq9j
# aQVLNfTs6g/RuNBA9XPakzQNHfP5XgrmU7iL5KP3z4AzMhDYnKu7QmJw9m51PqMs
# M3ybEWa4gg/MxjGCAw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABOczo6EOL8DThAAAAAAE5MA0GCWCGSAFlAwQCAQUAoIIBSjAa
# BgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIEA+1IGx
# N3gUZYHEtsOVghOA+mMmiBiyou+wzIekviBYMIH6BgsqhkiG9w0BCRACLzGB6jCB
# 5zCB5DCBvQQgPKGO5Dij1yR7MUKx4oEFrnxqVSfzmnqfJqbUoAcP/J8wgZgwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAATnM6OhDi/A04QAA
# AAABOTAiBCAAeLcVGrXqTnin70/WpfS97PyI284EpmVf1JuNrqzxezANBgkqhkiG
# 9w0BAQsFAASCAQBOhk+zA5gYHirinZOY3mf2+Ep0ypWfKTTKIP75tKqLwxQI8ZJc
# /5XB6+HXsJrD0RBW5Y3clhn915kJ7rO+/ah4lfIvk0IFLy4FpT9MIlO085Cw1YJ8
# Bd2mD402CV2/dLuhTZD0XMMnq/5hx2hPx8WWTI/BM5g1j7DW1CBvBQSLExmaxurR
# l5pI7teTyKOWVhxsdwjHb5ROaOItYf4a8kb8GZVkYk7pUOf7zb4ifuNN2gUo5HN4
# vNlgtL6vrzxTuSJEwCasSOIQoowpm2z4OJLBluamro+o7X858lSxvKsOVMtP8ZmP
# aTz/GzCde161IKVfWxYnEVL2HjspwTlTJ4oQ
# SIG # End signature block

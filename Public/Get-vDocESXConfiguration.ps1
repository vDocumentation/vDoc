function Get-vDocESXConfiguration {
    <#
    .SYNOPSIS
      Get ESXi host configuration
    .DESCRIPTION
      Will get ESXi host configuration details for a vSphere Cluster, Datacenter 
      or individual ESXi host
    .NOTES
      File Name    : Get-vDocESXConfiguration
      Author       : Edgar Sanchez - @edmsanchez13
      Contributor  : Ariel Sanchez - @arielsanchezmor
      Version      : 0.2.0
    .Link
      https://github.com/vDocumentation/vDoc
    .OUTPUTS
      CSV file
      Excel file
    .PARAMETER VMhost
      The name(s) of the vSphere ESXi Host(s)
    .EXAMPLE
      Get-vDocESXConfiguration -VMhost devvm001.lab.local
    .PARAMETER Cluster
      The name(s) of the vSphere Cluster(s)
    .EXAMPLE
      Get-vDocESXConfiguration -Cluster production
    .PARAMETER Datacenter
      The name(s) of the vSphere Virtual Datacenter(s).
    .EXAMPLE
      Get-vDocESXConfiguration -Datacenter vDC001
    .PARAMETER ExportCSV
      Switch to export all data to CSV file. File is saved to the current user directory from where the script was executed. Use -folderPath parameter to specify a alternate location
    .EXAMPLE
      Get-vDocESXConfiguration -Cluster production -ExportCSV
    .PARAMETER ExportExcel
      Switch to export all data to Excel file (No need to have Excel Installed). This relies on ImportExcel Module to be installed.
      ImportExcel Module can be installed directly from the PowerShell Gallery. See https://github.com/dfinke/ImportExcel for more information
    .EXAMPLE
      Get-vDocESXConfiguration -Cluster production -ExportExcel
    .PARAMETER OutputFile
      Specify an output file path and or file name where the exported data should be saved.
    .EXAMPLE
      Get-vDocESXConfiguration -Cluster production -ExportExcel -OutputFile C:\temp\report.xlsx
    .PARAMETER PassThru
      Switch to return object to command line
    .EXAMPLE
      Get-vDocESXConfiguration -VMhost devvm001.lab.local -PassThru
  #> 

    [CmdletBinding(DefaultParameterSetName = 'VMhost')]
    param (
        [Parameter(ParameterSetName = "VMhost")]
        [ValidateNotNullOrEmpty()]
        [String[]]$VMhost = "*",
        [Parameter(ParameterSetName = "Cluster")]
        [ValidateNotNullOrEmpty()]
        [String[]]$Cluster,
        [Parameter(ParameterSetName = "DataCenter")]
        [ValidateNotNullOrEmpty()]
        [String[]]$DataCenter,
        [switch]$ExportCSV,
        [switch]$ExportExcel,
        [ValidateNotNullOrEmpty()]
        [string]$OutputFile,
        [switch]$PassThru
    ) #END param

    BEGIN {
        $stopWatch = [System.Diagnostics.Stopwatch]::startNew()
        $date = Get-Date -format s
        $date = $date -replace ":", "-"
        $defaultFile = -join ("vDocConfiguration", $date)
        $skipCollection = [System.Collections.Generic.List[Object]]::new()
        $returnCollection = [System.Collections.Generic.List[Object]]::new()
        $configurationCollection = [System.Collections.Generic.List[Object]]::new()
                
        Write-vDocMessage -Message "$($callStack = Get-PSCallStack; "Executing function: {0}" -f $callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Adding parameters with default values to PSBoundParameters" -Type Verbose
        foreach ($key in $MyInvocation.MyCommand.Parameters.Keys) {
            $value = Get-Variable $key -ValueOnly -ErrorAction SilentlyContinue
            if (-not $PSBoundParameters.ContainsKey($key) -and $value) {
                $PSBoundParameters[$key] = $value
            } #END if
        } #END foreach
                
        $initParams = @{}
        Initialize-vDocParameters $PSBoundParameters
        $serviceInstance = Get-View -Id ServiceInstance
        $licenseManager = Get-View -Id $serviceInstance.Content.LicenseManager
        $licenseManagerAssign = Get-View -Id $licenseManager.LicenseAssignmentManager
        $vHostList = $initParams.vHostList
        $thisOS = Get-vDocSessionOs
    } #END BEGIN

    PROCESS {
        foreach ($esxiHost in $vHostList) {
            # Skip if ESXi host is not in a connected or maintenance connection state     
            Get-vDocEsxConnectionState -vmHost $esxiHost

            Write-vDocMessage -Message "Gathering configuration details from $esxiHost ..." -Type Host
            $vmHostView = Get-View -VIObject $esxiHost
            $esxCli = Get-EsxCli -VMHost $esxiHost -V2

            #Get Product details
            Write-vDocMessage -Message "Gathering Product, Version and Build..." -Type Verbose
            $esxiUpdateLevel = ($vmHostView.Config.Option | Where-Object { $_.Key -eq 'Misc.HostAgentUpdateLevel' }).Value 
            if ($esxiUpdateLevel) {
                $esxiVersion = -join ($esxiHost.Version, " U", $esxiUpdateLevel)
            }
            else {
                $esxiVersion = $esxiHost.Version
            } #END if/else

            # Get ESXi installation type and Boot config https://kb.vmware.com/s/article/2014558
            Write-vDocMessage -Message "Gathering ESXi installation type..." -Type Verbose
            $bootVendor = $null
            $bootDisplayName = $null
            $bootPath = $null
            $bootRuntime = $null
            $bootDevice = $esxCli.system.boot.device.get.Invoke()
            if ($bootDevice.BootFilesystemUUID) {
                $storageDevice = $esxCli.storage.core.device.list.Invoke() | Where-Object { $_.IsBootDevice -eq $true }
                $bootVendor = $storageDevice.Vendor, $storageDevice.Model -join ' '
                $bootDisplayName = $storageDevice.DisplayName
                $bootPath = $storageDevice.DevfsPath
                $storagePath = $esxCli.storage.core.path.list.Invoke() | Where-Object { $_.Device -eq $storageDevice.Device }
                $bootRuntime = $storagePath.RuntimeName
                if ($bootDevice.BootFilesystemUUID[6] -eq 'e') {
                    $installType = "Embedded"
                    $bootSource = $storageDevice.DisplayName.Split('(')[0]
                }
                else {
                    $installType = "Installable"
                    $bootSource = $esxCli.storage.filesystem.list.Invoke() | Where-Object { $_.UUID -eq $bootDevice.BootFilesystemUUID } | 
                    Select-Object -ExpandProperty MountPoint
                } #END if/else
            }
            elseif ($bootDevice.StatelessBootNIC) {
                $installType = "PXE Stateless"
                $bootSource = $bootDevice.StatelessBootNIC
            }
            else {
                $installType = "PXE"
                $bootSource = $bootDevice.BootNIC
            } #END if/else

            # Get Image Profile, UpTime and software configuration
            Write-vDocMessage -Message "Gathering Image Profile, uptime and install date Configuration..." -Type Verbose
            $vmhostLM = $licenseManagerAssign.QueryAssignedLicenses($vmHostView.Config.Host.Value)
            $vmhostvDC = Get-Datacenter -VMHost $esxiHost | Select-Object -ExpandProperty Name
            $configManagerView = Get-View -Id $vmHostView.ConfigManager.ImageConfigManager
            $imageProfileName = $configManagerView.HostImageConfigGetProfile().Name
            $imageProfileAcceptance = $configManagerView.HostImageConfigGetAcceptance()
            $bootTimeUTC = $vmHostView.Runtime.BootTime
            $BootTime = $bootTimeUTC.ToLocalTime()
            $upTimeSpan = New-TimeSpan -Seconds $vmHostView.Summary.QuickStats.Uptime
            $upTime = $upTimeSpan.Days, "Day(s),", $upTimeSpan.Hours, "Hrs,", $upTimeSpan.Minutes, "Mins" -join ' '
            $vmUUID = $esxCli.system.uuid.get.Invoke()
            $decimalDate = [Convert]::ToInt32($vmUUID.Split("-")[0], 16)
            $installDate = ([DateTime]'1/1/1970').AddSeconds($decimalDate).ToLocalTime()
            if ([decimal]$vmHostView.Config.Product.ApiVersion.Substring(0, 3) -ge '6.5') {
                $SoftwareProfile = $esxCli.software.profile.get.Invoke()
                $profileString = $SoftwareProfile.Description.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)

                foreach ($line in $profileString) {
                    if ($line.Contains(":")) {
                        $dateString = $line.Trim().split(" ")[0]
                        if ($dateString -as [DateTime]) {
                            $upgradeDate = $dateString.ToDateTime($_)
                        } #END if
                    } #END if
 
                    if ($line.Contains("esx-base")) {
                        # Find matching esx-base to match image profile build
                        $buildId = $line.trim().split(".")[-1]
                        if ($SoftwareProfile.Name.Contains($buildId)) {
                            # Match found, break foreach
                            break
                        } #END if
                    } #END if
                }#END foreach

                $softwarePackage = $configManagerView.fetchSoftwarePackages() | Where-Object { $_.Version -match $esxiHost.Build } | Select-Object -First 1
                $lastPatched = $softwarePackage.CreationDate.ToLocalTime()
                if (-not ($upgradeDate -gt $installDate)) {
                    $upgradeDate = $null
                } #END if
            }
            else {
                $upgradeDate = $null
                $vmhostPatch = $esxCli.software.vib.list.Invoke() | Where-Object { $_.ID -match $esxiHost.Build } | Select-Object -First 1
                $lastPatched = $vmhostPatch.InstallDate  
            } #END if/else

            # Get services, and syslog configuration
            Write-vDocMessage -Message "Gathering services configuration..." -Type Verbose
            $dnsAdress = Get-VMHostNetwork -VMHost $esxiHost | Select-Object -ExpandProperty DnsAddress
            $vmServices = Get-VMHostService -VMHost $esxiHost
            $vmhostFireWall = Get-VMHostFirewallException -VMHost $esxiHost
            $ntpServerList = Get-VMHostNtpServer -VMHost $esxiHost
            $ntpService = $vmServices | Where-Object { $_.key -eq "ntpd" }
            $ntpFWException = $vmhostFireWall | Select-Object Name, Enabled | Where-Object { $_.Name -eq "NTP Client" }
            $sshService = $vmServices | Where-Object { $_.key -eq "TSM-SSH" }
            $sshServerFWException = $vmhostFireWall | Select-Object Name, Enabled | Where-Object { $_.Name -eq "SSH Server" }
            $esxiShellService = $vmServices | Where-Object { $_.key -eq "TSM" }
            $ShellTimeOut = (Get-AdvancedSetting -Entity $esxiHost -Name "UserVars.ESXiShellTimeOut" -ErrorAction SilentlyContinue).value
            $interactiveShellTimeOut = (Get-AdvancedSetting -Entity $esxiHost -Name "UserVars.ESXiShellInteractiveTimeOut" -ErrorAction SilentlyContinue).value
            Write-Verbose -Message ((Get-Date -Format G) + "`tGathering Syslog Configuration...")
            $syslogList = @()
            $syslogFWException = $vmhostFireWall | Select-Object Name, Enabled | Where-Object { $_.Name -eq "syslog" }
            foreach ($syslog in  Get-VMHostSysLogServer -VMHost $esxiHost) {
                $syslogList += $syslog.Host, $syslog.Port -join ':'
            } #END foreach
      
            # Instantiate Inventory Class, and call methods based on Session OS
            $configuration = [vDocConfiguration]::new()
            $configurationCollection.Add($configuration)
        } #EDN foreach
    } #END PROCESS

    END { 
        $stopWatch.Stop()
        Write-vDocMessage -Message "Main code execution completed" -Type Verbose
        Write-vDocMessage -Message "Script Duration: $($stopWatch.Elapsed.Duration())" -Type Verbose
                  
        #Validate output and export Data
        switch ($true) {
            ($skipCollection.Count -gt 0) {
                Write-vDocMessage -Message "Check Connection State or Host name" -Type Warning
                Write-vDocMessage -Message "Skipped hosts:" -Type Warning
                $skipCollection | Format-Table -AutoSize  
            }
            ($configurationCollection.Count -gt 0) {
                Write-vDocMessage -Message "Information gathered" -Type Verbose
                Write-vDocMessage -Message "`nESXi Configuration:" -Type Host -Color
                Export-vDocDataCollection -ObjectCollection $configurationCollection -Description "Host_Configuration"
            }
            $PassThru { $returnCollection }
            default { Write-vDocMessage -Message "No information gathered" -Type Verbose }
        } #END switch
    } #END END
} #END Get-vDocESXConfiguration

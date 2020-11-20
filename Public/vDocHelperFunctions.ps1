function Write-vDocMessage {
    [cmdletbinding()]
    param (
        # Message String
        [Parameter(Mandatory)]
        [string]$Message,
        # Message Type
        [Parameter(Mandatory)]
        [ValidateSet("Host", "Verbose", "Warning", "Error")]
        [string]$Type,
        # Color switch, applicable only for write-host
        [Parameter(Mandatory = $false)]
        [switch]$Color
    ) #END param

    BEGIN {
        $timeStamp = Get-Date -Format G
    } #END BEGIN

    PROCESS {
        switch ($Type) {
            'Host' {
                if ($Color) {
                    Write-Host -Object $Message -ForegroundColor Green
                }
                else {
                    Write-Host -Object $Message                
                } #END if/else
            } #END "HOST"
            'Verbose' { Write-Verbose -Message "$timeStamp `t$Message" } 
            'Warning' { Write-Warning -Message "`t$Message" } 
            'Error' { Write-Host -Object "ERROR: `t$Message" -ForegroundColor Red } 
        } #END switch
    } #END PROCESS
} #END function Write-vDocMessage

function Get-vDocVMhostList {
    [CmdletBinding()]
    param (
        # Object Type
        [Parameter(Mandatory)]
        [ValidateSet("VMhost", "Cluster", "DataCenter")]
        [string]$Type,
        # Object Name
        [Parameter(Mandatory)]
        [string[]]$Name
    ) #END param

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
    } #END BEGIN

    PROCESS {
        Write-vDocMessage -Message "Executing Cmdlet using $Type parameter set" -Type Verbose
        Write-vDocMessage -Message "Gathering host list..." -Type Host
        $objectList = @()
        foreach ($oneName in $Name) {
            switch ($Type) {
                'VMhost' { $tempList = Get-VMHost -Name $oneName.Trim() -ErrorAction SilentlyContinue -ErrorVariable err } 
                'Cluster' { $tempList = Get-Cluster -Name $oneName.Trim() -ErrorAction SilentlyContinue -ErrorVariable err | Get-VMHost } 
                'DataCenter' { $tempList = Get-Datacenter -Name $oneName.Trim() -ErrorAction SilentlyContinue -ErrorVariable err | Get-VMHost } 
            } #END switch

            if ($tempList) {
                $objectList += $tempList
            }
            else {
                Write-vDocMessage -Message "$Type : $oneName was not found in $Global:DefaultViServers" -Type Warning
                if ($err) {
                    Write-vDocMessage -Message "Exception: $($err[0].Exception.InnerException.Message)" -Type Warning
                } #END if
            } #END if/else
        } #END foreach
    } #END PROCESS

    END {
        if ($objectList) {
            $objectList = $objectList | Sort-Object -Property Name
            $initParams.vHostList = $objectList
        }
        else {
            Write-vDocMessage -Message "No information gathered" -Type Verbose
        } #END if/else
    } #END END
} #END function Get-vDocVMhostList

function Get-vDocSessionOs {
    [CmdletBinding()]
    param (
    ) #END param

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
    } #END BEGIN

    PROCESS {
        switch ($true) {
            $IsLinux { $sessionOS = "Linux" }
            $IsMacOS { $sessionOS = "MacOS" }
            $IsWindows { $sessionOS = "Windows" }
            default { $sessionOS = "Windows" }
        } #END switch
    } #END PROCESS

    END {
        return $sessionOS
    } #END END
} #END function Get-vDocSessionOs
function Get-vDocOutputFile {
    [CmdletBinding()]
    param (
        # Output File/FilePath
        [Parameter(Mandatory)]
        [String]$FilePath,
        # Directory Separator char
        [Parameter(Mandatory)]
        [String]$PathChar,
        # Current session path
        [Parameter(Mandatory)]
        [String]$CurrentPath
    ) #END param

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
    } #END BEGIN

    PROCESS {
        # Test if path is provided is a folder
        if (Test-Path -PathType Container $FilePath.Trim()) {
            Write-vDocMessage -Message "Just folder path was provided: $FilePath" -Type Verbose
            $lastCharOfFolderPath = $FilePath.Substring($FilePath.Length - 1)
            if ($lastCharOfFolderPath -eq "\" -or $lastCharOfFolderPath -eq "/") {
                $exportFile = -join ($FilePath, $defaultFile)
            }
            else {
                $exportFile = -join ($FilePath, $PathChar, $defaultFile)
            } #END if/else
        }
        else {
            $leafName = Split-Path $FilePath.Trim() -Leaf
            if ($leafName) {
                $leafName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
                $indexOfInvalidChar = $leafName.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars())
                if (-not [string]::IsNullOrEmpty($leafName) -and $indexOfInvalidChar -eq -1) {
                    Write-vDocMessage -Message "'$leafName' is a valid filename" -Type Verbose
                    $parentPath = Split-Path $FilePath.Trim() -Parent
                    if ($parentPath) {
                        if (Test-Path $parentPath) {
                            Write-vDocMessage -Message "Parent path found: $parentPath is valid" -Type Verbose
                            $exportFile = -join ($parentPath, $PathChar, $leafName)
                        }
                        else {
                            Write-vDocMessage -Message "'$parentPath' path not found. The current location: '$CurrentPath' will be used instead" -Type Warning
                            $exportFile = -join ($CurrentPath, $PathChar, $leafName)
                        } #END if/else
                    }
                    else {
                        Write-vDocMessage -Message "Just file name was provided: $FilePath" -Type Verbose
                        $exportFile = -join ($CurrentPath, $PathChar, $leafName)
                    } #END if/else
                }
                else {
                    Write-vDocMessage -Message "Path: $FilePath contains invalid file name characters" -Type Error
                    break
                } #END if/else
            }
            else {
                Write-vDocMessage -Message "'$FilePath' path not found. The current location: '$CurrentPath' will be used instead" -Type Warning
                $exportFile = -join ($CurrentPath, $PathChar, $defaultFile)
            } #END if/else
        } #END if/else
    } #END PROCESS

    END {
        Write-vDocMessage -Message "Output File: $exportFile" -Type Verbose
        $initParams.exportFile = $exportFile
    } #END END
} #END function Get-vDocOutputFile
function Initialize-vDocParameters {
    [CmdletBinding()]
    param (
        # Accept $PSBoundParameters object from calling function
        [Parameter(Mandatory)]
        [System.Collections.Generic.Dictionary[System.String, System.Object]]$functionParameters
    ) #END param

    BEGIN {
        # Minimum Verion of ImportExcel Supported
        $importExcelVer = '6.5.0'
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[1].Arguments)" -Type Verbose
        if ($functionParameters.ContainsKey('Cluster') -or $functionParameters.ContainsKey('DataCenter')) {
            [void] $functionParameters.Remove('VMhost')
        } #END if
    } #END BEGIN

    PROCESS {
        # Check for an active connection to a VIServer
        Write-vDocMessage -Message "Validate connection to a vSphere server..." -Type Verbose
        try {
            if ($Global:DefaultViServers[0].IsConnected) {
                Write-vDocMessage -Message "Connected to $Global:DefaultViServers" -Type Host -Color
            }
            else {
                Write-vDocMessage -Message "You must be connected to a vSphere server before running this Cmdlet." -Type Error
                break
            } #END if/else
        }
        catch {
            Write-vDocMessage -Message "You must be connected to a vSphere server before running this Cmdlet." -Type Error
            Write-vDocMessage -Message "$_.Exception.Message" -Type Verbose
            break
        } #END try/catch
        
        # Query PowerCLI and vDocumentation versions
        if ($VerbosePreference -eq "Continue") {
            Write-vDocMessage -Message "PowerCLI Version:" -Type Verbose
            Get-Module -Name VMware.* | Select-Object -Property Name, Version | Format-Table -AutoSize
            Write-vDocMessage -Message "vDocumentation Version:" -Type Verbose
            Get-Module -Name vDocumentation -ListAvailable -ErrorAction SilentlyContinue | 
            Select-Object -Property Name, Version | Format-Table -AutoSize
        } #END if

        switch ($functionParameters.Keys) {
            #  Validate export switches, ouput file path and dependencies
            { 'ExportCSV' -contains $_ } { $initParams.ExportCSV = $true }
            { 'ExportExcel' -contains $_ } { 
                $importExcel = Get-Module -Name ImportExcel -ListAvailable -ErrorAction SilentlyContinue
                if ($importExcel) {
                    Write-Verbose -Message "$(Get-Date -Format G) `tImportExcel Module Version:"
                    $importExcel | Select-Object -Property Name, Version | Format-Table -AutoSize
                    if ([version]$importExcel.Version -gt [version]$importExcelVer) {
                        $initParams.ExportExcel = $true
                    }
                    else {
                        Write-vDocMessage -Message "Incompatible version of ImportExcel Module found. Please update to latest version" -Type Error
                        break
                    } #END if/else
                }
                else {
                    Write-vDocMessage -Message "ImportExcel Module Not Found. Will export data to CSV format instead" -Type Error
                    Write-vDocMessage -Message "ImportExcel Module can be installed directly from the PowerShell Gallery" -Type Error
                    Write-vDocMessage -Message "See https://github.com/dfinke/ImportExcel for more information" -Type Error
                    break
                } #END if/else 
            } #END 'ExpoertExcel'
            { 'ExportCSV', 'ExportExcel' -contains $_ } {
                $dirSeparatorChar = [System.IO.Path]::DirectorySeparatorChar
                $currentLocation = (Get-Location).Path
                Write-vDocMessage -Message "Validate export switch and output file path..." -Type Verbose
                if ($functionParameters['OutputFile']) {
                    Get-vDocOutputFile -FilePath $functionParameters['OutputFile'] -PathChar $dirSeparatorChar -CurrentPath $currentLocation
                }
                else {
                    Write-vDocMessage -Message "Output File Path (-OutputFile) was not specified for saving exported data. The current location: '$currentLocation' will be used" -Type Warning
                    $exportFile = -join ($currentLocation, $dirSeparatorChar, $defaultFile)
                    Write-vDocMessage -Message "Output File: $exportFile" -Type Verbose
                    $initParams.exportFile = $exportFile
                } #END if/else
            } #END 'ExportCSV','ExportExcel'

            # Validate QueryRAC Switch
            'QueryRAC' { 
                if ($functionParameters['Credential']) {
                    Write-vDocMessage -Message "RAC Credentials were provided" -Type Verbose
                    $racCredentials = $functionParameters['Credential']
                }
                else {
                    Write-vDocMessage -Message "Prompting user for RAC Credentials..." -Type Verbose
                    $racCredentials = Get-Credential -Message "Enter Host RAC Credentials"
                } #END if/else
            
                $initParams.racCredentials = $racCredentials
            } #END QueryRAC
            
            # Gather host list based on parameter set used
            'VMhost' { Get-vDocVMhostList -Type VMhost -Name $functionParameters['VMhost'] } 
            'Cluster' { Get-vDocVMhostList -Type Cluster -Name $functionParameters['Cluster'] } 
            'DataCenter' { Get-vDocVMhostList -Type DataCenter -Name $functionParameters['DataCenter'] } 
        } #END switch
    } #END PROCESS
} #END function Initialize-vDocParameters

function Get-vDocEsxConnectionState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.InventoryItem[]]$vmHost
    ) #END param

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
    } #END BEGIN

    PROCESS {
        if ($vmHost.ConnectionState -eq "Connected" -or $vmHost.ConnectionState -eq "Maintenance") {
            Write-vDocMessage -Message "$vmHost Connection State: $($vmHost.ConnectionState)" -Type Verbose
        }
        else {
            Write-vDocMessage -Message "$vmHost Connection State: $($vmHost.ConnectionState). Skipping..." -Type Verbose

            $output = [PSCustomObject]@{
                'Hostname'         = $vmHost.Name
                'Connection State' = $vmHost.ConnectionState
            }  #END [PSCustomObject]

            $skipCollection.Add($output)
            continue
        } #END if/else
    } #END PROCESS
} #END function Get-vDocEsxConnectionState
function Get-vDocVMHostHardware {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.InventoryItem[]]$vmHost,
        [Parameter(Mandatory)]
        $vmHostView,
        [Parameter(Mandatory)]
        $esxCli,
        [Parameter(Mandatory)]
        $OS
    ) #END param

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
    } #END BEGIN

    PROCESS {
        if ($OS -eq "Windows") {
            $params = @{
                VMhost                      = $vmHost
                WaitForAllData              = $true
                SkipAllSslCertificateChecks = $true
                ErrorAction                 = 'SilentlyContinue'
                ErrorVariable               = 'err'
            } #END $params
        
            $hostHardware = Get-VMHostHardware @params
            if ($err) {
                Write-vDocMessage -Message "Get-VMHostHardware exception : $err" -Type Verbose
            } #END if

            $Inventory.GetPlatform($hostHardware.Manufacturer, $hostHardware.Model, $hostHardware.SerialNumber)
            if ($vmhostView.Hardware.BiosInfo.ReleaseDate) {
                $biosDate = (Get-Date $vmhostView.Hardware.BiosInfo.ReleaseDate).ToShortDateString()
            } #END if
            $Inventory.GetBios($hostHardware.BiosVersion, $biosDate)
            $Inventory.GetCpu($hostHardware.CpuCount, $hostHardware.CpuCoreCountTotal, $hostHardware.MhzPerCpu)
            $Inventory.'Memory Slots Count' = $hostHardware.MemorySlotCount
            $Inventory.'Memory Slots Used' = $hostHardware.MemoryModules.Count
            $Inventory.'Power Supplies' = $hostHardware.PowerSupplies.Count
            $Inventory.'NIC Count' = $hostHardware.NicCount
        }
        else {
            # Get Platform info
            try {
                Write-vDocMessage -Message "Gathering hardware platform details..." -Type Verbose
                $esxPlatform = $esxCli.hardware.platform.get.Invoke()
                $Inventory.GetPlatform($esxPlatform.VendorName, $esxPlatform.ProductName, $esxPlatform.SerialNumber)
                $Inventory.'NIC Count' = $vmHostView.Summary.Hardware.NumNics
            }
            catch {
                Write-vDocMessage -Message "Get hardware platform details through esxCli failed, error:" -Type Verbose
                Write-vDocMessage -Message "$_.Exception.Message" -Type Verbose
            } #END try/catch

            #Get BIOS info
            try {
                Write-vDocMessage -Message "Gathering hardware BIOS details..." -Type Verbose
                $esxBios = @{}
                $esxBios.biosVersion = $vmhostView.Hardware.BiosInfo.BiosVersion
                if ($vmhostView.Hardware.BiosInfo.ReleaseDate) {
                    $esxBios.biosReleaseDate = (Get-Date $vmhostView.Hardware.BiosInfo.ReleaseDate).ToShortDateString()
                } #END if
                $Inventory.GetBios($esxBios.biosVersion, $esxBios.biosReleaseDate)
                $Inventory.'Memory Slots Count' = $esxSdrRam.count
                $Inventory.'Power Supplies' = $esxPsu.Count
            }
            catch {
                Write-vDocMessage -Message "Get hardware BIOS details, error:" -Type Verbose
                Write-vDocMessage -Message "$_.Exception.Message" -Type Verbose
            } #END try/catch

            #Get CPU Details
            try {
                Write-vDocMessage -Message "Gathering hardware CPU details..." -Type Verbose
                $esxCpuInfo = $vmHostView.Summary.Hardware
                $Inventory.GetCpu($esxCpuInfo.NumCpuPkgs, $esxCpuInfo.NumCpuCores, $esxCpuInfo.CpuMhz)
            }
            catch {
                Write-vDocMessage -Message "Get hardware CPU details, error:" -Type Verbose
                Write-vDocMessage -Message "$_.Exception.Message" -Type Verbose
            } #END try/catch
            
            #Get Memory Details
            try {
                #Best effort - Try Information from IPMI Sensor Data Respository (SDR)
                Write-vDocMessage -Message "Gathering hardware Memory details..." -Type Verbose               
                $esxIpmiSdr = $esxCli.hardware.ipmi.sdr.list.invoke()
                $esxRam = $esxIpmiSdr | Where-Object { $_.Description -match 'Memory Device|Memory Module' }
                switch ($true) {
                    ($esxRam.ComputedReading[0] -match 'Presence Detected') {
                        $esxSdrRam = $esxRam | Where-Object { $_.ComputedReading -match 'Presence Detected' }
                        $Inventory.'Memory Slots Count' = $esxSdrRam.count
                    }
    
                    ($esxRam.BaseUnit[0] -match 'degrees') {
                        $esxSdrRam = $esxRam | Where-Object { $_.BaseUnit -match 'degrees' -and $_.Description -notmatch 'Mem Zone' }
                        if ($esxSdrRam.Description[0] -match 'DIMM*-*') {
                            $count = 0
                            foreach ($sdrItem in $esxSdrRam) {
                                $dimmRange = $sdrItem.Description.split('DIMM')[1]
                                $dimmRange = $dimmRange.split('-')
                                $count = $count + ($dimmRange[0]..$dimmRange[1]).Count
                            } #END foreach

                            $Inventory.'Memory Slots Count' = $count
                        }
                        else {
                            $Inventory.'Memory Slots Count' = $esxSdrRam.count
                        } #END if/else
                    }
                } #END Switch
            }
            catch {
                Write-vDocMessage -Message "Get hardware Memory details, error:" -Type Verbose
                Write-vDocMessage -Message "$_.Exception.Message" -Type Verbose
            } #END try/catch

            #Get PSU Details
            try {
                # Get PSU from IPMI Field Replaceable Unit inventory (FRU)
                Write-vDocMessage -Message "Gathering hardware PSU details..." -Type Verbose
                $esxIpmiFru = $esxCli.hardware.ipmi.fru.list.invoke()
                $esxPsu = $esxIpmiFru | Where-Object { $_.PartName -match 'PWR SPLY' }
            }
            catch {
                Write-vDocMessage -Message "Get hardware PSU details, error:" -Type Verbose
                Write-vDocMessage -Message "$_.Exception.Message" -Type Verbose
            } #END try/catch

            if ($esxPsu) {
                $Inventory.'Power Supplies' = $esxPsu.Count
            }
            else {
                #Best effort - Try Information from IPMI Sensor Data Respository (SDR)
                $esxIpmiSdr = $esxCli.hardware.ipmi.sdr.list.invoke()
                $esxPsu = $esxIpmiSdr | Where-Object { $_.Description -match 'Power Supply' -and $_.RawReading -gt 0 } | 
                Sort-Object -Unique EntityInstance
                $Inventory.'Power Supplies' = $esxPsu.Count
            } #END if/else
        } #END if/else
    } #END PROCESS
} #END function Get-vDocVMHostHardware

function Get-vDocEsxRac {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("AvoidUsingConvertToSecureStringWithPlainText", '', Justification = 'Get-vDocEsxRac does not change system state')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.InventoryItem[]]$vmHost,
        [Parameter(Mandatory)]
        $vmHostView,
        [Parameter(Mandatory)]
        $esxCli,
        [Parameter(Mandatory)]
        $OS
    ) #END param

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
        $bmcGetfailed = $false
    } #END BEGIN

    PROCESS {
        try {
            $esxIpmi = $esxCli.hardware.ipmi.bmc.get.Invoke()
            $Inventory.GetRac($esxIpmi.IPv4Address, $esxIpmi.MACAddress, $esxIpmi.BMCFirmwareVersion)
        }
        catch {
            Write-vDocMessage -Message "Get BMC details through esxCli failed, error:" -Type Verbose
            Write-vDocMessage -Message "$_.Exception.Message" -Type Verbose
            $bmcGetfailed = $true
        } #END try/catch

        if ($OS -eq "Windows" -and $bmcGetfailed) {
            $cimServicesTicket = $vmhostView.AcquireCimServicesTicket()
            $secureString = ConvertTo-SecureString $cimServicesTicket.SessionId -AsPlainText -Force
            $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $cimServicesTicket.SessionId, $secureString
            $cimOpt = New-CimSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -Encoding Utf8 -UseSsl
            $params = @{
                Authentication = 'Basic'
                Credential     = $credential
                ComputerName   = $vmHost.Name
                Port           = '443'
                SessionOption  = $cimOpt
                ErrorAction    = 'Stop'
            } #END $params

            try {
                Write-vDocMessage -Message "Attempting New-CimSession to $($params.ComputerName)..." -Type Verbose
                $session = New-CimSession @params

                $params = @{
                    CimSession  = $session
                    ClassName   = 'CIM_IPProtocolEndpoint'
                    ErrorAction = 'Stop'
                } #END $params

                $rac = Get-CimInstance @params | Where-Object { $_.Name -match "Management Controller IP" }
                if ($rac.Name) {
                    $Inventory.GetRac($rac.IPv4Address, $rac.MACAddress, $null)
                } #END if
            }
            catch {
                Write-vDocMessage -Message "CIM session failed, error:" -Type Verbose
                Write-vDocMessage -Message "$_.Exception.Message" -Type Verbose
            } #END try/catch
    
            if ($bmc = $vmHostView.Runtime.HealthSystemRuntime.SystemHealthInfo.NumericSensorInfo | Where-Object { $_.Name -match "BMC Firmware" }) {
                $Inventory.'RAC Firmware' = (($bmc.Name -split "firmware")[1]) -split " " | Select-Object -Last 1
            }
            else {
                Write-vDocMessage -Message "Failed to get BMC firmware via CIM, testing using WSMan ..." -Type Verbose
                $cimOpt = New-WSManSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                $uri = "https://$($vmHost.Name)/wsman"
                $resourceURI = "http://schema.omc-project.org/wbem/wscim/1/cim-schema/2/OMC_MCFirmwareIdentity"
                $params = @{
                    Authentication = 'basic'
                    ConnectionURI  = $uri
                    Credential     = $credential
                    Enumerate      = $true
                    Port           = '443'
                    UseSSL         = $true
                    SessionOption  = $cimOpt
                    ResourceURI    = $resourceURI
                    ErrorAction    = 'Stop'
                } #END $params

                try {
                    $rac = Get-WSManInstance @params
                    if ($rac.VersionString) {
                        $Inventory.'RAC Firmware' = $rac.VersionString
                    } #END if
                }
                catch {
                    Write-vDocMessage -Message "WSMan session failed, error:" -Type Verbose
                    Write-vDocMessage -Message "$_.Exception.Message" -Type Verbose
                } #END try/catch
            } #END if/else
        } #END if
    } #END PROCESS
} #END function Get-vDocEsxRac {

function Get-vDocPciDevices {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.InventoryItem[]]$vmHost,
        [Parameter(Mandatory)]
        $esxCli
    ) #END param

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
    } #END BEGIN

    PROCESS {
        Write-vDocMessage -Message "Gathering details about PCI Devices..." -Type Verbose
        $pciDevices = $esxcli.hardware.pci.list.Invoke() | Where-Object { $_.VMKernelName -match 'vmhba|vmnic|vmgfx' } | Sort-Object -Property VMKernelName
        Write-vDocMessage -Message "Total 'vmhba|vmnic|vmgfx' PCI Devices: $($pciDevices.Count)" -Type Verbose
        $uniquePciDevices = $pciDevices | Sort-Object PhysicalSlot -Unique
        foreach ($uniquePciDevice in $uniquePciDevices) {
            Write-vDocMessage -Message "Gathering details about PCI Device in Slot $($uniquePciDevice.PhysicalSlot)..." -Type Verbose
            $onePciDevice = $pciDevices | Where-Object { $_.PhysicalSlot -eq $uniquePciDevice.PhysicalSlot }

            # Filter out Embedded Device like SATA AHCI Controller, USB Controller
            $onePciDevice = $onePciDevice | Where-Object { $_.ParentDevice }

            # Break-out PCI Device by Class Name Like NIC and RAID - both are integrated
            $onePciDeviceClassNames = $onePciDevice | Sort-Object DeviceClassName -Unique
            foreach ($onePciDeviceClassName in $onePciDeviceClassNames) {
                $onePciDeviceClassName = $pciDevices | 
                Where-Object { $_.PhysicalSlot -eq $onePciDeviceClassName.PhysicalSlot -and $_.DeviceClassName -eq $onePciDeviceClassName.DeviceClassName }
                if ($onePciDeviceClassName.Count -gt 1) {
                    $onePciDevicePorts = $onePciDeviceClassName.Count
    
                    # Check for Integrated/rNDC/NDC vs PCI/PCIe Slot Device
                    if ($onePciDevicePorts -eq ($onePciDeviceClassName | Where-Object { $_.SlotDescription -match 'slot|pci' }).Count) {
                        $slotDescription = $onePciDeviceClassName | Select-Object -ExpandProperty SlotDescription -First 1
                    }
                    else {
                        if ($onePciDeviceClassName.VMKernelName -match 'vmnic') {
                            $slotDescription = "Integrated NIC"
                        }
                        else {
                            $slotDescription = "Integrated"
                        } #END if/else
                    } #END if/else
    
                    # Check for different Ports on the Device like 2P 1Gbps/2P 10Gbps rNDC
                    if (($onePciDeviceClassName | Sort-Object DeviceName -Unique).Count -gt 1) {
                        $uniqueDeviceNames = $onePciDeviceClassName | Sort-Object DeviceName -Unique
                        $multipleDevice = @()
                        foreach ($uniqueDeviceName in $uniqueDeviceNames) {
                            $deviceNamePorts = ($onePciDeviceClassName | Where-Object { $_.DeviceName -eq $uniqueDeviceName.DeviceName }).Count
                            if ($uniqueDeviceName.DeviceName -match '2P|4P|DP|QP|Dual|Quad') {
                                $multipleDevice += $uniqueDeviceName.DeviceName
                            }
                            else {
                                $multipleDevice += [string]$deviceNamePorts + "P " + $uniqueDeviceName.DeviceName
                            } #END if/else
                        } #END foreach
                        $deviceName = (@($multipleDevice) -join '/')
                    }
                    else {
                        if ($onePciDeviceClassName.DeviceName -match '2P|4P|DP|QP|Dual|Quad') {
                            $deviceName = $onePciDeviceClassName | Select-Object -ExpandProperty DeviceName -First 1
                        }
                        else {
                            $deviceName = [string]$onePciDevicePorts + "P " + ($onePciDeviceClassName | Select-Object -ExpandProperty DeviceName -First 1)
                        } #END if/else
                    } #END if/esle
                }
                else {
                    if ($onePciDeviceClassName.SlotDescription) {
                        $slotDescription = $onePciDeviceClassName.SlotDescription
                    }
                    else {
                        $slotDescription = "Integrated " + [string]$onePciDeviceClassName.DeviceClassName
                    } #END if/else

                    $deviceName = $onePciDeviceClassName.DeviceName
                } #END if/else

                # Instantiate PciDevices Class
                $PciDevice = [vDocPciDevices]::new()

                if ($callStack[1].FunctionName -match 'ESXIODevice') {
                    $hashTable += [ordered]@{
                        'VMKernelName'    = $onePciDeviceClassName.VMKernelName
                        'DeviceClassName' = $onePciDeviceClassName.DeviceClassName | Select-Object -First 1
                        'VendorName'      = $onePciDeviceClassName.VendorName | Select-Object -First 1
                        'Address'         = $onePciDeviceClassName | Select-Object -ExpandProperty Address
                        'VendorId'        = [String]::Format("{0:x4}", [int]($onePciDeviceClassName.VendorId | Select-Object -First 1))
                        'DeviceId'        = [String]::Format("{0:x4}", [int]($onePciDeviceClassName.DeviceId | Select-Object -First 1))
                        'SubVendorId'     = [String]::Format("{0:x4}", [int]($onePciDeviceClassName.SubVendorId | Select-Object -First 1))
                        'SubDeviceId'     = [String]::Format("{0:x4}", [int]($onePciDeviceClassName.SubDeviceId | Select-Object -First 1))
                        'ModuleName'      = $onePciDeviceClassName.ModuleName | Select-Object -First 1
                    } #END $hashtable
                } #END if
    
                $pciDeviceCollection.Add($PciDevice)
            } #END foreach
        } #END foreach
    } #END PROCESS
} #END function Get-vDocPciDevices

function Invoke-vDocRestMethod {
    [CmdletBinding()]
    param (
        [Parameter()]
        $params
    )

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
    } #END BEGIN
    
    PROCESS {
        Write-vDocMessage -Message "Validating access to: $($params.uri)" -Type Verbose
        try {
            Invoke-RestMethod @params
        } 
        catch [System.Net.WebException] {
            $_.Exception
            Write-vDocMessage -Message "Invoke-RestMethod to '$($params.uri)' failed. Exception: $($_.Exception.Message)" -Type Verbose
        } #END try/catch
    } #END PROCESS
} #END function Invoke-vDocRestMethod

function Unblock-vDocSelfSignedCerts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $OS
    )

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
    } #END BEGIN
    
    PROCESS {
        if ($OS -eq 'Windows') {
            <#
              Add a .NET Framework Type to a PowerShell session to Ignore RAC
              self-signed certificates and safe header parsing. Set the session
              to use TLS 1.2 or TLS1.1
            #>
            try {
                Write-vDocMessage -Message "Adding TrustAllCertsPolicy Type...." -Type Verbose
                Add-Type -TypeDefinition @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy
            {
                public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem)
                {
                    return true;
                }
            }
"@
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                Write-vDocMessage -Message "TrustAllCertsPolicy Type added...." -Type Verbose
            }
            catch {
                Write-vDocMessage -Message "Adding TrustAllCertsPolicy Type failed. $_" -Type Verbose
            } #END try/catch
        } #END if
        
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
        $initParams.SkipCertCheck = $true
    } #END PROCESS
} #END function Unblock-vDocSelfSignedCerts
function Get-vDocRacConnectMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $racIP,
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$credential,
        [Parameter(Mandatory)]
        $OS
    ) #END param

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
        Unblock-vDocSelfSignedCerts -OS $OS
    } #END BEGIN

    PROCESS {
        # Determine connection to Dell RAC
        $headers = @{
            Accept = 'application/json'
        } #END $headers

        #URI to Query "/redfish/v1/Systems/System.Embedded.1"
        $params = @{
            uri             = "https://$racIP/redfish/v1/Systems/System.Embedded.1"
            Method          = 'Get'
            UseBasicParsing = $true
            Credential      = $credential
            ContentType     = 'application/json'
            Headers         = $headers
        } #END $params

        if ($OS -ne 'Windows') {
            $params.SkipCertificateCheck = $true
        } #END if

        $webRequest = Invoke-vDocRestMethod -params $params
        if (-not ($webRequest.GetType().Name -eq 'WebException')) {
            Write-vDocMessage -Message "Invoke-RestMethod to Redfish server was successful" -Type Verbose
            $connectMethod = "Redfish"
        }
        else {
            Write-vDocMessage -Message "Invoke-RestMethod to Redfish server failed. Testing using CIM..." -Type Verbose
            try {
                $cimOpt = New-CimSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -Encoding Utf8 -UseSsl
                $params = @{
                    Authentication = 'Basic'
                    Credential     = $credential
                    ComputerName   = $racIP
                    Port           = '443'
                    SessionOption  = $cimOpt
                    ErrorAction    = 'Stop'
                } #END $params
                Write-vDocMessage -Message "Attempting New-CimSession to $($params.ComputerName)..." -Type Verbose
                $session = New-CimSession @params
            }
            catch {
                Write-vDocMessage -Message "CIM session failed, error:" -Type Verbose
                Write-vDocMessage -Message "$_.Exception.Message" -Type Verbose
            } #END try/catch

            if ($session) {
                Write-vDocMessage -Message "New-CimSession to CIM server was successful" -Type Verbose
                $connectMethod = "CIM"
                Remove-CimSession -CimSession $session
            }
            else {
                Write-vDocMessage -Message "Failed to establish a connection to RAC: $racIP via Redfish/CIM" -Type Warning
                $connectMethod = "Failed"
            } #END if/else
        } #END if/else
    } #END PROCESS
    
    END {
        return $connectMethod
    } #END END
} #END function Get-vDocRacConnectMethod

function Get-vDocRedFishRacStorageInventory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $racIP,
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$credential,
        [Parameter(Mandatory)]
        $OS
    ) #END param

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
        if (-not $initParams.SkipCertCheck) {
            Unblock-vDocSelfSignedCerts -OS $OS
        } #END if
    } #END BEGIN

    PROCESS {
        <#
          Gather Storage Controller, Drives
          and Volumes details
        #>
        $headers = @{
            Accept = 'application/json'
        } #END $headers

        #URI to Query "/redfish/v1/Systems/System.Embedded.1/Storage"
        $params = @{
            uri             = "https://$racIP/redfish/v1/Systems/System.Embedded.1/Storage"
            Method          = 'Get'
            UseBasicParsing = $true
            Credential      = $credential
            ContentType     = 'application/json'
            Headers         = $headers
        } #END $params

        if ($OS -ne 'Windows') {
            $params.SkipCertificateCheck = $true
        } #END if

        $webRequest = Invoke-vDocRestMethod $params
        if (-not ($webRequest.GetType().Name -eq 'WebException')) {
            #Check for Storage Collection
            if ($webRequest.'Members@odata.count' -gt 0) {
                Write-Verbose -Message "$(Get-Date -Format G) `tStorage Collection found. Members: $($webRequest.Members.'@odata.id')"
                $storageCollection = $webRequest

                #Select only Storage Controllers that have Drives
                foreach ($storageMember in $storageCollection.Members) {
                    $params.uri = -join ("https://$racIP", $storageMember.'@odata.id')
                    $webRequest = Invoke-vDocRestMethod $params
                    if (-not ($webRequest.GetType().Name -eq 'WebException')) {
                        #Check for Drives and Get Storage Controller Details
                        if ($webRequest.'Drives@odata.count' -gt 0) {
                            $storageController = $webRequest
                            Write-vDocMessage -Message "Storage Controller $($storageController.Name) has $($storageController.'Drives@odata.count') Drives." -Type Verbose
                            Write-vDocMessage -Message "Drives: $($storageController.Drives.'@odata.id')" -Type Verbose
                            Write-vDocMessage -Message "Gathering Storage Controller details..." -Type Verbose
                            
                            $controller = [vDocRacStorageController]@{
                                'Id'                  = $storageController.Id
                                'Manufacturer'        = $storageController.StorageControllers.Manufacturer
                                'Model'               = $storageController.StorageControllers.Model
                                'Speed (Gbps)'        = $storageController.StorageControllers.SpeedGbps
                                'Firmware'            = $storageController.StorageControllers.FirmwareVersion
                                'Drives'              = $storageController.'Drives@odata.count'
                                'Controller Protocol' = $storageController.StorageControllers.SupportedControllerProtocols
                                'Device Protocol'     = (@($storageController.StorageControllers.SupportedDeviceProtocols) -join ',')
                                'Status'              = $storageController.StorageControllers.Status.Health
                            } #END $controller

                            $racStorageControllerCollection.Add($controller)
                            
                            #Get Drive details
                            foreach ($drive in $storageController.Drives) {
                                $params.uri = -join ("https://$racIP", $drive.'@odata.id')
                                $webRequest = Invoke-vDocRestMethod $params
                                if (-not ($webRequest.GetType().Name -eq 'WebException')) {
                                    $oneDrive = $webRequest
                                    Write-vDocMessage -Message "Gathering Drive: $($oneDrive.Name) details..." -Type Verbose

                                    if ($oneDrive.Id -match "Disk.Bay.|Disk.Direct.") {
                                        $stringPattern = 'Disk.Bay.\d*', 'Disk.Direct.\d*'
                                        $result = $oneDrive.Id | Select-String $stringPattern
                                        [int]$slotId = $result.Matches.Value.Split('.') | Select-Object -Last 1
                                    }
                                    else {
                                        [string]$slotId = $oneDrive.Id
                                    } #END if/else

                                    $drives = [vDocRacDrives]@{
                                        'Storage Controller'      = $storageController.Name
                                        'Id'                      = $oneDrive.Id
                                        'Slot'                    = $slotId
                                        'Name'                    = $oneDrive.Name
                                        'Capable Speed (Gbps)'    = $oneDrive.CapableSpeedGbs
                                        'Capacity (GB)'           = [math]::round($oneDrive.CapacityBytes / 1GB, 2)
                                        'Manufacturer'            = $oneDrive.Manufacturer
                                        'Type'                    = $oneDrive.MediaType
                                        'Model'                   = $oneDrive.Model
                                        'Negotiated Speed (Gbps)' = $oneDrive.NegotiatedSpeedGbs
                                        'Part Number'             = $oneDrive.PartNumber
                                        'Protocol'                = $oneDrive.Protocol
                                        'Firmware'                = $oneDrive.Revision
                                        'Serial Number'           = $oneDrive.SerialNumber
                                        'Failure Predicted'       = $oneDrive.FailurePredicted
                                        'Hotspare'                = $oneDrive.HotspareType
                                        'Speed (RPM)'             = $oneDrive.RotationSpeedRPM
                                        'Status'                  = $oneDrive.Status.Health
                                    } #END $drives

                                    $racDrivesCollection.Add($drives)
                                }
                                else {
                                    Write-vDocMessage -Message "Invoke-RestMethod to $($params.uri) failed." -Type Verbose
                                } #END if/else
                            } #END foreach

                            #Check for volumes
                            $params.uri = -join ("https://$racIP", $storageController.Volumes.'@odata.id')
                            $webRequest = Invoke-vDocRestMethod $params
                            if (-not ($webRequest.GetType().Name -eq 'WebException')) {
                                #Get Volumes detail
                                if ($webRequest.'Members@odata.count' -gt 0) {
                                    $storageVolumes = $webRequest
                                    Write-vDocMessage -Message "Storage Controller $($storageController.Name) has $($storageVolumes.'Members@odata.count') Volumes." -Type Verbose
                                    Write-vDocMessage -Message "Volumes: $($storageVolumes.Members.'@odata.id')" -Type Verbose
                                    foreach ($volume in $storageVolumes.Members) {
                                        $params.uri = -join ("https://$racIP", $volume.'@odata.id')
                                        $webRequest = Invoke-vDocRestMethod $params
                                        if (-not ($webRequest.GetType().Name -eq 'WebException')) {
                                            $oneVolume = $webRequest
                                            $slots = @()
                                            Write-vDocMessage -Message "Gathering Volume: $($oneVolume.Name) details..." -Type Verbose
                                            $linkDrives = $oneVolume.Links.Drives.'@odata.id'
                                            foreach ($link in $linkDrives) {
                                                $esxiDrives = $racDrivesCollection | Where-Object { $_.Hostname -eq $esxiHost.Name }
                                                $linkDrive = $esxiDrives | Where-Object { $_.Id -eq ($link.Split('/') | Select-Object -Last 1) }
                                                $index = $racDrivesCollection.IndexOf($linkDrive)
                                                $racDrivesCollection[$index].Volume = $oneVolume.Name
                                                $slots += $linkDrive | Select-Object -ExpandProperty Slot
                                            } #END foreach
                             
                                            $volumes = [vDocRacVolumes]@{
                                                'Storage Controller' = $storageController.Name
                                                'Id'                 = $oneVolume.Id
                                                'Name'               = $oneVolume.Name
                                                'Capacity (GB)'      = [math]::round($oneVolume.CapacityBytes / 1GB, 2)
                                                'Type'               = $oneVolume.VolumeType
                                                'Drives'             = $oneVolume.Links.'Drives@odata.count'
                                                'Slots'              = (@($slots) -join ',')
                                                'Status'             = $oneVolume.Status.Health
                                            } #END $volumes

                                            $racVolumesCollection.Add($volumes)
                                        }
                                        else {
                                            Write-vDocMessage -Message "Invoke-RestMethod to $($params.uri) failed." -Type Verbose
                                        } #END if/else
                                    } #END foreach
                                }
                                else {
                                    Write-vDocMessage -Message "Storage Controller $($storageController.Name) has no Volumes" -Type Verbose
                                } #END if/else
                            }
                            else {
                                Write-vDocMessage -Message "Invoke-RestMethod to $($params.uri) failed." -Type Verbose
                            } #END if/else
                        }
                        else {
                            #No Drives. Get Storage Controller Details
                            $storageController = $webRequest
                            Write-vDocMessage -Message "Storage Controller $($storageControllerOnly.Name) has no Drives" -Type Verbose
                            Write-vDocMessage -Message "Gathering Storage Controller details..." -Type Verbose
                            $controller = [vDocRacStorageController]@{
                                'Id'                  = $storageController.Id
                                'Manufacturer'        = $storageController.StorageControllers.Manufacturer
                                'Model'               = $storageController.StorageControllers.Model
                                'Speed (Gbps)'        = $storageController.StorageControllers.SpeedGbps
                                'Firmware'            = $storageController.StorageControllers.FirmwareVersion
                                'Drives'              = $storageController.'Drives@odata.count'
                                'Controller Protocol' = $storageController.StorageControllers.SupportedControllerProtocols
                                'Device Protocol'     = (@($storageController.StorageControllers.SupportedDeviceProtocols) -join ',')
                                'Status'              = $storageController.StorageControllers.Status.Health
                            } #END $controller

                            $racStorageControllerCollection.Add($controller)
                        } #END if/else
                    }
                    else {
                        Write-vDocMessage -Message "Invoke-RestMethod to $($params.uri) failed." -Type Verbose
                    } #END if/else
                } #END foreach
            }
            else {
                Write-vDocMessage -Message "No Storage Collection found." -Type Verbose
            } #END if/else
        }
        else {
            Write-vDocMessage -Message "Invoke-RestMethod to $($params.uri) failed." -Type Verbose
        } #END if/else
    } #END PROCESS
} #END function Get-vDocRedFishRacStorageInventory

function Get-vDocRedFishRacMemoryInventory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $racIP,
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]$credential,
        [Parameter(Mandatory)]
        $OS 
    )
  
    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
        if (-not $initParams.SkipCertCheck) {
            Unblock-vDocSelfSignedCerts -OS $OS
        } #END if
    } #END BEGIN
  
    PROCESS {
        # Gather Physical Memory details
        $headers = @{
            Accept = 'application/json'
        } #END $headers
  
        #URI to Query "/redfish/v1/Systems/System.Embedded.1/Memory"
        $params = @{
            uri             = "https://$racIP/redfish/v1/Systems/System.Embedded.1/Memory"
            Method          = 'Get'
            UseBasicParsing = $true
            Credential      = $credential
            ContentType     = 'application/json'
            Headers         = $headers
        } #END $params

        if ($OS -ne 'Windows') {
            $params.SkipCertificateCheck = $true
        } #END if
  
        $webRequest = Invoke-vDocRestMethod $params
        if (-not ($webRequest.GetType().Name -eq 'WebException')) {
            #Check for collection of memory devices
            if ($webRequest.'Members@odata.count' -gt 0) {
                Write-vDocMessage -Message "Memory Collection found. Count: $($webRequest.'Members@odata.count')" -Type Verbose
                $memoryCollection = $webRequest
                foreach ($dimm in $memoryCollection.Members) {
                    $params.uri = -join ("https://$racIP", $dimm.'@odata.id')
                    $webRequest = Invoke-vDocRestMethod $params
                    if (-not ($webRequest.GetType().Name -eq 'WebException')) {
                        $oneDimm = $webRequest
                        Write-vDocMessage -Message "Gathering Memory: $($oneDimm.Name) details..." -Type Verbose
                        $memDimms = [vDocMemory]@{
                            'Id'               = $oneDimm.Id
                            'Slot'             = $oneDimm.DeviceLocator
                            'Name'             = $oneDimm.Name
                            'Speed (Mhz)'      = $oneDimm.OperatingSpeedMhz
                            'Capacity (GB)'    = [math]::round($oneDimm.CapacityMiB / 1000)
                            'Manufacturer'     = $oneDimm.Manufacturer
                            'Type'             = $oneDimm.MemoryDeviceType
                            'Rank'             = $oneDimm.RankCount
                            'Error Correction' = $oneDimm.ErrorCorrection
                            'Part Number'      = $oneDimm.PartNumber
                            'Serial Number'    = $oneDimm.SerialNumber
                            'Status'           = $oneDimm.Status.Health
                        } #END $memDimms

                        $racMemoryCollection.Add($memDimms)
                    }
                    else {
                        Write-vDocMessage -Message "Invoke-RestMethod to $($params.uri) failed." -Type Verbose
                    } #END if/else
                } #END foreach
            }
            else {
                Write-vDocMessage -Message "No Memory Collection found." -Type Verbose
            } #END if/else
        }
        else {
            Write-vDocMessage -Message "Invoke-RestMethod to $($params.uri) failed." -Type Verbose
        } #END if/else
    } #END PROCESS
} #END function Get-vDocRedFishRacMemoryInventory

function Get-vDocRedFishRacFirmwareInventory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $racIP,
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$credential,
        [Parameter(Mandatory)]
        $OS
    ) #END param

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
        if (-not $initParams.SkipCertCheck) {
            Unblock-vDocSelfSignedCerts -OS $OS
        } #END if
    } #END BEGIN

    PROCESS {
        # Gather Firmware Details
        $headers = @{
            Accept = 'application/json'
        } #END $headers
  
        #URI to Query "/redfish/v1/UpdateService/FirmwareInventory"
        $params = @{
            uri             = "https://$racIP/redfish/v1/UpdateService/FirmwareInventory"
            Method          = 'Get'
            UseBasicParsing = $true
            Credential      = $credential
            ContentType     = 'application/json'
            Headers         = $headers
        } #END $params

        if ($OS -ne 'Windows') {
            $params.SkipCertificateCheck = $true
        } #END if
  
        $webRequest = Invoke-vDocRestMethod $params
        if (-not ($webRequest.GetType().Name -eq 'WebException')) {
            #Check for collection of memory devices
            if ($webRequest.'Members@odata.count' -gt 0) {
                Write-vDocMessage -Message "Firmware Collection found. Count: $($webRequest.'Members@odata.count')" -Type Verbose
                $firmwareCollection = $webRequest
                
                #Filter Installed Firmwares only
                foreach ($firmware in $firmwareCollection.Members) {
                    if (-not ($firmware.'@odata.id' -match "Installed")) {
                        Write-vDocMessage -Message "Skipping Firmware: $($firmware.'@odata.id')" -Type Verbose
                        continue
                    } #END if

                    $params.uri = -join ("https://$racIP", $firmware.'@odata.id')
                    $webRequest = Invoke-vDocRestMethod $params
                    if (-not ($webRequest.GetType().Name -eq 'WebException')) {
                        Write-vDocMessage -Message "Gathering Firmware: $($oneFirmware.Name) details..." -Type Verbose
                        $oneFirmware = $webRequest
                        $hardwarefw = [vDocFirmware]::new()
                        $hardwarefw.Component = $oneFirmware.Name
                        $hardwarefw.'FW Version' = $oneFirmware.Version
                        $racFirmwareCollection.Add($hardwarefw)
                    }
                    else {
                        Write-vDocMessage -Message "Invoke-RestMethod to $($params.uri) failed." -Type Verbose
                    } #END if/else
                } #END foreach
            }
            else {
                Write-vDocMessage -Message "No Firmwware Collection found." -Type Verbose
            } #END if/else
        }
        else {
            Write-vDocMessage -Message "Invoke-RestMethod to $($params.uri) failed." -Type Verbose
        } #END if/else
    } #END PROCESS
} #END function Get-vDocRedFishRacFirmwareInventory

function Get-vDocDellCimPropertyDescription {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $ResourceUri,
        [Parameter(Mandatory)]
        $Property,
        [Parameter(Mandatory)]
        $Value
    )

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
    } #END BEGIN
    
    PROCESS {
        $ResourceUri = $ResourceUri.Split('/') | Select-Object -Last 1
        Write-vDocMessage -Message "Get description for: $Property, Value: $Value, under $ResourceUri Class" -Type Verbose
        if ($ResourceUri -like "DCIM_ControllerView" -and $Property -like "PrimaryStatus") {
            switch ($Value) {
                0 { "Unknown"; break }
                1 { "OK"; break }
                2 { "Degraded"; break }
                3 { "Error"; break }
                default { "Unknown"; break }
            }#END Switch
        } #END if
 
        if ($ResourceUri -like "DCIM_PhysicalDiskView") {
            switch (($Property -like "MaxCapableSpeed")) {
                $true {
                    switch ($Value) {
                        0 { "Unknown"; break }
                        1 { "1.5"; break }
                        2 { "3"; break }
                        3 { "6"; break }
                        4 { "12"; break }
                        default { "Unknown"; break }
                    }#END Switch
                } #END $true
            } #END Switch

            switch (($Property -like "MediaType")) {
                $true {
                    switch ($Value) {
                        0 { "Hard Disk Drive"; break }
                        1 { "Solid State Drive"; break }
                        default { "Unknown"; break }
                    }#END Switch
                } #END $true
            } #END Switch

            switch (($Property -like "PredictiveFailureState")) {
                $true {
                    switch ($Value) {
                        0 { "Smart Alert Absent"; break }
                        1 { "Smart Alert Present"; break }
                        default { "Unknown"; break }
                    }#END Switch
                } #END $true
            } #END Switch

            switch (($Property -like "BusProtocol")) {
                $true {
                    switch ($Value) {
                        0 { "Unknown"; break }
                        1 { "SCSI"; break }
                        2 { "PATA"; break }
                        3 { "FIBRE"; break }
                        4 { "USB"; break }
                        5 { "SATA"; break }
                        6 { "SAS"; break }
                        7 { "PCIE"; break }
                        8 { "NVME"; break }
                        default { "Unknown"; break }
                    }#END Switch
                } #END $true
            } #END Switch

            switch (($Property -like "HotSpareStatus")) {
                $true {
                    switch ($Value) {
                        0 { "No"; break }
                        1 { "Dedicated"; break }
                        2 { "Global"; break }
                        default { "Unknown"; break }
                    }#END Switch
                } #END $true
            } #END Switch

            switch (($Property -like "PrimaryStatus")) {
                $true {
                    switch ($Value) {
                        0 { "Unknown"; break }
                        1 { "OK"; break }
                        2 { "Degraded"; break }
                        3 { "Error"; break }
                        default { "Unknown"; break }
                    }#END Switch
                } #END $true
            } #END Switch
        } #END if

        if ($ResourceUri -like "DCIM_VirtualDiskView") {
            switch (($Property -like "RAIDTypes")) {
                $true {
                    switch ($Value) {
                        1 { "No RAID"; break }
                        2 { "RAID-0"; break }
                        4 { "RAID-1"; break }
                        64 { "RAID-5"; break }
                        128 { "RAID-6"; break }
                        2048 { "RAID-10"; break }
                        8192 { "RAID-50"; break }
                        16384 { "RAID-60"; break }
                        default { "Unknown"; break }
                    }#END Switch
                } #END $true
            } #END Switch

            switch (($Property -like "PrimaryStatus")) {
                $true {
                    switch ($Value) {
                        0 { "Unknown"; break }
                        1 { "OK"; break }
                        2 { "Degraded"; break }
                        3 { "Error"; break }
                        4 { "Rebuilding"; break }
                        5 { "Offline"; break }
                        default { "Unknown"; break }
                    }#END Switch
                } #END $true
            } #END Switch
        } #END if

        if ($ResourceUri -like "DCIM_MemoryView") {
            switch (($Property -like "MemoryType")) {
                $true {
                    switch ($Value) {
                        0 { "Unknown"; break }
                        1 { "Other"; break }
                        2 { "DRAM"; break }
                        3 { "Synchronous DRAM"; break }
                        4 { "Cache DRAM"; break }
                        5 { "EDO"; break }
                        6 { " EDRAM"; break }
                        7 { "VRAM"; break }
                        8 { "SRAM"; break }
                        9 { "RAM"; break }
                        10 { "ROM"; break }
                        11 { "Flash"; break }
                        12 { "EEPROM"; break }
                        13 { "FEPROM"; break }
                        14 { "EPROM"; break }
                        15 { "CDRAM"; break }
                        16 { "3DRAM"; break }
                        17 { "SDRAM"; break }
                        18 { "SGRAM"; break }
                        19 { "RDRAM"; break }
                        20 { "DDR"; break }
                        21 { "DDR-2"; break }
                        22 { "BRAM"; break }
                        23 { "FB-DIMM"; break }
                        24 { "DDR3"; break }
                        25 { "FBD2"; break }
                        26 { "DDR4"; break }
                        27 { "LPDDR"; break }
                        28 { "LPDDR2"; break }
                        29 { "LPDDR3"; break }
                        30 { "LPDDR4"; break }
                        default { "Unknown"; break }
                    }#END Switch
                } #END $true
            } #END Switch

            switch (($Property -like "PrimaryStatus")) {
                $true {
                    switch ($Value) {
                        0 { "Unknown"; break }
                        1 { "OK"; break }
                        2 { "Degraded"; break }
                        3 { "Error"; break }
                        default { "Unknown"; break }
                    }#END Switch
                } #END $true
            } #END Switch
        } #END if
    } #END PROCESS
} #END function Get-vDocDellCimPropertyDescription

function Get-vDocCimRacStorageInventory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $racIP,
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]$credential 
    )

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
    } #END BEGIN

    PROCESS {
        
        # Gather Storage Controller, Drives and Volumes details
        $cimOpt = New-CimSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -Encoding Utf8 -UseSsl
        $params = @{
            Authentication = 'Basic'
            Credential     = $credential
            ComputerName   = $racIP
            Port           = '443'
            SessionOption  = $cimOpt
            ErrorAction    = 'Stop'
        } #END $params

        try {
            Write-vDocMessage -Message "Attempting New-CimSession to $($params.ComputerName)..." -Type Verbose
            $session = New-CimSession @params
        }
        catch {
            Write-vDocMessage -Message "CIM session failed, error:" -Type Verbose
            Write-vDocMessage -Message "$_.Exception.Message" -Type Verbose
        } #END try/catch

        $params = @{
            CimSession  = $session
            ResourceUri = 'http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_ControllerView'
            ErrorAction = 'Stop'
        } #END $params
        
        $webRequest = Invoke-vDocCimInstance $params        
        if (-not ($webRequest.GetType().Name -match "Exception")) {
            $storageControllers = $webRequest
            #Check for Storage Controller(s)
            if ($storageControllers.InstanceID.Count -gt 0) {
                Write-vDocMessage -Message "Storage Controller(s) found. Members: $(@($storageControllers.ProductName) -join ',')" -Type Verbose
                Write-vDocMessage -Message "Gathering Storage Controller details..." -Type Verbose
                foreach ($storageController in $storageControllers) {
                    $status = Get-vDocDellCimPropertyDescription -ResourceUri $params.ResourceUri -Property "PrimaryStatus" -Value $storageController.PrimaryStatus

                    $controller = [vDocRacStorageController]@{
                        'Id'           = $storageController.InstanceID
                        'Manufacturer' = $storageController.DeviceCardManufacturer
                        'Model'        = $storageController.ProductName
                        'Firmware'     = $storageController.ControllerFirmwareVersion
                        'Status'       = $status
                    } #END $controller
                        
                    $racStorageControllerCollection.Add($controller)
                } #END foreach
            }
            else {
                Write-vDocMessage -Message "No Storage Controller found." -Type Verbose
            } #END if/else
        }
        else {
            Write-vDocMessage -Message "Get-CimInstance to $($params.ResourceUri) failed." -Type Verbose
        } #END if/else

        #Get Drive details
        $params.ResourceUri = 'http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_PhysicalDiskView'
        $webRequest = Invoke-vDocCimInstance $params
        if (-not ($webRequest.GetType().Name -match "Exception")) {
            $diskDrives = $webRequest
            if ($diskDrives.InstanceID.Count -gt 0) {
                Write-vDocMessage -Message "Gathering Disk Drives details. Count found: $($diskDrives.InstanceID.Count)" -Type Verbose
                $parentController = @()
                foreach ($oneDrive in $diskDrives) {
                    Write-vDocMessage -Message "$(Get-Date -Format G) `tGathering Drive: $($oneDrive.InstanceID) details..." -Type Verbose
                    $linkController = $racStorageControllerCollection | Where-Object { $_.Id -eq ($oneDrive.InstanceID.Split(':') | Select-Object -Last 1) }  -ErrorAction SilentlyContinue
                    if (-not $parentController.Id -contains $linkController.Id) {
                        $parentController += [PSCustomObject]@{
                            'Id'     = $linkController.Id
                            'Drives' = 1
                        } #END PSCustomObject
                    }
                    else {
                        $indexController = $parentController | Where-Object { $_.Id -like $linkController.Id }
                        $index = $parentController.IndexOf($indexController)
                        $parentController[$index].Drives = $indexController.Drives + 1
                    } #END if/else

                    $speedGbps = Get-vDocDellCimPropertyDescription -ResourceUri $params.ResourceUri -Property "MaxCapableSpeed" -Value $oneDrive.MaxCapableSpeed
                    $mediaType = Get-vDocDellCimPropertyDescription -ResourceUri $params.ResourceUri -Property "MediaType" -Value $oneDrive.MediaType
                    $smartState = Get-vDocDellCimPropertyDescription -ResourceUri $params.ResourceUri -Property "PredictiveFailureState" -Value $oneDrive.PredictiveFailureState
                    $busProtocol = Get-vDocDellCimPropertyDescription -ResourceUri $params.ResourceUri -Property "BusProtocol" -Value $oneDrive.BusProtocol
                    $hotSpare = Get-vDocDellCimPropertyDescription -ResourceUri $params.ResourceUri -Property "HotSpareStatus" -Value $oneDrive.HotSpareStatus
                    $status = Get-vDocDellCimPropertyDescription -ResourceUri $params.ResourceUri -Property "PrimaryStatus" -Value $oneDrive.PrimaryStatus

                    $drives = [vDocRacDrives]@{
                        'Storage Controller'   = $linkController.Model
                        'Id'                   = $oneDrive.InstanceID
                        'Slot'                 = $oneDrive.Slot
                        'Name'                 = $oneDrive.DeviceDescription
                        'Capable Speed (Gbps)' = $speedGbps
                        'Capacity (GB)'        = [math]::round($oneDrive.SizeInBytes / 1GB, 2)
                        'Manufacturer'         = $oneDrive.Manufacturer
                        'Type'                 = $mediaType
                        'Model'                = $oneDrive.Model
                        'Part Number'          = $oneDrive.PPID
                        'Protocol'             = $busProtocol
                        'Firmware'             = $oneDrive.Revision
                        'Serial Number'        = $oneDrive.SerialNumber
                        'Failure Predicted'    = $smartState
                        'Hotspare'             = $hotSpare
                        'Status'               = $status
                    } #END $drives

                    $racDrivesCollection.Add($drives)            
                } #END foreach
            }
            else {
                Write-vDocMessage -Message "No Drive(s) found." -Type Verbose
            } #END if/else
        }
        else {
            Write-vDocMessage -Message "Get-CimInstance to $($params.ResourceUri) failed." -Type Verbose
        } #END if/else

        #Update Strorage Controllers Drives property
        if ($parentController) {
            foreach ($pController in $parentController) {
                $indexController = $racStorageControllerCollection | Where-Object { $_.Id -like $pController.Id }
                $index = $racStorageControllerCollection.IndexOf($indexController)
                $racStorageControllerCollection[$index].Drives = $pController.Drives
            } #END foreach
        } #END if

        #Get Volume details
        $params.ResourceUri = 'http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_VirtualDiskView'
        $webRequest = Invoke-vDocCimInstance $params
        if (-not ($webRequest.GetType().Name -match "Exception")) {
            $storageVolumes = $webRequest
            if ($storageVolumes.InstanceID.Count -gt 0) {
                Write-vDocMessage -Message "Gathering Volume details. Count found: $($storageVolumes.InstanceID.Count)" -Type Verbose
                Write-vDocMessage -Message "Volumes: $(@($storageVolumes.Name) -join ',')" -Type Verbose
                foreach ($volume in $storageVolumes) {
                    $slots = @()
                    Write-vDocMessage -Message "Gathering Volume: $($volume.Name) details..." -Type Verbose
                    $linkDrives = $volume.PhysicalDiskIDs
                    foreach ($link in $linkDrives) {
                        $linkDrive = $racDrivesCollection | Where-Object { $_.Id -like $link }
                        $index = $racDrivesCollection.IndexOf($linkDrive)
                        $racDrivesCollection[$index].Volume = $volume.Name
                        $slots += $linkDrive.Slot
                    } #END foreach

                    $sController = $racStorageControllerCollection | Where-Object { $_.Id -like ($volume.InstanceID.Split(':') | Select-Object -Last 1) }
                    $volumeType = Get-vDocDellCimPropertyDescription -ResourceUri $params.ResourceUri -Property "RAIDTypes" -Value $volume.RAIDTypes
                    $status = Get-vDocDellCimPropertyDescription -ResourceUri $params.ResourceUri -Property "PrimaryStatus" -Value $volume.PrimaryStatus

                    $volumes = [vDocRacVolumes]@{
                        'Storage Controller' = $sController.Model
                        'Id'                 = $volume.InstanceID
                        'Name'               = $volume.Name
                        'Capacity (GB)'      = [math]::round($volume.SizeInBytes / 1GB, 2)
                        'Type'               = $volumeType
                        'Drives'             = $linkDrives.Count
                        'Slots'              = (@($slots) -join ',')
                        'Status'             = $status
                    } #END $volumes

                    $racVolumesCollection.Add($volumes)
                } #END foreach
            }
            else {
                Write-vDocMessage -Message "No Volume(s) found." -Type Verbose
            } #END if/else
        }
        else {
            Write-vDocMessage -Message "Get-CimInstance to $($params.ResourceUri) failed." -Type Verbose
        } #END if/else
    } #END PROCESS
} #END function Get-vDocCimRacStorageInventory

function Get-vDocCimRacMemoryInventory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $racIP,
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]$credential 
    )

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
    } #END BEGIN

    PROCESS {
        # Gather Physical Memory details
        $cimOpt = New-CimSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -Encoding Utf8 -UseSsl
        $params = @{
            Authentication = 'Basic'
            Credential     = $credential
            ComputerName   = $racIP
            Port           = '443'
            SessionOption  = $cimOpt
            ErrorAction    = 'Stop'
        } #END $params

        try {
            Write-vDocMessage -Message "Attempting New-CimSession to $($params.ComputerName)..." -Type Verbose
            $session = New-CimSession @params
        }
        catch {
            Write-vDocMessage -Message "CIM session failed, error:" -Type Verbose
            Write-vDocMessage -Message "$_.Exception.Message" -Type Verbose
        } #END try/catch

        $params = @{
            CimSession  = $session
            ResourceUri = 'http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_MemoryView'
            ErrorAction = 'Stop'
        } #END $params
        
        $webRequest = Invoke-vDocCimInstance $params
        if (-not ($webRequest.GetType().Name -match "Exception")) {
            $memoryCollection = $webRequest
            if ($memoryCollection.InstanceID.Count -gt 0) {
                Write-vDocMessage -Message "Gathering Memory details. Count found: $($memoryCollection.InstanceID.Count)" -Type Verbose
                foreach ($dimm in $memoryCollection) {
                    Write-vDocMessage -Message "Gathering Memory: $($dimm.DeviceDescription) details..." -Type Verbose
                    $dimmType = Get-vDocDellCimPropertyDescription -ResourceUri $params.ResourceUri -Property "MemoryType" -Value $dimm.MemoryType
                    $status = Get-vDocDellCimPropertyDescription -ResourceUri $params.ResourceUri -Property "PrimaryStatus" -Value $dimm.PrimaryStatus

                    $memDimms = [vDocMemory]@{
                        'Id'            = $dimm.InstanceID
                        'Slot'          = $dimm.DeviceDescription
                        'Name'          = $dimm.DeviceDescription
                        'Speed (Mhz)'   = $dimm.Speed
                        'Capacity (GB)' = [math]::round($dimm.Size / 1024)
                        'Manufacturer'  = $dimm.Manufacturer
                        'Type'          = $dimmType
                        'Rank'          = $dimm.Rank
                        'Part Number'   = $dimm.PartNumber
                        'Serial Number' = $dimm.SerialNumber
                        'Status'        = $status
                    } #END $memDimms
                             
                    $racMemoryCollection.Add($memDimms)
                } #END foreach
            }
            else {
                Write-vDocMessage -Message "No Memory found." -Type Verbose
            } #END if/else
        }
        else {
            Write-vDocMessage -Message "Get-CimInstance to $($params.ResourceUri) failed." -Type Verbose
        } #END if/else
    } #END PROCESS
} #END function Get-vDocCimRacMemoryInventory

function Get-vDocCimRacFirmwareInventory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $racIP,
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]$credential 
    )

    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
    } #END BEGIN

    PROCESS {
        # Gather firmware details
        $cimOpt = New-CimSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -Encoding Utf8 -UseSsl
        $params = @{
            Authentication = 'Basic'
            Credential     = $credential
            ComputerName   = $racIP
            Port           = '443'
            SessionOption  = $cimOpt
            ErrorAction    = 'Stop'
        } #END $params

        try {
            Write-vDocMessage -Message "Attempting New-CimSession to $($params.ComputerName)..." -Type Verbose
            $session = New-CimSession @params
        }
        catch {
            Write-vDocMessage -Message "CIM session failed, error:" -Type Verbose
            Write-vDocMessage -Message "$_.Exception.Message" -Type Verbose
        } #END try/catch

        $params = @{
            CimSession  = $session
            ResourceUri = 'http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_SoftwareIdentity'
            ErrorAction = 'Stop'
        } #END $params
        
        $webRequest = Invoke-vDocCimInstance $params
        if (-not ($webRequest.GetType().Name -match "Exception")) {
            $firmwareCollection = $webRequest
            if ($firmwareCollection.InstanceID.Count -gt 0) {
                Write-vDocMessage -Message "Gathering Firmware details. Count found: $($firmwareCollection.InstanceID.Count)" -Type Verbose
                foreach ($firmware in $firmwareCollection) {
                    Write-vDocMessage -Message "Gathering firmware: $($firmware.ElementName) details..." -Type Verbose
                    
                    #Filter Installed Firmwares only
                    if (-not ($firmware.Status -match "Installed")) {
                        Write-vDocMessage -Message "Skipping Firmware: $($firmware.ElementName)" -Type Verbose
                        continue
                    } #END if

                    $hardwarefw = [vDocFirmware]::new()
                    $hardwarefw.Component = $firmware.ElementName
                    $hardwarefw.'FW Version' = $firmware.VersionString
                    $racFirmwareCollection.Add($hardwarefw)
                } #END foreach
            }
            else {
                Write-vDocMessage -Message "No Firmware found." -Type Verbose
            } #END if/else
        }
        else {
            Write-vDocMessage -Message "Get-CimInstance to $($params.ResourceUri) failed." -Type Verbose
        } #END if/else
    } #END PROCESS
} #END function Get-vDocCimRacFirmwareInventory
function Export-vDocDataCollection {
    [CmdletBinding()]
    param (
        $ObjectCollection,
        $Description
    )
    
    BEGIN {
        $callStack = Get-PSCallStack
        Write-vDocMessage -Message "Executing function: $($callStack[0].Command)..." -Type Verbose
        Write-vDocMessage -Message "Invoked by: $($callStack[1].Command). Arguments: $($callStack[0].Arguments)" -Type Verbose
    } #END BEGIN

    PROCESS {
        switch ($true) {
            ($initParams.ExportCSV -eq $true) {
                $exportPath = -join ($initParams.exportFile, $Description, ".csv")
                $objectCollection | Export-Csv -Path $exportPath -NoTypeInformation
                Write-vDocMessage -Message "Data exported to $exportPath file" -Type Host
            }
            ($initParams.ExportExcel -eq $true) {
                $exportPath = -join ($initParams.exportFile, ".xlsx")
                $params = @{
                    path                    = $exportPath
                    InputObject             = $ObjectCollection
                    WorksheetName           = $Description
                    NoNumberConversion      = '*'
                    BoldTopRow              = $true
                    AutoFilter              = $true
                    FreezeTopRowFirstColumn = $true
                    PassThru                = $true
                } #END $params
                
                $excel = Export-Excel @params
                Set-ExcelRow -Worksheet $excel.Workbook.Worksheets[$Description] -Row 1 -WrapText
                Set-ExcelRange -Range $excel.Workbook.Worksheets[$Description].Cells -AutoSize
                Close-ExcelPackage $excel
                Write-vDocMessage -Message "Data exported to $exportPath file" -Type Host -Color
            }
            $PassThru { $returnCollection.Add($ObjectCollection) }
            default { $ObjectCollection | Format-List }
        } #END switch
    } #END PROCESS
} #END function Export-vDocDataCollection
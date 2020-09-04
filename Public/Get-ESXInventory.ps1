function Get-vDocESXInventory {
  <#
    .SYNOPSIS
      Get basic ESXi host information
    .DESCRIPTION
      Will get inventory information for a vSphere Cluster, Datacenter or individual ESXi host
      The following is gathered:
      Hostname, Management IP, RAC IP, ESXi Version information, and hardware information
    .NOTES
      File Name    : Get-vDocESXInventory
      Author       : Edgar Sanchez - @edmsanchez13
      Contributor  : Ariel Sanchez - @arielsanchezmor
      Version      : 0.1.0
    .Link
      https://github.com/vDocumentation/vDoc
    .OUTPUTS
      CSV file
      Excel file
    .PARAMETER VMhost
      The name(s) of the vSphere ESXi Host(s)
    .EXAMPLE
      Get-vDocESXInventory -VMhost devvm001.lab.local
    .PARAMETER Cluster
      The name(s) of the vSphere Cluster(s)
    .EXAMPLE
      Get-vDocESXInventory -Cluster production
    .PARAMETER Datacenter
      The name(s) of the vSphere Virtual Datacenter(s).
    .EXAMPLE
      Get-vDocESXInventory -Datacenter vDC001
    .PARAMETER QueryRAC
      Switch to Query RAC configuration on the ESXi host
    .EXAMPLE
      Get-vDocESXInventory -VMhost devvm001.lab.local -QueryRAC
    .PARAMETER Credential
      Switch to provide Credentials to be used with QueryRAC switch. It accepts a PSCredential object or you will be prompted for them
    .EXAMPLE
      Get-vDocESXInventory -VMhost devvm001.lab.local -Credential
    .PARAMETER ExportCSV
      Switch to export all data to CSV file. File is saved to the current user directory from where the script was executed. Use -folderPath parameter to specify a alternate location
    .EXAMPLE
      Get-vDocESXInventory -Cluster production -ExportCSV
    .PARAMETER ExportExcel
      Switch to export all data to Excel file (No need to have Excel Installed). This relies on ImportExcel Module to be installed.
      ImportExcel Module can be installed directly from the PowerShell Gallery. See https://github.com/dfinke/ImportExcel for more information
    .EXAMPLE
      Get-vDocESXInventory -Cluster production -ExportExcel
    .PARAMETER OutputFile
      Specify an output file path and or file name where the exported data should be saved.
    .EXAMPLE
      Get-vDocESXInventory -Cluster production -ExportExcel -OutputFile C:\temp\report.xlsx
    .PARAMETER PassThru
      Switch to return object to command line
    .EXAMPLE
      Get-vDocESXInventory -VMhost devvm001.lab.local -PassThru
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
    [switch]$QueryRAC,
    [ValidateNotNullOrEmpty()]
    [System.Management.Automation.Credential()]
    [System.Management.Automation.PSCredential]$Credential,
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
    $defaultFile = -join ("vDocInventory", $date)
    $skipCollection = [System.Collections.Generic.List[Object]]::new()
    $returnCollection = [System.Collections.Generic.List[Object]]::new()
    $hardwareCollection = [System.Collections.Generic.List[Object]]::new()
    $pciDeviceCollection = [System.Collections.Generic.List[Object]]::new()
    $racStorageControllerCollection = [System.Collections.Generic.List[Object]]::new()
    $racDrivesCollection = [System.Collections.Generic.List[Object]]::new()
    $racVolumesCollection = [System.Collections.Generic.List[Object]]::new()
    $racMemoryCollection = [System.Collections.Generic.List[Object]]::new()
    $racFirmwareCollection = [System.Collections.Generic.List[Object]]::new()
            
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
    $vHostList = $initParams.vHostList
    $thisOS = Get-vDocSessionOs
  } #END BEGIN
    
  PROCESS {
    foreach ($esxiHost in $vHostList) {
      # Skip if ESXi host is not in a connected or maintenance connection state     
      Get-vDocEsxConnectionState -vmHost $esxiHost
                
      Write-vDocMessage -Message "Gathering Hardware inventory from $esxiHost ..." -Type Host
      $vmHostView = Get-View -VIObject $esxiHost
      $esxCli = Get-EsxCli -VMHost $esxiHost -V2
    
      #Get ESXi Version and mgmt IP
      Write-vDocMessage -Message "Gathering Product, Version and Build..." -Type Verbose
      $mgmtIP = Get-VMHostNetworkAdapter -VMHost $esxiHost | Where-Object { $_.ManagementTrafficEnabled -eq 'True' } | Select-Object -ExpandProperty IP
      $esxiUpdateLevel = ($vmHostView.Config.Option | Where-Object { $_.Key -eq 'Misc.HostAgentUpdateLevel' }).Value 
      if ($esxiUpdateLevel) {
        $esxiVersion = -join ($esxiHost.Version, " U", $esxiUpdateLevel)
      }
      else {
        $esxiVersion = $esxiHost.Version
      } #END if/else
    
      # Instantiate Inventory Class, and call methods based on Session OS
      $Inventory = [vDocInventory]::new()
                
      # Get Hardware details
      Write-vDocMessage -Message "Gathering VMHost Hardware..." -Type Verbose
      $params = @{
        vmHost     = $esxiHost
        vmHostView = $vmHostView
        esxCli     = $esxCli
        OS         = $thisOS
      } #END $params
      Get-vDocVMHostHardware @params
               
      # Get BMC details
      Get-vDocEsxRac @params
      $hardwareCollection.Add($Inventory)
    
      # Get PCI Devices list
      Write-vDocMessage -Message "Gathering PCI Device(s) Inventory..." -Type Verbose
      Get-vDocPciDevices -vmHost $esxiHost -esxCli $esxCli
    
      # Query RAC. Supports Dell Hardware only for now
      if ($QueryRAC) {
        if ($Inventory.'RAC IP' -and ($Inventory.Make -match 'Dell')) {
          $params = @{
            racIP      = $Inventory.'RAC IP'
            credential = $initParams.racCredentials
            OS         = $thisOS
          } #END $params
          $racConnectMethod = Get-vDocRacConnectMethod @params
        }
        else {
          if (-not $Inventory.'RAC IP') {
            Write-vDocMessage -Message "Failed to get RAC IP. Skipping..." -Type Warning
          }
          else {
            Write-vDocMessage -Message "QueryRAC supports only Dell Hardware at the moment. Skipping..." -Type Warning
          } #END if/else
        } #END if/else
      } #END if
    
      switch ($racConnectMethod) {
        'Redfish' {
          Write-vDocMessage -Message "Gathering RAC inventory using Redfish..." -Type Verbose
          Get-vDocRedFishRacStorageInventory @params
          Get-vDocRedFishRacMemoryInventory @params
          Get-vDocRedFishRacFirmwareInventory @params
        }
        'CIM' {
          Write-vDocMessage -Message "Gathering RAC inventory using CIM..." -Type Verbose
          Get-vDocCimRacStorageInventory @params
          Get-vDocCimRacMemoryInventory @params
          Get-vDocCimRacFirmwareInventory @params
        }
        'Failed' {
          Write-vDocMessage -Message "Skipping Host..." -Type Warning
        }
      } #END switch
    } #END foreach
  } #END PROGRESS
    
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
      ($hardwareCollection.Count -gt 0) {
        Write-vDocMessage -Message "Information gathered" -Type Verbose
        Write-vDocMessage -Message "`nESXi Hardware Inventory:" -Type Host -Color
        Export-vDocDataCollection -ObjectCollection $hardwareCollection -Description "Hardware_Inventory"
      }
      ($pciDeviceCollection.Count -gt 0) { 
        Write-vDocMessage -Message "`nESXi Hardware PCI Devices:" -Type Host -Color
        Export-vDocDataCollection -ObjectCollection $pciDeviceCollection -Description "Hardware_PciDevice" 
      }
      ($racStorageControllerCollection.Count -gt 0) { 
        Write-vDocMessage -Message "`nHost RAC Storage Controller(s):" -Type Host -Color
        Export-vDocDataCollection -ObjectCollection $racStorageControllerCollection -Description "RAC_Storage" 
      }
      ($racDrivesCollection.Count -gt 0) { 
        Write-vDocMessage -Message "`nHost RAC Physical Disk(s):" -Type Host -Color
        Export-vDocDataCollection -ObjectCollection $racDrivesCollection -Description "RAC_Disk" 
      }
      ($racVolumesCollection.Count -gt 0) { 
        Write-vDocMessage -Message "`nHost RAC Disk Volume(s):" -Type Host -Color
        Export-vDocDataCollection -ObjectCollection $racVolumesCollection -Description "RAC_Volume" 
      }
      ($racMemoryCollection.Count -gt 0) { 
        Write-vDocMessage -Message "`nHost RAC Memory Inventory:" -Type Host -Color
        Export-vDocDataCollection -ObjectCollection $racMemoryCollection -Description "RAC_Memory" 
      }
      ($racFirmwareCollection.Count -gt 0) { 
        Write-vDocMessage -Message "`nHost RAC Firmware Inventory:" -Type Host -Color
        Export-vDocDataCollection -ObjectCollection $racFirmwareCollection -Description "RAC_Firmware" 
      }
      $PassThru { $returnCollection }
      default { Write-vDocMessage -Message "No information gathered" -Type Verbose }
    } #END switch
  } #END END
} #END Get-vDocESXInventory
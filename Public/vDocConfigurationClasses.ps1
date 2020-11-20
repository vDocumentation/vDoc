class vDocConfiguration {
    [string]$Hostname = $esxiHost.Name
    [string]$Make = $esxiHost.Manufacturer
    [string]$Model = $esxiHost.Model
    [string]${CPU Model} = $esxiHost.ProcessorType -replace '\s+', ' '
    [string]${CPU Sockets} = $vmhostView.Hardware.CpuInfo.NumCpuPackages
    [string]${Cores Socket} = ($vmhostView.Hardware.CpuInfo.NumCpuCores / $vmhostView.Hardware.CpuInfo.NumCpuPackages)
    [string]${Total Cores} = $vmhostView.Hardware.CpuInfo.NumCpuCores
    [string]${Hyper-Threading} = $esxiHost.HyperthreadingActive
    [string]${Max EVC Mode} = $esxiHost.MaxEVCMode
    [string]$Product = $vmhostView.Config.Product.Name
    [string]$Version = $esxiVersion
    [string]$Build = $esxiHost.Build
    [string]${Install Type} = $installType
    [string]${Boot From} = $bootSource
    [string]${Device Model} = $bootVendor
    [string]${Boot Device} = $bootDisplayName
    [string]${Runtime Name} = $bootRuntime
    [string]${Device Path} = $bootPath
    [string]${Image Profile} = $imageProfileName
    [string]${Acceptance Level} = $imageProfileAcceptance
    [string]${Boot Time} = $BootTime
    [string]$Uptime = $upTime
    [string]${Install Date} = $installDate
    [string]${Upgrade Date} = $upgradeDate
    [string]${Last Patched} = $lastPatched
    [string]${License Version} = ($vmhostLM.AssignedLicense.Name | Select-Object -Unique)
    [string]${License Key} = ($vmhostLM.AssignedLicense.LicenseKey | Select-Object -Unique)
    [string]${Connection State} = $esxiHost.ConnectionState
    [string]$Standalone = $esxiHost.IsStandalone
    [string]$Cluster = $esxiHost.Parent.Name
    [string]${Virtual Datacenter} = $vmhostvDC
    [string]$vCenter = $vmhostView.CLient.ServiceUrl.Split('/')[2]
    [string]$DNS = (@($dnsAdress) -join ',')
    [string]$NTP = $ntpService.Label
    [string]${NTP Running} = $ntpService.Running
    [string]${NTP Startup Policy} = $ntpService.Policy
    [string]${NTP Client Enabled} = $ntpFWException.Enabled
    [string]${NTP Server} = (@($ntpServerList) -join ',')
    [string]$SSH = $sshService.Label
    [string]${SSH Running} = $sshService.Running
    [string]${SSH Startup Policy} = $sshService.Policy
    [string]${SSH TimeOut} = $ShellTimeOut
    [string]${SSH Server Enabled} = $sshServerFWException.Enabled
    [string]${ESXi Shell} = $esxiShellService.Label
    [string]${ESXi Shell Running} = $esxiShellService.Running
    [string]${ESXi Shell Startup Policy} = $esxiShellService.Policy
    [string]${ESXi Shell TimeOut} = $interactiveShellTimeOut
    [string]${Syslog Server} = (@($syslogList) -join ',')
    [string]${Syslog Client Enabled} = $syslogFWException.Enabled
    
    vDocConfiguration() {

    }
} #END class vDocConfiguration
 

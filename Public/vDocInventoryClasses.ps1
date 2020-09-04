class vDocInventory {
    [string]$Hostname = $esxiHost.Name
    [string]$Make = $null
    [string]$Model = $null  
    [string]${S/N} = $null
    [string]$UUID = $vmhostView.Hardware.SystemInfo.Uuid
    [string]$Product = $vmhostView.Config.Product.Name
    [string]$Version = $esxiVersion
    [string]$Build = $esxiHost.Build
    [string]${Management IP} = $mgmtIP
    [string]${RAC IP} = $null
    [string]${RAC MAC} = $null
    [string]${RAC Firmware} = $null
    [string]$BIOS = $null
    [string]${BIOS Release Date} = $null
    [string]${CPU Model} = $esxiHost.ProcessorType -replace '\s+', ' '
    [string]${CPU Sockets} = $null
    [string]${CPU Cores} = $null
    [string]${Speed (MHz)} = $null
    [string]${Memory (GB)} = $esxihost.MemoryTotalGB -as [int]
    [string]${Memory Slots Count} = $null
    [string]${Memory Slots Used} = $null
    [string]${Power Supplies} = $null
    [string]${NIC Count} = $null
    
    [void]GetPlatform([string]$vendor, [string]$productModel, [string]$serialNumber) {
        $this.Make = $vendor
        $this.Model = $productModel
        $this.'S/N' = $serialNumber
    } #END GetPlatform

    [void]GetRac([string]$IP, [string]$MAC, [string]$Firmware) {
        $this.'RAC IP' = $IP
        $this.'RAC MAC' = $MAC
        $this.'RAC Firmware' = $Firmware
    } #END GetPlatform

    [void]GetBios([string]$Version, [string]$ReleaseDate) {
        $this.BIOS = $Version
        $this.'BIOS Release Date' = $ReleaseDate
    } #END GetBios

    [void]GetCpu([string]$NumCpu, [string]$NumCores, [string]$speed) {
        $this.'CPU Sockets' = $NumCpu
        $this.'CPU Cores' = $NumCores
        $this.'Speed (MHz)' = $speed
    } #END GetCpu
} #END class vDocInventory
 
class vDocPciDevices {
    [string]$Hostname = $esxiHost.Name
    [string]${Slot Description} = $slotDescription
    [string]${Device Name} = $deviceName

    vDocPciDevices() {

    }
} #END class vDocPciDevices

class vDocRacStorageController {
    [string]$Hostname = $esxiHost.Name
    [string]$Id = $null
    [string]$Manufacturer = $null
    [string]$Model = $null
    [string]${Speed (Gbps)} = $null
    [string]$Firmware = $null
    [string]$Drives = $null
    [string]${Controller Protocol} = $null
    [string]${Device Protocol} = $null
    [string]$Status = $null

    vDocRacStorageController() {

    }

} #END class vDocRacStorageController

class vDocRacDrives {
    [string]$Hostname = $esxiHost.Name
    [string]${Storage Controller} = $null
    [string]$Id = $null
    [string]$Slot = $null
    [string]$Name = $null
    [string]${Capable Speed (Gbps)} = $null
    [string]${Capacity (GB)} = $null
    [string]$Manufacturer = $null
    [string]$Type = $null
    [string]$Model = $null
    [string]${Negotiated Speed (Gbps)} = $null
    [string]${Part Number} = $null
    [string]$Protocol = $null
    [string]$Firmware = $null
    [string]${Serial Number} = $null
    [string]${Failure Predicted} = $null
    [string]$Hotspare = $null
    [string]$Volume = $null 
    [string]${Speed (RPM)} = $null
    [string]$Status = $null

    vDocRacDrives() {

    }
} #END class vDocRacDrives

class vDocRacVolumes {
    [string]$Hostname = $esxiHost.Name
    [string]${Storage Controller} = $null
    [string]$Id = $null
    [string]$Name = $null
    [string]${Capacity (GB)} = $null
    [string]$Type = $null
    [string]$Drives = $null
    [string]$Slots = $null
    [string]$Status = $null

    vDocRacVolumes() {

    }
} #END class vDocRacVolumes

class vDocMemory {
    [string]$Hostname = $esxiHost.Name
    [string]$Id = $null
    [string]$Slot = $null
    [string]$Name = $null
    [string]${Speed (Mhz)} = $null
    [string]${Capacity (GB)} = $null
    [string]$Manufacturer = $null
    [string]$Type = $null
    [string]$Rank = $null
    [string]${Error Correction} = $null
    [string]${Part Number} = $null
    [string]${Serial Number} = $null
    [string]$Status = $null

    vDocMemory() {

    }
} #END class vDocMemory

class vDocFirmware {
    [string]$Hostname = $esxiHost.Name
    [string]$Make = $esxiHost.Manufacturer
    [string]$Model = $esxiHost.Model
    [string]$Component = $null
    [string]${FW Version} = $null

    vDocFirmware () {

    }
}
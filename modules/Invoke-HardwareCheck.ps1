function Invoke-HardwareCheck {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [hashtable]$Config,
        [switch]$LocalScan
    )

    $findings    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $hwInfo      = @{}

    $cimParams = @{ ErrorAction = 'Stop' }
    if (-not $LocalScan) {
        $cimParams['ComputerName'] = $ComputerName
        if ($Credential) { $cimParams['Credential'] = $Credential }
    }

    try {
        $cs      = Get-CimInstance -ClassName Win32_ComputerSystem   @cimParams
        $bios    = Get-CimInstance -ClassName Win32_BIOS              @cimParams
        $cpu     = Get-CimInstance -ClassName Win32_Processor         @cimParams | Select-Object -First 1
        $cpuAll  = @(Get-CimInstance -ClassName Win32_Processor       @cimParams)
        $mem     = Get-CimInstance -ClassName Win32_PhysicalMemory    @cimParams
        $baseboard = Get-CimInstance -ClassName Win32_BaseBoard       @cimParams

        $isVirtual   = ($cs.Manufacturer -match 'VMware|Microsoft|Hyper-V|Xen|QEMU|KVM|VirtualBox|Amazon EC2') -or
                       ($cs.Model        -match 'Virtual|VMware|HVM|KVM')
        $manufacturer = $cs.Manufacturer
        $model        = $cs.Model
        $totalRAMGB   = [math]::Round(($mem | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2)
        $ramSlots     = ($mem | Measure-Object).Count

        $biosDate     = $null
        if ($bios.ReleaseDate) {
            $biosDate = $bios.ReleaseDate
        }

        $cpuName       = $cpu.Name.Trim()
        $cpuCores      = ($cpuAll | Measure-Object -Property NumberOfCores -Sum).Sum
        $cpuLogical    = ($cpuAll | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        $cpuSocketCount = ($cpuAll | Measure-Object).Count
        $cpuSpeedMHz    = $cpu.MaxClockSpeed

        $hwInfo = @{
            Manufacturer   = $manufacturer
            Model          = $model
            IsVirtual      = $isVirtual
            SerialNumber   = $bios.SerialNumber
            BIOSVersion    = $bios.SMBIOSBIOSVersion
            BIOSDate       = $biosDate
            TotalRAMGB     = $totalRAMGB
            RAMSlots       = $ramSlots
            CPUName        = $cpuName
            CPUCores       = $cpuCores
            CPULogical     = $cpuLogical
            CPUSockets     = $cpuSocketCount
            CPUSpeedMHz    = $cpuSpeedMHz
            BoardManufacturer = $baseboard.Manufacturer
            BoardProduct   = $baseboard.Product
        }

        # ── Virtual vs Physical ────────────────────────────────────
        if ($isVirtual) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Hardware'
                Check          = 'Virtualization'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = "Server is running as a virtual machine ($manufacturer)"
                Details        = "Model: $model. Virtual machines have more flexible lifecycle management."
                Recommendation = 'Ensure hypervisor host hardware is within lifecycle. Track VM resource allocation.'
                Reference      = ''
            })
        }

        # ── BIOS / Firmware Age ────────────────────────────────────
        $ageWarnYears     = $Config.Thresholds.Hardware.AgeWarningYears
        $ageCritYears     = $Config.Thresholds.Hardware.AgeCriticalYears
        $ageEolYears      = $Config.Thresholds.Hardware.EndOfLifeYears

        if ($biosDate -and -not $isVirtual) {
            $biosAgeYears = [math]::Round(((Get-Date) - $biosDate).TotalDays / 365.25, 1)
            $hwInfo['AgeYears'] = $biosAgeYears

            if ($biosAgeYears -ge $ageEolYears) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Hardware'
                    Check          = 'Hardware Age'
                    Status         = 'FAIL'
                    Severity       = 'Critical'
                    Description    = "Hardware is $biosAgeYears years old  - past end of vendor service life"
                    Details        = "BIOS/firmware date: $($biosDate.ToString('yyyy-MM-dd')). Manufacturer: $manufacturer, Model: $model. Hardware older than $ageEolYears years typically has no vendor support, firmware updates, or certified spare parts."
                    Recommendation = "Immediately plan hardware replacement. No firmware patches = unmitigatable vulnerabilities. Consider Azure/AWS migration to eliminate physical hardware risk entirely."
                    Reference      = 'https://www.dell.com/support | https://support.hpe.com/lifecycle'
                })
            }
            elseif ($biosAgeYears -ge $ageCritYears) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Hardware'
                    Check          = 'Hardware Age'
                    Status         = 'FAIL'
                    Severity       = 'High'
                    Description    = "Hardware is $biosAgeYears years old  - approaching or at vendor end of service life"
                    Details        = "BIOS date: $($biosDate.ToString('yyyy-MM-dd')). $manufacturer $model. Vendor support typically ends at 5-7 years; parts and firmware updates become unavailable."
                    Recommendation = "Include this server in the next hardware refresh cycle. Identify replacement timeline within 12 months. Evaluate cloud migration as alternative."
                    Reference      = 'https://www.dell.com/support | https://support.hpe.com/lifecycle'
                })
            }
            elseif ($biosAgeYears -ge $ageWarnYears) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Hardware'
                    Check          = 'Hardware Age'
                    Status         = 'WARN'
                    Severity       = 'Medium'
                    Description    = "Hardware is $biosAgeYears years old  - within vendor warning period"
                    Details        = "BIOS date: $($biosDate.ToString('yyyy-MM-dd')). $manufacturer $model. Begin planning for replacement within 2 years."
                    Recommendation = 'Add to 3-year hardware refresh roadmap. Verify current warranty/support contract status with vendor.'
                    Reference      = 'https://www.dell.com/support | https://support.hpe.com/lifecycle'
                })
            }
            else {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Hardware'
                    Check          = 'Hardware Age'
                    Status         = 'PASS'
                    Severity       = 'Info'
                    Description    = "Hardware is $biosAgeYears years old  - within expected service life"
                    Details        = "$manufacturer $model. BIOS date: $($biosDate.ToString('yyyy-MM-dd'))."
                    Recommendation = 'Track warranty expiration. Maintain firmware update schedule.'
                    Reference      = ''
                })
            }
        }

        # ── RAM Adequacy ───────────────────────────────────────────
        if ($totalRAMGB -lt 8) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Hardware'
                Check          = 'Memory (RAM)'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = "Server has only $totalRAMGB GB RAM  - below recommended minimum"
                Details        = "$ramSlots memory module(s) installed. Minimum 16 GB recommended for modern server workloads."
                Recommendation = 'Upgrade RAM to minimum 16 GB for server roles. Check physical slots for expansion capacity.'
                Reference      = 'Microsoft minimum hardware requirements for Windows Server'
            })
        }
        elseif ($totalRAMGB -lt 16) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Hardware'
                Check          = 'Memory (RAM)'
                Status         = 'WARN'
                Severity       = 'Low'
                Description    = "$totalRAMGB GB RAM installed  - consider upgrading for server workloads"
                Details        = "$ramSlots memory module(s) installed."
                Recommendation = 'Evaluate RAM utilization. Upgrade to 32+ GB if running virtualization, databases, or multiple roles.'
                Reference      = ''
            })
        }
        else {
            $findings.Add([PSCustomObject]@{
                Category       = 'Hardware'
                Check          = 'Memory (RAM)'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = "$totalRAMGB GB RAM installed across $ramSlots module(s)"
                Details        = 'RAM capacity is adequate for server operations.'
                Recommendation = 'Monitor utilization. Plan expansion if consistently above 80% usage.'
                Reference      = ''
            })
        }

        # ── CPU Core Count ─────────────────────────────────────────
        if ($cpuCores -lt 4) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Hardware'
                Check          = 'CPU Capacity'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = "Only $cpuCores CPU core(s) available ($cpuName)"
                Details        = "$cpuSocketCount socket(s), $cpuLogical logical processors, $cpuSpeedMHz MHz"
                Recommendation = 'CPU is under-powered for enterprise server workloads. Plan hardware upgrade or migrate to cloud for on-demand scaling.'
                Reference      = ''
            })
        }
        else {
            $findings.Add([PSCustomObject]@{
                Category       = 'Hardware'
                Check          = 'CPU Capacity'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = "$cpuCores cores / $cpuLogical logical processors ($cpuName)"
                Details        = "$cpuSocketCount socket(s), $cpuSpeedMHz MHz."
                Recommendation = 'Monitor CPU utilization trends. Plan capacity if consistently above 75%.'
                Reference      = ''
            })
        }

    }
    catch {
        $findings.Add([PSCustomObject]@{
            Category       = 'Hardware'
            Check          = 'Hardware Data Collection'
            Status         = 'ERROR'
            Severity       = 'High'
            Description    = "Failed to collect hardware information from $ComputerName"
            Details        = $_.Exception.Message
            Recommendation = 'Verify WMI/CIM access and credentials.'
            Reference      = ''
        })
    }

    return [PSCustomObject]@{
        ModuleName   = 'HardwareCheck'
        HardwareInfo = $hwInfo
        Findings     = $findings
    }
}

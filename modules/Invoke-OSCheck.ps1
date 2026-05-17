function Invoke-OSCheck {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [hashtable]$Config,
        [switch]$LocalScan
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $osInfo    = @{}

    $cimParams = @{ ErrorAction = 'Stop' }
    if (-not $LocalScan) {
        $cimParams['ComputerName'] = $ComputerName
        if ($Credential) { $cimParams['Credential'] = $Credential }
    }

    try {
        $os      = Get-CimInstance -ClassName Win32_OperatingSystem @cimParams
        $cs      = Get-CimInstance -ClassName Win32_ComputerSystem  @cimParams
        # Win32_QuickFixEngineering is extremely slow — use WU COM object instead (instant)
        try {
            $wuSession   = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
            $hotfixCount = $wuSession.CreateUpdateSearcher().GetTotalHistoryCount()
        } catch {
            $hotfixCount = 0
        }

        $osCaption    = $os.Caption
        $osBuild      = $os.BuildNumber
        $osVersion    = $os.Version
        $installDate  = $os.InstallDate
        $lastBoot     = $os.LastBootUpTime
        $uptimeDays   = [math]::Round(((Get-Date) - $lastBoot).TotalDays, 1)

        $osInfo = @{
            Caption         = $osCaption
            Version         = $osVersion
            BuildNumber     = $osBuild
            InstallDate     = $installDate
            LastBootTime    = $lastBoot
            UptimeDays      = $uptimeDays
            TotalRAMGB      = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            HotfixCount     = $hotfixCount
        }

        # ── EOL Check ──────────────────────────────────────────────
        $eolDB      = $Config.WindowsServerEOL
        $today      = Get-Date
        $eolEntry   = $null
        $matchedKey = $null

        foreach ($key in $eolDB.Keys) {
            if ($osCaption -like "*$key*") {
                $eolEntry   = $eolDB[$key]
                $matchedKey = $key
                break
            }
        }

        if ($eolEntry) {
            $eolDate      = [datetime]::Parse($eolEntry.EOLDate)
            $extDate      = if ($eolEntry.ExtendedDate) { [datetime]::Parse($eolEntry.ExtendedDate) } else { $null }
            $effectiveEOL = if ($extDate) { $extDate } else { $eolDate }
            $daysToEOL    = ($effectiveEOL - $today).TotalDays

            if ($effectiveEOL -lt $today) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Operating System'
                    Check          = 'OS End of Life'
                    Status         = 'FAIL'
                    Severity       = 'Critical'
                    Description    = "$osCaption has reached End of Life"
                    Details        = "Extended support ended $($effectiveEOL.ToString('yyyy-MM-dd')). No security patches are being released."
                    Recommendation = "Immediately plan upgrade to $($eolEntry.Replacement). Every day without patches increases breach risk."
                    Reference      = 'https://learn.microsoft.com/en-us/lifecycle/'
                })
            }
            elseif ($daysToEOL -le 180) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Operating System'
                    Check          = 'OS Approaching End of Life'
                    Status         = 'WARN'
                    Severity       = 'High'
                    Description    = "$osCaption reaches End of Life in $([math]::Round($daysToEOL)) days ($($effectiveEOL.ToString('yyyy-MM-dd')))"
                    Details        = "Less than 6 months of support remaining."
                    Recommendation = "Begin upgrade planning to $($eolEntry.Replacement) immediately. Target completion before EOL date."
                    Reference      = 'https://learn.microsoft.com/en-us/lifecycle/'
                })
            }
            elseif ($daysToEOL -le 365) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Operating System'
                    Check          = 'OS Approaching End of Life'
                    Status         = 'WARN'
                    Severity       = 'Medium'
                    Description    = "$osCaption reaches End of Life in $([math]::Round($daysToEOL)) days ($($effectiveEOL.ToString('yyyy-MM-dd')))"
                    Details        = "Less than 12 months of support remaining."
                    Recommendation = "Plan and schedule upgrade to $($eolEntry.Replacement) within the next 6 months."
                    Reference      = 'https://learn.microsoft.com/en-us/lifecycle/'
                })
            }
            else {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Operating System'
                    Check          = 'OS Support Status'
                    Status         = 'PASS'
                    Severity       = 'Info'
                    Description    = "$osCaption is within support lifecycle"
                    Details        = "End of life: $($effectiveEOL.ToString('yyyy-MM-dd')) ($([math]::Round($daysToEOL)) days remaining)"
                    Recommendation = 'No action required. Monitor lifecycle dates annually.'
                    Reference      = 'https://learn.microsoft.com/en-us/lifecycle/'
                })
            }
        }
        else {
            $findings.Add([PSCustomObject]@{
                Category       = 'Operating System'
                Check          = 'OS Identification'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = "OS not found in EOL database: $osCaption"
                Details        = "Could not determine support lifecycle for this operating system."
                Recommendation = 'Manually verify support status at https://learn.microsoft.com/en-us/lifecycle/'
                Reference      = 'https://learn.microsoft.com/en-us/lifecycle/'
            })
        }

        # ── Uptime Check ───────────────────────────────────────────
        $rebootCritical = $Config.Thresholds.Uptime.RebootCriticalDays
        $rebootWarn     = $Config.Thresholds.Uptime.RebootRecommendedDays

        if ($uptimeDays -ge $rebootCritical) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Operating System'
                Check          = 'System Uptime'
                Status         = 'FAIL'
                Severity       = 'High'
                Description    = "Server has not been rebooted in $uptimeDays days"
                Details        = "Last boot: $($lastBoot.ToString('yyyy-MM-dd HH:mm')). Long uptimes delay critical patch application."
                Recommendation = 'Schedule a maintenance window to reboot and apply pending updates. Uptimes over 90 days indicate missed patching cycles.'
                Reference      = 'CIS Control 7: Continuous Vulnerability Management'
            })
        }
        elseif ($uptimeDays -ge $rebootWarn) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Operating System'
                Check          = 'System Uptime'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = "Server has been running for $uptimeDays days without reboot"
                Details        = "Last boot: $($lastBoot.ToString('yyyy-MM-dd HH:mm'))."
                Recommendation = 'Schedule a reboot to apply pending updates. Review patch management process.'
                Reference      = 'CIS Control 7: Continuous Vulnerability Management'
            })
        }
        else {
            $findings.Add([PSCustomObject]@{
                Category       = 'Operating System'
                Check          = 'System Uptime'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = "System uptime is $uptimeDays days"
                Details        = "Last boot: $($lastBoot.ToString('yyyy-MM-dd HH:mm'))."
                Recommendation = 'Maintain regular patching and reboot schedule.'
                Reference      = ''
            })
        }

        # ── Hotfix / Patch Check ───────────────────────────────────
        if ($hotfixCount -lt 10) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Operating System'
                Check          = 'Installed Hotfixes'
                Status         = 'WARN'
                Severity       = 'High'
                Description    = "Only $hotfixCount hotfixes detected via WMI"
                Details        = 'Very few patches detected. This may indicate Windows Update is not functioning or patches are long overdue.'
                Recommendation = 'Verify Windows Update service is running. Review update history in Windows Update settings or WSUS.'
                Reference      = 'NIST SP 800-53: SI-2 Flaw Remediation'
            })
        }
        else {
            $findings.Add([PSCustomObject]@{
                Category       = 'Operating System'
                Check          = 'Installed Hotfixes'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = "$hotfixCount hotfixes installed"
                Details        = 'Patch count appears healthy. Verify against WSUS/SCCM for pending updates.'
                Recommendation = 'Continue regular patch cycles. Validate against patch management system.'
                Reference      = ''
            })
        }

        # ── Install Date / OS Age ──────────────────────────────────
        $osAgeDays = ((Get-Date) - $installDate).TotalDays
        if ($osAgeDays -gt (365 * 5)) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Operating System'
                Check          = 'OS Installation Age'
                Status         = 'WARN'
                Severity       = 'Low'
                Description    = "OS was installed $([math]::Round($osAgeDays/365,1)) years ago ($($installDate.ToString('yyyy-MM-dd')))"
                Details        = 'Long-running OS installations may accumulate configuration drift and undetected issues.'
                Recommendation = 'Consider a clean OS rebuild during next hardware refresh. Validate current configuration against baseline.'
                Reference      = 'CIS Control 4: Secure Configuration'
            })
        }

    }
    catch {
        $findings.Add([PSCustomObject]@{
            Category       = 'Operating System'
            Check          = 'OS Data Collection'
            Status         = 'ERROR'
            Severity       = 'High'
            Description    = "Failed to collect OS information from $ComputerName"
            Details        = $_.Exception.Message
            Recommendation = 'Verify WMI/CIM access, firewall rules (port 135), and credentials.'
            Reference      = ''
        })
    }

    return [PSCustomObject]@{
        ModuleName = 'OSCheck'
        OSInfo     = $osInfo
        Findings   = $findings
    }
}

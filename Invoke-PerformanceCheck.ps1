function Invoke-PerformanceCheck {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [hashtable]$Config,
        [switch]$LocalScan
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $perfInfo = @{}

    $psParams = @{ ErrorAction = 'Stop' }
    if (-not $LocalScan) {
        $psParams['ComputerName'] = $ComputerName
        if ($Credential) { $psParams['Credential'] = $Credential }
    }

    try {
        $collectBlock = {

            $out = @{}

            # ── CPU Usage (snapshot) ───────────────────────────────
            try {
                $cpuLoad = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
                $out['CPULoadPct'] = [math]::Round($cpuLoad, 1)
            } catch {
                $out['CPULoadPct'] = $null
            }

            # ── Memory ────────────────────────────────────────────
            try {
                $os         = Get-CimInstance Win32_OperatingSystem
                $totalRAMGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
                $freeRAMGB  = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
                $usedRAMGB  = [math]::Round($totalRAMGB - $freeRAMGB, 2)
                $ramPct     = if ($totalRAMGB -gt 0) { [math]::Round(($usedRAMGB / $totalRAMGB) * 100, 1) } else { 0 }
                $out['TotalRAMGB']  = $totalRAMGB
                $out['FreeRAMGB']   = $freeRAMGB
                $out['UsedRAMGB']   = $usedRAMGB
                $out['RAMUsedPct']  = $ramPct
            } catch {
                $out['RAMError'] = $_.Exception.Message
            }

            # ── Page File ─────────────────────────────────────────
            try {
                $pf = Get-CimInstance Win32_PageFileUsage
                if ($pf) {
                    $pfTotal   = ($pf | Measure-Object -Property AllocatedBaseSize -Sum).Sum
                    $pfUsed    = ($pf | Measure-Object -Property CurrentUsage -Sum).Sum
                    $pfPct     = if ($pfTotal -gt 0) { [math]::Round(($pfUsed / $pfTotal) * 100, 1) } else { 0 }
                    $out['PageFileTotalMB'] = $pfTotal
                    $out['PageFileUsedMB']  = $pfUsed
                    $out['PageFileUsedPct'] = $pfPct
                }
            } catch {}

            # ── Top CPU Processes ──────────────────────────────────
            try {
                $topProcs = Get-Process -ErrorAction SilentlyContinue |
                    Sort-Object CPU -Descending |
                    Select-Object -First 5 |
                    ForEach-Object { "$($_.ProcessName) (CPU: $([math]::Round($_.CPU,1))s)" }
                $out['TopCPUProcesses'] = $topProcs
            } catch {}

            # ── Top Memory Processes ───────────────────────────────
            try {
                $topMemProcs = Get-Process -ErrorAction SilentlyContinue |
                    Sort-Object WorkingSet64 -Descending |
                    Select-Object -First 5 |
                    ForEach-Object { "$($_.ProcessName) ($([math]::Round($_.WorkingSet64/1MB,0)) MB)" }
                $out['TopMemProcesses'] = $topMemProcs
            } catch {}

            # ── Services: Stopped Critical Services ───────────────
            try {
                $criticalServices = @('Eventlog', 'W32Time', 'Winmgmt', 'WinRM', 'BFE', 'mpssvc')
                $stoppedCritical  = @()
                foreach ($svcName in $criticalServices) {
                    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                    if ($svc -and $svc.Status -ne 'Running') {
                        $stoppedCritical += "$svcName ($($svc.Status))"
                    }
                }
                $out['StoppedCriticalServices'] = $stoppedCritical
            } catch {}

            # ── Pending Reboot Check ───────────────────────────────
            try {
                $pendingReboot = $false
                $cbsKey  = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction SilentlyContinue
                $wuKey   = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue
                $pfKey   = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
                if ($cbsKey -or $wuKey -or $pfKey.PendingFileRenameOperations) { $pendingReboot = $true }
                $out['PendingReboot'] = $pendingReboot
            } catch {}

            # ── NTP / Time Synchronization ─────────────────────────
            try {
                $w32tmOut   = w32tm /query /status 2>$null
                $srcLine    = $w32tmOut | Where-Object { $_ -match '^Source\s*:' }        | Select-Object -First 1
                $offsetLine = $w32tmOut | Where-Object { $_ -match 'Phase Offset\s*:' }   | Select-Object -First 1
                $ntpSource  = if ($srcLine)    { ($srcLine    -split ':',2)[1].Trim() } else { $null }
                $ntpOffset  = $null
                if ($offsetLine -match '([+-]?\d+\.?\d*)s') {
                    $ntpOffset = [math]::Abs([double]$matches[1])
                }
                $out['NTPSource']        = $ntpSource
                $out['NTPOffsetSeconds'] = $ntpOffset
                $out['NTPSyncBroken']    = ($ntpSource -and ($ntpSource -match 'Local CMOS|Free-running|VM IC'))
            } catch {
                $out['NTPSource'] = $null
            }

            # ── Event Log Errors (last 24h) ────────────────────────
            # Capped at 500 events per log — Get-EventLog with no cap scans
            # the entire log and hangs on busy DCs with thousands of entries
            try {
                $since       = (Get-Date).AddHours(-24)
                $criticalIds = @(41,6008,7022,7023,7024,7026,7034,7043)

                $sysEvts  = Get-WinEvent -FilterHashtable @{ LogName='System';      Level=2; StartTime=$since } -MaxEvents 500 -ErrorAction SilentlyContinue
                $appEvts  = Get-WinEvent -FilterHashtable @{ LogName='Application'; Level=2; StartTime=$since } -MaxEvents 500 -ErrorAction SilentlyContinue

                $out['SystemErrors24h']    = if ($sysEvts) { $sysEvts.Count } else { 0 }
                $out['AppErrors24h']       = if ($appEvts) { $appEvts.Count } else { 0 }
                $out['CriticalEventCount'] = if ($sysEvts) { ($sysEvts | Where-Object { $_.Id -in $criticalIds } | Measure-Object).Count } else { 0 }
            } catch {
                $out['SystemErrors24h']    = 0
                $out['AppErrors24h']       = 0
                $out['CriticalEventCount'] = 0
                $out['EventLogError']      = $_.Exception.Message
            }

            $out
        }
        $results = if ($LocalScan) { & $collectBlock } else { Invoke-Command @psParams -ScriptBlock $collectBlock }

        $perfInfo = $results

        # ── CPU Findings ────────────────────────────────────────────
        $cpuWarn = $Config.Thresholds.CPU.UsageWarningPct
        $cpuCrit = $Config.Thresholds.CPU.UsageCriticalPct

        if ($null -ne $results.CPULoadPct) {
            if ($results.CPULoadPct -ge $cpuCrit) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Performance'
                    Check          = 'CPU Utilization'
                    Status         = 'FAIL'
                    Severity       = 'Critical'
                    Description    = "CPU utilization is $($results.CPULoadPct)%  - critically high"
                    Details        = "Top processes: $(($results.TopCPUProcesses) -join ', ')"
                    Recommendation = 'Identify runaway processes. Consider server role redistribution, scale-up (more cores), or migrate workload to cloud (Azure scale sets, AWS Auto Scaling).'
                    Reference      = ''
                })
            }
            elseif ($results.CPULoadPct -ge $cpuWarn) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Performance'
                    Check          = 'CPU Utilization'
                    Status         = 'WARN'
                    Severity       = 'Medium'
                    Description    = "CPU utilization is $($results.CPULoadPct)%  - elevated"
                    Details        = "Top processes: $(($results.TopCPUProcesses) -join ', ')"
                    Recommendation = 'Monitor CPU trend. Consider adding vCPUs (if virtual) or hardware upgrade. Review scheduled tasks that may cause spikes.'
                    Reference      = ''
                })
            }
            else {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Performance'
                    Check          = 'CPU Utilization'
                    Status         = 'PASS'
                    Severity       = 'Info'
                    Description    = "CPU utilization: $($results.CPULoadPct)%"
                    Details        = "Top processes: $(($results.TopCPUProcesses) -join ', ')"
                    Recommendation = 'Continue monitoring. Set alerts at 80% sustained utilization.'
                    Reference      = ''
                })
            }
        }

        # ── RAM Findings ─────────────────────────────────────────
        $memWarn = $Config.Thresholds.Memory.UsageWarningPct
        $memCrit = $Config.Thresholds.Memory.UsageCriticalPct

        if ($null -ne $results.RAMUsedPct) {
            if ($results.RAMUsedPct -ge $memCrit) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Performance'
                    Check          = 'Memory Utilization'
                    Status         = 'FAIL'
                    Severity       = 'Critical'
                    Description    = "RAM utilization is $($results.RAMUsedPct)% ($($results.UsedRAMGB) GB used of $($results.TotalRAMGB) GB)"
                    Details        = "Only $($results.FreeRAMGB) GB free. Top memory processes: $(($results.TopMemProcesses) -join ', ')"
                    Recommendation = 'Immediate action: identify memory-heavy processes, tune application memory limits, add physical RAM, or migrate memory-intensive workloads to cloud instances with higher memory tiers.'
                    Reference      = ''
                })
            }
            elseif ($results.RAMUsedPct -ge $memWarn) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Performance'
                    Check          = 'Memory Utilization'
                    Status         = 'WARN'
                    Severity       = 'Medium'
                    Description    = "RAM utilization is $($results.RAMUsedPct)% ($($results.FreeRAMGB) GB free)"
                    Details        = "Top memory processes: $(($results.TopMemProcesses) -join ', ')"
                    Recommendation = 'Plan RAM upgrade. Monitor page file usage  - heavy paging dramatically degrades performance.'
                    Reference      = ''
                })
            }
            else {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Performance'
                    Check          = 'Memory Utilization'
                    Status         = 'PASS'
                    Severity       = 'Info'
                    Description    = "Memory utilization: $($results.RAMUsedPct)%  - $($results.FreeRAMGB) GB free of $($results.TotalRAMGB) GB"
                    Details        = 'Memory is within acceptable range.'
                    Recommendation = 'Set alerting at 85% utilization sustained over 1 hour.'
                    Reference      = ''
                })
            }
        }

        # ── Page File ─────────────────────────────────────────────
        if ($results.PageFileUsedPct -gt 50) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Performance'
                Check          = 'Page File Usage'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = "Page file is $($results.PageFileUsedPct)% utilized ($($results.PageFileUsedMB) MB of $($results.PageFileTotalMB) MB)"
                Details        = 'High page file usage indicates insufficient physical RAM. Disk paging causes severe performance degradation.'
                Recommendation = 'Increase physical RAM. Review if page file is properly sized (1.5x RAM minimum). Migrate to cloud for elastic memory scaling.'
                Reference      = ''
            })
        }

        # ── Pending Reboot ────────────────────────────────────────
        if ($results.PendingReboot -eq $true) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Performance'
                Check          = 'Pending Reboot'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = 'Server has a PENDING REBOOT  - updates or changes are not fully applied'
                Details        = 'A pending reboot means patches or configuration changes are staged but not complete. The server is not in its intended final state.'
                Recommendation = 'Schedule a maintenance window to reboot this server. Coordinate with stakeholders for service impact. Validate services restart cleanly after reboot.'
                Reference      = ''
            })
        }

        # ── Stopped Critical Services ─────────────────────────────
        $stoppedSvcs = $results.StoppedCriticalServices
        if ($stoppedSvcs -and $stoppedSvcs.Count -gt 0) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Performance'
                Check          = 'Critical Services'
                Status         = 'FAIL'
                Severity       = 'High'
                Description    = "$($stoppedSvcs.Count) critical system service(s) are not running: $($stoppedSvcs -join ', ')"
                Details        = 'Stopped critical services can indicate system instability, failed updates, or tampering.'
                Recommendation = 'Investigate why these services are stopped. Restart if appropriate. Review system and application event logs for errors.'
                Reference      = ''
            })
        }

        # ── Event Log Errors ─────────────────────────────────────
        if ($results.CriticalEventCount -gt 0) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Performance'
                Check          = 'Critical System Events (24h)'
                Status         = 'WARN'
                Severity       = 'High'
                Description    = "$($results.CriticalEventCount) critical system event(s) in the last 24 hours"
                Details        = "System errors: $($results.SystemErrors24h). Application errors: $($results.AppErrors24h). Critical event IDs (41=kernel power, 6008=unexpected shutdown) detected."
                Recommendation = 'Review System event log for IDs 41, 6008 (unexpected shutdown/crash), 7034 (service crash). Check hardware health. Review application logs for recurring failures.'
                Reference      = ''
            })
        }
        elseif ($results.SystemErrors24h -gt 50 -or $results.AppErrors24h -gt 100) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Performance'
                Check          = 'Event Log Errors (24h)'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = "High event log error rate: $($results.SystemErrors24h) system errors, $($results.AppErrors24h) application errors in 24 hours"
                Details        = 'Elevated error rates indicate underlying instability or misconfiguration.'
                Recommendation = 'Investigate top error sources in Event Viewer. Filter by error level and source to identify recurring issues.'
                Reference      = ''
            })
        }

        # ── NTP Time Sync ─────────────────────────────────────────
        if ($results.NTPSource) {
            if ($results.NTPSyncBroken -eq $true) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Performance'
                    Check          = 'NTP Time Synchronization'
                    Status         = 'FAIL'
                    Severity       = 'High'
                    Description    = "Time synchronization BROKEN — server is using local clock ($($results.NTPSource))"
                    Details        = 'A server not synchronized to an external time source will drift from domain time. Kerberos authentication breaks when clock skew exceeds 5 minutes, causing ALL domain logins to fail.'
                    Recommendation = "Fix NTP: w32tm /config /manualpeerlist:'time.windows.com' /syncfromflags:manual /reliable:YES /update; Restart-Service W32Time; w32tm /resync /force"
                    Reference      = 'Microsoft KB816042 | CIS Control 8.4'
                })
            }
            elseif ($null -ne $results.NTPOffsetSeconds -and $results.NTPOffsetSeconds -gt 60) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Performance'
                    Check          = 'NTP Time Synchronization'
                    Status         = 'WARN'
                    Severity       = 'Medium'
                    Description    = "Time offset is $([math]::Round($results.NTPOffsetSeconds,1))s — elevated (Kerberos limit is 300s)"
                    Details        = "NTP source: $($results.NTPSource). Current drift is elevated. Kerberos auth will break if offset reaches 300 seconds (5 minutes)."
                    Recommendation = 'Force resync: w32tm /resync /force. Investigate why drift is elevated. Verify NTP source reachability and Windows Time service health.'
                    Reference      = ''
                })
            }
            else {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Performance'
                    Check          = 'NTP Time Synchronization'
                    Status         = 'PASS'
                    Severity       = 'Info'
                    Description    = "Time synchronization healthy — source: $($results.NTPSource)"
                    Details        = if ($null -ne $results.NTPOffsetSeconds) { "Current offset: $([math]::Round($results.NTPOffsetSeconds,4))s" } else { 'Time sync is active.' }
                    Recommendation = 'No action required. Ensure NTP source remains authoritative and reachable.'
                    Reference      = ''
                })
            }
        }

    }
    catch {
        $findings.Add([PSCustomObject]@{
            Category       = 'Performance'
            Check          = 'Performance Data Collection'
            Status         = 'ERROR'
            Severity       = 'High'
            Description    = "Failed to collect performance data from $ComputerName"
            Details        = $_.Exception.Message
            Recommendation = 'Verify PowerShell remoting is enabled and credentials are correct.'
            Reference      = ''
        })
    }

    return [PSCustomObject]@{
        ModuleName = 'PerformanceCheck'
        PerfInfo   = $perfInfo
        Findings   = $findings
    }
}

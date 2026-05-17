function Invoke-StorageCheck {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [hashtable]$Config,
        [switch]$LocalScan
    )

    $findings    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $storageInfo = @{ Disks = @(); Shares = @() }

    $cimParams = @{ ErrorAction = 'Stop' }
    if (-not $LocalScan) {
        $cimParams['ComputerName'] = $ComputerName
        if ($Credential) { $cimParams['Credential'] = $Credential }
    }

    $warnPct  = $Config.Thresholds.Storage.DiskUsageWarningPct
    $highPct  = $Config.Thresholds.Storage.DiskUsageHighPct
    $critPct  = $Config.Thresholds.Storage.DiskUsageCriticalPct
    $freeWarnGB = $Config.Thresholds.Storage.FreeDiskWarningGB
    $freeCritGB = $Config.Thresholds.Storage.FreeDiskCriticalGB

    # ── Local Disk Assessment ──────────────────────────────────────
    try {
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" @cimParams

        if (-not $disks) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Storage'
                Check          = 'Disk Discovery'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = 'No local fixed disks found via WMI'
                Details        = 'Could not enumerate local drives. May indicate a SAN/NAS-only configuration or WMI issue.'
                Recommendation = 'Verify disk configuration and WMI availability.'
                Reference      = ''
            })
        }

        foreach ($disk in $disks) {
            $totalGB = [math]::Round($disk.Size / 1GB, 2)
            $freeGB  = [math]::Round($disk.FreeSpace / 1GB, 2)
            $usedGB  = [math]::Round($totalGB - $freeGB, 2)
            $usedPct = if ($totalGB -gt 0) { [math]::Round(($usedGB / $totalGB) * 100, 1) } else { 0 }

            $diskEntry = @{
                Drive    = $disk.DeviceID
                Label    = $disk.VolumeName
                TotalGB  = $totalGB
                UsedGB   = $usedGB
                FreeGB   = $freeGB
                UsedPct  = $usedPct
            }
            $storageInfo.Disks += $diskEntry

            $driveLetter = $disk.DeviceID
            $label       = if ($disk.VolumeName) { " ($($disk.VolumeName))" } else { '' }

            if ($usedPct -ge $critPct -or $freeGB -le $freeCritGB) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Storage'
                    Check          = "Disk Usage: $driveLetter"
                    Status         = 'FAIL'
                    Severity       = 'Critical'
                    Description    = "Drive $driveLetter$label is $usedPct% full  - CRITICALLY LOW space ($freeGB GB free of $totalGB GB)"
                    Details        = "Used: $usedGB GB / $totalGB GB. Free: $freeGB GB. System instability, application failures, and data loss can occur when disks are full."
                    Recommendation = "Immediately free disk space. Identify and remove: old log files, temp files, shadow copies, IIS logs. Consider adding storage, expanding partition, or archiving to cloud storage (Azure Blob, AWS S3)."
                    Reference      = 'NIST SP 800-53: CP-10 System Recovery and Reconstitution'
                })
            }
            elseif ($usedPct -ge $highPct -or $freeGB -le $freeWarnGB) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Storage'
                    Check          = "Disk Usage: $driveLetter"
                    Status         = 'FAIL'
                    Severity       = 'High'
                    Description    = "Drive $driveLetter$label is $usedPct% full ($freeGB GB remaining)"
                    Details        = "Used: $usedGB GB / $totalGB GB. Approaching critical threshold."
                    Recommendation = "Clean up disk space now. Schedule storage expansion. Review log rotation policies and archiving strategy."
                    Reference      = ''
                })
            }
            elseif ($usedPct -ge $warnPct) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Storage'
                    Check          = "Disk Usage: $driveLetter"
                    Status         = 'WARN'
                    Severity       = 'Medium'
                    Description    = "Drive $driveLetter$label is $usedPct% full ($freeGB GB remaining)"
                    Details        = "Used: $usedGB GB / $totalGB GB. Monitor closely."
                    Recommendation = "Monitor disk growth trend. Implement disk space alerting at 80% and 90% thresholds."
                    Reference      = ''
                })
            }
            else {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Storage'
                    Check          = "Disk Usage: $driveLetter"
                    Status         = 'PASS'
                    Severity       = 'Info'
                    Description    = "Drive $driveLetter$label  - $usedPct% used ($freeGB GB free of $totalGB GB)"
                    Details        = 'Disk space is within acceptable range.'
                    Recommendation = 'Continue monitoring. Set alerts at 75% and 90% usage.'
                    Reference      = ''
                })
            }
        }
    }
    catch {
        $findings.Add([PSCustomObject]@{
            Category       = 'Storage'
            Check          = 'Local Disk Assessment'
            Status         = 'ERROR'
            Severity       = 'High'
            Description    = "Failed to enumerate local disks on $ComputerName"
            Details        = $_.Exception.Message
            Recommendation = 'Verify WMI/CIM access and credentials.'
            Reference      = ''
        })
    }

    # ── Network File Shares ────────────────────────────────────────
    try {
        $psParams = @{ ErrorAction = 'Stop' }
        if (-not $LocalScan) {
            $psParams['ComputerName'] = $ComputerName
            if ($Credential) { $psParams['Credential'] = $Credential }
        }

        $shares = Invoke-Command @psParams -ScriptBlock {
            Get-SmbShare -ErrorAction SilentlyContinue |
            Where-Object { $_.ShareType -eq 'FileSystemDirectory' -and $_.Name -notmatch '^\w\$$' -and $_.Name -ne 'IPC$' } |
            ForEach-Object {
                $share = $_
                $quota = $null
                try {
                    $quota = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                } catch {}

                $folderInfo = $null
                try {
                    $folderInfo = Get-Item $share.Path -ErrorAction SilentlyContinue
                } catch {}

                [PSCustomObject]@{
                    Name        = $share.Name
                    Path        = $share.Path
                    Description = $share.Description
                    ShareType   = $share.ShareType.ToString()
                }
            }
        }

        $shareCritPct = $Config.Thresholds.Storage.ShareUsageCriticalPct
        $shareWarnPct = $Config.Thresholds.Storage.ShareUsageWarningPct

        $shareCount = ($shares | Measure-Object).Count
        $storageInfo.ShareCount = $shareCount

        if ($shares) {
            foreach ($share in $shares) {
                $storageInfo.Shares += @{
                    Name        = $share.Name
                    Path        = $share.Path
                    Description = $share.Description
                }
            }

            $findings.Add([PSCustomObject]@{
                Category       = 'Storage'
                Check          = 'Network File Shares'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = "$shareCount file share(s) found on this server"
                Details        = ($shares | ForEach-Object { "$($_.Name) -> $($_.Path)" }) -join '; '
                Recommendation = 'Review share permissions regularly. Remove stale shares. Consider DFS namespace for redundancy.'
                Reference      = 'CIS Control 3: Data Protection'
            })

            # Check for shares on critically full disks
            foreach ($share in $shares) {
                if ($share.Path -match '^([A-Z]):') {
                    $shareDrive = "$($matches[1]):"
                    $matchDisk  = $storageInfo.Disks | Where-Object { $_.Drive -eq $shareDrive }
                    if ($matchDisk -and $matchDisk.UsedPct -ge $shareCritPct) {
                        $findings.Add([PSCustomObject]@{
                            Category       = 'Storage'
                            Check          = "File Share Full: $($share.Name)"
                            Status         = 'FAIL'
                            Severity       = 'Critical'
                            Description    = "Share '\\$ComputerName\$($share.Name)' resides on critically full drive $shareDrive ($($matchDisk.UsedPct)% used)"
                            Details        = "Path: $($share.Path). Users writing to this share may experience failures immediately."
                            Recommendation = "Urgently expand storage or move share to a less full volume. Implement FSRM quotas to prevent runaway growth."
                            Reference      = ''
                        })
                    }
                    elseif ($matchDisk -and $matchDisk.UsedPct -ge $shareWarnPct) {
                        $findings.Add([PSCustomObject]@{
                            Category       = 'Storage'
                            Check          = "File Share Warning: $($share.Name)"
                            Status         = 'WARN'
                            Severity       = 'High'
                            Description    = "Share '\\$ComputerName\$($share.Name)' resides on drive $shareDrive which is $($matchDisk.UsedPct)% full"
                            Details        = "Path: $($share.Path). Monitor closely and plan storage expansion."
                            Recommendation = "Implement FSRM quotas. Set disk space alert. Plan storage expansion within 30 days."
                            Reference      = ''
                        })
                    }
                }
            }
        }
        else {
            $storageInfo.ShareCount = 0
        }
    }
    catch {
        $findings.Add([PSCustomObject]@{
            Category       = 'Storage'
            Check          = 'Network Share Assessment'
            Status         = 'WARN'
            Severity       = 'Low'
            Description    = "Could not enumerate network shares on $ComputerName"
            Details        = $_.Exception.Message
            Recommendation = 'Verify PowerShell remoting is enabled and credentials are correct.'
            Reference      = ''
        })
    }

    # ── Shadow Copy / VSS ─────────────────────────────────────────
    try {
        $vss = Get-CimInstance -ClassName Win32_ShadowCopy @cimParams -ErrorAction SilentlyContinue
        $vssCount = ($vss | Measure-Object).Count

        if ($vssCount -eq 0) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Storage'
                Check          = 'Volume Shadow Copies (VSS)'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = 'No Volume Shadow Copies (VSS) found'
                Details        = 'VSS provides point-in-time recovery of files. Absence indicates no local recovery capability.'
                Recommendation = 'Enable and configure VSS on all data volumes. Ensure backup solution covers this server. Consider Azure Backup or AWS Backup.'
                Reference      = 'NIST SP 800-53: CP-9 System Backup'
            })
        }
        else {
            $findings.Add([PSCustomObject]@{
                Category       = 'Storage'
                Check          = 'Volume Shadow Copies (VSS)'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = "$vssCount shadow copy snapshot(s) found"
                Details        = 'VSS is active providing local point-in-time recovery capability.'
                Recommendation = 'Verify shadow copies do not consume excessive disk space. Supplement with off-site/cloud backup.'
                Reference      = ''
            })
        }
    }
    catch { }

    return [PSCustomObject]@{
        ModuleName  = 'StorageCheck'
        StorageInfo = $storageInfo
        Findings    = $findings
    }
}

function Invoke-HyperVCheck {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [hashtable]$Config,
        [switch]$LocalScan
    )

    $findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $hvInfo    = @{ IsHyperVHost = $false }

    $psParams  = @{ ErrorAction = 'Stop' }
    if (-not $LocalScan) {
        $psParams['ComputerName'] = $ComputerName
        if ($Credential) { $psParams['Credential'] = $Credential }
    }

    # ── Detect Hyper-V Role ────────────────────────────────────────
    try {
        $hvDetect = Invoke-Command @psParams -ScriptBlock {
            $out = @{ IsHyperVHost = $false }

            # Method 1: Windows Feature (Server with RSAT)
            try {
                $feat = Get-WindowsFeature -Name Hyper-V -ErrorAction SilentlyContinue
                if ($feat -and $feat.InstallState -eq 'Installed') {
                    $out.IsHyperVHost    = $true
                    $out.HyperVInstalled = $true
                    $out.DetectionMethod = 'WindowsFeature'
                }
            } catch {}

            # Method 2: WMI namespace check (works when RSAT not available)
            if (-not $out.IsHyperVHost) {
                try {
                    $vmms = Get-Service -Name 'vmms' -ErrorAction SilentlyContinue
                    if ($vmms -and $vmms.Status -eq 'Running') {
                        $out.IsHyperVHost    = $true
                        $out.HyperVInstalled = $true
                        $out.DetectionMethod = 'VMManagementService'
                    }
                } catch {}
            }

            # Method 3: CIM namespace
            if (-not $out.IsHyperVHost) {
                try {
                    $ns = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_VirtualSystemManagementService -ErrorAction SilentlyContinue
                    if ($ns) {
                        $out.IsHyperVHost    = $true
                        $out.HyperVInstalled = $true
                        $out.DetectionMethod = 'CIM_Namespace'
                    }
                } catch {}
            }

            $out
        }

        $hvInfo.IsHyperVHost = $hvDetect.IsHyperVHost

        if (-not $hvDetect.IsHyperVHost) {
            # Not a Hyper-V host — return early, no findings needed
            return [PSCustomObject]@{
                ModuleName = 'HyperVCheck'
                HVInfo     = $hvInfo
                Findings   = $findings
            }
        }
    }
    catch {
        $hvInfo.IsHyperVHost = $false
        return [PSCustomObject]@{
            ModuleName = 'HyperVCheck'
            HVInfo     = $hvInfo
            Findings   = $findings
        }
    }

    # ── Full Hyper-V Assessment ────────────────────────────────────
    try {
        $hvData = Invoke-Command @psParams -ScriptBlock {
            $out = @{
                VMList            = @()
                VirtualSwitches   = @()
                StorageLocations  = @()
                TotalVMCount      = 0
                RunningVMCount    = 0
                StoppedVMCount    = 0
                TotalVMRamGB      = 0
                TotalVMDiskGB     = 0
                Gen1VMCount       = 0
                Gen2VMCount       = 0
                VMsWithSnapshots  = 0
                VMsWithOldIntSvc  = 0
                HyperVVersion     = ''
                HostRAMGB         = 0
            }

            try {
                Import-Module Hyper-V -ErrorAction SilentlyContinue

                # Host RAM
                $hostOS = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
                $out.HostRAMGB = [math]::Round($hostOS.TotalVisibleMemorySize / 1MB, 1)

                # Hyper-V version from VMMS
                $vmms = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization' -ErrorAction SilentlyContinue
                if ($vmms) { $out.HyperVVersion = $vmms.GetValue('HypervisorVersion') }

                # Enumerate VMs
                $vms = Get-VM -ErrorAction SilentlyContinue
                $out.TotalVMCount   = ($vms | Measure-Object).Count
                $out.RunningVMCount = ($vms | Where-Object { $_.State -eq 'Running' } | Measure-Object).Count
                $out.StoppedVMCount = ($vms | Where-Object { $_.State -ne 'Running' } | Measure-Object).Count

                foreach ($vm in $vms) {
                    $ramGB      = [math]::Round($vm.MemoryAssigned / 1GB, 2)
                    $snapshots  = @(Get-VMSnapshot -VMName $vm.Name -ErrorAction SilentlyContinue)
                    $snapCount  = $snapshots.Count
                    $diskGB     = 0

                    # Get VHD info
                    $vhds = @()
                    try {
                        $vmDrives = Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction SilentlyContinue
                        foreach ($drive in $vmDrives) {
                            try {
                                $vhd = Get-VHD -Path $drive.Path -ErrorAction SilentlyContinue
                                if ($vhd) {
                                    $diskGB += [math]::Round($vhd.FileSize / 1GB, 2)
                                    $vhds += @{
                                        Path        = $drive.Path
                                        Type        = $vhd.VhdType.ToString()
                                        SizeGB      = [math]::Round($vhd.Size / 1GB, 1)
                                        FileSizeGB  = [math]::Round($vhd.FileSize / 1GB, 2)
                                        Fragmented  = ($vhd.FragmentationPercentage -gt 10)
                                    }
                                    # Track unique storage locations
                                    $folder = Split-Path $drive.Path -Parent
                                    if ($folder -notin $out.StorageLocations) {
                                        $out.StorageLocations += $folder
                                    }
                                }
                            } catch {}
                        }
                    } catch {}

                    # Integration Services version
                    $intSvcVersion = 'Unknown'
                    $intSvcOld     = $false
                    try {
                        $intSvc = Get-VMIntegrationService -VMName $vm.Name -ErrorAction SilentlyContinue
                        $heartbeat = $intSvc | Where-Object { $_.Name -eq 'Heartbeat' } | Select-Object -First 1
                        if ($heartbeat) {
                            $intSvcVersion = if ($heartbeat.SecondaryOperationalStatus) {
                                $heartbeat.SecondaryOperationalStatus.ToString()
                            } else { 'Installed' }
                        }
                        $notEnabled = $intSvc | Where-Object { $_.Enabled -eq $false -and $_.Name -ne 'Guest Service Interface' }
                        if ($notEnabled) { $intSvcOld = $true }
                    } catch {}

                    $uptimeDays = if ($vm.State -eq 'Running' -and $vm.Uptime) {
                        [math]::Round($vm.Uptime.TotalDays, 1)
                    } else { 0 }

                    $out.VMList += [PSCustomObject]@{
                        Name               = $vm.Name
                        State              = $vm.State.ToString()
                        Generation         = $vm.Generation
                        CPUCount           = $vm.ProcessorCount
                        RAMAssignedGB      = $ramGB
                        DynamicMemory      = $vm.DynamicMemoryEnabled
                        DiskGB             = $diskGB
                        SnapshotCount      = $snapCount
                        HasSnapshots       = ($snapCount -gt 0)
                        IntSvcVersion      = $intSvcVersion
                        IntSvcIssues       = $intSvcOld
                        UptimeDays         = $uptimeDays
                        VMVersion          = $vm.Version
                        VHDs               = $vhds
                    }

                    $out.TotalVMRamGB  += $ramGB
                    $out.TotalVMDiskGB += $diskGB
                    if ($vm.Generation -eq 1) { $out.Gen1VMCount++ }
                    if ($vm.Generation -eq 2) { $out.Gen2VMCount++ }
                    if ($snapCount -gt 0)     { $out.VMsWithSnapshots++ }
                    if ($intSvcOld)           { $out.VMsWithOldIntSvc++ }
                }

                # Virtual Switches
                $switches = Get-VMSwitch -ErrorAction SilentlyContinue
                $out.VirtualSwitches = $switches | ForEach-Object {
                    "$($_.Name) ($($_.SwitchType))"
                }
            }
            catch {
                $out['EnumerationError'] = $_.Exception.Message
            }

            $out
        }

        # Merge into hvInfo
        foreach ($key in $hvData.Keys) {
            $hvInfo[$key] = $hvData[$key]
        }
        $hvInfo.IsHyperVHost = $true

        $vmCount   = $hvInfo.TotalVMCount
        $hostRAM   = $hvInfo.HostRAMGB
        $totalVMRam = $hvInfo.TotalVMRamGB
        $ramPressurePct = if ($hostRAM -gt 0) { [math]::Round(($totalVMRam / $hostRAM) * 100, 1) } else { 0 }
        $hvInfo['RAMPressurePct'] = $ramPressurePct

        # ── Finding: This IS a Hyper-V host ───────────────────────
        $findings.Add([PSCustomObject]@{
            Category       = 'Hyper-V'
            Check          = 'Hyper-V Role'
            Status         = 'PASS'
            Severity       = 'Info'
            Description    = "This server is a Hyper-V host running $vmCount virtual machine(s)"
            Details        = "Running: $($hvInfo.RunningVMCount) | Stopped: $($hvInfo.StoppedVMCount) | Gen1: $($hvInfo.Gen1VMCount) | Gen2: $($hvInfo.Gen2VMCount) | Total VM RAM: $($hvInfo.TotalVMRamGB) GB | Host RAM: $hostRAM GB ($ramPressurePct% allocated to VMs)"
            Recommendation = 'Cloud migration strategy applies to the VMs hosted here, not the host itself. See Cloud Readiness section for VM migration paths.'
            Reference      = 'https://learn.microsoft.com/en-us/azure/migrate/migrate-services-overview'
        })

        # ── RAM Overcommitment ─────────────────────────────────────
        if ($ramPressurePct -ge 95) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Hyper-V'
                Check          = 'RAM Overcommitment'
                Status         = 'FAIL'
                Severity       = 'Critical'
                Description    = "VMs are allocated $ramPressurePct% of host RAM ($($hvInfo.TotalVMRamGB) GB allocated / $hostRAM GB available)"
                Details        = 'RAM overcommitment causes host paging, which degrades ALL VMs simultaneously. This is a single point of catastrophic performance failure.'
                Recommendation = 'Immediately reduce VM RAM allocations or add physical RAM to the host. Investigate which VMs can use dynamic memory. Consider migrating some VMs to another host or to cloud to reduce pressure.'
                Reference      = 'https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/best-practices-analyzer/avoid-storing-smart-paging-files-on-a-system-disk'
            })
        }
        elseif ($ramPressurePct -ge 85) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Hyper-V'
                Check          = 'RAM Overcommitment'
                Status         = 'WARN'
                Severity       = 'High'
                Description    = "VMs allocated $ramPressurePct% of host RAM - approaching overcommitment threshold"
                Details        = "$($hvInfo.TotalVMRamGB) GB allocated to VMs / $hostRAM GB host RAM."
                Recommendation = 'Enable dynamic memory on VMs where possible. Monitor host memory pressure counters. Plan RAM upgrade or VM migration before reaching 100%.'
                Reference      = ''
            })
        }
        else {
            $findings.Add([PSCustomObject]@{
                Category       = 'Hyper-V'
                Check          = 'RAM Allocation'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = "RAM allocation healthy: $ramPressurePct% of host RAM committed to VMs"
                Details        = "$($hvInfo.TotalVMRamGB) GB VM allocation / $hostRAM GB host RAM."
                Recommendation = 'Continue monitoring. Set alert at 85% allocation threshold.'
                Reference      = ''
            })
        }

        # ── Snapshots / Checkpoints ────────────────────────────────
        if ($hvInfo.VMsWithSnapshots -gt 0) {
            $snapshotVMs = ($hvInfo.VMList | Where-Object { $_.HasSnapshots } | ForEach-Object { "$($_.Name) ($($_.SnapshotCount) snapshot(s))" }) -join ', '
            $findings.Add([PSCustomObject]@{
                Category       = 'Hyper-V'
                Check          = 'VM Snapshots / Checkpoints'
                Status         = 'FAIL'
                Severity       = 'High'
                Description    = "$($hvInfo.VMsWithSnapshots) VM(s) have active checkpoints/snapshots: $snapshotVMs"
                Details        = 'Production snapshots cause AVHD/AVHDX differencing disk chains that grow unbounded. They degrade VM performance, consume disk rapidly, and BLOCK cloud migration tools until removed.'
                Recommendation = 'Delete all production checkpoints immediately. Checkpoints are not backups. Use Windows Server Backup, Veeam, or Azure Backup for actual backup strategy. Must be removed before using Azure Migrate or AWS MGN.'
                Reference      = 'https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/use-snapshots-to-manage-virtual-machines'
            })
        }

        # ── Generation 1 VMs ──────────────────────────────────────
        if ($hvInfo.Gen1VMCount -gt 0) {
            $gen1VMs = ($hvInfo.VMList | Where-Object { $_.Generation -eq 1 } | ForEach-Object { $_.Name }) -join ', '
            $findings.Add([PSCustomObject]@{
                Category       = 'Hyper-V'
                Check          = 'VM Generation Compatibility'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = "$($hvInfo.Gen1VMCount) Gen 1 VM(s) detected: $gen1VMs"
                Details        = 'Generation 1 VMs use legacy BIOS emulation. Azure and AWS support Gen1, but Gen2 VMs offer better cloud performance (UEFI boot, larger disks, faster startup). Gen1 cannot be converted to Gen2 in-place.'
                Recommendation = 'Gen1 VMs can still be migrated to Azure/AWS via Azure Migrate or AWS MGN. For new VMs, always use Gen2. Long-term: rebuild Gen1 workloads as Gen2 during the migration window.'
                Reference      = 'https://learn.microsoft.com/en-us/azure/virtual-machines/generation-2'
            })
        }

        if ($hvInfo.Gen2VMCount -gt 0 -and $hvInfo.Gen1VMCount -eq 0) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Hyper-V'
                Check          = 'VM Generation Compatibility'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = "All $($hvInfo.Gen2VMCount) VM(s) are Generation 2 - optimal cloud compatibility"
                Details        = 'Gen2 VMs support UEFI, Secure Boot, and larger virtual disks. Native compatibility with Azure Gen2 VM sizes and AWS Nitro-based instances.'
                Recommendation = 'Proceed with Azure Migrate or AWS Application Migration Service for lift-and-shift.'
                Reference      = ''
            })
        }

        # ── Stopped VMs ────────────────────────────────────────────
        if ($hvInfo.StoppedVMCount -gt 0) {
            $stoppedVMs = ($hvInfo.VMList | Where-Object { $_.State -ne 'Running' } | ForEach-Object { "$($_.Name) ($($_.State))" }) -join ', '
            $findings.Add([PSCustomObject]@{
                Category       = 'Hyper-V'
                Check          = 'Stopped Virtual Machines'
                Status         = 'WARN'
                Severity       = 'Low'
                Description    = "$($hvInfo.StoppedVMCount) VM(s) are not running: $stoppedVMs"
                Details        = 'Stopped VMs still consume disk space. If long-term stopped, they may be abandoned workloads wasting storage.'
                Recommendation = 'Audit stopped VMs. Delete or archive VMs no longer needed. Export to Azure or AWS if they need to be preserved but not active.'
                Reference      = ''
            })
        }

        # ── Integration Services ───────────────────────────────────
        if ($hvInfo.VMsWithOldIntSvc -gt 0) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Hyper-V'
                Check          = 'VM Integration Services'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = "$($hvInfo.VMsWithOldIntSvc) VM(s) have disabled or outdated integration services"
                Details        = 'Outdated or disabled integration services cause degraded performance: no time sync, no VSS-consistent backups, no live migration, and reduced network performance.'
                Recommendation = 'Update integration services on each VM: in guest, Windows Update handles this on supported OS. For older OS, install Integration Services manually from the Hyper-V host media.'
                Reference      = 'https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-integration-services'
            })
        }

        # ── No External Virtual Switch ─────────────────────────────
        $switches = $hvInfo.VirtualSwitches
        $hasExternal = $switches | Where-Object { $_ -match 'External' }
        if (-not $hasExternal) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Hyper-V'
                Check          = 'Virtual Switch Configuration'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = 'No External virtual switch detected - VMs may have no network connectivity outside the host'
                Details        = "Switches found: $(if($switches){"$($switches -join ', ')"}else{'None detected'}). Without an external switch, VMs cannot reach the network, domain, or internet."
                Recommendation = 'Verify VMs have correct network connectivity. An external switch is required for domain-joined VMs to communicate with AD infrastructure.'
                Reference      = 'https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/create-a-virtual-switch-for-hyper-v-virtual-machines'
            })
        }

        # ── Large VM Disk Consumers ────────────────────────────────
        $largeVMs = $hvInfo.VMList | Where-Object { $_.DiskGB -gt 200 } | Sort-Object DiskGB -Descending
        if ($largeVMs) {
            $largeList = ($largeVMs | ForEach-Object { "$($_.Name): $($_.DiskGB) GB" }) -join ', '
            $findings.Add([PSCustomObject]@{
                Category       = 'Hyper-V'
                Check          = 'Large VM Disk Consumers'
                Status         = 'INFO'
                Severity       = 'Info'
                Description    = "Large VM disk consumers identified: $largeList"
                Details        = 'Large VHDXs take longer to migrate to cloud and require adequate temporary storage during migration. Plan migration windows accordingly.'
                Recommendation = 'For VMs over 500 GB, use Azure Migrate appliance for delta-sync migration to minimize downtime. AWS MGN also supports large disk replication.'
                Reference      = ''
            })
        }

        # ── Single Host = Single Point of Failure ─────────────────
        if ($vmCount -gt 1) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Hyper-V'
                Check          = 'High Availability'
                Status         = 'WARN'
                Severity       = 'High'
                Description    = "$vmCount VMs on a single Hyper-V host with no cluster detected - single point of failure"
                Details        = 'If this host fails (hardware, OS crash, power), ALL VMs go offline simultaneously. No automatic failover is in place.'
                Recommendation = 'Options in priority order: (1) Migrate VMs to Azure/AWS for built-in HA and redundancy - eliminates this risk entirely. (2) Add a second Hyper-V host and configure Hyper-V Cluster with CSV. (3) At minimum, ensure Azure Site Recovery is replicating all VMs for DR.'
                Reference      = 'https://learn.microsoft.com/en-us/azure/site-recovery/hyper-v-azure-tutorial'
            })
        }

    }
    catch {
        $findings.Add([PSCustomObject]@{
            Category       = 'Hyper-V'
            Check          = 'Hyper-V Data Collection'
            Status         = 'ERROR'
            Severity       = 'High'
            Description    = "Failed to collect Hyper-V details from $ComputerName"
            Details        = $_.Exception.Message
            Recommendation = 'Ensure the Hyper-V PowerShell module is installed on the host (Install-WindowsFeature RSAT-Hyper-V-Tools) and PS remoting is enabled.'
            Reference      = ''
        })
    }

    return [PSCustomObject]@{
        ModuleName = 'HyperVCheck'
        HVInfo     = $hvInfo
        Findings   = $findings
    }
}

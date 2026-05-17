function Invoke-CloudReadinessCheck {
    param(
        [string]$ComputerName,
        [hashtable]$Config,
        [PSCustomObject]$OSResult,
        [PSCustomObject]$HardwareResult,
        [PSCustomObject]$SecurityResult,
        [PSCustomObject]$PerformanceResult,
        [PSCustomObject]$HyperVResult
    )

    $findings    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $cloudInfo   = @{}
    $scoreBreakdown = @{}
    $totalScore  = 0
    $weights     = $Config.CloudMigration.ScoringWeights

    # ── Score 1: OS Modernity ──────────────────────────────────────
    $osScore    = 0
    $osCaption  = $OSResult.OSInfo.Caption
    $osBuild    = $OSResult.OSInfo.BuildNumber

    if ($osCaption -match '2025|2022') {
        $osScore = $weights.OSModern      # Full score: current OS
    }
    elseif ($osCaption -match '2019|2016') {
        $osScore = [math]::Round($weights.OSModern * 0.75)  # Supported, minor cloud friction
    }
    elseif ($osCaption -match '2012') {
        $osScore = [math]::Round($weights.OSModern * 0.30)  # EOL, significant issues
    }
    else {
        $osScore = 0   # Very old / EOL  - migration requires OS upgrade first
    }
    $scoreBreakdown['OS Modernity'] = @{ Score = $osScore; Max = $weights.OSModern; Label = $osCaption }

    # ── Score 2: Hardware Age ──────────────────────────────────────
    $hwScore  = 0
    $hwAge    = $HardwareResult.HardwareInfo.AgeYears
    $isVirtual = $HardwareResult.HardwareInfo.IsVirtual

    if ($isVirtual) {
        $hwScore = $weights.HardwareAge   # Virtual = full score, no physical hardware concern
        $scoreBreakdown['Hardware'] = @{ Score = $hwScore; Max = $weights.HardwareAge; Label = 'Virtual machine  - no physical hardware barrier' }
    }
    elseif ($null -eq $hwAge) {
        $hwScore = [math]::Round($weights.HardwareAge * 0.5)
        $scoreBreakdown['Hardware'] = @{ Score = $hwScore; Max = $weights.HardwareAge; Label = 'Hardware age unknown' }
    }
    elseif ($hwAge -le 3) {
        $hwScore = $weights.HardwareAge
        $scoreBreakdown['Hardware'] = @{ Score = $hwScore; Max = $weights.HardwareAge; Label = "Hardware $hwAge years old  - modern" }
    }
    elseif ($hwAge -le 5) {
        $hwScore = [math]::Round($weights.HardwareAge * 0.75)
        $scoreBreakdown['Hardware'] = @{ Score = $hwScore; Max = $weights.HardwareAge; Label = "Hardware $hwAge years old  - aging but functional" }
    }
    elseif ($hwAge -le 7) {
        $hwScore = [math]::Round($weights.HardwareAge * 0.40)
        $scoreBreakdown['Hardware'] = @{ Score = $hwScore; Max = $weights.HardwareAge; Label = "Hardware $hwAge years old  - near end of life, migration urgent" }
    }
    else {
        $hwScore = [math]::Round($weights.HardwareAge * 0.10)
        $scoreBreakdown['Hardware'] = @{ Score = $hwScore; Max = $weights.HardwareAge; Label = "Hardware $hwAge years old  - past end of life" }
    }

    # ── Score 3: Security Posture ──────────────────────────────────
    $secScore    = $weights.SecurityPosture
    $secFindings = $SecurityResult.Findings | Where-Object { $_.Status -in 'FAIL','ERROR' }
    $critCount   = ($secFindings | Where-Object { $_.Severity -eq 'Critical' } | Measure-Object).Count
    $highCount   = ($secFindings | Where-Object { $_.Severity -eq 'High' }     | Measure-Object).Count

    $secDeduct = ($critCount * 5) + ($highCount * 2)
    $secScore  = [math]::Max(0, $secScore - $secDeduct)
    $scoreBreakdown['Security Posture'] = @{
        Score = $secScore
        Max   = $weights.SecurityPosture
        Label = "$critCount critical and $highCount high security findings"
    }

    # ── Score 4: Application / Workload Compatibility ──────────────
    $appScore = [math]::Round($weights.ApplicationCompatibility * 0.7)  # Default: partial score (unknown compatibility)
    $roleHint = ''
    # Try to detect role from available data
    $adRole = $OSResult.OSInfo.Caption
    if ($HardwareResult.HardwareInfo.IsVirtual) { $appScore = $weights.ApplicationCompatibility }
    $scoreBreakdown['App Compatibility'] = @{
        Score = $appScore
        Max   = $weights.ApplicationCompatibility
        Label = 'Estimated based on available data (manual application inventory recommended)'
    }

    # ── Score 5: Patch Compliance ──────────────────────────────────
    $patchScore   = $weights.PatchCompliance
    $osFindings   = $OSResult.Findings
    $hotfixFail   = $osFindings | Where-Object { $_.Check -eq 'Installed Hotfixes' -and $_.Status -eq 'WARN' }
    $uptimeFail   = $osFindings | Where-Object { $_.Check -eq 'System Uptime'      -and $_.Status -ne 'PASS' }
    if ($hotfixFail) { $patchScore = [math]::Round($patchScore * 0.4) }
    if ($uptimeFail) { $patchScore = [math]::Max(0, $patchScore - [math]::Round($weights.PatchCompliance * 0.3)) }
    $scoreBreakdown['Patch Compliance'] = @{
        Score = $patchScore
        Max   = $weights.PatchCompliance
        Label = if ($hotfixFail) { 'Patching appears inconsistent' } else { 'Patching appears healthy' }
    }

    # ── Score 6: Virtualization Readiness ─────────────────────────
    $virtScore = if ($isVirtual) { $weights.VirtualizationReady } else { [math]::Round($weights.VirtualizationReady * 0.6) }
    $scoreBreakdown['Virtualization Ready'] = @{
        Score = $virtScore
        Max   = $weights.VirtualizationReady
        Label = if ($isVirtual) { 'Already virtualized  - lift-and-shift viable' } else { 'Physical server  - P2V conversion needed' }
    }

    # ── Score 7: Network Readiness ─────────────────────────────────
    $netScore = [math]::Round($weights.NetworkReadiness * 0.8)  # Default assumption
    $scoreBreakdown['Network Readiness'] = @{
        Score = $netScore
        Max   = $weights.NetworkReadiness
        Label = 'Network assessment requires connectivity speed/latency testing (manual step)'
    }

    # ── Total Score ────────────────────────────────────────────────
    $totalScore = $osScore + $hwScore + $secScore + $appScore + $patchScore + $virtScore + $netScore
    $maxScore   = $weights.OSModern + $weights.HardwareAge + $weights.SecurityPosture +
                  $weights.ApplicationCompatibility + $weights.PatchCompliance +
                  $weights.VirtualizationReady + $weights.NetworkReadiness

    $cloudScorePct = [math]::Round(($totalScore / $maxScore) * 100)

    $cloudThresholds  = $Config.CloudMigration.Thresholds
    $cloudRecs        = $Config.CloudMigration.Recommendations

    if ($cloudScorePct -ge $cloudThresholds.CloudReady) {
        $readinessLabel = 'Cloud Ready'
        $readinessKey   = 'CloudReady'
        $badgeColor     = '#16a34a'
    }
    elseif ($cloudScorePct -ge $cloudThresholds.HybridReady) {
        $readinessLabel = 'Hybrid Candidate'
        $readinessKey   = 'HybridReady'
        $badgeColor     = '#d97706'
    }
    else {
        $readinessLabel = 'Upgrade Required Before Migration'
        $readinessKey   = 'MigrationNeeded'
        $badgeColor     = '#dc2626'
    }

    $recommendation = $cloudRecs[$readinessKey]

    $cloudInfo = @{
        Score          = $cloudScorePct
        MaxScore       = 100
        ReadinessLabel = $readinessLabel
        ReadinessKey   = $readinessKey
        BadgeColor     = $badgeColor
        ScoreBreakdown = $scoreBreakdown
        Recommendation = $recommendation
    }

    # ── Detect if this is a Hyper-V host ──────────────────────────
    $isHyperVHost = $HyperVResult -and $HyperVResult.HVInfo.IsHyperVHost -eq $true
    $hvInfo       = if ($isHyperVHost) { $HyperVResult.HVInfo } else { $null }

    # ── HYPER-V HOST: completely different cloud path ──────────────
    if ($isHyperVHost) {

        $vmCount    = $hvInfo.TotalVMCount
        $gen1Count  = $hvInfo.Gen1VMCount
        $gen2Count  = $hvInfo.Gen2VMCount
        $snapCount  = $hvInfo.VMsWithSnapshots
        $hwAge      = $HardwareResult.HardwareInfo.AgeYears

        # Urgency driven by physical hardware age
        $urgency = if ($null -ne $hwAge) {
            if ($hwAge -ge 7)    { 'CRITICAL - hardware is past end of service life' }
            elseif ($hwAge -ge 5){ 'HIGH - hardware approaching end of service life' }
            elseif ($hwAge -ge 3){ 'MEDIUM - plan migration within 2-3 years' }
            else                 { 'LOW - hardware is modern, plan migration at next refresh' }
        } else { 'UNKNOWN - hardware age could not be determined' }

        # Blockers
        $blockers = @()
        if ($snapCount -gt 0)  { $blockers += "$snapCount VM(s) have snapshots (must remove before migration)" }
        if ($gen1Count -gt 0)  { $blockers += "$gen1Count Gen1 VM(s) require extra migration testing" }

        $cloudInfo['IsHyperVHost']   = $true
        $cloudInfo['MigrationUrgency'] = $urgency
        $cloudInfo['VMCount']        = $vmCount
        $cloudInfo['MigrationBlockers'] = $blockers
        $cloudInfo['ReadinessLabel'] = 'Hyper-V Host - Migrate VMs'
        $cloudInfo['Score']          = $cloudScorePct

        $findings.Add([PSCustomObject]@{
            Category       = 'Cloud Readiness'
            Check          = 'Hyper-V Host - Cloud Strategy'
            Status         = 'PASS'
            Severity       = 'Info'
            Description    = "This is a Hyper-V HOST with $vmCount VM(s). Cloud migration applies to the VMs, not the host itself."
            Details        = "The host hardware is the migration driver. Urgency: $urgency. The host OS and standalone status are irrelevant for cloud scoring since the workloads live inside the VMs."
            Recommendation = 'Use Azure Migrate or AWS Application Migration Service to replicate and migrate the individual VMs to cloud. The Hyper-V host is decommissioned AFTER all VMs are migrated.'
            Reference      = 'https://learn.microsoft.com/en-us/azure/migrate/migrate-services-overview'
        })

        # Migration urgency based on hardware age
        $urgencySev = if ($hwAge -ge 7) { 'Critical' } elseif ($hwAge -ge 5) { 'High' } elseif ($hwAge -ge 3) { 'Medium' } else { 'Low' }
        $urgencyStatus = if ($hwAge -ge 5) { 'FAIL' } elseif ($hwAge -ge 3) { 'WARN' } else { 'PASS' }

        $findings.Add([PSCustomObject]@{
            Category       = 'Cloud Readiness'
            Check          = 'VM Migration Urgency'
            Status         = $urgencyStatus
            Severity       = $urgencySev
            Description    = "VM migration urgency: $urgency"
            Details        = "Physical host hardware age is the primary migration driver. When this host fails or reaches end of support, all $vmCount VMs go down. Cloud migration eliminates this single point of failure."
            Recommendation = if ($hwAge -ge 5) {
                "Begin Azure Migrate / AWS MGN replication NOW. Hardware failure risk is high. Each VM can be replicated while running with near-zero downtime cutover."
            } else {
                "Build migration plan targeting completion within 2 years. Deploy Azure Migrate appliance or AWS MGN agent to begin discovery."
            }
            Reference      = 'https://learn.microsoft.com/en-us/azure/migrate/tutorial-migrate-hyper-v'
        })

        # Per-VM cloud compatibility summary
        if ($hvInfo.VMList -and $hvInfo.VMList.Count -gt 0) {
            $vmSummary = ($hvInfo.VMList | ForEach-Object {
                $compat = if ($_.Generation -eq 2 -and -not $_.HasSnapshots) { 'Ready' }
                          elseif ($_.HasSnapshots) { 'Blocked (snapshots)' }
                          else { 'Needs testing (Gen1)' }
                "$($_.Name): $compat"
            }) -join ' | '

            $findings.Add([PSCustomObject]@{
                Category       = 'Cloud Readiness'
                Check          = 'Per-VM Migration Compatibility'
                Status         = if ($blockers) { 'WARN' } else { 'PASS' }
                Severity       = if ($blockers) { 'Medium' } else { 'Info' }
                Description    = "VM migration compatibility: $vmSummary"
                Details        = "Gen2 VMs with no snapshots = direct lift-and-shift. Gen1 VMs = supported but test boot post-migration. Snapshots = must delete before starting migration replication."
                Recommendation = if ($blockers) {
                    "Resolve blockers first: $($blockers -join '; '). Then deploy Azure Migrate appliance on this Hyper-V host for automated discovery and replication."
                } else {
                    "All VMs are migration-ready. Deploy Azure Migrate appliance: https://learn.microsoft.com/en-us/azure/migrate/tutorial-discover-hyper-v"
                }
                Reference      = 'https://learn.microsoft.com/en-us/azure/migrate/tutorial-migrate-hyper-v'
            })
        }

        # Azure Migrate step-by-step
        $findings.Add([PSCustomObject]@{
            Category       = 'Cloud Readiness'
            Check          = 'Recommended Migration Steps (Azure)'
            Status         = 'INFO'
            Severity       = 'Info'
            Description    = 'Azure Migrate provides native Hyper-V VM discovery and agentless replication'
            Details        = 'Azure Migrate can discover all VMs on this Hyper-V host automatically, replicate them to Azure while running, and cut over with minutes of downtime.'
            Recommendation = '1. Create Azure Migrate project in Azure Portal. 2. Download and deploy Azure Migrate appliance OVA on this Hyper-V host. 3. Discover all VMs (automatic). 4. Assess each VM for Azure sizing and cost. 5. Enable replication (agentless). 6. Run test migration. 7. Perform cutover during maintenance window. 8. Decommission Hyper-V host.'
            Reference      = 'https://learn.microsoft.com/en-us/azure/migrate/tutorial-migrate-hyper-v'
        })

        $findings.Add([PSCustomObject]@{
            Category       = 'Cloud Readiness'
            Check          = 'Recommended Migration Steps (AWS)'
            Status         = 'INFO'
            Severity       = 'Info'
            Description    = 'AWS Application Migration Service (MGN) supports Hyper-V VM migration'
            Details        = 'AWS MGN installs a lightweight agent in each VM guest, replicates to AWS in the background, and allows test and cutover without extended downtime.'
            Recommendation = '1. Create AWS MGN service in target AWS region. 2. Install AWS MGN Replication Agent in each guest VM. 3. Monitor replication lag in MGN console. 4. Launch test instances to validate. 5. Perform final cutover. 6. Decommission Hyper-V host after validation period.'
            Reference      = 'https://aws.amazon.com/application-migration-service/'
        })

        # DC-specific cloud path (if any VMs are DCs - user knows this from separate DC scan)
        $findings.Add([PSCustomObject]@{
            Category       = 'Cloud Readiness'
            Check          = 'Domain Controller VMs - Special Consideration'
            Status         = 'INFO'
            Severity       = 'Info'
            Description    = 'If any VMs on this host are Domain Controllers, additional planning is required'
            Details        = 'DCs cannot simply be lift-and-shifted without AD planning. Options: (1) Azure AD DS (managed AD in cloud - no VM needed), (2) DC replica VM in Azure IaaS connected via VPN/ExpressRoute, (3) Entra ID (formerly Azure AD) for cloud-native identity.'
            Recommendation = '1. Assess whether full AD DS is needed in cloud or if Entra ID suffices. 2. If keeping AD DS: deploy a DC replica in Azure BEFORE migrating workloads. 3. Never replicate your only DC to cloud without a local replica remaining. 4. Refer to separate DC scan report for AD health before migration.'
            Reference      = 'https://learn.microsoft.com/en-us/azure/architecture/reference-architectures/identity/adds-extend-domain'
        })

        # Cost note for Hyper-V hosts
        $findings.Add([PSCustomObject]@{
            Category       = 'Cloud Readiness'
            Check          = 'Cloud Cost - Hyper-V License Benefit'
            Status         = 'INFO'
            Severity       = 'Info'
            Description    = 'Azure Hybrid Benefit applies to each migrated VM, not just this host'
            Details        = 'Each Windows Server VM migrated to Azure with active Software Assurance qualifies for Azure Hybrid Benefit, saving 40-85% on Windows licensing costs per VM in Azure.'
            Recommendation = 'Inventory Software Assurance coverage for all VMs before migration. Use Azure Hybrid Benefit on every eligible VM. Run Azure TCO Calculator with actual VM specs for accurate cost projection.'
            Reference      = 'https://azure.microsoft.com/pricing/hybrid-benefit/'
        })

        return [PSCustomObject]@{
            ModuleName = 'CloudReadinessCheck'
            CloudInfo  = $cloudInfo
            Findings   = $findings
        }
    }

    # ── STANDARD SERVER: original cloud path (unchanged) ──────────

    $roleMap = $Config.CloudMigration.RoleCloudMap

    $findings.Add([PSCustomObject]@{
        Category       = 'Cloud Readiness'
        Check          = 'Cloud Migration Score'
        Status         = if ($cloudScorePct -ge 75) { 'PASS' } elseif ($cloudScorePct -ge 50) { 'WARN' } else { 'FAIL' }
        Severity       = if ($cloudScorePct -ge 75) { 'Info' } elseif ($cloudScorePct -ge 50) { 'Medium' } else { 'High' }
        Description    = "Cloud Readiness Score: $cloudScorePct / 100 - $readinessLabel"
        Details        = ($scoreBreakdown.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value.Score)/$($_.Value.Max) - $($_.Value.Label)" }) -join ' | '
        Recommendation = "$($recommendation.Description) Options: $($recommendation.Options -join ', ')"
        Reference      = 'https://azure.microsoft.com/migration | https://aws.amazon.com/cloud-migration/'
    })

    if ($cloudScorePct -ge $cloudThresholds.CloudReady) {
        $findings.Add([PSCustomObject]@{
            Category       = 'Cloud Readiness'
            Check          = 'Migration Path'
            Status         = 'PASS'
            Severity       = 'Info'
            Description    = 'Server is a strong candidate for direct cloud migration'
            Details        = 'Recommended migration approaches: Lift-and-shift (IaaS VM), or modernization to PaaS if application supports it.'
            Recommendation = '1. Run Azure Migrate / AWS Application Discovery Service for detailed assessment. 2. Use Azure Site Recovery or AWS Application Migration Service for replication. 3. Cut over during maintenance window with minimal downtime.'
            Reference      = 'https://learn.microsoft.com/en-us/azure/migrate/ | https://aws.amazon.com/application-migration-service/'
        })
    }
    elseif ($cloudScorePct -ge $cloudThresholds.HybridReady) {
        $findings.Add([PSCustomObject]@{
            Category       = 'Cloud Readiness'
            Check          = 'Migration Path'
            Status         = 'WARN'
            Severity       = 'Medium'
            Description    = 'Server suits a hybrid architecture as a migration stepping stone'
            Details        = 'Hybrid approach allows gradual migration while resolving blockers (security findings, OS age).'
            Recommendation = '1. Enroll in Azure Arc for unified management. 2. Configure Azure AD Connect for identity sync. 3. Resolve Critical/High security findings first. 4. Plan full migration within 12-18 months.'
            Reference      = 'https://azure.microsoft.com/products/azure-arc | https://aws.amazon.com/outposts/'
        })
    }
    else {
        $findings.Add([PSCustomObject]@{
            Category       = 'Cloud Readiness'
            Check          = 'Migration Blockers'
            Status         = 'FAIL'
            Severity       = 'High'
            Description    = 'Server has blockers that must be resolved before cloud migration'
            Details        = 'Low score indicates: outdated OS, aging hardware, poor security posture, or patching issues that will follow the server to the cloud if not addressed first.'
            Recommendation = '1. Resolve all Critical/High security findings. 2. Upgrade OS to Server 2019 or 2022. 3. Validate applications for cloud compatibility. 4. Re-assess after remediation. Target cloud migration within 24 months.'
            Reference      = ''
        })
    }

    $findings.Add([PSCustomObject]@{
        Category       = 'Cloud Readiness'
        Check          = 'Cloud Cost & Licensing'
        Status         = 'INFO'
        Severity       = 'Info'
        Description    = 'Azure Hybrid Benefit and Reserved Instances can reduce cloud migration costs significantly'
        Details        = 'Azure Hybrid Benefit allows use of existing Windows Server licenses with Software Assurance. Reserved Instances (1 or 3 year) reduce compute costs by up to 72% vs. pay-as-you-go.'
        Recommendation = 'Run Azure TCO Calculator or AWS Pricing Calculator. Engage Microsoft / AWS licensing desk. Factor in: Software Assurance credits, Reserved Instance savings, and reduced hardware maintenance costs.'
        Reference      = 'https://azure.microsoft.com/pricing/hybrid-benefit/ | https://aws.amazon.com/windows/resources/licensing/'
    })

    return [PSCustomObject]@{
        ModuleName = 'CloudReadinessCheck'
        CloudInfo  = $cloudInfo
        Findings   = $findings
    }
}

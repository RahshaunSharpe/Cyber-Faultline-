function New-HTMLReport {
    param(
        [array]$ServerResults,
        [string]$OutputPath,
        [string]$ReportTitle = 'Enterprise Infrastructure Assessment Report',
        [hashtable]$Config
    )

    $reportDate   = Get-Date -Format 'MMMM dd, yyyy HH:mm'
    $reportFile   = Join-Path $OutputPath "Assessment_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

    # ── Aggregate Stats ────────────────────────────────────────────
    $totalServers  = $ServerResults.Count
    $totalFindings = 0
    $critCount     = 0
    $highCount     = 0
    $medCount      = 0
    $lowCount      = 0
    $healthyCount  = 0

    foreach ($sr in $ServerResults) {
        $allFindings = @()
        foreach ($mod in $sr.Modules) { $allFindings += $mod.Findings }
        $critCount    += ($allFindings | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -ne 'PASS' } | Measure-Object).Count
        $highCount    += ($allFindings | Where-Object { $_.Severity -eq 'High'     -and $_.Status -ne 'PASS' } | Measure-Object).Count
        $medCount     += ($allFindings | Where-Object { $_.Severity -eq 'Medium'   -and $_.Status -ne 'PASS' } | Measure-Object).Count
        $lowCount     += ($allFindings | Where-Object { $_.Severity -eq 'Low'      -and $_.Status -ne 'PASS' } | Measure-Object).Count
        $totalFindings += $allFindings.Count
        if ($sr.OverallRisk -in 'Healthy','Low') { $healthyCount++ }
    }

    # ── Helpers ────────────────────────────────────────────────────
    function Get-SeverityBadge($severity) {
        switch ($severity) {
            'Critical' { return '<span class="badge badge-critical">CRITICAL</span>' }
            'High'     { return '<span class="badge badge-high">HIGH</span>' }
            'Medium'   { return '<span class="badge badge-medium">MEDIUM</span>' }
            'Low'      { return '<span class="badge badge-low">LOW</span>' }
            default    { return '<span class="badge badge-info">INFO</span>' }
        }
    }

    function Get-StatusIcon($status) {
        switch ($status) {
            'PASS'  { return '<span class="status-pass">&#10004; PASS</span>' }
            'FAIL'  { return '<span class="status-fail">&#10008; FAIL</span>' }
            'WARN'  { return '<span class="status-warn">&#9888; WARN</span>' }
            'ERROR' { return '<span class="status-error">&#9888; ERROR</span>' }
            'INFO'  { return '<span class="status-info">&#8505; INFO</span>' }
            default { return "<span>$status</span>" }
        }
    }

    function Get-RiskBadge($risk) {
        switch ($risk) {
            'Critical' { return '<span class="risk-badge risk-critical">Critical Risk</span>' }
            'High'     { return '<span class="risk-badge risk-high">High Risk</span>' }
            'Medium'   { return '<span class="risk-badge risk-medium">Medium Risk</span>' }
            'Low'      { return '<span class="risk-badge risk-low">Low Risk</span>' }
            default    { return '<span class="risk-badge risk-healthy">Healthy</span>' }
        }
    }

    function Get-ScoreColor($score) {
        if ($score -ge 75) { return '#dc2626' }
        elseif ($score -ge 50) { return '#ea580c' }
        elseif ($score -ge 25) { return '#d97706' }
        elseif ($score -ge 10) { return '#2563eb' }
        else { return '#16a34a' }
    }

    function Escape-Html($str) {
        if (-not $str) { return '' }
        return [System.Web.HttpUtility]::HtmlEncode($str.ToString())
    }

    # ── Build Server Cards ─────────────────────────────────────────
    $serverCardsHTML = ''
    $findingRowsHTML = ''
    $serverIndex     = 0

    foreach ($sr in $ServerResults) {
        $serverIndex++
        $sid = "server_$serverIndex"

        $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($mod in $sr.Modules) {
            if ($mod.Findings) { $allFindings.AddRange([PSCustomObject[]]$mod.Findings) }
        }

        $sCrit = ($allFindings | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -ne 'PASS' } | Measure-Object).Count
        $sHigh = ($allFindings | Where-Object { $_.Severity -eq 'High'     -and $_.Status -ne 'PASS' } | Measure-Object).Count
        $sMed  = ($allFindings | Where-Object { $_.Severity -eq 'Medium'   -and $_.Status -ne 'PASS' } | Measure-Object).Count
        $sLow  = ($allFindings | Where-Object { $_.Severity -eq 'Low'      -and $_.Status -ne 'PASS' } | Measure-Object).Count
        $sPass = ($allFindings | Where-Object { $_.Status -eq 'PASS' }       | Measure-Object).Count

        $scoreColor = Get-ScoreColor $sr.RiskScore
        $riskBadge  = Get-RiskBadge  $sr.OverallRisk

        $osModule  = $sr.Modules | Where-Object { $_.ModuleName -eq 'OSCheck' }             | Select-Object -First 1
        $hwModule  = $sr.Modules | Where-Object { $_.ModuleName -eq 'HardwareCheck' }       | Select-Object -First 1
        $stgModule = $sr.Modules | Where-Object { $_.ModuleName -eq 'StorageCheck' }        | Select-Object -First 1
        $cldModule = $sr.Modules | Where-Object { $_.ModuleName -eq 'CloudReadinessCheck' } | Select-Object -First 1
        $hvModule  = $sr.Modules | Where-Object { $_.ModuleName -eq 'HyperVCheck' }         | Select-Object -First 1
        $isHyperVHost = $hvModule -and $hvModule.HVInfo.IsHyperVHost -eq $true

        $osCaption = if ($osModule -and $osModule.OSInfo.Caption)    { $osModule.OSInfo.Caption } else { 'Unknown' }
        $hwModel   = if ($hwModule -and $hwModule.HardwareInfo.Model) { "$($hwModule.HardwareInfo.Manufacturer) $($hwModule.HardwareInfo.Model)" } else { 'Unknown' }
        $isVirtual = if ($hwModule) { $hwModule.HardwareInfo.IsVirtual } else { $false }
        $hwAge     = if ($hwModule -and $hwModule.HardwareInfo.AgeYears) { "$($hwModule.HardwareInfo.AgeYears) yrs" } else { 'N/A' }
        $totalRAM  = if ($osModule -and $osModule.OSInfo.TotalRAMGB) { "$($osModule.OSInfo.TotalRAMGB) GB" } else { 'N/A' }
        $cpuCores  = if ($hwModule -and $hwModule.HardwareInfo.CPUCores) { "$($hwModule.HardwareInfo.CPUCores) cores" } else { 'N/A' }

        # Sort and group findings by severity
        $actionFindings = $allFindings | Where-Object { $_.Status -ne 'PASS' -and $_.Status -ne 'INFO' } |
            Sort-Object @{E={ switch ($_.Severity) { 'Critical'{1} 'High'{2} 'Medium'{3} 'Low'{4} default{5} } }}

        $critFindings = @($actionFindings | Where-Object { $_.Severity -eq 'Critical' })
        $highFindings = @($actionFindings | Where-Object { $_.Severity -eq 'High' })
        $medFindings  = @($actionFindings | Where-Object { $_.Severity -eq 'Medium' })
        $lowFindings  = @($actionFindings | Where-Object { $_.Severity -eq 'Low' })

        # Top Priorities callout — split Fails vs Warnings
        $allActionTop = @($critFindings) + @($highFindings) + @($medFindings)
        $topFails = @($allActionTop | Where-Object { $_.Status -eq 'FAIL' -or $_.Status -eq 'ERROR' } | Select-Object -First 4)
        $topWarns = @($allActionTop | Where-Object { $_.Status -eq 'WARN' } | Select-Object -First 4)

        $topFailsHTML = ''
        foreach ($tp in $topFails) {
            $tpSev  = $tp.Severity.ToLower()
            $tpDesc = Escape-Html $tp.Description
            $tpRec  = Escape-Html $tp.Recommendation
            $topFailsHTML += "<li><span class='tp-badge tp-$tpSev'>$($tp.Severity.ToUpper())</span><strong> $tpDesc</strong><span class='tp-rec'> &mdash; $tpRec</span></li>"
        }

        $topWarnsHTML = ''
        foreach ($tp in $topWarns) {
            $tpSev  = $tp.Severity.ToLower()
            $tpDesc = Escape-Html $tp.Description
            $tpRec  = Escape-Html $tp.Recommendation
            $topWarnsHTML += "<li><span class='tp-badge tp-$tpSev'>$($tp.Severity.ToUpper())</span><strong> $tpDesc</strong><span class='tp-rec'> &mdash; $tpRec</span></li>"
        }

        # Build grouped per-server findings rows
        $serverFindingRows = ''

        if ($critFindings.Count -gt 0) {
            $word = if ($critFindings.Count -eq 1) { 'finding' } else { 'findings' }
            $serverFindingRows += "<tr class='sev-group-header sev-group-crit grp-critical-$sid'><td colspan='6'>&#128308; CRITICAL &nbsp;&mdash;&nbsp; $($critFindings.Count) $word requiring immediate action</td></tr>"
            foreach ($f in $critFindings) {
                $sevBadge   = Get-SeverityBadge $f.Severity
                $statusIcon = Get-StatusIcon    $f.Status
                $desc       = Escape-Html $f.Description
                $details    = Escape-Html $f.Details
                $rec        = Escape-Html $f.Recommendation
                $ref        = if ($f.Reference) { "<a href='$($f.Reference)' target='_blank' rel='noopener'>Ref</a>" } else { '' }
                $serverFindingRows += "<tr class='finding-row sev-critical srv-row-$sid'><td>$($f.Category)</td><td>$($f.Check)</td><td>$statusIcon</td><td>$sevBadge</td><td><strong>$desc</strong><br><small class='text-muted'>$details</small></td><td class='rec-cell'>$rec $ref</td></tr>"
            }
        }

        if ($highFindings.Count -gt 0) {
            $word = if ($highFindings.Count -eq 1) { 'finding' } else { 'findings' }
            $serverFindingRows += "<tr class='sev-group-header sev-group-high grp-high-$sid'><td colspan='6'>&#128992; HIGH &nbsp;&mdash;&nbsp; $($highFindings.Count) $word to remediate within days</td></tr>"
            foreach ($f in $highFindings) {
                $sevBadge   = Get-SeverityBadge $f.Severity
                $statusIcon = Get-StatusIcon    $f.Status
                $desc       = Escape-Html $f.Description
                $details    = Escape-Html $f.Details
                $rec        = Escape-Html $f.Recommendation
                $ref        = if ($f.Reference) { "<a href='$($f.Reference)' target='_blank' rel='noopener'>Ref</a>" } else { '' }
                $serverFindingRows += "<tr class='finding-row sev-high srv-row-$sid'><td>$($f.Category)</td><td>$($f.Check)</td><td>$statusIcon</td><td>$sevBadge</td><td><strong>$desc</strong><br><small class='text-muted'>$details</small></td><td class='rec-cell'>$rec $ref</td></tr>"
            }
        }

        if ($medFindings.Count -gt 0) {
            $word = if ($medFindings.Count -eq 1) { 'finding' } else { 'findings' }
            $serverFindingRows += "<tr class='sev-group-header sev-group-med grp-medium-$sid'><td colspan='6'>&#128993; MEDIUM &nbsp;&mdash;&nbsp; $($medFindings.Count) $word to address within weeks</td></tr>"
            foreach ($f in $medFindings) {
                $sevBadge   = Get-SeverityBadge $f.Severity
                $statusIcon = Get-StatusIcon    $f.Status
                $desc       = Escape-Html $f.Description
                $details    = Escape-Html $f.Details
                $rec        = Escape-Html $f.Recommendation
                $ref        = if ($f.Reference) { "<a href='$($f.Reference)' target='_blank' rel='noopener'>Ref</a>" } else { '' }
                $serverFindingRows += "<tr class='finding-row sev-medium srv-row-$sid'><td>$($f.Category)</td><td>$($f.Check)</td><td>$statusIcon</td><td>$sevBadge</td><td><strong>$desc</strong><br><small class='text-muted'>$details</small></td><td class='rec-cell'>$rec $ref</td></tr>"
            }
        }

        if ($lowFindings.Count -gt 0) {
            $word = if ($lowFindings.Count -eq 1) { 'finding' } else { 'findings' }
            $serverFindingRows += "<tr class='sev-group-header sev-group-low grp-low-$sid'><td colspan='6'>&#128309; LOW &nbsp;&mdash;&nbsp; $($lowFindings.Count) $word for normal maintenance cycle</td></tr>"
            foreach ($f in $lowFindings) {
                $sevBadge   = Get-SeverityBadge $f.Severity
                $statusIcon = Get-StatusIcon    $f.Status
                $desc       = Escape-Html $f.Description
                $details    = Escape-Html $f.Details
                $rec        = Escape-Html $f.Recommendation
                $ref        = if ($f.Reference) { "<a href='$($f.Reference)' target='_blank' rel='noopener'>Ref</a>" } else { '' }
                $serverFindingRows += "<tr class='finding-row sev-low srv-row-$sid'><td>$($f.Category)</td><td>$($f.Check)</td><td>$statusIcon</td><td>$sevBadge</td><td><strong>$desc</strong><br><small class='text-muted'>$details</small></td><td class='rec-cell'>$rec $ref</td></tr>"
            }
        }

        # Global priority remediation table rows
        foreach ($f in (@($critFindings) + @($highFindings) + @($medFindings) + @($lowFindings))) {
            $sevBadge   = Get-SeverityBadge $f.Severity
            $statusIcon = Get-StatusIcon    $f.Status
            $desc       = Escape-Html $f.Description
            $rec        = Escape-Html $f.Recommendation
            $findingRowsHTML += "<tr class='finding-row sev-$($f.Severity.ToLower())'><td><strong>$(Escape-Html $sr.ComputerName)</strong></td><td>$($f.Category)</td><td>$($f.Check)</td><td>$statusIcon</td><td>$sevBadge</td><td><strong>$desc</strong></td><td class='rec-cell'>$rec</td></tr>"
        }

        # Severity pills for the card header
        $pillsHTML = ''
        if ($sCrit -gt 0) { $pillsHTML += "<span class='sev-pill pill-crit'>$sCrit Crit</span>" }
        if ($sHigh -gt 0) { $pillsHTML += "<span class='sev-pill pill-high'>$sHigh High</span>" }
        if ($sMed  -gt 0) { $pillsHTML += "<span class='sev-pill pill-med'>$sMed Med</span>" }
        if ($sLow  -gt 0) { $pillsHTML += "<span class='sev-pill pill-low'>$sLow Low</span>" }
        if ($sCrit -eq 0 -and $sHigh -eq 0 -and $sMed -eq 0 -and $sLow -eq 0) {
            $pillsHTML = "<span class='sev-pill pill-ok'>All Clear</span>"
        }

        # Fail / Warn counts for status filter buttons
        $sFailCount = ($actionFindings | Where-Object { $_.Status -eq 'FAIL' -or $_.Status -eq 'ERROR' } | Measure-Object).Count
        $sWarnCount = ($actionFindings | Where-Object { $_.Status -eq 'WARN' } | Measure-Object).Count

        # Per-server filter buttons
        $critBtnClass = if ($sCrit -gt 0) { "filter-btn f-crit active" } else { "filter-btn f-crit disabled-btn" }
        $highBtnClass = if ($sHigh -gt 0) { "filter-btn f-high active" } else { "filter-btn f-high disabled-btn" }
        $medBtnClass  = if ($sMed  -gt 0) { "filter-btn f-med"  } else { "filter-btn f-med disabled-btn" }
        $lowBtnClass  = if ($sLow  -gt 0) { "filter-btn f-low"  } else { "filter-btn f-low disabled-btn" }
        $failBtnClass = if ($sFailCount -gt 0) { "filter-btn f-fail-btn active" } else { "filter-btn f-fail-btn disabled-btn" }
        $warnBtnClass = if ($sWarnCount -gt 0) { "filter-btn f-warn-btn active" } else { "filter-btn f-warn-btn disabled-btn" }

        $filterBarHTML = "<div class='server-filter-bar'>
            <span class='filter-label'>Severity:</span>
            <button class='$critBtnClass' data-sid='$sid' data-sev='critical' onclick='filterSrv(this)'>&#128308; Critical ($sCrit)</button>
            <button class='$highBtnClass' data-sid='$sid' data-sev='high'     onclick='filterSrv(this)'>&#128992; High ($sHigh)</button>
            <button class='$medBtnClass'  data-sid='$sid' data-sev='medium'   onclick='filterSrv(this)'>&#128993; Medium ($sMed)</button>
            <button class='$lowBtnClass'  data-sid='$sid' data-sev='low'      onclick='filterSrv(this)'>&#128309; Low ($sLow)</button>
            <span class='filter-divider'></span>
            <span class='filter-label'>Status:</span>
            <button class='$failBtnClass' data-sid='$sid' data-status='fail' onclick='filterSrvStatus(this)'>&#10008; Fails ($sFailCount)</button>
            <button class='$warnBtnClass' data-sid='$sid' data-status='warn' onclick='filterSrvStatus(this)'>&#9888; Warnings ($sWarnCount)</button>
            <button class='filter-btn filter-showall' onclick='showAllSrv(""$sid"")'>Show All</button>
        </div>"

        # Storage HTML
        $storageBoxHTML = ''
        if ($stgModule -and $stgModule.StorageInfo.Disks) {
            $storageBoxHTML = '<table class="detail-table">'
            foreach ($disk in $stgModule.StorageInfo.Disks) {
                $barColor = if ($disk.UsedPct -ge 90) { '#dc2626' } elseif ($disk.UsedPct -ge 75) { '#d97706' } else { '#16a34a' }
                $storageBoxHTML += "<tr><td>$($disk.Drive)$(if($disk.Label){" ($($disk.Label))"})</td><td><div class='disk-bar-wrap'><div class='disk-bar' style='width:$($disk.UsedPct)%;background:$barColor'></div></div><small>$($disk.UsedPct)% used &mdash; $($disk.FreeGB) GB free of $($disk.TotalGB) GB</small></td></tr>"
            }
            $storageBoxHTML += '</table>'
            if ($stgModule.StorageInfo.ShareCount -gt 0) {
                $storageBoxHTML += "<p style='margin-top:8px'><strong>$($stgModule.StorageInfo.ShareCount) network share(s)</strong></p>"
            }
        } else {
            $storageBoxHTML = '<p class="text-muted">Storage data unavailable</p>'
        }

        # Cloud HTML
        $cloudBoxHTML = '<p class="text-muted">Cloud assessment unavailable</p>'
        if ($cldModule) {
            $ci = $cldModule.CloudInfo
            $cBar = if ($ci.Score -ge 75) { '#16a34a' } elseif ($ci.Score -ge 50) { '#d97706' } else { '#dc2626' }
            $optHTML = ($ci.Recommendation.Options | ForEach-Object { "<li>$_</li>" }) -join ''
            $cloudBoxHTML = "<div class='cloud-score-wrap'><div class='cloud-score-bar-bg'><div class='cloud-score-bar' style='width:$($ci.Score)%;background:$cBar'></div></div><span class='cloud-score-label' style='color:$cBar'>$($ci.Score)% &mdash; $($ci.ReadinessLabel)</span></div><p style='margin:8px 0 6px;font-size:0.82rem'>$($ci.Recommendation.Description)</p><ul class='cloud-options'>$optHTML</ul>"
        }

        # HyperV rows
        $hvInfoRows = ''
        if ($isHyperVHost -and $hvModule.HVInfo.TotalVMCount -gt 0) {
            $hvInfoRows  = "<tr><td>Hosted VMs</td><td><strong style='color:#38bdf8'>$($hvModule.HVInfo.TotalVMCount) VMs ($($hvModule.HVInfo.RunningVMCount) running)</strong></td></tr>"
            $hvInfoRows += "<tr><td>VM RAM</td><td>$($hvModule.HVInfo.TotalVMRamGB) GB allocated / $($hvModule.HVInfo.HostRAMGB) GB host ($($hvModule.HVInfo.RAMPressurePct)%)</td></tr>"
            $hvInfoRows += "<tr><td>Gen1 / Gen2</td><td>$($hvModule.HVInfo.Gen1VMCount) Gen1 / $($hvModule.HVInfo.Gen2VMCount) Gen2</td></tr>"
        }

        # VM inventory table
        $vmTableHTML = ''
        if ($isHyperVHost -and $hvModule.HVInfo.VMList -and $hvModule.HVInfo.VMList.Count -gt 0) {
            $vmRows = ''
            foreach ($vm in $hvModule.HVInfo.VMList) {
                $stateColor  = if ($vm.State -eq 'Running') { '#16a34a' } else { '#94a3b8' }
                $snapWarning = if ($vm.HasSnapshots) { "<span style='color:#ea580c;font-weight:700'> &#9888; $($vm.SnapshotCount) snapshot(s)</span>" } else { '' }
                $genBadge    = if ($vm.Generation -eq 2) { "<span style='color:#38bdf8'>Gen2</span>" } else { "<span style='color:#d97706'>Gen1</span>" }
                $migStatus   = if ($vm.HasSnapshots) { "<span style='color:#ea580c'>Blocked - remove snapshots</span>" } elseif ($vm.Generation -eq 2) { "<span style='color:#16a34a'>Ready to migrate</span>" } else { "<span style='color:#d97706'>Needs migration testing</span>" }
                $vmRows += "<tr><td><strong>$($vm.Name)</strong></td><td><span style='color:$stateColor;font-weight:700'>$($vm.State)</span></td><td>$genBadge</td><td>$($vm.CPUCount)</td><td>$($vm.RAMAssignedGB) GB $(if($vm.DynamicMemory){'(Dynamic)'}else{'(Static)'})</td><td>$($vm.DiskGB) GB$snapWarning</td><td>$migStatus</td></tr>"
            }
            $vmTableHTML = "<h4 class='findings-heading'>&#9729; Virtual Machine Inventory ($($hvModule.HVInfo.TotalVMCount) VMs on this host)</h4><div class='table-scroll'><table class='findings-table'><thead><tr><th>VM Name</th><th>State</th><th>Generation</th><th>vCPUs</th><th>RAM</th><th>Disk</th><th>Cloud Migration Status</th></tr></thead><tbody>$vmRows</tbody></table></div>"
        }

        # Findings section
        $findingsSectionHTML = ''
        if ($serverFindingRows) {
            $findingsSectionHTML = "$filterBarHTML<div class='table-scroll'><table class='findings-table' id='ft_$sid'><thead><tr><th>Category</th><th>Check</th><th>Status</th><th>Severity</th><th>Description / Details</th><th>Recommendation</th></tr></thead><tbody>$serverFindingRows</tbody></table></div>"
        } else {
            $findingsSectionHTML = '<div class="all-clear"><span>&#10004;</span> No issues found on this server.</div>'
        }

        # Top priorities box
        $topPriHTML = ''
        if ($topFailsHTML -or $topWarnsHTML) {
            $failSection = ''
            $warnSection = ''
            if ($topFailsHTML) {
                $failSection = "<div class='tp-section'><div class='tp-section-label tp-label-fail'>&#10008; Active Failures <span class='tp-count'>($($topFails.Count))</span></div><ul class='tp-list'>$topFailsHTML</ul></div>"
            }
            if ($topWarnsHTML) {
                $warnSection = "<div class='tp-section'><div class='tp-section-label tp-label-warn'>&#9888; Warnings <span class='tp-count'>($($topWarns.Count))</span></div><ul class='tp-list'>$topWarnsHTML</ul></div>"
            }
            $topPriHTML = "<div class='top-priorities'><div class='tp-heading'>Top Priorities for This Server</div><div class='tp-sections'>$failSection$warnSection</div></div>"
        }

        $hvBadge = if ($isHyperVHost) { '<span class="hv-badge">HYPER-V HOST</span>' } else { '' }
        $serverTypeIcon = if ($isVirtual) { '&#9711;' } else { '&#9632;' }
        $serverTypeLabel = if (-not $isVirtual) { '(Physical)' } else { '(Virtual)' }

        $serverCardsHTML += @"
        <div class="server-card" id="$sid">
            <div class="server-card-header" onclick="toggleServer('$sid')">
                <div class="server-title-group">
                    <span class="server-icon">$serverTypeIcon</span>
                    <div>
                        <h3 class="server-name">$($sr.ComputerName)</h3>
                        <span class="server-subtitle">$osCaption &nbsp;|&nbsp; $hwModel $(if($isVirtual){'(Virtual)'})</span>
                    </div>
                </div>
                <div class="server-header-right">
                    $riskBadge
                    <div class="sev-pills-group">$pillsHTML</div>
                    <div class="risk-score-circle" style="border-color:$scoreColor;color:$scoreColor;">
                        <span class="score-number">$($sr.RiskScore)</span>
                        <span class="score-label">Risk</span>
                    </div>
                    <span class="chevron" id="chevron_$sid">&#9660;</span>
                </div>
            </div>

            <div class="server-body" id="body_$sid" style="display:none;">
                <!-- Quick Stats -->
                <div class="quick-stats">
                    <div class="qstat qstat-crit"><span class="qstat-num">$sCrit</span><span class="qstat-lbl">Critical</span></div>
                    <div class="qstat qstat-high"><span class="qstat-num">$sHigh</span><span class="qstat-lbl">High</span></div>
                    <div class="qstat qstat-med"> <span class="qstat-num">$sMed</span> <span class="qstat-lbl">Medium</span></div>
                    <div class="qstat qstat-low"> <span class="qstat-num">$sLow</span> <span class="qstat-lbl">Low</span></div>
                    <div class="qstat qstat-pass"><span class="qstat-num">$sPass</span><span class="qstat-lbl">Passed</span></div>
                </div>

                $topPriHTML

                <!-- Detail Grid -->
                <div class="detail-grid">
                    <div class="detail-box">
                        <h4>&#128421; System Info $hvBadge</h4>
                        <table class="detail-table">
                            <tr><td>Hostname</td><td><strong>$($sr.ComputerName)</strong></td></tr>
                            <tr><td>IP Address</td><td>$($sr.IPAddress)</td></tr>
                            <tr><td>OS</td><td>$osCaption</td></tr>
                            <tr><td>RAM</td><td>$totalRAM</td></tr>
                            <tr><td>CPU</td><td>$cpuCores</td></tr>
                            <tr><td>Hardware</td><td>$hwModel $serverTypeLabel</td></tr>
                            <tr><td>HW Age</td><td>$hwAge</td></tr>
                            $hvInfoRows
                            <tr><td>Scan Time</td><td>$($sr.ScanTime)</td></tr>
                        </table>
                    </div>
                    <div class="detail-box">
                        <h4>&#128190; Storage</h4>
                        $storageBoxHTML
                    </div>
                    <div class="detail-box">
                        <h4>&#9729; Cloud Readiness</h4>
                        $cloudBoxHTML
                    </div>
                </div>

                $vmTableHTML

                <!-- Findings -->
                <h4 class="findings-heading">&#128270; Findings for $($sr.ComputerName)</h4>
                $findingsSectionHTML
            </div>
        </div>
"@
    }

    # ── Full HTML Document ─────────────────────────────────────────
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>$ReportTitle</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155; --border: #475569;
    --text: #f1f5f9; --text-muted: #94a3b8; --accent: #38bdf8;
    --crit: #dc2626; --high: #ea580c; --med: #d97706; --low: #2563eb; --ok: #16a34a;
    --crit-bg: #7f1d1d22; --high-bg: #7c2d1222; --med-bg: #78350f22; --low-bg: #1e3a8a22; --ok-bg: #14532d22;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.5; }

  /* ── Header ── */
  .header { background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 50%, #0f172a 100%); border-bottom: 2px solid var(--accent); padding: 32px 40px; }
  .header-inner { max-width: 1400px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; gap: 24px; }
  .header h1 { font-size: 1.8rem; font-weight: 700; color: var(--accent); letter-spacing: -0.5px; }
  .header-meta { text-align: right; color: var(--text-muted); font-size: 0.85rem; }
  .header-meta strong { color: var(--text); display: block; font-size: 1rem; }
  .header-controls { display: flex; align-items: center; gap: 12px; margin-top: 12px; }

  /* ── Presentation Mode Button ── */
  .pres-btn { background: #1e293b; border: 2px solid #38bdf8; color: #38bdf8; padding: 8px 18px; border-radius: 8px; font-size: 0.82rem; font-weight: 700; cursor: pointer; letter-spacing: 0.3px; transition: all 0.2s; display: flex; align-items: center; gap: 6px; }
  .pres-btn:hover { background: #38bdf811; }
  .pres-btn.active { background: #38bdf8; color: #0f172a; }

  /* ── Presentation Mode: hide medium/low/info everywhere ── */
  body.pres-mode .sev-medium, body.pres-mode .sev-low, body.pres-mode .sev-info { display: none !important; }
  body.pres-mode .sev-group-med, body.pres-mode .sev-group-low { display: none !important; }
  .pres-banner { background: #0ea5e9; color: #0f172a; text-align: center; padding: 8px 16px; font-size: 0.82rem; font-weight: 700; display: none; position: sticky; top: 0; z-index: 100; }
  body.pres-mode .pres-banner { display: block; }

  /* ── Container ── */
  .container { max-width: 1400px; margin: 0 auto; padding: 24px 40px; }

  /* ── Executive Summary Cards ── */
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .summary-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }
  .summary-card .num { font-size: 2.4rem; font-weight: 800; line-height: 1; }
  .summary-card .lbl { color: var(--text-muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.8px; margin-top: 6px; }
  .card-total .num { color: var(--accent); }
  .card-crit  .num { color: var(--crit); }
  .card-high  .num { color: var(--high); }
  .card-med   .num { color: var(--med); }
  .card-low   .num { color: var(--low); }
  .card-ok    .num { color: var(--ok); }

  /* ── Section Heading ── */
  .section-heading { font-size: 1.15rem; font-weight: 600; color: var(--accent); margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 8px; }

  /* ── Server Card ── */
  .server-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 16px; overflow: hidden; }
  .server-card-header { padding: 16px 24px; cursor: pointer; display: flex; align-items: center; justify-content: space-between; transition: background 0.2s; }
  .server-card-header:hover { background: var(--surface2); }
  .server-title-group { display: flex; align-items: center; gap: 14px; }
  .server-icon { font-size: 1.4rem; color: var(--text-muted); }
  .server-name { font-size: 1.1rem; font-weight: 700; }
  .server-subtitle { font-size: 0.8rem; color: var(--text-muted); margin-top: 2px; }
  .server-header-right { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; justify-content: flex-end; }
  .chevron { font-size: 1rem; color: var(--text-muted); transition: transform 0.3s; }
  .server-body { padding: 0 24px 24px; border-top: 1px solid var(--border); animation: slideDown 0.2s ease; }
  @keyframes slideDown { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }

  /* ── Severity Pills (card header) ── */
  .sev-pills-group { display: flex; gap: 5px; flex-wrap: wrap; }
  .sev-pill { padding: 2px 8px; border-radius: 10px; font-size: 0.68rem; font-weight: 700; letter-spacing: 0.3px; white-space: nowrap; }
  .pill-crit { background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit); }
  .pill-high { background: var(--high-bg); color: var(--high); border: 1px solid var(--high); }
  .pill-med  { background: var(--med-bg);  color: var(--med);  border: 1px solid var(--med); }
  .pill-low  { background: var(--low-bg);  color: var(--low);  border: 1px solid var(--low); }
  .pill-ok   { background: var(--ok-bg);   color: var(--ok);   border: 1px solid var(--ok); }

  /* ── Risk Score Circle ── */
  .risk-score-circle { width: 56px; height: 56px; border-radius: 50%; border: 3px solid; display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0; }
  .score-number { font-size: 1.2rem; font-weight: 800; line-height: 1; }
  .score-label  { font-size: 0.55rem; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }

  /* ── Risk Badges ── */
  .risk-badge { padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; }
  .risk-critical { background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit); }
  .risk-high     { background: var(--high-bg); color: var(--high); border: 1px solid var(--high); }
  .risk-medium   { background: var(--med-bg);  color: var(--med);  border: 1px solid var(--med); }
  .risk-low      { background: var(--low-bg);  color: var(--low);  border: 1px solid var(--low); }
  .risk-healthy  { background: var(--ok-bg);   color: var(--ok);   border: 1px solid var(--ok); }

  /* ── Quick Stats ── */
  .quick-stats { display: flex; gap: 12px; flex-wrap: wrap; padding: 16px 0; }
  .qstat { padding: 10px 20px; border-radius: 8px; text-align: center; min-width: 80px; }
  .qstat-num { display: block; font-size: 1.6rem; font-weight: 800; }
  .qstat-lbl { display: block; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 2px; }
  .qstat-crit { background: var(--crit-bg); color: var(--crit); border: 1px solid #7f1d1d44; }
  .qstat-high { background: var(--high-bg); color: var(--high); border: 1px solid #7c2d1244; }
  .qstat-med  { background: var(--med-bg);  color: var(--med);  border: 1px solid #78350f44; }
  .qstat-low  { background: var(--low-bg);  color: var(--low);  border: 1px solid #1e3a8a44; }
  .qstat-pass { background: var(--ok-bg);   color: var(--ok);   border: 1px solid #14532d44; }

  /* ── Top Priorities Callout ── */
  .top-priorities { background: #111827; border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; margin: 4px 0 16px; }
  .tp-heading { font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 12px; }
  .tp-sections { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  @media (max-width: 900px) { .tp-sections { grid-template-columns: 1fr; } }
  .tp-section { display: flex; flex-direction: column; gap: 6px; }
  .tp-section-label { font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; padding: 5px 10px; border-radius: 4px; margin-bottom: 4px; display: flex; align-items: center; gap: 6px; }
  .tp-label-fail { background: #7f1d1d33; color: var(--crit); border-left: 3px solid var(--crit); }
  .tp-label-warn { background: #78350f22; color: var(--med);  border-left: 3px solid var(--med); }
  .tp-count { font-size: 0.68rem; opacity: 0.8; }
  .tp-list { list-style: none; display: flex; flex-direction: column; gap: 7px; }
  .tp-list li { font-size: 0.82rem; display: flex; align-items: baseline; flex-wrap: wrap; gap: 5px; }
  .tp-badge { padding: 1px 6px; border-radius: 3px; font-size: 0.65rem; font-weight: 700; flex-shrink: 0; }
  .tp-critical { background: var(--crit); color: white; }
  .tp-high     { background: var(--high); color: white; }
  .tp-medium   { background: var(--med);  color: white; }
  .tp-rec { color: var(--text-muted); font-size: 0.78rem; }

  /* ── Detail Grid ── */
  .detail-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin: 16px 0; }
  .detail-box { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .detail-box h4 { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.8px; color: var(--accent); margin-bottom: 12px; }
  .detail-table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
  .detail-table td { padding: 4px 0; vertical-align: top; }
  .detail-table td:first-child { color: var(--text-muted); width: 38%; padding-right: 8px; }

  /* ── Disk Bar ── */
  .disk-bar-wrap { background: var(--surface2); border-radius: 4px; height: 6px; margin: 4px 0 2px; width: 100%; }
  .disk-bar { height: 6px; border-radius: 4px; }

  /* ── Cloud ── */
  .cloud-score-wrap { margin-bottom: 12px; }
  .cloud-score-bar-bg { background: var(--surface2); border-radius: 6px; height: 10px; margin-bottom: 6px; }
  .cloud-score-bar { height: 10px; border-radius: 6px; }
  .cloud-score-label { font-size: 0.82rem; font-weight: 600; }
  .cloud-options { padding-left: 16px; font-size: 0.8rem; color: var(--text-muted); }
  .cloud-options li { margin: 2px 0; }

  /* ── Findings Heading ── */
  .findings-heading { font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.8px; color: var(--accent); margin: 20px 0 10px; }

  /* ── Server Filter Bar ── */
  .server-filter-bar { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; margin-bottom: 10px; padding: 10px 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; }
  .filter-label { color: var(--text-muted); font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-right: 2px; }
  .filter-divider { width: 1px; height: 20px; background: var(--border); margin: 0 6px; flex-shrink: 0; }
  .filter-showall { margin-left: auto; }
  .f-fail-btn.active { border-color: var(--crit); color: var(--crit); background: var(--crit-bg); }
  .f-warn-btn.active { border-color: var(--med);  color: var(--med);  background: var(--med-bg); }

  /* ── Severity Group Headers (within findings table) ── */
  .sev-group-header td { padding: 8px 12px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; }
  .sev-group-crit td { background: #7f1d1d33; color: var(--crit); border-left: 4px solid var(--crit); }
  .sev-group-high td { background: #7c2d1233; color: var(--high); border-left: 4px solid var(--high); }
  .sev-group-med  td { background: #78350f22; color: var(--med);  border-left: 4px solid var(--med); }
  .sev-group-low  td { background: #1e3a8a22; color: var(--low);  border-left: 4px solid var(--low); }

  /* ── Findings Table ── */
  .table-scroll { overflow-x: auto; }
  .findings-table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
  .findings-table th { background: var(--surface2); color: var(--text-muted); text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.8px; padding: 10px 12px; text-align: left; border-bottom: 2px solid var(--border); white-space: nowrap; }
  .findings-table td { padding: 10px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; }
  .finding-row:hover td { background: var(--surface2); }
  .finding-row.sev-critical td { border-left: 3px solid var(--crit); background: rgba(220,38,38,0.04); }
  .finding-row.sev-high     td { border-left: 3px solid var(--high); background: rgba(234,88,12,0.03); }
  .finding-row.sev-medium   td { border-left: 3px solid var(--med); }
  .finding-row.sev-low      td { border-left: 3px solid var(--low); }
  .finding-row.sev-info     td { border-left: 3px solid #334155; }
  .rec-cell { max-width: 340px; color: var(--text-muted); }
  .rec-cell a { color: var(--accent); font-size: 0.75rem; }
  .text-muted { color: var(--text-muted); }

  /* ── Severity Badges ── */
  .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.68rem; font-weight: 700; letter-spacing: 0.5px; white-space: nowrap; }
  .badge-critical { background: var(--crit); color: white; }
  .badge-high     { background: var(--high); color: white; }
  .badge-medium   { background: var(--med);  color: white; }
  .badge-low      { background: var(--low);  color: white; }
  .badge-info     { background: var(--surface2); color: var(--text-muted); }

  /* ── Status Icons ── */
  .status-pass  { color: var(--ok);   font-weight: 700; }
  .status-fail  { color: var(--crit); font-weight: 700; }
  .status-warn  { color: var(--med);  font-weight: 700; }
  .status-error { color: var(--high); font-weight: 700; }
  .status-info  { color: var(--accent); }

  /* ── Global Filter Bar ── */
  .filter-bar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; align-items: center; }
  .filter-btn { padding: 6px 14px; border-radius: 20px; border: 1px solid var(--border); background: var(--surface); color: var(--text-muted); cursor: pointer; font-size: 0.78rem; transition: all 0.2s; white-space: nowrap; }
  .filter-btn:hover { border-color: var(--accent); color: var(--accent); background: #0ea5e911; }
  .filter-btn.active { border-color: var(--accent); color: var(--accent); background: #0ea5e911; }
  .filter-btn.f-crit.active { border-color: var(--crit); color: var(--crit); background: var(--crit-bg); }
  .filter-btn.f-high.active { border-color: var(--high); color: var(--high); background: var(--high-bg); }
  .filter-btn.f-med.active  { border-color: var(--med);  color: var(--med);  background: var(--med-bg); }
  .filter-btn.f-low.active  { border-color: var(--low);  color: var(--low);  background: var(--low-bg); }
  .disabled-btn { opacity: 0.4; cursor: default; pointer-events: none; }

  /* ── HV Badge ── */
  .hv-badge { background: #0ea5e922; border: 1px solid #0ea5e9; color: #38bdf8; border-radius: 4px; font-size: 0.65rem; font-weight: 700; padding: 1px 6px; letter-spacing: 0.5px; vertical-align: middle; margin-left: 6px; }

  /* ── All Clear ── */
  .all-clear { background: var(--ok-bg); border: 1px solid var(--ok); border-radius: 8px; padding: 16px; color: var(--ok); text-align: center; font-weight: 600; margin-top: 12px; }

  /* ── Compliance Boxes ── */
  .compliance-box { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px 24px; margin-bottom: 16px; }
  .compliance-box h4 { color: var(--accent); margin-bottom: 8px; }
  .compliance-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
  .compliance-tag { background: var(--surface2); border: 1px solid var(--border); border-radius: 4px; padding: 3px 10px; font-size: 0.75rem; color: var(--text-muted); }

  /* ── Footer ── */
  .footer { text-align: center; padding: 32px; color: var(--text-muted); font-size: 0.78rem; border-top: 1px solid var(--border); margin-top: 40px; }

  @media (max-width: 768px) {
    .header-inner { flex-direction: column; gap: 12px; text-align: center; }
    .container { padding: 16px; }
    .server-card-header { flex-direction: column; gap: 12px; align-items: flex-start; }
    .server-header-right { justify-content: flex-start; }
    .detail-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<div class="pres-banner">&#128203; Presentation Mode &mdash; Showing Critical &amp; High findings only &nbsp;|&nbsp; <span style="text-decoration:underline;cursor:pointer" onclick="togglePresMode()">Click to show all findings</span></div>

<div class="header">
  <div class="header-inner">
    <div>
      <h1>&#128737; $ReportTitle</h1>
      <div style="color:#94a3b8;font-size:0.85rem;margin-top:4px;">Enterprise Infrastructure Security &amp; Compliance Assessment</div>
      <div class="header-controls">
        <button class="pres-btn" id="presBtn" onclick="togglePresMode()">&#128203; Presentation Mode</button>
        <span style="color:#475569;font-size:0.75rem">Hides Medium / Low findings &mdash; clean for client review</span>
      </div>
    </div>
    <div class="header-meta">
      <strong>$reportDate</strong>
      Frameworks: NIST SP 800-53 &bull; CIS Controls v8 &bull; DISA STIG<br>
      Servers Scanned: <strong style="color:#f1f5f9">$totalServers</strong>
    </div>
  </div>
</div>

<div class="container">

  <!-- Executive Summary -->
  <div class="section-heading">&#128202; Executive Summary</div>
  <div class="summary-grid">
    <div class="summary-card card-total"><div class="num">$totalServers</div><div class="lbl">Servers Scanned</div></div>
    <div class="summary-card card-crit"> <div class="num">$critCount</div>  <div class="lbl">Critical Findings</div></div>
    <div class="summary-card card-high"> <div class="num">$highCount</div>  <div class="lbl">High Findings</div></div>
    <div class="summary-card card-med">  <div class="num">$medCount</div>   <div class="lbl">Medium Findings</div></div>
    <div class="summary-card card-low">  <div class="num">$lowCount</div>   <div class="lbl">Low Findings</div></div>
    <div class="summary-card card-ok">   <div class="num">$healthyCount</div><div class="lbl">Healthy / Low Risk</div></div>
  </div>

  <div class="compliance-box">
    <h4>&#128270; Risk Score Methodology</h4>
    <p style="font-size:0.82rem;color:#94a3b8">Scores calculated from findings weighted by severity: Critical (40pts) &bull; High (20pts) &bull; Medium (10pts) &bull; Low (5pts). Normalized 0-100. Higher = greater risk.</p>
    <div class="compliance-tags">
      <span class="compliance-tag" style="color:#dc2626;border-color:#dc2626">&#9632; 75-100: Critical Risk</span>
      <span class="compliance-tag" style="color:#ea580c;border-color:#ea580c">&#9632; 50-74: High Risk</span>
      <span class="compliance-tag" style="color:#d97706;border-color:#d97706">&#9632; 25-49: Medium Risk</span>
      <span class="compliance-tag" style="color:#2563eb;border-color:#2563eb">&#9632; 10-24: Low Risk</span>
      <span class="compliance-tag" style="color:#16a34a;border-color:#16a34a">&#9632; 0-9: Healthy</span>
    </div>
  </div>

  <div class="compliance-box">
    <h4>&#128203; Compliance Frameworks Referenced</h4>
    <div class="compliance-tags">
      <span class="compliance-tag">NIST SP 800-53 Rev 5</span>
      <span class="compliance-tag">CIS Controls v8.1</span>
      <span class="compliance-tag">DISA STIG</span>
      <span class="compliance-tag">Microsoft Security Baseline</span>
      <span class="compliance-tag">MITRE ATT&amp;CK</span>
      <span class="compliance-tag">PCI-DSS v4.0</span>
      <span class="compliance-tag">ISO 27001:2022</span>
    </div>
  </div>

  <!-- Priority Remediation List -->
  <div class="section-heading">&#9888;&#65039; Priority Remediation List &mdash; All Findings</div>
  <div class="filter-bar">
    <span style="color:#94a3b8;font-size:0.78rem;margin-right:4px;">Filter:</span>
    <button class="filter-btn f-crit active" onclick="filterGlobal('Critical', this)">&#128308; Critical ($critCount)</button>
    <button class="filter-btn f-high active" onclick="filterGlobal('High', this)">&#128992; High ($highCount)</button>
    <button class="filter-btn f-med"         onclick="filterGlobal('Medium', this)">&#128993; Medium ($medCount)</button>
    <button class="filter-btn f-low"         onclick="filterGlobal('Low', this)">&#128309; Low ($lowCount)</button>
    <button class="filter-btn filter-showall" onclick="showAllGlobal()">Show All</button>
  </div>
  <div class="table-scroll">
  <table class="findings-table" id="all-findings-table">
    <thead>
      <tr><th>Server</th><th>Category</th><th>Check</th><th>Status</th><th>Severity</th><th>Description</th><th>Recommendation</th></tr>
    </thead>
    <tbody>$findingRowsHTML</tbody>
  </table>
  </div>

  <!-- Server Detail Cards -->
  <div class="section-heading">&#128421;&#65039; Server Detail &amp; Drill-Down</div>
  $serverCardsHTML

  <div class="footer">
    Enterprise Infrastructure Assessment Report &bull; Generated $reportDate<br>
    <a href="https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final" target="_blank" style="color:#38bdf8">NIST SP 800-53</a> &bull;
    <a href="https://www.cisecurity.org/controls/v8" target="_blank" style="color:#38bdf8">CIS Controls v8</a> &bull;
    <a href="https://public.cyber.mil/stigs/" target="_blank" style="color:#38bdf8">DISA STIGs</a><br>
    <small style="color:#475569;margin-top:6px;display:block">This report is confidential. Handle in accordance with your organization's data classification policy.</small>
  </div>

</div>

<script>
  // ── Server expand/collapse ──
  function toggleServer(sid) {
    var body    = document.getElementById('body_' + sid);
    var chevron = document.getElementById('chevron_' + sid);
    if (body.style.display === 'none') {
      body.style.display = 'block';
      chevron.style.transform = 'rotate(180deg)';
    } else {
      body.style.display = 'none';
      chevron.style.transform = 'rotate(0deg)';
    }
  }

  // ── Presentation Mode ──
  var presMode = false;
  function togglePresMode() {
    presMode = !presMode;
    var btn = document.getElementById('presBtn');
    if (presMode) {
      document.body.classList.add('pres-mode');
      btn.classList.add('active');
      btn.textContent = '✕ Exit Presentation Mode';
    } else {
      document.body.classList.remove('pres-mode');
      btn.classList.remove('active');
      btn.textContent = '📋 Presentation Mode';
    }
  }

  // ── Global findings filter ──
  var activeGlobalFilters = ['Critical','High'];

  function filterGlobal(severity, btn) {
    if (activeGlobalFilters.indexOf(severity) >= 0) {
      activeGlobalFilters = activeGlobalFilters.filter(function(f) { return f !== severity; });
      btn.classList.remove('active');
    } else {
      activeGlobalFilters.push(severity);
      btn.classList.add('active');
    }
    applyGlobalFilter();
  }

  function showAllGlobal() {
    activeGlobalFilters = ['Critical','High','Medium','Low'];
    document.querySelectorAll('.filter-bar .filter-btn').forEach(function(b) {
      if (!b.classList.contains('filter-showall')) b.classList.add('active');
    });
    applyGlobalFilter();
  }

  function applyGlobalFilter() {
    var rows = document.querySelectorAll('#all-findings-table tbody tr');
    rows.forEach(function(row) {
      var badge = row.querySelector('.badge');
      if (!badge) { row.style.display = ''; return; }
      var sevText = badge.textContent.trim();
      var show = activeGlobalFilters.length === 0 ||
        activeGlobalFilters.some(function(f) { return sevText.toUpperCase().indexOf(f.toUpperCase()) >= 0; });
      row.style.display = show ? '' : 'none';
    });
  }

  // ── Per-server findings filter ──
  var serverActiveSev    = {};  // severity filters per server
  var serverActiveStatus = {};  // status filters per server (fail/warn)

  function filterSrv(btn) {
    var sid = btn.getAttribute('data-sid');
    var sev = btn.getAttribute('data-sev');
    if (!serverActiveSev[sid]) { serverActiveSev[sid] = ['critical','high']; }
    var filters = serverActiveSev[sid];
    var idx = filters.indexOf(sev);
    if (idx >= 0) { filters.splice(idx, 1); btn.classList.remove('active'); }
    else          { filters.push(sev);       btn.classList.add('active'); }
    applyServerFilter(sid);
  }

  function filterSrvStatus(btn) {
    var sid    = btn.getAttribute('data-sid');
    var status = btn.getAttribute('data-status');
    if (!serverActiveStatus[sid]) { serverActiveStatus[sid] = ['fail','warn']; }
    var filters = serverActiveStatus[sid];
    var idx = filters.indexOf(status);
    if (idx >= 0) { filters.splice(idx, 1); btn.classList.remove('active'); }
    else          { filters.push(status);    btn.classList.add('active'); }
    applyServerFilter(sid);
  }

  function showAllSrv(sid) {
    serverActiveSev[sid]    = ['critical','high','medium','low'];
    serverActiveStatus[sid] = ['fail','warn'];
    document.querySelectorAll('[data-sid="' + sid + '"]').forEach(function(b) { b.classList.add('active'); });
    applyServerFilter(sid);
  }

  function applyServerFilter(sid) {
    var table = document.getElementById('ft_' + sid);
    if (!table) return;
    var sevFilters    = serverActiveSev[sid]    || ['critical','high'];
    var statusFilters = serverActiveStatus[sid] || ['fail','warn'];

    table.querySelectorAll('tr.finding-row').forEach(function(row) {
      var badge      = row.querySelector('.badge');
      var statusEl   = row.querySelector('[class^="status-"]');
      if (!badge) { row.style.display = ''; return; }

      var sev        = badge.textContent.trim().toLowerCase();
      var statusText = statusEl ? statusEl.textContent.trim().toLowerCase() : '';
      var isFail     = statusText.indexOf('fail') >= 0 || statusText.indexOf('error') >= 0;
      var isWarn     = statusText.indexOf('warn') >= 0;

      var sevOk = sevFilters.length === 0 || sevFilters.indexOf(sev) >= 0;
      var statusOk = statusFilters.length === 0 ||
        (isFail && statusFilters.indexOf('fail') >= 0) ||
        (isWarn && statusFilters.indexOf('warn') >= 0) ||
        (!isFail && !isWarn);  // INFO/PASS rows always visible if not filtered out by severity

      row.style.display = (sevOk && statusOk) ? '' : 'none';
    });

    // Show/hide severity group headers
    ['critical','high','medium','low'].forEach(function(g) {
      var hdrs = table.querySelectorAll('.grp-' + g + '-' + sid);
      if (!hdrs.length) return;
      var visible = sevFilters.indexOf(g) >= 0;
      hdrs.forEach(function(h) { h.style.display = visible ? '' : 'none'; });
    });
  }

  // ── Auto-expand first server with critical findings ──
  document.addEventListener('DOMContentLoaded', function() {
    // Init per-server filters — Critical+High severity active, both statuses active
    document.querySelectorAll('.server-filter-bar').forEach(function(bar) {
      var btns = bar.querySelectorAll('[data-sid]');
      if (btns.length > 0) {
        var sid = btns[0].getAttribute('data-sid');
        serverActiveSev[sid]    = ['critical','high'];
        serverActiveStatus[sid] = ['fail','warn'];
        applyServerFilter(sid);
      }
    });
    applyGlobalFilter();

    // Auto-open first critical server
    var critRows = document.querySelectorAll('tr.sev-critical');
    if (critRows.length > 0) {
      var firstCard = document.querySelector('.server-card');
      if (firstCard) { toggleServer(firstCard.id); }
    }
  });
</script>
</body>
</html>
"@

    [System.IO.File]::WriteAllText($reportFile, $html, [System.Text.Encoding]::UTF8)
    return $reportFile
}

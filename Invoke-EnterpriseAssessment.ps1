<#
.SYNOPSIS
    Enterprise Infrastructure Assessment Tool  - assesses servers for security, compliance,
    hardware lifecycle, storage capacity, Active Directory health, and cloud readiness.

.DESCRIPTION
    Scans one or more Windows servers (domain controllers, file servers, member servers)
    and produces a color-coded HTML report with risk scores, prioritized findings, and
    actionable recommendations aligned to NIST SP 800-53, CIS Controls v8, and DISA STIGs.

.PARAMETER ComputerName
    One or more server hostnames or IP addresses to scan.
    Accepts pipeline input and comma-separated values.

.PARAMETER CredentialUser
    Username for remote connections (domain\user or user@domain).
    If omitted, the current user's credentials are used.

.PARAMETER ConfigPath
    Path to AssessmentConfig.json. Defaults to .\config\AssessmentConfig.json.

.PARAMETER OutputPath
    Directory where the HTML report will be saved. Defaults to .\Reports.

.PARAMETER DiscoverFromAD
    If specified, queries Active Directory to discover all domain computers automatically.
    Requires RSAT AD module and domain connectivity.

.PARAMETER MaxParallel
    Maximum number of servers to scan simultaneously (default: 5).

.PARAMETER SkipModules
    List of module names to skip. Options: OS, Hardware, Storage, Security, AD, Performance, Cloud.

.PARAMETER OpenReport
    If specified, automatically opens the HTML report in the default browser when complete.

.EXAMPLE
    # Scan a single server
    .\Invoke-EnterpriseAssessment.ps1 -ComputerName "DC01"

.EXAMPLE
    # Scan multiple servers with stored credentials
    .\Invoke-EnterpriseAssessment.ps1 -ComputerName "DC01","FS01","APP01" -CredentialUser "DOMAIN\Admin"

.EXAMPLE
    # Scan all domain computers from AD
    .\Invoke-EnterpriseAssessment.ps1 -DiscoverFromAD -CredentialUser "DOMAIN\Admin" -MaxParallel 10

.EXAMPLE
    # Scan from a text file list
    Get-Content .\servers.txt | .\Invoke-EnterpriseAssessment.ps1

.NOTES
    Requirements:
    - PowerShell 5.1 or later
    - WinRM enabled on target servers (Enable-PSRemoting)
    - Firewall: TCP 5985 (WinRM) or 5986 (WinRM HTTPS) open between scanner and targets
    - Account with local admin rights on target servers
    - For AD checks on DCs: domain admin or equivalent
    - RSAT Active Directory module for -DiscoverFromAD switch

    Run from an elevated (admin) PowerShell session.
#>

[CmdletBinding(DefaultParameterSetName = 'Manual')]
param(
    [Parameter(ParameterSetName = 'Manual', ValueFromPipeline, Position = 0)]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [string]$CredentialUser,

    [Parameter()]
    [string]$ConfigPath = "$PSScriptRoot\config\AssessmentConfig.json",

    [Parameter()]
    [string]$OutputPath,

    [Parameter(ParameterSetName = 'AD')]
    [switch]$DiscoverFromAD,

    [Parameter()]
    [ValidateRange(1,50)]
    [int]$MaxParallel = 5,

    [Parameter()]
    [ValidateSet('OS','Hardware','Storage','Security','AD','Performance','Cloud')]
    [string[]]$SkipModules = @(),

    [Parameter()]
    [switch]$OpenReport,

    [Parameter()]
    [switch]$ExportJson,

    [Parameter()]
    [switch]$LocalScan
)

Begin {
    $ErrorActionPreference = 'Continue'
    $ProgressPreference    = 'Continue'

    # ── Banner ─────────────────────────────────────────────────────
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║     Enterprise Infrastructure Assessment Tool  v2.0          ║" -ForegroundColor Cyan
    Write-Host "  ║     NIST SP 800-53 | CIS Controls v8 | DISA STIG            ║" -ForegroundColor DarkCyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    if ($LocalScan) {
        Write-Host "  [LOCAL MODE] Running directly on this machine — WinRM not required" -ForegroundColor Green
    }
    Write-Host ""

    # ── Load Config ────────────────────────────────────────────────
    if (-not (Test-Path $ConfigPath)) {
        Write-Host "  [ERROR] Config file not found: $ConfigPath" -ForegroundColor Red
        exit 1
    }

    try {
        $configRaw = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        # Convert PSCustomObject to hashtable for easier access
        $Config = @{}
        $configRaw.PSObject.Properties | ForEach-Object {
            $Config[$_.Name] = $_.Value
        }
        # Deep convert sub-objects
        function ConvertTo-Hashtable($obj) {
            if ($obj -is [System.Management.Automation.PSCustomObject]) {
                $ht = @{}
                $obj.PSObject.Properties | ForEach-Object { $ht[$_.Name] = ConvertTo-Hashtable $_.Value }
                return $ht
            }
            elseif ($obj -is [System.Collections.IEnumerable] -and $obj -isnot [string]) {
                return @($obj | ForEach-Object { ConvertTo-Hashtable $_ })
            }
            return $obj
        }
        $Config = ConvertTo-Hashtable $configRaw
    }
    catch {
        Write-Host "  [ERROR] Failed to parse config: $_" -ForegroundColor Red
        exit 1
    }

    # ── Output Path ────────────────────────────────────────────────
    if (-not $OutputPath) {
        $OutputPath = Join-Path $PSScriptRoot $Config.Assessment.OutputPath
    }
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # ── Load Modules ───────────────────────────────────────────────
    $moduleDir = Join-Path $PSScriptRoot 'modules'
    $moduleFiles = @(
        'Invoke-OSCheck.ps1',
        'Invoke-HardwareCheck.ps1',
        'Invoke-StorageCheck.ps1',
        'Invoke-SecurityCheck.ps1',
        'Invoke-ADCheck.ps1',
        'Invoke-HyperVCheck.ps1',
        'Invoke-PerformanceCheck.ps1',
        'Invoke-CloudReadinessCheck.ps1',
        'New-HTMLReport.ps1'
    )

    foreach ($mf in $moduleFiles) {
        $mPath = Join-Path $moduleDir $mf
        if (Test-Path $mPath) {
            . $mPath
            Write-Host "  [+] Loaded module: $mf" -ForegroundColor DarkGreen
        }
        else {
            Write-Host "  [!] Module not found: $mPath" -ForegroundColor Yellow
        }
    }
    Write-Host ""

    # ── Credentials ───────────────────────────────────────────────
    $Credential = $null
    if ($LocalScan) {
        Write-Host "  [LOCAL] No credentials needed — running as current user ($env:USERDOMAIN\$env:USERNAME)" -ForegroundColor DarkGreen
    }
    elseif ($CredentialUser) {
        Write-Host "  Credential required for: $CredentialUser" -ForegroundColor Yellow
        $Credential = Get-Credential -UserName $CredentialUser -Message "Enter password for remote server access"
    }

    $allComputers    = [System.Collections.Generic.List[string]]::new()
    $allResults      = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ── Risk Score Calculator ──────────────────────────────────────
    function Get-RiskScore {
        param([array]$Findings, [hashtable]$Config)

        $weights  = $Config.RiskScoring.FindingSeverityWeights
        $rawScore = 0
        foreach ($f in $Findings) {
            if ($f.Status -notin 'PASS','INFO') {
                $w = switch ($f.Severity) {
                    'Critical' { $weights.Critical }
                    'High'     { $weights.High     }
                    'Medium'   { $weights.Medium   }
                    'Low'      { $weights.Low      }
                    default    { 0 }
                }
                $rawScore += $w
            }
        }

        $bands = $Config.RiskScoring.RiskBands

        # Normalize: cap at 200 raw points = 100 score
        $normalized = [math]::Min(100, [math]::Round(($rawScore / 200) * 100))

        $risk = if     ($normalized -ge $bands.Critical.Min) { 'Critical' }
                elseif ($normalized -ge $bands.High.Min)     { 'High' }
                elseif ($normalized -ge $bands.Medium.Min)   { 'Medium' }
                elseif ($normalized -ge $bands.Low.Min)      { 'Low' }
                else                                          { 'Healthy' }

        return @{ Score = $normalized; Risk = $risk }
    }

    # ── Server Scanner ────────────────────────────────────────────
    function Invoke-ServerScan {
        param(
            [string]$Computer,
            [PSCredential]$Credential,
            [hashtable]$Config,
            [string[]]$SkipModules,
            [switch]$LocalScan
        )

        $scanStart = Get-Date
        $result    = [PSCustomObject]@{
            ComputerName = $Computer
            IPAddress    = $null
            ScanTime     = $scanStart.ToString('yyyy-MM-dd HH:mm:ss')
            ScanStatus   = 'Unknown'
            OverallRisk  = 'Unknown'
            RiskScore    = 0
            Modules      = [System.Collections.Generic.List[PSCustomObject]]::new()
        }

        # ── Connectivity Test ──────────────────────────────────────
        if ($LocalScan) {
            Write-Host "  [~] Local scan — skipping network connectivity test" -ForegroundColor DarkGray
            $result.IPAddress = '127.0.0.1 (local)'
        }
        else {
            Write-Host "  [~] Testing connectivity to $Computer ..." -ForegroundColor DarkGray
            $pingOK = Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue
            if (-not $pingOK) {
                Write-Host "  [!] $Computer  - UNREACHABLE (ping failed)" -ForegroundColor Red
                $result.ScanStatus = 'Unreachable'
                $result.Modules.Add([PSCustomObject]@{
                    ModuleName = 'Connectivity'
                    Findings   = @([PSCustomObject]@{
                        Category = 'Connectivity'; Check = 'Network Reachability'
                        Status = 'ERROR'; Severity = 'Critical'
                        Description = "$Computer is not reachable via ICMP ping"
                        Details = 'Server may be offline, firewall blocking ICMP, or hostname is incorrect.'
                        Recommendation = 'Verify server power state, DNS resolution, and firewall rules. Confirm hostname is correct.'
                        Reference = ''
                    })
                })
                return $result
            }
            try {
                $dnsResult = [System.Net.Dns]::GetHostAddresses($Computer) | Select-Object -First 1
                $result.IPAddress = $dnsResult.IPAddressToString
            } catch { $result.IPAddress = 'N/A' }

            $winrmOK = Test-WSMan -ComputerName $Computer -ErrorAction SilentlyContinue
            if (-not $winrmOK) {
                Write-Host "  [!] $Computer  - WinRM not responding. CIM-only checks will run." -ForegroundColor Yellow
            }
        }

        $cimParams = @{ ComputerName = $Computer; ErrorAction = 'Stop' }
        if ($Credential) { $cimParams['Credential'] = $Credential }

        $result.ScanStatus = 'InProgress'
        Write-Host "  [>] Scanning $Computer ..." -ForegroundColor Cyan

        $moduleParams = @{
            ComputerName = $Computer
            Credential   = $Credential
            Config       = $Config
            LocalScan    = $LocalScan
        }

        # ── OS Check ──────────────────────────────────────────────
        if ('OS' -notin $SkipModules) {
            Write-Host "      [OS] Operating system assessment ..." -ForegroundColor DarkGray
            try {
                $osResult = Invoke-OSCheck @moduleParams
                $result.Modules.Add($osResult)
            }
            catch {
                Write-Host "      [!] OS check failed: $_" -ForegroundColor Yellow
                $result.Modules.Add([PSCustomObject]@{
                    ModuleName = 'OSCheck'; OSInfo = @{}
                    Findings = @([PSCustomObject]@{
                        Category='OS'; Check='OS Check'; Status='ERROR'; Severity='High'
                        Description="OS check failed: $_"; Details=$_.Exception.Message
                        Recommendation='Verify WMI access and credentials.'; Reference=''
                    })
                })
            }
        }

        # ── Hardware Check ────────────────────────────────────────
        if ('Hardware' -notin $SkipModules) {
            Write-Host "      [HW] Hardware assessment ..." -ForegroundColor DarkGray
            try {
                $hwResult = Invoke-HardwareCheck @moduleParams
                $result.Modules.Add($hwResult)
            }
            catch {
                Write-Host "      [!] Hardware check failed: $_" -ForegroundColor Yellow
                $result.Modules.Add([PSCustomObject]@{
                    ModuleName = 'HardwareCheck'; HardwareInfo = @{}
                    Findings = @([PSCustomObject]@{
                        Category='Hardware'; Check='Hardware Check'; Status='ERROR'; Severity='High'
                        Description="Hardware check failed"; Details=$_.Exception.Message
                        Recommendation='Verify WMI access.'; Reference=''
                    })
                })
            }
        }

        # ── Storage Check ─────────────────────────────────────────
        if ('Storage' -notin $SkipModules) {
            Write-Host "      [ST] Storage assessment ..." -ForegroundColor DarkGray
            try {
                $stgResult = Invoke-StorageCheck @moduleParams
                $result.Modules.Add($stgResult)
            }
            catch {
                Write-Host "      [!] Storage check failed: $_" -ForegroundColor Yellow
                $result.Modules.Add([PSCustomObject]@{
                    ModuleName = 'StorageCheck'; StorageInfo = @{ Disks=@(); Shares=@() }
                    Findings = @([PSCustomObject]@{
                        Category='Storage'; Check='Storage Check'; Status='ERROR'; Severity='High'
                        Description="Storage check failed"; Details=$_.Exception.Message
                        Recommendation='Verify WMI and PS remoting access.'; Reference=''
                    })
                })
            }
        }

        # ── Security Check ────────────────────────────────────────
        if ('Security' -notin $SkipModules) {
            Write-Host "      [SC] Security assessment ..." -ForegroundColor DarkGray
            try {
                $secResult = Invoke-SecurityCheck @moduleParams
                $result.Modules.Add($secResult)
            }
            catch {
                Write-Host "      [!] Security check failed: $_" -ForegroundColor Yellow
                $result.Modules.Add([PSCustomObject]@{
                    ModuleName = 'SecurityCheck'; SecurityInfo = @{}
                    Findings = @([PSCustomObject]@{
                        Category='Security'; Check='Security Check'; Status='ERROR'; Severity='High'
                        Description="Security check failed"; Details=$_.Exception.Message
                        Recommendation='Verify PS remoting and admin credentials.'; Reference=''
                    })
                })
            }
        }

        # ── AD Check ──────────────────────────────────────────────
        if ('AD' -notin $SkipModules) {
            Write-Host "      [AD] Active Directory assessment ..." -ForegroundColor DarkGray
            try {
                $adResult = Invoke-ADCheck @moduleParams
                $result.Modules.Add($adResult)
            }
            catch {
                Write-Host "      [!] AD check failed: $_" -ForegroundColor Yellow
                $result.Modules.Add([PSCustomObject]@{
                    ModuleName = 'ADCheck'; ADInfo = @{}
                    Findings = @([PSCustomObject]@{
                        Category='Active Directory'; Check='AD Check'; Status='ERROR'; Severity='Medium'
                        Description="AD check failed"; Details=$_.Exception.Message
                        Recommendation='Verify PS remoting and credentials.'; Reference=''
                    })
                })
            }
        }

        # ── Performance Check ─────────────────────────────────────
        if ('Performance' -notin $SkipModules) {
            Write-Host "      [PF] Performance assessment ..." -ForegroundColor DarkGray
            try {
                $perfResult = Invoke-PerformanceCheck @moduleParams
                $result.Modules.Add($perfResult)
            }
            catch {
                Write-Host "      [!] Performance check failed: $_" -ForegroundColor Yellow
                $result.Modules.Add([PSCustomObject]@{
                    ModuleName = 'PerformanceCheck'; PerfInfo = @{}
                    Findings = @([PSCustomObject]@{
                        Category='Performance'; Check='Performance Check'; Status='ERROR'; Severity='Medium'
                        Description="Performance check failed"; Details=$_.Exception.Message
                        Recommendation='Verify PS remoting.'; Reference=''
                    })
                })
            }
        }

        # ── Hyper-V Check ─────────────────────────────────────────
        $hvResult = $null
        if ('HyperV' -notin $SkipModules) {
            Write-Host "      [HV] Hyper-V assessment ..." -ForegroundColor DarkGray
            try {
                $hvResult = Invoke-HyperVCheck @moduleParams
                $result.Modules.Add($hvResult)
                if ($hvResult.HVInfo.IsHyperVHost) {
                    Write-Host "      [HV] Hyper-V host detected: $($hvResult.HVInfo.TotalVMCount) VM(s) found" -ForegroundColor Cyan
                }
            }
            catch {
                Write-Host "      [!] Hyper-V check failed: $_" -ForegroundColor Yellow
                $hvResult = $null
            }
        }

        # ── Cloud Readiness ───────────────────────────────────────
        if ('Cloud' -notin $SkipModules) {
            Write-Host "      [CL] Cloud readiness assessment ..." -ForegroundColor DarkGray
            try {
                $osResultForCloud  = $result.Modules | Where-Object { $_.ModuleName -eq 'OSCheck' }       | Select-Object -First 1
                $hwResultForCloud  = $result.Modules | Where-Object { $_.ModuleName -eq 'HardwareCheck' } | Select-Object -First 1
                $secResultForCloud = $result.Modules | Where-Object { $_.ModuleName -eq 'SecurityCheck' } | Select-Object -First 1
                $pfResultForCloud  = $result.Modules | Where-Object { $_.ModuleName -eq 'PerformanceCheck' } | Select-Object -First 1
                $hvResultForCloud  = $result.Modules | Where-Object { $_.ModuleName -eq 'HyperVCheck' }   | Select-Object -First 1

                if (-not $osResultForCloud)  { $osResultForCloud  = [PSCustomObject]@{ OSInfo=@{};       Findings=@() } }
                if (-not $hwResultForCloud)  { $hwResultForCloud  = [PSCustomObject]@{ HardwareInfo=@{}; Findings=@() } }
                if (-not $secResultForCloud) { $secResultForCloud = [PSCustomObject]@{ SecurityInfo=@{}; Findings=@() } }
                if (-not $pfResultForCloud)  { $pfResultForCloud  = [PSCustomObject]@{ PerfInfo=@{};     Findings=@() } }
                if (-not $hvResultForCloud)  { $hvResultForCloud  = [PSCustomObject]@{ HVInfo=@{ IsHyperVHost=$false }; Findings=@() } }

                $cloudResult = Invoke-CloudReadinessCheck -ComputerName $Computer -Config $Config `
                    -OSResult $osResultForCloud -HardwareResult $hwResultForCloud `
                    -SecurityResult $secResultForCloud -PerformanceResult $pfResultForCloud `
                    -HyperVResult $hvResultForCloud
                $result.Modules.Add($cloudResult)
            }
            catch {
                Write-Host "      [!] Cloud check failed: $_" -ForegroundColor Yellow
            }
        }

        # ── Aggregate Score ───────────────────────────────────────
        $allFindings = @()
        foreach ($mod in $result.Modules) { $allFindings += $mod.Findings }

        $scoreData          = Get-RiskScore -Findings $allFindings -Config $Config
        $result.RiskScore   = $scoreData.Score
        $result.OverallRisk = $scoreData.Risk
        $result.ScanStatus  = 'Complete'

        $scanDuration = [math]::Round(((Get-Date) - $scanStart).TotalSeconds, 1)

        $riskColor = switch ($result.OverallRisk) {
            'Critical' { 'Red' }
            'High'     { 'DarkYellow' }
            'Medium'   { 'Yellow' }
            'Low'      { 'Cyan' }
            default    { 'Green' }
        }

        Write-Host "  [✓] $Computer  - Risk: $($result.OverallRisk.ToUpper()) (Score: $($result.RiskScore)) [$scanDuration sec]" -ForegroundColor $riskColor

        return $result
    }
}

Process {
    # Collect computers from pipeline or parameter
    if ($ComputerName) {
        foreach ($c in $ComputerName) {
            if ($c.Trim()) { $allComputers.Add($c.Trim()) }
        }
    }
}

End {
    # ── AD Discovery ──────────────────────────────────────────────
    if ($DiscoverFromAD) {
        Write-Host "  [AD] Discovering computers from Active Directory ..." -ForegroundColor Cyan
        try {
            $adComputers = Get-ADComputer -Filter { OperatingSystem -like '*Server*' } -Properties OperatingSystem, LastLogonDate |
                Where-Object { $_.Enabled -eq $true } |
                Select-Object -ExpandProperty DNSHostName

            Write-Host "  [AD] Found $($adComputers.Count) server(s) in Active Directory" -ForegroundColor Green
            foreach ($c in $adComputers) {
                if ($c) { $allComputers.Add($c) }
            }
        }
        catch {
            Write-Host "  [!] AD discovery failed: $_" -ForegroundColor Red
            Write-Host "  [!] Falling back to localhost scan." -ForegroundColor Yellow
            $allComputers.Add($env:COMPUTERNAME)
        }
    }

    if ($allComputers.Count -eq 0) {
        $allComputers.Add($env:COMPUTERNAME)
    }

    # Deduplicate
    $allComputers = $allComputers | Sort-Object -Unique

    Write-Host "  Scanning $($allComputers.Count) server(s) | Max Parallel: $MaxParallel" -ForegroundColor White
    Write-Host "  Skipping modules: $(if($SkipModules){"$($SkipModules -join ', ')"}else{'None'})" -ForegroundColor DarkGray
    Write-Host ""

    # ── Parallel Scanning with Runspaces ──────────────────────────
    if ($MaxParallel -le 1 -or $allComputers.Count -eq 1) {
        # Sequential scan
        foreach ($computer in $allComputers) {
            $res = Invoke-ServerScan -Computer $computer -Credential $Credential -Config $Config -SkipModules $SkipModules -LocalScan:$LocalScan
            $allResults.Add($res)
        }
    }
    else {
        # Parallel scan using runspaces
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxParallel)
        $runspacePool.Open()

        $jobs = [System.Collections.Generic.List[hashtable]]::new()

        # Runspace scriptblock: dot-sources modules from disk (avoids string-embedding issues)
        $moduleDir  = Join-Path $PSScriptRoot 'modules'
        $riskFnPath = Join-Path $PSScriptRoot 'modules\_RiskScore.ps1'

        # Write a tiny helper file so each runspace can load it
        $riskFnCode = @'
function Get-RiskScore {
    param([array]$Findings, [hashtable]$Config)
    $weights  = $Config.RiskScoring.FindingSeverityWeights
    $rawScore = 0
    foreach ($f in $Findings) {
        if ($f.Status -notin 'PASS','INFO') {
            $w = switch ($f.Severity) {
                'Critical' { $weights.Critical }
                'High'     { $weights.High     }
                'Medium'   { $weights.Medium   }
                'Low'      { $weights.Low      }
                default    { 0 }
            }
            $rawScore += $w
        }
    }
    $bands      = $Config.RiskScoring.RiskBands
    $normalized = [math]::Min(100, [math]::Round(($rawScore / 200) * 100))
    $risk = if     ($normalized -ge $bands.Critical.Min) { 'Critical' }
            elseif ($normalized -ge $bands.High.Min)     { 'High' }
            elseif ($normalized -ge $bands.Medium.Min)   { 'Medium' }
            elseif ($normalized -ge $bands.Low.Min)      { 'Low' }
            else                                         { 'Healthy' }
    return @{ Score = $normalized; Risk = $risk }
}
'@
        [System.IO.File]::WriteAllText($riskFnPath, $riskFnCode, [System.Text.Encoding]::UTF8)

        $scanScriptBlock = {
            param($Computer, $Credential, $Config, $SkipModules, $ModuleDir)

            # Load all modules in this runspace
            Get-ChildItem $ModuleDir -Filter 'Invoke-*.ps1' |
                Where-Object { $_.Name -ne 'New-HTMLReport.ps1' } |
                ForEach-Object { . $_.FullName }
            . (Join-Path $ModuleDir '_RiskScore.ps1')

            $scanStart = Get-Date
            $result = [PSCustomObject]@{
                ComputerName = $Computer
                IPAddress    = $null
                ScanTime     = $scanStart.ToString('yyyy-MM-dd HH:mm:ss')
                ScanStatus   = 'Unknown'
                OverallRisk  = 'Unknown'
                RiskScore    = 0
                Modules      = [System.Collections.Generic.List[PSCustomObject]]::new()
            }

            $pingOK = Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue
            if (-not $pingOK) {
                $result.ScanStatus = 'Unreachable'
                $result.Modules.Add([PSCustomObject]@{
                    ModuleName = 'Connectivity'
                    Findings = @([PSCustomObject]@{
                        Category='Connectivity'; Check='Network Reachability'; Status='ERROR'; Severity='Critical'
                        Description="$Computer is not reachable"; Details='Ping failed'
                        Recommendation='Verify server is online and network accessible.'; Reference=''
                    })
                })
                return $result
            }

            try { $result.IPAddress = ([System.Net.Dns]::GetHostAddresses($Computer) | Select-Object -First 1).IPAddressToString } catch {}

            $p = @{ ComputerName = $Computer; Credential = $Credential; Config = $Config }

            if ('OS'          -notin $SkipModules) { try { $result.Modules.Add((Invoke-OSCheck @p))          } catch {} }
            if ('Hardware'    -notin $SkipModules) { try { $result.Modules.Add((Invoke-HardwareCheck @p))    } catch {} }
            if ('Storage'     -notin $SkipModules) { try { $result.Modules.Add((Invoke-StorageCheck @p))     } catch {} }
            if ('Security'    -notin $SkipModules) { try { $result.Modules.Add((Invoke-SecurityCheck @p))    } catch {} }
            if ('AD'          -notin $SkipModules) { try { $result.Modules.Add((Invoke-ADCheck @p))          } catch {} }
            if ('Performance' -notin $SkipModules) { try { $result.Modules.Add((Invoke-PerformanceCheck @p)) } catch {} }
            if ('HyperV'      -notin $SkipModules) { try { $result.Modules.Add((Invoke-HyperVCheck @p))      } catch {} }

            if ('Cloud' -notin $SkipModules) {
                try {
                    $osR  = $result.Modules | Where-Object { $_.ModuleName -eq 'OSCheck' }          | Select-Object -First 1
                    $hwR  = $result.Modules | Where-Object { $_.ModuleName -eq 'HardwareCheck' }    | Select-Object -First 1
                    $scR  = $result.Modules | Where-Object { $_.ModuleName -eq 'SecurityCheck' }    | Select-Object -First 1
                    $pfR  = $result.Modules | Where-Object { $_.ModuleName -eq 'PerformanceCheck' } | Select-Object -First 1
                    $hvR  = $result.Modules | Where-Object { $_.ModuleName -eq 'HyperVCheck' }      | Select-Object -First 1
                    if (-not $osR)  { $osR  = [PSCustomObject]@{ OSInfo=@{};       Findings=@() } }
                    if (-not $hwR)  { $hwR  = [PSCustomObject]@{ HardwareInfo=@{}; Findings=@() } }
                    if (-not $scR)  { $scR  = [PSCustomObject]@{ SecurityInfo=@{}; Findings=@() } }
                    if (-not $pfR)  { $pfR  = [PSCustomObject]@{ PerfInfo=@{};     Findings=@() } }
                    if (-not $hvR)  { $hvR  = [PSCustomObject]@{ HVInfo=@{ IsHyperVHost=$false }; Findings=@() } }
                    $cloudR = Invoke-CloudReadinessCheck -ComputerName $Computer -Config $Config `
                        -OSResult $osR -HardwareResult $hwR -SecurityResult $scR -PerformanceResult $pfR -HyperVResult $hvR
                    $result.Modules.Add($cloudR)
                } catch {}
            }

            $allF = @()
            foreach ($m in $result.Modules) { $allF += $m.Findings }
            $sd = Get-RiskScore -Findings $allF -Config $Config
            $result.RiskScore   = $sd.Score
            $result.OverallRisk = $sd.Risk
            $result.ScanStatus  = 'Complete'
            $result
        }

        foreach ($computer in $allComputers) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $runspacePool

            [void]$ps.AddScript($scanScriptBlock)
            [void]$ps.AddArgument($computer)
            [void]$ps.AddArgument($Credential)
            [void]$ps.AddArgument($Config)
            [void]$ps.AddArgument($SkipModules)
            [void]$ps.AddArgument($moduleDir)

            $jobs.Add(@{ PS = $ps; Handle = $ps.BeginInvoke(); Computer = $computer })
        }

        # Collect results
        $completed = 0
        foreach ($job in $jobs) {
            try {
                $res = $job.PS.EndInvoke($job.Handle)
                if ($res) {
                    $allResults.Add($res)
                    $completed++
                    $riskColor = switch ($res.OverallRisk) {
                        'Critical' { 'Red' } 'High' { 'DarkYellow' } 'Medium' { 'Yellow' }
                        'Low' { 'Cyan' } default { 'Green' }
                    }
                    Write-Host "  [✓] $($job.Computer)  - $($res.OverallRisk) (Score: $($res.RiskScore)) [$completed/$($allComputers.Count)]" -ForegroundColor $riskColor
                }
            }
            catch {
                Write-Host "  [!] $($job.Computer)  - Scan error: $_" -ForegroundColor Red
            }
            finally {
                $job.PS.Dispose()
            }
        }

        $runspacePool.Close()
        $runspacePool.Dispose()
    }

    # ── Generate Report ────────────────────────────────────────────
    Write-Host ""
    Write-Host "  Generating HTML report ..." -ForegroundColor Cyan

    $reportPath = New-HTMLReport -ServerResults $allResults -OutputPath $OutputPath `
        -ReportTitle $Config.Assessment.ReportTitle -Config $Config

    # ── JSON Export ───────────────────────────────────────────────
    if ($ExportJson) {
        $jsonPath = $reportPath -replace '\.html$', '.json'
        $allResults | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
        Write-Host "  [+] JSON export: $jsonPath" -ForegroundColor DarkGreen
    }

    # ── Final Summary ─────────────────────────────────────────────
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "   ASSESSMENT COMPLETE" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor DarkCyan

    $critServers = $allResults | Where-Object { $_.OverallRisk -eq 'Critical' }
    $highServers = $allResults | Where-Object { $_.OverallRisk -eq 'High' }
    $okServers   = $allResults | Where-Object { $_.OverallRisk -in 'Healthy','Low' }

    Write-Host ""
    Write-Host "   Servers Scanned : $($allResults.Count)" -ForegroundColor White
    if ($critServers) {
        Write-Host "   Critical Risk   : $($critServers.Count) server(s)  - IMMEDIATE ACTION REQUIRED" -ForegroundColor Red
        foreach ($s in $critServers) { Write-Host "     > $($s.ComputerName) (Score: $($s.RiskScore))" -ForegroundColor Red }
    }
    if ($highServers) {
        Write-Host "   High Risk       : $($highServers.Count) server(s)" -ForegroundColor DarkYellow
        foreach ($s in $highServers) { Write-Host "     > $($s.ComputerName) (Score: $($s.RiskScore))" -ForegroundColor DarkYellow }
    }
    if ($okServers) {
        Write-Host "   Healthy / Low   : $($okServers.Count) server(s)" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "   Report saved to:" -ForegroundColor White
    Write-Host "   $reportPath" -ForegroundColor Cyan
    Write-Host ""

    if ($OpenReport -and (Test-Path $reportPath)) {
        Start-Process $reportPath
    }

    return $reportPath
}

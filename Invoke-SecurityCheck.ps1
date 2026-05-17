function Invoke-SecurityCheck {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [hashtable]$Config,
        [switch]$LocalScan
    )

    $findings    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $secInfo     = @{}

    $psParams = @{ ErrorAction = 'Stop' }
    if (-not $LocalScan) {
        $psParams['ComputerName'] = $ComputerName
        if ($Credential) { $psParams['Credential'] = $Credential }
    }

    try {
        $collectBlock = {

            $out = @{}

            # ── Windows Firewall ───────────────────────────────────
            try {
                $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                $out['FirewallProfiles'] = $fw | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
            } catch {
                $out['FirewallProfiles'] = $null
                $out['FirewallError']    = $_.Exception.Message
            }

            # ── Third-Party AV Detection ───────────────────────────
            # Check for known third-party AV/EDR services before evaluating Defender.
            # If one is running, Defender being disabled/passive is correct behavior.
            try {
                $knownAVServices = [ordered]@{
                    'ntrtscan'         = 'Trend Micro'
                    'tmlisten'         = 'Trend Micro'
                    'tmccsf'           = 'Trend Micro'
                    'TMBMSRV'          = 'Trend Micro'
                    'TmPfw'            = 'Trend Micro'
                    'CSFalconService'  = 'CrowdStrike Falcon'
                    'CbDefense'        = 'VMware Carbon Black'
                    'SentinelAgent'    = 'SentinelOne'
                    'SAVService'       = 'Sophos'
                    'SepMasterService' = 'Symantec Endpoint Protection'
                    'McShield'         = 'McAfee/Trellix'
                    'masvc'            = 'McAfee/Trellix'
                    'ekrn'             = 'ESET'
                    'AVP'              = 'Kaspersky'
                    'MBAMService'      = 'Malwarebytes'
                    'CylanceSvc'       = 'Cylance'
                    'bdservicehost'    = 'Bitdefender'
                    'WRSA'             = 'Webroot'
                    'SophosNtpService' = 'Sophos'
                }
                $detectedAV = $null
                foreach ($svcName in $knownAVServices.Keys) {
                    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                    if ($svc -and $svc.Status -eq 'Running') {
                        $detectedAV = $knownAVServices[$svcName]
                        break
                    }
                }
                $out['ThirdPartyAV'] = $detectedAV
            } catch {
                $out['ThirdPartyAV'] = $null
            }

            # ── Windows Defender / AV ──────────────────────────────
            # Get-MpComputerStatus throws 0x80070002 when a third-party AV has
            # replaced Defender — run in a job with a hard timeout so it never hangs
            try {
                $mpJob = Start-Job { Get-MpComputerStatus -ErrorAction SilentlyContinue }
                $av    = $null
                if (Wait-Job $mpJob -Timeout 3) {
                    $av = Receive-Job $mpJob -ErrorAction SilentlyContinue
                }
                Remove-Job $mpJob -Force -ErrorAction SilentlyContinue
                $out['DefenderStatus'] = if ($av) {
                    $av | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled,
                        RealTimeProtectionEnabled, NISEnabled, IoavProtectionEnabled,
                        AntivirusSignatureAge, AntispywareSignatureAge, QuickScanAge, FullScanAge,
                        AMRunningMode, AMProductVersion
                } else { $null }
                $out['AVError'] = if (-not $av) { 'Defender WMI provider unavailable' } else { $null }
            } catch {
                $out['DefenderStatus'] = $null
                $out['AVError']        = $_.Exception.Message
            }

            # ── SMBv1 ──────────────────────────────────────────────
            # Registry and SMB cmdlet are instant. Get-WindowsOptionalFeature
            # runs DISM and can block for 60+ seconds on DCs — avoid it.
            try {
                $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
                if ($smbConfig -ne $null) {
                    $out['SMBv1Enabled'] = $smbConfig.EnableSMB1Protocol
                } else {
                    throw 'SmbServerConfiguration unavailable'
                }
            } catch {
                try {
                    $smb1reg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -ErrorAction SilentlyContinue
                    # SMB1 reg value: 0 = disabled, 1 or missing = enabled
                    $out['SMBv1Enabled'] = ($smb1reg -eq $null -or $smb1reg.SMB1 -ne 0)
                } catch {
                    $out['SMBv1Enabled'] = $null
                }
            }

            # ── TLS Registry Settings ──────────────────────────────
            try {
                $tls10Server = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -ErrorAction SilentlyContinue
                $tls11Server = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -ErrorAction SilentlyContinue
                $tls12Server = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -ErrorAction SilentlyContinue
                $out['TLS10_Disabled'] = if ($tls10Server) { $tls10Server.Enabled -eq 0 -or $tls10Server.DisabledByDefault -eq 1 } else { $null }
                $out['TLS11_Disabled'] = if ($tls11Server) { $tls11Server.Enabled -eq 0 -or $tls11Server.DisabledByDefault -eq 1 } else { $null }
                $out['TLS12_Enabled']  = if ($tls12Server) { $tls12Server.Enabled -eq 1 } else { $null }
            } catch {}

            # ── WDigest ───────────────────────────────────────────
            try {
                $wdigest = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue
                $out['WDigestEnabled'] = ($wdigest.UseLogonCredential -eq 1)
            } catch {
                $out['WDigestEnabled'] = $false
            }

            # ── LLMNR ──────────────────────────────────────────────
            try {
                $llmnr = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue
                $out['LLMNREnabled'] = if ($llmnr) { $llmnr.EnableMulticast -ne 0 } else { $true }
            } catch {
                $out['LLMNREnabled'] = $true
            }

            # ── Guest Account ──────────────────────────────────────
            try {
                $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
                $out['GuestEnabled'] = $guest.Enabled
            } catch {
                $out['GuestEnabled'] = $null
            }

            # ── RDP Status ─────────────────────────────────────────
            try {
                $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue
                $out['RDPEnabled']   = ($rdp.fDenyTSConnections -eq 0)
                $rdpNLA = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthenticationRequired -ErrorAction SilentlyContinue
                $out['RDPNLA']       = ($rdpNLA.UserAuthenticationRequired -eq 1)
            } catch {
                $out['RDPEnabled']   = $null
                $out['RDPNLA']       = $null
            }

            # ── Open Listening Ports ───────────────────────────────
            try {
                $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                    Select-Object LocalPort, LocalAddress, OwningProcess
                $udpListeners = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
                    Select-Object LocalPort, LocalAddress, OwningProcess
                $out['OpenTCPPorts'] = ($listeners.LocalPort | Sort-Object -Unique)
                $out['OpenUDPPorts'] = ($udpListeners.LocalPort | Sort-Object -Unique)
            } catch {
                $out['OpenTCPPorts'] = @()
                $out['OpenUDPPorts'] = @()
            }

            # ── Local Administrators ───────────────────────────────
            # Get-LocalGroupMember hangs on DCs because it recursively resolves
            # nested domain group memberships via LDAP. ADSI WinNT is instant.
            try {
                $group       = [ADSI]"WinNT://./Administrators,group"
                $members     = @($group.psbase.Invoke('Members')) | ForEach-Object {
                    try { $_.GetType().InvokeMember('Name','GetProperty',$null,$_,$null) } catch { 'Unknown' }
                }
                $out['LocalAdmins']     = $members
                $out['LocalAdminCount'] = $members.Count
            } catch {
                $out['LocalAdmins']     = @()
                $out['LocalAdminCount'] = 0
            }

            # ── Audit Policy ──────────────────────────────────────
            # Only check Logon/Logoff subcategory — /category:* fetches everything
            # and is significantly slower
            try {
                $auditResult = auditpol /get /subcategory:"Logon","Logoff","Account Logon" /r 2>$null
                $out['AuditPolicRaw'] = $auditResult
                $hasLogon = $auditResult | Where-Object { $_ -match 'Logon' -and ($_ -match 'Success' -or $_ -match 'Failure') }
                $out['AuditLogonConfigured'] = ($null -ne $hasLogon)
            } catch {
                $out['AuditLogonConfigured'] = $false
            }

            # ── AutoRun / Autoplay ────────────────────────────────
            try {
                $autorun = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue
                $out['AutoRunDisabled'] = ($autorun.NoDriveTypeAutoRun -eq 255 -or $autorun.NoDriveTypeAutoRun -eq 0xFF)
            } catch {
                $out['AutoRunDisabled'] = $false
            }

            # ── Password Policy ───────────────────────────────────
            try {
                $secPol = net accounts 2>$null
                $out['NetAccountsOutput'] = $secPol
            } catch {}

            # ── Print Spooler (PrintNightmare) ────────────────────
            try {
                $spooler = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
                $out['PrintSpoolerRunning'] = ($spooler -and $spooler.Status -eq 'Running')
            } catch {
                $out['PrintSpoolerRunning'] = $false
            }

            # ── Backup Agent Detection ────────────────────────────
            try {
                $knownBackupServices = [ordered]@{
                    'VeeamBackupSvc'          = 'Veeam Backup & Replication'
                    'VeeamAgentSvc'           = 'Veeam Agent'
                    'OBEngine'                = 'Azure Backup (MARS Agent)'
                    'WindowsAzureGuestAgent'  = 'Azure VM Agent'
                    'WBENGINE'                = 'Windows Server Backup'
                    'BackupExecAgentAccelerator' = 'Veritas Backup Exec'
                    'BackupExecJobEngine'      = 'Veritas Backup Exec'
                    'GxCVD'                   = 'Commvault'
                    'DPMRA'                   = 'Microsoft DPM Agent'
                    'stc_raw_agent'           = 'Carbonite/OpenText'
                    'ArcserveUDP'             = 'Arcserve UDP'
                    'CagService'              = 'Arcserve'
                }
                $detectedBackup = $null
                foreach ($svcName in $knownBackupServices.Keys) {
                    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                    if ($svc -and $svc.Status -eq 'Running') {
                        $detectedBackup = $knownBackupServices[$svcName]
                        break
                    }
                }
                # Fallback: check if wbadmin has backup history (Windows Server Backup)
                if (-not $detectedBackup) {
                    $wbResult = wbadmin get versions 2>$null
                    if ($wbResult -and ($wbResult | Where-Object { $_ -match 'Backup time' })) {
                        $detectedBackup = 'Windows Server Backup'
                    }
                }
                $out['BackupAgent'] = $detectedBackup
            } catch {
                $out['BackupAgent'] = $null
            }

            $out
        }
        $results = if ($LocalScan) { & $collectBlock } else { Invoke-Command @psParams -ScriptBlock $collectBlock }

        $secInfo = $results

        # ─────────────────────────────────────────────────────────
        # Process results into findings
        # ─────────────────────────────────────────────────────────

        # Firewall
        if ($results.FirewallProfiles) {
            $disabledProfiles = $results.FirewallProfiles | Where-Object { $_.Enabled -eq $false }
            if ($disabledProfiles) {
                $profileNames = ($disabledProfiles.Name) -join ', '
                $findings.Add([PSCustomObject]@{
                    Category       = 'Security'
                    Check          = 'Windows Firewall'
                    Status         = 'FAIL'
                    Severity       = 'Critical'
                    Description    = "Windows Firewall is DISABLED on profile(s): $profileNames"
                    Details        = 'Disabled firewall profiles expose all listening services to network attacks. This is a critical security gap.'
                    Recommendation = 'Re-enable Windows Firewall on all profiles immediately. If a third-party firewall is in use, verify it is active and configured. Document exception if disabled intentionally.'
                    Reference      = 'CIS Control 12.4: Establish and Maintain Architecture Diagram | NIST AC-17'
                })
            }
            else {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Security'
                    Check          = 'Windows Firewall'
                    Status         = 'PASS'
                    Severity       = 'Info'
                    Description    = 'Windows Firewall is enabled on all profiles (Domain, Private, Public)'
                    Details        = 'Firewall profiles: ' + (($results.FirewallProfiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', ')
                    Recommendation = 'Review inbound/outbound rules periodically. Remove stale rules.'
                    Reference      = ''
                })
            }
        }
        elseif ($results.FirewallError) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'Windows Firewall'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = 'Could not assess Windows Firewall status'
                Details        = $results.FirewallError
                Recommendation = 'Manually verify firewall status. Ensure Get-NetFirewallProfile is accessible remotely.'
                Reference      = ''
            })
        }

        # Antivirus / Defender
        # Logic: third-party AV running OR Defender in passive mode = protected. Defender
        # passive mode is the correct state when a third-party AV is managing the endpoint.
        $thirdPartyAV = $results.ThirdPartyAV
        $av           = $results.DefenderStatus
        $defenderMode = if ($av) { $av.AMRunningMode } else { $null }
        $defenderPassive = $defenderMode -and ($defenderMode -match 'Passive|EDR Block')

        if ($thirdPartyAV -or $defenderPassive) {
            $avName = if ($thirdPartyAV) { $thirdPartyAV } else { "third-party AV (Defender in $defenderMode)" }
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'Antivirus Protection'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = "$avName is active as the primary antivirus/EDR solution"
                Details        = "Windows Defender is passive/disabled — the correct state when a third-party security product manages endpoint protection."
                Recommendation = "Verify $avName definitions are current and real-time protection is enabled via its management console. Confirm policy is centrally managed."
                Reference      = 'CIS Control 10: Malware Defenses'
            })
        }
        elseif ($av) {
            # Defender is the only AV on this server — check its health
            if (-not $av.AntivirusEnabled -or -not $av.RealTimeProtectionEnabled) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Security'
                    Check          = 'Antivirus Protection'
                    Status         = 'FAIL'
                    Severity       = 'Critical'
                    Description    = 'NO antivirus protection detected — Defender is disabled and no third-party AV is running'
                    Details        = "AntivirusEnabled=$($av.AntivirusEnabled), RealTimeProtection=$($av.RealTimeProtectionEnabled). Unprotected servers are primary ransomware and malware targets."
                    Recommendation = 'Enable Windows Defender immediately or deploy an enterprise EDR solution (CrowdStrike, SentinelOne, Defender for Endpoint).'
                    Reference      = 'CIS Control 10: Malware Defenses'
                })
            }
            else {
                $sigAge  = $av.AntivirusSignatureAge
                $scanAge = $av.QuickScanAge
                if ($sigAge -gt 3) {
                    $findings.Add([PSCustomObject]@{
                        Category       = 'Security'
                        Check          = 'AV Signature Age'
                        Status         = 'FAIL'
                        Severity       = 'High'
                        Description    = "Windows Defender signatures are $sigAge day(s) old — outdated"
                        Details        = "Signatures older than 3 days cannot detect recently emerged malware and ransomware variants."
                        Recommendation = 'Verify Windows Update / WSUS connectivity. Force update: Update-MpSignature. Check SCCM/Defender for Endpoint deployment health.'
                        Reference      = 'CIS Control 10.2'
                    })
                }
                else {
                    $findings.Add([PSCustomObject]@{
                        Category       = 'Security'
                        Check          = 'Antivirus Protection'
                        Status         = 'PASS'
                        Severity       = 'Info'
                        Description    = "Windows Defender active. Signatures: $sigAge day(s) old. Last scan: $scanAge day(s) ago."
                        Details        = "Version: $($av.AMProductVersion). Mode: $($av.AMRunningMode)."
                        Recommendation = 'Ensure full scans run weekly. Consider upgrading to Defender for Endpoint for advanced threat protection.'
                        Reference      = ''
                    })
                }
            }
        }
        else {
            # Could not determine AV status at all
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'Antivirus Protection'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = 'Antivirus status could not be determined'
                Details        = "Windows Defender WMI provider is unavailable and no known third-party AV service was detected. $($results.AVError)"
                Recommendation = 'Manually verify antivirus protection via the management console. Confirm the AV agent is running and reporting to its central management platform.'
                Reference      = 'CIS Control 10: Malware Defenses'
            })
        }

        # SMBv1
        $smbEnabled = $false
        if ($null -ne $results.SMBv1Enabled) { $smbEnabled = [bool]$results.SMBv1Enabled }

        if ($smbEnabled) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'SMBv1 Protocol'
                Status         = 'FAIL'
                Severity       = 'Critical'
                Description    = 'SMBv1 is ENABLED  - EternalBlue vulnerability risk'
                Details        = 'SMBv1 is exploited by EternalBlue (CVE-2017-0144), used in WannaCry and NotPetya ransomware attacks that cost billions globally. Zero legitimate modern use cases for SMBv1.'
                Recommendation = 'Disable SMBv1 immediately: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force. Also disable via: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'
                Reference      = 'CVE-2017-0144 | MS17-010 | CIS Control 4.8'
            })
        }
        else {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'SMBv1 Protocol'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = 'SMBv1 is disabled'
                Details        = 'EternalBlue attack vector is mitigated.'
                Recommendation = 'Confirm SMBv2/v3 signing is enforced: Set-SmbServerConfiguration -RequireSecuritySignature $true'
                Reference      = ''
            })
        }

        # TLS
        if ($null -ne $results.TLS10_Disabled -and -not $results.TLS10_Disabled) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'TLS 1.0'
                Status         = 'FAIL'
                Severity       = 'High'
                Description    = 'TLS 1.0 is ENABLED  - deprecated and insecure'
                Details        = 'TLS 1.0 is vulnerable to POODLE and BEAST attacks. PCI-DSS, HIPAA, and most compliance frameworks require TLS 1.0 to be disabled.'
                Recommendation = 'Disable TLS 1.0 server-side via registry. Use IIS Crypto tool (Nartac Software) for guided hardening. Ensure TLS 1.2+ is enforced.'
                Reference      = 'CVE-2014-3566 (POODLE) | PCI-DSS v4.0 Req 6.4.3'
            })
        }

        if ($null -ne $results.TLS11_Disabled -and -not $results.TLS11_Disabled) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'TLS 1.1'
                Status         = 'FAIL'
                Severity       = 'High'
                Description    = 'TLS 1.1 is ENABLED  - deprecated protocol'
                Details        = 'TLS 1.1 is deprecated by RFC 8996. Most browsers and clients have removed support. Should be disabled in favor of TLS 1.2 and 1.3.'
                Recommendation = 'Disable TLS 1.1 server-side. Enforce TLS 1.2 minimum. Test applications for compatibility before disabling.'
                Reference      = 'RFC 8996 | PCI-DSS v4.0'
            })
        }

        # WDigest
        if ($results.WDigestEnabled -eq $true) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'WDigest Authentication'
                Status         = 'FAIL'
                Severity       = 'Critical'
                Description    = 'WDigest is ENABLED  - plaintext passwords stored in LSASS memory'
                Details        = 'WDigest causes Windows to store credentials in plaintext in LSASS memory. Mimikatz and similar tools can extract these directly. This is a primary credential theft attack vector.'
                Recommendation = 'Disable WDigest: Set registry HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0. Reboot required.'
                Reference      = 'NIST SP 800-53: IA-5 | CIS Control 5.4'
            })
        }
        else {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'WDigest Authentication'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = 'WDigest is disabled  - plaintext credentials not cached in LSASS'
                Details        = 'Credential theft via LSASS memory dumping is mitigated for WDigest.'
                Recommendation = 'Also consider enabling Credential Guard and Protected Users security group for defense-in-depth.'
                Reference      = ''
            })
        }

        # LLMNR
        if ($results.LLMNREnabled -eq $true) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'LLMNR (Link-Local Multicast Name Resolution)'
                Status         = 'FAIL'
                Severity       = 'High'
                Description    = 'LLMNR is ENABLED  - LLMNR/NBT-NS poisoning attack risk'
                Details        = 'LLMNR enables Responder attacks where an attacker intercepts name resolution broadcasts and captures NTLM hashes for offline cracking or relay attacks. A fundamental internal network attack vector.'
                Recommendation = 'Disable LLMNR via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Turn off multicast name resolution = Enabled'
                Reference      = 'MITRE ATT&CK T1557.001 | CIS Benchmark'
            })
        }

        # Guest Account
        if ($results.GuestEnabled -eq $true) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'Guest Account'
                Status         = 'FAIL'
                Severity       = 'High'
                Description    = 'Local Guest account is ENABLED'
                Details        = 'The enabled Guest account provides unauthenticated access and is a well-known initial access vector.'
                Recommendation = 'Disable the Guest account: Disable-LocalUser -Name Guest'
                Reference      = 'CIS Benchmark L1 | NIST IA-2'
            })
        }
        else {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'Guest Account'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = 'Local Guest account is disabled'
                Details        = 'Unauthenticated Guest access is blocked.'
                Recommendation = 'Periodically verify no other anonymous access vectors exist (null sessions, anonymous shares).'
                Reference      = ''
            })
        }

        # RDP
        if ($results.RDPEnabled -eq $true) {
            if ($results.RDPNLA -eq $false) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Security'
                    Check          = 'RDP Network Level Authentication'
                    Status         = 'FAIL'
                    Severity       = 'High'
                    Description    = 'RDP is enabled but Network Level Authentication (NLA) is DISABLED'
                    Details        = 'Without NLA, an attacker can initiate an RDP session before authenticating, enabling BlueKeep-style and credential stuffing attacks. NLA pre-authenticates before session creation.'
                    Recommendation = 'Enable NLA for RDP: Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Require NLA. Also ensure RDP is only accessible via VPN/jump host, not directly from internet.'
                    Reference      = 'CVE-2019-0708 (BlueKeep) | CIS Benchmark'
                })
            }
            else {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Security'
                    Check          = 'RDP Configuration'
                    Status         = 'PASS'
                    Severity       = 'Info'
                    Description    = 'RDP is enabled with Network Level Authentication (NLA) required'
                    Details        = 'NLA is enforced, reducing RDP pre-auth attack surface.'
                    Recommendation = 'Ensure RDP is not directly internet-accessible. Use MFA and a VPN or jump server for remote access.'
                    Reference      = ''
                })
            }
        }

        # Dangerous Open Ports
        $dangerousPorts = $Config.SecurityChecks.DangerousPorts
        $openTCP        = $results.OpenTCPPorts
        $openUDP        = $results.OpenUDPPorts

        foreach ($dp in $dangerousPorts) {
            $portNum = $dp.Port
            $isOpen  = if ($dp.Protocol -eq 'UDP') { $openUDP -contains $portNum } else { $openTCP -contains $portNum }
            if ($isOpen) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Security'
                    Check          = "Open Port: $portNum/$($dp.Protocol) ($($dp.Service))"
                    Status         = 'WARN'
                    Severity       = $dp.Severity
                    Description    = "Port $portNum/$($dp.Protocol) ($($dp.Service)) is listening"
                    Details        = "Risk: $($dp.Reason). Verify this service is intentionally exposed and properly secured."
                    Recommendation = "Validate whether $($dp.Service) on port $portNum needs to be accessible. Restrict with firewall rules to authorized source IPs only. Disable the service if not needed."
                    Reference      = 'CIS Control 4.4: Implement and Manage a Firewall on Servers'
                })
            }
        }

        # Local Admin Count
        if ($results.LocalAdminCount -gt 3) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'Local Administrators'
                Status         = 'WARN'
                Severity       = 'Medium'
                Description    = "$($results.LocalAdminCount) accounts in local Administrators group  - excessive admin rights"
                Details        = 'Excess local admin accounts increase the blast radius of a credential compromise. Principle of least privilege should apply.'
                Recommendation = 'Audit and remove unnecessary local admin accounts. Use LAPS (Local Administrator Password Solution) for managed local admin accounts. Prefer domain group-based access.'
                Reference      = 'CIS Control 5: Account Management | NIST AC-6 Least Privilege'
            })
        }

        # AutoRun
        if (-not $results.AutoRunDisabled) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'AutoRun / AutoPlay'
                Status         = 'WARN'
                Severity       = 'Low'
                Description    = 'AutoRun/AutoPlay may not be fully disabled'
                Details        = 'AutoRun can automatically execute malicious code from removable media (USB, CD).'
                Recommendation = 'Disable AutoRun via GPO: Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Turn off Autoplay = Enabled for All Drives.'
                Reference      = 'CIS Control 10.3'
            })
        }

        # Print Spooler — PrintNightmare (CVE-2021-34527)
        if ($results.PrintSpoolerRunning -eq $true) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'Print Spooler Service'
                Status         = 'WARN'
                Severity       = 'High'
                Description    = 'Print Spooler service is running on a non-print server (PrintNightmare risk)'
                Details        = 'CVE-2021-34527 (PrintNightmare) allows local privilege escalation and remote code execution via the Print Spooler service. Unless this is a dedicated print server, there is no reason to run it.'
                Recommendation = 'Disable Print Spooler on all non-print servers: Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled. If printing is required, use a dedicated print server tier.'
                Reference      = 'CVE-2021-34527 | MS-MSRC July 2021 | CIS Control 4.8'
            })
        }

        # Backup Detection
        if ($results.BackupAgent) {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'Backup Solution'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = "$($results.BackupAgent) backup agent detected and running"
                Details        = 'A backup agent is active. Verify jobs are completing successfully and test restoration procedures regularly.'
                Recommendation = 'Confirm last successful backup in the backup console. Test recovery quarterly. Ensure at least one backup copy is stored off-site or in immutable cloud storage (protects against ransomware).'
                Reference      = 'NIST SP 800-53: CP-9 | CIS Control 11: Data Recovery'
            })
        }
        else {
            $findings.Add([PSCustomObject]@{
                Category       = 'Security'
                Check          = 'Backup Solution'
                Status         = 'FAIL'
                Severity       = 'Critical'
                Description    = 'NO backup agent detected on this server'
                Details        = 'No recognized backup service is running. This server has no verified backup coverage. A ransomware attack, hardware failure, or accidental deletion would result in unrecoverable data loss.'
                Recommendation = 'Deploy a backup solution immediately: Azure Backup (MARS agent), Veeam, Windows Server Backup, or equivalent. Implement the 3-2-1 rule: 3 copies, 2 media types, 1 off-site. Use immutable storage to protect against ransomware.'
                Reference      = 'NIST SP 800-53: CP-9 | CIS Control 11: Data Recovery'
            })
        }

    }
    catch {
        $findings.Add([PSCustomObject]@{
            Category       = 'Security'
            Check          = 'Security Data Collection'
            Status         = 'ERROR'
            Severity       = 'High'
            Description    = "Failed to collect security data from $ComputerName"
            Details        = $_.Exception.Message
            Recommendation = 'Verify PowerShell remoting (WinRM) is enabled and credentials have local admin rights.'
            Reference      = ''
        })
    }

    return [PSCustomObject]@{
        ModuleName   = 'SecurityCheck'
        SecurityInfo = $secInfo
        Findings     = $findings
    }
}

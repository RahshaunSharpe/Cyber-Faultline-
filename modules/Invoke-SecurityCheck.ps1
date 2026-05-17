function Invoke-SecurityCheck {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [hashtable]$Config
    )

    $findings    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $secInfo     = @{}

    $psParams = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }
    if ($Credential) { $psParams['Credential'] = $Credential }

    try {
        $results = Invoke-Command @psParams -ScriptBlock {

            $out = @{}

            # ── Windows Firewall ───────────────────────────────────
            try {
                $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                $out['FirewallProfiles'] = $fw | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
            } catch {
                $out['FirewallProfiles'] = $null
                $out['FirewallError']    = $_.Exception.Message
            }

            # ── Windows Defender / AV ──────────────────────────────
            try {
                $av = Get-MpComputerStatus -ErrorAction SilentlyContinue
                $out['DefenderStatus'] = $av | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled,
                    RealTimeProtectionEnabled, NISEnabled, IoavProtectionEnabled,
                    AntivirusSignatureAge, AntispywareSignatureAge, QuickScanAge, FullScanAge,
                    AMRunningMode, AMProductVersion
            } catch {
                $out['DefenderStatus'] = $null
                $out['AVError']        = $_.Exception.Message
            }

            # ── SMBv1 ──────────────────────────────────────────────
            try {
                $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
                $out['SMBv1Feature'] = $smb1.State
            } catch {
                try {
                    $smb1reg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -ErrorAction SilentlyContinue
                    $out['SMBv1Reg'] = $smb1reg.SMB1
                } catch {
                    $out['SMBv1'] = 'Unknown'
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
            try {
                $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
                $out['LocalAdmins']      = $admins | Select-Object Name, ObjectClass, PrincipalSource
                $out['LocalAdminCount']  = ($admins | Measure-Object).Count
            } catch {
                $out['LocalAdmins']     = @()
                $out['LocalAdminCount'] = 0
            }

            # ── Audit Policy ──────────────────────────────────────
            try {
                $auditResult = auditpol /get /category:* /r 2>$null
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

            $out
        }

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
        if ($results.DefenderStatus) {
            $av = $results.DefenderStatus
            if (-not $av.AntivirusEnabled -or -not $av.RealTimeProtectionEnabled) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Security'
                    Check          = 'Antivirus Protection'
                    Status         = 'FAIL'
                    Severity       = 'Critical'
                    Description    = 'Windows Defender antivirus or real-time protection is DISABLED'
                    Details        = "AntivirusEnabled=$($av.AntivirusEnabled), RealTimeProtection=$($av.RealTimeProtectionEnabled). Unprotected servers are primary ransomware and malware targets."
                    Recommendation = 'Enable Windows Defender or install and configure an enterprise EDR solution (e.g., Microsoft Defender for Endpoint, CrowdStrike, SentinelOne).'
                    Reference      = 'CIS Control 10: Malware Defenses'
                })
            }
            else {
                $sigAge = $av.AntivirusSignatureAge
                $scanAge = $av.QuickScanAge

                if ($sigAge -gt 3) {
                    $findings.Add([PSCustomObject]@{
                        Category       = 'Security'
                        Check          = 'AV Signature Age'
                        Status         = 'FAIL'
                        Severity       = 'High'
                        Description    = "Antivirus signatures are $sigAge day(s) old  - outdated"
                        Details        = "Signatures older than 3 days cannot detect recently emerged malware and ransomware variants."
                        Recommendation = 'Verify Windows Update / WSUS connectivity. Force signature update: Update-MpSignature. Check SCCM/Defender for Endpoint deployment health.'
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

        # SMBv1
        $smbEnabled = $false
        if ($results.SMBv1Feature -eq 'Enabled') { $smbEnabled = $true }
        if ($null -ne $results.SMBv1Reg -and $results.SMBv1Reg -eq 1) { $smbEnabled = $true }

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

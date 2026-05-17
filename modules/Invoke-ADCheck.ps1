function Invoke-ADCheck {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [hashtable]$Config,
        [bool]$IsDomainController = $false,
        [switch]$LocalScan
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $adInfo   = @{}

    $psParams = @{ ErrorAction = 'Stop' }
    if (-not $LocalScan) {
        $psParams['ComputerName'] = $ComputerName
        if ($Credential) { $psParams['Credential'] = $Credential }
    }

    # ── Is it even joined to a domain? ────────────────────────────
    try {
        $csResult = Invoke-Command @psParams -ScriptBlock {
            $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                DomainRole     = $cs.DomainRole
                Domain         = $cs.Domain
                PartOfDomain   = $cs.PartOfDomain
            }
        }

        $adInfo['DomainRole']   = $csResult.DomainRole
        $adInfo['Domain']       = $csResult.Domain
        $adInfo['PartOfDomain'] = $csResult.PartOfDomain

        # DomainRole: 0=StandaloneWS, 1=MemberWS, 2=StandaloneServer, 3=MemberServer, 4=BackupDC, 5=PrimaryDC
        $roleMap = @{
            0 = 'Standalone Workstation'
            1 = 'Member Workstation'
            2 = 'Standalone Server'
            3 = 'Member Server'
            4 = 'Backup Domain Controller'
            5 = 'Primary Domain Controller'
        }
        $adInfo['RoleName'] = $roleMap[$csResult.DomainRole]
        $IsDomainController = ($csResult.DomainRole -in 4, 5)

        if (-not $csResult.PartOfDomain) {
            # Check if this is a Hyper-V host - standalone is expected and by design
            $isHyperVHost = $false
            try {
                $hvCheck = Invoke-Command @psParams -ScriptBlock {
                    $svc = Get-Service -Name 'vmms' -ErrorAction SilentlyContinue
                    $svc -and $svc.Status -eq 'Running'
                } -ErrorAction SilentlyContinue
                $isHyperVHost = ($hvCheck -eq $true)
            } catch {}

            if ($isHyperVHost) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Active Directory'
                    Check          = 'Domain Membership'
                    Status         = 'PASS'
                    Severity       = 'Info'
                    Description    = "Server is standalone (workgroup) - expected configuration for a dedicated Hyper-V host"
                    Details        = "Domain role: $($roleMap[$csResult.DomainRole]). Hyper-V hosts are intentionally kept out of the domain as a security best practice (Tier 0 isolation). The hosted VMs handle domain membership independently."
                    Recommendation = 'Ensure local Administrator account uses a strong unique password (LAPS equivalent for standalone). Limit who has local admin rights on the host. This standalone status is correct.'
                    Reference      = 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group'
                })
            } else {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Active Directory'
                    Check          = 'Domain Membership'
                    Status         = 'WARN'
                    Severity       = 'Medium'
                    Description    = "Server is NOT joined to a domain (Standalone mode)"
                    Details        = "Domain role: $($roleMap[$csResult.DomainRole]). Standalone servers cannot benefit from centralized policy, authentication, or audit."
                    Recommendation = 'Join server to Active Directory domain for centralized management, GPO enforcement, and authentication. If intentionally standalone, implement local security policy hardening.'
                    Reference      = 'CIS Control 5: Account Management'
                })
            }
            return [PSCustomObject]@{ ModuleName = 'ADCheck'; ADInfo = $adInfo; Findings = $findings }
        }
        else {
            $findings.Add([PSCustomObject]@{
                Category       = 'Active Directory'
                Check          = 'Domain Membership'
                Status         = 'PASS'
                Severity       = 'Info'
                Description    = "Server is domain-joined: $($csResult.Domain) ($($roleMap[$csResult.DomainRole]))"
                Details        = 'Centralized management and GPO enforcement is available.'
                Recommendation = 'Verify GPO is actively applied: gpresult /r. Confirm domain trust is healthy.'
                Reference      = ''
            })
        }
    }
    catch {
        $findings.Add([PSCustomObject]@{
            Category       = 'Active Directory'
            Check          = 'AD Data Collection'
            Status         = 'ERROR'
            Severity       = 'High'
            Description    = "Could not collect AD information from $ComputerName"
            Details        = $_.Exception.Message
            Recommendation = 'Verify PowerShell remoting and credentials.'
            Reference      = ''
        })
        return [PSCustomObject]@{ ModuleName = 'ADCheck'; ADInfo = $adInfo; Findings = $findings }
    }

    # ── DC-Specific Checks ─────────────────────────────────────────
    if ($IsDomainController) {
        try {
            $dcResults = Invoke-Command @psParams -ScriptBlock {

                $out = @{}

                # Domain / Forest Functional Level
                try {
                    $domain = Get-ADDomain -ErrorAction SilentlyContinue
                    $forest = Get-ADForest -ErrorAction SilentlyContinue
                    $out['DomainFunctionalLevel']  = $domain.DomainMode.ToString()
                    $out['ForestFunctionalLevel']  = $forest.ForestMode.ToString()
                    $out['DomainName']             = $domain.DNSRoot
                    $out['PDCEmulator']            = $domain.PDCEmulator
                    $out['RIDMaster']              = $domain.RIDMaster
                    $out['InfrastructureMaster']   = $domain.InfrastructureMaster
                    $out['SchemaMaster']           = $forest.SchemaMaster
                    $out['DomainNamingMaster']     = $forest.DomainNamingMaster
                } catch {
                    $out['ADModuleError'] = $_.Exception.Message
                }

                # Password Policy
                try {
                    $pp = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
                    $out['PasswordPolicy'] = [PSCustomObject]@{
                        MinLength            = $pp.MinPasswordLength
                        MaxAge               = $pp.MaxPasswordAge.Days
                        MinAge               = $pp.MinPasswordAge.Days
                        History              = $pp.PasswordHistoryCount
                        Complexity           = $pp.ComplexityEnabled
                        LockoutThreshold     = $pp.LockoutThreshold
                        LockoutDuration      = $pp.LockoutDuration.TotalMinutes
                        ReversibleEncryption = $pp.ReversibleEncryptionEnabled
                    }
                } catch {
                    $out['PasswordPolicyError'] = $_.Exception.Message
                }

                # Stale Accounts
                try {
                    $staleDate = (Get-Date).AddDays(-90)
                    $staleUsers     = (Get-ADUser -Filter { LastLogonDate -lt $staleDate -and Enabled -eq $true } -Properties LastLogonDate -ErrorAction SilentlyContinue | Measure-Object).Count
                    $staleComputers = (Get-ADComputer -Filter { LastLogonDate -lt $staleDate -and Enabled -eq $true } -Properties LastLogonDate -ErrorAction SilentlyContinue | Measure-Object).Count
                    $out['StaleUsers']     = $staleUsers
                    $out['StaleComputers'] = $staleComputers
                } catch {
                    $out['StaleAccountError'] = $_.Exception.Message
                }

                # Privileged Groups
                try {
                    $daCount  = (Get-ADGroupMember 'Domain Admins'  -Recursive -ErrorAction SilentlyContinue | Measure-Object).Count
                    $eaCount  = (Get-ADGroupMember 'Enterprise Admins' -Recursive -ErrorAction SilentlyContinue | Measure-Object).Count
                    $saCount  = (Get-ADGroupMember 'Schema Admins'  -Recursive -ErrorAction SilentlyContinue | Measure-Object).Count
                    $buaCount = (Get-ADGroupMember 'Builtin\Administrators' -Recursive -ErrorAction SilentlyContinue | Measure-Object).Count
                    $out['DomainAdminCount']      = $daCount
                    $out['EnterpriseAdminCount']  = $eaCount
                    $out['SchemaAdminCount']       = $saCount
                    $out['BuiltinAdminCount']      = $buaCount
                } catch {
                    $out['PrivGroupError'] = $_.Exception.Message
                }

                # Replication health
                try {
                    $replSummary = repadmin /replsummary 2>$null
                    $replErrors  = $replSummary | Where-Object { $_ -match 'error|fail' }
                    $out['ReplicationErrors']   = ($replErrors | Measure-Object).Count
                    $out['ReplicationSummary']  = ($replSummary -join "`n") | Select-Object -First 30
                } catch {
                    $out['ReplicationCheckError'] = $_.Exception.Message
                }

                # SYSVOL / NETLOGON shares
                try {
                    $sysvolShare   = Get-SmbShare -Name 'SYSVOL'  -ErrorAction SilentlyContinue
                    $netlogonShare = Get-SmbShare -Name 'NETLOGON' -ErrorAction SilentlyContinue
                    $out['SYSVOLShared']   = ($null -ne $sysvolShare)
                    $out['NETLOGONShared'] = ($null -ne $netlogonShare)
                } catch {
                    $out['SYSVOLError'] = $_.Exception.Message
                }

                # Krbtgt password age
                try {
                    $krbtgt     = Get-ADUser -Filter { SamAccountName -eq 'krbtgt' } -Properties PasswordLastSet -ErrorAction SilentlyContinue
                    $krbtgtAge  = if ($krbtgt.PasswordLastSet) { [math]::Round(((Get-Date) - $krbtgt.PasswordLastSet).TotalDays) } else { 9999 }
                    $out['KrbtgtPasswordAgeDays'] = $krbtgtAge
                } catch {
                    $out['KrbtgtError'] = $_.Exception.Message
                }

                $out
            }

            $adInfo = $adInfo + $dcResults

            # ── Domain Functional Level ────────────────────────────
            $dfl = $dcResults.DomainFunctionalLevel
            if ($dfl) {
                $legacyLevels = @('Windows2000Domain','Windows2003Domain','Windows2008Domain','Windows2008R2Domain','Windows2012Domain')
                if ($legacyLevels -contains $dfl) {
                    $findings.Add([PSCustomObject]@{
                        Category       = 'Active Directory'
                        Check          = 'Domain Functional Level'
                        Status         = 'FAIL'
                        Severity       = 'High'
                        Description    = "Domain Functional Level is '$dfl'  - outdated"
                        Details        = 'Low functional levels prevent use of modern AD features: Protected Users group, Kerberos armoring, dynamic access control, and Entra ID hybrid capabilities.'
                        Recommendation = 'Raise Domain Functional Level after removing all DCs running older OS. Target Windows Server 2016 or higher. Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels'
                        Reference      = 'NIST SP 800-53: IA-2 | CIS AD Benchmark'
                    })
                }
                else {
                    $findings.Add([PSCustomObject]@{
                        Category       = 'Active Directory'
                        Check          = 'Domain Functional Level'
                        Status         = 'PASS'
                        Severity       = 'Info'
                        Description    = "Domain Functional Level: $dfl"
                        Details        = 'Modern domain functional level supports current AD security features.'
                        Recommendation = 'Ensure forest functional level matches. Consider raising to 2016+ if eligible.'
                        Reference      = ''
                    })
                }
            }

            # ── Password Policy ────────────────────────────────────
            $pp = $dcResults.PasswordPolicy
            if ($pp) {
                $ppIssues = @()
                if ($pp.MinLength -lt 12)            { $ppIssues += "Minimum length is $($pp.MinLength) (recommend 14+)" }
                if (-not $pp.Complexity)              { $ppIssues += 'Complexity is not required' }
                if ($pp.MaxAge -eq 0)                 { $ppIssues += 'Passwords never expire' }
                if ($pp.MaxAge -gt 90 -and $pp.MaxAge -gt 0) { $ppIssues += "Password max age is $($pp.MaxAge) days (recommend 60-90)" }
                if ($pp.History -lt 10)               { $ppIssues += "Password history is only $($pp.History) (recommend 24+)" }
                if ($pp.LockoutThreshold -eq 0)       { $ppIssues += 'Account lockout is NOT configured  - brute force risk' }
                if ($pp.LockoutThreshold -gt 10)      { $ppIssues += "Lockout threshold is $($pp.LockoutThreshold) attempts (recommend 5 or less)" }
                if ($pp.ReversibleEncryption)         { $ppIssues += 'Reversible encryption is enabled  - stores passwords insecurely' }

                if ($ppIssues.Count -gt 0) {
                    $sev = if ($ppIssues -match 'lockout|Complexity|length') { 'High' } else { 'Medium' }
                    $findings.Add([PSCustomObject]@{
                        Category       = 'Active Directory'
                        Check          = 'Password Policy'
                        Status         = 'FAIL'
                        Severity       = $sev
                        Description    = "Default Domain Password Policy has $($ppIssues.Count) weakness(es)"
                        Details        = $ppIssues -join ' | '
                        Recommendation = 'Strengthen password policy: 14+ character minimum, complexity required, 24+ history, 5 lockout attempts, 30-min lockout duration. Consider adopting NIST 800-63B guidance: favor length over complexity, check passwords against breach databases.'
                        Reference      = 'NIST SP 800-63B | CIS Control 5.2'
                    })
                }
                else {
                    $findings.Add([PSCustomObject]@{
                        Category       = 'Active Directory'
                        Check          = 'Password Policy'
                        Status         = 'PASS'
                        Severity       = 'Info'
                        Description    = "Password policy meets baseline requirements"
                        Details        = "MinLength=$($pp.MinLength), Complexity=$($pp.Complexity), MaxAge=$($pp.MaxAge)d, History=$($pp.History), Lockout=$($pp.LockoutThreshold)"
                        Recommendation = 'Review against NIST 800-63B and implement Fine-Grained Password Policies for privileged accounts.'
                        Reference      = ''
                    })
                }
            }

            # ── Stale Accounts ─────────────────────────────────────
            $staleUsers = $dcResults.StaleUsers
            $stalePCs   = $dcResults.StaleComputers
            if ($staleUsers -gt 20) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Active Directory'
                    Check          = 'Stale User Accounts'
                    Status         = 'FAIL'
                    Severity       = 'High'
                    Description    = "$staleUsers enabled user accounts have not logged in for 90+ days"
                    Details        = 'Stale accounts are a significant attack surface: dormant accounts can be compromised without detection and used for lateral movement or data theft.'
                    Recommendation = 'Audit stale accounts: Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly. Disable after 90 days, delete after 180 days. Automate with AD cleanup scripts or Microsoft Entra Identity Governance.'
                    Reference      = 'CIS Control 5.3 | NIST IA-4'
                })
            }
            elseif ($staleUsers -gt 5) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Active Directory'
                    Check          = 'Stale User Accounts'
                    Status         = 'WARN'
                    Severity       = 'Medium'
                    Description    = "$staleUsers user account(s) inactive for 90+ days"
                    Details        = 'Moderate number of stale accounts detected.'
                    Recommendation = 'Review and disable inactive accounts. Implement automated quarterly account review process.'
                    Reference      = 'CIS Control 5.3'
                })
            }

            # ── Privileged Groups ──────────────────────────────────
            $daCount = $dcResults.DomainAdminCount
            if ($daCount -gt 5) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Active Directory'
                    Check          = 'Domain Admins Count'
                    Status         = 'FAIL'
                    Severity       = 'High'
                    Description    = "$daCount accounts in Domain Admins group  - excessive privileged access"
                    Details        = 'Domain Admin is the highest privilege in the domain. Each DA account is a potential complete domain compromise if credentials are stolen. Ideal count is 2-5 break-glass accounts.'
                    Recommendation = 'Reduce Domain Admins to 2-5 dedicated admin accounts. Use Tier 0/1/2 admin model. Implement Privileged Access Workstations (PAW). Consider Microsoft Entra Privileged Identity Management (PIM) for Just-in-Time access.'
                    Reference      = 'CIS Control 5.4 | NIST AC-6'
                })
            }

            # ── Krbtgt Password Age ────────────────────────────────
            $krbtgtAge = $dcResults.KrbtgtPasswordAgeDays
            if ($krbtgtAge -gt 365) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Active Directory'
                    Check          = 'Krbtgt Account Password Age'
                    Status         = 'FAIL'
                    Severity       = 'High'
                    Description    = "krbtgt account password is $krbtgtAge days old  - Golden Ticket risk"
                    Details        = 'A stale krbtgt password means any Golden Ticket generated from a prior compromise remains valid indefinitely. Microsoft recommends rotating krbtgt annually at minimum, or immediately after any suspected compromise.'
                    Recommendation = 'Rotate krbtgt password twice (spaced 10 hours apart to allow replication). Use the krbtgt reset script from Microsoft: https://github.com/microsoft/New-KrbtgtKeys.ps1'
                    Reference      = 'Microsoft Security Advisory | NIST IR-4'
                })
            }
            elseif ($krbtgtAge -gt 180) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Active Directory'
                    Check          = 'Krbtgt Account Password Age'
                    Status         = 'WARN'
                    Severity       = 'Medium'
                    Description    = "krbtgt account password is $krbtgtAge days old  - consider rotation"
                    Details        = "Password last set $krbtgtAge days ago. Annual rotation recommended."
                    Recommendation = 'Schedule krbtgt password rotation within 60 days.'
                    Reference      = ''
                })
            }
            else {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Active Directory'
                    Check          = 'Krbtgt Account Password Age'
                    Status         = 'PASS'
                    Severity       = 'Info'
                    Description    = "krbtgt password rotated $krbtgtAge days ago"
                    Details        = 'Within acceptable rotation window.'
                    Recommendation = 'Continue annual rotation schedule.'
                    Reference      = ''
                })
            }

            # ── Replication Health ─────────────────────────────────
            $replErrors = $dcResults.ReplicationErrors
            if ($null -ne $replErrors) {
                if ($replErrors -gt 0) {
                    $findings.Add([PSCustomObject]@{
                        Category       = 'Active Directory'
                        Check          = 'AD Replication Health'
                        Status         = 'FAIL'
                        Severity       = 'Critical'
                        Description    = "AD replication shows $replErrors error(s)"
                        Details        = 'Replication failures cause divergent domain states, authentication failures, and GPO inconsistencies. Left unresolved, can lead to USN rollback.'
                        Recommendation = "Run: repadmin /showrepl /errorsonly to identify failing partners. Check event log (Directory Service) for errors 1311, 1388, 1925, 2042. Verify network connectivity between DCs."
                        Reference      = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/replication-error-8453'
                    })
                }
                else {
                    $findings.Add([PSCustomObject]@{
                        Category       = 'Active Directory'
                        Check          = 'AD Replication Health'
                        Status         = 'PASS'
                        Severity       = 'Info'
                        Description    = 'AD replication appears healthy (no errors detected)'
                        Details        = 'Replication summary shows no failures.'
                        Recommendation = 'Run repadmin /replsummary weekly. Monitor AD replication via SCOM or Azure Monitor.'
                        Reference      = ''
                    })
                }
            }

            # ── SYSVOL / NETLOGON ──────────────────────────────────
            if ($dcResults.SYSVOLShared -eq $false) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'Active Directory'
                    Check          = 'SYSVOL Share'
                    Status         = 'FAIL'
                    Severity       = 'Critical'
                    Description    = 'SYSVOL share is NOT present on this Domain Controller'
                    Details        = 'Missing SYSVOL prevents GPO delivery to all domain clients, causing authentication and policy failures across the entire domain.'
                    Recommendation = 'Check and repair SYSVOL replication: net share sysvol. Review DFSR or FRS status. This is a domain-critical issue requiring immediate remediation.'
                    Reference      = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/rebuild-sysvol-tree-and-content-in-a-domain'
                })
            }
        }
        catch {
            $findings.Add([PSCustomObject]@{
                Category       = 'Active Directory'
                Check          = 'DC-Specific Checks'
                Status         = 'ERROR'
                Severity       = 'High'
                Description    = "DC-specific AD checks failed on $ComputerName"
                Details        = $_.Exception.Message
                Recommendation = 'Ensure RSAT AD PowerShell module is installed on the DC. Verify credentials have Domain Admin rights for AD queries.'
                Reference      = ''
            })
        }
    }

    return [PSCustomObject]@{
        ModuleName = 'ADCheck'
        ADInfo     = $adInfo
        Findings   = $findings
    }
}

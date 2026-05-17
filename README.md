# Enterprise Infrastructure Assessment Tool
### Complete Usage Guide

---

## What This Tool Does

Scans your Windows servers and produces a single HTML report that tells you:

- Which servers are a security risk and exactly why
- Which servers are running outdated or end-of-life operating systems
- Which hard drives and file shares are running full
- How old your hardware is and when it needs replacing
- Whether your Active Directory is healthy
- Whether your servers are ready to move to cloud (Azure / AWS) or need work first
- For Hyper-V hosts — a full inventory of every VM and whether each one is ready to migrate

You run it from **one machine**. It reaches out to all your servers remotely. You never log into the servers themselves.

---

## Before You Start

### What You Need

| Requirement | Details |
|---|---|
| **Your scanner machine** | Any Windows PC or server you are already logged into as an admin |
| **PowerShell 5.1 or later** | Already installed on Windows 10 / Server 2016 and newer |
| **Network access** | Your scanner machine must be able to reach the target servers on port **5985** (WinRM) |
| **Admin credentials** | Local admin on standalone/Hyper-V servers. Domain admin for domain-joined servers. |

---

## One-Time Setup on Each Server You Want to Scan

You only do this once per server. Either log in directly or use an existing RDP session.

**On domain-joined servers (DCs, file servers, member servers):**
```powershell
Enable-PSRemoting -Force
```
> Many domains already have this enabled via Group Policy. Try scanning first — if it works, you don't need to do anything.

**On your Hyper-V host (workgroup/standalone):**
```powershell
Enable-PSRemoting -Force
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -Enabled True
```

**On your scanner machine — only needed if scanning a workgroup/standalone server:**
```powershell
# Replace HYPERV-HOST01 with your actual Hyper-V hostname or IP
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "HYPERV-HOST01" -Force
```

---

## Running the Scanner

Open **PowerShell as Administrator** on your scanner machine, then navigate to this folder:

```powershell
cd "C:\Users\ctadmin\Documents\ServerAsses"
```

---

### Scenario 1 — Scan a Single Server

```powershell
.\Invoke-EnterpriseAssessment.ps1 -ComputerName "DC01" -OpenReport
```

The report opens automatically in your browser when done.

---

### Scenario 2 — Scan Multiple Servers at Once

```powershell
.\Invoke-EnterpriseAssessment.ps1 -ComputerName "DC01","DC02","FS01","APP01" -OpenReport
```

All results appear in one report, side by side.

---

### Scenario 3 — Scan the Hyper-V Host

The Hyper-V host uses its own local admin account, not a domain account.

```powershell
.\Invoke-EnterpriseAssessment.ps1 -ComputerName "HYPERV-HOST01" -CredentialUser "HYPERV-HOST01\Administrator" -OpenReport
```

A password prompt will appear. Enter the local Administrator password for that host.

The report will show:
- Physical hardware age and lifecycle status
- Every VM hosted on it (name, state, Gen1/Gen2, RAM, disk, snapshot status)
- Whether each VM is ready to migrate to cloud or has blockers
- Cloud migration steps specific to Hyper-V (Azure Migrate, AWS MGN)

---

### Scenario 4 — Scan the Domain VMs (DCs, File Servers, etc.)

```powershell
.\Invoke-EnterpriseAssessment.ps1 -ComputerName "DC01","DC02","FS01" -CredentialUser "YOURDOMAIN\Administrator" -OpenReport
```

Replace `YOURDOMAIN` with your actual domain name. A password prompt appears once and is used for all listed servers.

---

### Scenario 5 — Scan Everything in Your Environment

Run two commands — one for the Hyper-V host, one for everything else. Two separate reports are generated.

```powershell
# Report 1 — Physical host
.\Invoke-EnterpriseAssessment.ps1 -ComputerName "HYPERV-HOST01" -CredentialUser "HYPERV-HOST01\Administrator" -OpenReport

# Report 2 — All domain VMs
.\Invoke-EnterpriseAssessment.ps1 -ComputerName "DC01","DC02","FS01","APP01" -CredentialUser "YOURDOMAIN\Administrator" -OpenReport
```

---

### Scenario 6 — Scan All Domain Servers Automatically (Discovers from Active Directory)

If you have many servers and don't want to type them all out:

```powershell
.\Invoke-EnterpriseAssessment.ps1 -DiscoverFromAD -CredentialUser "YOURDOMAIN\Administrator" -OpenReport
```

This queries Active Directory for every server and scans them all.

---

### Scenario 7 — Scan Faster with Parallel Scanning

By default the tool scans 5 servers at the same time. You can increase this:

```powershell
.\Invoke-EnterpriseAssessment.ps1 -ComputerName "DC01","DC02","FS01","APP01","WEB01","SQL01" -CredentialUser "YOURDOMAIN\Administrator" -MaxParallel 10 -OpenReport
```

---

### Scenario 8 — Skip Certain Checks

If you want to skip specific checks (for example, skip Active Directory checks on non-DC servers):

```powershell
.\Invoke-EnterpriseAssessment.ps1 -ComputerName "WEB01" -SkipModules AD,HyperV -OpenReport
```

Available modules to skip: `OS`, `Hardware`, `Storage`, `Security`, `AD`, `HyperV`, `Performance`, `Cloud`

---

### Scenario 9 — Also Export Raw Data as JSON

Useful if you want to feed results into another tool or keep a record:

```powershell
.\Invoke-EnterpriseAssessment.ps1 -ComputerName "DC01","FS01" -CredentialUser "YOURDOMAIN\Administrator" -ExportJson -OpenReport
```

---

## Where Reports Are Saved

All reports save automatically to:
```
C:\Users\ctadmin\Documents\ServerAsses\Reports\
```

Each report is a single self-contained HTML file named with the date and time:
```
Assessment_Report_20260516_143022.html
```

You can email this file, open it on any computer, or share it with management. No special software needed — it opens in any browser.

---

## Understanding the Report

### Risk Score (0–100)
Every server gets a risk score. Higher is worse.

| Score | Label | What It Means |
|---|---|---|
| 75–100 | 🔴 Critical Risk | Needs immediate attention — serious vulnerabilities or failures present |
| 50–74 | 🟠 High Risk | Significant issues — remediate within days |
| 25–49 | 🟡 Medium Risk | Issues present — plan remediation within weeks |
| 10–24 | 🔵 Low Risk | Minor issues — address during normal maintenance |
| 0–9 | 🟢 Healthy | No significant issues found |

### Finding Severity
Each individual finding has its own severity label:

| Label | Meaning |
|---|---|
| **CRITICAL** | Act immediately — active risk of outage, breach, or data loss |
| **HIGH** | Remediate soon — significant exposure |
| **MEDIUM** | Plan remediation — moderate risk |
| **LOW** | Best practice improvement — low urgency |
| **INFO** | Informational — no action required |

### Report Sections

**Executive Summary** — Total counts of findings by severity across all servers. Good for a management overview.

**Priority Remediation List** — Every Critical and High finding across all servers in one table, sorted by severity. Start here.

**Server Detail Cards** — Click any server card to expand it and see:
- System info (OS, hardware, RAM, CPU)
- Storage bar charts showing disk usage
- Cloud readiness score and migration recommendation
- VM inventory table (Hyper-V hosts only)
- Full findings table for that server with recommendations

---

## What Each Check Covers

| Area | What Gets Checked |
|---|---|
| **Operating System** | Windows version, end-of-life date, days until support ends, uptime, patch count |
| **Hardware** | Server age (from BIOS date), manufacturer, model, RAM amount, CPU cores, virtual vs physical |
| **Storage** | Every drive — how full it is, how much free space remains; file shares and whether they sit on full disks; VSS backups |
| **Security** | Windows Firewall on/off, antivirus status and signature age, SMBv1 (EternalBlue risk), TLS 1.0/1.1 enabled, WDigest (credential theft risk), LLMNR poisoning risk, RDP without NLA, open dangerous ports, Guest account, local admin count, AutoRun |
| **Active Directory** | Domain membership, domain/forest functional level, password policy weaknesses, account lockout policy, stale user and computer accounts, Domain Admins count, krbtgt password age, replication health, SYSVOL share |
| **Hyper-V** | VM inventory, RAM overcommitment, snapshots blocking migration, Gen1 vs Gen2 compatibility, single host single point of failure, integration services, virtual switch config |
| **Performance** | CPU and RAM utilization, page file usage, pending reboot, stopped critical services, event log error rate |
| **Cloud Readiness** | For regular servers: scored migration path to Azure/AWS. For Hyper-V hosts: VM-by-VM migration compatibility, step-by-step Azure Migrate and AWS MGN instructions, DC migration planning |

---

## Common Questions

**Q: Do I need to be on the server to run it?**
No. You run it from your own machine and it connects to the servers remotely.

**Q: Do I need to install anything on the servers I'm scanning?**
No. The scanner uses built-in Windows remote management (WinRM). The only setup is enabling WinRM on each server if it isn't already on.

**Q: The Hyper-V host is in a workgroup but the VMs are domain joined. Do I need two scans?**
Yes — two scans, two reports. The host uses local admin credentials, the VMs use domain credentials. See Scenario 5 above.

**Q: A server shows as unreachable. What do I do?**
1. Make sure the server is powered on
2. Make sure you can ping it: `ping SERVERNAME`
3. Make sure WinRM is enabled on it (see One-Time Setup above)
4. If it's a workgroup server, make sure you've added it to TrustedHosts on your scanner machine

**Q: It asks for a password. What do I enter?**
For domain servers: your domain admin password.
For the Hyper-V host: the local Administrator password on that specific host.

**Q: Can I scan a server I'm currently logged into?**
Yes. Just use its hostname in the `-ComputerName` parameter. It will scan it remotely the same as any other server.

**Q: The cloud section says my Hyper-V host is not ready for cloud. Is that right?**
The Hyper-V host itself is never "migrated" to cloud. The tool knows this and instead tells you how to migrate the VMs that are running on it. The urgency is based on how old the physical hardware is — older hardware means you should start moving the VMs sooner.

**Q: Where do I start after reading the report?**
Go to the **Priority Remediation List** section at the top of the report. Work through Critical findings first, then High. Each finding includes a specific recommendation telling you exactly what to do.

---

## Quick Reference Card

```
SCAN HYPER-V HOST (workgroup):
  .\Invoke-EnterpriseAssessment.ps1 -ComputerName "HOSTNAME" -CredentialUser "HOSTNAME\Administrator" -OpenReport

SCAN DOMAIN VMs / DCs / SERVERS:
  .\Invoke-EnterpriseAssessment.ps1 -ComputerName "DC01","FS01" -CredentialUser "DOMAIN\Administrator" -OpenReport

SCAN ALL DOMAIN SERVERS AUTOMATICALLY:
  .\Invoke-EnterpriseAssessment.ps1 -DiscoverFromAD -CredentialUser "DOMAIN\Administrator" -OpenReport

REPORTS SAVE TO:
  C:\Users\ctadmin\Documents\ServerAsses\Reports\
```

---

*Reports are generated as self-contained HTML files. No internet connection required to view them. Safe to email or print.*

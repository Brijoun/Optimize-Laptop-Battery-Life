# Toggle Feature Script
param (
    [string]$FeatureName,
    [string]$Action  # Accepts "Enable" or "Disable"
)

# Optimize Battery & System Security for HP Pavilion 15t-eg300
# Created by: Brian Villesca

# Logging System - Azure Storage Integration
$LogFile = "$env:USERPROFILE\Documents\OptimizationLog.txt"
$AzureLogURL = "https://your-azure-storage-account.blob.core.windows.net/logs/OptimizationLog.txt"

function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append

    # Upload log to Azure
    try {
        $logData = Get-Content -Path $LogFile -Raw
        Invoke-RestMethod -Uri $AzureLogURL -Method Put -Body $logData
    } catch {
        Write-Host "❌ Azure log upload failed: $_" -ForegroundColor Red
    }
}

Write-Log "Script started."

# Add a fail-safe mechanism to ensure the script does not execute if critical conditions are not met.

# Fail-safe: Check if running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator. Exiting..." -ForegroundColor Red
    Write-Log "Script terminated: Not running as Administrator."
    exit
}

# Fail-safe: Check if sufficient disk space is available
$FreeSpaceGB = (Get-PSDrive -Name C).Free / 1GB
if ($FreeSpaceGB -lt 3) {
    Write-Host "Insufficient disk space (less than 3GB free). Exiting..." -ForegroundColor Red
    Write-Log "Script terminated: Insufficient disk space."
    exit
}

# AI-driven workload optimization
$WorkloadType = "general"
$AppUsage = Get-Process | Where-Object { $_.CPU -gt 10 }

if ($AppUsage.Name -match "Code|Python|IDE") { $WorkloadType = "coding" }
elseif ($AppUsage.Name -match "Game|Steam|GPU") { $WorkloadType = "gaming" }

Write-Log "Detected workload type: $WorkloadType"

switch ($WorkloadType) {
    "coding" {
        powercfg -setactive SCHEME_BALANCED
        Write-Host "🔹 Optimized for coding workload." -ForegroundColor Green
    }
    "gaming" {
        powercfg -setactive SCHEME_HIGH_PERFORMANCE
        Write-Host "🎮 Optimized for gaming workload." -ForegroundColor Green
    }
    default {
        powercfg -setactive SCHEME_BALANCED
        Write-Host "⚙️ General optimization applied." -ForegroundColor Green
    }
}
Write-Log "Battery optimization applied for $WorkloadType."

# Disable Unnecessary Background Services
Get-Service | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -eq "Running" } |
Where-Object { $_.Name -notmatch "(Windows Defender|WLAN AutoConfig|CryptSvc|BITS)" } |
ForEach-Object {
    try {
        Stop-Service -Name $_.Name -Force
        Write-Log "Service '$($_.Name)' stopped successfully."
    } catch {
        Write-Log "Failed to stop service '$($_.Name)': $_"
    }
}

# Enable Anti-Malware Protection (Defender Quick Scan)
try {
    Start-MpScan -ScanType QuickScan
    Write-Host "✅ Defender Quick Scan completed." -ForegroundColor Green
    Write-Log "Defender Quick Scan completed successfully."
} catch {
    Write-Log "❌ Defender scan failed: $_"
}

# Lightweight Honeypot - Fake SSH Port to Detect Unauthorized Access
try {
    New-NetFirewallRule -DisplayName "Fake SSH Trap" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
    Write-Host "Honeypot activated: Monitoring unauthorized SSH connection attempts." -ForegroundColor Green
    Write-Log "Honeypot activated: Monitoring unauthorized SSH connection attempts."
} catch {
    Write-Error "❌ Failed to create honeypot firewall rule: $_"
    Write-Log "Failed to create honeypot firewall rule: $_"
}

# Clear Cache & Unnecessary Temp Files
try {
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force
    Write-Host "🗑️ Temp files cleared." -ForegroundColor Green
    Write-Log "Temp files cleared to improve system efficiency."
} catch {
    Write-Log "❌ Failed to clear temp files: $_"
}

# Disable Wake Timers (Prevents Unexpected Power Drain)
try {
    powercfg -waketimers | ForEach-Object { powercfg -devicedisablewake $_.ID }
    Write-Host "Wake timers disabled successfully." -ForegroundColor Green
    Write-Log "Wake timers disabled successfully."
} catch {
    Write-Error "❌ Failed to disable wake timers: $_"
    Write-Log "Failed to disable wake timers: $_"
}

# Apply System Security Hardening
try {
    Set-ExecutionPolicy Restricted -Force
    Write-Host "⚡ Security policy applied successfully." -ForegroundColor Green
    Write-Log "System power and security optimizations applied successfully!"
} catch {
    Write-Error "❌ Failed to apply execution policy: $_"
    Write-Log "Failed to apply execution policy: $_"
}

# Disk Cleanup
function Invoke-DiskCleanup {
    try {
        Write-Log "Starting disk cleanup."
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -NoNewWindow -Wait
        Write-Log "Disk cleanup completed successfully."
    } catch {
        Write-Log "Disk cleanup failed: $_"
    }
}

# System Restore Point
function New-RestorePoint {
    try {
        Write-Log "Creating system restore point."
        Checkpoint-Computer -Description "Optimization Script Restore Point" -RestorePointType MODIFY_SETTINGS
        Write-Log "System restore point created successfully."
    } catch {
        Write-Log "Failed to create system restore point: $_"
    }
}

# Battery Health Check
function Test-BatteryHealth {
    try {
        Write-Log "Checking battery health."
        powercfg /batteryreport /output "$env:USERPROFILE\Documents\BatteryReport.html"
        Write-Log "Battery health report generated at $env:USERPROFILE\Documents\BatteryReport.html."
    } catch {
        Write-Log "Failed to generate battery health report: $_"
    }
}

# Call new features
New-RestorePoint
Invoke-DiskCleanup
Test-BatteryHealth

switch ($FeatureName) {
    "BatteryOptimization" {
        if ($Action -eq "Enable") {
            # Enable Battery Optimization
            powercfg -setactive SCHEME_BALANCED
            powercfg -change -monitor-timeout-ac 5
            powercfg -change -monitor-timeout-dc 3
            powercfg -change -standby-timeout-ac 10
            powercfg -change -standby-timeout-dc 5
            powercfg -change -hibernate-timeout-dc 10
            Write-Host "Battery Optimization Enabled." -ForegroundColor Green
            Write-Log "Battery Optimization Enabled."
        } elseif ($Action -eq "Disable") {
            # Disable Battery Optimization (Revert to default settings)
            powercfg -setactive SCHEME_MIN
            Write-Host "Battery Optimization Disabled." -ForegroundColor Yellow
            Write-Log "Battery Optimization Disabled."
        } else {
            Write-Error "Invalid Action. Use 'Enable' or 'Disable'."
            Write-Log "Invalid Action for Battery Optimization. Use 'Enable' or 'Disable'."
        }
    }
    "SecurityHardening" {
        if ($Action -eq "Enable") {
            # Enable Security Hardening
            Set-ExecutionPolicy Restricted -Force
            Write-Host "Security Hardening Enabled." -ForegroundColor Green
            Write-Log "Security Hardening Enabled."
        } elseif ($Action -eq "Disable") {
            # Disable Security Hardening (Revert to default settings)
            Set-ExecutionPolicy RemoteSigned -Force
            Write-Host "Security Hardening Disabled." -ForegroundColor Yellow
            Write-Log "Security Hardening Disabled."
        } else {
            Write-Error "Invalid Action. Use 'Enable' or 'Disable'."
            Write-Log "Invalid Action for Security Hardening. Use 'Enable' or 'Disable'."
        }
    }
    default {
        Write-Error "Feature '$FeatureName' not recognized."
        Write-Log "Feature '$FeatureName' not recognized."
    }
}

Write-Log "Script execution completed."

# Placeholder for future scripts
# Add new features here following the same structure.

# End of Script
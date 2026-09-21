# collector.ps1
# FORENSICA Advanced Forensic Collector Script (v2.0)
# Enforce Elevation - Must run in Administrator context

# Step 1: Privilege Validation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "[-] FORENSICA: This script must be run as Administrator (elevated console). Exiting."
    Exit 1
}

Write-Output "[*] FORENSICA: Starting Advanced Collection Script..."

# Step 2: Staging Environment & Stealth Setup
$sourceDir = $PSScriptRoot
$stagingDir = "C:\ProgramData\KAPE_CSIR"
if (Test-Path $stagingDir) {
    Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Create output folders
$folders = @("FileSystem", "Memory", "Additional", "LiveResponse", "Network", "Timeline")
foreach ($folder in $folders) {
    New-Item -ItemType Directory -Force -Path "$stagingDir\$folder" | Out-Null
}

Write-Output "[*] Staging directories initialized under $stagingDir"

# Step 3: Capture Case Metadata
$hostname = $env:COMPUTERNAME
$os = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.*" } | Select-Object -First 1).IPAddress

$metadata = @{
    "case_id"     = "CASE-$((New-Guid).Guid.Substring(0,8).ToUpper())"
    "hostname"    = $hostname
    "os_version"  = $os
    "username"    = $user
    "timestamp"   = $timestamp
    "ip_address"  = $ipAddress
    "collector"   = "FORENSICA-v2.0.0"
}
$metadata | ConvertTo-Json | Out-File -FilePath "$stagingDir\case_meta.json" -Encoding UTF8

Write-Output "[*] Metadata telemetry recorded."

# Step 4: Live Incident Triage Collection
Write-Output "[*] Harvesting live triage artifacts..."

# 4A. Processes
Get-Process | Select-Object Id, ProcessName, Path, CPU, WorkingSet | Export-Csv -Path "$stagingDir\LiveResponse\pslist.csv" -NoTypeInformation

# 4B. Sockets
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Export-Csv -Path "$stagingDir\Network\tcpconnections.csv" -NoTypeInformation

# 4C. DNS Cache displaydns snapshot
try {
    Get-DnsClientCache -ErrorAction Stop | Select-Object Name, Type, Status, Data | Export-Csv -Path "$stagingDir\Network\dns_cache.csv" -NoTypeInformation
} catch {
    # Fallback to displaydns text output if cmdlet is missing
    ipconfig /displaydns > "$stagingDir\Network\dns_cache.txt"
}

# 4D. Scheduled Tasks (CSV & XML)
try {
    schtasks /query /v /fo CSV > "$stagingDir\LiveResponse\scheduled_tasks.csv" 2>$null
    schtasks /query /v /fo XML > "$stagingDir\LiveResponse\scheduled_tasks.xml" 2>$null
} catch {
    Write-Output "[!] Failed to query full schtasks."
}

# 4E. PSReadLine ConsoleHost Command History
$userProfiles = Get-ChildItem "C:\Users" -Directory
foreach ($profile in $userProfiles) {
    $historyFile = "$($profile.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $historyFile) {
        $destFile = "$stagingDir\Timeline\PowerShell_History_$($profile.Name).txt"
        Copy-Item -Path $historyFile -Destination $destFile -Force
    }
}

# 4F. Windows Defender Detection Support Logs
$defenderSupportDir = "C:\ProgramData\Microsoft\Windows Defender\Support"
if (Test-Path $defenderSupportDir) {
    New-Item -ItemType Directory -Force -Path "$stagingDir\LiveResponse\DefenderLogs" | Out-Null
    Copy-Item -Path "$defenderSupportDir\*" -Destination "$stagingDir\LiveResponse\DefenderLogs\" -Force -Recurse -ErrorAction SilentlyContinue
}

Write-Output "[*] Live response triage collection completed."

# Step 5: Cryptographic Chain of Custody Integrity Mapping
Write-Output "[*] Generating SHA-256 integrity manifest..."
$manifestRows = @()
$manifestRows += "file_name,sha256"

$allFiles = Get-ChildItem -Path $stagingDir -Recurse -File | Where-Object { $_.Name -ne "artifact_manifest.csv" }
foreach ($file in $allFiles) {
    # Get path relative to staging root
    $relativePath = $file.FullName.Replace("$stagingDir\", "")
    $hashObj = Get-FileHash -Path $file.FullName -Algorithm SHA256
    $manifestRows += "$relativePath,$($hashObj.Hash)"
}
$manifestRows | Out-File -FilePath "$stagingDir\artifact_manifest.csv" -Encoding UTF8

Write-Output "[*] Integrity manifest generated."

# Step 6: Evidence Zip Compilation
Write-Output "[*] Packaging evidence ZIP archive..."
$zipPath = "$stagingDir\..\$($hostname)_evidence.zip"
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}

# Load zip filesystem to support system ZIP compression natively
[System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
[System.IO.Compression.ZipFile]::CreateFromDirectory($stagingDir, $zipPath)

# Copy final evidence ZIP to target output path (Desktop of current user)
$targetOutput = "$env:USERPROFILE\Desktop\$($hostname)_evidence.zip"
Copy-Item -Path $zipPath -Destination $targetOutput -Force
Write-Output "[+] Success: Evidence package generated at: $targetOutput"

# Step 7: Gutmann-Style Cryptographic Self-Destruct Overwrite
Write-Output "[*] Initiating secure self-destruction of intermediate staging files..."

function Secure-Delete {
    param (
        [string]$Path
    )
    if (Test-Path $Path) {
        try {
            $fileInfo = New-Object System.IO.FileInfo($Path)
            $len = $fileInfo.Length
            if ($len -gt 0) {
                # Open write-accessible filestream
                $stream = [System.IO.File]::OpenWrite($Path)
                
                # Pass 1: Fill with zeros (0x00)
                $zeros = New-Object Byte[] $len
                $stream.Write($zeros, 0, $len)
                $stream.Position = 0
                
                # Pass 2: Fill with ones (0xFF)
                $ones = New-Object Byte[] $len
                for ($i = 0; $i -lt $len; $i++) { $ones[$i] = 255 }
                $stream.Write($ones, 0, $len)
                $stream.Position = 0
                
                # Pass 3: Fill with Cryptographic Random Bytes
                $rand = New-Object Byte[] $len
                $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
                $rng.GetBytes($rand)
                $stream.Write($rand, 0, $len)
                
                $stream.Flush()
                $stream.Close()
            }
            Remove-Item $Path -Force
        } catch {
            Remove-Item $Path -Force -ErrorAction SilentlyContinue
        }
    }
}

# Shred all staged evidence files recursively
$stagingFiles = Get-ChildItem -Path $stagingDir -Recurse -File
foreach ($file in $stagingFiles) {
    Secure-Delete -Path $file.FullName
}

# Shred the temporary staging zip itself
Secure-Delete -Path $zipPath

# Clean up remaining empty folders
Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Output "[+] Secure staging folder deletion complete. Counter-forensics recovery mitigated."
Write-Output "[*] FORENSICA: Collection finished successfully."

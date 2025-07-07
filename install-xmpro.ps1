# This is a simplified version of the installation script that follows the flowchart:
# 0. Install Windows Updates
# 1. Install IIS and dependencies
# 2. Install .NET 4.8.1
# 3. Install WSL
# 4. Install Container Service
# 5. First Restart
# 6. Install Ubuntu on WSL w/credentials
# 7. Second Restart
# 8. Install Docker and Docker Compose
# 9. Post Installation Configuration

param (
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoRestart,
    
    [Parameter(Mandatory=$false)]
    [string]$DockerVersion = "latest",
    
    [Parameter(Mandatory=$false)]
    [switch]$ContinueAfterRestart,
    
    [Parameter(Mandatory=$false)]
    [int]$InstallPhase = 0,
    
    [Parameter(Mandatory=$false)]
    [string]$UbuntuAppxUrl = "https://aka.ms/wslubuntu2204",
    
    [Parameter(Mandatory=$false)]
    [string]$ScriptUrl = "",
    
    [Parameter(Mandatory=$false)]
    [string]$SqlSaPassword = "YourStrongP@ssw0rd123",
    
    [Parameter(Mandatory=$false)]
    [string]$DockerComposeVersion = "2.36.1",
    
    # Application deployment parameters
    [Parameter(Mandatory=$false)]
    [string]$BaseUrl = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipApplicationDeployment,
    
    [Parameter(Mandatory=$false)]
    [string]$ApplicationScriptUrl = "",
    
    # Installation mode - determines which components to install
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "SMOnly")]
    [string]$InstallMode = "All"
)

# Try to get the script URL from environment variable or detect from command line
if ([string]::IsNullOrEmpty($ScriptUrl)) {
    # First check for environment variable
    if (-not [string]::IsNullOrEmpty($env:SCRIPT_URL)) {
        $ScriptUrl = $env:SCRIPT_URL
        Write-Host "Using script URL from environment variable: $ScriptUrl"
    }
    # Fall back to regex detection
    elseif ($MyInvocation.Line -match "irm\s+([^\s\)]+)") {
        $detectedUrl = $matches[1]
        Write-Host "Detected script URL from command line: $detectedUrl"
        $ScriptUrl = $detectedUrl
    }
}

# Check for UbuntuAppxUrl in environment variable
if (-not [string]::IsNullOrEmpty($env:UBUNTU_APPX_URL)) {
    $UbuntuAppxUrl = $env:UBUNTU_APPX_URL
    Write-Host "Using Ubuntu AppX URL from environment variable: $UbuntuAppxUrl"
}

# Check for SQL password in environment variable
if (-not [string]::IsNullOrEmpty($env:SQL_SA_PASSWORD)) {
    $SqlSaPassword = $env:SQL_SA_PASSWORD
    Write-Host "Using SQL SA password from environment variable"
}

# Auto-detect BaseUrl and ApplicationScriptUrl from ScriptUrl if not provided
if ([string]::IsNullOrEmpty($BaseUrl) -and -not [string]::IsNullOrEmpty($ScriptUrl)) {
    # Extract base URL from script URL including path (e.g., https://example.com/v2/install-xmpro.ps1 -> https://example.com/v2)
    try {
        $uri = [System.Uri]::new($ScriptUrl)
        $BaseUrl = "$($uri.Scheme)://$($uri.Host)"
        if ($uri.Port -ne -1 -and $uri.Port -ne 80 -and $uri.Port -ne 443) {
            $BaseUrl += ":$($uri.Port)"
        }
        
        # Include the path but remove the filename
        $path = $uri.AbsolutePath
        if ($path -and $path -ne "/") {
            $directory = [System.IO.Path]::GetDirectoryName($path).Replace("\", "/")
            if ($directory -and $directory -ne ".") {
                $BaseUrl += $directory
            }
        }
        
        Write-Host "Auto-detected BaseUrl from ScriptUrl: $BaseUrl"
    }
    catch {
        Write-Warning "Could not auto-detect BaseUrl from ScriptUrl: $_"
    }
}

# Auto-detect ApplicationScriptUrl if not provided
if ([string]::IsNullOrEmpty($ApplicationScriptUrl) -and -not [string]::IsNullOrEmpty($ScriptUrl)) {
    # Replace install-xmpro.ps1 with install-xmpro-application.ps1 in the URL
    $ApplicationScriptUrl = $ScriptUrl -replace "install-xmpro\.ps1$", "install-xmpro-application.ps1"
    Write-Host "Auto-detected ApplicationScriptUrl: $ApplicationScriptUrl"
}

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires administrative privileges. Please run as administrator."
    exit
}

# Global variables
$global:RebootRequired = $false
$global:BootstrapTask = "XMPRODockerBootstrap"
$global:DockerServiceName = "docker"
$global:PersistentDir = "$env:USERPROFILE\.xmpro-install"

# Handle user profile change when running as SYSTEM after restart (SM Only mode)
if ($InstallMode -eq "SMOnly") {
    $currentWorkingDir = Get-Location | Select-Object -ExpandProperty Path
    if (-not $currentWorkingDir.StartsWith($env:USERPROFILE, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Host "Detected user profile change (likely running as SYSTEM). Using current working directory as persistent dir." -ForegroundColor Yellow
        Write-Host "Original USERPROFILE: $env:USERPROFILE" -ForegroundColor Gray
        Write-Host "Current working directory: $currentWorkingDir" -ForegroundColor Gray
        $global:PersistentDir = $currentWorkingDir
    }
}

$global:LogFile = "$global:PersistentDir\XMPRO-Docker-Install.log"
$global:RestartMarkerFile = "$global:PersistentDir\XMPRO-Docker-RestartMarker.json"
$global:TempScriptPath = "$global:PersistentDir\Install-XMPRO-DockerCE-Flowchart.ps1"

# Create persistent directory if it doesn't exist
if (-not (Test-Path $global:PersistentDir)) {
    New-Item -Path $global:PersistentDir -ItemType Directory -Force | Out-Null
}

# Check if we're continuing after a restart
if (Test-Path $global:RestartMarkerFile) {
    try {
        $markerContent = Get-Content -Path $global:RestartMarkerFile -Raw | ConvertFrom-Json
        if ($markerContent.InstallPhase) { $InstallPhase = $markerContent.InstallPhase }
        if ($markerContent.Force) { $Force = $true }
        if ($markerContent.DockerVersion) { $DockerVersion = $markerContent.DockerVersion }
        if ($markerContent.UbuntuAppxUrl) { $UbuntuAppxUrl = $markerContent.UbuntuAppxUrl }
        $ContinueAfterRestart = $true
    }
    catch {
        Write-Warning "Error reading restart marker file: $_"
    }
}

# Function to write to log file
function Write-Log {
    param (
        [string]$Message = " ",
        [string]$ForegroundColor = "White"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host $Message -ForegroundColor $ForegroundColor
    "$timestamp - $Message" | Out-File -FilePath $global:LogFile -Append
}

# Function to set up script to run after restart
function Register-ScriptForAfterRestart {
    param (
        [string]$ScriptPath,
        [string]$Arguments = ""
    )
    
    try {
        # First, ensure we have a persistent copy of the script
        $persistentScriptPath = "$global:PersistentDir\Install-XMPRO-DockerCE-Flowchart.ps1"
        
        # If the script path is empty or doesn't exist, we need to create a copy from the current script content
        if ([string]::IsNullOrEmpty($ScriptPath) -or -not (Test-Path $ScriptPath)) {
            Write-Log "Script path is empty or doesn't exist. Creating a persistent copy..." -ForegroundColor Yellow
            
            # Get the script content from the current execution context
            $scriptContent = $MyInvocation.MyCommand.ScriptBlock.ToString()
            
            # If we couldn't get the content, try to use the script that was passed in
            if ([string]::IsNullOrEmpty($scriptContent) -and (Test-Path $ScriptPath)) {
                $scriptContent = Get-Content -Path $ScriptPath -Raw
            }
            
            # Save the script content to the persistent directory
            if (-not [string]::IsNullOrEmpty($scriptContent)) {
                Set-Content -Path $persistentScriptPath -Value $scriptContent -Force
                Write-Log "Created persistent script copy at: $persistentScriptPath" -ForegroundColor Green
            } else {
                Write-Error "Could not get script content to create a persistent copy."
                return $false
            }
        } else {
            # Only copy if source and destination are different
            if ($ScriptPath -ne $persistentScriptPath) {
                # Copy the script to the persistent directory
                Copy-Item -Path $ScriptPath -Destination $persistentScriptPath -Force
                Write-Log "Copied script to persistent location: $persistentScriptPath" -ForegroundColor Green
            } else {
                Write-Log "Script is already in the persistent location: $persistentScriptPath" -ForegroundColor Green
            }
        }
        
        # Now use the persistent script path for the scheduled task
        $taskName = $global:BootstrapTask
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        if ($InstallMode -ne "SMOnly") {
            $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$persistentScriptPath`" $Arguments"
            $trigger = New-ScheduledTaskTrigger -AtLogon
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest
        } else {
            $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$persistentScriptPath`" $Arguments" -WorkingDirectory $global:PersistentDir
            $trigger = New-ScheduledTaskTrigger -AtStartup  # Changed from AtLogon to AtStartup for system tasks
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        }
        # Remove the task if it already exists
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        
        # Register the new task
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal
        
        Write-Log "Successfully registered script to run after restart." -ForegroundColor Green
        Write-Log "Scheduled task will run: PowerShell.exe -ExecutionPolicy Bypass -File `"$persistentScriptPath`" $Arguments" -ForegroundColor Yellow
        return $true
    }
    catch {
        Write-Warning "Failed to set up post-restart script execution: ${_}"
        return $false
    }
}

# Function to install Docker in WSL with retry logic
function Install-DockerInWSL {
    param (
        [string]$DockerComposeVersion
    )
    
    # Check if Docker is already installed in WSL
    $dockerCheckResult = wsl -d Ubuntu -e bash -c "command -v docker && docker --version" 2>&1
    if ($dockerCheckResult -match "Docker version") {
        Write-Log "Docker is already installed in WSL2 Ubuntu: $dockerCheckResult" -ForegroundColor Green
        return $true
    }
    
    Write-Log "Docker not found in WSL2 Ubuntu. Installing..." -ForegroundColor Yellow
    
    $dockerInstallSuccess = $false
    $dockerMaxRetries = 3
    
    for ($dockerAttempt = 1; $dockerAttempt -le $dockerMaxRetries; $dockerAttempt++) {
        Write-Log "Docker installation attempt $dockerAttempt of $dockerMaxRetries..." -ForegroundColor Yellow
        
        try {
            # Docker installation commands for Ubuntu (without docker-compose)
        $dockerInstallCommands = @"
#!/bin/bash
# Enable command echo to see each command as it executes
set -x

# Update package index and install prerequisites
apt-get update
apt-get install -y ca-certificates curl gnupg

# Add Docker's official GPG key
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Get Ubuntu version codename using lsb_release
UBUNTU_CODENAME=`$(lsb_release -cs)
echo "Ubuntu version codename: `$UBUNTU_CODENAME"

# Add the repository to Apt sources
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu `$UBUNTU_CODENAME stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable Docker service to start on boot
systemctl enable docker.service

# Start Docker service
service docker start

# Verify Docker installation
echo "Docker Version:"
docker --version

# Verify Docker service status
echo "Docker Service Status:"
service docker status

"@

            # Save the script to the XMPRO installation directory
            $dockerScriptPath = "$global:PersistentDir\docker-wsl-install.sh"
            $dockerInstallCommands | Out-File -FilePath $dockerScriptPath -Encoding ASCII
            
            # Make the script accessible from WSL
            $wslPath = "/mnt/c" + $dockerScriptPath.Substring(2).Replace("\", "/")
            
            # Execute the script in WSL and display output to both console and log file
            Write-Log "Executing Docker installation script in WSL2..." -ForegroundColor Yellow
            Write-Log "Command: wsl -d Ubuntu -u root bash $wslPath" -ForegroundColor Yellow
            
            # Run the command, capture output, and write to both console and log file
            Write-Log "--- WSL Docker Installation Output (Attempt $dockerAttempt) ---" -ForegroundColor Cyan

            # Capture the output and write to both console and log file
            $wslOutput = wsl -d Ubuntu -u root bash $wslPath 2>&1
            $wslOutput | ForEach-Object {
                Write-Log $_ -ForegroundColor White
            }

            Write-Log "--- End of WSL Docker Installation Output (Attempt $dockerAttempt) ---" -ForegroundColor Cyan
            
            # Verify installation was successful
            Start-Sleep -Seconds 3
            $dockerVerifyResult = wsl -d Ubuntu -e bash -c "command -v docker && docker --version" 2>&1
            if ($dockerVerifyResult -match "Docker version") {
                Write-Log "Docker installation successful: $dockerVerifyResult" -ForegroundColor Green
                Write-Log "Docker installation script saved at: $dockerScriptPath" -ForegroundColor Green
                $dockerInstallSuccess = $true
                break
            } else {
                Write-Log "Docker installation verification failed on attempt $dockerAttempt" -ForegroundColor Red
                if ($dockerAttempt -lt $dockerMaxRetries) {
                    Write-Log "Retrying Docker installation in 10 seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 10
                }
            }
        }
        catch {
            Write-Log "Error during Docker installation attempt ${dockerAttempt}: $_" -ForegroundColor Red
            if ($dockerAttempt -lt $dockerMaxRetries) {
                Write-Log "Retrying Docker installation in 10 seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds 10
            }
        }
    }
    
    if (-not $dockerInstallSuccess) {
        Write-Error "Docker installation failed after $dockerMaxRetries attempts"
        return $false
    }
    
    return $true
}

# Function to download files with multiple methods and retry logic
function Download-FileWithRetry {
    param (
        [string]$Url,
        [string]$OutputPath,
        [string]$Description = "file",
        [int]$MaxRetries = 3
    )
    
    Write-Log "Downloading $Description from $Url..." -ForegroundColor Yellow
    
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Write-Log "Download attempt $attempt of $MaxRetries for $Description..." -ForegroundColor Yellow
        
        # Remove any existing partial download
        if (Test-Path $OutputPath) {
            Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
        }
        
        $success = $false
        
        # Method 1: BITS transfer (fastest for large files)
        if ($attempt -eq 1) {
            try {
                Write-Log "Attempt ${attempt}: Using BITS transfer for $Description..." -ForegroundColor Cyan
                $bitsJob = Start-BitsTransfer -Source $Url -Destination $OutputPath -Asynchronous -DisplayName "$Description Download"
                
                # Monitor the download with timeout (10 minutes)
                $timeout = 600
                $timer = 0
                
                while ($bitsJob.JobState -eq "Transferring" -and $timer -lt $timeout) {
                    Start-Sleep -Seconds 10
                    $timer += 10
                    if ($bitsJob.BytesTotal -gt 0) {
                        $progress = [math]::Round(($bitsJob.BytesTransferred / $bitsJob.BytesTotal) * 100, 1)
                        Write-Log "Download progress: $progress% ($([math]::Round($bitsJob.BytesTransferred / 1MB, 1))MB / $([math]::Round($bitsJob.BytesTotal / 1MB, 1))MB)" -ForegroundColor Cyan
                    }
                }
                
                if ($bitsJob.JobState -eq "Transferred") {
                    Complete-BitsTransfer -BitsJob $bitsJob
                    $success = $true
                    Write-Log "$Description download completed successfully using BITS." -ForegroundColor Green
                } else {
                    if ($bitsJob.ErrorCondition) {
                        Write-Log "BITS Error: $($bitsJob.ErrorDescription)" -ForegroundColor Red
                    }
                    Remove-BitsTransfer -BitsJob $bitsJob -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-Log "BITS transfer failed for $Description : $_" -ForegroundColor Red
                Remove-BitsTransfer -BitsJob $bitsJob -ErrorAction SilentlyContinue
            }
        }
        # Method 2: curl.exe (reliable fallback)
        elseif ($attempt -eq 2) {
            try {
                Write-Log "Attempt ${attempt}: Using curl.exe for $Description..." -ForegroundColor Yellow
                $curlResult = curl.exe -L -o $OutputPath $Url --progress-bar
                if ($LASTEXITCODE -eq 0 -and (Test-Path $OutputPath)) {
                    $success = $true
                    Write-Log "$Description download completed successfully using curl.exe." -ForegroundColor Green
                } else {
                    Write-Log "curl.exe failed with exit code: $LASTEXITCODE" -ForegroundColor Red
                }
            }
            catch {
                Write-Log "curl.exe failed for $Description : $_" -ForegroundColor Red
            }
        }
        # Method 3: Invoke-WebRequest (final fallback)
        else {
            try {
                Write-Log "Attempt ${attempt}: Using Invoke-WebRequest for $Description..." -ForegroundColor Yellow
                Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
                if (Test-Path $OutputPath) {
                    $success = $true
                    Write-Log "$Description download completed successfully using Invoke-WebRequest." -ForegroundColor Green
                } else {
                    Write-Log "Invoke-WebRequest failed - file not created" -ForegroundColor Red
                }
            }
            catch {
                Write-Log "Invoke-WebRequest failed for $Description : $_" -ForegroundColor Red
            }
        }
        
        # Check if download was successful
        if ($success -and (Test-Path $OutputPath)) {
            $fileSize = (Get-Item $OutputPath).Length
            if ($fileSize -gt 0) {
                Write-Log "$Description download successful. File size: $([math]::Round($fileSize / 1MB, 1))MB" -ForegroundColor Green
                return $true
            } else {
                Write-Log "$Description download resulted in empty file" -ForegroundColor Red
                Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
            }
        }
        
        # If not the last attempt, wait before retrying
        if ($attempt -lt $MaxRetries) {
            Write-Log "Retrying $Description download in 10 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 10
        }
    }
    
    Write-Log "CRITICAL ERROR: Failed to download $Description after $MaxRetries attempts using all methods (BITS, curl.exe, Invoke-WebRequest)" -ForegroundColor Red
    return $false
}

# Function to install Docker Compose in WSL with retry logic
function Install-DockerComposeInWSL {
    param (
        [string]$DockerComposeVersion
    )
    
    # Check if Docker Compose is already installed in WSL (separate check)
    $dockerComposeCheckResult = wsl -d Ubuntu -e bash -c "command -v docker-compose && docker-compose --version" 2>&1
    if ($dockerComposeCheckResult -match "Docker Compose version") {
        Write-Log "Docker Compose is already installed in WSL2 Ubuntu: $dockerComposeCheckResult" -ForegroundColor Green
        return $true
    }
    
    Write-Log "Docker Compose not found in WSL2 Ubuntu. Installing..." -ForegroundColor Yellow
    
    $composeInstallSuccess = $false
    $composeMaxRetries = 3
    
    for ($composeAttempt = 1; $composeAttempt -le $composeMaxRetries; $composeAttempt++) {
        Write-Log "Docker Compose installation attempt $composeAttempt of $composeMaxRetries..." -ForegroundColor Yellow
        
        try {
            # Docker Compose installation commands for Ubuntu
        $dockerComposeInstallCommands = @"
#!/bin/bash
# Enable command echo to see each command as it executes
set -x

# Install standalone Docker Compose
COMPOSE_VERSION="v$DockerComposeVersion"
curl -L "https://github.com/docker/compose/releases/download/`${COMPOSE_VERSION}/docker-compose-linux-x86_64" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose

# Verify Docker Compose installation
echo "Docker Compose Version:"
docker-compose --version

"@

            # Save the script to the XMPRO installation directory
            $dockerComposeScriptPath = "$global:PersistentDir\docker-compose-wsl-install.sh"
            $dockerComposeInstallCommands | Out-File -FilePath $dockerComposeScriptPath -Encoding ASCII
            
            # Make the script accessible from WSL
            $wslComposePath = "/mnt/c" + $dockerComposeScriptPath.Substring(2).Replace("\", "/")
            
            # Execute the script in WSL and display output to both console and log file
            Write-Log "Executing Docker Compose installation script in WSL2..." -ForegroundColor Yellow
            Write-Log "Command: wsl -d Ubuntu -u root bash $wslComposePath" -ForegroundColor Yellow
            
            # Run the command, capture output, and write to both console and log file
            Write-Log "--- WSL Docker Compose Installation Output (Attempt $composeAttempt) ---" -ForegroundColor Cyan

            # Capture the output and write to both console and log file
            $wslComposeOutput = wsl -d Ubuntu -u root bash $wslComposePath 2>&1
            $wslComposeOutput | ForEach-Object {
                Write-Log $_ -ForegroundColor White
            }

            Write-Log "--- End of WSL Docker Compose Installation Output (Attempt $composeAttempt) ---" -ForegroundColor Cyan
            
            # Verify installation was successful
            Start-Sleep -Seconds 3
            $composeVerifyResult = wsl -d Ubuntu -e bash -c "command -v docker-compose && docker-compose --version" 2>&1
            if ($composeVerifyResult -match "Docker Compose version") {
                Write-Log "Docker Compose installation successful: $composeVerifyResult" -ForegroundColor Green
                Write-Log "Docker Compose installation script saved at: $dockerComposeScriptPath" -ForegroundColor Green
                $composeInstallSuccess = $true
                break
            } else {
                Write-Log "Docker Compose installation verification failed on attempt $composeAttempt" -ForegroundColor Red
                if ($composeAttempt -lt $composeMaxRetries) {
                    Write-Log "Retrying Docker Compose installation in 10 seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 10
                }
            }
        }
        catch {
            Write-Log "Error during Docker Compose installation attempt ${composeAttempt}: $_" -ForegroundColor Red
            if ($composeAttempt -lt $composeMaxRetries) {
                Write-Log "Retrying Docker Compose installation in 10 seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds 10
            }
        }
    }
    
    if (-not $composeInstallSuccess) {
        Write-Error "Docker Compose installation failed after $composeMaxRetries attempts"
        return $false
    }
    
    return $true
}

# Function to handle restart
function Handle-Restart {
    param (
        [int]$NextPhase,
        [string]$Message
    )
    
    if ($NoRestart) {
        Write-Warning "A reboot is required to continue with Phase $NextPhase; stopping script execution"
        exit
    }
    
    # Set up the script to run after restart
    $scriptPath = $MyInvocation.MyCommand.Path
    $arguments = "-InstallPhase $NextPhase -ContinueAfterRestart -InstallMode `"$InstallMode`""
    if ($Force) { $arguments += " -Force" }
    if ($DockerVersion -ne "latest") { $arguments += " -DockerVersion `"$DockerVersion`"" }
    if ($UbuntuAppxUrl -ne "https://aka.ms/wslubuntu2204") { $arguments += " -UbuntuAppxUrl `"$UbuntuAppxUrl`"" }
    if (-not [string]::IsNullOrEmpty($ScriptUrl)) { $arguments += " -ScriptUrl `"$ScriptUrl`"" }
    
    # Log the script path for debugging
    Write-Log "Current script path: $scriptPath" -ForegroundColor Yellow
    
    # Check if script is running from a file or from memory (web execution)
    if ([string]::IsNullOrEmpty($scriptPath)) {
        # Script is running from memory (web execution)
        Write-Log "Script is running from web execution (memory)." -ForegroundColor Yellow
        
        # If we have a script URL, download the script
        if (-not [string]::IsNullOrEmpty($ScriptUrl)) {
            Write-Log "Downloading script from URL: $ScriptUrl" -ForegroundColor Yellow
            try {
                Start-BitsTransfer -Source $ScriptUrl -Destination $global:TempScriptPath
                Write-Log "Script downloaded to $global:TempScriptPath" -ForegroundColor Green
                $taskRegistered = Register-ScriptForAfterRestart -ScriptPath $global:TempScriptPath -Arguments $arguments
            }
            catch {
                Write-Error "Failed to download script from $ScriptUrl : $_"
                # Fall back to saving the script content
                Write-Log "Falling back to saving script content..." -ForegroundColor Yellow
                $scriptContent = $MyInvocation.MyCommand.ScriptBlock.ToString()
                Set-Content -Path $global:TempScriptPath -Value $scriptContent -Force
                Write-Log "Script content saved to $global:TempScriptPath" -ForegroundColor Green
                $taskRegistered = Register-ScriptForAfterRestart -ScriptPath $global:TempScriptPath -Arguments $arguments
            }
        }
        else {
            # Save the current script content to a file
            Write-Log "Saving script content to file..." -ForegroundColor Yellow
            $scriptContent = $MyInvocation.MyCommand.ScriptBlock.ToString()
            Set-Content -Path $global:TempScriptPath -Value $scriptContent -Force
            Write-Log "Script saved to $global:TempScriptPath" -ForegroundColor Green
            $taskRegistered = Register-ScriptForAfterRestart -ScriptPath $global:TempScriptPath -Arguments $arguments
        }
    }
    else {
        # Script is running from a file
        $taskRegistered = Register-ScriptForAfterRestart -ScriptPath $scriptPath -Arguments $arguments
    }
    
    if ($taskRegistered) {
        # Create a marker file with the current parameters
        $markerContent = @{
            InstallPhase = $NextPhase
            Force = $Force
            DockerVersion = $DockerVersion
            UbuntuAppxUrl = $UbuntuAppxUrl
            ScriptUrl = $ScriptUrl
            # SQL password is stored securely in a separate encrypted file
        }
        
        # Save the marker file
        $markerContent | ConvertTo-Json | Out-File -FilePath $global:RestartMarkerFile -Force
        
        Write-Log $Message -ForegroundColor Yellow
        Write-Log "The script will continue automatically after restart." -ForegroundColor Yellow
        
        # Skip user prompt for SM Only mode
        if ($InstallMode -ne "SMOnly") {
            Read-Host "Press Enter to restart your computer"
        } else {
            Write-Log "SM Only mode: Restarting automatically without user prompt..." -ForegroundColor Yellow
        }
        Write-Log "Restarting computer..." -ForegroundColor Cyan
        if ($Force) {
            Restart-Computer -Force
        }
        else {
            Restart-Computer
        }
        
        exit
    }
    else {
        Write-Error "Failed to register script to run after restart. Please run the script again manually after restart."
        exit 1
    }
}

# Display current phase
Write-Log "Current installation phase: $InstallPhase" -ForegroundColor Cyan

# Unregister the bootstrap task if it exists
if ((Get-ScheduledTask -TaskName $global:BootstrapTask -ErrorAction SilentlyContinue) -ne $null) {
    Unregister-ScheduledTask -TaskName $global:BootstrapTask -Confirm:$false
}

# Phase 0: Install Windows Updates
if ($InstallPhase -eq 0) {
    Write-Log "Phase 0: Installing Windows Updates" -ForegroundColor Cyan
    
    # Install the PSWindowsUpdate module
    Write-Log "Installing PSWindowsUpdate module..." -ForegroundColor Yellow
    try {
        # Set execution policy and security protocol
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # Check if NuGet package provider is already installed
        $nugetProvider = Get-PackageProvider -ListAvailable | Where-Object {$_.Name -eq "NuGet"}
        if (-not $nugetProvider -or $nugetProvider.Version -lt "2.8.5.208") {
            Write-Log "Installing NuGet package provider..." -ForegroundColor Yellow
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force
        } else {
            Write-Log "NuGet package provider is already installed." -ForegroundColor Green
        }
        
        # Check if PSWindowsUpdate module is installed and functional
        $moduleInstalled = Get-Module -ListAvailable -Name PSWindowsUpdate
        $commandAvailable = Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue
        
        if (-not $moduleInstalled -or -not $commandAvailable) {
            Write-Log "Installing PSWindowsUpdate module..." -ForegroundColor Yellow
            Install-Module PSWindowsUpdate -Force -Confirm:$false
        } else {
            Write-Log "PSWindowsUpdate module is already installed." -ForegroundColor Green
        }
        
        # Import the module if not already imported
        if (-not (Get-Module PSWindowsUpdate)) {
            Write-Log "Importing PSWindowsUpdate module..." -ForegroundColor Yellow
            Import-Module PSWindowsUpdate
        } else {
            Write-Log "PSWindowsUpdate module is already imported." -ForegroundColor Green
        }
        
        # View available updates
        Write-Log "Checking for available Windows updates..." -ForegroundColor Yellow
        $updates = Get-WindowsUpdate
        
        if ($updates.Count -gt 0) {
            Write-Log "Found $($updates.Count) updates available for installation." -ForegroundColor Green
            
            # Install all available updates without automatic reboot
            Write-Log "Installing all available Windows updates..." -ForegroundColor Yellow
            Install-WindowsUpdate -AcceptAll -AutoReboot:$false -Confirm:$false -IgnoreReboot
            
            # Ask for restart to ensure updates are properly applied
            Handle-Restart -NextPhase 1 -Message "Windows updates have been installed. A restart is required to complete the update process."
        } else {
            Write-Log "No Windows updates available for installation." -ForegroundColor Green
            
            # Proceed to Phase 1
            $InstallPhase = 1
            Write-Log "Proceeding to Phase 1..." -ForegroundColor Green
        }
    }
    catch {
        Write-Error "An error occurred during Windows Update installation: ${_}"
        
        # If there's an error, we'll still try to proceed to Phase 1
        $InstallPhase = 1
        Write-Log "Proceeding to Phase 1 despite Windows Update errors..." -ForegroundColor Yellow
    }
}

# Phase 1: Install IIS, .NET 4.8.1, WSL, and Container Service
if ($InstallPhase -eq 1) {
    Write-Log "Phase 1: Installing IIS, .NET 4.8.1, WSL, and Container Service" -ForegroundColor Cyan
    
    # Reset reboot flag for this phase
    $global:RebootRequired = $false
    
    # Install IIS features
    Write-Log "Installing IIS features..." -ForegroundColor Yellow
    
    # First, ensure .NET Framework 3.5 is installed (required for ASP.NET 3.5)
    Write-Log "Installing .NET Framework 3.5 (includes .NET 2.0 and 3.0)..." -ForegroundColor Yellow
    if (-not (Get-WindowsOptionalFeature -Online -FeatureName "NetFx3").State -eq "Enabled") {
        $result = Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -All -NoRestart
        if ($result.RestartNeeded) {
            $global:RebootRequired = $true
        }
    }
    
    # Complete list of IIS features - compressed into categories for efficiency
    $iisFeatureCategories = @{
        "Web Server Role" = @("IIS-WebServerRole", "IIS-WebServer")
        "Common HTTP Features" = @("IIS-CommonHttpFeatures", "IIS-StaticContent", "IIS-DefaultDocument", "IIS-DirectoryBrowsing", "IIS-HttpErrors", "IIS-HttpRedirect", "IIS-WebSockets")
        "Application Development" = @("IIS-ApplicationDevelopment", "IIS-ASPNET45", "IIS-NetFxExtensibility45", "IIS-ASPNET", "IIS-NetFxExtensibility", "IIS-ASP", "IIS-ISAPIExtensions", "IIS-ISAPIFilter", "IIS-ServerSideIncludes", "IIS-ApplicationInit")
        "Health and Diagnostics" = @("IIS-HealthAndDiagnostics", "IIS-HttpLogging", "IIS-LoggingLibraries", "IIS-RequestMonitor", "IIS-HttpTracing", "IIS-CustomLogging", "IIS-ODBCLogging")
        "Security" = @("IIS-Security", "IIS-RequestFiltering", "IIS-BasicAuthentication", "IIS-WindowsAuthentication", "IIS-DigestAuthentication", "IIS-ClientCertificateMappingAuthentication", "IIS-IISCertificateMappingAuthentication", "IIS-CertProvider", "IIS-IPSecurity", "IIS-URLAuthorization")
        "Performance" = @("IIS-Performance", "IIS-HttpCompressionStatic", "IIS-HttpCompressionDynamic")
        "Management Tools" = @("IIS-WebServerManagementTools", "IIS-ManagementConsole", "IIS-ManagementScriptingTools", "IIS-ManagementService", "IIS-WMICompatibility", "IIS-LegacyScripts", "IIS-LegacySnapIn")
    }
    
    # Get all currently enabled features once for efficiency
    Write-Log "Checking currently enabled Windows features..." -ForegroundColor Yellow
    $enabledFeatures = (Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"}).FeatureName
    
    # Install all IIS features by category, only if not already enabled
    foreach ($category in $iisFeatureCategories.Keys) {
        $categoryFeatures = $iisFeatureCategories[$category]
        $missingFeatures = $categoryFeatures | Where-Object { $_ -notin $enabledFeatures }
        
        if ($missingFeatures.Count -gt 0) {
            Write-Log "Installing $category features: $($missingFeatures -join ', ')..." -ForegroundColor Yellow
            foreach ($feature in $missingFeatures) {
                $result = Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart
                if ($result.RestartNeeded) {
                    $global:RebootRequired = $true
                }
            }
        } else {
            Write-Log "$category features are already enabled." -ForegroundColor Green
        }
    }
    
    # Install IIS URL Rewrite 2.1
    Write-Log "Installing IIS URL Rewrite 2.1..." -ForegroundColor Yellow
    $rewriteModule = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\IIS Extensions\URL Rewrite" -ErrorAction SilentlyContinue
    if (-not ($rewriteModule -and $rewriteModule.Version -ge "2.1.0")) {
        Write-Log "URL Rewrite module not found or version is below 2.1.0. Installing..." -ForegroundColor Yellow
        $urlRewriteUrl = "https://download.microsoft.com/download/D/D/E/DDE57C26-C62C-4C59-A1BB-31D58B36ADA2/rewrite_amd64_en-US.msi"
        $urlRewriteInstaller = "$env:TEMP\rewrite_amd64_en-US.msi"
        Start-BitsTransfer -Source $urlRewriteUrl -Destination $urlRewriteInstaller
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$urlRewriteInstaller`" /quiet /norestart" -Wait
        Remove-Item -Path $urlRewriteInstaller -Force
        Write-Log "IIS URL Rewrite 2.1 installed successfully." -ForegroundColor Green
    } else {
        Write-Log "IIS URL Rewrite 2.1 (or higher) is already installed. Version: $($rewriteModule.Version)" -ForegroundColor Green
    }
    
    # Install .NET Framework 4.8.1
    Write-Log "Installing .NET Framework 4.8.1..." -ForegroundColor Yellow
    $dotnet481Check = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
    if (-not ($dotnet481Check -and $dotnet481Check.Release -ge 533320)) {
        $dotnetUrl = "https://go.microsoft.com/fwlink/?linkid=2203304"
        $dotnetInstaller = "$env:TEMP\ndp481-x86-x64-allos-enu.exe"
        Start-BitsTransfer -Source $dotnetUrl -Destination $dotnetInstaller
        Start-Process -FilePath $dotnetInstaller -ArgumentList "/quiet /norestart" -Wait
        Remove-Item -Path $dotnetInstaller -Force
        $global:RebootRequired = $true
    }
    
    # P13: Install Mode Decision Point
    if ($InstallMode -eq "SMOnly") {
        Write-Log "SM Only mode: Skipping WSL2, Container Service, and SQL Server installation" -ForegroundColor Yellow
        Write-Log "Phase 1 complete for SM Only installation." -ForegroundColor Green
        
        # Force restart to go directly to Phase 4 (SM deployment)
        $global:RebootRequired = $true
        Handle-Restart -NextPhase 4 -Message "Phase 1 complete for SM Only installation. Restarting to proceed with SM deployment."
        return
    }
    
    Write-Log "All mode: Continuing with WSL2, Container Service, and SQL Server installation..." -ForegroundColor Yellow
    
    # Enable WSL and Virtual Machine Platform
    Write-Log "Enabling WSL and Virtual Machine Platform..." -ForegroundColor Yellow
    $wslEnabled = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
    if ($wslEnabled.State -ne "Enabled") {
        $wslResult = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
        if ($wslResult.RestartNeeded) {
            $global:RebootRequired = $true
        }
    }
    
    $vmPlatformEnabled = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
    if ($vmPlatformEnabled.State -ne "Enabled") {
        $vmResult = Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
        if ($vmResult.RestartNeeded) {
            $global:RebootRequired = $true
        }
    }
    
    # Enable Container feature
    Write-Log "Enabling Containers feature..." -ForegroundColor Yellow
    $containerEnabled = Get-WindowsOptionalFeature -Online -FeatureName Containers
    if ($containerEnabled.State -ne "Enabled") {
        $containerResult = Enable-WindowsOptionalFeature -Online -FeatureName Containers -NoRestart
        if ($containerResult.RestartNeeded) {
            $global:RebootRequired = $true
        }
    }
    
    # Enable Hyper-V feature
    Write-Log "Enabling Hyper-V feature..." -ForegroundColor Yellow
    
    # List of Hyper-V features to enable
    $hyperVFeatures = @(
        "Microsoft-Hyper-V"
    )
    
    # Check and enable each Hyper-V feature
    foreach ($feature in $hyperVFeatures) {
        $featureEnabled = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
        if ($featureEnabled -and $featureEnabled.State -ne "Enabled") {
            Write-Log "Installing Hyper-V feature: $feature" -ForegroundColor Yellow
            $featureResult = Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart
            if ($featureResult.RestartNeeded) {
                $global:RebootRequired = $true
            }
        } elseif ($featureEnabled) {
            Write-Log "Hyper-V feature $feature is already enabled." -ForegroundColor Green
        } else {
            Write-Log "Hyper-V feature $feature is not available on this system." -ForegroundColor Yellow
        }
    }
    
    # Install SQL Server 2022 Express
    Write-Log "Installing SQL Server 2022 Express..." -ForegroundColor Cyan
    
    # Check if SQL Server Express is already installed
    $instanceName = "SQLEXPRESS"
    $sqlServiceName = "MSSQL`$$instanceName"
    $sqlService = Get-Service -Name $sqlServiceName -ErrorAction SilentlyContinue
    
    if ($sqlService) {
        Write-Log "SQL Server Express instance '$instanceName' is already installed." -ForegroundColor Green
        Write-Log "Service status: $($sqlService.Status)" -ForegroundColor Green
        
        # Ensure the service is running
        if ($sqlService.Status -ne "Running") {
            Write-Log "Starting SQL Server service..." -ForegroundColor Yellow
            Start-Service -Name $sqlServiceName
        }
    } else {
        Write-Log "SQL Server Express not found. Installing SQL Server 2022 Express..." -ForegroundColor Yellow
        
        # Direct download URL for SQL Server 2022 Express
        $downloadUrl = "https://download.microsoft.com/download/3/8/d/38de7036-2433-4207-8eae-06e247e17b25/SQLEXPR_x64_ENU.exe"
        $outputPath = "$env:TEMP\SQLEXPR_x64_ENU.exe"
    
        # Save SQL password to a secure file
        $sqlPasswordFile = "$global:PersistentDir\sql-credentials.xml"
        if (-not (Test-Path $sqlPasswordFile)) {
            # Create a secure string from the password
            $securePassword = ConvertTo-SecureString $SqlSaPassword -AsPlainText -Force
            # Save the secure string to a file
            $securePassword | ConvertFrom-SecureString | Out-File $sqlPasswordFile
            Write-Log "SQL Server credentials saved securely." -ForegroundColor Green
        } else {
            Write-Log "Using existing SQL Server credentials." -ForegroundColor Green
        }

        
        Write-Log "Downloading SQL Server 2022 Express full installer..." -ForegroundColor Yellow
        
        # Download the installer using BITS
        Start-BitsTransfer -Source $downloadUrl -Destination $outputPath -DisplayName "SQL Server Express Download"
        
        Write-Log "Download completed." -ForegroundColor Green
        
        # Parameters for silent installation
        $installArgs = @(
            "/Q",
            "/IACCEPTSQLSERVERLICENSETERMS",
            "/ACTION=install",
            "/INSTANCEID=$instanceName",
            "/INSTANCENAME=$instanceName",
            "/FEATURES=SQLENGINE,FullText,Conn",
            "/SECURITYMODE=SQL",
            "/SAPWD=`"$SqlSaPassword`"",
            "/UPDATEENABLED=FALSE",
            "/BROWSERSVCSTARTUPTYPE=Automatic",
            "/TCPENABLED=1",
            "/SQLSVCACCOUNT=`"NT Service\MSSQL`$$instanceName`"",
            "/SQLSYSADMINACCOUNTS=`"BUILTIN\Administrators`"",
            "/ADDCURRENTUSERASSQLADMIN=True"
        )
        
        Write-Log "Starting silent installation of SQL Server 2022 Express..." -ForegroundColor Yellow
        Write-Log "This may take several minutes. Please wait..." -ForegroundColor Yellow
        
        # Run the installer with silent parameters
        $process = Start-Process -FilePath $outputPath -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
        $exitCode = $process.ExitCode
        
        if ($exitCode -ne 0) {
            Write-Error "SQL Server installation failed with exit code: $exitCode"
        } else {
            Write-Log "SQL Server 2022 Express installed successfully!" -ForegroundColor Green
        }
        
        # Clean up the installer
        Remove-Item -Path $outputPath -Force -ErrorAction SilentlyContinue
    }
    
    # Configure SQL Server to use TCP/IP and port 1433 for WSL access
    Write-Log "Configuring SQL Server to use TCP/IP and port 1433 for WSL access..." -ForegroundColor Cyan
    
    try {
        # Load the SQL Server SMO assembly
        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null
        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement") | Out-Null
        
        # Create a connection to the WMI provider
        $wmi = New-Object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer
        
        # Get the instance
        Write-Log "Finding SQL Server instance: $instanceName..." -ForegroundColor Yellow
        $serverInstance = $wmi.ServerInstances[$instanceName]
        
        if ($serverInstance -eq $null) {
            Write-Error "SQL Server instance '$instanceName' not found. Please check the instance name."
        } else {
            # Get the TCP protocol
            Write-Log "Configuring TCP/IP protocol..." -ForegroundColor Yellow
            $tcp = $serverInstance.ServerProtocols["Tcp"]
            
            if ($tcp -eq $null) {
                Write-Error "TCP protocol not found!"
            } else {
                # Enable TCP protocol if it's disabled
                if ($tcp.IsEnabled -eq $false) {
                    Write-Log "TCP/IP is currently DISABLED. Enabling it now..." -ForegroundColor Yellow
                    $tcp.IsEnabled = $true
                } else {
                    Write-Log "TCP/IP protocol is already enabled." -ForegroundColor Green
                }
                
                # Configure all IP addresses
                $configChanged = $false
                foreach ($ipAddress in $tcp.IPAddresses) {
                    $properties = $ipAddress.IPAddressProperties
                    
                    # Enable IP addresses if not already enabled
                    $enabled = $properties["Enabled"]
                    if ($enabled -ne $null -and $enabled.Value -ne $true) {
                        $enabled.Value = $true
                        Write-Log "Enabled IP Address: $($ipAddress.Name)" -ForegroundColor Yellow
                        $configChanged = $true
                    } elseif ($enabled -ne $null) {
                        Write-Log "IP Address $($ipAddress.Name) is already enabled." -ForegroundColor Green
                    }
                    
                    # Set static port 1433 for all IP addresses if not already set
                    $tcpPort = $properties["TcpPort"]
                    if ($tcpPort -ne $null -and $tcpPort.Value -ne "1433") {
                        $tcpPort.Value = "1433"
                        Write-Log "Set port 1433 for IP Address: $($ipAddress.Name)" -ForegroundColor Yellow
                        $configChanged = $true
                    } elseif ($tcpPort -ne $null) {
                        Write-Log "IP Address $($ipAddress.Name) is already configured for port 1433." -ForegroundColor Green
                    }
                    
                    # Disable dynamic ports if not already disabled
                    $dynamicPorts = $properties["TcpDynamicPorts"]
                    if ($dynamicPorts -ne $null -and $dynamicPorts.Value -ne "") {
                        $dynamicPorts.Value = ""
                        Write-Log "Disabled dynamic ports for IP Address: $($ipAddress.Name)" -ForegroundColor Yellow
                        $configChanged = $true
                    } elseif ($dynamicPorts -ne $null) {
                        Write-Log "Dynamic ports already disabled for IP Address: $($ipAddress.Name)" -ForegroundColor Green
                    }
                }
                
                # Apply the changes only if configuration was changed
                if ($configChanged) {
                    $tcp.Alter()
                    Write-Log "TCP/IP configuration changes applied successfully." -ForegroundColor Green
                    
                    # Restart the SQL Server service for changes to take effect
                    Write-Log "Restarting SQL Server service to apply changes..." -ForegroundColor Yellow
                    $serviceName = "MSSQL`$$instanceName"
                    Restart-Service -Name $serviceName -Force
                } else {
                    Write-Log "TCP/IP configuration is already correct. No changes needed." -ForegroundColor Green
                }
                
                # Also make sure SQL Browser is running
                $browserService = Get-Service -Name "SQLBrowser" -ErrorAction SilentlyContinue
                if ($browserService -ne $null) {
                    if ($browserService.Status -ne "Running") {
                        Write-Log "Starting SQL Browser service..." -ForegroundColor Yellow
                        Start-Service -Name "SQLBrowser"
                        Set-Service -Name "SQLBrowser" -StartupType Automatic
                        Write-Log "SQL Browser service started and set to automatic startup." -ForegroundColor Green
                    } else {
                        Write-Log "SQL Browser service is already running." -ForegroundColor Green
                    }
                }
                
                # Verify that SQL Server is now listening on port 1433
                Write-Log "Verifying SQL Server is listening on port 1433..." -ForegroundColor Yellow
                
                $tcpConnections = netstat -ano | findstr :1433 | findstr LISTENING
                if ($tcpConnections) {
                    Write-Log "SUCCESS: SQL Server is now listening on port 1433" -ForegroundColor Green
                } else {
                    Write-Log "WARNING: SQL Server doesn't appear to be listening on port 1433. Additional configuration may be needed." -ForegroundColor Red
                }
                
                # Add Windows Firewall rule for SQL Server
                Write-Log "Adding Windows Firewall rule for SQL Server on port 1433..." -ForegroundColor Yellow
                
                $firewallRuleName = "SQL Server $instanceName (TCP 1433)"
                $existingRule = Get-NetFirewallRule -DisplayName $firewallRuleName -ErrorAction SilentlyContinue
                
                # Known WSL2 subnets and localhost
                $allowedAddresses = @(
                    "127.0.0.1",           # Localhost
                    "172.16.0.0/12",       # Common WSL2 subnet range
                    "192.168.0.0/16"       # Alternative WSL2 subnet range
                )
                
                if ($existingRule -eq $null) {
                    New-NetFirewallRule -DisplayName $firewallRuleName -Direction Inbound -Protocol TCP -LocalPort 1433 -RemoteAddress $allowedAddresses -Action Allow | Out-Null
                    Write-Log "Firewall rule added for SQL Server on port 1433 (localhost and WSL subnets only)." -ForegroundColor Green
                } else {
                    Write-Log "Firewall rule for SQL Server already exists." -ForegroundColor Green
                }
                
                Write-Log "SQL Server is now configured to be accessible from WSL on port 1433." -ForegroundColor Green
                Write-Log "You can connect from WSL using: sqlcmd -S host.docker.internal,1433 -U sa -P '<your-password>'" -ForegroundColor Cyan
                Write-Log "Note: Replace <your-password> with the SQL Server SA password." -ForegroundColor Yellow
                Write-Log "For security, the password is stored securely at: $sqlPasswordFile" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Error "An error occurred while configuring SQL Server: $_"
        Write-Log "You may need to manually configure SQL Server using SQL Server Configuration Manager." -ForegroundColor Yellow
    }
    
    # If a restart is required, set up to continue with Phase 2 after restart
    if ($global:RebootRequired) {
        Handle-Restart -NextPhase 2 -Message "Phase 1 complete. A restart is required before continuing to Phase 2 (Ubuntu installation)."
    } else {
        # If no restart is required, proceed to Phase 2
        $InstallPhase = 2
        Write-Log "No restart required. Proceeding to Phase 2..." -ForegroundColor Green
    }
}

# Function to configure WSL persistence to prevent 60-second timeout
function Configure-WSLPersistence {
    Write-Log "Configuring WSL persistence to prevent 60-second timeout..." -ForegroundColor Cyan
    
    try {
        # Check if WSL-KeepAlive task already exists
        $existingTask = Get-ScheduledTask -TaskName "WSL-KeepAlive" -ErrorAction SilentlyContinue
        
        if ($existingTask) {
            Write-Log "WSL-KeepAlive scheduled task already exists" -ForegroundColor Yellow
            Write-Log "WSL persistence is already configured" -ForegroundColor Green
            return
        }
        
        # Create scheduled task to keep WSL alive across reboots
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $action = New-ScheduledTaskAction -Execute "wsl" -Argument "--exec dbus-launch true"
        
        # Prompt for password for reliable task authentication
        Write-Log "WSL persistence requires your user password for reliable task authentication." -ForegroundColor Yellow
        $credential = Get-Credential -UserName $env:USERNAME -Message "Enter your password to enable WSL persistence"
        
        if ($credential) {
            Register-ScheduledTask -TaskName "WSL-KeepAlive" -Trigger $trigger -Action $action -User $credential.UserName -Password $credential.GetNetworkCredential().Password -RunLevel Highest
            Start-ScheduledTask -TaskName "WSL-KeepAlive"
            Write-Log "WSL persistence scheduled task created successfully" -ForegroundColor Green
        } else {
            Write-Log "Password not provided. Attempting S4U method as fallback..." -ForegroundColor Yellow
            $principal = New-ScheduledTaskPrincipal -UserID $env:USERNAME -LogonType S4U -RunLevel Highest
            Register-ScheduledTask -TaskName "WSL-KeepAlive" -Trigger $trigger -Action $action -Principal $principal
            Start-ScheduledTask -TaskName "WSL-KeepAlive"
            Write-Log "WSL persistence configured with S4U method (may be less reliable)" -ForegroundColor Yellow
        }
        
        Write-Log "WSL will remain active and prevent Docker container shutdowns" -ForegroundColor Green
    }
    catch {
        Write-Log "Warning: Could not create WSL persistence task: $_" -ForegroundColor Yellow
        Write-Log "You may need to manually keep WSL active for container persistence" -ForegroundColor Yellow
    }
}

# Phase 2: Install Ubuntu on WSL with credentials
if ($InstallPhase -eq 2) {
    Write-Log "Phase 2: Installing Ubuntu on WSL with credentials" -ForegroundColor Cyan
    
    # Update WSL
    Write-Log "Updating WSL..." -ForegroundColor Yellow
    try {
        $wslUpdateResult = Invoke-Expression "wsl --update" 2>&1
        Write-Log "WSL update result: $wslUpdateResult" -ForegroundColor Green
    }
    catch {
        Write-Error "An error occurred while updating WSL: ${_}"
    }
    
    # Set WSL2 as the default version
    Write-Log "Setting WSL2 as the default version..." -ForegroundColor Yellow
    try {
        $wslSetDefaultResult = Invoke-Expression "wsl --set-default-version 2" 2>&1
        Write-Log "WSL2 set as default version: $wslSetDefaultResult" -ForegroundColor Green
    }
    catch {
        Write-Error "An error occurred while setting WSL2 as the default version: ${_}"
    }
    
    # Install Ubuntu
    Write-Log "Checking for WSL Linux distributions..." -ForegroundColor Yellow
    $wslOutput = Invoke-Expression "wsl --list" 2>&1
    $wslOutputString = $wslOutput | Out-String
    
    # Debug: Show what we got from wsl --list
    Write-Log "WSL list output: $wslOutputString" -ForegroundColor Yellow
    
    # More thorough check for Ubuntu installation - check for various Ubuntu variations
    # Split output into lines and clean each line properly
    $wslLines = $wslOutputString -split "`n" | ForEach-Object { 
        # Remove null characters using regex, trim whitespace, and remove carriage returns
        ($_ -replace "`0", "").Trim() -replace "`r", ""
    }
    $hasUbuntu = $false
    
    # Check each line for Ubuntu
    foreach ($line in $wslLines) {
        if ($line.Length -gt 0 -and ($line.ToLower().Contains("ubuntu"))) {
            $hasUbuntu = $true
            Write-Log "Found Ubuntu distribution: '$line'" -ForegroundColor Green
            break
        }
    }
    $ubuntuRunning = $false
    
    # Debug: Show detection result
    Write-Log "Ubuntu detection result: $hasUbuntu" -ForegroundColor Yellow
    
    if ($hasUbuntu) {
        Write-Log "Ubuntu distribution found in WSL list. Testing functionality..." -ForegroundColor Yellow
        # Test if Ubuntu is actually functional by running a simple command
        try {
            $testOutput = Invoke-Expression "wsl -d Ubuntu -e echo 'test'" 2>&1
            Write-Log "Ubuntu test command output: $testOutput" -ForegroundColor Yellow
            if ($testOutput -contains "test" -or $testOutput -eq "test") {
                $ubuntuRunning = $true
                Write-Log "Ubuntu distribution is installed and functional." -ForegroundColor Green
            } else {
                Write-Log "Ubuntu test command did not return expected result. Will reinstall." -ForegroundColor Yellow
            }
        } catch {
            Write-Log "Ubuntu distribution found but not functional. Will reinstall. Error: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Log "No Ubuntu distribution found in WSL list." -ForegroundColor Yellow
    }
    
    if (-not $hasUbuntu -or -not $ubuntuRunning) {
        Write-Log "No Ubuntu distribution found. Installing Ubuntu..." -ForegroundColor Yellow
        
        # Download Ubuntu AppX package using robust download function
        $ubuntuAppxFile = "$env:TEMP\Ubuntu2004.appx"
        Write-Log "Ubuntu package is large (~400MB), this may take several minutes..." -ForegroundColor Yellow
        
        $downloadSuccess = Download-FileWithRetry -Url $UbuntuAppxUrl -OutputPath $ubuntuAppxFile -Description "Ubuntu AppX package"
        
        if (-not $downloadSuccess) {
            Write-Log "CRITICAL ERROR: Failed to download Ubuntu AppX package" -ForegroundColor Red
            Write-Log "This is a critical failure. The installation cannot continue without Ubuntu." -ForegroundColor Red
            Write-Log "Please check your internet connection and try again, or manually download Ubuntu from Microsoft Store." -ForegroundColor Red
            Read-Host "Press Enter to exit"
            exit 1
        }
        
        try {
            # Install required dependencies first
            Write-Log "Installing required dependencies for Ubuntu 22.04..." -ForegroundColor Yellow
            
            # Download and install Microsoft.VCLibs.140.00.UWPDesktop
            $vcLibsUrl = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
            $vcLibsFile = "$env:TEMP\Microsoft.VCLibs.x64.14.00.Desktop.appx"
            
            $vcLibsDownloadSuccess = Download-FileWithRetry -Url $vcLibsUrl -OutputPath $vcLibsFile -Description "Microsoft.VCLibs.140.00.UWPDesktop"
            
            if ($vcLibsDownloadSuccess) {
                try {
                    Write-Log "Installing Microsoft.VCLibs.140.00.UWPDesktop..." -ForegroundColor Yellow
                    Add-AppxPackage -Path $vcLibsFile -ForceApplicationShutdown
                    Remove-Item -Path $vcLibsFile -Force -ErrorAction SilentlyContinue
                    Write-Log "Microsoft.VCLibs.140.00.UWPDesktop installed successfully." -ForegroundColor Green
                }
                catch {
                    Write-Log "CRITICAL ERROR: Failed to install Microsoft.VCLibs.140.00.UWPDesktop dependency: $_" -ForegroundColor Red
                    Write-Log "This dependency is required for Ubuntu 22.04 installation" -ForegroundColor Red
                    Read-Host "Press Enter to exit"
                    exit 1
                }
            } else {
                Write-Log "CRITICAL ERROR: Failed to download Microsoft.VCLibs.140.00.UWPDesktop dependency" -ForegroundColor Red
                Write-Log "This dependency is required for Ubuntu 22.04 installation" -ForegroundColor Red
                Read-Host "Press Enter to exit"
                exit 1
            }
            
            # Install the AppX package directly
            Write-Log "Installing Ubuntu AppX package..." -ForegroundColor Yellow
            Add-AppxPackage -Path $ubuntuAppxFile -ForceApplicationShutdown
            
            # Initialize Ubuntu with root user immediately after installation
            Write-Log "Installing Ubuntu with root user..." -ForegroundColor Yellow
            Start-Process -FilePath "$HOME\AppData\Local\Microsoft\WindowsApps\ubuntu" -ArgumentList "install", "--root" -NoNewWindow -Wait
            
            # Verify installation
            Start-Sleep -Seconds 5
            $verifyOutput = Invoke-Expression "wsl --list" 2>&1
            $verifyOutputString = $verifyOutput | Out-String
            Write-Log "Verification - WSL list output: $verifyOutputString" -ForegroundColor Yellow
            
            # More robust check for Ubuntu in the WSL list (same logic as earlier detection)
            $verifyLines = $verifyOutputString -split "`n" | ForEach-Object { 
                # Remove null characters using regex, trim whitespace, and remove carriage returns
                ($_ -replace "`0", "").Trim() -replace "`r", ""
            }
            $ubuntuFoundInVerification = $false
            
            # Check each line for Ubuntu
            foreach ($line in $verifyLines) {
                if ($line.Length -gt 0 -and ($line.ToLower().Contains("ubuntu"))) {
                    $ubuntuFoundInVerification = $true
                    Write-Log "Verification: Found Ubuntu distribution: '$line'" -ForegroundColor Green
                    break
                }
            }
            
            if ($ubuntuFoundInVerification) {
                Write-Log "Ubuntu installation successful!" -ForegroundColor Green
                
                # Clean up
                Remove-Item -Path $ubuntuAppxFile -Force -ErrorAction SilentlyContinue
            } else {
                Write-Error "CRITICAL ERROR: Ubuntu installation verification failed."
                Write-Log "Ubuntu does not appear in WSL list after installation." -ForegroundColor Red
                Write-Log "This is a critical failure. The installation cannot continue without Ubuntu." -ForegroundColor Red
                Read-Host "Press Enter to exit"
                exit 1
            }
        }
        catch {
            Write-Error "CRITICAL ERROR: Ubuntu installation failed: $($_.Exception.Message)"
            Write-Log "This is a critical failure. The installation cannot continue without Ubuntu." -ForegroundColor Red
            Read-Host "Press Enter to exit"
            exit 1
        }
        
        # A restart is required after Ubuntu installation
        Handle-Restart -NextPhase 3 -Message "Phase 2 complete. A restart is required after Ubuntu installation before continuing to Phase 3 (Docker installation)."
    } else {
        Write-Log "Ubuntu distribution is already installed and functional." -ForegroundColor Green
        # If Ubuntu was already installed and functional, proceed to Phase 3
        $InstallPhase = 3
        Write-Log "Proceeding to Phase 3..." -ForegroundColor Green
    }
}

# Phase 3: Install Docker and Docker Compose
if ($InstallPhase -eq 3) {
    Write-Log "Phase 3: Installing Docker and Docker Compose" -ForegroundColor Cyan
    
    # Configure Docker daemon.json to use WSL2
    Write-Log "Configuring Docker to use WSL2..." -ForegroundColor Yellow
    
    $dockerConfigDir = "$env:ProgramData\docker\config"
    $dockerDaemonJson = "$dockerConfigDir\daemon.json"
    
    # Create the directory if it doesn't exist
    if (-not (Test-Path $dockerConfigDir)) {
        New-Item -Path $dockerConfigDir -ItemType Directory -Force | Out-Null
    }
    
    # Create or update the daemon.json file
    $daemonConfig = @{
        "experimental" = $true
        "features" = @{
            "buildkit" = $true
        }
    }
    
    $daemonConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $dockerDaemonJson
    
    # Install Docker
    Write-Log "Installing Docker CE..." -ForegroundColor Yellow
    
    # Check if Docker is already installed and functional
    $service = Get-Service -Name $global:DockerServiceName -ErrorAction SilentlyContinue
    $dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
    
    if ($service -and $dockerCommand) {
        Write-Log "Docker is already installed and available." -ForegroundColor Green
        Write-Log "Docker service status: $($service.Status)" -ForegroundColor Green
        
        # Ensure the service is running
        if ($service.Status -ne "Running") {
            Write-Log "Starting Docker service..." -ForegroundColor Yellow
            Start-Service -Name $global:DockerServiceName
        }
    } else {
        # Download Docker installation script from GitHub
        $dockerInstallScriptUrl = "https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1"
        $tempFile = [System.IO.Path]::GetTempFileName() + ".ps1"
        
        try {
            Start-BitsTransfer -Source $dockerInstallScriptUrl -Destination $tempFile
            
            # Build the parameter string for the Docker installation script
            $paramString = " -NoRestart"
            if ($DockerVersion -ne "latest") { $paramString += " -DockerVersion `"$DockerVersion`"" }
            
            # Execute the Docker installation script
            Write-Log "Executing Docker CE installation script..." -ForegroundColor Yellow
            Invoke-Expression "& `"$tempFile`"$paramString"
            
            # Clean up
            Remove-Item -Path $tempFile -Force
            
            Write-Log "Docker CE installation completed." -ForegroundColor Green
        }
        catch {
            Write-Error "An error occurred during Docker CE installation: ${_}"
            if (Test-Path $tempFile) {
                Remove-Item -Path $tempFile -Force
            }
        }
    }
    
    # Install Docker Compose
    Write-Log "Installing Docker Compose..." -ForegroundColor Yellow
    
    # Define paths
    $composeUrl = "https://github.com/docker/compose/releases/download/v$DockerComposeVersion/docker-compose-windows-x86_64.exe"
    $composePath = "$env:ProgramFiles\Docker\docker-compose.exe"
    $batchPath = "$env:SystemRoot\System32\docker-compose.bat"
    
    # Check if Docker Compose is already installed by checking for the executable
    if ((Test-Path $composePath) -and (Test-Path $batchPath)) {
        Write-Log "Docker Compose is already installed at: $composePath" -ForegroundColor Green
    } else {
        try {
            # Create the directory if it doesn't exist
            $composeDir = [System.IO.Path]::GetDirectoryName($composePath)
            if (-not (Test-Path $composeDir)) {
                New-Item -Path $composeDir -ItemType Directory -Force | Out-Null
            }
            
            # Download Docker Compose using BITS for faster transfer
            Write-Log "Downloading Docker Compose v$DockerComposeVersion..." -ForegroundColor Yellow
            Start-BitsTransfer -Source $composeUrl -Destination $composePath
            
            # Create a batch file for Docker Compose
            $batchContent = "@echo off`r`n`"$composePath`" %*"
            Set-Content -Path $batchPath -Value $batchContent -Force
            
            Write-Log "Docker Compose installed successfully." -ForegroundColor Green
            Write-Log "Executable: $composePath" -ForegroundColor Green
            Write-Log "Batch file: $batchPath" -ForegroundColor Green
        }
        catch {
            Write-Log "Error installing Docker Compose: $_" -ForegroundColor Red
        }
    }
    
    # Restart Docker service to apply changes
    Write-Log "Restarting Docker service to apply changes..." -ForegroundColor Yellow
    try {
        Restart-Service -Name $global:DockerServiceName -Force
        Write-Log "Docker service restarted successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to restart Docker service: ${_}"
    }
    
    # Configure systemd in WSL2 Ubuntu
    Write-Log "Configuring systemd in WSL2 Ubuntu..." -ForegroundColor Yellow
    try {
        # Check if systemd is already enabled in WSL
        Write-Log "Checking if systemd is enabled in WSL..." -ForegroundColor Yellow
        $systemdCheck = wsl -e bash -c "ps -p 1 -o comm= 2>/dev/null || echo 'not-systemd'" 2>&1
        
        if ($systemdCheck -match "systemd") {
            Write-Log "Systemd is already enabled in WSL." -ForegroundColor Green
        } else {
            Write-Log "Enabling systemd in WSL..." -ForegroundColor Yellow
            wsl -e bash -c "echo -e '[boot]\nsystemd=true' | sudo tee /etc/wsl.conf"
            Write-Log "Restarting WSL to enable systemd..." -ForegroundColor Yellow
            wsl --shutdown
            Start-Sleep 2
            $systemdVerify = wsl -e bash -c "ps -p 1 -o comm=" 2>&1
            if ($systemdVerify -match "systemd") {
                Write-Log "Systemd successfully enabled in WSL." -ForegroundColor Green
            } else {
                Write-Log "Warning: Systemd may not be fully enabled. Check manually if needed." -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Error "An error occurred while configuring systemd in WSL: ${_}"
    }
    
    # Install Docker inside WSL2 Ubuntu
    Write-Log "Installing Docker inside WSL2 Ubuntu..." -ForegroundColor Yellow
    $dockerSuccess = Install-DockerInWSL -DockerComposeVersion $DockerComposeVersion
    
    # Exit if Docker installation failed (critical for XMPro deployment)
    if (-not $dockerSuccess) {
        Write-Log "CRITICAL: Docker installation failed. Cannot proceed with XMPro deployment." -ForegroundColor Red
        Write-Log "Docker is required for the XMPro platform deployment." -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # Install Docker Compose inside WSL2 Ubuntu
    Write-Log "Installing Docker Compose inside WSL2 Ubuntu..." -ForegroundColor Yellow
    $composeSuccess = Install-DockerComposeInWSL -DockerComposeVersion $DockerComposeVersion
    
    # Exit if Docker Compose installation failed (critical for XMPro deployment)
    if (-not $composeSuccess) {
        Write-Log "CRITICAL: Docker Compose installation failed. Cannot proceed with XMPro deployment." -ForegroundColor Red
        Write-Log "Docker Compose is required for the XMPro platform deployment." -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    Write-Log "Phase 3 completed successfully!" -ForegroundColor Green
    Write-Log "You can now run Docker with WSL2 for Linux containers." -ForegroundColor Green
    Write-Log "Docker is also installed inside the WSL2 Ubuntu instance." -ForegroundColor Green
    
    # Restart before Phase 4 to ensure services are properly initialized
    Handle-Restart -NextPhase 4 -Message "Phase 3 complete. A restart is required to ensure all services are properly initialized before Phase 4 (Application Deployment)."
}

# Phase 4: Service Verification and Application Deployment
if ($global:CurrentPhase -eq 4 -or (-not $global:CurrentPhase -and -not $SkipApplicationDeployment)) {
    Write-Log "Phase 4: Service Verification and Application Deployment" -ForegroundColor Cyan
    
    # Re-verify all services are working properly after potential restart (skip for SM Only)
    if ($InstallMode -ne "SMOnly") {
        Write-Log "Re-verifying system services before application deployment..." -ForegroundColor Cyan
        
        # Optimize WSL networking before restart - Force disable vEthernet (nat) for migrate containers
        Write-Log "Optimizing WSL networking interfaces..." -ForegroundColor Cyan
        try {
            # Check if vEthernet (nat) interface exists and disable it
            $natInterface = Get-NetAdapter -Name "vEthernet (nat)" -ErrorAction SilentlyContinue
            if ($natInterface) {
                Write-Log "Found vEthernet (nat) interface - disabling to ensure migrate containers work properly..." -ForegroundColor Yellow
                try {
                    Disable-NetAdapter -Name "vEthernet (nat)" -Confirm:$false
                    Write-Log "Successfully disabled vEthernet (nat) interface" -ForegroundColor Green
                    Start-Sleep -Seconds 2
                }
                catch {
                    Write-Log "Warning: Could not disable vEthernet (nat): $_" -ForegroundColor Yellow
                }
            } else {
                Write-Log "vEthernet (nat) interface not found - no action needed" -ForegroundColor Green
            }
        }
        catch {
            Write-Log "Warning: Could not optimize WSL networking: $_" -ForegroundColor Yellow
        }
        
        # Restart WSL to ensure clean state
        Write-Log "Restarting WSL to ensure clean state..." -ForegroundColor Yellow
        try {
            wsl --shutdown
            wsl --exec dbus-launch true
            Start-Sleep -Seconds 5
            wsl echo "WSL restarted successfully"
            Write-Log "WSL restarted successfully" -ForegroundColor Green
        }
        catch {
            Write-Log "Warning: Could not restart WSL: $_" -ForegroundColor Yellow
        }
        
        # Verify Docker services
        Write-Log "Verifying Docker services..." -ForegroundColor Cyan
        try {
            $dockerVersion = docker --version
            Write-Log "Docker is accessible: $dockerVersion" -ForegroundColor Green
        }
        catch {
            Write-Log "Warning: Docker may not be properly initialized: $_" -ForegroundColor Yellow
            Write-Log "Attempting to start Docker..." -ForegroundColor Yellow
            Start-Service Docker -ErrorAction SilentlyContinue
        }
        
        # Verify SQL Server service
        Write-Log "Verifying SQL Server service..." -ForegroundColor Cyan
        $sqlService = Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
        if ($sqlService) {
            Write-Log "SQL Server service is running: $($sqlService.Name)" -ForegroundColor Green
        } else {
            Write-Log "Warning: SQL Server service may not be running" -ForegroundColor Yellow
        }
    
    }  else {
        # SM Only mode: Run p4-hook.ps1 if it exists
        $p4HookPath = "C:\XMPro\p4-hook.ps1"
        if (Test-Path $p4HookPath) {
            Write-Log "Running p4-hook.ps1 for SM Only mode..." -ForegroundColor Cyan
            try {
                & $p4HookPath
                Write-Log "p4-hook.ps1 executed successfully" -ForegroundColor Green
            }
            catch {
                Write-Log "Warning: Error executing p4-hook.ps1: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Log "p4-hook.ps1 not found at $p4HookPath - skipping" -ForegroundColor Gray
        }
    }
    
    Write-Log "Service verification complete. Proceeding to application deployment..." -ForegroundColor Green
    
    # Automatically proceed to application deployment if not skipped
    if (-not $SkipApplicationDeployment) {
        Write-Log "Starting application deployment..." -ForegroundColor Cyan
        
        # Function to download and execute application script
        function Invoke-ApplicationDeployment {
            param(
                [string]$AppScriptUrl,
                [string]$AppBaseUrl
            )
            
            
            $appScriptPath = "$global:PersistentDir\install-xmpro-application.ps1"
            $useLocalScript = $false
            
            # Check for local script files (zipped bundle scenario)
            $currentDir = ""
            
            try {
                if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
                    $currentDir = Split-Path -Parent $PSCommandPath
                }
                elseif ($PSScriptRoot -and (Test-Path $PSScriptRoot)) {
                    $currentDir = $PSScriptRoot
                }
                else {
                    $currentDir = Get-Location
                }
            }
            catch {
                Write-Log "ERROR: Could not detect script directory in Invoke-ApplicationDeployment: $_" -ForegroundColor Red
                $currentDir = Get-Location
            }
            
            # Ensure currentDir is not null
            if (-not $currentDir -or $currentDir -eq "") {
                $currentDir = "C:\temp"
                Write-Log "WARNING: currentDir was null/empty, using fallback: '$currentDir'" -ForegroundColor Yellow
            }
            
            $localAppScript = Join-Path $currentDir "install-xmpro-application.ps1"
            
            if (Test-Path $localAppScript) {
                Write-Log "Found local install-xmpro-application.ps1, using local file" -ForegroundColor Green
                $appScriptPath = $localAppScript
                $useLocalScript = $true
                
                # Check for other bundle files and copy them to persistent directory if needed
                $bundleFiles = @("docker-compose.yml", "ca.sh", "issue.sh")
                foreach ($file in $bundleFiles) {
                    $localFile = Join-Path $currentDir $file
                    $targetFile = Join-Path $global:PersistentDir $file
                    
                    if (Test-Path $localFile) {
                        Write-Log "Found local $file, copying to persistent directory" -ForegroundColor Green
                        try {
                            Copy-Item $localFile $targetFile -Force
                        }
                        catch {
                            Write-Warning "Failed to copy $file : $_"
                        }
                    }
                }
            }
            elseif (-not [string]::IsNullOrEmpty($AppScriptUrl)) {
                Write-Log "Downloading install-xmpro-application.ps1 from: $AppScriptUrl" -ForegroundColor Yellow
                try {
                    Invoke-RestMethod -Uri $AppScriptUrl -OutFile $appScriptPath
                    Write-Log "Successfully downloaded application script" -ForegroundColor Green
                }
                catch {
                    Write-Error "Failed to download application script: $_"
                    return $false
                }
            }
            else {
                Write-Warning "No ApplicationScriptUrl provided and no local script found. Skipping application deployment."
                return $false
            }
            
            # Execute the application script
            if (Test-Path $appScriptPath) {
                Write-Log "Executing application deployment script..." -ForegroundColor Cyan
                try {
                    $appParams = @{
                        SkipEmailConfiguration = $false
                        DebugMode = $true
                        InstallMode = $InstallMode
                    }
                    
                    if (-not [string]::IsNullOrEmpty($AppBaseUrl)) {
                        $appParams.BaseUrl = $AppBaseUrl
                    }
                    
                    & $appScriptPath @appParams
                    Write-Log "Application deployment completed successfully!" -ForegroundColor Green
                    return $true
                }
                catch {
                    Write-Error "Application deployment failed: $_"
                    return $false
                }
            }
            else {
                Write-Error "Application script not found at: $appScriptPath"
                return $false
            }
        }
        
        # Call the application deployment
        $deploymentSuccess = Invoke-ApplicationDeployment -AppScriptUrl $ApplicationScriptUrl -AppBaseUrl $BaseUrl
        
        if ($deploymentSuccess) {
            Write-Log "Complete XMPro installation finished successfully!" -ForegroundColor Green
            
            # Check XMPro application container status
            Write-Log "Checking XMPro application containers..." -ForegroundColor Cyan
            try {
                $xmproContainers = @("xmpro-sh-1", "xmpro-ad-1", "xmpro-ds-1")
                foreach ($container in $xmproContainers) {
                    $status = wsl docker ps -a --filter "name=$container" --format "{{.Names}}: {{.Status}}"
                    if ($status) {
                        Write-Log $status -ForegroundColor White
                    } else {
                        Write-Log "${container}: Not found" -ForegroundColor Yellow
                    }
                }
            }
            catch {
                Write-Log "Could not check XMPro container status: $_" -ForegroundColor Yellow
            }
        }
        else {
            Write-Log "Machine preparation completed, but application deployment encountered issues." -ForegroundColor Yellow
            Write-Log "You can manually run install-xmpro-application.ps1 to complete the setup." -ForegroundColor Yellow
        }
    }
    else {
        Write-Log "Application deployment skipped. Run install-xmpro-application.ps1 manually to complete setup." -ForegroundColor Yellow
    }
    
    # Configure WSL persistence to prevent 60-second timeout (skip for SM Only)
    if ($InstallMode -ne "SMOnly") {
        Configure-WSLPersistence
    }
    
    # Mark Phase 4 as completed to prevent restart loop
    Write-Log "Phase 4 completed successfully!" -ForegroundColor Green
    
    # Clean up scheduled task to prevent restart loop
    Write-Log "Cleaning up scheduled tasks..." -ForegroundColor Cyan
    Write-Log "Looking for task named: $global:BootstrapTask" -ForegroundColor Cyan
    
    # List all tasks that might be related to XMPro
    try {
        $allTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*XMPRO*" -or $_.TaskName -like "*Bootstrap*" }
        if ($allTasks) {
            Write-Log "Found XMPro/Bootstrap related tasks:" -ForegroundColor Yellow
            foreach ($task in $allTasks) {
                Write-Log "  - $($task.TaskName) (State: $($task.State))" -ForegroundColor White
            }
        } else {
            Write-Log "No XMPro/Bootstrap related tasks found" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Log "Could not enumerate scheduled tasks: $_" -ForegroundColor Yellow
    }
    
    # Remove the specific ContainerBootstrap task (the actual task created)
    try {
        $specificTask = Get-ScheduledTask -TaskName "ContainerBootstrap" -ErrorAction SilentlyContinue
        if ($specificTask) {
            Write-Log "Removing scheduled task: ContainerBootstrap" -ForegroundColor Yellow
            Unregister-ScheduledTask -TaskName "ContainerBootstrap" -Confirm:$false
            Write-Log "Removed: ContainerBootstrap" -ForegroundColor Green
        } else {
            Write-Log "ContainerBootstrap task not found (may have been cleaned up already)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Log "Error cleaning up ContainerBootstrap task: $_" -ForegroundColor Red
    }
    
    # Prompt to press any key to continue
    Write-Log "Press any key to continue..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

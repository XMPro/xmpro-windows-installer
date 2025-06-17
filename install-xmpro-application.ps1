# Post-Installation Flow Script for XMPro
# This script handles the post-installation steps after the main installation (install-xmpro.ps1) has completed.
# Current flow:
# 1. Check Prerequisites and Create Environment File
# 2. Download Docker Compose File
# 3. Download CA Scripts and Create Private CA
# 4. Generate XMPro Certificates (SSL and JWT signing)
# 5. Add CA to Windows Trust Store
# 6. Run Single-Stage Docker Compose (all containers)
# 7. Wait for Database Migration Containers
# 8. Deploy SM in IIS with Enterprise Install.ps1
# 9. Perform Health Checks

param (
    [Parameter(Mandatory=$false)]
    [switch]$GenerateConfigFiles,
    
    [Parameter(Mandatory=$false)]
    [string]$DockerComposeDir = "$env:USERPROFILE\.xmpro-post-install\docker-compose",
    
    [Parameter(Mandatory=$false)]
    [string]$CertificatesDir = "$env:USERPROFILE\.xmpro-post-install\certificates",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipTrustStore,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipIISDeployment,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipDockerCompose,
    
    [Parameter(Mandatory=$false)]
    [string]$IISDeploymentScript = "",
    
    
    [Parameter(Mandatory=$false)]
    [string]$BaseUrl = "https://jstmpfls.z8.web.core.windows.net/",
    
    [Parameter(Mandatory=$false)]
    [string]$DockerComposeFileName = "docker-compose.yml",
    
    [Parameter(Mandatory=$false)]
    [string]$RegistryUrl = "xmprononprod.azurecr.io",
    
    [Parameter(Mandatory=$false)]
    [string]$RegistryVersion = "4.5.0-alpha",
    
    [Parameter(Mandatory=$false)]
    [switch]$UseScriptBasedCA = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$CertificatePassword = "somepassword",
    
    # SM IIS Deployment Parameters
    [Parameter(Mandatory=$false)]
    [string]$CompanyName = "XMPro",
    
    [Parameter(Mandatory=$false)]
    [string]$SqlServerName = "localhost",
    
    [Parameter(Mandatory=$false)]
    [string]$SmZipUrl = "https://jstmpfls.z8.web.core.windows.net/v2/Files-4.5.0-alpha/SM.zip",
    
    [Parameter(Mandatory=$false)]
    [string]$SmWebsiteName = "SM",
    
    [Parameter(Mandatory=$false)]
    [string]$SmWebsitePath = "C:\inetpub\wwwroot\XMPro-SM",
    
    [Parameter(Mandatory=$false)]
    [string]$SmAppPoolName = "XMPro-SM-AppPool",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipEmailConfiguration,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipHealthChecks,
    
    [Parameter(Mandatory=$false)]
    [switch]$DebugMode
)

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

# Function to get SQL SA password from secure file
function Get-SqlSaPassword {
    $sqlPasswordFile = "$env:USERPROFILE\.xmpro-install\sql-credentials.xml"
    
    if (Test-Path $sqlPasswordFile) {
        try {
            # Read the secure string from the file
            $securePasswordText = Get-Content $sqlPasswordFile
            
            # Convert the secure string back to plain text
            $securePassword = ConvertTo-SecureString $securePasswordText
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            
            return $plainPassword
        }
        catch {
            Write-Log "Error reading SQL password from secure file: $_" -ForegroundColor Red
            Write-Log "Using default password instead." -ForegroundColor Yellow
            return "YourStrongP@ssw0rd123"
        }
    }
    else {
        Write-Log "SQL password file not found at: $sqlPasswordFile" -ForegroundColor Yellow
        Write-Log "Using default password instead." -ForegroundColor Yellow
        return "YourStrongP@ssw0rd123"
    }
}

# Global variables
$global:PersistentDir = "$env:USERPROFILE\.xmpro-post-install"
$global:LogFile = "$global:PersistentDir\XMPro-Post-Install.log"
$global:EnvFile = "$global:PersistentDir\.env"
$global:DockerComposeFile = "$DockerComposeDir\$DockerComposeFileName"
$global:CertificatesDir = $CertificatesDir



# Database user credentials - randomized passwords for security (using GUIDs for simplicity)
$global:EnvCache = @{}


function Load-EnvCache {
    if (Test-Path $global:EnvFile) {
        $content = Get-Content $global:EnvFile
        foreach ($line in $content) {
            if ($line -match "^([^#][^=]+)=(.*)$") {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()
                $global:EnvCache[$key] = $value
            }
        }
        Write-Log "Loaded $($global:EnvCache.Count) environment variables from cache" -ForegroundColor Green
    }
}

function Set-FromEnv {
    param(
        [ref]$Variable,
        [string]$EnvVariableName,
        [string]$DefaultValue
    )
    
    if ($global:EnvCache.ContainsKey($EnvVariableName)) {
        $Variable.Value = $global:EnvCache[$EnvVariableName]
    } else {
        $Variable.Value = $DefaultValue
    }
}

$global:CAName = "xmpro-private-ca"
$global:CAContainerName = "xmpro-ca"
$global:CertificatesContainerName = "xmpro-certificates"

# Common variables used throughout the script - initialized at startup
$global:Hostname = [System.Net.Dns]::GetHostName().ToLower()
$global:ProductId = "380129dd-6ac3-47fc-a399-234394977680"  # XMPro Product ID
$global:SqlSaPassword = Get-SqlSaPassword
$global:SqlUsername = "sa"  # Always use SA for all database connections

$global:SmDbUser = "smuser"
$global:SmDbPassword = ""
$global:AdDbUser = "aduser"
$global:AdDbPassword = ""
$global:DsDbUser = "dsuser"
$global:DsDbPassword = ""
$global:DefaultCollectionId = ""
$global:DefaultCollectionSecret = ""

Load-EnvCache
Set-FromEnv ([ref]$global:SmDbUser) "SMDB_USER" $global:SmDbUser
Set-FromEnv ([ref]$global:AdDbUser) "ADDB_USER" $global:AdDbUser
Set-FromEnv ([ref]$global:DsDbUser) "DSDB_USER" $global:DsDbUser
Set-FromEnv ([ref]$global:SmDbPassword) "SMDB_PASSWORD" ([System.Guid]::NewGuid().ToString())
Set-FromEnv ([ref]$global:AdDbPassword) "ADDB_PASSWORD" ([System.Guid]::NewGuid().ToString())
Set-FromEnv ([ref]$global:DsDbPassword) "DSDB_PASSWORD" ([System.Guid]::NewGuid().ToString())
Set-FromEnv ([ref]$global:DefaultCollectionId) "DEFAULT_COLLECTION_ID" ([System.Guid]::NewGuid().ToString())
Set-FromEnv ([ref]$global:DefaultCollectionSecret) "DEFAULT_COLLECTION_SECRET" ([System.Guid]::NewGuid().ToString())

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires administrative privileges. Please run as administrator."
    exit
}

# Create persistent directory if it doesn't exist
if (-not (Test-Path $global:PersistentDir)) {
    New-Item -Path $global:PersistentDir -ItemType Directory -Force | Out-Null
}

# Create Docker Compose directory if it doesn't exist
if (-not (Test-Path $DockerComposeDir)) {
    New-Item -Path $DockerComposeDir -ItemType Directory -Force | Out-Null
}

# Create Certificates directory if it doesn't exist
if (-not (Test-Path $CertificatesDir)) {
    New-Item -Path $CertificatesDir -ItemType Directory -Force | Out-Null
}

# Function to write to log file

# Function to write debug messages (only when DebugMode is enabled)
function Write-Debug-Log {
    param (
        [string]$Message,
        [string]$ForegroundColor = "Cyan"
    )
    
    if ($DebugMode) {
        Write-Log "DEBUG: $Message" -ForegroundColor $ForegroundColor
    }
}



# Function to perform health checks on deployed applications
function Perform-HealthChecks {
    Write-Log "Starting health check for XMPro applications..." -ForegroundColor Yellow
    
    $healthResults = @()
    
    # First, check Docker container status
    Write-Log "Checking Docker container status..." -ForegroundColor Cyan
    
    $containerChecks = @(
        @{ Name = "AD (App Designer)"; ContainerName = "ad"; Port = "5202" },
        @{ Name = "DS (DataStream Designer)"; ContainerName = "ds"; Port = "5203" },
        @{ Name = "SH (Stream Host)"; ContainerName = "sh"; Port = "" }
    )
    
    $allContainersHealthy = $false
    $maxWaitTime = 120  # 2 minutes
    $checkInterval = 5  # 5 seconds
    $stabilityTime = 20  # 20 seconds of stable health required
    $elapsedTime = 0
    $healthyStartTime = $null  # When containers first became healthy
    
    Write-Log "Waiting up to $maxWaitTime seconds for containers to become healthy and stable for $stabilityTime seconds..." -ForegroundColor Cyan
    
    while ($elapsedTime -lt $maxWaitTime) {
        $allContainersHealthy = $true
        $containerStatuses = @()
        
        # Get all container info once (more efficient)
        try {
            $allContainers = wsl docker ps --format "{{.Names}}\\t{{.Status}}" 2>$null
        } catch {
            $allContainers = $null
            Write-Log "Error getting container status: $($_.Exception.Message)" -ForegroundColor Red
        }
        
        foreach ($container in $containerChecks) {
            $containerHealthy = $false
            
            try {
                # Find matching container from the single docker ps call
                $actualContainerName = $null
                $containerStatus = $null
                
                if ($allContainers -and $container.ContainerName) {
                    # Split into array first, then filter
                    $allLines = $allContainers -split "\n"
                    # Match containers that contain our target name (e.g., "ad" matches "xmpro-ad-1")
                    $lines = @($allLines | Where-Object { $_ -and $_ -match "\b$($container.ContainerName)\b" })
                    
                    
                    if ($lines -and $lines.Count -gt 0) {
                        # Now $lines should be a proper array, get the first line
                        $line = $lines[0]
                        
                        
                        # Parse the line
                        if ($line -and $line.Length -gt 1) {
                            # Use regex to parse: container name + whitespace + status
                            if ($line -match "^([^\s]+)\s+(.+)$") {
                                $actualContainerName = $matches[1].Trim()
                                $containerStatus = $matches[2].Trim()
                                
                            } else {
                            }
                        }
                    }
                }
                
                if ($actualContainerName -and $containerStatus) {
                    if ($containerStatus -match "Up") {
                        # Check for health status in the status string first (shows in docker ps)
                        if ($containerStatus -match "\(healthy\)") {
                            $containerHealthy = $true
                            $containerStatuses += "$($container.ContainerName): Healthy"
                        } elseif ($containerStatus -match "\(unhealthy\)") {
                            $containerStatuses += "$($container.ContainerName): Unhealthy"
                        } elseif ($containerStatus -match "\(starting\)") {
                            $containerStatuses += "$($container.ContainerName): Starting health check"
                        } else {
                            # No health check info in status, check inspect
                            $healthStatus = wsl docker inspect --format="{{.State.Health.Status}}" $actualContainerName 2>$null
                            if ($healthStatus -and $healthStatus.Trim() -ne "<no value>" -and $healthStatus.Trim() -ne "") {
                                if ($healthStatus.Trim() -eq "healthy") {
                                    $containerHealthy = $true
                                    $containerStatuses += "$($container.ContainerName): Healthy"
                                } else {
                                    $containerStatuses += "$($container.ContainerName): $($healthStatus.Trim())"
                                }
                            } else {
                                # No health check defined, assume healthy if running
                                $containerHealthy = $true
                                $containerStatuses += "$($container.ContainerName): Running (no health check)"
                            }
                        }
                    } else {
                        $containerStatuses += "$($container.ContainerName): Not running - $containerStatus"
                    }
                } else {
                    $containerStatuses += "$($container.ContainerName): Not found"
                }
            } catch {
                $containerStatuses += "$($container.ContainerName): Error - $($_.Exception.Message)"
            }
            
            if (-not $containerHealthy) {
                $allContainersHealthy = $false
            }
        }
        
        # Show current status
        if ($elapsedTime -eq 0) {
            Write-Log "Initial container status check:" -ForegroundColor Gray
        } else {
            Write-Log "Container status check (${elapsedTime}s elapsed):" -ForegroundColor Gray
        }
        
        foreach ($status in $containerStatuses) {
            if ($status -match "Healthy|Running") {
                Write-Log "  $status" -ForegroundColor Green
            } elseif ($status -match "starting|unhealthy") {
                Write-Log "  $status" -ForegroundColor Yellow
            } else {
                Write-Log "  $status" -ForegroundColor Red
            }
        }
        
        if ($allContainersHealthy) {
            if ($healthyStartTime -eq $null) {
                # First time all containers are healthy
                $healthyStartTime = $elapsedTime
                Write-Log "All containers are healthy! Monitoring stability for $stabilityTime seconds..." -ForegroundColor Yellow
            } else {
                # Check if containers have been stable long enough
                $healthyDuration = $elapsedTime - $healthyStartTime
                if ($healthyDuration -ge $stabilityTime) {
                    Write-Log "All containers have been healthy and stable for $healthyDuration seconds!" -ForegroundColor Green
                    break
                } else {
                    $remainingTime = $stabilityTime - $healthyDuration
                    Write-Log "Containers healthy for $healthyDuration seconds, need $remainingTime more seconds for stability" -ForegroundColor Yellow
                }
            }
        } else {
            # Reset stability timer if any container becomes unhealthy
            if ($healthyStartTime -ne $null) {
                Write-Log "Container health regressed, resetting stability timer" -ForegroundColor Yellow
                $healthyStartTime = $null
            }
        }
        
        # Only sleep and continue if we haven't met the stability requirement
        if ($elapsedTime -lt $maxWaitTime) {
            Write-Log "Waiting $checkInterval seconds before next check..." -ForegroundColor Gray
            Start-Sleep -Seconds $checkInterval
            $elapsedTime += $checkInterval
        }
        
    }
    
    if (-not $allContainersHealthy) {
        Write-Log "Timeout: Some containers did not become healthy within $maxWaitTime seconds" -ForegroundColor Red
        Write-Log "Checking container logs for troubleshooting..." -ForegroundColor Yellow
        
        # Show recent logs for all containers to help troubleshoot
        foreach ($container in $containerChecks) {
            try {
                # Find actual container name for logs
                $containerStatus = wsl docker ps -a --filter "name=$($container.ContainerName)" --format "{{.Names}}" 2>$null
                $actualContainerName = $null
                if ($containerStatus) {
                    $lines = $containerStatus -split "\n" | Where-Object { $_ -match $container.ContainerName }
                    if ($lines) {
                        $actualContainerName = $lines[0].Trim()
                    }
                }
                
                if ($actualContainerName) {
                    Write-Log "Recent logs for $($container.ContainerName) ($actualContainerName):" -ForegroundColor Gray
                    $logs = wsl docker logs --tail 15 $actualContainerName 2>$null
                    if ($logs) {
                        $logs | ForEach-Object { Write-Log "  $_" -ForegroundColor Gray }
                    } else {
                        Write-Log "  No logs available" -ForegroundColor Gray
                    }
                } else {
                    Write-Log "Recent logs for $($container.ContainerName): Container not found" -ForegroundColor Gray
                }
                Write-Log "" # Empty line for readability
            } catch {
                Write-Log "Could not retrieve logs for $($container.ContainerName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        Write-Log "Container issues detected. HTTP endpoint checks may fail." -ForegroundColor Yellow
    } else {
        Write-Log "All Docker containers are healthy. Proceeding with HTTP endpoint checks..." -ForegroundColor Green
        Write-Log "Waiting 10 seconds for HTTP endpoints to be ready..." -ForegroundColor Gray
        Start-Sleep -Seconds 10
    }
    
    # Define application endpoints to check
    $endpoints = @(
        @{
            Name = "SM (Subscription Manager)"
            Url = "https://$global:Hostname.local/version"
            FallbackUrl = "https://localhost/version"
            ExpectedContent = "version"
        },
        @{
            Name = "AD (App Designer)"
            Url = "https://localhost:5202/version"
            FallbackUrl = "http://localhost:5202/version"
            ExpectedContent = "version"
        },
        @{
            Name = "DS (DataStream Designer)"
            Url = "https://localhost:5203/version"
            FallbackUrl = "http://localhost:5203/version"
            ExpectedContent = "version"
        }
    )
    
    foreach ($endpoint in $endpoints) {
        Write-Log "Checking $($endpoint.Name)..." -ForegroundColor Cyan
        
        $result = @{
            Application = $endpoint.Name
            Status = "Unknown"
            ResponseTime = 0
            Version = "Unknown"
            Error = $null
        }
        
        try {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            
            # Try primary URL first with retries
            $maxRetries = 3
            $retryDelay = 2
            $success = $false
            
            for ($retry = 1; $retry -le $maxRetries; $retry++) {
                try {
                    $response = Invoke-WebRequest -Uri $endpoint.Url -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
                    $responseBody = $response.Content
                    $success = $true
                    break
                }
                catch {
                    Write-Log "Attempt $retry failed for $($endpoint.Url): $($_.Exception.Message)" -ForegroundColor Gray
                    if ($retry -lt $maxRetries) {
                        Start-Sleep -Seconds $retryDelay
                    }
                }
            }
            
            # Try fallback URL if primary failed
            if (-not $success -and $endpoint.FallbackUrl) {
                Write-Log "Primary URL failed after $maxRetries attempts, trying fallback: $($endpoint.FallbackUrl)" -ForegroundColor Yellow
                try {
                    $response = Invoke-WebRequest -Uri $endpoint.FallbackUrl -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
                    $responseBody = $response.Content
                    $success = $true
                }
                catch {
                    Write-Log "Fallback URL also failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            if (-not $success) {
                throw "All endpoints failed for $($endpoint.Name)"
            }
            
            $stopwatch.Stop()
            $result.ResponseTime = $stopwatch.ElapsedMilliseconds
            
            if ($response.StatusCode -eq 200) {
                $result.Status = "Healthy"
                
                # Try to extract version information from different possible fields
                if ($responseBody -match '"XMProPlatformVersion"\s*:\s*"([^"]+)"') {
                    $result.Version = $matches[1]
                } elseif ($responseBody -match '"version"\s*:\s*"([^"]+)"') {
                    $result.Version = $matches[1]  
                } elseif ($responseBody -match '"InformationalVersion"\s*:\s*"([^"]+)"') {
                    $version = $matches[1] -replace '\+.*$', '' # Remove commit hash suffix
                    $result.Version = $version
                }
                
                Write-Log "$($endpoint.Name): HEALTHY ($($stopwatch.ElapsedMilliseconds)ms) - Version: $($result.Version)" -ForegroundColor Green
            } else {
                $result.Status = "Unhealthy"
                $result.Error = "HTTP $($response.StatusCode)"
                Write-Log "$($endpoint.Name): UNHEALTHY - HTTP $($response.StatusCode)" -ForegroundColor Red
            }
        }
        catch {
            $stopwatch.Stop()
            $result.Status = "Unhealthy"
            $result.Error = $_.Exception.Message
            Write-Log "$($endpoint.Name): UNHEALTHY - $($_.Exception.Message)" -ForegroundColor Red
        }
        
        $healthResults += $result
    }
    
    # Summary
    Write-Log "`nHealth Check Summary:" -ForegroundColor Cyan
    Write-Log "===================" -ForegroundColor Cyan
    
    $healthyCount = ($healthResults | Where-Object { $_.Status -eq "Healthy" }).Count
    $totalCount = $healthResults.Count
    
    foreach ($result in $healthResults) {
        $statusColor = if ($result.Status -eq "Healthy") { "Green" } else { "Red" }
        $versionInfo = if ($result.Version -ne "Unknown") { " (v$($result.Version))" } else { "" }
        Write-Log "$($result.Application): $($result.Status)$versionInfo" -ForegroundColor $statusColor
    }
    
    Write-Log "`nOverall Status: $healthyCount/$totalCount applications healthy" -ForegroundColor $(if ($healthyCount -eq $totalCount) { "Green" } else { "Yellow" })
    
    # Log detailed results to file
    $healthResults | ConvertTo-Json -Depth 3 | Out-File -FilePath "$global:PersistentDir\health-check-results.json" -Encoding UTF8
    Write-Log "Detailed health check results saved to: $global:PersistentDir\health-check-results.json" -ForegroundColor Gray
}

# Function to get the version of currently deployed SM
function Get-DeployedSMVersion {
    
    try {
        # Check if SM is already deployed by checking if the directory exists
        if (-not (Test-Path $SmWebsitePath)) {
            Write-Log "SM website path does not exist: $SmWebsitePath" -ForegroundColor Yellow
            return $null
        }
        
        Write-Log "Checking deployed SM version using /version endpoint..." -ForegroundColor Yellow
        
        # Try to get version from /version endpoint
        $versionUrls = @(
            "https://$global:Hostname.local/version",
            "https://localhost/version",
            "https://sm/version"
        )
        
        foreach ($url in $versionUrls) {
            try {
                Write-Log "Trying version endpoint: $url" -ForegroundColor Gray
                $response = Invoke-WebRequest -Uri $url -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
                
                if ($response.StatusCode -eq 200) {
                    # Parse JSON response
                    $versionData = $response.Content | ConvertFrom-Json
                    
                    # Extract version from XMProPlatformVersion field
                    if ($versionData.XMProPlatformVersion) {
                        Write-Log "Found SM version from endpoint: $($versionData.XMProPlatformVersion)" -ForegroundColor Green
                        return $versionData.XMProPlatformVersion
                    }
                    
                    # Fallback to InformationalVersion if XMProPlatformVersion not found
                    if ($versionData.InformationalVersion) {
                        $version = $versionData.InformationalVersion -replace '\+.*$', '' # Remove commit hash suffix
                        Write-Log "Found SM version from InformationalVersion: $version" -ForegroundColor Green
                        return $version
                    }
                }
            }
            catch {
                Write-Log "Version endpoint $url not accessible: $($_.Exception.Message)" -ForegroundColor Gray
                # Continue to next URL
            }
        }
        
        Write-Log "SM /version endpoint not accessible - assuming SM is not running" -ForegroundColor Yellow
        return $null
    }
    catch {
        Write-Log "Error checking deployed SM version: $_" -ForegroundColor Yellow
        return $null
    }
}

# Function to extract target SM version from download URL
function Get-TargetSMVersion {
    
    try {
        # Extract version from URL pattern like "Files-4.4.18/SM.zip"
        if ($SmZipUrl -match "Files-(\d+\.\d+\.\d+)") {
            $version = $matches[1]
            Write-Log "Target SM version extracted from URL: $version" -ForegroundColor Green
            return $version
        }
        
        # Try other common patterns
        if ($SmZipUrl -match "(\d+\.\d+\.\d+)") {
            $version = $matches[1]
            Write-Log "Target SM version extracted: $version" -ForegroundColor Green
            return $version
        }
        
        Write-Log "Could not extract version from URL: $SmZipUrl" -ForegroundColor Yellow
        return "latest"
    }
    catch {
        Write-Log "Error extracting target SM version: $_" -ForegroundColor Yellow
        return "latest"
    }
}


# Function to check prerequisites
function Check-Prerequisites {
    Write-Log "Checking prerequisites..." -ForegroundColor Cyan
    
    # Check if Docker is installed
    try {
        $dockerVersion = docker --version
        Write-Log "Docker is installed: $dockerVersion" -ForegroundColor Green
    }
    catch {
        Write-Log "Docker is not installed or not in PATH. Please run the install-xmpro.ps1 script first." -ForegroundColor Red
        exit
    }
    
    # Check if Docker Compose is installed
    try {
        $dockerComposeVersion = docker-compose --version
        Write-Log "Docker Compose is installed: $dockerComposeVersion" -ForegroundColor Green
    }
    catch {
        Write-Log "Docker Compose is not installed or not in PATH. Please run the install-xmpro.ps1 script first." -ForegroundColor Red
        exit
    }
    
    # Check if WSL is installed
    try {
        $wslVersion = wsl --version
        Write-Log "WSL is installed: $wslVersion" -ForegroundColor Green
    }
    catch {
        Write-Log "WSL is not installed or not in PATH. Please run the install-xmpro.ps1 script first." -ForegroundColor Red
        exit
    }
    
    # Check if SQL Express is installed
    $sqlService = Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue
    if ($sqlService) {
        Write-Log "SQL Server is installed and service is $($sqlService.Status)" -ForegroundColor Green
        
        # Check if SQL Server is running
        if ($sqlService.Status -ne "Running") {
            Write-Log "Starting SQL Server service..." -ForegroundColor Yellow
            Start-Service -Name $sqlService.Name
            Write-Log "SQL Server service started." -ForegroundColor Green
        }
    }
    else {
        Write-Log "SQL Server is not installed. Please run the install-xmpro.ps1 script first." -ForegroundColor Red
        exit
    }
    
    Write-Log "All prerequisites are met." -ForegroundColor Green
}

# Function to create environment file
function Create-EnvironmentFile {
    Write-Log "Creating environment file..." -ForegroundColor Cyan
    
    # Create .env file with SQL_HOST
    "SQL_HOST=$global:Hostname.local" | Out-File -FilePath $global:EnvFile -Encoding ASCII
    # Create .env file with SQL_HOST
    "DB_SERVER=$global:Hostname.local" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add Windows IP for extra_hosts configuration
    
    # Add additional environment variables as needed
    "COMPOSE_PROJECT_NAME=xmpro" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Convert Windows path to WSL path for Docker volume mounting
    $wslCertificatesDir = "/mnt/c" + $CertificatesDir.Substring(2).Replace("\", "/")
    "CERTIFICATES_DIR=$wslCertificatesDir" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Create config directory for SH configuration
    $configDir = "$env:USERPROFILE\.xmpro-post-install\config"
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        Write-Log "Created config directory: $configDir" -ForegroundColor Green
    }
    $wslConfigDir = "/mnt/c" + $configDir.Substring(2).Replace("\", "/")
    "CONFIG_DIR=$wslConfigDir" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add database credentials
    "SQLCMDUSER=$global:SqlUsername" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DB_SA_PASSWORD=$sqlSaPassword" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "SQLCMDDBNAME=master" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add database user credentials
    "SMDB_USER=$global:SmDbUser" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "SMDB_PASSWORD=$global:SmDbPassword" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "ADDB_USER=$global:AdDbUser" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "ADDB_PASSWORD=$global:AdDbPassword" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DSDB_USER=$global:DsDbUser" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DSDB_PASSWORD=$global:DsDbPassword" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DEFAULT_COLLECTION_ID=$global:DefaultCollectionId" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DEFAULT_COLLECTION_SECRET=$global:DefaultCollectionSecret" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add connection strings
    #"SMDB_CONNECTIONSTRING=Server=tcp:${hostname}.local,1433;persist security info=True;user id=sa;password=$sqlSaPassword;Initial Catalog=SM;TrustServerCertificate=True;" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    #"ADDB_CONNECTIONSTRING=Server=tcp:${hostname}.local,1433;persist security info=True;user id=sa;password=$sqlSaPassword;Initial Catalog=AD;TrustServerCertificate=True;" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    #"DSDB_CONNECTIONSTRING=Server=tcp:${hostname}.local,1433;persist security info=True;user id=sa;password=$sqlSaPassword;Initial Catalog=DS;TrustServerCertificate=True;" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add company information
    "COMPANY_NAME=EvaluationCompany" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "COMPANY_ADMIN_FIRSTNAME=Admin" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "COMPANY_ADMIN_SURNAME=User" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "COMPANY_ADMIN_EMAILADDRESS=admin@xmpro.com" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "COMPANY_ADMIN_USERNAME=admin@xmpro.com" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "COMPANY_ADMIN_PASSWORD=Pass@word1" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add host variables
    "SM_HOST=$global:Hostname.local" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add service URLs
    "AD_BASEURL_CLIENT=https://localhost:5202/" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DS_BASEURL_CLIENT=https://localhost:5203/" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "SM_BASEURL_SERVER=https://$global:Hostname.local/" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "AD_BASEURL_SERVER=https://ad:8443/" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DS_BASEURL_SERVER=https://ds:8443/" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add registry information
    "REGISTRY_URL=$RegistryUrl" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "REGISTRY_VERSION=$RegistryVersion" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add certificate configuration
    "ASPNETCORE_Kestrel__Certificates__Default__Password=$CertificatePassword" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add product IDs and keys
    "AD_PRODUCT_ID=fe011f90-5bb6-80ad-b0a2-56300bf3b65d" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "AI_PRODUCT_ID=b7be889b-01d3-4bd2-95c6-511017472ec8" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DS_PRODUCT_ID=71435803-967a-e9ac-574c-face863f7ec0" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "SM_PRODUCT_ID=$global:ProductId" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "XMPRO_NOTEBOOK_PRODUCT_ID=c6de3c46-e8ab-4c71-8787-947e6fd2292c" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "AD_PRODUCT_KEY=f27eeb2d-c557-281c-9d4c-fe44cfb74a97" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "AI_PRODUCT_KEY=87c38802-cafb-cfb1-c966-182f86e09b99" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DS_PRODUCT_KEY=f744911d-e8a6-f8fb-9665-61b185845d6a" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "XMPRO_NOTEBOOK_PRODUCT_KEY=0c549103-d30a-c402-4b51-2df9e259043f" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add feature flags
    "AI_PRODUCT_ENABLE=true" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "SM_LOG_LEVEL=Information" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DS_LOG_LEVEL=Information" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "AD_LOG_LEVEL=Information" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "SM_TRUST_ALL_SSL_CERTIFICATES=true" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "AD_TRUST_ALL_SSL_CERTIFICATES=true" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    "DS_TRUST_ALL_SSL_CERTIFICATES=true" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "SH_NAME=XMPro-1click-Container" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    Write-Log "Environment file created at: $global:EnvFile" -ForegroundColor Green
    Write-Log "SQL_HOST is set to: $global:Hostname.local" -ForegroundColor Green
}

# Function to set environment variables for SM Install.ps1
function Set-SMInstallEnvironmentVariables {
    param(
        [string]$SqlServerName,
        [string]$SqlDatabaseName
    )
    
    # Certificate paths
    $tokenCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\sign.pfx"
    $sslCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\ssl.pfx"
    
    # Set environment variables for SM Install.ps1
    $env:PRODUCT_ID = $global:ProductId
    Write-Log "Setting PRODUCT_ID environment variable to: $($env:PRODUCT_ID)" -ForegroundColor Cyan
    $env:BASE_URL = "https://$global:Hostname.local/"
    $env:INTERNAL_BASE_URL = ""
    $env:SITE_PATH = $SmWebsitePath
    $env:SITE_NAME = $SmWebsiteName
    $env:APP_POOL_NAME = $SmAppPoolName
    
    # SSL Certificate (required)
    $env:SSL_CERT_PATH = $sslCertPath
    $env:SSL_CERT_PASSWORD = $CertificatePassword
    
    # Token Certificate (required) 
    $env:TOKEN_CERT_PATH = $tokenCertPath
    $env:TOKEN_CERT_PASSWORD = $CertificatePassword
    $env:TOKEN_CERT_SUBJECT = "CN=sm"
    $env:TOKEN_CERT_LOCATION = "LocalMachine"
    
    # Database settings
    $env:DB_CONNECTION_STRING = "Server=$SqlServerName;Database=$SqlDatabaseName;User Id=$global:SmDbUser;Password=$global:SmDbPassword;Encrypt=false;TrustServerCertificate=true;"
    $env:ENABLE_DB_MIGRATIONS = "false"
    $env:INCLUDE_AI_DB_MIGRATIONS = "false"
    
    # Security settings
    $env:AES_SALT = [System.Web.Security.Membership]::GeneratePassword(32, 8)
    
    # Email settings (disable for now)
    $env:ENABLE_EMAIL = "false"
    
    # Logging
    $env:LOG_LEVEL = "Verbose"
    $env:ENABLE_LOG_FILE_OUTPUT = "true"
    
    Write-Log "SM Install.ps1 environment variables set" -ForegroundColor Green
}

# Function to create SM signing certificate using OpenSSL
function New-SMSigningCertificate {
    param(
        [string]$CertificatePassword
    )
    
    Write-Log "Creating simple self-signed certificate with CN=sm..." -ForegroundColor Yellow
    
    # Create certificates directory if it doesn't exist
    $certsDir = Join-Path -Path $global:CertificatesDir -ChildPath "certs"
    if (!(Test-Path $certsDir)) {
        New-Item -ItemType Directory -Path $certsDir -Force | Out-Null
    }
    
    # Use OpenSSL in WSL to create simple certificate (like XMPro docs)
    $signKeyPath = Join-Path -Path $certsDir -ChildPath "sign.key"
    $signCrtPath = Join-Path -Path $certsDir -ChildPath "sign.crt"
    $signPfxPath = Join-Path -Path $certsDir -ChildPath "sign.pfx"
    
    # Convert Windows paths to WSL paths
    $wslCertsDir = $certsDir -replace "C:", "/mnt/c" -replace "\\", "/"
    $wslSignKey = "$wslCertsDir/sign.key"
    $wslSignCrt = "$wslCertsDir/sign.crt"
    $wslSignPfx = "$wslCertsDir/sign.pfx"
    
    Write-Log "Creating certificate files in: $certsDir" -ForegroundColor Yellow
    
    # Create self-signed certificate using OpenSSL with -legacy flag (requires OpenSSL 3.x in Ubuntu 22.04)
    Write-Log "Creating signing certificate using OpenSSL with -legacy flag..." -ForegroundColor Gray
    
    # Create simple self-signed certificate with CN=sm (4096-bit for better security)
    $opensslCmd1 = "wsl openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout `"$wslSignKey`" -out `"$wslSignCrt`" -subj `"/CN=sm`" -days 365"
    Write-Log "Running: $opensslCmd1" -ForegroundColor Gray
    Invoke-Expression $opensslCmd1
    
    # Export to PFX format using -legacy flag for .NET Framework compatibility (with certfile)
    $opensslCmd2 = "wsl openssl pkcs12 -export -legacy -out `"$wslSignPfx`" -inkey `"$wslSignKey`" -in `"$wslSignCrt`" -certfile `"$wslSignCrt`" -passout pass:`"$CertificatePassword`""
    Write-Log "Running: $opensslCmd2" -ForegroundColor Gray
    Invoke-Expression $opensslCmd2
    
    if ($LASTEXITCODE -ne 0) {
        Write-Log "OpenSSL -legacy flag failed, trying PowerShell fallback..." -ForegroundColor Yellow
        try {
            # Fallback to PowerShell with legacy CAPI provider
            $cert = New-SelfSignedCertificate -Subject "CN=sm" -CertStoreLocation "Cert:\LocalMachine\My" -KeyExportPolicy Exportable -NotAfter (Get-Date).AddDays(365) -KeyAlgorithm RSA -KeyLength 2048 -Provider "Microsoft RSA SChannel Cryptographic Provider"
            
            $securePassword = ConvertTo-SecureString $CertificatePassword -AsPlainText -Force
            Export-PfxCertificate -Cert $cert -FilePath $signPfxPath -Password $securePassword -Force | Out-Null
            
            Remove-Item -Path "Cert:\LocalMachine\My\$($cert.Thumbprint)" -Force
            Write-Log "PowerShell fallback certificate created successfully" -ForegroundColor Green
        } catch {
            Write-Log "PowerShell fallback also failed: $($_.Exception.Message)" -ForegroundColor Red
            
            # Final fallback to manual OpenSSL algorithms
            $opensslCmd2Final = "wsl openssl pkcs12 -export -out `"$wslSignPfx`" -inkey `"$wslSignKey`" -in `"$wslSignCrt`" -passout pass:`"$CertificatePassword`" -keypbe PBE-SHA1-RC2-40 -certpbe PBE-SHA1-RC2-40"
            Write-Log "Running final fallback: $opensslCmd2Final" -ForegroundColor Gray
            Invoke-Expression $opensslCmd2Final
        }
    }
    
    if (Test-Path $signPfxPath) {
        Write-Log "Successfully created certificate: $signPfxPath" -ForegroundColor Green
        Write-Log "Certificate will be imported by SM Install.ps1" -ForegroundColor Yellow
        
        return "cert-created"
    } else {
        Write-Log "Failed to create certificate with OpenSSL" -ForegroundColor Red
        return $null
    }
}

# Function to download Docker Compose file
function Download-DockerComposeFile {
    # Check for local files first (zipped bundle scenario)
    # Use a more reliable method to get script directory
    $scriptDir = ""
    
    
    # Method 1: Try to get the actual script file path
    try {
        if ($PSCommandPath -and $PSCommandPath.Length -gt 0 -and (Test-Path $PSCommandPath)) {
            $scriptDir = Split-Path -Parent $PSCommandPath
        }
        elseif ($MyInvocation.MyCommand.Path -and $MyInvocation.MyCommand.Path.Length -gt 0 -and (Test-Path $MyInvocation.MyCommand.Path)) {
            $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        }
        elseif ($PSScriptRoot -and $PSScriptRoot.Length -gt 0 -and (Test-Path $PSScriptRoot)) {
            $scriptDir = $PSScriptRoot
        }
        else {
            # Fallback: assume current directory
            $scriptDir = Get-Location
        }
    }
    catch {
        Write-Log "ERROR: Could not detect script directory: $_" -ForegroundColor Red
        $scriptDir = Get-Location
    }
    
    # Ensure scriptDir is not null or empty
    if (-not $scriptDir -or $scriptDir -eq "") {
        $scriptDir = "C:\temp"
        Write-Log "WARNING: scriptDir was null/empty, using fallback: '$scriptDir'" -ForegroundColor Yellow
    }
    $localDockerCompose = Join-Path -Path $scriptDir -ChildPath $DockerComposeFileName
    
    # First priority: Check if docker-compose.yml exists locally
    if (Test-Path $localDockerCompose) {
        Write-Log "Found local $DockerComposeFileName, using local file" -ForegroundColor Green
        Copy-Item -Path $localDockerCompose -Destination $global:DockerComposeFile -Force
        Write-Log "Local Docker Compose file used: $localDockerCompose" -ForegroundColor Green
        return
    }
    
    # Second priority: Try to download from URL if BaseUrl is provided
    if (-not [string]::IsNullOrEmpty($BaseUrl)) {
        Write-Log "Downloading Docker Compose file from $BaseUrl/$DockerComposeFileName..." -ForegroundColor Cyan
        
        try {
            # Create the URL
            $url = "$BaseUrl/$DockerComposeFileName"
            
            # Download the file
            Invoke-WebRequest -Uri $url -OutFile $global:DockerComposeFile
            
            Write-Log "Docker Compose file downloaded successfully to: $global:DockerComposeFile" -ForegroundColor Green
            return
        }
        catch {
            Write-Log "Error downloading Docker Compose file: $_" -ForegroundColor Yellow
        }
    }
    
    # No local file found and download failed
    Write-Log "No Docker Compose file found locally or remotely. Expected locations:" -ForegroundColor Red
    Write-Log "  - Local: $localDockerCompose" -ForegroundColor Red
    if (-not [string]::IsNullOrEmpty($BaseUrl)) {
        Write-Log "  - Remote: $BaseUrl/$DockerComposeFileName" -ForegroundColor Red
    }
    exit
}

# Function to download CA scripts
function Download-CAScripts {
    # Check for local files first (zipped bundle scenario)
    # Use a more reliable method to get script directory
    $scriptDir = ""
    
    
    # Method 1: Try to get the actual script file path
    try {
        if ($PSCommandPath -and $PSCommandPath.Length -gt 0 -and (Test-Path $PSCommandPath)) {
            $scriptDir = Split-Path -Parent $PSCommandPath
        }
        elseif ($MyInvocation.MyCommand.Path -and $MyInvocation.MyCommand.Path.Length -gt 0 -and (Test-Path $MyInvocation.MyCommand.Path)) {
            $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        }
        elseif ($PSScriptRoot -and $PSScriptRoot.Length -gt 0 -and (Test-Path $PSScriptRoot)) {
            $scriptDir = $PSScriptRoot
        }
        else {
            # Fallback: assume current directory
            $scriptDir = Get-Location
        }
    }
    catch {
        Write-Log "ERROR: Could not detect script directory: $_" -ForegroundColor Red
        $scriptDir = Get-Location
    }
    
    # Ensure scriptDir is not null or empty
    if (-not $scriptDir -or $scriptDir -eq "") {
        $scriptDir = "C:\temp"
        Write-Log "WARNING: scriptDir was null/empty, using fallback: '$scriptDir'" -ForegroundColor Yellow
    }
    $localCAScript = Join-Path -Path $scriptDir -ChildPath "ca.sh"
    $localIssueScript = Join-Path -Path $scriptDir -ChildPath "issue.sh"
    
    # CA scripts should be in the persistent directory
    $caScriptPath = Join-Path -Path $global:PersistentDir -ChildPath "ca.sh"
    $issueScriptPath = Join-Path -Path $global:PersistentDir -ChildPath "issue.sh"
    
    # Handle ca.sh
    if (Test-Path $localCAScript) {
        Write-Log "Found local ca.sh, using local file" -ForegroundColor Green
        Copy-Item -Path $localCAScript -Destination $caScriptPath -Force
        Write-Log "Local ca.sh copied to: $caScriptPath" -ForegroundColor Green
    }
    elseif (-not [string]::IsNullOrEmpty($BaseUrl)) {
        try {
            # Try to download ca.sh script
            Write-Log "Downloading ca.sh from $BaseUrl/ca.sh..." -ForegroundColor Cyan
            $caUrl = "$BaseUrl/ca.sh"
            Invoke-WebRequest -Uri $caUrl -OutFile $caScriptPath
            Write-Log "ca.sh downloaded successfully." -ForegroundColor Green
        }
        catch {
            Write-Log "Error downloading ca.sh: $_" -ForegroundColor Red
            Write-Log "ca.sh not found locally at: $localCAScript" -ForegroundColor Red
            exit
        }
    }
    else {
        Write-Log "No BaseUrl provided and ca.sh not found locally at: $localCAScript" -ForegroundColor Red
        exit
    }
    
    # Handle issue.sh
    if (Test-Path $localIssueScript) {
        Write-Log "Found local issue.sh, using local file" -ForegroundColor Green
        Copy-Item -Path $localIssueScript -Destination $issueScriptPath -Force
        Write-Log "Local issue.sh copied to: $issueScriptPath" -ForegroundColor Green
    }
    elseif (-not [string]::IsNullOrEmpty($BaseUrl)) {
        try {
            # Try to download issue.sh script
            Write-Log "Downloading issue.sh from $BaseUrl/issue.sh..." -ForegroundColor Cyan
            $issueUrl = "$BaseUrl/issue.sh"
            Invoke-WebRequest -Uri $issueUrl -OutFile $issueScriptPath
            Write-Log "issue.sh downloaded successfully." -ForegroundColor Green
        }
        catch {
            Write-Log "Error downloading issue.sh: $_" -ForegroundColor Red
            Write-Log "issue.sh not found locally at: $localIssueScript" -ForegroundColor Red
            exit
        }
    }
    else {
        Write-Log "No BaseUrl provided and issue.sh not found locally at: $localIssueScript" -ForegroundColor Red
        exit
    }
    
    # Make scripts executable in WSL
    try {
        if ($caScriptPath -and $caScriptPath.Length -gt 2) {
            $wslCaScriptPath = "/mnt/c" + $caScriptPath.Substring(2).Replace("\", "/")
            wsl chmod +x "$wslCaScriptPath"
        }
        
        if ($issueScriptPath -and $issueScriptPath.Length -gt 2) {
            $wslIssueScriptPath = "/mnt/c" + $issueScriptPath.Substring(2).Replace("\", "/")
            wsl chmod +x "$wslIssueScriptPath"
        }
        
        Write-Log "CA scripts made executable." -ForegroundColor Green
    }
    catch {
        Write-Log "Warning: Could not make scripts executable: $_" -ForegroundColor Yellow
    }
}





# Function to run Docker Compose for self-signed certificates

# Function to check if CA already exists
function Test-CAExists {
    $caCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "$global:CAName.crt"
    $caChainPath = Join-Path -Path $global:CertificatesDir -ChildPath "ca-chain.crt"
    $trustedCaPath = Join-Path -Path $global:CertificatesDir -ChildPath "trustedcerts\privateca\root-ca.crt"
    
    # Check if all required CA files exist
    return (Test-Path $caCertPath) -and (Test-Path $caChainPath) -and (Test-Path $trustedCaPath)
}

# Function to check if CA is already trusted in Windows
function Test-CAIsTrusted {
    $caCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "$global:CAName.crt"
    
    if (-not (Test-Path $caCertPath)) {
        return $false
    }
    
    try {
        # Get the certificate thumbprint
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caCertPath)
        $thumbprint = $cert.Thumbprint
        
        # Check if certificate exists in the trusted root store
        $trustedCert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $thumbprint }
        
        return $trustedCert -ne $null
    }
    catch {
        Write-Log "Error checking if CA is trusted: $_" -ForegroundColor Yellow
        return $false
    }
}

# Function to create private CA using local scripts
function Create-PrivateCAFromScript {
    # Check if CA already exists
    if (Test-CAExists) {
        Write-Log "Private CA already exists. Skipping CA creation..." -ForegroundColor Yellow
        return
    }
    
    Write-Log "Creating private CA using local scripts..." -ForegroundColor Cyan
    
    try {
        # Path to the local CA creation script in persistent directory
        $caScriptPath = Join-Path -Path $global:PersistentDir -ChildPath "ca.sh"
        $wslCaScriptPath = "/mnt/c" + $caScriptPath.Substring(2).Replace("\", "/")
        
        # Convert Windows certificates directory to WSL path
        $wslCertificatesDir = "/mnt/c" + $CertificatesDir.Substring(2).Replace("\", "/")
        
        # Create the certificates directory structure in WSL
        wsl mkdir -p "$wslCertificatesDir/certs"
        wsl mkdir -p "$wslCertificatesDir/trustedcerts/privateca"
        
        # Run the CA creation script in WSL
        Write-Log "Running CA creation script..." -ForegroundColor Yellow
        wsl bash -c "cd /tmp && bash '$wslCaScriptPath'"
        
        # Copy the CA certificates to the certificates directory (for Windows trust store)
        Write-Log "Copying CA certificates to certificates directory..." -ForegroundColor Yellow
        wsl bash -c "cp ~/js-private-ca/certs/ca.crt '$wslCertificatesDir/$global:CAName.crt'"
        wsl bash -c "cp ~/js-private-ca/intermediate/certs/intermediate.crt '$wslCertificatesDir/intermediate-ca.crt'"
        wsl bash -c "cp ~/js-private-ca/intermediate/certs/ca-chain.crt '$wslCertificatesDir/ca-chain.crt'"
        
        # Copy CA certificates to trustedcerts directory for container mounting
        Write-Log "Copying individual CA certificates to trustedcerts directory for containers..." -ForegroundColor Yellow
        wsl bash -c "cp ~/js-private-ca/certs/ca.crt '$wslCertificatesDir/trustedcerts/privateca/root-ca.crt'"
        wsl bash -c "cp ~/js-private-ca/intermediate/certs/intermediate.crt '$wslCertificatesDir/trustedcerts/privateca/intermediate-ca.crt'"
        
        # Verify the CA certificate was copied
        $caCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "$global:CAName.crt"
        if (Test-Path $caCertPath) {
            Write-Log "CA certificate created successfully at: $caCertPath" -ForegroundColor Green
        }
        else {
            Write-Log "Error: CA certificate not found after creation." -ForegroundColor Red
            exit
        }
    }
    catch {
        Write-Log "Error creating private CA: $_" -ForegroundColor Red
        exit
    }
}

# Function to check if XMPro certificates already exist
function Test-XMProCertificatesExist {
    $components = @("ds", "ad", "sh", "sm")
    
    # Check if all component certificates exist
    foreach ($component in $components) {
        $componentCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\$component.pfx"
        if (-not (Test-Path $componentCertPath)) {
            return $false
        }
    }
    
    # Check if SSL and signing certificates exist
    $sslCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\ssl.pfx"
    $signCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\sign.pfx"
    
    return (Test-Path $sslCertPath) -and (Test-Path $signCertPath)
}

# Function to generate certificates for XMPro components using local scripts
function Generate-XMProCertificatesFromScript {
    # Check if certificates already exist
    if (Test-XMProCertificatesExist) {
        Write-Log "XMPro certificates already exist. Skipping certificate generation..." -ForegroundColor Yellow
        return
    }
    
    Write-Log "Generating certificates for XMPro components using local scripts..." -ForegroundColor Cyan
    
    try {
        # Path to the local certificate issuance script in persistent directory
        $issueScriptPath = Join-Path -Path $global:PersistentDir -ChildPath "issue.sh"
        $wslIssueScriptPath = "/mnt/c" + $issueScriptPath.Substring(2).Replace("\", "/")
        
        # Convert Windows certificates directory to WSL path
        $wslCertificatesDir = "/mnt/c" + $global:CertificatesDir.Substring(2).Replace("\", "/")
        
        
        # XMPro components that need certificates
        $components = @("ds", "ad", "sh", "sm")
        
        foreach ($component in $components) {
            Write-Log "Generating certificate for $component component..." -ForegroundColor Yellow
            
            # Generate certificate with PFX for each component in the certs subdirectory
            # Pass the component name as both the certificate name and Common Name
            wsl bash -c "cd /tmp && bash '$wslIssueScriptPath' --name '$component' --common-name '$component' --pfx --pfx-password '$CertificatePassword' --output-dir '$wslCertificatesDir/certs'"
            
            # Verify the certificate was created
            $componentCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\$component.pfx"
            if (Test-Path $componentCertPath) {
                Write-Log "$component certificate created: $componentCertPath" -ForegroundColor Green
            }
            else {
                Write-Log "Warning: $component certificate not found at: $componentCertPath" -ForegroundColor Yellow
            }
        }
        
        # Generate SSL certificate for the hostname (for general SSL/TLS)
        Write-Log "Generating SSL certificate for $global:Hostname.local..." -ForegroundColor Yellow
        wsl bash -c "cd /tmp && bash '$wslIssueScriptPath' --name '$global:Hostname.local' --common-name '$global:Hostname.local' --pfx --pfx-password '$CertificatePassword' --output-dir '$wslCertificatesDir/certs'"
                
        # Create copies with expected names for backward compatibility (avoid symlink issues in containers)
        Write-Log "Creating certificate copies with expected names..." -ForegroundColor Yellow
        wsl bash -c "cd '$wslCertificatesDir/certs' && pwd && ls -la"
        wsl bash -c "cd '$wslCertificatesDir/certs' && cp '$global:Hostname.local.crt' ssl.crt"
        wsl bash -c "cd '$wslCertificatesDir/certs' && cp '$global:Hostname.local.key' ssl.key"
        wsl bash -c "cd '$wslCertificatesDir/certs' && cp '$global:Hostname.local.pfx' ssl.pfx"
        
        # Generate SM-specific signing certificate for JWT token signing
        Write-Log "Generating SM signing certificate for JWT tokens..." -ForegroundColor Yellow
        $smSigningThumbprint = New-SMSigningCertificate -CertificatePassword $CertificatePassword
        if ($smSigningThumbprint) {
            Write-Log "SM signing certificate created successfully with thumbprint: $smSigningThumbprint" -ForegroundColor Green
        } else {
            Write-Log "Warning: Failed to create SM signing certificate" -ForegroundColor Yellow
        }
        
        # Verify all component certificates were created
        $allCertsCreated = $true
        foreach ($component in $components) {
            $componentCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\$component.pfx"
            if (-not (Test-Path $componentCertPath)) {
                Write-Log "Error: $component certificate not found." -ForegroundColor Red
                $allCertsCreated = $false
            }
        }
        
        if ($allCertsCreated) {
            Write-Log "All XMPro component certificates generated successfully:" -ForegroundColor Green
            foreach ($component in $components) {
                $componentCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\$component.pfx"
                Write-Log "$component Certificate: $componentCertPath" -ForegroundColor Green
            }
            Write-Log "Certificate password: $CertificatePassword" -ForegroundColor Green
            Write-Log "Trusted CA certificates available at: $($global:CertificatesDir)\trustedcerts\privateca\" -ForegroundColor Green
        }
        else {
            Write-Log "Error: Some certificates were not created successfully." -ForegroundColor Red
            exit
        }
    }
    catch {
        Write-Log "Error generating XMPro certificates: $_" -ForegroundColor Red
        exit
    }
}

# Function to install XMPro SM in IIS
function Install-XMProSM {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SqlServerName,

        [Parameter(Mandatory = $false)]
        [string]$SqlDatabaseName = "SM",

        [Parameter(Mandatory = $false)]
        [string]$AppPoolDotNetVersion = "v4.0",

        [Parameter(Mandatory = $false)]
        [string]$CertificateSubject = "",

        [Parameter(Mandatory = $false)]
        [string]$CertificateThumbprint = ""
    )

    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "This script must be run as Administrator" -ForegroundColor Red
        return
    }

    # Check version compatibility before proceeding
    Write-Log "Checking SM version compatibility..." -ForegroundColor Cyan
    
    $currentVersion = Get-DeployedSMVersion
    $targetVersion = Get-TargetSMVersion
    
    Write-Log "Current SM version: $(if ($currentVersion) { $currentVersion } else { 'Not deployed' })" -ForegroundColor Yellow
    Write-Log "Target SM version: $targetVersion" -ForegroundColor Yellow
    
    # Skip deployment if versions match (unless it's unknown)
    if ($currentVersion -and $currentVersion -ne "unknown" -and $currentVersion -eq $targetVersion) {
        Write-Log "SM version $targetVersion is already deployed. Skipping deployment..." -ForegroundColor Green
        Write-Log "To force reinstallation, delete the existing deployment directory first." -ForegroundColor Yellow
        return
    }
    
    if ($currentVersion -and $currentVersion -ne "unknown") {
        Write-Log "Version mismatch detected. Upgrading from $currentVersion to $targetVersion..." -ForegroundColor Yellow
    } else {
        Write-Log "Proceeding with fresh SM installation (version: $targetVersion)..." -ForegroundColor Yellow
    }

    # Verify IIS is installed
    if (-not (Get-Service -Name W3SVC -ErrorAction SilentlyContinue)) {
        Write-Log "IIS is not installed. Please install IIS before running this script." -ForegroundColor Red
        return
    }

    # Create a temporary directory for downloads
    $tempDir = [System.IO.Path]::GetTempPath() + [System.IO.Path]::GetRandomFileName()
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    
    # Download SM.zip
    $zipFilePath = Join-Path -Path $tempDir -ChildPath "SM.zip"
    Write-Log "Downloading SM.zip from $SmZipUrl..." -ForegroundColor Yellow
    
    try {
        # Import BITS module
        Import-Module BitsTransfer -ErrorAction SilentlyContinue
        
        # Use BITS for large file downloads with progress and resume capability
        Start-BitsTransfer -Source $SmZipUrl -Destination $zipFilePath -DisplayName "Downloading SM.zip" -Description "XMPro SM deployment package"
        
        Write-Log "SM.zip downloaded successfully using BITS" -ForegroundColor Green
    }
    catch {
        Write-Log "BITS download failed, falling back to Invoke-WebRequest: $_" -ForegroundColor Yellow
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $SmZipUrl -OutFile $zipFilePath
            Write-Log "SM.zip downloaded successfully using fallback method" -ForegroundColor Green
        }
        catch {
            Write-Log "Failed to download SM.zip: $_" -ForegroundColor Red
            return
        }
    }

    # Create the IIS website directory for extraction
    if (-not (Test-Path $SmWebsitePath)) {
        New-Item -ItemType Directory -Path $SmWebsitePath -Force | Out-Null
        Write-Log "Created IIS website directory: $SmWebsitePath" -ForegroundColor Green
    }
    
    # Extract the zip file directly to the IIS website directory
    Write-Log "Extracting SM.zip directly to IIS website directory: $SmWebsitePath" -ForegroundColor Yellow
    try {
        Expand-Archive -Path $zipFilePath -DestinationPath $SmWebsitePath -Force
    }
    catch {
        Write-Log "Failed to extract SM.zip: $_" -ForegroundColor Red
        return
    }
    
    # Find the SM Install.ps1 file
    Write-Log "Searching for SM Install.ps1 file..." -ForegroundColor Yellow
    $installScriptFiles = Get-ChildItem -Path $SmWebsitePath -Filter "Install.ps1" -Recurse
    
    if ($installScriptFiles.Count -eq 0) {
        Write-Log "No Install.ps1 file found in the extracted SM.zip files." -ForegroundColor Red
        return
    }
    
    # Use the first Install.ps1 found
    $installScriptPath = $installScriptFiles[0].FullName
    $smExtractedPath = $installScriptFiles[0].DirectoryName
    Write-Log "Found Install.ps1 in: $smExtractedPath" -ForegroundColor Green
    
    # Initialize environment variables for SM Install.ps1
    Write-Log "Setting up environment variables for SM Install.ps1..." -ForegroundColor Yellow
    
    # Try to get existing Product ID from database, otherwise use default
    try {
        $global:ProductId = Invoke-Sqlcmd -ServerInstance $global:Hostname -Database "SM" -Username $global:SqlUsername -Password $global:SqlSaPassword -Query "SELECT Id FROM Product WHERE Name='XMPro'" | Select-Object -ExpandProperty Id
        Write-Log "Using existing XMPro Product ID: $global:ProductId" -ForegroundColor Green
    } catch {
        Write-Log "Could not query database for XMPro Product ID, using default..." -ForegroundColor Yellow
        # Keep the default ProductId already set in global variables
    }
    
    # Clean up any duplicate certificates before running SM Install.ps1
    Write-Log "Cleaning up duplicate certificates before SM Install.ps1..." -ForegroundColor Yellow
    try {
        $duplicateCerts = Get-ChildItem "Cert:\LocalMachine\My" | Where-Object { $_.Subject -ieq "CN=sm" }
        if ($duplicateCerts.Count -gt 1) {
            Write-Log "Found $($duplicateCerts.Count) certificates with CN=sm, removing duplicates..." -ForegroundColor Yellow
            # Keep the newest certificate, remove the rest
            $sortedCerts = $duplicateCerts | Sort-Object NotBefore -Descending
            for ($i = 1; $i -lt $sortedCerts.Count; $i++) {
                $certToRemove = $sortedCerts[$i]
                Write-Log "Removing duplicate certificate: $($certToRemove.Thumbprint)" -ForegroundColor Yellow
                Remove-Item -Path "Cert:\LocalMachine\My\$($certToRemove.Thumbprint)" -Force
            }
            Write-Log "Kept newest certificate: $($sortedCerts[0].Thumbprint)" -ForegroundColor Green
        }
    } catch {
        Write-Log "Warning: Could not clean up duplicate certificates: $_" -ForegroundColor Yellow
    }
    
    # Set all environment variables for SM Install.ps1 using centralized function
    Set-SMInstallEnvironmentVariables -SqlServerName $SqlServerName -SqlDatabaseName $SqlDatabaseName
    
    # Execute the SM Install.ps1
    Write-Log "" -ForegroundColor White
    Write-Log "=================================================================================" -ForegroundColor Cyan
    Write-Log "                         EXECUTING SM INSTALL.PS1                               " -ForegroundColor Cyan
    Write-Log "=================================================================================" -ForegroundColor Cyan
    Write-Log "" -ForegroundColor White
    
    try {
        Push-Location -Path $smExtractedPath
        
        # Build parameters hashtable based on what already exists
        $installParams = @{}
        
        # Check if app pool already exists
        $appPoolExists = Get-IISAppPool -Name $SmAppPoolName -ErrorAction SilentlyContinue
        if ($appPoolExists) {
            Write-Log "App pool $SmAppPoolName already exists, will skip creation" -ForegroundColor Yellow
            $installParams['NoAppPool'] = $true
        }
        
        # Check if SSL certificate already exists
        $sslCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\ssl.pfx"
        if (Test-Path $sslCertPath) {
            $sslCert = Get-ChildItem "Cert:\LocalMachine\My" | Where-Object { $_.Subject -like "*$($global:Hostname)*" } | Select-Object -First 1
            if ($sslCert) {
                Write-Log "SSL certificate found in certificate store, will skip import" -ForegroundColor Yellow
                $installParams['NoSslCert'] = $true
            }
        }
        
        # Check if token certificate already exists
        
        # Check if SM IIS site already exists
        $smSite = Get-Website -Name $SmWebsiteName -ErrorAction SilentlyContinue
        if ($smSite) {
            Write-Log "SM IIS site '$SmWebsiteName' already exists, will skip creation" -ForegroundColor Yellow
            $installParams['NoSite'] = $true
        }
        
        $installParams['NoTokenCert'] = $true
        
        # Execute with dynamic parameters and capture output
        # Debug environment variables before calling Install.ps1
        Write-Log "Environment variables before calling SM Install.ps1:" -ForegroundColor Magenta
        Write-Log "  PRODUCT_ID: $($env:PRODUCT_ID)" -ForegroundColor Magenta
        Write-Log "  BASE_URL: $($env:BASE_URL)" -ForegroundColor Magenta
        Write-Log "  SITE_NAME: $($env:SITE_NAME)" -ForegroundColor Magenta
        
        if ($installParams.Count -gt 0) {
            $paramString = ($installParams.Keys | ForEach-Object { "-$_" }) -join ' '
            Write-Log "Executing SM Install.ps1 with parameters: $paramString" -ForegroundColor Cyan
            Write-Log "--- SM Install.ps1 Output Start ---" -ForegroundColor Gray
            & $installScriptPath @installParams *>&1 | Tee-Object -Variable smOutput | Write-Host
            Write-Log "--- SM Install.ps1 Output End ---" -ForegroundColor Gray
        } else {
            Write-Log "Executing SM Install.ps1 with no skip parameters" -ForegroundColor Cyan
            Write-Log "--- SM Install.ps1 Output Start ---" -ForegroundColor Gray
            & $installScriptPath *>&1 | Tee-Object -Variable smOutput | Write-Host
            Write-Log "--- SM Install.ps1 Output End ---" -ForegroundColor Gray
        }
        
        Pop-Location
        
        Write-Log "" -ForegroundColor White
        Write-Log "=================================================================================" -ForegroundColor Cyan
        Write-Log "                      SM INSTALL.PS1 COMPLETED SUCCESSFULLY                     " -ForegroundColor Cyan
        Write-Log "=================================================================================" -ForegroundColor Cyan
        Write-Log "" -ForegroundColor White
        
        # Grant private key access now that Install.ps1 has created the app pool
        if ($certThumbprint) {
            Write-Log "Granting private key access after Install.ps1 completion..." -ForegroundColor Cyan
            Grant-CertificatePrivateKeyAccess -CertificateThumbprint $certThumbprint -AppPoolName $SmAppPoolName
        }
        
        # Force update SSL binding with our certificate
        Update-SSLBinding
        Configure-SigningCertificate
        
        # Restart IIS AppPool to apply certificate changes
        Write-Log "Restarting IIS AppPool to apply certificate changes..." -ForegroundColor Yellow
        try {
            Restart-WebAppPool -Name $SmAppPoolName -ErrorAction Stop
            Write-Log "IIS AppPool '$SmAppPoolName' restarted successfully" -ForegroundColor Green
        } catch {
            Write-Log "Warning: Could not restart IIS AppPool '$SmAppPoolName': $_" -ForegroundColor Yellow
        }
        
        # Clean up temporary files
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        
        # Determine the application URL
        $applicationUrl = "https://$hostname.local/"
        Write-Log "Installation completed successfully!" -ForegroundColor Green
        Write-Log "SM is now available at: $applicationUrl" -ForegroundColor Green
        Write-Log "Product ID: $($env:PRODUCT_ID)" -ForegroundColor Green
        # return
    }
    catch {
        Write-Log "" -ForegroundColor White
        Write-Log "=================================================================================" -ForegroundColor Red
        Write-Log "                        SM INSTALL.PS1 FAILED - ERROR                           " -ForegroundColor Red
        Write-Log "=================================================================================" -ForegroundColor Red
        Write-Log "Error executing SM Install.ps1: $_" -ForegroundColor Red
        Write-Log "SM Install.ps1 execution failed. Please check the error above." -ForegroundColor Red
        Write-Log "=================================================================================" -ForegroundColor Red
        Write-Log "" -ForegroundColor White
        Pop-Location -ErrorAction SilentlyContinue
        throw "SM Install.ps1 execution failed: $_"
    }

    # Set folder permissions
    Write-Log "Setting folder permissions..." -ForegroundColor Yellow
    try {
        # Verify the directory exists before setting permissions
        if (Test-Path -Path $SmWebsitePath) {
            $acl = Get-Acl -Path $SmWebsitePath
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS AppPool\$SmAppPoolName", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.SetAccessRule($accessRule)
            Set-Acl -Path $SmWebsitePath -AclObject $acl
            Write-Log "Folder permissions set successfully." -ForegroundColor Green
        }
        else {
            Write-Log "Cannot set folder permissions because the path $SmWebsitePath does not exist." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Log "Failed to set folder permissions: $_" -ForegroundColor Yellow
        Write-Log "You may need to manually set folder permissions in File Explorer." -ForegroundColor Yellow
    }

    # Ensure website is running
    $websiteState = (Get-WebsiteState -Name $SmWebsiteName).Value
    if ($websiteState -ne "Started") {
        Write-Log "Starting $SmWebsiteName..." -ForegroundColor Yellow
        try {
            Start-Website -Name $SmWebsiteName -ErrorAction Stop
            Write-Log "$SmWebsiteName started successfully." -ForegroundColor Green
        }
        catch {
            Write-Log "Could not start ${SmWebsiteName}: $_" -ForegroundColor Yellow
            Write-Log "You may need to manually start the ${SmWebsiteName} from IIS Manager." -ForegroundColor Yellow
        }
    }
    else {
        Write-Log "$SmWebsiteName is already running." -ForegroundColor Green
    }

    # Clean up temporary files
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

    # Get the website binding information for HTTPS
    $site = Get-Website -Name $SmWebsiteName
    $httpsBinding = $site.bindings.Collection | Where-Object { $_.protocol -eq "https" } | Select-Object -First 1
    $httpBinding = $site.bindings.Collection | Where-Object { $_.protocol -eq "http" } | Select-Object -First 1
    
    # Determine the application URL (prefer HTTPS)
    if ($httpsBinding) {
        $applicationUrl = "https://$global:Hostname.local/"
    } elseif ($httpBinding) {
        $bindingInfo = $httpBinding.bindingInformation.Split(":")
        $port = $bindingInfo[1]
        $applicationUrl = "http://localhost:$port/"
    } else {
        $applicationUrl = "https://$global:Hostname.local/"
    }
    
    Write-Log "Installation completed successfully!" -ForegroundColor Green
    Write-Log "SM is now available at: $applicationUrl" -ForegroundColor Green
    Write-Log "Product ID: $productId" -ForegroundColor Green
}

# Function to add private CA to Windows Trust Store
function Add-CAToTrustStore {
    # Check if CA is already trusted
    if (Test-CAIsTrusted) {
        Write-Log "CA certificate is already trusted in Windows Trust Store. Skipping..." -ForegroundColor Yellow
        return
    }
    
    Write-Log "Configuring IIS folder permissions..." -ForegroundColor Cyan
    
    # Set Full Control permissions for IIS_IUSRS on wwwroot folder
    $wwwrootPath = "C:\inetpub\wwwroot"
    
    if (Test-Path $wwwrootPath) {
        try {
            Write-Log "Setting Full Control permissions for IIS_IUSRS on $wwwrootPath..." -ForegroundColor Yellow
            
            # Get current ACL
            $acl = Get-Acl $wwwrootPath
            
            # Create access rule for IIS_IUSRS with Full Control
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            
            # Add the access rule to ACL
            $acl.SetAccessRule($accessRule)
            
            # Apply the modified ACL
            Set-Acl -Path $wwwrootPath -AclObject $acl
            
            Write-Log "IIS folder permissions configured successfully." -ForegroundColor Green
        }
        catch {
            Write-Log "Error setting IIS folder permissions: $_" -ForegroundColor Yellow
            Write-Log "You may need to manually set permissions for IIS_IUSRS on C:\inetpub\wwwroot" -ForegroundColor Yellow
        }
    }
    else {
        Write-Log "Warning: wwwroot path not found at $wwwrootPath" -ForegroundColor Yellow
    }
    
    Write-Log "Adding private CA to Windows Trust Store..." -ForegroundColor Cyan
    
    $caCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "$global:CAName.crt"
    
    if (-not (Test-Path $caCertPath)) {
        Write-Log "CA certificate not found at: $caCertPath" -ForegroundColor Red
        exit
    }
    
    try {
        # Import the CA certificate to the Root store
        Import-Certificate -FilePath $caCertPath -CertStoreLocation Cert:\LocalMachine\Root
        
        Write-Log "CA certificate added to Windows Trust Store successfully." -ForegroundColor Green
    }
    catch {
        Write-Log "Error adding CA certificate to Windows Trust Store: $_" -ForegroundColor Red
        exit
    }
}

# Function to force update SSL binding with our certificate
function Update-SSLBinding {
    try {
        Write-Log "Forcing SSL binding update with our certificate..." -ForegroundColor Cyan
        
        $sslCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\ssl.pfx"
        $siteName = $env:SITE_NAME
        if (-not $siteName) { $siteName = "SM" }
        
        if (Test-Path $sslCertPath) {
            $pfxData = Get-PfxData $sslCertPath -Password $(ConvertTo-SecureString $CertificatePassword -AsPlainText -Force)
            $certs = $pfxData.EndEntityCertificates
            if ($certs.Length -eq 0) { throw "No certs found in $sslCertPath" }
            if ($certs.Length -gt 1) { throw "More than one cert found in $sslCertPath" }
            $cert = $certs[0]
            $thumbprint = $cert.Thumbprint
            
            Import-Module WebAdministration -ErrorAction SilentlyContinue
            
            if (!(Test-Path "IIS:\Sites\$siteName")) { 
                Write-Log "$siteName IIS site not found - SSL binding update skipped" -ForegroundColor Yellow
                return
            }
            
            $site = Get-Item "IIS:\Sites\$siteName"
            $bindings = @($site.Bindings.Collection | Where-Object { $_.Protocol -eq 'https' })
            
            foreach ($binding in $bindings) {
                if ($binding.protocol -ine 'https') { 
                    Write-Log "Skipping non-HTTPS binding: $($binding.bindingInformation) (Protocol: $($binding.protocol))" -ForegroundColor Gray
                    continue 
                }
                Write-Log "Binding SSL cert to $siteName IIS site $($binding.bindingInformation)" -ForegroundColor Yellow
                $binding.AddSslCertificate($thumbprint, 'My')
            }
            
            Write-Log "SSL binding force update completed" -ForegroundColor Green
        } else {
            Write-Log "SSL certificate not found at: $sslCertPath" -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Warning: SSL binding force update failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Function to deploy SM in IIS
function Deploy-SMInIIS {
    Write-Log "Deploying SM in IIS using integrated Install-XMProSM..." -ForegroundColor Cyan
    
    # Call the integrated Install-XMPROSM function
    try {
        Install-XMProSM -SqlServerName $SqlServerName -CertificateThumbprint $certificateThumbprint
        Write-Log "SM deployment completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Log "Error deploying SM in IIS: $_" -ForegroundColor Red
        exit
    }
}




# Function to grant certificate private key access after Install.ps1
function Grant-CertificatePrivateKeyAccess {
    param(
        [string]$CertificateThumbprint,
        [string]$AppPoolName = $SmAppPoolName
    )
    
    Write-Log "Granting private key access for certificate: $CertificateThumbprint" -ForegroundColor Cyan
    
    try {
        # Find the certificate in the store
        $cert = Get-ChildItem "Cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }
        if (-not $cert) {
            Write-Log "Certificate not found in store" -ForegroundColor Red
            return $false
        }
        
        # Use certutil to find the private key container
        $certutilOutput = & certutil -store -v my $CertificateThumbprint 2>&1
        $privateKeyLine = $certutilOutput | Where-Object { $_ -match "Unique container name:" }
        
        if ($privateKeyLine -and $privateKeyLine -match "Unique container name:\s*(.+)") {
            $containerName = $matches[1].Trim()
            $keyPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$containerName"
            
            if (Test-Path $keyPath) {
                # Grant full control for signing operations
                icacls $keyPath /grant "IIS_IUSRS:(F)" 2>$null
                Write-Log "Granted full private key access to IIS_IUSRS" -ForegroundColor Green
                
                # Grant to specific app pool (should exist now)
                $appPool = Get-IISAppPool -Name $AppPoolName -ErrorAction SilentlyContinue
                if ($appPool) {
                    icacls $keyPath /grant "IIS AppPool\${AppPoolName}:(F)" 2>$null
                    Write-Log "Granted full private key access to app pool: $AppPoolName" -ForegroundColor Green
                } else {
                    Write-Log "App pool $AppPoolName still not found" -ForegroundColor Yellow
                }
                
                return $true
            } else {
                Write-Log "Private key file not found at: $keyPath" -ForegroundColor Yellow
                return $false
            }
        } else {
            Write-Log "Could not determine private key container name" -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Log "Error granting private key access: $_" -ForegroundColor Red
        return $false
    }
}

# Function to configure signing certificate with CSP compatibility and private key access
function Configure-SigningCertificate {
    param(
        [string]$AppPoolName = $SmAppPoolName,
        [string]$CertPassword = $CertificatePassword
    )
    
    Write-Log "Configuring signing certificate..." -ForegroundColor Cyan
    
    try {
        # Look for sign.pfx certificate (created above) or fallback to sm.pfx
        $signCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\sign.pfx"
        $smCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\sm.pfx"
        
        $certPathToUse = $null
        if (Test-Path $signCertPath) {
            $certPathToUse = $signCertPath
            Write-Log "Found signing certificate at: $signCertPath" -ForegroundColor Green
        } elseif (Test-Path $smCertPath) {
            $certPathToUse = $smCertPath
            Write-Log "Found SM certificate at: $smCertPath" -ForegroundColor Green
        }
        
        if ($certPathToUse) {
            # Import the certificate to Personal store
            $cert = Import-PfxCertificate -FilePath $certPathToUse -CertStoreLocation "Cert:\LocalMachine\My" -Password (ConvertTo-SecureString -String $CertPassword -AsPlainText -Force) -ErrorAction SilentlyContinue
            
            if ($cert) {
                Write-Log "SM certificate imported with thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
                Write-Log "SM certificate subject: $($cert.Subject)" -ForegroundColor Green
                Write-Log "SM certificate store location: LocalMachine\My" -ForegroundColor Green
                
                # Check certificate CSP compatibility and fix if needed
                Write-Log "Checking certificate CSP compatibility..." -ForegroundColor Yellow
                try {
                    $certCSP = ""
                    if ($cert.HasPrivateKey) {
                        try {
                            # Test if we can access the private key for JWT signing
                            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
                            $testData = [System.Text.Encoding]::UTF8.GetBytes("test")
                            $signature = $rsa.SignData($testData, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                            Write-Log "Certificate private key is accessible and compatible for JWT signing" -ForegroundColor Green
                        } catch [System.Security.Cryptography.CryptographicException] {
                            if ($_.Exception.Message -match "Invalid provider type") {
                                Write-Log "Certificate has incompatible CSP - attempting to fix..." -ForegroundColor Yellow
                                
                                # Export and re-import certificate with compatible CSP
                                $tempCertPath = "$env:TEMP\temp_sm_cert.pfx"
                                $certPassword = ConvertTo-SecureString -String "temp123!" -AsPlainText -Force
                                
                                # Export current certificate
                                Export-PfxCertificate -Cert $cert -FilePath $tempCertPath -Password $certPassword -Force | Out-Null
                                
                                # Remove old certificate
                                Remove-Item "Cert:\LocalMachine\My\$($cert.Thumbprint)" -Force
                                
                                # Import with updated parameters for better CSP compatibility
                                $newCert = Import-PfxCertificate -FilePath $tempCertPath -CertStoreLocation "Cert:\LocalMachine\My" -Password $certPassword -Exportable
                                
                                # Clean up temp file
                                Remove-Item $tempCertPath -Force
                                
                                $cert = $newCert
                                Write-Log "Certificate re-imported with compatible CSP" -ForegroundColor Green
                            } else {
                                throw $_
                            }
                        }
                    }
                } catch {
                    Write-Log "Warning: Could not verify/fix certificate CSP compatibility: $($_.Exception.Message)" -ForegroundColor Yellow
                }
                
                # Grant IIS AppPool access to certificate private key
                Write-Log "Granting IIS AppPool access to certificate private key..." -ForegroundColor Yellow
                try {
                    # Method 1: Grant permission to specific certificate private key
                    if ($cert.HasPrivateKey) {
                        try {
                            # Get the private key container name
                            $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
                            
                            # Try to get the key file path for newer certificate formats
                            $keyName = ""
                            if ($privateKey -is [System.Security.Cryptography.RSACng]) {
                                # CNG key - different path structure
                                $machineKeysPath = "$env:ProgramData\Microsoft\Crypto\Keys"
                                icacls $machineKeysPath /grant "IIS AppPool\${AppPoolName}:(R)" /T 2>$null | Out-Null
                            } else {
                                # Legacy CSP key
                                $machineKeysPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
                                icacls $machineKeysPath /grant "IIS AppPool\${AppPoolName}:(R)" /T 2>$null | Out-Null
                            }
                            
                            Write-Log "Granted private key access to IIS AppPool\${AppPoolName}" -ForegroundColor Green
                            
                        } catch {
                            # Fallback: Grant broader permissions to both key directories
                            $machineKeysPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
                            $cngKeysPath = "$env:ProgramData\Microsoft\Crypto\Keys"
                            
                            icacls $machineKeysPath /grant "IIS AppPool\${AppPoolName}:(R)" /T 2>$null | Out-Null
                            icacls $cngKeysPath /grant "IIS AppPool\${AppPoolName}:(R)" /T 2>$null | Out-Null
                            icacls $machineKeysPath /grant "IIS_IUSRS:(R)" /T 2>$null | Out-Null
                            icacls $cngKeysPath /grant "IIS_IUSRS:(R)" /T 2>$null | Out-Null
                            
                            Write-Log "Applied fallback certificate permissions to both CSP and CNG key stores" -ForegroundColor Yellow
                        }
                    }
                } catch {
                    Write-Log "Warning: Could not set certificate private key permissions: $($_.Exception.Message)" -ForegroundColor Yellow
                    Write-Log "Certificate may work but if you see private key errors, manually grant IIS AppPool access" -ForegroundColor Yellow
                }
                
                return $cert.Thumbprint
            } else {
                Write-Log "Failed to import SM certificate. Using fallback certificate for signing only." -ForegroundColor Yellow
                return $null
            }
        } else {
            Write-Log "SM certificate not found. Using fallback certificate for signing only." -ForegroundColor Yellow
            return $null
        }
    } catch {
        Write-Log "Error configuring signing certificate: $_" -ForegroundColor Red
        return $null
    }
}

# Function to configure HTTPS bindings and hosts file
function Configure-HttpsBindings {
    param(
        [string]$CertificateThumbprint,
        [string]$Hostname = $global:Hostname
    )
    
    Write-Log "Configuring HTTPS bindings..." -ForegroundColor Cyan
    
    try {
        # Get the certificate from the store
        $cert = Get-ChildItem "Cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }
        if (-not $cert) {
            Write-Log "Certificate with thumbprint $CertificateThumbprint not found in store" -ForegroundColor Red
            return $false
        }
        
        # Add HTTPS binding to Default Web Site for the SM application
        $httpsBindingExists = Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -HostHeader "$Hostname.local" -ErrorAction SilentlyContinue
        
        if (-not $httpsBindingExists) {
            Write-Log "Adding HTTPS binding for ${Hostname}.local:443..." -ForegroundColor Yellow
            New-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -HostHeader "$Hostname.local" -SslFlags 1
            
            # Bind the certificate to the HTTPS binding
            $binding = Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -HostHeader "$Hostname.local"
            $binding.AddSslCertificate($CertificateThumbprint, "My")
            
            Write-Log "HTTPS binding configured successfully for https://${Hostname}.local:443/" -ForegroundColor Green
        } else {
            Write-Log "HTTPS binding already exists for ${Hostname}.local:443, updating certificate..." -ForegroundColor Yellow
            
            # Update existing binding with new certificate
            try {
                $binding = Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -HostHeader "$Hostname.local"
                if ($binding) {
                    # Remove old certificate binding and add new one
                    $binding.RemoveSslCertificate()
                    $binding.AddSslCertificate($CertificateThumbprint, "My")
                    Write-Log "HTTPS binding updated with new certificate" -ForegroundColor Green
                }
            } catch {
                Write-Log "Could not update HTTPS binding certificate: $_" -ForegroundColor Yellow
                Write-Log "You may need to manually update the certificate in IIS Manager" -ForegroundColor Yellow
            }
        }
        
        # Also add HTTPS binding for "sm" hostname for easier access
        $smHttpsBinding = Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -HostHeader "sm" -ErrorAction SilentlyContinue
        if (-not $smHttpsBinding) {
            try {
                Write-Log "Adding HTTPS binding for sm:443..." -ForegroundColor Yellow
                New-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -HostHeader "sm" -SslFlags 1
                $smBinding = Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -HostHeader "sm"
                $smBinding.AddSslCertificate($CertificateThumbprint, "My")
                Write-Log "HTTPS binding for sm added successfully" -ForegroundColor Green
            } catch {
                Write-Log "Could not add sm HTTPS binding: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Log "HTTPS binding for sm already exists, updating certificate..." -ForegroundColor Yellow
            try {
                $smBinding = Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -HostHeader "sm"
                if ($smBinding) {
                    $smBinding.RemoveSslCertificate()
                    $smBinding.AddSslCertificate($CertificateThumbprint, "My")
                    Write-Log "HTTPS binding for sm updated with new certificate" -ForegroundColor Green
                }
            } catch {
                Write-Log "Could not update sm HTTPS binding certificate: $_" -ForegroundColor Yellow
            }
        }
        
        # Add "sm" to hosts file idempotently
        $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
        $hostsEntry = "127.0.0.1`tsm"
        
        try {
            $hostsContent = Get-Content $hostsFile -ErrorAction SilentlyContinue
            $smEntryExists = $hostsContent | Where-Object { $_ -match "^\s*127\.0\.0\.1\s+sm\s*$" }
            
            if (-not $smEntryExists) {
                Write-Log "Adding 'sm' to hosts file..." -ForegroundColor Yellow
                Add-Content -Path $hostsFile -Value $hostsEntry -Encoding ASCII
                Write-Log "Added '127.0.0.1 sm' to hosts file" -ForegroundColor Green
            } else {
                Write-Log "'sm' already exists in hosts file" -ForegroundColor Green
            }
        } catch {
            Write-Log "Could not update hosts file: $_" -ForegroundColor Yellow
            Write-Log "You may need to manually add '127.0.0.1 sm' to $hostsFile" -ForegroundColor Yellow
        }
        
        return $true
    } catch {
        Write-Log "Error configuring HTTPS binding: $_" -ForegroundColor Yellow
        Write-Log "SM application will use HTTP only." -ForegroundColor Yellow
        return $false
    }
}


# Function to wait for database migration containers to complete
function Wait-ForMigrationContainers {
    Write-Log "Monitoring database migration containers..." -ForegroundColor Cyan
    
    $migrationContainers = @("smdbmigrate", "addbmigrate", "dsdbmigrate")
    $maxWaitTime = 300 # 5 minutes
    $startTime = Get-Date
    
    # Constants to avoid PowerShell parsing issues
    $exitedSuccessPattern = "Exited \(0\)"
    $exitedFailurePattern = 'Exited \([1-9][0-9]*\)'
    $runningPattern = "Up"
    
    foreach ($containerName in $migrationContainers) {
        Write-Log "Waiting for ${containerName} to complete..." -ForegroundColor Yellow
        
        do {
            $elapsed = (Get-Date) - $startTime
            if ($elapsed.TotalSeconds -gt $maxWaitTime) {
                Write-Log "Timeout waiting for ${containerName} after $maxWaitTime seconds" -ForegroundColor Red
                break
            }
            
            # Check container status using docker ps
            $containerStatus = wsl docker ps -a --filter "name=$containerName" --format "table {{.Names}}\t{{.Status}}" 2>$null
            
            if ($containerStatus -match $exitedSuccessPattern) {
                Write-Log "$containerName completed successfully" -ForegroundColor Green
                break
            }
            elseif ($containerStatus -match $exitedFailurePattern) {
                Write-Log "$containerName failed with non-zero exit code" -ForegroundColor Red
                break
            }
            elseif ($containerStatus -match $runningPattern) {
                $elapsedSeconds = [math]::Round($elapsed.TotalSeconds)
                Write-Log "${containerName} still running... ${elapsedSeconds} seconds elapsed" -ForegroundColor Cyan
                Start-Sleep -Seconds 10
            }
            else {
                Write-Log "${containerName} not found or not started yet..." -ForegroundColor Yellow
                Start-Sleep -Seconds 5
            }
        } while ($true)
    }
    
    Write-Log "Database migration monitoring completed." -ForegroundColor Green
}

# Function to gracefully stop existing Docker Compose services
function Stop-DockerCompose {
    Write-Log "Stopping any existing Docker Compose services..." -ForegroundColor Cyan
    
    try {
        # Convert Windows paths to WSL paths
        $wslDockerComposeFile = "/mnt/c" + $global:DockerComposeFile.Substring(2).Replace("\", "/")
        $wslEnvFile = "/mnt/c" + $global:EnvFile.Substring(2).Replace("\", "/")
        
        # Try to stop and remove existing containers gracefully
        $downResult = wsl docker-compose -f $wslDockerComposeFile --env-file $wslEnvFile down 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Existing Docker Compose services stopped successfully." -ForegroundColor Green
        }
        else {
            Write-Log "No existing Docker Compose services found or already stopped." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Log "No existing Docker Compose services to stop (this is normal for first run)." -ForegroundColor Yellow
    }
}

# Function to run Docker Compose
function Run-DockerCompose {
    Write-Log "Running Docker Compose inside WSL..." -ForegroundColor Cyan
    
    try {
        # Create network if it doesn't exist
        wsl docker network create xmpro-network 2>$null
        
        # Convert Windows paths to WSL paths
        $wslDockerComposeFile = "/mnt/c" + $global:DockerComposeFile.Substring(2).Replace("\", "/")
        $wslEnvFile = "/mnt/c" + $global:EnvFile.Substring(2).Replace("\", "/")
        
        # Start all services in single deployment
        Write-Log "Starting all XMPro services..." -ForegroundColor Yellow
        wsl docker-compose -f $wslDockerComposeFile --env-file $wslEnvFile up -d
        
        # Wait for database migrations to complete before proceeding with SM installation
        Write-Log "Waiting for database migrations to complete..." -ForegroundColor Yellow
        Wait-ForMigrationContainers
        
        Write-Log "Docker Compose completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Log "Error running Docker Compose: $_" -ForegroundColor Red
        exit
    }
}

# Main execution flow
Write-Log "Starting XMPro Post-Installation..." -ForegroundColor Cyan

# Check prerequisites
Check-Prerequisites

# Create environment file
Create-EnvironmentFile

# Generate Config Files if requested
if ($GenerateConfigFiles) {
    Write-Log "Generating config files..." -ForegroundColor Cyan
    # Add code to generate config files
    Write-Log "Config files generated successfully." -ForegroundColor Green
}

# Download Docker Compose file
Download-DockerComposeFile

# Download CA scripts
Download-CAScripts

# Generate certificates if using script-based CA
if ($UseScriptBasedCA) {
    Write-Log "Using script-based CA creation..." -ForegroundColor Cyan
    Create-PrivateCAFromScript
    
    # Trust the CA immediately after generation
    if (-not $SkipTrustStore) {
        Add-CAToTrustStore
    }
    
    Generate-XMProCertificatesFromScript
}

# Run Docker Compose if not skipped
if (-not $SkipDockerCompose) {
    Stop-DockerCompose
    Run-DockerCompose
}

# Note: CA trust store is handled immediately after CA generation for script-based CA

# Deploy SM in IIS if not skipped
if (-not $SkipIISDeployment) {
    Deploy-SMInIIS
}

# Perform health checks on deployed applications if not skipped
if (-not $SkipHealthChecks) {
    Write-Log "Performing health checks on deployed applications..." -ForegroundColor Cyan
    Perform-HealthChecks
} else {
    Write-Log "Health checks skipped per user request." -ForegroundColor Yellow
}

Write-Log "XMPro Post-Installation completed successfully!" -ForegroundColor Green
Write-Log "You can now access the XMPro application." -ForegroundColor Green

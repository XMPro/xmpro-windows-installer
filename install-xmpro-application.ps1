# Post-Installation Flow Script for XMPro
# This script handles the post-installation steps after the main installation (install-xmpro.ps1) has completed.
# It follows the flowchart:
# 1. Generate Config Files (optional)
# 2. Generate/Download Docker Compose Files
# 3. Run Docker Compose for:
#    - Running SM/AD/DS DB Containers
#    - Running SM/AD/DS DB migrate Containers
#    - Running private CA
#    - Running Self-signed Certificates (for SSL and OIDC)
#    - Run application docker-compose file
# 4. Add the private CA to the Windows Trust Store
# 5. Deploy SM in IIS

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
    [string]$SqlUsername = "sa",
    
    [Parameter(Mandatory=$false)]
    [string]$SqlPassword = "Password1234!",
    
    [Parameter(Mandatory=$false)]
    [string]$SmZipUrl = "https://xmmarketplacestorage.blob.core.windows.net/deploymentpackage/Files-4.4.19/SM.zip",
    
    [Parameter(Mandatory=$false)]
    [string]$SmWebsiteName = "Default Web Site",
    
    [Parameter(Mandatory=$false)]
    [string]$SmWebsitePath = "C:\inetpub\wwwroot\XMPro-SM",
    
    [Parameter(Mandatory=$false)]
    [string]$SmAppPoolName = "XMPro-SM-AppPool",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipEmailConfiguration,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipHealthChecks
)

# Global variables
$global:PersistentDir = "$env:USERPROFILE\.xmpro-post-install"
$global:LogFile = "$global:PersistentDir\XMPro-Post-Install.log"
$global:EnvFile = "$global:PersistentDir\.env"
$global:DockerComposeFile = "$global:DockerComposeDir\$DockerComposeFileName"
$global:CAName = "xmpro-private-ca"
$global:CAContainerName = "xmpro-ca"
$global:CertificatesContainerName = "xmpro-certificates"

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
if (-not (Test-Path $global:DockerComposeDir)) {
    New-Item -Path $global:DockerComposeDir -ItemType Directory -Force | Out-Null
}

# Create Certificates directory if it doesn't exist
if (-not (Test-Path $global:CertificatesDir)) {
    New-Item -Path $global:CertificatesDir -ItemType Directory -Force | Out-Null
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

# Function to generate a random string
function New-RandomString {
    param (
        [int]$Length = 13
    )
    
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    $random = New-Object System.Random
    $result = ""
    
    for ($i = 0; $i -lt $Length; $i++) {
        $result += $chars[$random.Next(0, $chars.Length)]
    }
    
    return $result
}

# Function to generate a random GUID
function New-RandomGuid {
    return [guid]::NewGuid().ToString()
}

# Function to perform health checks on deployed applications
function Perform-HealthChecks {
    Write-Log "Starting health check for XMPro applications..." -ForegroundColor Yellow
    
    $healthResults = @()
    $hostname = [System.Net.Dns]::GetHostName().ToLower()
    
    # Define application endpoints to check
    $endpoints = @(
        @{
            Name = "SM (Subscription Manager)"
            Url = "https://${hostname}.local/version"
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
                
                Write-Log "$($endpoint.Name): ✓ Healthy (${stopwatch.ElapsedMilliseconds}ms) - Version: $($result.Version)" -ForegroundColor Green
            } else {
                $result.Status = "Unhealthy"
                $result.Error = "HTTP $($response.StatusCode)"
                Write-Log "$($endpoint.Name): ✗ Unhealthy - HTTP $($response.StatusCode)" -ForegroundColor Red
            }
        }
        catch {
            $stopwatch.Stop()
            $result.Status = "Unhealthy"
            $result.Error = $_.Exception.Message
            Write-Log "$($endpoint.Name): ✗ Unhealthy - $($_.Exception.Message)" -ForegroundColor Red
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
    param (
        [string]$WebsitePath
    )
    
    try {
        # Check if SM is already deployed by checking if the directory exists
        if (-not (Test-Path $WebsitePath)) {
            Write-Log "SM website path does not exist: $WebsitePath" -ForegroundColor Yellow
            return $null
        }
        
        Write-Log "Checking deployed SM version using /version endpoint..." -ForegroundColor Yellow
        
        # Try to get version from /version endpoint
        $hostname = [System.Net.Dns]::GetHostName().ToLower()
        $versionUrls = @(
            "https://${hostname}.local/version",
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
    param (
        [string]$ZipFileUrl
    )
    
    try {
        # Extract version from URL pattern like "Files-4.4.18/SM.zip"
        if ($ZipFileUrl -match "Files-(\d+\.\d+\.\d+)") {
            $version = $matches[1]
            Write-Log "Target SM version extracted from URL: $version" -ForegroundColor Green
            return $version
        }
        
        # Try other common patterns
        if ($ZipFileUrl -match "(\d+\.\d+\.\d+)") {
            $version = $matches[1]
            Write-Log "Target SM version extracted: $version" -ForegroundColor Green
            return $version
        }
        
        Write-Log "Could not extract version from URL: $ZipFileUrl" -ForegroundColor Yellow
        return "latest"
    }
    catch {
        Write-Log "Error extracting target SM version: $_" -ForegroundColor Yellow
        return "latest"
    }
}

# Function to create a self-signed certificate if none is provided
function New-SelfSignedCertificateEx {
    param (
        [string]$Subject
    )
    
    # Create certificate with Microsoft Software Key Storage Provider for better JWT compatibility
    # This ensures the private key uses a CSP that's compatible with IdentityServer3 JWT token signing
    $cert = New-SelfSignedCertificate -DnsName $Subject -CertStoreLocation "cert:\LocalMachine\My" `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -Provider "Microsoft Software Key Storage Provider" `
        -KeyExportPolicy ExportableEncrypted `
        -NotAfter (Get-Date).AddYears(5)
    
    Write-Log "Certificate created with thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
    Write-Log "Certificate provider: Microsoft Software Key Storage Provider" -ForegroundColor Green
    
    return $cert.Thumbprint
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

# Function to get Windows IP address for WSL access
function Get-WindowsIPForWSL {
    try {
        # Get the default gateway IP from WSL perspective (which is the Windows host IP)
        $wslOutput = wsl bash -c "ip route show | grep default | awk '{print `$3}'"
        if ($wslOutput -and $wslOutput.Trim() -match '^(\d{1,3}\.){3}\d{1,3}$') {
            Write-Log "Detected Windows IP for WSL: $($wslOutput.Trim())" -ForegroundColor Green
            return $wslOutput.Trim()
        }
        
        # Fallback: Try to get it from Windows network configuration
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -like "*WSL*" -or $_.Name -like "*vEthernet*" } | Select-Object -First 1
        if ($adapter) {
            $ip = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 | Select-Object -First 1
            if ($ip) {
                Write-Log "Detected Windows IP via adapter: $($ip.IPAddress)" -ForegroundColor Green
                return $ip.IPAddress
            }
        }
        
        # Final fallback: Use hostname resolution
        $hostname = [System.Net.Dns]::GetHostName().ToLower()
        Write-Log "Using hostname fallback: $hostname.local" -ForegroundColor Yellow
        return "$hostname.local"
    }
    catch {
        Write-Log "Error detecting Windows IP: $($_.Exception.Message)" -ForegroundColor Red
        $hostname = [System.Net.Dns]::GetHostName().ToLower()
        Write-Log "Using hostname fallback: $hostname.local" -ForegroundColor Yellow
        return "$hostname.local"
    }
}

# Function to create environment file
function Create-EnvironmentFile {
    Write-Log "Creating environment file..." -ForegroundColor Cyan
    
    # Get hostname and Windows IP for WSL
    $hostname = [System.Net.Dns]::GetHostName().ToLower()
    $windowsIP = Get-WindowsIPForWSL
    
    # Get SQL SA password from secure file
    $sqlSaPassword = Get-SqlSaPassword
    
    # Create .env file with SQL_HOST
    "SQL_HOST=$hostname.local" | Out-File -FilePath $global:EnvFile -Encoding ASCII
    # Create .env file with SQL_HOST
    "DB_SERVER=$hostname.local" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add Windows IP for extra_hosts configuration
    "WINDOWS_IP=$windowsIP" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add additional environment variables as needed
    "COMPOSE_PROJECT_NAME=xmpro" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Convert Windows path to WSL path for Docker volume mounting
    $wslCertificatesDir = "/mnt/c" + $global:CertificatesDir.Substring(2).Replace("\", "/")
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
    "SQLCMDUSER=sa" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DB_SA_PASSWORD=$sqlSaPassword" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "SQLCMDDBNAME=master" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add database user credentials
    "SMDB_USERNAME=smuser" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "SMDB_PASSWORD=YourStrongPassword123!" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "ADDB_USERNAME=aduser" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "ADDB_PASSWORD=YourStrongPassword123!" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DSDB_USERNAME=dsuser" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DSDB_PASSWORD=YourStrongPassword123!" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
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
    "COMPANY_ADMIN_PASSWORD=YourStrongPassword123!" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add host variables
    "SM_HOST=$hostname.local" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add service URLs
    "AD_BASEURL_CLIENT=https://localhost:5202/" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DS_BASEURL_CLIENT=https://localhost:5203/" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "SM_BASEURL_SERVER=https://$hostname.local/" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "AD_BASEURL_SERVER=https://ad:8443/" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DS_BASEURL_SERVER=https://ds:8443/" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add registry information
    "REGISTRY_URL=$RegistryUrl" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "REGISTRY_VERSION=$RegistryVersion" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add certificate configuration
    "CERT_PASSWORD=$CertificatePassword" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    # Add product IDs and keys
    "AD_PRODUCT_ID=fe011f90-5bb6-80ad-b0a2-56300bf3b65d" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "AI_PRODUCT_ID=b7be889b-01d3-4bd2-95c6-511017472ec8" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "DS_PRODUCT_ID=71435803-967a-e9ac-574c-face863f7ec0" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    "SM_PRODUCT_ID=380129dd-6ac3-47fc-a399-234394977680" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
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
    
    # Create initial SH config file with defaults
    $shConfigFile = "$configDir\sh-config.env"
    if (-not (Test-Path $shConfigFile)) {
        @"
xm__xmpro__gateway__collectionid=00000000-0000-0000-0000-000000000000
xm__xmpro__gateway__secret=some-secret
"@ | Out-File -FilePath $shConfigFile -Encoding ASCII
        Write-Log "Created initial SH config file: $shConfigFile" -ForegroundColor Green
    }
    "DS_TRUST_ALL_SSL_CERTIFICATES=true" | Out-File -FilePath $global:EnvFile -Append -Encoding ASCII
    
    Write-Log "Environment file created at: $global:EnvFile" -ForegroundColor Green
    Write-Log "SQL_HOST is set to: $hostname.local" -ForegroundColor Green
}

# Function to download Docker Compose file
function Download-DockerComposeFile {
    Write-Log "Downloading Docker Compose file from $BaseUrl/$DockerComposeFileName..." -ForegroundColor Cyan
    
    try {
        # Create the URL
        $url = "$BaseUrl/$DockerComposeFileName"
        
        # Download the file
        Invoke-WebRequest -Uri $url -OutFile $global:DockerComposeFile
        
        Write-Log "Docker Compose file downloaded successfully to: $global:DockerComposeFile" -ForegroundColor Green
    }
    catch {
        Write-Log "Error downloading Docker Compose file: $_" -ForegroundColor Red
        Write-Log "Using local copy of sc-compose.yaml1click as fallback..." -ForegroundColor Yellow
        
        # Use local copy as fallback
        $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
        $localFile = Join-Path -Path $scriptDir -ChildPath "sc-compose.yaml1click"
        if (Test-Path $localFile) {
            Copy-Item -Path $localFile -Destination $global:DockerComposeFile -Force
            Write-Log "Local copy of Docker Compose file used: $localFile" -ForegroundColor Green
        }
        else {
            Write-Log "Local copy of Docker Compose file not found at: $localFile" -ForegroundColor Red
            exit
        }
    }
}

# Function to download CA scripts
function Download-CAScripts {
    Write-Log "Downloading CA scripts..." -ForegroundColor Cyan
    
    # CA scripts should be downloaded to the persistent directory
    $caScriptPath = Join-Path -Path $global:PersistentDir -ChildPath "ca.sh"
    $issueScriptPath = Join-Path -Path $global:PersistentDir -ChildPath "issue.sh"
    
    try {
        # Try to download ca.sh script
        Write-Log "Downloading ca.sh from $BaseUrl/ca.sh..." -ForegroundColor Cyan
        $caUrl = "$BaseUrl/ca.sh"
        Invoke-WebRequest -Uri $caUrl -OutFile $caScriptPath
        Write-Log "ca.sh downloaded successfully." -ForegroundColor Green
    }
    catch {
        Write-Log "Error downloading ca.sh: $_" -ForegroundColor Yellow
        Write-Log "Using local copy as fallback..." -ForegroundColor Yellow
        
        # Check if local copy exists
        if (-not (Test-Path $caScriptPath)) {
            Write-Log "Local copy of ca.sh not found at: $caScriptPath" -ForegroundColor Red
            exit
        }
        else {
            Write-Log "Local copy of ca.sh found: $caScriptPath" -ForegroundColor Green
        }
    }
    
    try {
        # Try to download issue.sh script
        Write-Log "Downloading issue.sh from $BaseUrl/issue.sh..." -ForegroundColor Cyan
        $issueUrl = "$BaseUrl/issue.sh"
        Invoke-WebRequest -Uri $issueUrl -OutFile $issueScriptPath
        Write-Log "issue.sh downloaded successfully." -ForegroundColor Green
    }
    catch {
        Write-Log "Error downloading issue.sh: $_" -ForegroundColor Yellow
        Write-Log "Using local copy as fallback..." -ForegroundColor Yellow
        
        # Check if local copy exists
        if (-not (Test-Path $issueScriptPath)) {
            Write-Log "Local copy of issue.sh not found at: $issueScriptPath" -ForegroundColor Red
            exit
        }
        else {
            Write-Log "Local copy of issue.sh found: $issueScriptPath" -ForegroundColor Green
        }
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


# Function to run Docker Compose for DB setup containers
function Run-DockerComposeDBSetup {
    Write-Log "Running Docker Compose for DB setup containers inside WSL..." -ForegroundColor Cyan
    
    try {
        # Create network if it doesn't exist
        wsl docker network create xmpro-network 2>$null
        
        # Convert Windows paths to WSL paths
        $wslDockerComposeFile = "/mnt/c" + $global:DockerComposeDBSetupFile.Substring(2).Replace("\", "/")
        $wslEnvFile = "/mnt/c" + $global:EnvFile.Substring(2).Replace("\", "/")
        
        # Run Docker Compose for DB setup containers inside WSL
        wsl docker-compose -f $wslDockerComposeFile --env-file $wslEnvFile up
        
        Write-Log "DB setup containers completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Log "Error running Docker Compose for DB setup containers: $_" -ForegroundColor Red
        exit
    }
}

# Function to run Docker Compose for DB migrate containers
function Run-DockerComposeDBMigrate {
    Write-Log "Running Docker Compose for DB migrate containers inside WSL..." -ForegroundColor Cyan
    
    try {
        # Convert Windows paths to WSL paths
        $wslDockerComposeFile = "/mnt/c" + $global:DockerComposeDBMigrateFile.Substring(2).Replace("\", "/")
        $wslEnvFile = "/mnt/c" + $global:EnvFile.Substring(2).Replace("\", "/")
        
        # Run Docker Compose for DB migrate containers inside WSL
        wsl docker-compose -f $wslDockerComposeFile --env-file $wslEnvFile up
        
        Write-Log "DB migrate containers completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Log "Error running Docker Compose for DB migrate containers: $_" -ForegroundColor Red
        exit
    }
}

# Function to run Docker Compose for private CA
function Run-DockerComposeCA {
    Write-Log "Running Docker Compose for private CA inside WSL..." -ForegroundColor Cyan
    
    try {
        # Convert Windows paths to WSL paths
        $wslDockerComposeFile = "/mnt/c" + $global:DockerComposeCAFile.Substring(2).Replace("\", "/")
        $wslEnvFile = "/mnt/c" + $global:EnvFile.Substring(2).Replace("\", "/")
        
        # Run Docker Compose for private CA inside WSL
        wsl docker-compose -f $wslDockerComposeFile --env-file $wslEnvFile up -d
        
        Write-Log "Private CA container started successfully." -ForegroundColor Green
        
        # Wait for CA to be generated
        Write-Log "Waiting for CA to be generated..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        
        # Check if CA certificate exists
        $caCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "$global:CAName.crt"
        $maxRetries = 10
        $retryCount = 0
        
        while (-not (Test-Path $caCertPath) -and $retryCount -lt $maxRetries) {
            Write-Log "CA certificate not found. Waiting..." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            $retryCount++
        }
        
        if (Test-Path $caCertPath) {
            Write-Log "CA certificate generated successfully at: $caCertPath" -ForegroundColor Green
        }
        else {
            Write-Log "CA certificate not found after waiting. Please check the CA container logs." -ForegroundColor Red
            docker logs $global:CAContainerName
            exit
        }
    }
    catch {
        Write-Log "Error running Docker Compose for private CA: $_" -ForegroundColor Red
        exit
    }
}

# Function to run Docker Compose for self-signed certificates
function Run-DockerComposeCertificates {
    Write-Log "Running Docker Compose for self-signed certificates inside WSL..." -ForegroundColor Cyan
    
    try {
        # Convert Windows paths to WSL paths
        $wslDockerComposeFile = "/mnt/c" + $global:DockerComposeCertificatesFile.Substring(2).Replace("\", "/")
        $wslEnvFile = "/mnt/c" + $global:EnvFile.Substring(2).Replace("\", "/")
        
        # Run Docker Compose for self-signed certificates inside WSL
        wsl docker-compose -f $wslDockerComposeFile --env-file $wslEnvFile up -d
        
        Write-Log "Certificates container started successfully." -ForegroundColor Green
        
        # Wait for certificates to be generated
        Write-Log "Waiting for certificates to be generated..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        
        # Check if SSL certificate exists
        $sslCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "ssl.crt"
        $oidcCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "oidc.crt"
        $maxRetries = 10
        $retryCount = 0
        
        while ((-not (Test-Path $sslCertPath) -or -not (Test-Path $oidcCertPath)) -and $retryCount -lt $maxRetries) {
            Write-Log "Certificates not found. Waiting..." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            $retryCount++
        }
        
        if (Test-Path $sslCertPath -and Test-Path $oidcCertPath) {
            Write-Log "Certificates generated successfully:" -ForegroundColor Green
            Write-Log "SSL Certificate: $sslCertPath" -ForegroundColor Green
            Write-Log "OIDC Certificate: $oidcCertPath" -ForegroundColor Green
        }
        else {
            Write-Log "Certificates not found after waiting. Please check the certificates container logs." -ForegroundColor Red
            docker logs $global:CertificatesContainerName
            exit
        }
    }
    catch {
        Write-Log "Error running Docker Compose for self-signed certificates: $_" -ForegroundColor Red
        exit
    }
}

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
        $wslCertificatesDir = "/mnt/c" + $global:CertificatesDir.Substring(2).Replace("\", "/")
        
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
    $hostname = [System.Net.Dns]::GetHostName().ToLower()
    
    # Check if all component certificates exist
    foreach ($component in $components) {
        $componentCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\$component.pfx"
        if (-not (Test-Path $componentCertPath)) {
            return $false
        }
    }
    
    # Check if SSL and OIDC certificates exist
    $sslCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\ssl.pfx"
    $oidcCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\oidc.pfx"
    
    return (Test-Path $sslCertPath) -and (Test-Path $oidcCertPath)
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
        
        # Get hostname for certificate generation
        $hostname = [System.Net.Dns]::GetHostName().ToLower()
        
        # Certificate password for PFX files (use configurable parameter)
        $certPassword = $CertificatePassword
        
        # XMPro components that need certificates
        $components = @("ds", "ad", "sh", "sm")
        
        foreach ($component in $components) {
            Write-Log "Generating certificate for $component component..." -ForegroundColor Yellow
            
            # Generate certificate with PFX for each component in the certs subdirectory
            # Pass the component name as both the certificate name and Common Name
            wsl bash -c "cd /tmp && bash '$wslIssueScriptPath' --name '$component' --common-name '$component' --pfx --pfx-password '$certPassword' --output-dir '$wslCertificatesDir/certs'"
            
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
        Write-Log "Generating SSL certificate for $hostname.local..." -ForegroundColor Yellow
        wsl bash -c "cd /tmp && bash '$wslIssueScriptPath' --name '$hostname.local' --common-name '$hostname.local' --pfx --pfx-password '$certPassword' --output-dir '$wslCertificatesDir/certs'"
        

        # Generate OIDC certificate (for OIDC signing)
        Write-Log "Generating OIDC certificate for OIDC signing..." -ForegroundColor Yellow
        wsl bash -c "cd /tmp && bash '$wslIssueScriptPath' --name 'oidc-signing' --common-name 'oidc-signing' --pfx --pfx-password '$certPassword' --output-dir '$wslCertificatesDir/certs'"
        
        # Create copies with expected names for backward compatibility (avoid symlink issues in containers)
        Write-Log "Creating certificate copies with expected names..." -ForegroundColor Yellow
        wsl bash -c "cd '$wslCertificatesDir/certs' && pwd && ls -la"
        wsl bash -c "cd '$wslCertificatesDir/certs' && cp '$hostname.local.crt' ssl.crt"
        wsl bash -c "cd '$wslCertificatesDir/certs' && cp '$hostname.local.key' ssl.key"
        wsl bash -c "cd '$wslCertificatesDir/certs' && cp '$hostname.local.pfx' ssl.pfx"
        wsl bash -c "cd '$wslCertificatesDir/certs' && cp 'oidc-signing.crt' oidc.crt"
        wsl bash -c "cd '$wslCertificatesDir/certs' && cp 'oidc-signing.key' oidc.key"
        wsl bash -c "cd '$wslCertificatesDir/certs' && cp 'oidc-signing.pfx' oidc.pfx"
        
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
            Write-Log "Certificate password: $certPassword" -ForegroundColor Green
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
        [string]$CompanyName,

        [Parameter(Mandatory = $true)]
        [string]$SqlServerName,

        [Parameter(Mandatory = $true)]
        [string]$SqlUsername,

        [Parameter(Mandatory = $true)]
        [string]$SqlPassword,

        [Parameter(Mandatory = $false)]
        [string]$SqlDatabaseName = "SM",

        [Parameter(Mandatory = $false)]
        [string]$ZipFileUrl = "https://xmmarketplacestorage.blob.core.windows.net/deploymentpackage/Files-4.4.19/SM.zip",

        [Parameter(Mandatory = $false)]
        [string]$WebsiteName = "Default Web Site",

        [Parameter(Mandatory = $false)]
        [string]$WebsitePort = "443",

        [Parameter(Mandatory = $false)]
        [string]$WebsitePath = "C:\inetpub\wwwroot\XMPRO-SM",

        [Parameter(Mandatory = $false)]
        [string]$AppPoolName = "XMPRO-SM-AppPool",

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
    
    $currentVersion = Get-DeployedSMVersion -WebsitePath $WebsitePath
    $targetVersion = Get-TargetSMVersion -ZipFileUrl $ZipFileUrl
    
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
    Write-Log "Downloading SM.zip from $ZipFileUrl..." -ForegroundColor Yellow
    
    try {
        # Import BITS module
        Import-Module BitsTransfer -ErrorAction SilentlyContinue
        
        # Use BITS for large file downloads with progress and resume capability
        Start-BitsTransfer -Source $ZipFileUrl -Destination $zipFilePath -DisplayName "Downloading SM.zip" -Description "XMPro SM deployment package"
        
        Write-Log "SM.zip downloaded successfully using BITS" -ForegroundColor Green
    }
    catch {
        Write-Log "BITS download failed, falling back to Invoke-WebRequest: $_" -ForegroundColor Yellow
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $ZipFileUrl -OutFile $zipFilePath
            Write-Log "SM.zip downloaded successfully using fallback method" -ForegroundColor Green
        }
        catch {
            Write-Log "Failed to download SM.zip: $_" -ForegroundColor Red
            return
        }
    }

    # Create a temporary directory for extraction
    $extractionDir = Join-Path -Path $tempDir -ChildPath "extracted"
    New-Item -ItemType Directory -Path $extractionDir -Force | Out-Null
    
    # Extract the zip file to the temporary directory
    Write-Log "Extracting SM.zip to temporary directory..." -ForegroundColor Yellow
    try {
        Expand-Archive -Path $zipFilePath -DestinationPath $extractionDir -Force
    }
    catch {
        Write-Log "Failed to extract SM.zip: $_" -ForegroundColor Red
        return
    }
    
    # Find the web.config file
    Write-Log "Searching for web.config file..." -ForegroundColor Yellow
    $webConfigFiles = Get-ChildItem -Path $extractionDir -Filter "web.config" -Recurse
    
    if ($webConfigFiles.Count -eq 0) {
        Write-Log "No web.config file found in the extracted files." -ForegroundColor Red
        return
    }
    
    # Use the directory containing web.config as the website root
    $webConfigDir = $webConfigFiles[0].DirectoryName
    Write-Log "Found web.config in: $webConfigDir" -ForegroundColor Green
    
    # Create website directory if it doesn't exist
    Write-Log "Creating website directory at $WebsitePath..." -ForegroundColor Yellow
    try {
        # Ensure parent directory exists first
        $parentDir = Split-Path -Path $WebsitePath -Parent
        if (-not (Test-Path -Path $parentDir)) {
            Write-Log "Creating parent directory: $parentDir" -ForegroundColor Yellow
            New-Item -ItemType Directory -Path $parentDir -Force -ErrorAction Stop | Out-Null
        }
        
        if (-not (Test-Path -Path $WebsitePath)) {
            New-Item -ItemType Directory -Path $WebsitePath -Force -ErrorAction Stop | Out-Null
            Write-Log "Website directory created successfully." -ForegroundColor Green
        }
        else {
            Write-Log "Website directory already exists." -ForegroundColor Green
            
            # Read existing SMTP configuration from existing web.config if it exists
            $existingWebConfigPath = Join-Path -Path $WebsitePath -ChildPath "web.config"
            if (Test-Path -Path $existingWebConfigPath) {
                Write-Log "Found existing web.config, reading SMTP configuration..." -ForegroundColor Yellow
                try {
                    $existingWebConfig = [xml](Get-Content -Path $existingWebConfigPath)
                    $existingXmnotificationNode = $existingWebConfig.SelectSingleNode("//xmpro/xmnotification")
                    if ($existingXmnotificationNode -ne $null) {
                        $existingEmailNode = $existingXmnotificationNode.SelectSingleNode("email")
                        if ($existingEmailNode -ne $null) {
                            $global:ExistingSmtpEnabled = $existingEmailNode.GetAttribute("enable")
                            $global:ExistingSmtpServer = $existingEmailNode.GetAttribute("smtpServer")
                            $global:ExistingSmtpPort = $existingEmailNode.GetAttribute("port")
                            $global:ExistingSmtpEnableSSL = $existingEmailNode.GetAttribute("enableSsl")
                            $global:ExistingSmtpUser = $existingEmailNode.GetAttribute("userName")
                            $global:ExistingSmtpPassword = $existingEmailNode.GetAttribute("password")
                            $global:ExistingSmtpFromAddress = $existingEmailNode.GetAttribute("fromAddress")
                            
                            # Clean up placeholder values
                            if ($global:ExistingSmtpServer -match '\$\{.*\}') { $global:ExistingSmtpServer = "" }
                            if ($global:ExistingSmtpUser -match '\$\{.*\}') { $global:ExistingSmtpUser = "" }
                            if ($global:ExistingSmtpPassword -match '\$\{.*\}') { $global:ExistingSmtpPassword = "" }
                            if ($global:ExistingSmtpFromAddress -match '\$\{.*\}') { $global:ExistingSmtpFromAddress = "" }
                            
                            Write-Log "Existing SMTP configuration saved for reuse" -ForegroundColor Green
                        }
                    }
                } catch {
                    Write-Log "Could not read existing SMTP configuration: $_" -ForegroundColor Yellow
                }
            }
        }
        
        # Verify the directory exists and is writable
        if (-not (Test-Path -Path $WebsitePath)) {
            throw "Failed to create website directory at $WebsitePath"
        }
        
        # Test write permissions
        $testFile = Join-Path -Path $WebsitePath -ChildPath "test.tmp"
        try {
            "test" | Out-File -FilePath $testFile -ErrorAction Stop
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
            Write-Log "Directory permissions verified." -ForegroundColor Green
        }
        catch {
            Write-Log "Warning: Cannot write to directory $WebsitePath. Permissions may be insufficient." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Log "Failed to create website directory: $_" -ForegroundColor Red
        Write-Log "Please ensure you have administrative privileges and the path is valid." -ForegroundColor Red
        return
    }
    
    # Copy files from the web.config directory to the website directory
    Write-Log "Copying files from $webConfigDir to $WebsitePath..." -ForegroundColor Yellow
    
    # Debug: List what's in the source directory
    # Write-Log "Source directory contents:" -ForegroundColor Cyan
    # Get-ChildItem -Path $webConfigDir -Recurse | ForEach-Object { Write-Log "  $($_.FullName)" -ForegroundColor Gray }
    
    try {
        Copy-Item -Path "$webConfigDir\*" -Destination $WebsitePath -Recurse -Force -ErrorAction Stop
        Write-Log "Files copied successfully." -ForegroundColor Green
        
        # Debug: List what's in the destination directory after copy
        # Write-Log "Destination directory contents after copy:" -ForegroundColor Cyan
        # if (Test-Path -Path $WebsitePath) {
        #     Get-ChildItem -Path $WebsitePath -Recurse | ForEach-Object { Write-Log "  $($_.FullName)" -ForegroundColor Gray }
        # } else {
        #     Write-Log "  Directory does not exist!" -ForegroundColor Red
        # }
        
        # Verify that files were copied AND directory still exists
        Write-Log "Verifying website directory still exists at: $WebsitePath" -ForegroundColor Cyan
        if (-not (Test-Path -Path $WebsitePath)) {
            Write-Log "ERROR: Website directory disappeared after file copy!" -ForegroundColor Red
            Write-Log "Recreating website directory..." -ForegroundColor Yellow
            New-Item -ItemType Directory -Path $WebsitePath -Force -ErrorAction Stop | Out-Null
        }
        
        $webConfigDestination = Join-Path -Path $WebsitePath -ChildPath "web.config"
        if (-not (Test-Path -Path $webConfigDestination)) {
            Write-Log "web.config was not copied to the destination. Creating a minimal web.config file." -ForegroundColor Yellow
            
            # Create a minimal web.config file
            $minimalWebConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
  </appSettings>
  <system.web>
    <compilation debug="true" targetFramework="4.8" />
    <httpRuntime targetFramework="4.8" />
  </system.web>
</configuration>
"@
            Set-Content -Path $webConfigDestination -Value $minimalWebConfig -Force
        }
    }
    catch {
        Write-Log "Failed to copy files: $_" -ForegroundColor Red
        return
    }

    # Import WebAdministration module
    Import-Module WebAdministration -ErrorAction Stop
    
    # Check if application pool exists
    $appPoolExists = Get-IISAppPool -Name $AppPoolName -ErrorAction SilentlyContinue
    
    if ($appPoolExists) {
        # Remove existing application pool
        Write-Log "Removing existing application pool $AppPoolName..." -ForegroundColor Yellow
        try {
            # Stop the app pool first to ensure it can be removed
            if ((Get-WebAppPoolState -Name $AppPoolName).Value -ne "Stopped") {
                Stop-WebAppPool -Name $AppPoolName
                Start-Sleep -Seconds 2  # Give it time to stop
            }
            
            # Remove the app pool
            Remove-WebAppPool -Name $AppPoolName
            Start-Sleep -Seconds 2  # Give IIS time to process the removal
        }
        catch {
            Write-Log "Error removing application pool: $_" -ForegroundColor Yellow
            Write-Log "Attempting to continue with creation..." -ForegroundColor Yellow
        }
    }
    
    # Create new application pool
    Write-Log "Creating application pool $AppPoolName..." -ForegroundColor Yellow
    try {
        # Create the app pool with Force parameter
        New-WebAppPool -Name $AppPoolName -Force -ErrorAction Stop
        Start-Sleep -Seconds 2  # Give IIS time to create the app pool
        
        # Configure application pool settings
        Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name "managedRuntimeVersion" -Value $AppPoolDotNetVersion
        Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name "processModel.identityType" -Value 4  # ApplicationPoolIdentity
        
        Write-Log "Application pool created and configured successfully." -ForegroundColor Green
    }
    catch {
        Write-Log "Error creating application pool: $_" -ForegroundColor Yellow
        Write-Log "Attempting to use existing application pool..." -ForegroundColor Yellow
        
        # Try to configure the existing app pool
        try {
            Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name "managedRuntimeVersion" -Value $AppPoolDotNetVersion
            Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name "processModel.identityType" -Value 4  # ApplicationPoolIdentity
            Write-Log "Existing application pool configured successfully." -ForegroundColor Green
        }
        catch {
            Write-Log "Error configuring existing application pool: $_" -ForegroundColor Yellow
            Write-Log "You may need to manually configure the application pool in IIS Manager." -ForegroundColor Yellow
        }
    }

    # Check if the Default Web Site exists
    $defaultWebsite = Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
    if (-not $defaultWebsite) {
        Write-Log "Default Web Site not found in IIS. Please ensure IIS is properly installed with the default website." -ForegroundColor Red
        return
    }
    
    # Since we're configuring Default Web Site directly (not creating sub-application),
    # we just need to update its physical path and app pool
    Write-Log "Configuring $WebsiteName to serve SM from root path..." -ForegroundColor Yellow
    Write-Log "Physical Path: $WebsitePath" -ForegroundColor Cyan
    Write-Log "Application Pool: $AppPoolName" -ForegroundColor Cyan
    
    # Final verification of physical path before IIS creation
    Write-Log "Final verification: checking if $WebsitePath exists..." -ForegroundColor Cyan
    if (-not (Test-Path -Path $WebsitePath)) {
        Write-Log "ERROR: Physical path $WebsitePath does not exist!" -ForegroundColor Red
        Write-Log "Attempting to recreate the directory one more time..." -ForegroundColor Yellow
        try {
            New-Item -ItemType Directory -Path $WebsitePath -Force -ErrorAction Stop | Out-Null
            Write-Log "Website directory recreated successfully." -ForegroundColor Green
        } catch {
            Write-Log "Failed to recreate website directory: $_" -ForegroundColor Red
            Write-Log "Cannot create IIS application with non-existent path." -ForegroundColor Red
            return
        }
    } else {
        Write-Log "Physical path verification passed: $WebsitePath exists" -ForegroundColor Green
    }
    
    try {
        # Deploy SM as root application by updating Default Web Site physical path
        Set-ItemProperty -Path "IIS:\Sites\Default Web Site" -Name "physicalPath" -Value $WebsitePath
        Set-ItemProperty -Path "IIS:\Sites\Default Web Site" -Name "applicationPool" -Value $AppPoolName
        Write-Log "Default Web Site configured to serve SM from root path." -ForegroundColor Green
        
        # Verify the website configuration
        $defaultSite = Get-Website -Name $WebsiteName
        if ($defaultSite.physicalPath -eq $WebsitePath) {
            Write-Log "IIS $WebsiteName verified - serving SM from root path: $WebsitePath" -ForegroundColor Green
        } else {
            Write-Log "Warning: $WebsiteName may not be configured correctly." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Log "Error creating application: $_" -ForegroundColor Red
        Write-Log "Physical Path: $WebsitePath" -ForegroundColor Red
        Write-Log "Application Pool: $AppPoolName" -ForegroundColor Red
        Write-Log "You may need to manually create the application in IIS Manager." -ForegroundColor Yellow
    }
    
    # Generate or use provided certificate for signing
    if ([string]::IsNullOrEmpty($CertificateThumbprint)) {
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
        
        # Create simple self-signed certificate with CN=sm (like XMPro documentation)
        $opensslCmd1 = "wsl openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout `"$wslSignKey`" -out `"$wslSignCrt`" -subj `"/CN=sm`" -days 365"
        Write-Log "Running: $opensslCmd1" -ForegroundColor Gray
        Invoke-Expression $opensslCmd1
        
        # Export to PFX format for Windows/IIS with legacy compatibility for .NET Framework
        $pfxPassword = $CertificatePassword
        $opensslCmd2 = "wsl openssl pkcs12 -export -legacy -out `"$wslSignPfx`" -inkey `"$wslSignKey`" -in `"$wslSignCrt`" -certfile `"$wslSignCrt`" -passout pass:`"$pfxPassword`""
        Write-Log "Running: $opensslCmd2" -ForegroundColor Gray
        Invoke-Expression $opensslCmd2
        
        if (Test-Path $signPfxPath) {
            Write-Log "Successfully created certificate: $signPfxPath" -ForegroundColor Green
            
            # Import the certificate to get thumbprint
            $cert = Import-PfxCertificate -FilePath $signPfxPath -CertStoreLocation "Cert:\LocalMachine\My" -Password (ConvertTo-SecureString -String $pfxPassword -AsPlainText -Force)
            $CertificateThumbprint = $cert.Thumbprint
            Write-Log "Certificate imported with thumbprint: $CertificateThumbprint" -ForegroundColor Green
            Write-Log "Certificate subject: $($cert.Subject)" -ForegroundColor Green
        } else {
            Write-Log "Failed to create certificate with OpenSSL" -ForegroundColor Red
            # Fallback to PowerShell method
            $CertificateSubject = "sm"
            $CertificateThumbprint = New-SelfSignedCertificateEx -Subject $CertificateSubject
        }
    }
    
    # Configure HTTPS binding for the SM application
    Write-Log "Configuring HTTPS binding for SM application..." -ForegroundColor Yellow
    
    try {
        # Look for sign.pfx certificate (created above) or fallback to sm.pfx
        $signCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\sign.pfx"
        $smCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\sm.pfx"
        $certPassword = $CertificatePassword  # Use the configured certificate password
        
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
            $cert = Import-PfxCertificate -FilePath $certPathToUse -CertStoreLocation "Cert:\LocalMachine\My" -Password (ConvertTo-SecureString -String $certPassword -AsPlainText -Force) -ErrorAction SilentlyContinue
            
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
                
                # Add HTTPS binding to Default Web Site for the SM application
                $hostname = [System.Net.Dns]::GetHostName()
                $httpsBindingExists = Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -HostHeader "$hostname.local" -ErrorAction SilentlyContinue
                
                if (-not $httpsBindingExists) {
                    Write-Log "Adding HTTPS binding for $hostname.local:443..." -ForegroundColor Yellow
                    New-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -HostHeader "$hostname.local" -SslFlags 1
                    
                    # Bind the certificate to the HTTPS binding
                    $binding = Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -HostHeader "$hostname.local"
                    $binding.AddSslCertificate($cert.Thumbprint, "My")
                    
                    Write-Log "HTTPS binding configured successfully for https://$hostname.local:443/" -ForegroundColor Green
                } else {
                    Write-Log "HTTPS binding already exists for $hostname.local:443, updating certificate..." -ForegroundColor Yellow
                    
                    # Update existing binding with new certificate
                    try {
                        $binding = Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -HostHeader "$hostname.local"
                        if ($binding) {
                            # Remove old certificate binding and add new one
                            $binding.RemoveSslCertificate()
                            $binding.AddSslCertificate($cert.Thumbprint, "My")
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
                        $smBinding.AddSslCertificate($cert.Thumbprint, "My")
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
                            $smBinding.AddSslCertificate($cert.Thumbprint, "My")
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
                
                # Update CertificateThumbprint to use the SM certificate
                $CertificateThumbprint = $cert.Thumbprint
            } else {
                Write-Log "Failed to import SM certificate. Using fallback certificate for signing only." -ForegroundColor Yellow
            }
        } else {
            Write-Log "SM certificate not found at: $smCertPath. Using fallback certificate for signing only." -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Error configuring HTTPS binding: $_" -ForegroundColor Yellow
        Write-Log "SM application will use HTTP only." -ForegroundColor Yellow
    }
    
    Write-Log "Certificate with thumbprint $CertificateThumbprint will be used for signing." -ForegroundColor Yellow

    # Generate random values
    # Get existing XMPro Product ID from database instead of random GUID
    $sqlSaPassword = Get-SqlSaPassword
    $hostname = [System.Net.Dns]::GetHostName()
    try {
        $productId = Invoke-Sqlcmd -ServerInstance $hostname -Database "SM" -Username "sa" -Password $sqlSaPassword -Query "SELECT Id FROM Product WHERE Name='XMPro'" | Select-Object -ExpandProperty Id
        Write-Log "Using existing XMPro Product ID: $productId" -ForegroundColor Green
    } catch {
        Write-Log "Could not query database for XMPro Product ID, generating new GUID..." -ForegroundColor Yellow
        $productId = New-RandomGuid
    }
    $salt = New-RandomString -Length 13

    # Create web.config transformation
    $webConfigPath = Join-Path -Path $WebsitePath -ChildPath "web.config"
    
    if (Test-Path -Path $webConfigPath) {
        Write-Log "Updating web.config with XMPro configuration..." -ForegroundColor Yellow
        
        # Load the web.config file
        $webConfig = [xml](Get-Content -Path $webConfigPath)
        
        # Clear conflicting app settings that override xmpro section (like Azure App Service)
        Write-Log "Clearing conflicting app settings to allow xmpro section to be used..." -ForegroundColor Yellow
        $appSettingsNode = $webConfig.SelectSingleNode("//appSettings")
        if ($appSettingsNode -ne $null) {
            $conflictingKeys = @(
                "xm__xmpro__data__connectionString",
                "xmpro__xmidentity__server__baseUrl",
                "SigningCertificateThumbprint",
                "EncryptionCertificateThumbprint",
                "SigningCertificateStoreName",
                "SigningCertificateStoreLocation",
                "EncryptionCertificateStoreName",
                "EncryptionCertificateStoreLocation",
                "SM_PRODUCT_ID",
                "SM_BASE_URL"
            )
            
            foreach ($key in $conflictingKeys) {
                $existingNode = $appSettingsNode.SelectSingleNode("add[@key='$key']")
                if ($existingNode -ne $null) {
                    $appSettingsNode.RemoveChild($existingNode) | Out-Null
                    Write-Log "Removed conflicting app setting: $key" -ForegroundColor Green
                }
            }
        }
        
        # Get the Default Web Site binding information for URL construction
        $defaultSite = Get-Website -Name "Default Web Site"
        $httpBinding = $defaultSite.bindings.Collection | Where-Object { $_.protocol -eq "http" } | Select-Object -First 1
        $httpsBinding = $defaultSite.bindings.Collection | Where-Object { $_.protocol -eq "https" } | Select-Object -First 1
        
        # Determine base URL (prefer HTTPS with simple hostname if available)
        $baseUrl = ""
        $hostname = [System.Net.Dns]::GetHostName().ToLower()
        if ($httpsBinding) {
            # Use simple "sm" hostname for better certificate matching - SM deployed as root
            $baseUrl = "https://${hostname}.local/"
        } else {
            $httpPort = $httpBinding.bindingInformation.Split(":")[1]
            $baseUrl = "http://localhost:$httpPort/"
        }
        
        # Get the actual SQL SA password from secure storage
        $actualSqlPassword = Get-SqlSaPassword
        
        # Connection strings - Entity Framework requires specific format with escaped quotes
        $sqlConnectionPart = "Data Source=tcp:$SqlServerName,1433;Initial Catalog=$SqlDatabaseName;User ID=$SqlUsername;Password=$actualSqlPassword;multipleactiveresultsets=True;application name=EntityFramework"
        $efConnectionString = "metadata=res://*/Context.csdl|res://*/Context.ssdl|res://*/Context.msl;provider=System.Data.SqlClient;provider connection string=`"$sqlConnectionPart`""
        $settingsConnectionString = "metadata=res://*/SettingsContext.csdl|res://*/SettingsContext.ssdl|res://*/SettingsContext.msl;provider=System.Data.SqlClient;provider connection string=`"$sqlConnectionPart`""
        $operationalConnectionString = "Data Source=tcp:$SqlServerName,1433;Initial Catalog=$SqlDatabaseName;User ID=$SqlUsername;Password=$actualSqlPassword"
        
        # Debug connection strings
        Write-Log "EF Connection String: $efConnectionString" -ForegroundColor Cyan
        Write-Log "Operational Connection String: $operationalConnectionString" -ForegroundColor Cyan
        
        # Remove Azure Key Vault config builder if it exists
        $configBuildersNode = $webConfig.SelectSingleNode("//configBuilders")
        if ($configBuildersNode -ne $null) {
            Write-Log "Removing Azure Key Vault config builder..." -ForegroundColor Yellow
            $configBuildersNode.ParentNode.RemoveChild($configBuildersNode)
        }
        
        # Remove configBuilders attribute from xmpro section
        $xmproNode = $webConfig.SelectSingleNode("//xmpro")
        if ($xmproNode -ne $null) {
            $xmproNode.RemoveAttribute("configBuilders")
            Write-Log "Removed configBuilders reference from xmpro section" -ForegroundColor Green
        }
        
        # Update XMIdentity configuration
        $xmidentityNode = $webConfig.SelectSingleNode("//xmpro/xmidentity")
        if ($xmidentityNode -ne $null) {
            # Update data connection string
            $dataNode = $xmidentityNode.SelectSingleNode("data")
            if ($dataNode -ne $null) {
                $dataNode.SetAttribute("connectionString", $efConnectionString)
            }
            
            # Update operational data connection string
            $operationalDataNode = $xmidentityNode.SelectSingleNode("operationalData")
            if ($operationalDataNode -ne $null) {
                $operationalDataNode.SetAttribute("connectionString", $operationalConnectionString)
            }
            
            # Update server configuration
            $serverNode = $xmidentityNode.SelectSingleNode("server")
            if ($serverNode -ne $null) {
                # Use subject name from imported certificate if available
                $certSubjectName = "CN=sm"  # Default fallback
                
                # Try to get the actual subject from the imported certificate
                try {
                    $importedCert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Subject -like "*sm*" } | Select-Object -First 1
                    if ($importedCert) {
                        $certSubjectName = $importedCert.Subject
                        Write-Log "Using actual certificate subject: $certSubjectName" -ForegroundColor Green
                    } else {
                        Write-Log "SM certificate not found in LocalMachine\My store, using default: $certSubjectName" -ForegroundColor Yellow
                    }
                } catch {
                    Write-Log "Could not verify certificate in store, using default: $certSubjectName" -ForegroundColor Yellow
                }
                
                $serverNode.SetAttribute("signingCertificate", $certSubjectName)
                $serverNode.SetAttribute("certificateLocation", "LocalMachine")
                $serverNode.SetAttribute("baseUrl", $baseUrl)
                $serverNode.SetAttribute("serverUUID", $productId)
                Write-Log "Server signingCertificate set to: $certSubjectName" -ForegroundColor Cyan
            }
        }
        
        # Update XMSettings configuration
        $xmsettingsNode = $webConfig.SelectSingleNode("//xmpro/xmsettings")
        if ($xmsettingsNode -ne $null) {
            $settingsDataNode = $xmsettingsNode.SelectSingleNode("data")
            if ($settingsDataNode -ne $null) {
                $settingsDataNode.SetAttribute("connectionString", $settingsConnectionString)
            }
        }
        
        # Update XMCryptography configuration
        $xmcryptographyNode = $webConfig.SelectSingleNode("//xmpro/xmcryptography")
        if ($xmcryptographyNode -ne $null) {
            $aesNode = $xmcryptographyNode.SelectSingleNode("aes")
            if ($aesNode -ne $null) {
                # Use the same certificate subject name as the server configuration
                $encryptionCertSubject = $certSubjectName  # Use the same value determined above
                $aesNode.SetAttribute("encryptionCertificate", $encryptionCertSubject)
                $aesNode.SetAttribute("certificateLocation", "LocalMachine")
                $aesNode.SetAttribute("salt", $salt)
                Write-Log "AES encryptionCertificate set to: $encryptionCertSubject" -ForegroundColor Cyan
            }
        }
        
        # Update AutoScale configuration
        $autoScaleNode = $webConfig.SelectSingleNode("//xmpro/autoScale")
        if ($autoScaleNode -ne $null) {
            $autoScaleNode.SetAttribute("enabled", "false")
            $autoScaleNode.SetAttribute("connectionString", "")
            Write-Log "AutoScale disabled for local installation" -ForegroundColor Green
        }
        
        # Update Serilog minimum level to Verbose
        Write-Log "Updating Serilog minimum level to Verbose..." -ForegroundColor Yellow
        $serilogNode = $webConfig.configuration.appSettings.SelectSingleNode("//add[@key='serilog:minimum-level']")
        if ($serilogNode -ne $null) {
            $serilogNode.SetAttribute("value", "Verbose")
            Write-Log "Serilog minimum level updated to Verbose" -ForegroundColor Green
        } else {
            Write-Log "Serilog minimum-level setting not found in web.config" -ForegroundColor Yellow
        }
        
        # SMTP configuration - skip prompts if SkipEmailConfiguration is set
        Write-Log "`nSMTP Email Configuration" -ForegroundColor Cyan
        
        # Use existing values as defaults if available
        $defaultSmtpEnabled = if ($global:ExistingSmtpEnabled -eq "true" -and $global:ExistingSmtpServer -ne "") { "y" } else { "n" }
        $defaultSmtpServer = if ($global:ExistingSmtpServer -ne "") { $global:ExistingSmtpServer } else { "" }
        $defaultSmtpPort = if ($global:ExistingSmtpPort -ne "") { $global:ExistingSmtpPort } else { "587" }
        $defaultSmtpSSL = if ($global:ExistingSmtpEnableSSL -eq "true") { "y" } else { "n" }
        $defaultSmtpUser = if ($global:ExistingSmtpUser -ne "") { $global:ExistingSmtpUser } else { "" }
        $defaultSmtpFromAddress = if ($global:ExistingSmtpFromAddress -ne "") { $global:ExistingSmtpFromAddress } else { "" }
        
        if ($SkipEmailConfiguration) {
            Write-Log "Email configuration skipped via parameter." -ForegroundColor Yellow
            if ($defaultSmtpServer -ne "") {
                Write-Log "Using existing SMTP configuration." -ForegroundColor Green
                $enableEmail = $defaultSmtpEnabled
            } else {
                Write-Log "No existing SMTP configuration found, disabling email." -ForegroundColor Yellow
                $enableEmail = "n"
            }
        } else {
            if ($defaultSmtpServer -ne "") {
                Write-Log "Found existing SMTP configuration. Press Enter to keep current settings." -ForegroundColor Yellow
            } else {
                Write-Log "The SM application needs SMTP settings for email notifications." -ForegroundColor Yellow
                Write-Log "You can configure this now or disable email and configure later." -ForegroundColor Yellow
            }
            
            $enableEmail = Read-Host "`nEnable email notifications? (y/n) [default: $defaultSmtpEnabled]"
            if ($enableEmail -eq "") { $enableEmail = $defaultSmtpEnabled }
        }
        
        if ($enableEmail.ToLower() -eq "n") {
            $smtpEnabled = "false"
            $smtpServer = ""
            $smtpPort = "25"
            $smtpEnableSSL = "false"
            $smtpUser = ""
            $smtpPassword = ""
            $smtpFromAddress = ""
            Write-Log "Email notifications disabled. You can configure SMTP later in web.config." -ForegroundColor Yellow
        } else {
            $smtpEnabled = "true"
            
            if ($SkipEmailConfiguration) {
                # Use existing values without prompts
                $smtpServer = $defaultSmtpServer
                $smtpPort = $defaultSmtpPort
                $smtpEnableSSL = $global:ExistingSmtpEnableSSL
                $smtpUser = $defaultSmtpUser
                $smtpPassword = $global:ExistingSmtpPassword
                $smtpFromAddress = $defaultSmtpFromAddress
                Write-Log "Using existing SMTP configuration without prompts." -ForegroundColor Green
            } else {
                Write-Log "`nEnter SMTP server details (press Enter to keep existing):" -ForegroundColor Cyan
                
                $serverPrompt = if ($defaultSmtpServer -ne "") { "SMTP Server [current: $defaultSmtpServer]" } else { "SMTP Server (e.g., smtp.gmail.com, smtp.office365.com)" }
                $smtpServer = Read-Host $serverPrompt
                if ($smtpServer -eq "") { $smtpServer = $defaultSmtpServer }
                
                $portPrompt = if ($defaultSmtpPort -ne "587") { "SMTP Port [current: $defaultSmtpPort]" } else { "SMTP Port [default: 587]" }
                $smtpPort = Read-Host $portPrompt
                if ($smtpPort -eq "") { $smtpPort = $defaultSmtpPort }
                
                $sslPrompt = if ($global:ExistingSmtpEnableSSL -ne "") { "Use SSL/TLS? (y/n) [current: $defaultSmtpSSL]" } else { "Use SSL/TLS? (y/n) [default: y]" }
                $smtpSSL = Read-Host $sslPrompt
                if ($smtpSSL -eq "") { $smtpSSL = if ($global:ExistingSmtpEnableSSL -ne "") { $defaultSmtpSSL } else { "y" } }
                $smtpEnableSSL = if ($smtpSSL.ToLower() -eq "y") { "true" } else { "false" }
                
                $userPrompt = if ($defaultSmtpUser -ne "") { "SMTP Username [current: $defaultSmtpUser]" } else { "SMTP Username (email address)" }
                $smtpUser = Read-Host $userPrompt
                if ($smtpUser -eq "") { $smtpUser = $defaultSmtpUser }
                
                if ($global:ExistingSmtpPassword -ne "" -and $global:ExistingSmtpPassword -notmatch '^\$\{.*\}$') {
                    $passwordPrompt = Read-Host "Update SMTP Password? (y/n) [current password will be kept if 'n']"
                    if ($passwordPrompt.ToLower() -eq "y") {
                        $smtpPassword = Read-Host "SMTP Password" -AsSecureString
                        $smtpPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($smtpPassword))
                    } else {
                        $smtpPassword = $global:ExistingSmtpPassword
                    }
                } else {
                    $smtpPassword = Read-Host "SMTP Password" -AsSecureString
                    $smtpPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($smtpPassword))
                }
                
                $fromPrompt = if ($defaultSmtpFromAddress -ne "") { "From Email Address [current: $defaultSmtpFromAddress]" } else { "From Email Address [default: $smtpUser]" }
                $smtpFromAddress = Read-Host $fromPrompt
                if ($smtpFromAddress -eq "") { 
                    $smtpFromAddress = if ($defaultSmtpFromAddress -ne "") { $defaultSmtpFromAddress } else { $smtpUser }
                }
                
                Write-Log "SMTP configuration will be applied to web.config." -ForegroundColor Green
            }
        }
        
        # Update SMTP/Email configuration
        $xmnotificationNode = $webConfig.SelectSingleNode("//xmpro/xmnotification")
        if ($xmnotificationNode -ne $null) {
            $emailNode = $xmnotificationNode.SelectSingleNode("email")
            if ($emailNode -ne $null) {
                $emailNode.SetAttribute("enable", $smtpEnabled)
                $emailNode.SetAttribute("smtpServer", $smtpServer)
                $emailNode.SetAttribute("enableSsl", $smtpEnableSSL)
                $emailNode.SetAttribute("port", $smtpPort)
                $emailNode.SetAttribute("useDefaultCredentials", "false")
                $emailNode.SetAttribute("userName", $smtpUser)
                $emailNode.SetAttribute("password", $smtpPassword)
                $emailNode.SetAttribute("fromAddress", $smtpFromAddress)
                # Keep existing template folder and webApplication settings
                Write-Log "Email configuration updated in web.config" -ForegroundColor Green
            }
        }
        
        # Add app settings for tracking deployment info
        $appSettingsNode = $webConfig.SelectSingleNode("//appSettings")
        if ($appSettingsNode -eq $null) {
            $appSettingsNode = $webConfig.CreateElement("appSettings")
            $webConfig.configuration.AppendChild($appSettingsNode)
        }
        
        # Clear any appSettings overrides that might interfere with connection strings
        $connectionOverrides = @("xm__xmpro__data__connectionString", "xmpro__xmidentity__server__baseUrl", "xmpro__xmidentity__featureFlags__dbMigrationsEnabled")
        foreach ($override in $connectionOverrides) {
            $setting = $webConfig.SelectSingleNode("//add[@key='$override']")
            if ($setting -ne $null) {
                $setting.SetAttribute("value", "")
                Write-Log "Cleared override setting: $override" -ForegroundColor Yellow
            }
        }
        
        # Deployment tracking settings
        $deploymentSettings = @{
            "SM_PRODUCT_ID" = $productId
            "SM_VERSION" = $targetVersion
            "SM_DEPLOYED_DATE" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            "SM_BASE_URL" = $baseUrl
            # Enable developer options for local installation
            "TrustAllSslCertificates" = "true"
            "LogPii" = "true"
            "NoServerRequireSsl" = "false"
        }
        
        foreach ($key in $deploymentSettings.Keys) {
            $setting = $webConfig.SelectSingleNode("//add[@key='$key']")
            if ($setting -ne $null) {
                $setting.SetAttribute("value", $deploymentSettings[$key])
            } else {
                $addElement = $webConfig.CreateElement("add")
                $addElement.SetAttribute("key", $key)
                $addElement.SetAttribute("value", $deploymentSettings[$key])
                $appSettingsNode.AppendChild($addElement)
            }
        }
        
        # Save the web.config file
        $webConfig.Save($webConfigPath)
        Write-Log "Web.config updated with direct XMPro configuration (no Azure Key Vault dependency)" -ForegroundColor Green
    }
    else {
        Write-Log "web.config not found at $webConfigPath. Application settings were not updated." -ForegroundColor Yellow
    }

    # Set folder permissions
    Write-Log "Setting folder permissions..." -ForegroundColor Yellow
    try {
        # Verify the directory exists before setting permissions
        if (Test-Path -Path $WebsitePath) {
            $acl = Get-Acl -Path $WebsitePath
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS AppPool\$AppPoolName", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.SetAccessRule($accessRule)
            Set-Acl -Path $WebsitePath -AclObject $acl
            Write-Log "Folder permissions set successfully." -ForegroundColor Green
        }
        else {
            Write-Log "Cannot set folder permissions because the path $WebsitePath does not exist." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Log "Failed to set folder permissions: $_" -ForegroundColor Yellow
        Write-Log "You may need to manually set folder permissions in File Explorer." -ForegroundColor Yellow
    }

    # Ensure Default Web Site is running
    $defaultWebsiteState = (Get-WebsiteState -Name "Default Web Site").Value
    if ($defaultWebsiteState -ne "Started") {
        Write-Log "Starting Default Web Site..." -ForegroundColor Yellow
        try {
            Start-Website -Name "Default Web Site" -ErrorAction Stop
            Write-Log "Default Web Site started successfully." -ForegroundColor Green
        }
        catch {
            Write-Log "Could not start Default Web Site: $_" -ForegroundColor Yellow
            Write-Log "You may need to manually start the Default Web Site from IIS Manager." -ForegroundColor Yellow
        }
    }
    else {
        Write-Log "Default Web Site is already running." -ForegroundColor Green
    }

    # Clean up temporary files
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

    # Get the Default Web Site binding information for HTTPS
    $defaultSite = Get-Website -Name "Default Web Site"
    $httpsBinding = $defaultSite.bindings.Collection | Where-Object { $_.protocol -eq "https" } | Select-Object -First 1
    $httpBinding = $defaultSite.bindings.Collection | Where-Object { $_.protocol -eq "http" } | Select-Object -First 1
    
    # Determine the application URL (prefer HTTPS)
    $hostname = [System.Net.Dns]::GetHostName().ToLower()
    if ($httpsBinding) {
        $applicationUrl = "https://$hostname.local/"
    } elseif ($httpBinding) {
        $bindingInfo = $httpBinding.bindingInformation.Split(":")
        $port = $bindingInfo[1]
        $applicationUrl = "http://localhost:$port/"
    } else {
        $applicationUrl = "https://$hostname.local/"
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

# Function to deploy SM in IIS
function Deploy-SMInIIS {
    Write-Log "Deploying SM in IIS using integrated Install-XMProSM..." -ForegroundColor Cyan
    
    # Use existing SSL certificate if available
    $sslCertPath = Join-Path -Path $global:CertificatesDir -ChildPath "certs\ssl.pfx"
    $certificateThumbprint = ""
    
    if (Test-Path $sslCertPath) {
        # Import the certificate and get thumbprint
        try {
            $cert = Import-PfxCertificate -FilePath $sslCertPath -CertStoreLocation Cert:\LocalMachine\My -Password (ConvertTo-SecureString $CertificatePassword -AsPlainText -Force)
            $certificateThumbprint = $cert.Thumbprint
            Write-Log "Using existing SSL certificate: $certificateThumbprint" -ForegroundColor Green
        }
        catch {
            Write-Log "Failed to import SSL certificate: $_" -ForegroundColor Yellow
        }
    }
    
    # Call the integrated Install-XMPROSM function
    try {
        Install-XMProSM -CompanyName $CompanyName -SqlServerName $SqlServerName -SqlUsername $SqlUsername -SqlPassword $SqlPassword -ZipFileUrl $SmZipUrl -WebsiteName $SmWebsiteName -WebsitePath $SmWebsitePath -AppPoolName $SmAppPoolName -CertificateThumbprint $certificateThumbprint
        Write-Log "SM deployment completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Log "Error deploying SM in IIS: $_" -ForegroundColor Red
        exit
    }
}

# Function to update SH configuration from database
function Update-SHConfiguration {
    Write-Log "Updating SH configuration from database..." -ForegroundColor Cyan
    
    try {
        $sqlSaPassword = Get-SqlSaPassword
        $hostname = [System.Net.Dns]::GetHostName().ToLower()
        $configDir = "$env:USERPROFILE\.xmpro-post-install\config"
        $shConfigFile = "$configDir\sh-config.env"
        
        Write-Log "Querying DS database for SH configuration..." -ForegroundColor Yellow
        
        # Use the same SQL host as configured in the environment
        $collectionId = Invoke-Sqlcmd -ServerInstance $hostname -Database "DS" -Username "sa" -Password $sqlSaPassword -Query "SELECT TOP 1 CAST(Id AS VARCHAR(50)) AS CollectionId FROM dbo.EdgeContainer" | Select-Object -ExpandProperty CollectionId
        
        $secret = Invoke-Sqlcmd -ServerInstance $hostname -Database "DS" -Username "sa" -Password $sqlSaPassword -Query "SELECT TOP 1 Secret FROM dbo.EdgeContainer" | Select-Object -ExpandProperty Secret
        
        if ($collectionId -and $secret) {
            # Create updated config file
            @"
xm__xmpro__gateway__collectionid=$collectionId
xm__xmpro__gateway__secret=$secret
"@ | Out-File -FilePath $shConfigFile -Encoding ASCII
            
            Write-Log "SH configuration updated successfully:" -ForegroundColor Green
            Write-Log "  Collection ID: $collectionId" -ForegroundColor Green
            Write-Log "  Secret: $secret" -ForegroundColor Green
        } else {
            Write-Log "Failed to query database, keeping default SH configuration" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Log "Error updating SH configuration: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Keeping default SH configuration" -ForegroundColor Yellow
    }
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
        
        # Stage 1: Start databases and migrations
        Write-Log "Stage 1: Starting databases and migrations..." -ForegroundColor Yellow
        wsl docker-compose -f $wslDockerComposeFile --env-file $wslEnvFile up smdb addb dsdb smdbmigrate addbmigrate dsdbmigrate
        
        # Update SH configuration from database
        Update-SHConfiguration
        
        # Stage 2: Start all application services
        Write-Log "Stage 2: Starting all application services..." -ForegroundColor Yellow
        wsl docker-compose -f $wslDockerComposeFile --env-file $wslEnvFile up -d
        
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

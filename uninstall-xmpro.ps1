#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Uninstalls XMPro platform and cleans up all related components.

.DESCRIPTION
    This script removes all XMPro installation components including:
    - Docker containers and images
    - IIS applications and certificates
    - Private CA certificates
    - Configuration files and directories
    - Database (optional)

.PARAMETER RemoveDatabase
    Remove the SQL Server databases (SM, AD, DS)

.PARAMETER Force
    Force removal without confirmation prompts

.EXAMPLE
    .\uninstall-xmpro.ps1
    
.EXAMPLE
    .\uninstall-xmpro.ps1 -RemoveDatabase -Force
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$RemoveDatabase,
    
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Global variables
$global:LogPath = "$env:USERPROFILE\.xmpro-install\uninstall-log-$(Get-Date -Format 'yyyy-MM-dd-HH-mm-ss').txt"
$global:CertificatesDir = "$env:USERPROFILE\.xmpro-install"
$global:PrivateCADir = "$env:USERPROFILE\js-private-ca"

# Ensure log directory exists
$logDir = Split-Path -Parent $global:LogPath
if (!(Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Function to write log messages
function Write-Log {
    param(
        [string]$Message,
        [string]$ForegroundColor = "White"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    
    Write-Host $logMessage -ForegroundColor $ForegroundColor
    Add-Content -Path $global:LogPath -Value $logMessage
}

# Function to confirm action
function Confirm-Action {
    param(
        [string]$Message
    )
    
    if ($Force) {
        return $true
    }
    
    $response = Read-Host "$Message (y/N)"
    return ($response -eq 'y' -or $response -eq 'Y')
}

# Function to stop and remove Docker containers
function Remove-DockerContainers {
    Write-Log "=== Removing Docker containers and images ===" -ForegroundColor Cyan
    
    try {
        # Stop containers from docker-compose files FIRST (proper way)
        Write-Log "Stopping Docker Compose services..." -ForegroundColor Yellow
        
        # Check post-install docker-compose directory first (using same approach as post-install)
        $postInstallBaseDir = "$env:USERPROFILE\.xmpro-post-install"
        $postInstallComposeDir = "$postInstallBaseDir\docker-compose"
        $postInstallCompose = Join-Path -Path $postInstallComposeDir -ChildPath "docker-compose.yml"
        $postInstallEnv = "$postInstallBaseDir\.env"
        
        if ((Test-Path $postInstallCompose) -and (Test-Path $postInstallEnv)) {
            Write-Log "Found post-install docker-compose and .env files" -ForegroundColor Green
            
            # Convert to WSL paths (same as post-install approach)
            $wslDockerComposeFile = $postInstallCompose -replace "C:", "/mnt/c" -replace "\\", "/"
            $wslEnvFile = $postInstallEnv -replace "C:", "/mnt/c" -replace "\\", "/"
            
            Write-Log "Running: wsl docker-compose -f $wslDockerComposeFile --env-file $wslEnvFile down --remove-orphans" -ForegroundColor Gray
            wsl docker-compose -f $wslDockerComposeFile --env-file $wslEnvFile down --remove-orphans
        } else {
            Write-Log "Post-install docker-compose or .env file not found" -ForegroundColor Yellow
        }
        
        # Also check current directory and other common locations
        $composeFiles = @(
            "docker-compose.yml",
            "sc-compose.yaml1click", 
            "test-compose.yml"
        )
        
        foreach ($composeFile in $composeFiles) {
            if (Test-Path $composeFile) {
                Write-Log "Stopping containers from $composeFile..." -ForegroundColor Yellow
                docker-compose -f $composeFile down --remove-orphans
            }
        }
        
        # Fallback: manually stop any remaining XMPro containers
        $remainingContainers = docker ps -a --filter "name=xmpro" --format "{{.Names}}"
        if ($remainingContainers) {
            Write-Log "Manually stopping remaining XMPro containers..." -ForegroundColor Yellow
            $remainingContainers | ForEach-Object {
                Write-Log "Stopping container: $_" -ForegroundColor Gray
                docker stop $_
                docker rm $_
            }
        } else {
            Write-Log "All XMPro containers stopped successfully" -ForegroundColor Green
        }
        
        # Remove XMPro related images
        if (Confirm-Action "Remove XMPro Docker images?") {
            $images = docker images --filter "reference=*xmpro*" --format "{{.Repository}}:{{.Tag}}" 2>$null
            if ($images) {
                Write-Log "Removing XMPro Docker images..." -ForegroundColor Yellow
                $images | ForEach-Object {
                    Write-Log "Removing image: $_" -ForegroundColor Gray
                    docker rmi $_ --force 2>$null
                }
            }
        }
        
        # Clean up Docker system
        if (Confirm-Action "Clean up Docker system (remove unused containers, networks, images)?") {
            Write-Log "Cleaning Docker system..." -ForegroundColor Yellow
            docker system prune -f 2>$null
        }
        
        Write-Log "Docker cleanup completed" -ForegroundColor Green
    }
    catch {
        Write-Log "Error during Docker cleanup: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to remove IIS applications and certificates
function Remove-IISApplications {
    Write-Log "=== Removing IIS applications and certificates ===" -ForegroundColor Cyan
    
    try {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        
        # First check what XMPro items exist in IIS
        Write-Log "Checking for XMPro sites and applications in IIS..." -ForegroundColor Yellow
        
        # Check for XMPro sites (not just applications)
        $xmproSites = Get-Website | Where-Object { $_.Name -like "*XMPRO*" }
        if ($xmproSites) {
            Write-Log "Found XMPro sites:" -ForegroundColor Yellow
            $xmproSites | ForEach-Object { Write-Log "  Site: $($_.Name)" -ForegroundColor Gray }
        }
        
        # Check for XMPro applications under Default Web Site
        $xmproApps = Get-WebApplication -Site "Default Web Site" | Where-Object { $_.Path -like "*XMPRO*" }
        if ($xmproApps) {
            Write-Log "Found XMPro applications under Default Web Site:" -ForegroundColor Yellow
            $xmproApps | ForEach-Object { Write-Log "  App: $($_.Path)" -ForegroundColor Gray }
        }
        
        # Remove XMPro sites first
        if ($xmproSites) {
            foreach ($site in $xmproSites) {
                Write-Log "Removing site: $($site.Name)" -ForegroundColor Yellow
                try {
                    Remove-Website -Name $site.Name
                    Write-Log "Removed site: $($site.Name)" -ForegroundColor Green
                } catch {
                    Write-Log "Error removing site $($site.Name): $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
        
        # Handle SM deployed as root application
        Write-Log "Checking for SM deployed as root application..." -ForegroundColor Yellow
        $defaultSite = Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
        if ($defaultSite) {
            $currentPhysicalPath = $defaultSite.physicalPath
            Write-Log "Default Web Site physical path: $currentPhysicalPath" -ForegroundColor Gray
            
            # Check if SM is deployed as root (physical path contains XMPRO-SM)
            if ($currentPhysicalPath -like "*XMPRO-SM*") {
                Write-Log "Found SM deployed as root application" -ForegroundColor Yellow
                
                # Reset Default Web Site to default IIS configuration
                try {
                    Set-ItemProperty -Path "IIS:\Sites\Default Web Site" -Name "physicalPath" -Value "C:\inetpub\wwwroot"
                    Set-ItemProperty -Path "IIS:\Sites\Default Web Site" -Name "applicationPool" -Value "DefaultAppPool"
                    Write-Log "Reset Default Web Site to default configuration" -ForegroundColor Green
                } catch {
                    Write-Log "Error resetting Default Web Site: $($_.Exception.Message)" -ForegroundColor Red
                }
                
                # Remove SM application pool
                $smAppPool = Get-IISAppPool -Name "XMPRO-SM-AppPool" -ErrorAction SilentlyContinue
                if ($smAppPool) {
                    try {
                        Remove-WebAppPool -Name "XMPRO-SM-AppPool"
                        Write-Log "Removed SM application pool: XMPRO-SM-AppPool" -ForegroundColor Green
                    } catch {
                        Write-Log "Error removing SM application pool: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
                
                # Remove SM physical directory
                if (Test-Path $currentPhysicalPath) {
                    try {
                        Remove-Item -Path $currentPhysicalPath -Recurse -Force
                        Write-Log "Removed SM directory: $currentPhysicalPath" -ForegroundColor Green
                    } catch {
                        Write-Log "Error removing SM directory: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
        }
        
        # Remove any remaining XMPro web applications (AD, DS if deployed as sub-applications)
        $webApps = @("XMPRO-AD", "XMPRO-DS")
        
        foreach ($webApp in $webApps) {
            # Check if web application exists
            $app = Get-WebApplication -Site "Default Web Site" -Name $webApp -ErrorAction SilentlyContinue
            if ($app) {
                Write-Log "Found web application: $webApp at $($app.PhysicalPath)" -ForegroundColor Yellow
                try {
                    Remove-WebApplication -Site "Default Web Site" -Name $webApp
                    Write-Log "Removed web application: $webApp" -ForegroundColor Green
                } catch {
                    Write-Log "Error removing web application ${webApp}: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            # Remove application pool
            $appPoolName = "$webApp-AppPool"
            $appPool = Get-IISAppPool -Name $appPoolName -ErrorAction SilentlyContinue
            if ($appPool) {
                try {
                    Remove-WebAppPool -Name $appPoolName
                    Write-Log "Removed application pool: $appPoolName" -ForegroundColor Green
                } catch {
                    Write-Log "Error removing application pool ${appPoolName}: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            # Remove physical directory
            $physicalPath = "C:\inetpub\wwwroot\$webApp"
            if (Test-Path $physicalPath) {
                try {
                    Remove-Item -Path $physicalPath -Recurse -Force
                    Write-Log "Removed directory: $physicalPath" -ForegroundColor Green
                } catch {
                    Write-Log "Error removing directory ${physicalPath}: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
        
        # Remove HTTPS certificate bindings from Default Web Site
        Write-Log "Removing HTTPS certificate bindings..." -ForegroundColor Yellow
        try {
            $httpsBindings = Get-WebBinding -Name "Default Web Site" -Protocol "https" -ErrorAction SilentlyContinue
            if ($httpsBindings) {
                foreach ($binding in $httpsBindings) {
                    Write-Log "Removing HTTPS binding: $($binding.bindingInformation)" -ForegroundColor Yellow
                    Remove-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -ErrorAction SilentlyContinue
                }
                Write-Log "HTTPS certificate bindings removed" -ForegroundColor Green
            } else {
                Write-Log "No HTTPS bindings found to remove" -ForegroundColor Gray
            }
        } catch {
            Write-Log "Error removing HTTPS bindings: $($_.Exception.Message)" -ForegroundColor Red
        }
        
        Write-Log "IIS applications removed" -ForegroundColor Green
    }
    catch {
        Write-Log "Error removing IIS applications: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to remove certificates
function Remove-Certificates {
    Write-Log "=== Removing certificates ===" -ForegroundColor Cyan
    
    try {
        # Remove XMPro certificates from LocalMachine store
        $stores = @("My", "Root", "CA")
        
        foreach ($storeName in $stores) {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
            $store.Open("ReadWrite")
            
            $certsToRemove = $store.Certificates | Where-Object { 
                $_.Subject -like "*sm*" -or 
                $_.Subject -like "*XMPro*" -or 
                $_.Subject -like "*XMIdentity*" -or
                $_.Issuer -like "*JS*CA*" -or
                $_.FriendlyName -like "*XMPro*"
            }
            
            foreach ($cert in $certsToRemove) {
                Write-Log "Removing certificate: $($cert.Subject) from LocalMachine\$storeName" -ForegroundColor Yellow
                $store.Remove($cert)
            }
            
            $store.Close()
        }
        
        # Remove from CurrentUser store as well
        foreach ($storeName in $stores) {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "CurrentUser")
            $store.Open("ReadWrite")
            
            $certsToRemove = $store.Certificates | Where-Object { 
                $_.Subject -like "*sm*" -or 
                $_.Subject -like "*XMPro*" -or 
                $_.Subject -like "*XMIdentity*" -or
                $_.Issuer -like "*JS*CA*" -or
                $_.FriendlyName -like "*XMPro*"
            }
            
            foreach ($cert in $certsToRemove) {
                Write-Log "Removing certificate: $($cert.Subject) from CurrentUser\$storeName" -ForegroundColor Yellow
                $store.Remove($cert)
            }
            
            $store.Close()
        }
        
        Write-Log "Certificates removed" -ForegroundColor Green
    }
    catch {
        Write-Log "Error removing certificates: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to remove Private CA (in WSL and Windows)
function Remove-PrivateCA {
    Write-Log "=== Removing Private CA ===" -ForegroundColor Cyan
    
    try {
        # Remove WSL Private CA directory (/root/js-private-ca)
        Write-Log "Removing WSL Private CA directory: /root/js-private-ca" -ForegroundColor Yellow
        wsl rm -rf /root/js-private-ca 2>$null
        Write-Log "WSL Private CA directory removed" -ForegroundColor Green
        
        # Also remove Windows Private CA directory if it exists (fallback)
        if (Test-Path $global:PrivateCADir) {
            if (Confirm-Action "Remove Windows Private CA directory ($global:PrivateCADir)?") {
                Write-Log "Removing Windows Private CA directory..." -ForegroundColor Yellow
                Remove-Item -Path $global:PrivateCADir -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Windows Private CA directory removed" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Log "Error removing Private CA: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to remove post-install directories and files
function Remove-PostInstallFiles {
    Write-Log "=== Removing post-install directories and files ===" -ForegroundColor Cyan
    
    try {
        # Remove specific items UNDER .xmpro-post-install directory
        $postInstallBaseDir = "$env:USERPROFILE\.xmpro-post-install"
        
        if (Test-Path $postInstallBaseDir) {
            Write-Log "Removing specific items from post-install directory..." -ForegroundColor Yellow
            
            # Remove specific subdirectories
            $subDirs = @("certificates", "docker-compose", "config")
            foreach ($subDir in $subDirs) {
                $dirPath = Join-Path -Path $postInstallBaseDir -ChildPath $subDir
                if (Test-Path $dirPath) {
                    Write-Log "  Removing: $subDir folder" -ForegroundColor Gray
                    Remove-Item -Path $dirPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            
            # Remove .env file
            $envFile = Join-Path -Path $postInstallBaseDir -ChildPath ".env"
            if (Test-Path $envFile) {
                Write-Log "  Removing: .env file" -ForegroundColor Gray
                Remove-Item -Path $envFile -Force -ErrorAction SilentlyContinue
            }
            
            Write-Log "Post-install items removed (directory preserved)" -ForegroundColor Green
        } else {
            Write-Log "Post-install directory not found" -ForegroundColor Gray
        }
        
        # Also remove any environment files in current directory
        $localEnvFiles = @(".env", "docker-compose.override.yml")
        foreach ($envFile in $localEnvFiles) {
            if (Test-Path $envFile) {
                Write-Log "Removing local $envFile..." -ForegroundColor Yellow
                Remove-Item -Path $envFile -Force -ErrorAction SilentlyContinue
            }
        }
        
        Write-Log "Post-install cleanup completed" -ForegroundColor Green
    }
    catch {
        Write-Log "Error removing post-install files: $($_.Exception.Message)" -ForegroundColor Red
    }
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

# Function to remove databases
function Remove-Databases {
    Write-Log "=== Removing databases ===" -ForegroundColor Cyan
    
    if (!$RemoveDatabase) {
        Write-Log "Database removal skipped (use -RemoveDatabase to enable)" -ForegroundColor Gray
        return
    }
    
    try {
        $databases = @("SM", "AD", "DS")
        $hostname = [System.Net.Dns]::GetHostName()
        
        # Get SQL SA password using the same logic as post-install
        $sqlPassword = Get-SqlSaPassword
        
        foreach ($database in $databases) {
            try {
                Write-Log "Removing database: $database" -ForegroundColor Yellow
                $dropQuery = "DROP DATABASE IF EXISTS [$database]"
                Invoke-Sqlcmd -ServerInstance "$hostname\SQLEXPRESS" -Database "master" -Username "sa" -Password $sqlPassword -Query $dropQuery -ErrorAction SilentlyContinue
                Write-Log "Database ${database} removed" -ForegroundColor Green
            }
            catch {
                Write-Log "Could not remove database ${database}: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Log "Error removing databases: $($_.Exception.Message)" -ForegroundColor Red
    }
}


# Function to clean up Windows hosts file
function Remove-HostsEntries {
    Write-Log "=== Removing hosts file entries ===" -ForegroundColor Cyan
    
    try {
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        if (Test-Path $hostsPath) {
            $hostsContent = Get-Content $hostsPath
            $newContent = $hostsContent | Where-Object { 
                $_ -notlike "*sm*" -and 
                $_ -notlike "*ad*" -and 
                $_ -notlike "*ds*" -and
                $_ -notlike "*xmpro*"
            }
            
            if ($hostsContent.Count -ne $newContent.Count) {
                Write-Log "Removing XMPro entries from hosts file..." -ForegroundColor Yellow
                Set-Content -Path $hostsPath -Value $newContent
                Write-Log "Hosts file updated" -ForegroundColor Green
            } else {
                Write-Log "No XMPro entries found in hosts file" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Log "Error updating hosts file: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Main execution
Write-Log "=== XMPro Uninstaller Started ===" -ForegroundColor Magenta
Write-Log "Log file: $global:LogPath" -ForegroundColor Magenta

if (!$Force) {
    Write-Host ""
    Write-Host "This will remove:" -ForegroundColor Yellow
    Write-Host "  - Docker containers and images" -ForegroundColor White
    Write-Host "  - IIS applications and certificates" -ForegroundColor White
    Write-Host "  - Private CA certificates and trust store" -ForegroundColor White
    Write-Host "  - Post-install generated certificates and files" -ForegroundColor White
    if ($RemoveDatabase) {
        Write-Host "  - SQL Server databases" -ForegroundColor Red
    }
    Write-Host ""
    
    if (!$(Confirm-Action "Continue with uninstallation?")) {
        Write-Log "Uninstallation cancelled by user" -ForegroundColor Yellow
        exit
    }
}

# Execute removal steps
Remove-DockerContainers
Remove-IISApplications
Remove-Certificates
Remove-PrivateCA
Remove-PostInstallFiles
Remove-HostsEntries
Remove-Databases

Write-Log "=== XMPro Uninstallation Completed ===" -ForegroundColor Magenta
Write-Log "Log file saved to: $global:LogPath" -ForegroundColor Magenta
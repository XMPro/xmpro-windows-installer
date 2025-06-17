# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is the `/install` directory of the XMPro platform - an enterprise IoT platform that provides comprehensive machine preparation and application deployment automation for Windows Server environments.

## Key Scripts and Purpose

### Machine Preparation Scripts
- `install-xmpro.ps1` - Main installation script that prepares Windows Server 2022 machines through a 13-step automated process including Windows Updates, IIS, .NET Framework 4.8.1, WSL2, Docker, SQL Server Express, and all required dependencies
- `install-xmpro-application.ps1` - Application deployment script that handles Docker Compose deployment, certificate management, and IIS configuration for the XMPro applications

### Docker Configuration
- `docker-compose.yml` - Main Docker Compose file for running the XMPro platform stack including:
  - **SM (Subscription Manager)** - Identity and subscription management
  - **AD (App Designer)** - Application design interface
  - **DS (DataStream Designer)** - Data stream processing design
  - **SH (Stream Host)** - Runtime execution environment
  - **Database migration containers** for each component
  - **License management** service

### Alternative Deployment
- `sc-compose.yaml1click` - Single-click deployment configuration

## Architecture

The XMPro platform consists of:
- **Subscription Manager (SM)** - Central identity and licensing service
- **App Designer (AD)** - Web-based application builder
- **DataStream Designer (DS)** - Real-time data processing designer  
- **Stream Host (SH)** - Distributed runtime for executing data streams
- **SQL Server databases** - Separate databases for each component (SM, AD, DS)

## Common Tasks

### Running the Installation
```powershell
# Basic installation
.\install-xmpro.ps1

# With custom parameters
.\install-xmpro.ps1 -SqlSaPassword "YourPassword123" -DockerVersion "24.0.7"

# One-liner download and install
powershell.exe -ExecutionPolicy Bypass -Command "iex (irm http://your-server/install-xmpro.ps1)"
```

### Application Deployment
```powershell
# Deploy XMPro applications
.\install-xmpro-application.ps1

# With custom registry
.\install-xmpro-application.ps1 -RegistryUrl "your-registry.azurecr.io" -RegistryVersion "4.5.0"
```

### Docker Operations
```bash
# Start the platform
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Environment Variables

Key environment variables for Docker Compose:
- `SQL_HOST` - SQL Server hostname (default: localhost)
- `DB_SA_PASSWORD` - SQL Server SA password (see CLAUDE.local.md)
- `REGISTRY_URL` - Docker registry URL (default: xmprononprod.azurecr.io)
- `REGISTRY_VERSION` - Image version tag (default: 4.5.0-alpha)
- `AD_PORT` - App Designer port (default: 5202)
- `DS_PORT` - DataStream Designer port (default: 5203)
- `SH_COLLECTIONID` - Stream Host Collection ID (queried from DS database)
- `SH_SECRET` - Stream Host Secret (queried from DS database)

## Stream Host (SH) Configuration

The Stream Host service requires proper configuration to connect to the DataStream Designer. The installation process handles this automatically:

### **Dynamic Configuration Update (Fixed June 2025)**
Between Docker Compose Stage 1 (databases) and Stage 2 (applications), the script:

1. **Queries DS Database**: Retrieves real values from `dbo.EdgeContainer` table
   ```sql
   SELECT TOP 1 CAST(Id AS VARCHAR(50)) AS CollectionId FROM dbo.EdgeContainer
   SELECT TOP 1 Secret FROM dbo.EdgeContainer
   ```

2. **Updates .env File**: Adds real configuration to main environment file
   ```bash
   SH_COLLECTIONID=<real-collection-id>
   SH_SECRET=<real-secret>
   ```

3. **Docker Compose Stage 2**: SH container starts with actual database values instead of defaults

### **Previous Issue (Fixed)**
Originally, the script created a separate `sh-config.env` file that wasn't used by Docker Compose, causing SH to use default placeholder values (`00000000-0000-0000-0000-000000000000` and `some-secret`). This gap has been resolved to ensure proper SH connectivity.

## Installation Flow

The installation follows this sequence:
1. Windows Updates and IIS installation
2. .NET Framework 4.8.1 installation
3. WSL2 and container services setup
4. SQL Server Express configuration
5. Docker installation (Windows and WSL2)
6. Ubuntu on WSL setup
7. Post-installation configuration

## Dependencies and Requirements

- Windows Server 2022
- Hyper-V virtualization extensions (for VM environments)
- Internet connectivity for downloads
- Administrative privileges
- Minimum 8GB RAM, 4 CPU cores recommended

## Security Configuration

- SQL Server configured with mixed authentication
- Firewall rules restrict access to localhost and WSL subnets
- Self-signed certificates generated for HTTPS/OIDC
- Service accounts configured with least privilege
- **Azure VM Security**: All VMs created via Terraform or Azure CLI must restrict RDP access to deployer's IP only (no wildcard access)

## Communication Guidelines

**CRITICAL**: Follow these guidelines when working with this project to avoid inefficient back-and-forth:

- **Read full instructions carefully** before making ANY changes
- **Address ALL points mentioned in a single comprehensive edit** - never make partial fixes
- **Ask clarifying questions upfront** if anything is unclear - don't assume
- **Never make assumptions** about requirements or implementation details
- **Avoid multiple back-and-forth edits** for the same issue
- **Consider licensing implications** when choosing Docker images or tools
- **Use appropriate tool sizes** - don't pull large images when lightweight ones suffice

## Docker Best Practices

- Use correct paths for commands in containers (e.g., `/opt/mssql-tools/bin/sqlcmd`)
- Don't change Docker images unnecessarily when the issue is just a missing command path
- Consider licensing and image size when selecting base images
- Create separate directories for different types of configuration (certificates vs config files)

## Cloud Infrastructure Management

**IMPORTANT**: Claude Code has full access to Azure CLI and Terraform and can execute infrastructure commands directly when requested. This includes:

### Azure VM Creation for Testing
Claude can create Azure VMs for testing the XMPro installation scripts:

```bash
# Example: Create Windows Server 2022 VM with nested virtualization
az vm create --resource-group "rg-xmpro-test" --name "vm-test-ws2022" \
  --image "Win2022Datacenter" --size "Standard_D4s_v3" \
  --admin-username "testuser" --admin-password "SecurePass123!"
```

### Available Azure Operations
- Create/delete resource groups and VMs
- Switch between Azure subscriptions
- Configure VM settings for Hyper-V/WSL2 support
- Manage networking and security groups
- Query VM status and connection details

### Terraform Infrastructure as Code
Claude can also manage infrastructure using Terraform:

```hcl
# Example: Terraform configuration for XMPro test environment
resource "azurerm_windows_virtual_machine" "xmpro_test" {
  name                = "vm-xmpro-test"
  resource_group_name = azurerm_resource_group.test.name
  location            = "Australia East"
  size                = "Standard_D4s_v3"
  admin_username      = "xmproadmin"
  admin_password      = "SecurePass123!"
  
  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-g2"
    version   = "latest"
  }
}
```

### Available Terraform Operations
- Write and apply Terraform configurations
- Plan infrastructure changes before applying
- Manage state files and workspaces
- Create reusable modules for XMPro environments
- Import existing Azure resources into Terraform state
- Destroy test environments when no longer needed

### Testing Environment Setup
For testing install-xmpro.ps1, Claude can provision using either Azure CLI or Terraform:
- Windows Server 2022 VMs in Australia East region
- Standard_D4s_v3 size (4 vCPUs, 16GB RAM) for nested virtualization
- RDP access configured automatically
- Proper VM sizing for Hyper-V and WSL2 requirements
- Infrastructure as Code for repeatable deployments

**Notes**: 
- Claude will check subscription access and can switch subscriptions as needed before creating resources
- Terraform configurations can be versioned and reused for consistent test environments
- Both Azure CLI (quick deployment) and Terraform (infrastructure as code) approaches are available

## Custom Commands and Workflows

### Quick Commands for Common Tasks
For frequently used commands, you can request Claude to execute them directly:

**Reupload install script:**
```
"reupload install-xmpro.ps1"
```

**Create test VM:**
```
"create test vm in australia east"
```

**Upload all files:**
```
"upload all files to azure storage"
```

### Azure DevOps Commands

**Get pull request comments:**
```bash
az devops invoke \
    --area git \
    --resource pullRequestThreads \
    --org "$organization" \
    --route-parameters project="$project" repositoryId="$repositoryId" pullRequestId="$pullRequestId" \
    --api-version 7.0
```

Example usage:
```bash
az devops invoke \
    --area git \
    --resource pullRequestThreads \
    --org "https://xmpro.visualstudio.com" \
    --route-parameters project="XMPro Development" repositoryId="1f071285-340f-4d85-a847-ef83b54b06f9" pullRequestId="2728" \
    --api-version 7.0
```

### Custom Slash Commands (Future Enhancement)
Claude Code supports custom slash commands through configuration. To add a `/reupload` command:

1. **Project-level commands** can be defined in `.claude/settings.local.json`
2. **Global commands** are configured in Claude Code settings
3. **Workflow automation** can be achieved through saved command patterns

**Example configuration structure:**
```json
{
  "commands": {
    "/reupload": {
      "description": "Reupload install-xmpro.ps1 to Azure storage",
      "action": "bash",
      "command": "az storage blob upload --account-name xmproinstallfiles --container-name '$web' --name install-xmpro.ps1 --file /home/john/projects/xmpro-development/install/install-xmpro.ps1 --overwrite --auth-mode key"
    },
    "/createvm": {
      "description": "Create test VM in Australia East",
      "action": "sequence",
      "commands": [
        "az vm create --resource-group rg-xmpro-test --name vm-test-$(date +%s) --image Win2022Datacenter --size Standard_D4s_v3"
      ]
    }
  }
}
```

**Note**: Custom slash command support varies by Claude Code version. Check current documentation at https://docs.anthropic.com/en/docs/claude-code/cli-usage for latest features.

## Script Hosting and Distribution

### Azure Static Website Hosting
The installation scripts are hosted on Azure Storage for public access:

**Base URL**: `https://jstmpfls.z8.web.core.windows.net/`

**Key hosted files**:
- `install-xmpro.ps1` - Main installation script
- `post-install-xmpro.ps1` - Post-installation deployment script  
- `ca.sh` - Certificate authority script
- `issue.sh` - Certificate issuance script
- `docker-compose.yml` - Production Docker Compose configuration

### Remote Installation
```powershell
# One-liner remote installation
iex (irm "https://jstmpfls.z8.web.core.windows.net/install-xmpro.ps1")
```

### Updating Hosted Files
```bash
# Upload all files to Azure storage
az storage blob upload-batch \
  --account-name "jstmpfls" \
  --destination '$web' \
  --source "/home/john/projects/xmpro-development/install" \
  --auth-mode key

# Upload single file (e.g., after script updates)
az storage blob upload \
  --account-name "jstmpfls" \
  --container-name '$web' \
  --name "install-xmpro.ps1" \
  --file "/home/john/projects/xmpro-development/install/install-xmpro.ps1" \
  --overwrite \
  --auth-mode key
```

## Script Idempotency and Testing

### Idempotency Improvements Made
The install-xmpro.ps1 script has been enhanced for true idempotency:

1. **PSWindowsUpdate Module** - Checks for existing installation and import status
2. **IIS Features** - Batch checks enabled features, only installs missing ones
3. **SQL Server** - Verifies service exists before attempting installation
4. **Docker** - Checks for both service and command availability
5. **WSL Ubuntu** - Tests functionality, not just presence
6. **SQL TCP/IP Configuration** - Only applies changes when current state differs from desired state
7. **WSL Systemd** - Independent check for systemd configuration

### Common Idempotency Issues Fixed
- **Ubuntu Detection** - Fixed null character parsing in WSL output using regex cleaning
- **Restart Logic** - Only restarts when components were actually installed/changed
- **SQL Configuration** - Prevents unnecessary service restarts when already configured
- **Variable Scoping** - Fixed PowerShell string interpolation issues with colons

### Testing Environment
- **VM Requirements**: Standard_D4s_v3 (4 vCPUs, 16GB RAM) with nested virtualization
- **Test Subscription**: Visual Studio Enterprise Subscription (5d1dfe30-829c-4e9d-af56-7582bf2a7442)
- **Test Resource Group**: rg-xmpro-test
- **Region**: Australia East

### Current Test VM Details

#### Azure VM (vm-xmpro-ws2022)
- **Public IP**: 4.196.123.119
- **Username**: xmproadmin
- **Password**: [See CLAUDE.local.md]
- **Status**: Running

#### Hyper-V VM (Local)
- **VM Name**: Windows2022-Temp
- **Username**: administrator
- **Password**: [See CLAUDE.local.md]
- **Access Method**: Hyper-V via PowerShell remote execution
- **Status**: Running - Active for XMPro troubleshooting

### PowerShell Execution Guidelines
**IMPORTANT**: When running PowerShell scripts, create a temporary script in `/tmp/` and then execute it to avoid conflicts between PowerShell and Bash:

```bash
# Create temp script
cat > /tmp/get-vms.ps1 << 'EOF'
Get-VM | Select-Object Name, State
EOF

# Execute temp script with execution policy bypass
powershell.exe -ExecutionPolicy Bypass -File /tmp/get-vms.ps1
```

This prevents parsing conflicts that occur when PowerShell and Bash commands are mixed directly. **Always use `-ExecutionPolicy Bypass`** to avoid script signing restrictions.

### PowerShell Syntax Best Practices

**CRITICAL SYNTAX RULES** - Apply these automatically to avoid common errors:

#### Variable References in Strings
```powershell
# WRONG - PowerShell interprets as drive reference
"Database $database: error message"

# CORRECT - Use curly braces to delimit variable
"Database ${database}: error message"
```

#### Never Mix Bash and PowerShell Operators
```powershell
# WRONG - bash redirection in PowerShell
$result | Select-Object Name < /dev/null

# CORRECT - pure PowerShell
$result | Select-Object Name
```

#### WSL Path Conversion Pattern
```powershell
# Convert Windows paths to WSL paths for OpenSSL/Linux commands
$wslPath = $windowsPath -replace "C:", "/mnt/c" -replace "\\", "/"
```

#### Complex Command String Escaping
```powershell
# Use backticks for nested quotes in command strings
$cmd = "wsl openssl req -config `"$wslConfigPath`" -subj `"/CN=sm`""
```

#### Always Use ExecutionPolicy Bypass for Automation
```bash
# ALWAYS include -ExecutionPolicy Bypass for automated execution
powershell.exe -ExecutionPolicy Bypass -File script.ps1
```

**These are fundamental patterns that must be applied automatically, not learned through errors.**

**Azure CLI commands used to create this VM:**
```bash
# Switch to Visual Studio subscription
az account set --subscription "5d1dfe30-829c-4e9d-af56-7582bf2a7442"

# Create resource group
az group create --name "rg-xmpro-test" --location "Australia East"

# Create Windows Server 2022 VM
az vm create \
  --resource-group "rg-xmpro-test" \
  --name "vm-xmpro-ws2022" \
  --image "Win2022Datacenter" \
  --size "Standard_D4s_v3" \
  --admin-username "xmproadmin" \
  --admin-password "XMProTest2024!"

# Enable nested virtualization (deallocate/start cycle)
az vm deallocate --resource-group "rg-xmpro-test" --name "vm-xmpro-ws2022"
az vm start --resource-group "rg-xmpro-test" --name "vm-xmpro-ws2022"

# Get connection details
az vm show --resource-group "rg-xmpro-test" --name "vm-xmpro-ws2022" --show-details --query "{Name:name, PublicIP:publicIps, PowerState:powerState}" --output table
```

## Troubleshooting

### Installation Logs
Check the installation logs in `%USERPROFILE%\.xmpro-install\` for detailed error information. The scripts are idempotent and safe to re-run.

### Common Issues
1. **WSL Ubuntu Detection Failures** - Usually caused by null characters in wsl --list output
2. **SQL Server TCP/IP Configuration** - May require manual restart if SMO assemblies fail to load
3. **Docker Installation in WSL** - Requires systemd to be enabled first
4. **Restart Requirements** - Script automatically handles restarts between phases when needed

## Recent Fixes and Learnings (May 2025)

### Critical Issues Resolved in post-install-xmpro.ps1

#### 1. "Unknown client" Authentication Error
**Problem**: SM generated random GUID for `serverUUID` but didn't create corresponding database record, causing IdentityServer3 to reject authentication with "Unknown client or not enabled: [GUID]"

**Root Cause**: Line 1406 used `$productId = New-RandomGuid` but didn't insert into Product table

**Fix Applied**: Modified script to query existing XMPro Product ID from database:
```powershell
# Lines 1406-1415: Use existing XMPro Product ID instead of random GUID
$sqlSaPassword = Get-SqlSaPassword
$hostname = [System.Net.Dns]::GetHostName()
try {
    $productId = Invoke-Sqlcmd -ServerInstance $hostname -Database "SM" -Username "sa" -Password $sqlSaPassword -Query "SELECT Id FROM Product WHERE Name='XMPro'" | Select-Object -ExpandProperty Id
    Write-Log "Using existing XMPro Product ID: $productId" -ForegroundColor Green
} catch {
    Write-Log "Could not query database for XMPro Product ID, generating new GUID..." -ForegroundColor Yellow
    $productId = New-RandomGuid
}
```

#### 2. Certificate Private Key Access Error
**Problem**: IIS AppPool couldn't access certificate private key, causing "Signing certificate has no private key or the private key is not accessible" error

**Fix Applied**: Added certificate permission fix after certificate import (Lines 1316-1343):
```powershell
# Grant IIS AppPool access to certificate private key
Write-Log "Granting IIS AppPool access to certificate private key..." -ForegroundColor Yellow
try {
    # Method 1: Use icacls to grant permission to machine keys directory
    $machineKeysPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
    $icaclsResult = icacls $machineKeysPath /grant "IIS AppPool\${AppPoolName}:(R)" /T 2>$null
    
    # Method 2: Grant permission to specific certificate private key if we can find it
    if ($cert.HasPrivateKey) {
        try {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            if ($rsa.Key.UniqueName) {
                $keyPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$($rsa.Key.UniqueName)"
                if (Test-Path $keyPath) {
                    icacls $keyPath /grant "IIS AppPool\${AppPoolName}:(R)" 2>$null
                    Write-Log "Granted private key access to IIS AppPool\${AppPoolName}" -ForegroundColor Green
                }
            }
        } catch {
            # Fallback: Grant broader permissions
            icacls $machineKeysPath /grant "IIS_IUSRS:(R)" /T 2>$null
            Write-Log "Applied fallback certificate permissions" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Log "Warning: Could not set certificate private key permissions: $($_.Exception.Message)" -ForegroundColor Yellow
}
```

#### 3. Interactive SMTP Prompts Issue
**Problem**: Script would hang on SMTP configuration prompts during automated deployment

**Fix Applied**: Added `SkipEmailConfiguration` parameter (Lines 84, 1557-1598):
```powershell
[Parameter(Mandatory=$false)]
[switch]$SkipEmailConfiguration
```

**Usage**: `.\install-xmpro-application.ps1 -SkipEmailConfiguration`

### SM Authentication and Authorization

#### Successfully Discovered Credentials
- **Username**: `admin@xmpro.com`
- **Password**: [See CLAUDE.local.md]
- **Location Found**: Environment file `COMPANY_ADMIN_PASSWORD`
- **Database**: SM database, User table, ID=2, Company: XMPROCompany

#### Database Structure Verified
- **User Table**: Contains 2 admin users with proper company assignments
- **Security Table**: Contains hashed passwords with salt (varbinary columns: Password, Salt)
- **Subscription Table**: Multiple valid subscriptions for different products (SM, DS, AD, AI, Notebook)
- **SubscriptionAccess Table**: User has proper access with ProductRoleId assignments

#### Hostname Case Sensitivity Fix - OIDC Authentication Issue
**Issue**: Uppercase Windows hostname (e.g., `WIN-P5B5Q1FRBBI`) caused **401 authentication errors** due to OIDC hostname case sensitivity
**Root Cause**: **OpenID Connect (OIDC) is hostname case-sensitive** - authorization URLs must match exactly
**Solution**: Convert hostname to lowercase using `.ToLower()` method in PowerShell
**Location**: `install-xmpro-application.ps1` line 1625: `$hostname = [System.Net.Dns]::GetHostName().ToLower()`
**Result**: `https://win-p5b5q1frbbi.local/` instead of `https://WIN-P5B5Q1FRBBI.local/`
**Critical**: This affects SM IdentityServer authorization endpoints and AD→SM authentication flow

#### Certificate Setup Complete (May 2025)

### Inter-App Authentication Certificate (Signing Certificate)
**Status**: ✅ **COMPLETED** - Created with proper password protection

**Working Certificate Creation Method** (install-xmpro-application.ps1 line 1342):
```powershell
# Create simple self-signed certificate with CN=sm (PROVEN WORKING)
$opensslCmd1 = "wsl openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout `"$wslSignKey`" -out `"$wslSignCrt`" -subj `"/CN=sm`" -days 365"

# Export to PFX format for Windows/IIS  
$opensslCmd2 = "wsl openssl pkcs12 -export -out `"$wslSignPfx`" -inkey `"$wslSignKey`" -in `"$wslSignCrt`" -certfile `"$wslSignCrt`" -passout pass:`"$pfxPassword`""
```

**Key Learnings**:
- **Subject**: `CN=sm` (NOT `CN=XMIdentity` as per docs)
- **Simple self-signed certificate** works better than using a Certificate Authority (CA)
- **Simple OpenSSL approach** works better than complex PowerShell certificate management
- **No complex private key permission management needed** - IIS handles permissions automatically
- **4096-bit RSA, SHA256** for security
- **Files**: `sign.key`, `sign.crt`, `sign.pfx`
- **CRITICAL**: Must use `-legacy` flag in OpenSSL PKCS12 export for .NET Framework compatibility
- **JWT Signing Fix**: Resolves "Invalid provider type specified" crypto errors

## Complete Working Solution (June 2025)

**Three-Part Fix Required for Full Functionality:**

### 1. Certificate Compatibility Fix ✅
- **Issue**: "Invalid provider type specified" error during JWT signing
- **Solution**: Added `-legacy` flag to OpenSSL PKCS12 export
- **Impact**: Fixed SM IdentityServer token generation

### 2. IIS HTTPS Binding Cleanup ✅
- **Issue**: Old certificate bindings interfering with new certificates
- **Solution**: Added HTTPS binding removal to uninstall script
- **Impact**: Clean certificate installation without conflicts

### 3. Hostname Case Sensitivity Fix ✅
- **Issue**: OIDC 401 authentication errors with uppercase hostnames
- **Solution**: Lowercase hostname conversion in base URL generation
- **Impact**: Fixed AD→SM authentication flow and authorization

**Result**: Complete end-to-end authentication working from AD to SM with proper certificate-based JWT signing.

## Final Certificate Solution - PRODUCTION READY ✅ (June 2025)

### **Working Certificate Configuration**
The following configuration has been **proven in production** and resolves all .NET Framework 4.8 cryptographic compatibility issues:

```bash
# Certificate Generation (4096-bit with -legacy flag for .NET Framework compatibility)
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout sign.key -out sign.crt -subj "/CN=sm" -days 365
openssl pkcs12 -export -legacy -out sign.pfx -inkey sign.key -in sign.crt -certfile sign.crt -passout pass:password
```

### **Enhanced Health Check System**
**Status**: ✅ **PRODUCTION READY** - Advanced container monitoring with stability validation

```powershell
# Intelligent Container Health Monitoring (June 2025)
# - Checks Docker container status every 5 seconds
# - Requires 20 seconds of stable health before proceeding
# - 67% performance improvement (single Docker call per cycle)
# - Real-time progress feedback with countdown
# - Automatic regression detection and timer reset
```

**Key Features**:
- **Stability Requirement**: Containers must be healthy for 20 consecutive seconds
- **Progress Tracking**: "Healthy for 15 seconds, need 5 more seconds for stability"
- **Performance Optimized**: Single `docker ps` call instead of multiple per container
- **Smart Recovery**: Resets timer if containers become unhealthy
- **Multi-stage Validation**: Docker containers → HTTP endpoints → Application health

### **Certificate Installation Process**
Implemented via `Configure-SigningCertificate` function in install-xmpro-application.ps1:

1. **Import PFX** to LocalMachine\My certificate store
2. **CSP Compatibility Testing** - Tests actual JWT signing capability
3. **Fallback Directory Permissions** (most reliable approach):
   - Grant `IIS AppPool\XMPro-SM-AppPool:(R)` to both CSP and CNG key directories
   - Grant `IIS_IUSRS:(R)` to both key directories  
   - Applied to: `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` and `%ProgramData%\Microsoft\Crypto\Keys`
4. **IIS AppPool Restart** - Critical for permissions to take effect

### **Key Success Factors**
- **4096-bit RSA with -legacy flag**: Essential for .NET Framework 4.8 compatibility
- **Broad directory permissions**: More reliable than specific key file permissions
- **Fallback approach**: Handles PFX array imports and certificate format variations
- **No Unicode characters**: Prevents PowerShell parsing errors in remote execution

### **Troubleshooting Notes**
- **PFX Array Handling**: `Import-PfxCertificate` may return certificate arrays; fallback permissions bypass parsing complexity
- **Unicode Issues**: Remove ✓ ⚠ symbols from scripts to prevent remote execution failures
- **AppPool Restart Required**: Certificate permissions don't take effect until restart

### HTTPS/SSL Certificate Setup
**Status**: ✅ **COMPLETED** - IIS configured with self-signed SSL certificate

**Certificate Details**:
- **Friendly Name**: `XMPro-vm-test-ws2022`
- **Subject**: `CN=vm-test-ws2022`
- **Thumbprint**: `9FBEB6EC23649F2355DE09C995D48293C7A2A236`
- **Store Location**: LocalMachine\My (Personal)
- **IIS Binding**: HTTPS on port 443
- **Test URLs**: `https://localhost`, `https://vm-test-ws2022`, `https://4.197.67.85`

### Scripts Created
- **`create-xmpro-signing-certificate.ps1`** - Creates XMIdentity signing certificate with password protection
- **`setup-iis-https-certificate.ps1`** - Automates IIS SSL certificate setup and HTTPS binding

## Current Issue: Web.config Comparison Needed

**Problem**: Differences between Hyper-V VM and Azure VM configurations causing authentication issues

**VMs to Compare**:
1. **Azure VM**: `vm-test-ws2022` (4.197.67.85)
   - **Web.config Path**: `C:\inetpub\wwwroot\XMPRO-SM\web.config`
   - **Access**: Azure CLI commands available
   
2. **Hyper-V VM**: `Windows2022-Temp`
   - **Credentials**: administrator / P@ss!123
   - **Web.config Path**: TBD (need to locate)
   - **Access**: Requires PowerShell admin access via Hyper-V

**Next Steps**:
1. Access both VMs with admin privileges
2. Locate and read web.config files from both environments
3. Compare configuration differences (especially certificate settings, OIDC config, connection strings)
4. Identify root cause of "We could not grant you access to the requested subscription" error

### Previously Identified Issues (Fixed)
1. ✅ **"Unknown client" Authentication Error** - Fixed by using existing XMPro Product ID
2. ✅ **Certificate Private Key Access Error** - Fixed by granting IIS AppPool access
3. ✅ **Interactive SMTP Prompts** - Fixed with SkipEmailConfiguration parameter

### SM Application Details
- **IIS Path**: `C:\inetpub\wwwroot\XMPRO-SM\`
- **Logs Path**: `C:\inetpub\wwwroot\XMPRO-SM\App_Data\Logs\sm-log-YYYY-MM-DD.txt`
- **Web.config serverUUID**: Set to existing Product ID: `380129dd-6ac3-47fc-a399-234394977680`
- **App Pool**: XMPRO-SM-AppPool (running)

### Test Environment - Hyper-V VM
- **VM**: Windows2022-Temp (Hyper-V)
- **Credentials**: [See CLAUDE.local.md]
- **SQL**: localhost\SQLEXPRESS [credentials in CLAUDE.local.md]
- **Status**: Fully functional for database access and IIS operations
- **Issue**: Authentication works but subscription access fails

### Test Environment - Azure VM  
- **VM**: vm-test-ws2022 (4.197.67.85)
- **Resource Group**: RG-XMPRO-TEST
- **Subscription**: Visual Studio Enterprise Subscription – MPN - John Sanchez
- **Status**: Certificates configured, ready for XMPro deployment comparison

## Integration Completion Status (June 2025)

### **1-Click Installation Integration - IN PROGRESS 🔄**

**Work Item 20447**: Integrating all XMPro installation components for seamless 1-click deployment.

#### **Completed Integrations**
1. **Automatic Application Deployment**: install-xmpro.ps1 now automatically calls install-xmpro-application.ps1 after machine preparation
2. **Local File Detection**: Scripts detect when they're in the same directory (zipped bundle scenario) and avoid unnecessary downloads
3. **Enhanced Reliability**: Added Ubuntu download retry logic with proper exit handling
4. **Network Conflict Resolution**: Disabled vEthernet NAT to prevent WSL/Docker network conflicts
5. **Stream Host Configuration Fix**: Implemented dynamic SH_COLLECTIONID and SH_SECRET retrieval from DS database

#### **Pending Integrations**
6. **SM Install.ps1 Enterprise Deployment**: Integration planned for when SM.zip becomes available
7. **Docker Compose Simplification**: Remove 2-phase deployment when collection ID can be passed directly

#### **Integration Flow**
```bash
# Single command now handles complete deployment
iex (irm "https://jstmpfls.z8.web.core.windows.net/install-xmpro.ps1")

# Flow: Machine Prep → Auto-download App Script → Execute with BaseUrl → Full Platform Deployment
```

#### **Docker Compose Improvements**
- Aligned with latest main branch 1-click build
- Proper service dependencies and startup ordering
- Environment variable standardization
- Certificate handling improvements

## SM Install.ps1 Enterprise Integration (Planned)

**Future Integration Flow:**
```
install-xmpro.ps1 (machine prep)
    ↓
install-xmpro-application.ps1 (Docker deployment)
    ↓
Download SM.zip 
    ↓
Extract SM.zip → Install.ps1
    ↓
Execute SM Install.ps1 (replaces manual SM installation)
```

### **SM Install.ps1 Requirements Analysis**

#### **Environment Variables Needed (30+ variables):**
```powershell
# Core Required
PRODUCT_ID, BASE_URL, SITE_PATH, SITE_NAME, APP_POOL_NAME
SSL_CERT_PATH, SSL_CERT_PASSWORD
TOKEN_CERT_PATH, TOKEN_CERT_PASSWORD  
DB_CONNECTION_STRING, ENABLE_DB_MIGRATIONS
AES_SALT

# Email (Optional)
ENABLE_EMAIL, EMAIL_SERVER, EMAIL_USERNAME, EMAIL_PASSWORD

# Certificates
ROOT_CERT_PATH, ROOT_CERT_PASSWORD (optional)
TOKEN_CERT_SUBJECT, TOKEN_CERT_LOCATION
```

#### **Integration Points in install-xmpro-application.ps1:**

1. **After Docker Compose Stage 2** - SM container is running
2. **Download SM.zip** - From registry or storage location
3. **Extract to temp directory** 
4. **Set environment variables** - Map current values to SM Install.ps1 format
5. **Execute Install.ps1** - IIS deployment for production SM

#### **Key Integration Challenges:**

1. **Certificate Management** - SM Install.ps1 expects .pfx files, current process uses OpenSSL
2. **Database Connection** - Need to convert Docker connection strings to IIS format  
3. **Environment Variable Mapping** - 30+ variables need to be set from current config
4. **IIS vs Docker** - This replaces Docker SM with IIS SM deployment

#### **Integration Strategy:**
```powershell
# In install-xmpro-application.ps1, add after Docker deployment:

function Install-SM-Enterprise {
    # Download SM.zip (when ready)
    $smZipUrl = "$RegistryUrl/sm-release.zip"
    $smZipPath = "$env:TEMP\sm-release.zip" 
    
    # Extract to temp directory
    $smExtractPath = "$env:TEMP\SM-Enterprise"
    
    # Set environment variables for SM Install.ps1
    $env:PRODUCT_ID = "380129dd-6ac3-47fc-a399-234394977680"
    $env:BASE_URL = "https://$hostname.local/XMPRO-SM/"
    # ... map all 30+ environment variables
    
    # Execute SM Install.ps1
    & "$smExtractPath\Install.ps1"
}
```

**Current Status:** 🔄 **INTEGRATION IMPLEMENTED - TESTING REQUIRED**

**Code Changes Made:**
- SM.zip extraction and Install.ps1 detection implemented  
- Enterprise Install.ps1 execution path added with environment variable mapping
- Fallback to manual installation if Install.ps1 not found or fails
- All 30+ environment variables mapped from current configuration to SM Install.ps1 format
- **Refactored web.config transformation** into separate `Update-SMWebConfig` function
- Manual installation now calls refactored function instead of inline web.config manipulation

**Testing Required:**
- Test SM.zip download and extraction 
- Verify Install.ps1 is found and executed correctly
- Validate environment variable mapping 
- Confirm certificate paths and database connections
- Test fallback to manual installation if needed
- End-to-end IIS deployment validation
- **CRITICAL**: Verify ALL `[System.Net.Dns]::GetHostName()` instances use `.ToLower()` to prevent OIDC authentication failures

**⚠️ CRITICAL:** Changes are NOT complete until testing confirms functionality.

**⚠️ HOSTNAME CASE SENSITIVITY REMINDER:** ALL instances of `[System.Net.Dns]::GetHostName()` MUST include `.ToLower()` to prevent OIDC authentication failures in SM IdentityServer.

### **Test Environment Status**
- **Integration Testing**: Completed successfully for current phase
- **VM Environment**: vm-xmpro-v4 (4.197.163.10) - Clean V4 testing with all fixes
- **Deployment Method**: Remote execution via `iex (irm ...)` - Working
- **Local Bundle Support**: Local file detection - Working
- **Next Phase**: SM.zip integration when package becomes available

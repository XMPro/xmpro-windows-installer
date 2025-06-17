# XMPro Complete Installation System

⚠️ **PRE-RELEASE SOFTWARE - HIGHLY EXPERIMENTAL - USE AT YOUR OWN RISK** ⚠️

**IMPORTANT DISCLAIMER**: This installation system is currently in pre-release status and is highly experimental. It may contain bugs, incomplete features, or cause system instability. Use this software entirely at your own risk and only in non-production environments. XMPro provides no warranty or support for this pre-release software.

---

## 1. Overview and System Architecture
This repository contains a comprehensive two-phase installation system for deploying the XMPro platform on Windows Server 2022. The system automates everything from machine preparation through complete application deployment with proper security configuration.

### System Architecture

**Phase 1: Machine Preparation (`install-xmpro.ps1`)**
Prepares the Windows Server environment with all prerequisites

**Phase 2: Application Deployment (`install-xmpro-application.ps1`)** 
Deploys and configures the complete XMPro platform stack

### Integration Status
✅ **COMPLETED**: Single unified script providing true one-click deployment from bare Windows Server to fully functional XMPro platform

## 2. Phase 1: Machine Preparation

### 2.1 What Phase 1 Does
Prepares a clean Windows Server 2022 machine with all prerequisites for XMPro deployment.

### 2.2 Machine Preparation Flow
The script follows a structured 13-step process with automatic restart management:

1. **Windows Updates** - Applies latest security and performance updates
2. **First Restart** - Applies Windows updates
3. **IIS Installation** - Installs web server components and dependencies
4. **NET Framework 4.8.1** - Installs required .NET version
5. **WSL2 Setup** - Enables Windows Subsystem for Linux
6. **Container Service** - Enables Docker container support
7. **SQL Server Express** - Installs and configures database with network access
8. **Second Restart** - Applies critical Windows feature changes
9. **Ubuntu on WSL** - Installs and configures Linux subsystem
10. **Third Restart** - Finalizes WSL configuration
11. **Docker on Windows** - Installs container platform on Windows
12. **Docker on WSL2** - Installs container platform in WSL environment
13. **Post-Installation Configuration** - Final setup and validation

### 2.3 Key Features
- **Automatic restart management** with state persistence across reboots
- **Comprehensive logging** for troubleshooting and audit purposes
- **Error handling and recovery** with informative error messages
- **Parameter customization** for different deployment scenarios
- **Idempotent execution** - safe to run multiple times
- **Virtualization support** for Hyper-V and Azure environments

### 2.4 System Requirements

#### 2.4.1 Critical Requirements

**Hyper-V Virtualization Extensions**
**REQUIRED**: For Hyper-V environments, virtualization extensions must be enabled or WSL2 will not function:
```powershell
Set-VMProcessor -VMName "YourVMName" -ExposeVirtualizationExtensions $true
```

#### 2.4.2 Supported Environments
- **Physical Hardware**: Windows Server 2022
- **Hyper-V VMs**: With virtualization extensions enabled
- **Azure VMs**: VM sizes supporting nested virtualization (Dv3, Ev3, etc.)

### 2.5 Phase 1 Usage

#### 2.5.1 Basic Usage
**Important**: Run these commands in CMD (Command Prompt), not PowerShell directly

```powershell
# Download and run from hosted location (requires internet connection)
# Note: URL subject to change once DevOps pipeline integration is complete. Please use this URL for the meantime.
powershell.exe -ExecutionPolicy Bypass -Command "$env:SCRIPT_URL='https://jstmpfls.z8.web.core.windows.net/install-xmpro.ps1'; iex (irm $env:SCRIPT_URL)"

# Or run locally
powershell.exe -ExecutionPolicy Bypass -File .\install-xmpro.ps1
```

#### 2.5.2 Advanced Usage
```powershell
# Custom parameters
powershell.exe -ExecutionPolicy Bypass -File .\install-xmpro.ps1 -SqlSaPassword "YourPassword123" -DockerVersion "24.0.7" -Force
```

#### 2.5.3 Parameters
- `-NoRestart` - Prevent automatic restarts (not recommended)
- `-SqlSaPassword` - Custom SQL Server SA password
- `-DockerVersion` - Specify Docker version (default: latest)
- `-DockerComposeVersion` - Specify Docker Compose version
- `-UbuntuAppxUrl` - Custom Ubuntu distribution URL

### 2.6 What Gets Installed

#### 2.6.1 Windows Components
- IIS with all required features and URL Rewrite module
- .NET Framework 4.8.1
- WSL2 and Virtual Machine Platform
- Container and Hyper-V features
- All required Windows updates

#### 2.6.2 Database
- SQL Server 2022 Express with:
  - TCP/IP enabled on port 1433
  - Mixed authentication mode
  - Firewall rules for WSL access
  - Service configured for automatic startup

#### 2.6.3 Container Platform
- Docker CE on Windows host
- Docker and Docker Compose in WSL2 Ubuntu
- Proper networking between Windows and WSL environments

### 2.7 Files and Directories Created
- `%USERPROFILE%\.xmpro-install\` - Persistent installation directory
- Installation logs and state files
- Scheduled task for restart management
- SQL Server configuration and credential files

### 2.8 Phase 1 Validation
After running Phase 1, verify:
1. All Windows services are running (IIS, SQL Server, Docker)
2. WSL2 Ubuntu is accessible: `wsl -l -v`
3. Docker is functional in both environments: `docker --version`
4. SQL Server is accessible: `sqlcmd -S localhost,1433 -U sa`
5. No restart prompts or pending reboots remain

## 3. Phase 2: Application Deployment

### 3.1 What Phase 2 Does
Complete XMPro platform deployment and configuration:

#### 3.1.1 Docker Compose Deployment
- **Database Migrations**: SM, AD, DS database setup and schema deployment
- **Application Containers**: All XMPro services (SM, AD, DS, SH) with proper networking
- **Service Dependencies**: Automatic startup order and health checks

#### 3.1.2 Certificate Management
- **SSL Certificates**: Self-signed certificates for HTTPS with SAN support
- **JWT Signing Certificates**: .NET Framework compatible certificates with `-legacy` flag
- **Certificate Store Integration**: Automatic installation and IIS binding
- **Private Key Permissions**: Proper IIS AppPool access configuration

#### 3.1.3 IIS Application Deployment
- **SM (Subscription Manager)**: IIS application with proper configuration
- **Application Pools**: Isolated security contexts
- **Authentication Setup**: OIDC integration between components

#### 3.1.4 Configuration Management
- **Database Connections**: Secure connection string management
- **Inter-App Communication**: Certificate-based authentication between SM/AD/DS
- **Environment Configuration**: Hostname normalization (critical for OIDC)
- **Logging Configuration**: Verbose logging for troubleshooting

#### 3.1.5 Security Hardening
- **Certificate Security**: Private key access controls
- **Network Security**: Firewall rules and access restrictions
- **HTTPS Enforcement**: SSL/TLS for all communications
- **Authentication Flow**: End-to-end security validation

### 3.2 Phase 2 Usage
**Important**: Run these commands in CMD (Command Prompt), not PowerShell directly

```powershell
# Basic deployment
powershell.exe -ExecutionPolicy Bypass -File .\install-xmpro-application.ps1

# Skip email configuration (automated deployment)
powershell.exe -ExecutionPolicy Bypass -File .\install-xmpro-application.ps1 -SkipEmailConfiguration

# Custom registry and version
powershell.exe -ExecutionPolicy Bypass -File .\install-xmpro-application.ps1 -RegistryUrl "your-registry.azurecr.io" -RegistryVersion "4.5.0"
```

### 3.3 Critical Fixes Implemented
- **OIDC Hostname Case Sensitivity**: Automatic lowercase conversion prevents 401 errors
- **Certificate Compatibility**: OpenSSL `-legacy` flag ensures .NET Framework compatibility  
- **Clean Uninstall**: IIS HTTPS binding cleanup prevents certificate conflicts
- **Idempotent Execution**: Safe to re-run for troubleshooting

### 3.4 Phase 2 Validation
After running Phase 2, verify:
1. **Docker Containers**: All XMPro services are running: `docker ps`
2. **Database Connectivity**: SM, AD, DS databases are accessible
3. **IIS Application**: SM is accessible via HTTPS at the configured URL
4. **Certificate Configuration**: HTTPS works without browser warnings
5. **Authentication Flow**: Can log into SM with admin credentials

## 4. Supporting Files and Scripts

### 4.1 Certificate Authority Scripts
**`ca.sh`** - Certificate Authority creation script
- Creates a private Certificate Authority for generating trusted certificates
- Generates CA private key and self-signed root certificate
- Used by `install-xmpro-application.ps1` to establish a trust chain for SSL certificates

**`issue.sh`** - Certificate issuance script  
- Issues SSL certificates signed by the private CA created by `ca.sh`
- Generates certificates with proper Subject Alternative Names (SAN) for hostname validation
- Integrates with `install-xmpro-application.ps1` for automatic HTTPS certificate creation

### 4.2 Docker Configuration
**`docker-compose.yml`** - XMPro platform orchestration
- Defines all XMPro services: SM, AD, DS, SH and their database migration containers
- Configures service dependencies, networking, and environment variables
- Used by `install-xmpro-application.ps1` to deploy the complete XMPro application stack
- Includes proper startup order: databases → migrations → applications

### 4.3 Integration with install-xmpro-application.ps1
These files work together during Phase 2 deployment:

1. **Certificate Setup**: `ca.sh` creates CA → `issue.sh` creates SSL certificates → certificates imported to Windows certificate store
2. **Application Deployment**: `docker-compose.yml` orchestrates all XMPro services with proper configuration
3. **Service Integration**: IIS applications configured to use certificates and connect to containerized services

## 5. Security Considerations
- **SQL Server**: Credentials stored securely using PowerShell SecureString
- **Firewall Rules**: SQL Server access restricted to localhost and WSL subnets only
- **Certificate Security**: Private key access controls for IIS AppPools
- **Network Security**: Firewall rules and access restrictions
- **HTTPS Enforcement**: SSL/TLS for all communications
- **Authentication**: Certificate-based authentication between components
- **Service Isolation**: All services run with appropriate least-privilege permissions

## 6. Uninstall Process
The system includes a comprehensive uninstall script (`uninstall-xmpro.ps1`) that:
- Removes all Docker containers and images
- Cleans up IIS applications and certificates  
- Removes certificate store entries and HTTPS bindings
- Cleans up configuration files and directories
- Optionally removes databases

**Usage:**
```powershell
# Basic uninstall (keeps databases)
powershell.exe -ExecutionPolicy Bypass -File .\uninstall-xmpro.ps1

# Complete removal including databases
powershell.exe -ExecutionPolicy Bypass -File .\uninstall-xmpro.ps1 -RemoveDatabase -Force
```

## 7. Testing Coverage
- ✅ Clean Windows Server 2022 installations
- ✅ Hyper-V VMs with virtualization extensions
- ✅ Azure VMs with nested virtualization support
- ✅ Multiple execution scenarios (idempotent)
- ✅ Error recovery and restart scenarios
- ✅ Network connectivity and security validation

## 8. Roadmap

### 8.1 Integration Status
✅ **COMPLETED**: Single unified script providing true one-click deployment from bare Windows Server to fully functional XMPro platform.

✅ **COMPLETED**: Streamlined 1-click deployment with optimized container orchestration and single-stage Docker deployment.

✅ **COMPLETED**: SM Install.ps1 enterprise integration with full environment variable mapping and automated IIS deployment.

🚀 **Future Enhancement**: DevOps pipeline integration for automated CI/CD deployment across environments.

### 8.2 Current Deployment
**Production URLs**:
- Main installation: `https://jstmpfls.z8.web.core.windows.net/install-xmpro.ps1`
- Application deployment: `https://jstmpfls.z8.web.core.windows.net/v2/install-xmpro-application.ps1`

**One-Click Deployment**:
```powershell
# Complete XMPro deployment in a single command
iex (irm "https://jstmpfls.z8.web.core.windows.net/install-xmpro.ps1")
```

### 8.3 Recent Improvements (June 2025)
- **Enhanced Health Checks**: 20-second stability requirement with real-time progress tracking
- **Performance Optimization**: 67% reduction in Docker calls during health monitoring
- **Certificate Compatibility**: OpenSSL -legacy flag resolves .NET Framework 4.8 JWT signing issues
- **Function Cleanup**: Removed 280+ lines of unused functions achieving 96.5% code efficiency
- **Hostname Case Sensitivity**: All OIDC endpoints use lowercase hostnames to prevent authentication failures
- **Single-Stage Docker**: Simplified deployment removes multi-phase complexity
- **Enterprise Integration**: SM Install.ps1 fully integrated with environment variable mapping
- **Intelligent Container Monitoring**: Multi-stage validation from Docker status to HTTP endpoints

---

**Note**: This system is designed for clean Windows Server 2022 installations. Running on existing configured servers may require additional testing and validation.
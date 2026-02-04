# OS Version & Patch Status Reports

## Overview
The OS Version & Patch Status Report provides comprehensive analysis of operating system versions, patch compliance, and vulnerability status across all managed devices in Microsoft Intune.

## Key Features

### 1. OS Version Analysis
- **Version Parsing**: Automatic detection of Windows, macOS, iOS, Android versions
- **Support Status**: Checks if OS version is still supported by vendor
- **Lifecycle Tracking**: End-of-support date tracking for proactive planning
- **Release Identification**: Recognizes specific releases (21H2, 22H2, 24H2, Sonoma, Ventura, etc.)

### 2. Patch Compliance Checking
- **Patch Status Categories**:
  - `up_to_date` - Device has all available patches installed
  - `security_updates_available` - Security patches are pending
  - `feature_updates_available` - Feature updates are available
  - `outdated` - Device is significantly behind on patches
  - `unsupported` - OS version is no longer supported
  - `unknown` - Unable to determine patch status

- **Vulnerability Assessment**: Critical, high, medium, low, none
- **Missing Patches**: Count of missing security and feature updates
- **Days Since Last Patch**: Time since last patch installation

### 3. Compliance Scoring
Each device receives a compliance score (0-100) based on:
- Patch status (up to 60 points deducted)
- Vulnerability level (up to 30 points deducted)
- Days since last patch (up to 15 points deducted)
- Missing security patches (up to 30 points deducted)

### 4. Reporting Formats
- **Console Display**: Color-coded status with key metrics
- **CSV Export**: Three separate CSV files for different audiences
- **Text Report**: Comprehensive analysis report for documentation

## CSV Output Files

### 1. Summary CSV (`os_patch_summary_*.csv`)
Contains device-level summary data:
- Device ID and name
- OS name, version, build number, release name
- Support status (is_supported)
- Patch status and vulnerability level
- Compliance score (0-100)
- Missing patch counts
- Days since last patch
- Pending reboot status

### 2. Detailed CSV (`os_patch_detailed_*.csv`)
Contains individual patch information:
- Device information
- Patch ID, name, description
- Release date and install date
- Security patch indicator
- Severity level
- KB number (for Windows)
- Reboot requirement

### 3. Support Matrix CSV (`os_support_matrix_*.csv`)
Contains OS lifecycle information:
- OS name and version
- Release name
- End of support date
- Current support status

## Usage

### Generating a Report
1. Navigate to: Main Menu > Equipment Reports > OS Version/Patch Status Report
2. The report will automatically:
   - Fetch devices from Microsoft Intune
   - Analyze OS versions
   - Check patch status
   - Generate statistics

### Report Interpretation

**Compliance Scores:**
| Score Range | Status | Action |
|-------------|--------|--------|
| 90-100% | Excellent | Continue current practices |
| 80-89% | Good | Monitor for updates |
| 70-79% | Fair | Review and address issues |
| 60-69% | Poor | Prioritize remediation |
| <60% | Critical | Immediate action required |

**Status Icons:**
- Green/Success: Up to date, no issues
- Yellow/Warning: Updates available, needs attention
- Red/Error: Outdated, unsupported, or critical vulnerabilities

## Configuration

### OS Support Data
The module includes built-in support matrices for:
- **Windows**: 10, 11 with releases (21H2, 22H2, 23H2, 24H2)
- **macOS**: Sequoia (15), Sonoma (14), Ventura (13), Monterey (12)
- **iOS**: 15, 16, 17, 18
- **Android**: 12, 13, 14, 15

### Customization
Support matrices can be updated in:
- `data/os_patch/os_lifecycle.json` - OS lifecycle data
- `data/os_patch/critical_vulnerabilities.json` - Known vulnerabilities
- `modules/os_patch_checker.py` - Module source code

## Data Sources

### Current Implementation
- Device inventory from Microsoft Intune
- OS version data from managed device properties
- Simulated patch data (for demonstration purposes)

### Production Integration
For production use, consider integrating with:
- **Windows**: WSUS, SCCM, Windows Update for Business
- **macOS**: Jamf, Kandji, Mosyle
- **iOS/Android**: Mobile Device Management solutions
- **Vulnerability Data**: NVD, Microsoft Security Response Center, Apple Security Updates

## Troubleshooting

### No Patch Data Available
- Verify Intune device enrollment
- Check API permissions for device management
- Ensure devices are syncing regularly

### Incorrect OS Detection
1. Verify device inventory data quality in Intune
2. Check OS version string format
3. Update parsing logic if needed for new OS versions

### Performance Issues
1. Large datasets: CSV exports are limited to 1000 rows for detailed data
2. Consider implementing pagination for very large deployments
3. Cache support matrix data for repeated queries

## API Permissions Required

The following Microsoft Graph API permissions are needed:
- `DeviceManagementManagedDevices.Read.All` - Read managed devices
- `DeviceManagementConfiguration.Read.All` - Read device configurations

## Related Reports

- **Device Encryption Status Report** - Encryption compliance
- **Compliance Policy Adherence Report** - Policy compliance details
- **Asset Tracking Report** - Device inventory and serial numbers

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-11 | Initial implementation with OS analysis, patch status, compliance scoring |

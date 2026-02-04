# Equipment Reports Module

## Overview
The Equipment Reports module provides device management and compliance reporting for Microsoft Intune/Azure AD registered devices.

## Features

### 1. Device Encryption Status Report
- Fetches managed devices from Microsoft Intune
- Checks encryption status (BitLocker, FileVault, etc.)
- Calculates encryption compliance rate
- Identifies non-compliant devices
- Exports to CSV with detailed information

### 2. Compliance Policy Adherence Report
- Lists devices with their compliance state
- Shows applied compliance policies
- Identifies non-compliant devices
- Tracks policy coverage

### 3. OS Version/Patch Status Report
- Shows OS version distribution
- Identifies outdated versions
- Tracks patch levels
- Helps with upgrade planning

### 4. Asset Tracking Report
- Serial number inventory
- Manufacturer and model breakdown
- User assignment tracking
- Device enrollment information

## Required Azure Permissions

The following Microsoft Graph permissions are required:
- `DeviceManagementManagedDevices.Read.All` - Read managed device data
- `DeviceManagementConfiguration.Read.All` - Read device configuration policies
- `Device.Read.All` - Read Azure AD device information

## Usage

### Generating Reports

1. Run EntraLense: `python entra_lense.py`
2. Select "Equipment" from the main menu
3. Choose a report type:
   - Device encryption status
   - Compliance policy adherence
   - OS version/patch status
   - Asset tracking

### View Options

Each report offers multiple view options:
- **Summary table**: All devices with key fields
- **Filtered views**: Non-compliant, non-encrypted, etc.
- **Statistics**: OS distribution, manufacturer breakdown
- **CSV export**: Full data export for further analysis

## Output Files

Reports are saved to: `exports/equipment/`
- `EncryptionStatus_YYYYMMDD-HHMMSS.csv`
- `CompliancePolicy_YYYYMMDD-HHMMSS.csv`
- `OSPatchStatus_YYYYMMDD-HHMMSS.csv`
- `AssetTracking_YYYYMMDD-HHMMSS.csv`

## Encryption Detection

### Windows Devices
- Checks for BitLocker encryption
- Uses compliance policy state to determine encryption status
- Reports "Compliant with encryption policy" when BitLocker is enabled

### macOS Devices
- Checks for FileVault encryption
- Uses compliance policy state to determine encryption status
- Reports "Compliant with FileVault policy" when FileVault is enabled

### Mobile Devices (iOS/Android)
- Assumes encrypted by default (modern devices encrypt by default)
- Reports "Mobile device (encrypted by default)"

## Compliance Threshold

Default encryption compliance threshold: 95%

The report will indicate:
- **COMPLIANT**: Encryption rate meets or exceeds threshold
- **NON-COMPLIANT**: Encryption rate below threshold

## Troubleshooting

### No Devices Found
1. Verify Azure AD permissions are correctly configured
2. Check if devices are enrolled in Microsoft Intune
3. Ensure the authenticated user has access to device data
4. Verify tenant has Intune license

### Permission Errors
1. Ensure the app registration has the required Graph permissions
2. Admin consent may be required for device management permissions
3. Check if conditional access policies are blocking access

### Slow Report Generation
1. Large device counts may take time to process
2. Compliance policy enrichment adds processing time
3. Consider filtering by device type to reduce data volume

## Architecture

```
EquipmentReports
    └── IntuneIntegration
            └── Microsoft Graph API
                    └── Device Management APIs
```

The module uses:
- `msgraph-sdk` for Microsoft Graph API communication
- `pandas` for data processing and CSV export
- Async/await for non-blocking API calls

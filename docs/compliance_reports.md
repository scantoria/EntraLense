# Compliance Policy Adherence Reports

## Overview
The Compliance Policy Adherence Report module provides comprehensive checking of device compliance against security policies and standards.

## Features

### 1. Policy Coverage
- **Encryption Policies**: BitLocker, FileVault, device encryption
- **Password Policies**: Complexity, expiration, history
- **Firewall Policies**: Enabled status, configuration
- **Antivirus Policies**: Installation, updates, scanning
- **Screen Lock Policies**: Timeout, password requirements
- **OS Version Policies**: Minimum supported versions
- **Jailbreak Detection**: Mobile device security checks

### 2. Report Formats
- **Executive Summary**: High-level overview for management
- **Detailed Report**: Comprehensive analysis for IT teams
- **Summary Report**: Balanced detail for different audiences

### 3. Severity Levels
- **Critical**: Immediate action required (e.g., no encryption)
- **High**: Important security issues (e.g., no firewall)
- **Medium**: Moderate security concerns
- **Low**: Minor issues or recommendations

## Configuration

### Compliance Settings in EntraConfig
The following settings can be configured:

```python
compliance_check_types: list  # Policy types to check
compliance_severity_threshold: str  # Minimum severity to report
compliance_report_format: str  # Report format (detailed/summary/executive)
compliance_alert_threshold: float  # Compliance % threshold for alerts
include_remediation_details: bool  # Include fix instructions
```

### Default Check Types
- encryption
- password
- firewall
- antivirus
- screen_lock
- jailbreak
- minimum_os

## Usage

### Generating Compliance Report
```
Main Menu > Equipment Reports > Compliance Policy Adherence
```

### Report Outputs
1. **Console Display**: Summary and key findings
2. **CSV Files**: Detailed results in exports/equipment/compliance/
   - `compliance_detailed_*.csv`: Per-check results
   - `compliance_summary_*.csv`: Per-device summaries
3. **Text Reports**: Full reports in exports/equipment/compliance/

## Compliance Scoring

### Calculation
```
Compliance Score = (Compliant Checks / Applicable Checks) x 100
```

### Score Interpretation
- **90-100%**: Excellent compliance
- **80-89%**: Good compliance
- **70-79%**: Fair compliance (monitor)
- **Below 70%**: Poor compliance (action required)

## Policy Definitions

### ENC-001: Device Encryption Requirement
- **Type**: encryption
- **Severity**: Critical
- **Platforms**: Windows, macOS, iOS, Android
- **Requirements**: Disk encryption must be enabled

### PWD-001: Password Complexity Requirement
- **Type**: password
- **Severity**: High
- **Platforms**: All
- **Requirements**: Password policies must be enforced

### FW-001: Firewall Enabled
- **Type**: firewall
- **Severity**: High
- **Platforms**: Windows, macOS
- **Requirements**: Firewall must be active

### AV-001: Antivirus Protection
- **Type**: antivirus
- **Severity**: High
- **Platforms**: Windows, macOS
- **Requirements**: AV installed and up-to-date

### SL-001: Screen Lock Timeout
- **Type**: screen_lock
- **Severity**: Medium
- **Platforms**: All
- **Requirements**: Auto-lock within 5 minutes

### OS-001: Minimum OS Version
- **Type**: minimum_os
- **Severity**: High
- **Platforms**: All
- **Requirements**: Meet minimum supported version

### JB-001: Jailbreak/Root Detection
- **Type**: jailbreak
- **Severity**: Critical
- **Platforms**: iOS, Android
- **Requirements**: Device not jailbroken/rooted

## Integration with Intune

### Data Sources
1. Device inventory from Microsoft Intune
2. Compliance state from device management
3. Encryption status from device reports

### Required Permissions
- DeviceManagementManagedDevices.Read.All
- DeviceManagementConfiguration.Read.All

## Extending Compliance Checks

### Adding Custom Policies
Modify `_load_default_policies()` in `compliance_checker.py`:

```python
self.policies["CUSTOM-001"] = CompliancePolicy(
    policy_id="CUSTOM-001",
    policy_name="Custom Policy Name",
    policy_type="custom_type",
    description="Policy description",
    requirements={...},
    severity=ComplianceSeverity.HIGH,
    platforms=["windows", "macos"],
    applies_to=["all_company_devices"],
    remediation_steps=["Step 1", "Step 2"],
    references=["Reference 1"]
)
```

## Troubleshooting

### No Compliance Results
1. Verify devices are enrolled in Intune
2. Check compliance policy assignments
3. Verify Graph API permissions

### Missing Device Data
1. Ensure devices sync regularly with Intune
2. Check device enrollment status
3. Verify MDM agent is functioning

### Performance Issues
1. Reduce number of devices scanned
2. Increase timeout values if needed
3. Check network connectivity to Graph API

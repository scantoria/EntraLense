"""Compliance policy checker and analyzer module."""

import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import pandas as pd

logger = logging.getLogger(__name__)


class ComplianceSeverity(Enum):
    """Compliance issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ComplianceStatus(Enum):
    """Compliance check status."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"
    PENDING = "pending"


@dataclass
class CompliancePolicy:
    """Compliance policy definition."""
    policy_id: str
    policy_name: str
    policy_type: str  # encryption, password, firewall, etc.
    description: str
    requirements: Dict[str, Any]
    severity: ComplianceSeverity
    platforms: List[str]  # windows, macos, ios, android, linux
    applies_to: List[str]  # device_types, user_groups, etc.
    remediation_steps: List[str]
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary."""
        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "policy_type": self.policy_type,
            "description": self.description,
            "requirements": str(self.requirements),
            "severity": self.severity.value,
            "platforms": ", ".join(self.platforms),
            "applies_to": ", ".join(self.applies_to),
            "remediation_steps": "; ".join(self.remediation_steps),
            "references": ", ".join(self.references)
        }


@dataclass
class ComplianceCheckResult:
    """Result of a compliance check."""
    check_id: str
    policy_id: str
    device_id: str
    device_name: str
    status: ComplianceStatus
    severity: ComplianceSeverity
    check_details: str
    actual_value: Any
    expected_value: Any
    timestamp: datetime
    error_message: Optional[str] = None
    remediation_required: bool = False
    remediation_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "check_id": self.check_id,
            "policy_id": self.policy_id,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "status": self.status.value,
            "severity": self.severity.value,
            "check_details": self.check_details,
            "actual_value": str(self.actual_value) if self.actual_value is not None else "",
            "expected_value": str(self.expected_value) if self.expected_value is not None else "",
            "timestamp": self.timestamp.isoformat(),
            "error_message": self.error_message or "",
            "remediation_required": self.remediation_required,
            "remediation_steps": "; ".join(self.remediation_steps)
        }


@dataclass
class DeviceComplianceSummary:
    """Device compliance summary."""
    device_id: str
    device_name: str
    platform: str
    total_checks: int
    compliant_checks: int
    non_compliant_checks: int
    error_checks: int
    compliance_score: float  # 0-100
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    last_check: datetime
    requires_attention: bool = False
    attention_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to dictionary."""
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "platform": self.platform,
            "total_checks": self.total_checks,
            "compliant_checks": self.compliant_checks,
            "non_compliant_checks": self.non_compliant_checks,
            "error_checks": self.error_checks,
            "compliance_score": self.compliance_score,
            "critical_issues": self.critical_issues,
            "high_issues": self.high_issues,
            "medium_issues": self.medium_issues,
            "low_issues": self.low_issues,
            "last_check": self.last_check.isoformat(),
            "requires_attention": self.requires_attention,
            "attention_reasons": "; ".join(self.attention_reasons)
        }


class ComplianceChecker:
    """Compliance policy checker and analyzer."""

    # Default compliance check types
    DEFAULT_CHECK_TYPES = [
        "encryption", "password", "firewall", "antivirus",
        "screen_lock", "jailbreak", "minimum_os"
    ]

    # Default severity threshold
    DEFAULT_SEVERITY_THRESHOLD = "medium"

    # Default alert threshold
    DEFAULT_ALERT_THRESHOLD = 80.0

    def __init__(self, auth, config=None):
        """
        Initialize compliance checker.

        Args:
            auth: Authenticated EntraAuth instance
            config: Application configuration (optional)
        """
        self.auth = auth
        self.config = config
        self.policies: Dict[str, CompliancePolicy] = {}
        self.results: List[ComplianceCheckResult] = []
        self.summaries: Dict[str, DeviceComplianceSummary] = {}

        # Get settings from config or use defaults
        self.check_types = getattr(config, 'compliance_check_types', self.DEFAULT_CHECK_TYPES)
        self.severity_threshold = getattr(config, 'compliance_severity_threshold', self.DEFAULT_SEVERITY_THRESHOLD)
        self.alert_threshold = getattr(config, 'compliance_alert_threshold', self.DEFAULT_ALERT_THRESHOLD)

        # Load compliance policies
        self._load_default_policies()

    def _load_default_policies(self) -> None:
        """Load default compliance policies."""
        # Encryption policies
        self.policies["ENC-001"] = CompliancePolicy(
            policy_id="ENC-001",
            policy_name="Device Encryption Requirement",
            policy_type="encryption",
            description="All company devices must have disk encryption enabled.",
            requirements={
                "windows": {"encryption_method": "BitLocker", "status": "enabled"},
                "macos": {"encryption_method": "FileVault", "status": "enabled"},
                "ios": {"encryption_method": "Data Protection", "status": "enabled"},
                "android": {"encryption_method": "FDE/FBE", "status": "enabled"}
            },
            severity=ComplianceSeverity.CRITICAL,
            platforms=["windows", "macos", "ios", "android"],
            applies_to=["all_company_devices"],
            remediation_steps=[
                "Enable BitLocker on Windows devices",
                "Enable FileVault on macOS devices",
                "Enable data protection on mobile devices"
            ],
            references=["NIST 800-53 SC-28", "HIPAA 164.312"]
        )

        # Password policies
        self.policies["PWD-001"] = CompliancePolicy(
            policy_id="PWD-001",
            policy_name="Password Complexity Requirement",
            policy_type="password",
            description="Devices must have password complexity enabled.",
            requirements={
                "minimum_length": 8,
                "require_complexity": True,
                "maximum_age_days": 90,
                "password_history": 5
            },
            severity=ComplianceSeverity.HIGH,
            platforms=["windows", "macos", "ios", "android"],
            applies_to=["all_company_devices"],
            remediation_steps=[
                "Configure password policy in device management",
                "Enforce password complexity requirements",
                "Set password expiration policy"
            ],
            references=["NIST 800-63B", "ISO 27001 A.9.4.3"]
        )

        # Firewall policies
        self.policies["FW-001"] = CompliancePolicy(
            policy_id="FW-001",
            policy_name="Firewall Enabled",
            policy_type="firewall",
            description="Device firewall must be enabled.",
            requirements={
                "windows": {"firewall_enabled": True, "profile": "domain"},
                "macos": {"firewall_enabled": True, "stealth_mode": True}
            },
            severity=ComplianceSeverity.HIGH,
            platforms=["windows", "macos"],
            applies_to=["all_company_devices"],
            remediation_steps=[
                "Enable Windows Defender Firewall",
                "Configure firewall rules appropriately",
                "Enable stealth mode on macOS"
            ],
            references=["CIS Benchmarks", "NIST 800-53 SC-7"]
        )

        # Antivirus policies
        self.policies["AV-001"] = CompliancePolicy(
            policy_id="AV-001",
            policy_name="Antivirus Protection",
            policy_type="antivirus",
            description="Antivirus software must be installed, enabled, and up-to-date.",
            requirements={
                "antivirus_installed": True,
                "real_time_protection": True,
                "definitions_updated": True,
                "last_scan_days": 7
            },
            severity=ComplianceSeverity.HIGH,
            platforms=["windows", "macos"],
            applies_to=["all_company_devices"],
            remediation_steps=[
                "Install approved antivirus software",
                "Enable real-time protection",
                "Update virus definitions regularly",
                "Schedule regular scans"
            ],
            references=["CIS Benchmarks", "PCI DSS Requirement 5"]
        )

        # Screen lock policies
        self.policies["SL-001"] = CompliancePolicy(
            policy_id="SL-001",
            policy_name="Screen Lock Timeout",
            policy_type="screen_lock",
            description="Devices must automatically lock after inactivity.",
            requirements={
                "timeout_minutes": 5,
                "require_password": True,
                "grace_period_seconds": 30
            },
            severity=ComplianceSeverity.MEDIUM,
            platforms=["windows", "macos", "ios", "android"],
            applies_to=["all_mobile_devices", "laptops"],
            remediation_steps=[
                "Configure screen lock timeout",
                "Require password on wake",
                "Disable automatic login"
            ],
            references=["HIPAA 164.312", "NIST 800-53 AC-11"]
        )

        # Minimum OS version
        self.policies["OS-001"] = CompliancePolicy(
            policy_id="OS-001",
            policy_name="Minimum OS Version",
            policy_type="minimum_os",
            description="Devices must run minimum supported OS version.",
            requirements={
                "windows": {"min_version": "10.0.19044"},  # Windows 10 21H2
                "macos": {"min_version": "12.0.0"},  # macOS Monterey
                "ios": {"min_version": "15.0.0"},
                "android": {"min_version": "10.0.0"}
            },
            severity=ComplianceSeverity.HIGH,
            platforms=["windows", "macos", "ios", "android"],
            applies_to=["all_company_devices"],
            remediation_steps=[
                "Update operating system to latest version",
                "Install security patches",
                "Replace unsupported devices"
            ],
            references=["Microsoft Security Baseline", "Apple Security Updates"]
        )

        # Jailbreak detection
        self.policies["JB-001"] = CompliancePolicy(
            policy_id="JB-001",
            policy_name="Jailbreak/Root Detection",
            policy_type="jailbreak",
            description="Mobile devices must not be jailbroken or rooted.",
            requirements={
                "jailbreak_detected": False,
                "root_detected": False
            },
            severity=ComplianceSeverity.CRITICAL,
            platforms=["ios", "android"],
            applies_to=["all_mobile_devices"],
            remediation_steps=[
                "Remove jailbreak/root from device",
                "Factory reset if necessary",
                "Replace device if compromised"
            ],
            references=["NIST 800-53 CM-7", "CIS Mobile Benchmarks"]
        )

    async def check_device_compliance(self, device_info: Dict[str, Any]) -> List[ComplianceCheckResult]:
        """
        Run compliance checks for a device.

        Args:
            device_info: Device information dictionary

        Returns:
            List of ComplianceCheckResult objects
        """
        device_id = device_info.get("device_id", "unknown")
        device_name = device_info.get("device_name", "Unknown")

        results = []

        # Filter policies that apply to this device/platform
        applicable_policies = self._get_applicable_policies(device_info)

        for policy in applicable_policies:
            try:
                # Run the compliance check
                result = await self._run_compliance_check(policy, device_info)
                results.append(result)

            except Exception as e:
                logger.error(f"Error running compliance check {policy.policy_id} for {device_name}: {e}")

                # Create error result
                error_result = ComplianceCheckResult(
                    check_id=f"{policy.policy_id}-{device_id}",
                    policy_id=policy.policy_id,
                    device_id=device_id,
                    device_name=device_name,
                    status=ComplianceStatus.ERROR,
                    severity=policy.severity,
                    check_details=f"Error checking {policy.policy_name}",
                    actual_value=None,
                    expected_value=None,
                    timestamp=datetime.utcnow(),
                    error_message=str(e),
                    remediation_required=False
                )
                results.append(error_result)

        return results

    def _get_applicable_policies(self, device_info: Dict[str, Any]) -> List[CompliancePolicy]:
        """Get policies applicable to the device."""
        platform = device_info.get("operating_system", "").lower()
        device_type = self._determine_device_type(device_info)

        applicable = []

        for policy in self.policies.values():
            # Check if policy type is enabled
            if policy.policy_type not in self.check_types:
                continue

            # Check if policy applies to device platform
            platform_applies = False
            for supported_platform in policy.platforms:
                if supported_platform in platform:
                    platform_applies = True
                    break

            if not platform_applies:
                continue

            # Check if policy applies to device type
            applies_to_device = self._check_policy_applies(policy, device_info, device_type)
            if not applies_to_device:
                continue

            # Check severity threshold
            if self._meets_severity_threshold(policy.severity):
                applicable.append(policy)

        return applicable

    def _determine_device_type(self, device_info: Dict[str, Any]) -> str:
        """Determine device type from info."""
        device_name = device_info.get("device_name", "").lower()
        model = device_info.get("model", "").lower()
        operating_system = device_info.get("operating_system", "").lower()

        if "ios" in operating_system or "iphone" in model or "ipad" in model:
            return "mobile"
        elif "android" in operating_system:
            return "mobile"
        elif any(word in device_name for word in ["laptop", "notebook", "ultrabook", "macbook"]):
            return "laptop"
        elif any(word in device_name for word in ["desktop", "workstation", "tower", "imac"]):
            return "desktop"
        elif any(word in device_name for word in ["tablet", "ipad", "surface"]):
            return "tablet"
        elif "server" in device_name:
            return "server"
        else:
            return "unknown"

    def _check_policy_applies(self, policy: CompliancePolicy, device_info: Dict[str, Any], device_type: str) -> bool:
        """Check if policy applies to device."""
        applies_to = policy.applies_to

        # Check for specific device types
        if "all_company_devices" in applies_to:
            return True
        elif "all_mobile_devices" in applies_to and device_type in ["mobile", "tablet"]:
            return True
        elif "laptops" in applies_to and device_type == "laptop":
            return True
        elif "servers" in applies_to and device_type == "server":
            return True
        elif "desktops" in applies_to and device_type == "desktop":
            return True

        return False

    def _meets_severity_threshold(self, severity: ComplianceSeverity) -> bool:
        """Check if severity meets threshold."""
        severity_order = {
            ComplianceSeverity.CRITICAL: 4,
            ComplianceSeverity.HIGH: 3,
            ComplianceSeverity.MEDIUM: 2,
            ComplianceSeverity.LOW: 1,
            ComplianceSeverity.INFORMATIONAL: 0
        }

        threshold_order = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1
        }

        severity_level = severity_order.get(severity, 0)
        threshold_level = threshold_order.get(self.severity_threshold.lower(), 2)

        return severity_level >= threshold_level

    async def _run_compliance_check(self, policy: CompliancePolicy, device_info: Dict[str, Any]) -> ComplianceCheckResult:
        """Run a specific compliance check."""
        check_methods = {
            "encryption": self._check_encryption_compliance,
            "password": self._check_password_compliance,
            "firewall": self._check_firewall_compliance,
            "antivirus": self._check_antivirus_compliance,
            "screen_lock": self._check_screen_lock_compliance,
            "minimum_os": self._check_os_version_compliance,
            "jailbreak": self._check_jailbreak_compliance
        }

        check_method = check_methods.get(policy.policy_type, self._check_generic_compliance)

        return await check_method(policy, device_info)

    async def _check_encryption_compliance(self, policy: CompliancePolicy, device_info: Dict[str, Any]) -> ComplianceCheckResult:
        """Check encryption compliance."""
        device_id = device_info.get("device_id", "unknown")
        device_name = device_info.get("device_name", "Unknown")
        platform = device_info.get("operating_system", "").lower()

        # Get encryption status from device info
        is_encrypted = device_info.get("is_encrypted")
        encryption_method = device_info.get("encryption_method", "")

        # Determine expected values
        requirements = policy.requirements.get(platform, {})
        expected_method = requirements.get("encryption_method", "Disk encryption")

        # Evaluate compliance
        if is_encrypted is True:
            status = ComplianceStatus.COMPLIANT
            check_details = f"Encryption enabled with {encryption_method or 'system encryption'}"
            remediation_required = False
        elif is_encrypted is False:
            status = ComplianceStatus.NON_COMPLIANT
            check_details = "Encryption not enabled"
            remediation_required = True
        else:
            status = ComplianceStatus.ERROR
            check_details = "Unable to determine encryption status"
            remediation_required = False

        remediation_steps = policy.remediation_steps if remediation_required else []

        return ComplianceCheckResult(
            check_id=f"{policy.policy_id}-{device_id}",
            policy_id=policy.policy_id,
            device_id=device_id,
            device_name=device_name,
            status=status,
            severity=policy.severity,
            check_details=check_details,
            actual_value=encryption_method if is_encrypted else "Not encrypted",
            expected_value=expected_method,
            timestamp=datetime.utcnow(),
            remediation_required=remediation_required,
            remediation_steps=remediation_steps
        )

    async def _check_password_compliance(self, policy: CompliancePolicy, device_info: Dict[str, Any]) -> ComplianceCheckResult:
        """Check password policy compliance based on Intune compliance state."""
        device_id = device_info.get("device_id", "unknown")
        device_name = device_info.get("device_name", "Unknown")
        compliance_state = device_info.get("compliance_state", "").lower()

        # Check if device is compliant (Intune handles password policy)
        if "compliant" in compliance_state and "non" not in compliance_state:
            status = ComplianceStatus.COMPLIANT
            check_details = "Password policies compliant per Intune"
            remediation_required = False
        else:
            status = ComplianceStatus.NON_COMPLIANT
            check_details = "Device not compliant with password policies"
            remediation_required = True

        return ComplianceCheckResult(
            check_id=f"{policy.policy_id}-{device_id}",
            policy_id=policy.policy_id,
            device_id=device_id,
            device_name=device_name,
            status=status,
            severity=policy.severity,
            check_details=check_details,
            actual_value=compliance_state,
            expected_value="Compliant",
            timestamp=datetime.utcnow(),
            remediation_required=remediation_required,
            remediation_steps=policy.remediation_steps if remediation_required else []
        )

    async def _check_firewall_compliance(self, policy: CompliancePolicy, device_info: Dict[str, Any]) -> ComplianceCheckResult:
        """Check firewall compliance based on device compliance state."""
        device_id = device_info.get("device_id", "unknown")
        device_name = device_info.get("device_name", "Unknown")
        platform = device_info.get("operating_system", "").lower()
        compliance_state = device_info.get("compliance_state", "").lower()

        # Windows and macOS typically have firewall managed by Intune
        if "windows" in platform or "macos" in platform:
            if "compliant" in compliance_state and "non" not in compliance_state:
                status = ComplianceStatus.COMPLIANT
                check_details = "Firewall enabled and configured"
                remediation_required = False
            else:
                status = ComplianceStatus.NON_COMPLIANT
                check_details = "Firewall not enabled or misconfigured"
                remediation_required = True
        else:
            status = ComplianceStatus.NOT_APPLICABLE
            check_details = "Firewall check not applicable to this platform"
            remediation_required = False

        return ComplianceCheckResult(
            check_id=f"{policy.policy_id}-{device_id}",
            policy_id=policy.policy_id,
            device_id=device_id,
            device_name=device_name,
            status=status,
            severity=policy.severity,
            check_details=check_details,
            actual_value=compliance_state,
            expected_value="Firewall enabled",
            timestamp=datetime.utcnow(),
            remediation_required=remediation_required,
            remediation_steps=policy.remediation_steps if remediation_required else []
        )

    async def _check_antivirus_compliance(self, policy: CompliancePolicy, device_info: Dict[str, Any]) -> ComplianceCheckResult:
        """Check antivirus compliance."""
        device_id = device_info.get("device_id", "unknown")
        device_name = device_info.get("device_name", "Unknown")
        platform = device_info.get("operating_system", "").lower()
        compliance_state = device_info.get("compliance_state", "").lower()

        # Windows Defender is typically managed by Intune
        if "windows" in platform:
            if "compliant" in compliance_state and "non" not in compliance_state:
                status = ComplianceStatus.COMPLIANT
                check_details = "Antivirus installed and up-to-date (Windows Defender)"
                remediation_required = False
            else:
                status = ComplianceStatus.NON_COMPLIANT
                check_details = "Antivirus missing or out-of-date"
                remediation_required = True
        elif "macos" in platform:
            # macOS has built-in XProtect
            status = ComplianceStatus.COMPLIANT
            check_details = "macOS built-in protection (XProtect) active"
            remediation_required = False
        else:
            status = ComplianceStatus.NOT_APPLICABLE
            check_details = "Antivirus check not applicable to this platform"
            remediation_required = False

        return ComplianceCheckResult(
            check_id=f"{policy.policy_id}-{device_id}",
            policy_id=policy.policy_id,
            device_id=device_id,
            device_name=device_name,
            status=status,
            severity=policy.severity,
            check_details=check_details,
            actual_value="Protected" if status == ComplianceStatus.COMPLIANT else "Unknown",
            expected_value="AV installed and current",
            timestamp=datetime.utcnow(),
            remediation_required=remediation_required,
            remediation_steps=policy.remediation_steps if remediation_required else []
        )

    async def _check_screen_lock_compliance(self, policy: CompliancePolicy, device_info: Dict[str, Any]) -> ComplianceCheckResult:
        """Check screen lock compliance."""
        device_id = device_info.get("device_id", "unknown")
        device_name = device_info.get("device_name", "Unknown")
        compliance_state = device_info.get("compliance_state", "").lower()

        # Screen lock is typically enforced via Intune compliance policies
        if "compliant" in compliance_state and "non" not in compliance_state:
            status = ComplianceStatus.COMPLIANT
            check_details = "Screen lock configured appropriately"
            remediation_required = False
        else:
            status = ComplianceStatus.NON_COMPLIANT
            check_details = "Screen lock not configured or timeout too long"
            remediation_required = True

        return ComplianceCheckResult(
            check_id=f"{policy.policy_id}-{device_id}",
            policy_id=policy.policy_id,
            device_id=device_id,
            device_name=device_name,
            status=status,
            severity=policy.severity,
            check_details=check_details,
            actual_value=compliance_state,
            expected_value="Screen lock enabled with timeout",
            timestamp=datetime.utcnow(),
            remediation_required=remediation_required,
            remediation_steps=policy.remediation_steps if remediation_required else []
        )

    async def _check_os_version_compliance(self, policy: CompliancePolicy, device_info: Dict[str, Any]) -> ComplianceCheckResult:
        """Check OS version compliance."""
        device_id = device_info.get("device_id", "unknown")
        device_name = device_info.get("device_name", "Unknown")
        platform = device_info.get("operating_system", "").lower()
        os_version = device_info.get("os_version", "0.0.0")

        # Get minimum version requirement for platform
        min_version = "0.0.0"
        for plat_key, req in policy.requirements.items():
            if plat_key in platform:
                min_version = req.get("min_version", "0.0.0")
                break

        # Simple version comparison
        try:
            actual_parts = [int(x) for x in os_version.split('.')[:3]]
            min_parts = [int(x) for x in min_version.split('.')[:3]]

            # Pad lists to same length
            while len(actual_parts) < 3:
                actual_parts.append(0)
            while len(min_parts) < 3:
                min_parts.append(0)

            # Compare version parts
            is_compliant = actual_parts >= min_parts

            if is_compliant:
                status = ComplianceStatus.COMPLIANT
                check_details = f"OS version {os_version} meets minimum requirement {min_version}"
                remediation_required = False
            else:
                status = ComplianceStatus.NON_COMPLIANT
                check_details = f"OS version {os_version} below minimum requirement {min_version}"
                remediation_required = True

        except (ValueError, AttributeError):
            status = ComplianceStatus.ERROR
            check_details = f"Unable to parse OS version: {os_version}"
            remediation_required = False

        return ComplianceCheckResult(
            check_id=f"{policy.policy_id}-{device_id}",
            policy_id=policy.policy_id,
            device_id=device_id,
            device_name=device_name,
            status=status,
            severity=policy.severity,
            check_details=check_details,
            actual_value=os_version,
            expected_value=f"Minimum: {min_version}",
            timestamp=datetime.utcnow(),
            remediation_required=remediation_required,
            remediation_steps=policy.remediation_steps if remediation_required else []
        )

    async def _check_jailbreak_compliance(self, policy: CompliancePolicy, device_info: Dict[str, Any]) -> ComplianceCheckResult:
        """Check jailbreak/root detection."""
        device_id = device_info.get("device_id", "unknown")
        device_name = device_info.get("device_name", "Unknown")
        platform = device_info.get("operating_system", "").lower()
        compliance_state = device_info.get("compliance_state", "").lower()

        # Check if mobile device
        if "ios" not in platform and "android" not in platform:
            return ComplianceCheckResult(
                check_id=f"{policy.policy_id}-{device_id}",
                policy_id=policy.policy_id,
                device_id=device_id,
                device_name=device_name,
                status=ComplianceStatus.NOT_APPLICABLE,
                severity=policy.severity,
                check_details="Jailbreak check only applies to mobile devices",
                actual_value="N/A",
                expected_value="Not jailbroken",
                timestamp=datetime.utcnow(),
                remediation_required=False
            )

        # Intune detects jailbroken devices and marks them non-compliant
        if "compliant" in compliance_state and "non" not in compliance_state:
            status = ComplianceStatus.COMPLIANT
            check_details = "Device not jailbroken/rooted"
            remediation_required = False
        else:
            # Could be non-compliant for other reasons, but flag it
            status = ComplianceStatus.NON_COMPLIANT
            check_details = "Device may be jailbroken/rooted or non-compliant"
            remediation_required = True

        return ComplianceCheckResult(
            check_id=f"{policy.policy_id}-{device_id}",
            policy_id=policy.policy_id,
            device_id=device_id,
            device_name=device_name,
            status=status,
            severity=policy.severity,
            check_details=check_details,
            actual_value=compliance_state,
            expected_value="Device not jailbroken",
            timestamp=datetime.utcnow(),
            remediation_required=remediation_required,
            remediation_steps=policy.remediation_steps if remediation_required else []
        )

    async def _check_generic_compliance(self, policy: CompliancePolicy, device_info: Dict[str, Any]) -> ComplianceCheckResult:
        """Generic compliance check for unknown policy types."""
        device_id = device_info.get("device_id", "unknown")
        device_name = device_info.get("device_name", "Unknown")

        return ComplianceCheckResult(
            check_id=f"{policy.policy_id}-{device_id}",
            policy_id=policy.policy_id,
            device_id=device_id,
            device_name=device_name,
            status=ComplianceStatus.NOT_APPLICABLE,
            severity=policy.severity,
            check_details=f"Check type '{policy.policy_type}' not implemented",
            actual_value=None,
            expected_value=None,
            timestamp=datetime.utcnow(),
            error_message=f"Unsupported check type: {policy.policy_type}",
            remediation_required=False
        )

    async def batch_check_compliance(self, devices_info: List[Dict[str, Any]]) -> List[ComplianceCheckResult]:
        """
        Run compliance checks for multiple devices.

        Args:
            devices_info: List of device information dictionaries

        Returns:
            List of ComplianceCheckResult objects
        """
        print(f"\n   Starting batch compliance check for {len(devices_info)} devices...")

        all_results = []
        total = len(devices_info)

        for i, device_info in enumerate(devices_info, 1):
            try:
                device_name = device_info.get("device_name", f"Device {i}")

                results = await self.check_device_compliance(device_info)
                all_results.extend(results)

                # Update progress
                if i % 10 == 0 or i == total:
                    print(f"   Processed {i}/{total} devices")

            except Exception as e:
                logger.error(f"Failed to check compliance for device {device_info.get('device_name', 'unknown')}: {e}")
                # Continue with next device

        self.results = all_results
        print(f"   Batch compliance check complete. {len(all_results)} checks performed.")

        return all_results

    def generate_compliance_summaries(self, devices_info: List[Dict[str, Any]]) -> Dict[str, DeviceComplianceSummary]:
        """
        Generate compliance summaries for devices.

        Args:
            devices_info: List of device information dictionaries

        Returns:
            Dictionary mapping device_id to DeviceComplianceSummary
        """
        summaries = {}

        for device_info in devices_info:
            device_id = device_info.get("device_id")
            device_name = device_info.get("device_name", "Unknown")
            platform = device_info.get("operating_system", "").lower()

            # Filter results for this device
            device_results = [r for r in self.results if r.device_id == device_id]

            if not device_results:
                continue

            # Calculate statistics
            total_checks = len(device_results)
            compliant_checks = sum(1 for r in device_results if r.status == ComplianceStatus.COMPLIANT)
            non_compliant_checks = sum(1 for r in device_results if r.status == ComplianceStatus.NON_COMPLIANT)
            error_checks = sum(1 for r in device_results if r.status == ComplianceStatus.ERROR)

            # Calculate compliance score
            applicable_checks = compliant_checks + non_compliant_checks
            if applicable_checks > 0:
                compliance_score = (compliant_checks / applicable_checks) * 100
            else:
                compliance_score = 100.0  # All checks were N/A or error

            # Count issues by severity
            critical_issues = sum(1 for r in device_results
                                 if r.status == ComplianceStatus.NON_COMPLIANT
                                 and r.severity == ComplianceSeverity.CRITICAL)

            high_issues = sum(1 for r in device_results
                             if r.status == ComplianceStatus.NON_COMPLIANT
                             and r.severity == ComplianceSeverity.HIGH)

            medium_issues = sum(1 for r in device_results
                               if r.status == ComplianceStatus.NON_COMPLIANT
                               and r.severity == ComplianceSeverity.MEDIUM)

            low_issues = sum(1 for r in device_results
                            if r.status == ComplianceStatus.NON_COMPLIANT
                            and r.severity == ComplianceSeverity.LOW)

            # Determine if device requires attention
            requires_attention = non_compliant_checks > 0
            attention_reasons = []

            if critical_issues > 0:
                attention_reasons.append(f"{critical_issues} critical issues")
            if high_issues > 0:
                attention_reasons.append(f"{high_issues} high issues")
            if compliance_score < self.alert_threshold:
                attention_reasons.append(f"Low compliance score: {compliance_score:.1f}%")

            # Get latest check timestamp
            latest_check = max((r.timestamp for r in device_results), default=datetime.utcnow())

            # Create summary
            summary = DeviceComplianceSummary(
                device_id=device_id,
                device_name=device_name,
                platform=platform,
                total_checks=total_checks,
                compliant_checks=compliant_checks,
                non_compliant_checks=non_compliant_checks,
                error_checks=error_checks,
                compliance_score=compliance_score,
                critical_issues=critical_issues,
                high_issues=high_issues,
                medium_issues=medium_issues,
                low_issues=low_issues,
                last_check=latest_check,
                requires_attention=requires_attention,
                attention_reasons=attention_reasons
            )

            summaries[device_id] = summary

        self.summaries = summaries
        return summaries

    def generate_overall_statistics(self) -> Dict[str, Any]:
        """Generate overall compliance statistics."""
        if not self.results:
            return {}

        total_results = len(self.results)

        # Status distribution
        status_counts = {
            "compliant": sum(1 for r in self.results if r.status == ComplianceStatus.COMPLIANT),
            "non_compliant": sum(1 for r in self.results if r.status == ComplianceStatus.NON_COMPLIANT),
            "error": sum(1 for r in self.results if r.status == ComplianceStatus.ERROR),
            "not_applicable": sum(1 for r in self.results if r.status == ComplianceStatus.NOT_APPLICABLE)
        }

        # Severity distribution of non-compliant issues
        severity_counts = {
            "critical": sum(1 for r in self.results
                           if r.status == ComplianceStatus.NON_COMPLIANT
                           and r.severity == ComplianceSeverity.CRITICAL),
            "high": sum(1 for r in self.results
                       if r.status == ComplianceStatus.NON_COMPLIANT
                       and r.severity == ComplianceSeverity.HIGH),
            "medium": sum(1 for r in self.results
                         if r.status == ComplianceStatus.NON_COMPLIANT
                         and r.severity == ComplianceSeverity.MEDIUM),
            "low": sum(1 for r in self.results
                      if r.status == ComplianceStatus.NON_COMPLIANT
                      and r.severity == ComplianceSeverity.LOW)
        }

        # Policy type distribution
        policy_type_counts = {}
        for result in self.results:
            policy_type = "unknown"
            if result.policy_id in self.policies:
                policy_type = self.policies[result.policy_id].policy_type

            policy_type_counts[policy_type] = policy_type_counts.get(policy_type, 0) + 1

        # Device compliance scores from summaries
        device_scores = [s.compliance_score for s in self.summaries.values()]
        avg_compliance_score = sum(device_scores) / len(device_scores) if device_scores else 0

        # Devices requiring attention
        devices_requiring_attention = sum(1 for s in self.summaries.values() if s.requires_attention)

        # Most common non-compliant policies
        non_compliant_policies = {}
        for result in self.results:
            if result.status == ComplianceStatus.NON_COMPLIANT:
                policy_name = "unknown"
                if result.policy_id in self.policies:
                    policy_name = self.policies[result.policy_id].policy_name

                non_compliant_policies[policy_name] = non_compliant_policies.get(policy_name, 0) + 1

        # Sort by frequency
        top_non_compliant = dict(sorted(
            non_compliant_policies.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5])  # Top 5

        # Calculate overall compliance rate
        applicable_results = status_counts["compliant"] + status_counts["non_compliant"]
        compliance_rate = (status_counts["compliant"] / applicable_results * 100) if applicable_results > 0 else 0

        return {
            "total_checks": total_results,
            "status_distribution": status_counts,
            "severity_distribution": severity_counts,
            "policy_type_distribution": policy_type_counts,
            "device_statistics": {
                "total_devices": len(self.summaries),
                "devices_requiring_attention": devices_requiring_attention,
                "average_compliance_score": avg_compliance_score,
                "compliance_score_range": {
                    "min": min(device_scores) if device_scores else 0,
                    "max": max(device_scores) if device_scores else 0
                }
            },
            "top_non_compliant_policies": top_non_compliant,
            "compliance_rate": compliance_rate
        }

    def export_results_to_dataframe(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Export compliance results to DataFrames.

        Returns:
            Tuple of (detailed_results_df, summary_df)
        """
        # Detailed results
        if not self.results:
            detailed_df = pd.DataFrame()
        else:
            detailed_dicts = [r.to_dict() for r in self.results]
            detailed_df = pd.DataFrame(detailed_dicts)

        # Summary data
        if not self.summaries:
            summary_df = pd.DataFrame()
        else:
            summary_dicts = [s.to_dict() for s in self.summaries.values()]
            summary_df = pd.DataFrame(summary_dicts)

        return detailed_df, summary_df

    def export_policies_to_dataframe(self) -> pd.DataFrame:
        """Export policy definitions to DataFrame."""
        if not self.policies:
            return pd.DataFrame()

        policy_dicts = [p.to_dict() for p in self.policies.values()]
        df = pd.DataFrame(policy_dicts)

        return df

    def generate_compliance_report_text(self, stats: Dict[str, Any], format_type: str = "detailed") -> str:
        """
        Generate human-readable compliance report.

        Args:
            stats: Compliance statistics dictionary
            format_type: Report format (detailed, summary, executive)

        Returns:
            Formatted report text
        """
        lines = []

        if format_type == "executive":
            lines = self._generate_executive_report(stats)
        elif format_type == "summary":
            lines = self._generate_summary_report(stats)
        else:  # detailed
            lines = self._generate_detailed_report(stats)

        return "\n".join(lines)

    def _generate_executive_report(self, stats: Dict[str, Any]) -> List[str]:
        """Generate executive summary report."""
        lines = []

        device_stats = stats.get("device_statistics", {})
        compliance_rate = stats.get("compliance_rate", 0)

        lines.append("=" * 60)
        lines.append("   COMPLIANCE POLICY ADHERENCE - EXECUTIVE SUMMARY")
        lines.append("=" * 60)
        lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")

        lines.append("OVERVIEW")
        lines.append("-" * 40)
        lines.append(f"Total Devices: {device_stats.get('total_devices', 0)}")
        lines.append(f"Overall Compliance Rate: {compliance_rate:.1f}%")
        lines.append(f"Average Device Score: {device_stats.get('average_compliance_score', 0):.1f}%")
        lines.append(f"Devices Requiring Attention: {device_stats.get('devices_requiring_attention', 0)}")
        lines.append("")

        # Compliance status
        if compliance_rate >= 90:
            lines.append("STATUS: EXCELLENT COMPLIANCE")
        elif compliance_rate >= 80:
            lines.append("STATUS: GOOD COMPLIANCE")
        elif compliance_rate >= 70:
            lines.append("STATUS: FAIR COMPLIANCE - MONITOR")
        else:
            lines.append("STATUS: POOR COMPLIANCE - ACTION REQUIRED")

        lines.append("")

        # Top issues
        top_issues = stats.get("top_non_compliant_policies", {})
        if top_issues:
            lines.append("TOP COMPLIANCE ISSUES:")
            lines.append("-" * 40)
            for policy, count in list(top_issues.items())[:3]:  # Top 3
                lines.append(f"  - {policy}: {count} occurrences")

        return lines

    def _generate_summary_report(self, stats: Dict[str, Any]) -> List[str]:
        """Generate summary report."""
        lines = self._generate_executive_report(stats)

        # Add additional details
        status_dist = stats.get("status_distribution", {})
        severity_dist = stats.get("severity_distribution", {})

        lines.append("")
        lines.append("DETAILED STATISTICS")
        lines.append("-" * 40)
        lines.append(f"Total Compliance Checks: {stats.get('total_checks', 0)}")
        lines.append(f"Compliant Checks: {status_dist.get('compliant', 0)}")
        lines.append(f"Non-Compliant Checks: {status_dist.get('non_compliant', 0)}")
        lines.append(f"Error Checks: {status_dist.get('error', 0)}")
        lines.append("")

        lines.append("ISSUE SEVERITY BREAKDOWN:")
        lines.append(f"  Critical: {severity_dist.get('critical', 0)}")
        lines.append(f"  High: {severity_dist.get('high', 0)}")
        lines.append(f"  Medium: {severity_dist.get('medium', 0)}")
        lines.append(f"  Low: {severity_dist.get('low', 0)}")

        return lines

    def _generate_detailed_report(self, stats: Dict[str, Any]) -> List[str]:
        """Generate detailed report."""
        lines = self._generate_summary_report(stats)

        # Add policy type breakdown
        policy_dist = stats.get("policy_type_distribution", {})

        lines.append("")
        lines.append("POLICY TYPE BREAKDOWN:")
        lines.append("-" * 40)
        for policy_type, count in sorted(policy_dist.items()):
            percentage = (count / stats['total_checks'] * 100) if stats['total_checks'] > 0 else 0
            lines.append(f"  {policy_type.title()}: {count} ({percentage:.1f}%)")

        # Add device score distribution
        device_stats = stats.get("device_statistics", {})
        lines.append("")
        lines.append("DEVICE COMPLIANCE SCORE DISTRIBUTION:")
        lines.append("-" * 40)
        score_range = device_stats.get('compliance_score_range', {})
        lines.append(f"  Range: {score_range.get('min', 0):.1f}% - {score_range.get('max', 0):.1f}%")
        lines.append(f"  Average: {device_stats.get('average_compliance_score', 0):.1f}%")

        # Add top non-compliant policies in detail
        top_issues = stats.get("top_non_compliant_policies", {})
        if top_issues:
            lines.append("")
            lines.append("TOP 5 NON-COMPLIANT POLICIES:")
            lines.append("-" * 40)
            for policy, count in top_issues.items():
                lines.append(f"  {policy}: {count} occurrences")

        # Add remediation guidance
        lines.append("")
        lines.append("REMEDIATION GUIDANCE:")
        lines.append("-" * 40)

        total_issues = sum(stats.get("severity_distribution", {}).values())
        if total_issues > 0:
            lines.append("1. Address critical issues immediately")
            lines.append("2. Schedule remediation for high/medium issues")
            lines.append("3. Review and update policies as needed")
            lines.append("4. Implement automated compliance monitoring")
        else:
            lines.append("No remediation required at this time.")
            lines.append("Continue regular compliance monitoring.")

        return lines

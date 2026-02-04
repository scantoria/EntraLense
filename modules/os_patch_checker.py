"""OS version and patch status checker module."""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class PatchStatus(Enum):
    """Patch compliance status."""
    UP_TO_DATE = "up_to_date"
    SECURITY_UPDATES_AVAILABLE = "security_updates_available"
    FEATURE_UPDATES_AVAILABLE = "feature_updates_available"
    OUTDATED = "outdated"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class VulnerabilityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class OSVersionInfo:
    """OS version information."""
    os_name: str  # windows, macos, ios, android, linux
    version: str  # e.g., "11.0.22000" for Windows 11
    build_number: str
    release_name: str  # e.g., "21H2", "Monterey", "Ventura"
    release_date: Optional[datetime]
    end_of_support: Optional[datetime]
    is_supported: bool
    latest_version: str
    latest_build: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "os_name": self.os_name,
            "version": self.version,
            "build_number": self.build_number,
            "release_name": self.release_name,
            "release_date": self.release_date.isoformat() if self.release_date else "",
            "end_of_support": self.end_of_support.isoformat() if self.end_of_support else "",
            "is_supported": self.is_supported,
            "latest_version": self.latest_version,
            "latest_build": self.latest_build
        }


@dataclass
class PatchInfo:
    """Patch information."""
    patch_id: str
    name: str
    description: str
    release_date: datetime
    install_date: Optional[datetime]
    is_installed: bool
    is_security: bool
    kb_number: str  # For Windows patches
    severity: VulnerabilityLevel
    superseded: bool
    requires_reboot: bool

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "patch_id": self.patch_id,
            "name": self.name,
            "description": self.description,
            "release_date": self.release_date.isoformat(),
            "install_date": self.install_date.isoformat() if self.install_date else "",
            "is_installed": self.is_installed,
            "is_security": self.is_security,
            "kb_number": self.kb_number,
            "severity": self.severity.value,
            "superseded": self.superseded,
            "requires_reboot": self.requires_reboot
        }


@dataclass
class DevicePatchStatus:
    """Device patch status summary."""
    device_id: str
    device_name: str
    os_info: OSVersionInfo
    patch_status: PatchStatus
    vulnerability_level: VulnerabilityLevel
    days_since_last_patch: int
    missing_security_patches: int
    missing_feature_updates: int
    pending_reboot: bool
    last_patch_scan: datetime
    patch_compliance_score: float  # 0-100

    # Detailed patch lists
    installed_patches: List[PatchInfo] = field(default_factory=list)
    missing_patches: List[PatchInfo] = field(default_factory=list)
    available_updates: List[PatchInfo] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "os_name": self.os_info.os_name,
            "os_version": self.os_info.version,
            "build_number": self.os_info.build_number,
            "release_name": self.os_info.release_name,
            "is_supported": self.os_info.is_supported,
            "latest_version": self.os_info.latest_version,
            "patch_status": self.patch_status.value,
            "vulnerability_level": self.vulnerability_level.value,
            "days_since_last_patch": self.days_since_last_patch,
            "missing_security_patches": self.missing_security_patches,
            "missing_feature_updates": self.missing_feature_updates,
            "pending_reboot": self.pending_reboot,
            "last_patch_scan": self.last_patch_scan.isoformat(),
            "patch_compliance_score": self.patch_compliance_score,
            "total_installed_patches": len(self.installed_patches),
            "total_missing_patches": len(self.missing_patches),
            "total_available_updates": len(self.available_updates)
        }


class OSPatchChecker:
    """OS version and patch status checker."""

    def __init__(self, auth, config=None):
        """
        Initialize OS patch checker.

        Args:
            auth: Authenticated EntraAuth instance
            config: Application configuration (optional)
        """
        self.auth = auth
        self.config = config

        # OS support matrices (simplified - would be external data in production)
        self.os_support_matrix = self._load_os_support_matrix()
        self.latest_versions = self._load_latest_versions()

        # Known critical patches (simplified - would be external feed in production)
        self.critical_patches = self._load_critical_patches()

    def _load_os_support_matrix(self) -> Dict[str, Dict[str, Any]]:
        """Load OS support matrix."""
        # Simplified support matrix - in production, this would come from an external source
        # or API like Microsoft Lifecycle Policy, Apple support, etc.

        return {
            "windows": {
                "11": {
                    "21H2": {"eos": "2023-10-10", "supported": False},
                    "22H2": {"eos": "2024-10-08", "supported": True},
                    "23H2": {"eos": "2025-10-14", "supported": True},
                    "24H2": {"eos": "2026-10-13", "supported": True}
                },
                "10": {
                    "21H2": {"eos": "2023-06-13", "supported": False},
                    "22H2": {"eos": "2025-10-14", "supported": True}
                }
            },
            "macos": {
                "15": {"name": "Sequoia", "eos": "2027-10-01", "supported": True},
                "14": {"name": "Sonoma", "eos": "2026-10-01", "supported": True},
                "13": {"name": "Ventura", "eos": "2025-10-01", "supported": True},
                "12": {"name": "Monterey", "eos": "2024-10-01", "supported": False},
                "11": {"name": "Big Sur", "eos": "2023-10-01", "supported": False}
            },
            "ios": {
                "18": {"eos": "2027-09-01", "supported": True},
                "17": {"eos": "2026-09-01", "supported": True},
                "16": {"eos": "2025-09-01", "supported": True},
                "15": {"eos": "2024-09-01", "supported": False}
            },
            "android": {
                "15": {"eos": "2027-09-01", "supported": True},
                "14": {"eos": "2026-09-01", "supported": True},
                "13": {"eos": "2025-09-01", "supported": True},
                "12": {"eos": "2024-09-01", "supported": False},
                "11": {"eos": "2023-09-01", "supported": False}
            }
        }

    def _load_latest_versions(self) -> Dict[str, Dict[str, str]]:
        """Load latest OS versions."""
        return {
            "windows": {"version": "11", "build": "24H2", "release": "2024 Update"},
            "macos": {"version": "15", "build": "15.2", "release": "Sequoia"},
            "ios": {"version": "18", "build": "18.2", "release": "iOS 18"},
            "android": {"version": "15", "build": "15", "release": "Android 15"},
            "linux": {"version": "varies", "build": "varies", "release": "Varies by distro"}
        }

    def _load_critical_patches(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load known critical patches (simplified)."""
        # In production, this would come from security advisories
        # like Microsoft Security Response Center, NVD, etc.

        return {
            "windows": [
                {
                    "kb": "KB5044284",
                    "name": "2024-10 Cumulative Security Update",
                    "severity": "critical",
                    "release_date": "2024-10-08",
                    "requires_reboot": True
                },
                {
                    "kb": "KB5044380",
                    "name": "2024-10 Security Update for Windows 11",
                    "severity": "critical",
                    "release_date": "2024-10-08",
                    "requires_reboot": True
                }
            ],
            "macos": [
                {
                    "name": "Security Update 2024-001",
                    "version": "15.1.1",
                    "severity": "high",
                    "release_date": "2024-11-19",
                    "requires_reboot": True
                }
            ]
        }

    def analyze_os_version(self, os_name: str, version: str, build: str = "") -> OSVersionInfo:
        """
        Analyze OS version and determine support status.

        Args:
            os_name: Operating system name
            version: OS version string
            build: Build number/string

        Returns:
            OSVersionInfo object
        """
        os_name_lower = os_name.lower()
        now = datetime.utcnow()

        # Default values
        os_info = OSVersionInfo(
            os_name=os_name_lower,
            version=version,
            build_number=build,
            release_name="",
            release_date=None,
            end_of_support=None,
            is_supported=True,
            latest_version="",
            latest_build=""
        )

        # Get latest version info
        latest = self.latest_versions.get(os_name_lower, {})
        os_info.latest_version = latest.get("version", "")
        os_info.latest_build = latest.get("build", "")

        # Parse Windows versions
        if "windows" in os_name_lower:
            return self._analyze_windows_version(os_info, version, build, now)

        # Parse macOS versions
        elif "mac" in os_name_lower or "macos" in os_name_lower:
            return self._analyze_macos_version(os_info, version, build, now)

        # Parse iOS versions
        elif "ios" in os_name_lower:
            return self._analyze_ios_version(os_info, version, now)

        # Parse Android versions
        elif "android" in os_name_lower:
            return self._analyze_android_version(os_info, version, now)

        # Linux - hard to standardize
        elif "linux" in os_name_lower:
            os_info.release_name = self._parse_linux_distro(version)
            # Linux support varies by distro - assume supported for now
            os_info.is_supported = True

        return os_info

    def _analyze_windows_version(self, os_info: OSVersionInfo, version: str, build: str, now: datetime) -> OSVersionInfo:
        """Analyze Windows version."""
        try:
            # Parse version like "10.0.19045" or "11.0.22621"
            parts = version.split('.')
            if len(parts) >= 2:
                major_version = parts[0]
                build_number = parts[-1] if len(parts) > 2 and parts[-1] else build

                # Determine Windows version (10 or 11)
                if major_version == "10":
                    # Check build number to differentiate Windows 10 and 11
                    if build_number:
                        try:
                            build_int = int(build_number)
                            # Windows 11 builds start at 22000
                            if build_int >= 22000:
                                windows_version = "11"
                            else:
                                windows_version = "10"
                        except ValueError:
                            windows_version = "10"
                    else:
                        windows_version = "10"
                    release_name = self._get_windows_release(build_number)
                elif major_version == "11":
                    windows_version = "11"
                    release_name = self._get_windows_release(build_number)
                else:
                    windows_version = major_version
                    release_name = "Unknown"

                os_info.release_name = release_name

                # Check support matrix
                support_info = self.os_support_matrix.get("windows", {}).get(
                    windows_version, {}).get(release_name, {})

                if support_info:
                    eos_str = support_info.get("eos")
                    if eos_str:
                        try:
                            os_info.end_of_support = datetime.strptime(eos_str, "%Y-%m-%d")
                            os_info.is_supported = now <= os_info.end_of_support
                        except ValueError:
                            os_info.is_supported = support_info.get("supported", True)
                    else:
                        os_info.is_supported = support_info.get("supported", True)
                else:
                    # If not in matrix, make educated guess
                    os_info.is_supported = self._guess_windows_support(windows_version, release_name, now)

        except Exception as e:
            logger.error(f"Error analyzing Windows version {version}: {e}")

        return os_info

    def _get_windows_release(self, build_number: str) -> str:
        """Get Windows release name from build number."""
        build_map = {
            "19044": "21H2",
            "19045": "22H2",
            "22000": "21H2",
            "22621": "22H2",
            "22631": "23H2",
            "26100": "24H2",
            "25398": "Canary"
        }
        return build_map.get(build_number, build_number)

    def _guess_windows_support(self, version: str, release: str, now: datetime) -> bool:
        """Guess if Windows version is still supported."""
        # Very simplified logic - production would use proper lifecycle data
        if version == "11":
            return True  # Assume Windows 11 is supported
        elif version == "10":
            # Windows 10 22H2 supported until Oct 2025
            if release == "22H2":
                return now.year < 2025 or (now.year == 2025 and now.month <= 10)
            else:
                return False  # Older releases likely unsupported
        else:
            return False  # Windows 8.1 and older unsupported

    def _analyze_macos_version(self, os_info: OSVersionInfo, version: str, build: str, now: datetime) -> OSVersionInfo:
        """Analyze macOS version."""
        try:
            # Parse version like "13.6.1" or "14.1"
            parts = version.split('.')
            major_version = parts[0] if len(parts) > 0 else ""

            # Get macOS release name
            release_name = self._get_macos_release(major_version)
            os_info.release_name = release_name

            # Check support matrix
            support_info = self.os_support_matrix.get("macos", {}).get(major_version, {})

            if support_info:
                eos_str = support_info.get("eos")
                if eos_str:
                    try:
                        os_info.end_of_support = datetime.strptime(eos_str, "%Y-%m-%d")
                        os_info.is_supported = now <= os_info.end_of_support
                    except ValueError:
                        os_info.is_supported = support_info.get("supported", True)
                else:
                    os_info.is_supported = support_info.get("supported", True)
            else:
                # Guess based on version
                try:
                    major = int(major_version)
                    # Assume macOS versions from last 3 years are supported
                    os_info.is_supported = major >= 13  # Ventura or newer
                except (ValueError, TypeError):
                    os_info.is_supported = True  # Unknown, assume supported

        except Exception as e:
            logger.error(f"Error analyzing macOS version {version}: {e}")

        return os_info

    def _get_macos_release(self, major_version: str) -> str:
        """Get macOS release name from version."""
        release_map = {
            "15": "Sequoia",
            "14": "Sonoma",
            "13": "Ventura",
            "12": "Monterey",
            "11": "Big Sur",
            "10": "Catalina"
        }
        return release_map.get(major_version, f"macOS {major_version}")

    def _analyze_ios_version(self, os_info: OSVersionInfo, version: str, now: datetime) -> OSVersionInfo:
        """Analyze iOS version."""
        try:
            parts = version.split('.')
            major_version = parts[0] if len(parts) > 0 else ""

            os_info.release_name = f"iOS {major_version}"

            # Check support matrix
            support_info = self.os_support_matrix.get("ios", {}).get(major_version, {})

            if support_info:
                eos_str = support_info.get("eos")
                if eos_str:
                    try:
                        os_info.end_of_support = datetime.strptime(eos_str, "%Y-%m-%d")
                        os_info.is_supported = now <= os_info.end_of_support
                    except ValueError:
                        os_info.is_supported = support_info.get("supported", True)
                else:
                    os_info.is_supported = support_info.get("supported", True)
            else:
                # Guess based on version
                try:
                    major = int(major_version)
                    # Assume iOS versions from last 2 years are supported
                    os_info.is_supported = major >= 16  # iOS 16 or newer
                except (ValueError, TypeError):
                    os_info.is_supported = True

        except Exception as e:
            logger.error(f"Error analyzing iOS version {version}: {e}")

        return os_info

    def _analyze_android_version(self, os_info: OSVersionInfo, version: str, now: datetime) -> OSVersionInfo:
        """Analyze Android version."""
        try:
            parts = version.split('.')
            major_version = parts[0] if len(parts) > 0 else ""

            os_info.release_name = f"Android {major_version}"

            # Check support matrix
            support_info = self.os_support_matrix.get("android", {}).get(major_version, {})

            if support_info:
                eos_str = support_info.get("eos")
                if eos_str:
                    try:
                        os_info.end_of_support = datetime.strptime(eos_str, "%Y-%m-%d")
                        os_info.is_supported = now <= os_info.end_of_support
                    except ValueError:
                        os_info.is_supported = support_info.get("supported", True)
                else:
                    os_info.is_supported = support_info.get("supported", True)
            else:
                # Guess based on version
                try:
                    major = int(major_version)
                    # Assume Android versions from last 3 years are supported
                    os_info.is_supported = major >= 12  # Android 12 or newer
                except (ValueError, TypeError):
                    os_info.is_supported = True

        except Exception as e:
            logger.error(f"Error analyzing Android version {version}: {e}")

        return os_info

    def _parse_linux_distro(self, version: str) -> str:
        """Parse Linux distribution from version string."""
        version_lower = version.lower()

        if "ubuntu" in version_lower:
            return "Ubuntu"
        elif "debian" in version_lower:
            return "Debian"
        elif "centos" in version_lower:
            return "CentOS"
        elif "redhat" in version_lower or "rhel" in version_lower:
            return "Red Hat"
        elif "fedora" in version_lower:
            return "Fedora"
        elif "suse" in version_lower or "opensuse" in version_lower:
            return "SUSE"
        else:
            return "Linux"

    def check_patch_status(self, device_info: Dict[str, Any]) -> DevicePatchStatus:
        """
        Check patch status for a device.

        Args:
            device_info: Device information dictionary

        Returns:
            DevicePatchStatus object
        """
        import random

        device_id = device_info.get("device_id", "")
        device_name = device_info.get("device_name", "Unknown")
        os_name = device_info.get("operating_system", "").lower()
        os_version = device_info.get("os_version", "")
        build_number = device_info.get("build_number", "")

        # Analyze OS version
        os_info = self.analyze_os_version(os_name, os_version, build_number)

        # Check for known critical patches
        critical_patches = self.critical_patches.get(os_info.os_name, [])

        # Simulate patch checking (in production, this would query device management APIs)
        patch_status, vulnerability_level = self._simulate_patch_check(os_info, critical_patches)

        # Calculate days since last patch
        days_since_last_patch = self._calculate_days_since_last_patch(device_info)

        # Generate patch lists
        installed_patches, missing_patches, available_updates = self._generate_patch_lists(
            os_info, critical_patches
        )

        # Calculate compliance score
        compliance_score = self._calculate_patch_compliance_score(
            patch_status,
            vulnerability_level,
            days_since_last_patch,
            len(missing_patches)
        )

        return DevicePatchStatus(
            device_id=device_id,
            device_name=device_name,
            os_info=os_info,
            patch_status=patch_status,
            vulnerability_level=vulnerability_level,
            days_since_last_patch=days_since_last_patch,
            missing_security_patches=sum(1 for p in missing_patches if p.is_security),
            missing_feature_updates=sum(1 for p in missing_patches if not p.is_security),
            pending_reboot=self._check_pending_reboot(device_info),
            last_patch_scan=datetime.utcnow(),
            patch_compliance_score=compliance_score,
            installed_patches=installed_patches,
            missing_patches=missing_patches,
            available_updates=available_updates
        )

    def _simulate_patch_check(self, os_info: OSVersionInfo, critical_patches: List[Dict[str, Any]]) -> Tuple[PatchStatus, VulnerabilityLevel]:
        """Simulate patch status check (for demonstration)."""
        import random

        # In production, this would query actual patch status from device management

        # Simple simulation logic
        if not os_info.is_supported:
            return PatchStatus.UNSUPPORTED, VulnerabilityLevel.CRITICAL

        # Randomly assign status for demo purposes
        rand = random.random()

        if rand < 0.6:  # 60% up to date
            return PatchStatus.UP_TO_DATE, VulnerabilityLevel.NONE
        elif rand < 0.8:  # 20% security updates available
            return PatchStatus.SECURITY_UPDATES_AVAILABLE, VulnerabilityLevel.HIGH
        elif rand < 0.9:  # 10% feature updates available
            return PatchStatus.FEATURE_UPDATES_AVAILABLE, VulnerabilityLevel.MEDIUM
        else:  # 10% outdated
            return PatchStatus.OUTDATED, VulnerabilityLevel.CRITICAL

    def _calculate_days_since_last_patch(self, device_info: Dict[str, Any]) -> int:
        """Calculate days since last patch was installed."""
        import random

        # In production, this would come from device management data
        # For demo, simulate based on device info
        # Simulate last patch date between 0 and 90 days ago
        days_ago = random.randint(0, 90)
        return days_ago

    def _generate_patch_lists(self, os_info: OSVersionInfo, critical_patches: List[Dict[str, Any]]) -> Tuple[List[PatchInfo], List[PatchInfo], List[PatchInfo]]:
        """Generate simulated patch lists."""
        import random

        now = datetime.utcnow()
        installed_patches = []
        missing_patches = []
        available_updates = []

        # Generate some installed patches
        for i in range(random.randint(5, 20)):
            patch_date = now - timedelta(days=random.randint(1, 180))
            install_date = patch_date + timedelta(days=random.randint(0, 30))

            patch = PatchInfo(
                patch_id=f"PATCH-{os_info.os_name.upper()}-{i+1:03d}",
                name=f"{os_info.os_name.title()} Update {i+1}",
                description="Security and reliability improvements",
                release_date=patch_date,
                install_date=install_date,
                is_installed=True,
                is_security=random.random() > 0.3,
                kb_number=f"KB{5000000 + i}" if os_info.os_name == "windows" else "",
                severity=random.choice(list(VulnerabilityLevel)[:4]),  # Exclude NONE
                superseded=random.random() > 0.8,
                requires_reboot=random.random() > 0.5
            )
            installed_patches.append(patch)

        # Generate some missing patches (critical ones)
        for crit_patch in critical_patches[:random.randint(0, 3)]:  # 0-3 critical patches missing
            patch_date = now - timedelta(days=random.randint(1, 90))

            severity_map = {
                "critical": VulnerabilityLevel.CRITICAL,
                "high": VulnerabilityLevel.HIGH,
                "medium": VulnerabilityLevel.MEDIUM,
                "low": VulnerabilityLevel.LOW
            }

            patch = PatchInfo(
                patch_id=f"CRIT-{os_info.os_name.upper()}-{crit_patch.get('kb', crit_patch.get('name', 'UNKNOWN')).replace(' ', '-')}",
                name=crit_patch.get("name", "Critical Update"),
                description="Critical security update",
                release_date=patch_date,
                install_date=None,
                is_installed=False,
                is_security=True,
                kb_number=crit_patch.get("kb", ""),
                severity=severity_map.get(crit_patch.get("severity", "high"), VulnerabilityLevel.HIGH),
                superseded=False,
                requires_reboot=crit_patch.get("requires_reboot", True)
            )
            missing_patches.append(patch)

        # Generate available updates
        for i in range(random.randint(0, 5)):
            patch_date = now - timedelta(days=random.randint(1, 60))

            patch = PatchInfo(
                patch_id=f"UPDATE-{os_info.os_name.upper()}-{i+1:03d}",
                name=f"{os_info.os_name.title()} Cumulative Update {i+1}",
                description="Latest quality improvements",
                release_date=patch_date,
                install_date=None,
                is_installed=False,
                is_security=random.random() > 0.5,
                kb_number=f"KB{6000000 + i}" if os_info.os_name == "windows" else "",
                severity=random.choice([VulnerabilityLevel.LOW, VulnerabilityLevel.MEDIUM]),
                superseded=False,
                requires_reboot=random.random() > 0.3
            )
            available_updates.append(patch)

        return installed_patches, missing_patches, available_updates

    def _check_pending_reboot(self, device_info: Dict[str, Any]) -> bool:
        """Check if device has pending reboot."""
        import random

        # In production, this would query device management API
        return random.random() > 0.7  # 30% chance of pending reboot

    def _calculate_patch_compliance_score(self, patch_status: PatchStatus,
                                         vulnerability_level: VulnerabilityLevel,
                                         days_since_last_patch: int,
                                         missing_patches_count: int) -> float:
        """Calculate patch compliance score (0-100)."""
        score = 100.0

        # Deduct based on patch status
        status_deductions = {
            PatchStatus.UP_TO_DATE: 0,
            PatchStatus.SECURITY_UPDATES_AVAILABLE: 20,
            PatchStatus.FEATURE_UPDATES_AVAILABLE: 10,
            PatchStatus.OUTDATED: 40,
            PatchStatus.UNSUPPORTED: 60,
            PatchStatus.UNKNOWN: 30
        }
        score -= status_deductions.get(patch_status, 0)

        # Deduct based on vulnerability level
        vuln_deductions = {
            VulnerabilityLevel.CRITICAL: 30,
            VulnerabilityLevel.HIGH: 20,
            VulnerabilityLevel.MEDIUM: 10,
            VulnerabilityLevel.LOW: 5,
            VulnerabilityLevel.NONE: 0
        }
        score -= vuln_deductions.get(vulnerability_level, 0)

        # Deduct for days since last patch
        if days_since_last_patch > 30:
            score -= 15
        elif days_since_last_patch > 14:
            score -= 10
        elif days_since_last_patch > 7:
            score -= 5

        # Deduct for missing patches
        score -= min(missing_patches_count * 5, 30)  # Max 30 point deduction

        return max(0.0, min(100.0, score))

    async def batch_check_patch_status(self, devices_info: List[Dict[str, Any]]) -> List[DevicePatchStatus]:
        """
        Check patch status for multiple devices.

        Args:
            devices_info: List of device information dictionaries

        Returns:
            List of DevicePatchStatus objects
        """
        print(f"   Checking OS patch status for {len(devices_info)} devices...")

        results = []
        total = len(devices_info)

        for i, device_info in enumerate(devices_info, 1):
            try:
                # Check patch status
                patch_status = self.check_patch_status(device_info)
                results.append(patch_status)

                # Show progress
                if i % 10 == 0 or i == total:
                    print(f"   Processed {i}/{total} devices")

            except Exception as e:
                logger.error(f"Failed to check patch status for {device_info.get('device_name', 'unknown')}: {e}")
                # Create error status
                error_status = DevicePatchStatus(
                    device_id=device_info.get("device_id", ""),
                    device_name=device_info.get("device_name", "Unknown"),
                    os_info=self.analyze_os_version(
                        device_info.get("operating_system", ""),
                        device_info.get("os_version", "")
                    ),
                    patch_status=PatchStatus.UNKNOWN,
                    vulnerability_level=VulnerabilityLevel.NONE,
                    days_since_last_patch=999,
                    missing_security_patches=0,
                    missing_feature_updates=0,
                    pending_reboot=False,
                    last_patch_scan=datetime.utcnow(),
                    patch_compliance_score=0.0
                )
                results.append(error_status)

        print(f"   Patch status check complete. {len(results)} devices analyzed.")

        return results

    def generate_statistics(self, patch_statuses: List[DevicePatchStatus]) -> Dict[str, Any]:
        """Generate statistics from patch status results."""
        if not patch_statuses:
            return {}

        total = len(patch_statuses)

        # Patch status distribution
        status_counts = {
            "up_to_date": 0,
            "security_updates_available": 0,
            "feature_updates_available": 0,
            "outdated": 0,
            "unsupported": 0,
            "unknown": 0
        }

        # Vulnerability level distribution
        vuln_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "none": 0
        }

        # OS distribution
        os_distribution = {}

        # Compliance scores
        compliance_scores = []

        # Counters
        total_missing_security = 0
        total_missing_feature = 0
        devices_pending_reboot = 0
        unsupported_devices = 0

        for status in patch_statuses:
            # Count status
            status_counts[status.patch_status.value] += 1

            # Count vulnerability level
            vuln_counts[status.vulnerability_level.value] += 1

            # Count OS
            os_name = status.os_info.os_name
            os_distribution[os_name] = os_distribution.get(os_name, 0) + 1

            # Add compliance score
            compliance_scores.append(status.patch_compliance_score)

            # Sum missing patches
            total_missing_security += status.missing_security_patches
            total_missing_feature += status.missing_feature_updates

            # Count pending reboot
            if status.pending_reboot:
                devices_pending_reboot += 1

            # Count unsupported
            if not status.os_info.is_supported:
                unsupported_devices += 1

        # Calculate averages
        avg_compliance_score = sum(compliance_scores) / len(compliance_scores) if compliance_scores else 0
        avg_days_since_patch = sum(s.days_since_last_patch for s in patch_statuses) / total if total > 0 else 0

        # Find devices needing attention
        devices_needing_attention = []
        for status in patch_statuses:
            needs_attention = (
                status.patch_status in [PatchStatus.OUTDATED, PatchStatus.UNSUPPORTED] or
                status.vulnerability_level in [VulnerabilityLevel.CRITICAL, VulnerabilityLevel.HIGH] or
                status.days_since_last_patch > 30 or
                status.missing_security_patches > 0
            )
            if needs_attention:
                devices_needing_attention.append({
                    "device_name": status.device_name,
                    "os": status.os_info.os_name,
                    "version": status.os_info.version,
                    "issues": self._get_device_issues(status)
                })

        return {
            "total_devices": total,
            "status_distribution": status_counts,
            "vulnerability_distribution": vuln_counts,
            "os_distribution": os_distribution,
            "compliance_scores": {
                "average": avg_compliance_score,
                "min": min(compliance_scores) if compliance_scores else 0,
                "max": max(compliance_scores) if compliance_scores else 0,
                "distribution": self._calculate_score_distribution(compliance_scores)
            },
            "patch_metrics": {
                "total_missing_security_patches": total_missing_security,
                "total_missing_feature_updates": total_missing_feature,
                "average_missing_security_per_device": total_missing_security / total if total > 0 else 0,
                "average_days_since_last_patch": avg_days_since_patch,
                "devices_pending_reboot": devices_pending_reboot,
                "unsupported_devices": unsupported_devices
            },
            "devices_needing_attention": {
                "count": len(devices_needing_attention),
                "devices": devices_needing_attention[:10]  # Top 10 only
            },
            "summary": {
                "patch_compliance_rate": (status_counts["up_to_date"] / total * 100) if total > 0 else 0,
                "security_compliance_rate": ((total - status_counts["security_updates_available"] - status_counts["outdated"]) / total * 100) if total > 0 else 0,
                "overall_health": self._calculate_overall_health(avg_compliance_score, vuln_counts, total)
            }
        }

    def _get_device_issues(self, status: DevicePatchStatus) -> List[str]:
        """Get list of issues for a device."""
        issues = []

        if status.patch_status == PatchStatus.UNSUPPORTED:
            issues.append("OS unsupported")
        elif status.patch_status == PatchStatus.OUTDATED:
            issues.append("OS outdated")

        if status.vulnerability_level == VulnerabilityLevel.CRITICAL:
            issues.append("Critical vulnerabilities")
        elif status.vulnerability_level == VulnerabilityLevel.HIGH:
            issues.append("High vulnerabilities")

        if status.days_since_last_patch > 30:
            issues.append("No patches in 30+ days")

        if status.missing_security_patches > 0:
            issues.append(f"{status.missing_security_patches} missing security patches")

        if status.pending_reboot:
            issues.append("Pending reboot")

        if not status.os_info.is_supported:
            issues.append("Unsupported OS version")

        return issues

    def _calculate_score_distribution(self, scores: List[float]) -> Dict[str, int]:
        """Calculate score distribution in ranges."""
        distribution = {
            "excellent_90_100": 0,
            "good_80_89": 0,
            "fair_70_79": 0,
            "poor_60_69": 0,
            "critical_below_60": 0
        }

        for score in scores:
            if score >= 90:
                distribution["excellent_90_100"] += 1
            elif score >= 80:
                distribution["good_80_89"] += 1
            elif score >= 70:
                distribution["fair_70_79"] += 1
            elif score >= 60:
                distribution["poor_60_69"] += 1
            else:
                distribution["critical_below_60"] += 1

        return distribution

    def _calculate_overall_health(self, avg_score: float, vuln_counts: Dict[str, int], total: int) -> str:
        """Calculate overall health status."""
        critical_percentage = (vuln_counts["critical"] / total * 100) if total > 0 else 0

        if avg_score >= 90 and critical_percentage == 0:
            return "Excellent"
        elif avg_score >= 80 and critical_percentage < 5:
            return "Good"
        elif avg_score >= 70 and critical_percentage < 10:
            return "Fair"
        elif avg_score >= 60:
            return "Poor"
        else:
            return "Critical"

    def export_to_dataframe(self, patch_statuses: List[DevicePatchStatus]) -> tuple:
        """
        Export patch status data to DataFrames.

        Returns:
            Tuple of (summary_df, detailed_df, support_df)
        """
        import pandas as pd

        # Summary DataFrame
        summary_dicts = [s.to_dict() for s in patch_statuses]
        summary_df = pd.DataFrame(summary_dicts) if summary_dicts else pd.DataFrame()

        # Detailed patches DataFrame
        detailed_rows = []
        for status in patch_statuses:
            for patch in status.installed_patches + status.missing_patches + status.available_updates:
                row = {
                    "device_id": status.device_id,
                    "device_name": status.device_name,
                    "os_name": status.os_info.os_name,
                    "os_version": status.os_info.version,
                    **patch.to_dict()
                }
                detailed_rows.append(row)

        detailed_df = pd.DataFrame(detailed_rows) if detailed_rows else pd.DataFrame()

        # OS support matrix DataFrame
        support_rows = []
        for os_name, versions in self.os_support_matrix.items():
            for version, releases in versions.items():
                if isinstance(releases, dict):
                    if "eos" in releases:
                        # This is a single release info (like macos)
                        support_rows.append({
                            "os_name": os_name,
                            "version": version,
                            "release": releases.get("name", version),
                            "end_of_support": releases.get("eos", ""),
                            "supported": releases.get("supported", False)
                        })
                    else:
                        # This is a dict of releases (like windows)
                        for release, info in releases.items():
                            if isinstance(info, dict):
                                support_rows.append({
                                    "os_name": os_name,
                                    "version": version,
                                    "release": release,
                                    "end_of_support": info.get("eos", ""),
                                    "supported": info.get("supported", False)
                                })

        support_df = pd.DataFrame(support_rows) if support_rows else pd.DataFrame()

        return summary_df, detailed_df, support_df

    def generate_report_text(self, stats: Dict[str, Any]) -> str:
        """Generate human-readable patch status report."""
        lines = []

        lines.append("=" * 60)
        lines.append("   OS VERSION & PATCH STATUS REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")

        # Overall summary
        summary = stats.get("summary", {})
        lines.append("OVERALL SUMMARY")
        lines.append("-" * 40)
        lines.append(f"Total Devices: {stats.get('total_devices', 0)}")
        lines.append(f"Patch Compliance Rate: {summary.get('patch_compliance_rate', 0):.1f}%")
        lines.append(f"Security Compliance Rate: {summary.get('security_compliance_rate', 0):.1f}%")
        lines.append(f"Overall Health: {summary.get('overall_health', 'Unknown')}")
        lines.append("")

        # Patch status breakdown
        status_dist = stats.get("status_distribution", {})
        lines.append("PATCH STATUS BREAKDOWN")
        lines.append("-" * 40)
        for status, count in status_dist.items():
            percentage = (count / stats['total_devices'] * 100) if stats['total_devices'] > 0 else 0
            status_display = status.replace('_', ' ').title()
            lines.append(f"{status_display}: {count} devices ({percentage:.1f}%)")
        lines.append("")

        # Vulnerability breakdown
        vuln_dist = stats.get("vulnerability_distribution", {})
        lines.append("VULNERABILITY LEVELS")
        lines.append("-" * 40)
        for level, count in vuln_dist.items():
            percentage = (count / stats['total_devices'] * 100) if stats['total_devices'] > 0 else 0
            level_display = level.title()
            lines.append(f"{level_display}: {count} devices ({percentage:.1f}%)")
        lines.append("")

        # Patch metrics
        patch_metrics = stats.get("patch_metrics", {})
        lines.append("PATCH METRICS")
        lines.append("-" * 40)
        lines.append(f"Total Missing Security Patches: {patch_metrics.get('total_missing_security_patches', 0)}")
        lines.append(f"Average Missing per Device: {patch_metrics.get('average_missing_security_per_device', 0):.1f}")
        lines.append(f"Devices Pending Reboot: {patch_metrics.get('devices_pending_reboot', 0)}")
        lines.append(f"Unsupported OS Versions: {patch_metrics.get('unsupported_devices', 0)}")
        lines.append(f"Average Days Since Last Patch: {patch_metrics.get('average_days_since_last_patch', 0):.1f}")
        lines.append("")

        # Devices needing attention
        attention = stats.get("devices_needing_attention", {})
        if attention.get("count", 0) > 0:
            lines.append(f"DEVICES NEEDING ATTENTION ({attention['count']} devices)")
            lines.append("-" * 40)

            for i, device in enumerate(attention.get("devices", [])[:5], 1):  # Show top 5
                lines.append(f"{i}. {device['device_name']}")
                lines.append(f"   OS: {device['os']} {device['version']}")
                lines.append(f"   Issues: {', '.join(device['issues'])}")
                lines.append("")

            if attention['count'] > 5:
                lines.append(f"... and {attention['count'] - 5} more devices")
                lines.append("")

        # Recommendations
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 40)

        if patch_metrics.get("unsupported_devices", 0) > 0:
            lines.append("1. Upgrade or replace devices with unsupported OS versions")

        if vuln_dist.get("critical", 0) > 0 or vuln_dist.get("high", 0) > 0:
            lines.append("2. Prioritize patching devices with critical/high vulnerabilities")

        if patch_metrics.get("devices_pending_reboot", 0) > 0:
            lines.append("3. Schedule reboots for devices with pending updates")

        if patch_metrics.get("average_days_since_last_patch", 0) > 30:
            lines.append("4. Review patch deployment schedules")

        if summary.get("patch_compliance_rate", 0) < 80:
            lines.append("5. Implement automated patch management")

        lines.append("6. Regular review of OS patch status reports")

        return "\n".join(lines)

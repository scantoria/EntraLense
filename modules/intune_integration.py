"""Microsoft Intune integration for device management."""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import pandas as pd

logger = logging.getLogger(__name__)


@dataclass
class IntuneDevice:
    """Intune device data structure."""
    device_id: str
    device_name: str
    operating_system: str
    os_version: str
    manufacturer: str
    model: str
    serial_number: str
    azure_ad_device_id: str
    azure_ad_registered: bool
    compliance_state: str
    management_agent: str
    last_sync_date_time: Optional[datetime]
    user_principal_name: str
    device_enrollment_type: str
    is_encrypted: Optional[bool] = None
    encryption_method: Optional[str] = None
    encryption_status_details: Optional[str] = None
    compliance_policies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert device to dictionary."""
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "operating_system": self.operating_system,
            "os_version": self.os_version,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "serial_number": self.serial_number,
            "azure_ad_device_id": self.azure_ad_device_id,
            "azure_ad_registered": self.azure_ad_registered,
            "compliance_state": self.compliance_state,
            "management_agent": self.management_agent,
            "last_sync_date_time": self.last_sync_date_time.isoformat() if self.last_sync_date_time else "",
            "user_principal_name": self.user_principal_name,
            "device_enrollment_type": self.device_enrollment_type,
            "is_encrypted": self.is_encrypted,
            "encryption_method": self.encryption_method,
            "encryption_status_details": self.encryption_status_details,
            "compliance_policies": ", ".join(self.compliance_policies) if self.compliance_policies else ""
        }


class IntuneIntegration:
    """Microsoft Intune integration handler."""

    def __init__(self, auth, config):
        """
        Initialize Intune integration.

        Args:
            auth: Authenticated EntraAuth instance
            config: Application configuration
        """
        self.auth = auth
        self.config = config

    async def get_managed_devices(self, device_types: List[str] = None, batch_size: int = 100) -> List[IntuneDevice]:
        """
        Fetch managed devices from Intune.

        Args:
            device_types: Filter by device types
            batch_size: Number of devices per batch

        Returns:
            List of IntuneDevice objects
        """
        print("   Fetching managed devices from Microsoft Intune...")

        devices = []
        try:
            client = await self.auth.get_graph_client()

            # Build filter expression for device types
            filter_expr = None
            if device_types:
                os_filters = []
                for device_type in device_types:
                    if device_type.lower() == "windows":
                        os_filters.append("operatingSystem eq 'Windows'")
                    elif device_type.lower() == "macos":
                        os_filters.append("operatingSystem eq 'macOS'")
                    elif device_type.lower() == "ios":
                        os_filters.append("operatingSystem eq 'iOS'")
                    elif device_type.lower() == "android":
                        os_filters.append("operatingSystem eq 'Android'")
                    elif device_type.lower() == "linux":
                        os_filters.append("operatingSystem eq 'Linux'")

                if os_filters:
                    filter_expr = " or ".join(os_filters)

            # Fetch devices using Graph API
            from msgraph.generated.device_management.managed_devices.managed_devices_request_builder import ManagedDevicesRequestBuilder

            query_params = ManagedDevicesRequestBuilder.ManagedDevicesRequestBuilderGetQueryParameters(
                select=["id", "deviceName", "operatingSystem", "osVersion",
                        "manufacturer", "model", "serialNumber", "azureADRegistered",
                        "azureADDeviceId", "complianceState", "managementAgent",
                        "lastSyncDateTime", "userPrincipalName", "deviceEnrollmentType",
                        "isEncrypted"],
                top=batch_size,
                filter=filter_expr
            )

            request_config = ManagedDevicesRequestBuilder.ManagedDevicesRequestBuilderGetRequestConfiguration(
                query_parameters=query_params
            )

            batch_number = 0
            total_devices = 0

            response = await client.device_management.managed_devices.get(request_configuration=request_config)

            while response:
                batch_number += 1

                if response.value:
                    for device_data in response.value:
                        device = self._parse_device_data(device_data)
                        if device:
                            devices.append(device)
                            total_devices += 1

                    print(f"   Batch {batch_number}: Retrieved {total_devices} devices so far...")

                # Check for more pages
                if hasattr(response, 'odata_next_link') and response.odata_next_link:
                    response = await client.device_management.managed_devices.with_url(
                        response.odata_next_link
                    ).get()
                else:
                    break

            print(f"   Successfully fetched {len(devices)} managed devices")

        except Exception as e:
            print(f"   Error fetching Intune devices: {e}")
            logger.exception("Intune device fetch failed")

        return devices

    def _parse_device_data(self, device_data) -> Optional[IntuneDevice]:
        """Parse Graph API device data into IntuneDevice object."""
        try:
            # Parse last sync datetime
            last_sync = None
            if hasattr(device_data, 'last_sync_date_time') and device_data.last_sync_date_time:
                last_sync = device_data.last_sync_date_time

            # Get compliance state as string
            compliance_state = "unknown"
            if hasattr(device_data, 'compliance_state') and device_data.compliance_state:
                compliance_state = str(device_data.compliance_state.value) if hasattr(device_data.compliance_state, 'value') else str(device_data.compliance_state)

            # Get management agent as string
            management_agent = "unknown"
            if hasattr(device_data, 'management_agent') and device_data.management_agent:
                management_agent = str(device_data.management_agent.value) if hasattr(device_data.management_agent, 'value') else str(device_data.management_agent)

            # Get enrollment type as string
            enrollment_type = "unknown"
            if hasattr(device_data, 'device_enrollment_type') and device_data.device_enrollment_type:
                enrollment_type = str(device_data.device_enrollment_type.value) if hasattr(device_data.device_enrollment_type, 'value') else str(device_data.device_enrollment_type)

            device = IntuneDevice(
                device_id=getattr(device_data, 'id', '') or '',
                device_name=getattr(device_data, 'device_name', 'Unknown') or 'Unknown',
                operating_system=getattr(device_data, 'operating_system', 'Unknown') or 'Unknown',
                os_version=getattr(device_data, 'os_version', '') or '',
                manufacturer=getattr(device_data, 'manufacturer', 'Unknown') or 'Unknown',
                model=getattr(device_data, 'model', 'Unknown') or 'Unknown',
                serial_number=getattr(device_data, 'serial_number', '') or '',
                azure_ad_device_id=getattr(device_data, 'azure_ad_device_id', '') or '',
                azure_ad_registered=getattr(device_data, 'azure_a_d_registered', False) or False,
                compliance_state=compliance_state,
                management_agent=management_agent,
                last_sync_date_time=last_sync,
                user_principal_name=getattr(device_data, 'user_principal_name', '') or '',
                device_enrollment_type=enrollment_type,
                is_encrypted=getattr(device_data, 'is_encrypted', None)
            )

            return device

        except Exception as e:
            logger.error(f"Error parsing device data: {e}")
            return None

    async def get_device_compliance_policies(self, device_id: str) -> Tuple[List[str], Optional[str]]:
        """
        Get compliance policies applied to a device.

        Args:
            device_id: Device ID

        Returns:
            Tuple of (list of compliance policy names, error code if any)
        """
        try:
            client = await self.auth.get_graph_client()

            response = await client.device_management.managed_devices.by_managed_device_id(
                device_id
            ).device_compliance_policy_states.get()

            policies = []
            if response and response.value:
                for policy_state in response.value:
                    if hasattr(policy_state, 'display_name') and policy_state.display_name:
                        policies.append(policy_state.display_name)

            return policies, None

        except Exception as e:
            # Extract error code for cleaner handling
            error_code = None
            if hasattr(e, 'error') and hasattr(e.error, 'code'):
                error_code = e.error.code
            elif 'Code:' in str(e):
                # Try to extract from string representation
                import re
                match = re.search(r'Code:\s*(\d+)', str(e))
                if match:
                    error_code = match.group(1)

            logger.debug(f"Error fetching compliance policies for device {device_id}: {error_code or 'Unknown'}")
            return [], error_code

    async def enrich_devices_with_compliance(self, devices: List[IntuneDevice]) -> None:
        """
        Enrich devices with compliance policy information.

        Args:
            devices: List of IntuneDevice objects
        """
        print("   Enriching devices with compliance policy data...")

        total = len(devices)
        error_counts = {}  # Track errors by type

        for i, device in enumerate(devices, 1):
            try:
                policies, error_code = await self.get_device_compliance_policies(device.device_id)
                device.compliance_policies = policies

                if error_code:
                    error_counts[error_code] = error_counts.get(error_code, 0) + 1

                # Show progress
                if i % 50 == 0 or i == total:
                    print(f"   Processed {i}/{total} devices")

            except Exception as e:
                logger.debug(f"Error enriching device {device.device_name}: {e}")
                error_counts["Unknown"] = error_counts.get("Unknown", 0) + 1

        # Show error summary if any errors occurred
        if error_counts:
            print("   Device enrichment complete (with some limitations):")
            for error_code, count in error_counts.items():
                if error_code == "Forbidden" or error_code == "403":
                    print(f"      - {count} devices: Missing DeviceManagementConfiguration.Read.All permission")
                else:
                    print(f"      - {count} devices: {error_code} error")
            print("      Note: Report will continue using available compliance data.")
        else:
            print("   Device enrichment complete")

    async def check_encryption_status(self, devices: List[IntuneDevice]) -> None:
        """
        Check encryption status for devices based on compliance and OS.

        Args:
            devices: List of IntuneDevice objects
        """
        print("   Checking device encryption status...")

        for device in devices:
            try:
                # If is_encrypted is already set from API, use it
                if device.is_encrypted is not None:
                    if device.is_encrypted:
                        device.encryption_method = self._get_encryption_method(device.operating_system)
                        device.encryption_status_details = "Encrypted (reported by device)"
                    else:
                        device.encryption_method = "None"
                        device.encryption_status_details = "Not encrypted (reported by device)"
                    continue

                # Otherwise, infer from compliance state
                if device.operating_system.lower() == "windows":
                    is_encrypted, method, details = self._check_windows_encryption(device)
                elif device.operating_system.lower() == "macos":
                    is_encrypted, method, details = self._check_macos_encryption(device)
                elif device.operating_system.lower() in ["ios", "android"]:
                    # Mobile devices are typically encrypted by default
                    is_encrypted = True
                    method = "Device Encryption"
                    details = "Mobile device (encrypted by default)"
                else:
                    is_encrypted = None
                    method = "Unknown"
                    details = "Encryption check not available for this OS"

                device.is_encrypted = is_encrypted
                device.encryption_method = method
                device.encryption_status_details = details

            except Exception as e:
                logger.error(f"Error checking encryption for {device.device_name}: {e}")
                device.is_encrypted = None
                device.encryption_method = "Error"
                device.encryption_status_details = f"Error: {str(e)}"

    def _get_encryption_method(self, os: str) -> str:
        """Get expected encryption method for OS."""
        os_lower = os.lower()
        if os_lower == "windows":
            return "BitLocker"
        elif os_lower == "macos":
            return "FileVault"
        elif os_lower == "ios":
            return "iOS Data Protection"
        elif os_lower == "android":
            return "Android Encryption"
        elif os_lower == "linux":
            return "LUKS/dm-crypt"
        return "Unknown"

    def _check_windows_encryption(self, device: IntuneDevice) -> Tuple[Optional[bool], str, str]:
        """Check Windows device encryption status based on compliance."""
        # Check if BitLocker is required by compliance policies
        requires_bitlocker = any(
            "bitlocker" in policy.lower() or "encryption" in policy.lower()
            for policy in device.compliance_policies
        )

        if requires_bitlocker:
            if "compliant" in device.compliance_state.lower():
                return True, "BitLocker", "Compliant with encryption policy"
            else:
                return False, "BitLocker Required", "Non-compliant - encryption required"
        else:
            if "compliant" in device.compliance_state.lower():
                return True, "Likely BitLocker", "Compliant device (assumed encrypted)"
            else:
                return None, "Unknown", "No encryption policy applied"

    def _check_macos_encryption(self, device: IntuneDevice) -> Tuple[Optional[bool], str, str]:
        """Check macOS device encryption status based on compliance."""
        has_filevault_policy = any(
            "filevault" in policy.lower() or "encryption" in policy.lower()
            for policy in device.compliance_policies
        )

        if has_filevault_policy:
            if "compliant" in device.compliance_state.lower():
                return True, "FileVault", "Compliant with FileVault policy"
            else:
                return False, "FileVault Required", "Non-compliant - FileVault required"
        else:
            return None, "Unknown", "No FileVault policy detected"

    def export_to_dataframe(self, devices: List[IntuneDevice]) -> pd.DataFrame:
        """
        Export devices to pandas DataFrame.

        Returns:
            pandas.DataFrame with device data
        """
        if not devices:
            return pd.DataFrame()

        device_dicts = [device.to_dict() for device in devices]
        df = pd.DataFrame(device_dicts)

        # Rename columns for display
        column_renames = {
            "device_id": "Device ID",
            "device_name": "Device Name",
            "operating_system": "Operating System",
            "os_version": "OS Version",
            "manufacturer": "Manufacturer",
            "model": "Model",
            "serial_number": "Serial Number",
            "azure_ad_device_id": "Azure AD Device ID",
            "azure_ad_registered": "Azure AD Registered",
            "compliance_state": "Compliance State",
            "management_agent": "Management Agent",
            "last_sync_date_time": "Last Sync",
            "user_principal_name": "User Principal Name",
            "device_enrollment_type": "Enrollment Type",
            "is_encrypted": "Is Encrypted",
            "encryption_method": "Encryption Method",
            "encryption_status_details": "Encryption Details",
            "compliance_policies": "Compliance Policies"
        }

        df = df.rename(columns=column_renames)

        return df

    def generate_statistics(self, devices: List[IntuneDevice]) -> Dict[str, Any]:
        """Generate statistics from device list."""
        if not devices:
            return {}

        total = len(devices)

        # Encryption statistics
        encrypted = sum(1 for d in devices if d.is_encrypted is True)
        not_encrypted = sum(1 for d in devices if d.is_encrypted is False)
        unknown = sum(1 for d in devices if d.is_encrypted is None)

        # OS distribution
        os_distribution = {}
        for device in devices:
            os = device.operating_system
            os_distribution[os] = os_distribution.get(os, 0) + 1

        # Compliance status
        compliant = sum(1 for d in devices if "compliant" in d.compliance_state.lower() and "non" not in d.compliance_state.lower())
        non_compliant = total - compliant

        # Management agent distribution
        agent_distribution = {}
        for device in devices:
            agent = device.management_agent
            agent_distribution[agent] = agent_distribution.get(agent, 0) + 1

        return {
            "total_devices": total,
            "encryption": {
                "encrypted": encrypted,
                "not_encrypted": not_encrypted,
                "unknown": unknown,
                "encryption_rate": (encrypted / total * 100) if total > 0 else 0
            },
            "compliance": {
                "compliant": compliant,
                "non_compliant": non_compliant,
                "compliance_rate": (compliant / total * 100) if total > 0 else 0
            },
            "os_distribution": os_distribution,
            "agent_distribution": agent_distribution
        }

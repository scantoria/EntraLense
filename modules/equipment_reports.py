"""Equipment reports module for EntraLense."""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import pandas as pd

from modules.intune_integration import IntuneIntegration, IntuneDevice
from modules.compliance_checker import ComplianceChecker
from modules.os_patch_checker import OSPatchChecker, PatchStatus, VulnerabilityLevel

logger = logging.getLogger(__name__)


class EquipmentReports:
    """Equipment reports generation engine."""

    # Default device types to scan
    DEFAULT_DEVICE_TYPES = ["windows", "macOS", "ios", "android"]

    # Default compliance threshold
    DEFAULT_COMPLIANCE_THRESHOLD = 95.0

    def __init__(self, auth, export_dir: Path = None, compliance_threshold: float = None, config=None):
        """
        Initialize equipment reports.

        Args:
            auth: Authenticated EntraAuth instance
            export_dir: Directory for CSV exports
            compliance_threshold: Encryption compliance threshold percentage
            config: Application configuration (optional)
        """
        self.auth = auth
        self.config = config
        self.export_dir = export_dir or Path("./exports/equipment")
        self.compliance_threshold = compliance_threshold or self.DEFAULT_COMPLIANCE_THRESHOLD
        self.intune = IntuneIntegration(auth, None)

        # Ensure export directory exists
        self.export_dir.mkdir(parents=True, exist_ok=True)

        # Report statistics
        self.report_stats: Dict[str, Any] = {}

    async def generate_encryption_status_report(
        self,
        device_types: List[str] = None,
        export_to_csv: bool = True,
        include_raw_data: bool = False
    ) -> Dict[str, Any]:
        """
        Generate device encryption status report.

        Args:
            device_types: Filter by device types (default: all)
            export_to_csv: Whether to export to CSV
            include_raw_data: Whether to include raw device data

        Returns:
            Dictionary with report data
        """
        device_types = device_types or self.DEFAULT_DEVICE_TYPES

        print("\n" + "=" * 60)
        print("   DEVICE ENCRYPTION STATUS REPORT")
        print("=" * 60)

        # Step 1: Fetch devices from Intune
        print("\n[Step 1/3] Fetching devices from Microsoft Intune...")
        devices = await self.intune.get_managed_devices(device_types)

        if not devices:
            print("   No devices found in Intune")
            return {
                "dataframe": pd.DataFrame(),
                "statistics": {},
                "csv_path": None,
                "generated_at": datetime.utcnow(),
                "message": "No devices found",
                "raw_data": [] if include_raw_data else None
            }

        print(f"   Found {len(devices)} devices")

        # Step 2: Check encryption status
        print("\n[Step 2/3] Checking encryption status...")
        await self.intune.check_encryption_status(devices)

        # Step 3: Generate statistics and report
        print("\n[Step 3/3] Generating report...")

        # Calculate statistics
        stats = self.intune.generate_statistics(devices)
        self.report_stats = stats

        # Create DataFrame
        df = self.intune.export_to_dataframe(devices)

        # Export to CSV if requested
        csv_path = None
        if export_to_csv and not df.empty:
            csv_path = self._export_to_csv(df, "encryption_status")

        # Generate summary
        summary = self._generate_encryption_summary(stats)

        print("\n   Report generated successfully!")

        return {
            "dataframe": df,
            "devices": devices,
            "statistics": stats,
            "summary": summary,
            "csv_path": csv_path,
            "generated_at": datetime.utcnow(),
            "raw_data": [d.to_dict() for d in devices] if include_raw_data else None
        }

    def _generate_encryption_summary(self, stats: Dict[str, Any]) -> str:
        """Generate human-readable summary from statistics."""
        lines = []
        lines.append("=" * 60)
        lines.append("   DEVICE ENCRYPTION STATUS SUMMARY")
        lines.append("=" * 60)
        lines.append(f"\nGenerated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")

        lines.append("OVERALL STATUS")
        lines.append("-" * 40)

        encryption = stats.get("encryption", {})
        compliance = stats.get("compliance", {})

        lines.append(f"Total Devices: {stats.get('total_devices', 0)}")
        lines.append(f"Encrypted Devices: {encryption.get('encrypted', 0)}")
        lines.append(f"Not Encrypted: {encryption.get('not_encrypted', 0)}")
        lines.append(f"Unknown Status: {encryption.get('unknown', 0)}")
        lines.append(f"Encryption Rate: {encryption.get('encryption_rate', 0):.1f}%")
        lines.append(f"Compliance Rate: {compliance.get('compliance_rate', 0):.1f}%")
        lines.append("")

        # Check against compliance threshold
        current_rate = encryption.get('encryption_rate', 0)

        if current_rate >= self.compliance_threshold:
            lines.append(f"COMPLIANT: Encryption rate ({current_rate:.1f}%) meets threshold ({self.compliance_threshold}%)")
        else:
            lines.append(f"NON-COMPLIANT: Encryption rate ({current_rate:.1f}%) below threshold ({self.compliance_threshold}%)")
            lines.append(f"   Action required: Need {self.compliance_threshold - current_rate:.1f}% improvement")

        lines.append("")

        # OS Distribution
        lines.append("OPERATING SYSTEM DISTRIBUTION")
        lines.append("-" * 40)

        os_dist = stats.get("os_distribution", {})
        total = stats.get('total_devices', 1)
        for os_name, count in sorted(os_dist.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            lines.append(f"{os_name}: {count} devices ({percentage:.1f}%)")

        return "\n".join(lines)

    def _export_to_csv(self, df: pd.DataFrame, report_type: str) -> str:
        """
        Export DataFrame to CSV file.

        Args:
            df: DataFrame to export
            report_type: Type of report for filename

        Returns:
            Path to exported CSV file
        """
        try:
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{report_type}_{timestamp}.csv"
            filepath = self.export_dir / filename

            # Export to CSV with UTF-8 BOM for Excel compatibility
            df.to_csv(filepath, index=False, encoding='utf-8-sig')

            print(f"   Report exported to: {filepath}")

            return str(filepath)

        except Exception as e:
            print(f"   Error exporting to CSV: {e}")
            logger.exception("CSV export failed")
            return None

    async def generate_compliance_policy_report(
        self,
        device_types: List[str] = None,
        export_to_csv: bool = True,
        include_raw_data: bool = False
    ) -> Dict[str, Any]:
        """
        Generate compliance policy adherence report with detailed policy checking.

        Args:
            device_types: Filter by device types
            export_to_csv: Whether to export to CSV
            include_raw_data: Whether to include raw data

        Returns:
            Dictionary with report data including compliance check results
        """
        device_types = device_types or self.DEFAULT_DEVICE_TYPES

        print("\n" + "=" * 60)
        print("   COMPLIANCE POLICY ADHERENCE REPORT")
        print("=" * 60)

        # Step 1: Fetch devices from Intune
        print("\n[Step 1/4] Fetching devices from Microsoft Intune...")
        devices = await self.intune.get_managed_devices(device_types)

        if not devices:
            return {
                "dataframe": pd.DataFrame(),
                "statistics": {},
                "csv_path": None,
                "message": "No devices found",
                "generated_at": datetime.utcnow()
            }

        print(f"   Found {len(devices)} devices")

        # Step 2: Enrich with compliance data from Intune
        print("\n[Step 2/4] Fetching compliance policy data...")
        await self.intune.enrich_devices_with_compliance(devices)

        # Step 3: Convert Intune devices to device info dictionaries for compliance checker
        print("\n[Step 3/4] Running compliance policy checks...")
        devices_info = []
        for device in devices:
            device_info = {
                "device_id": device.device_id,
                "device_name": device.device_name,
                "operating_system": device.operating_system.lower() if device.operating_system else "",
                "os_version": device.os_version or "0.0.0",
                "manufacturer": device.manufacturer,
                "model": device.model,
                "serial_number": device.serial_number,
                "is_encrypted": device.is_encrypted,
                "encryption_method": device.encryption_method,
                "compliance_state": device.compliance_state,
                "management_agent": device.management_agent,
                "user_principal_name": device.user_principal_name,
                "last_sync_date_time": device.last_sync_date_time,
                "device_enrollment_type": device.device_enrollment_type,
                "compliance_policies": device.compliance_policies
            }
            devices_info.append(device_info)

        # Initialize compliance checker and run checks
        compliance_checker = ComplianceChecker(self.auth, self.config)
        check_results = await compliance_checker.batch_check_compliance(devices_info)

        # Step 4: Generate statistics and summaries
        print("\n[Step 4/4] Generating compliance report...")

        if not check_results:
            # Fall back to basic compliance report
            return self._generate_basic_compliance_report(devices, export_to_csv, include_raw_data)

        # Generate summaries and statistics
        summaries = compliance_checker.generate_compliance_summaries(devices_info)
        statistics = compliance_checker.generate_overall_statistics()

        # Generate report text
        report_format = getattr(self.config, 'compliance_report_format', 'detailed') if self.config else 'detailed'
        report_text = compliance_checker.generate_compliance_report_text(statistics, report_format)

        # Export to DataFrames
        detailed_df, summary_df = compliance_checker.export_results_to_dataframe()
        policies_df = compliance_checker.export_policies_to_dataframe()

        # Export to CSV if requested
        csv_paths = []
        if export_to_csv:
            if not detailed_df.empty:
                csv_path = self._export_to_csv(detailed_df, "compliance_detailed")
                if csv_path:
                    csv_paths.append(csv_path)

            if not summary_df.empty:
                csv_path = self._export_to_csv(summary_df, "compliance_summary")
                if csv_path:
                    csv_paths.append(csv_path)

        print("\n   Compliance policy report generated successfully!")

        return {
            "dataframe": summary_df,  # Primary dataframe is the summary
            "detailed_results": detailed_df,
            "policy_definitions": policies_df,
            "devices_info": devices_info,
            "check_results": check_results,
            "device_summaries": summaries,
            "statistics": statistics,
            "report_text": report_text,
            "csv_paths": csv_paths,
            "generated_at": datetime.utcnow(),
            "raw_data": [d.to_dict() for d in devices] if include_raw_data else None
        }

    def _generate_basic_compliance_report(
        self,
        devices: List[IntuneDevice],
        export_to_csv: bool,
        include_raw_data: bool
    ) -> Dict[str, Any]:
        """Generate basic compliance report without detailed policy checking."""
        # Build compliance-focused DataFrame
        data = []
        for device in devices:
            data.append({
                "Device Name": device.device_name,
                "Operating System": device.operating_system,
                "OS Version": device.os_version,
                "Compliance State": device.compliance_state,
                "User": device.user_principal_name,
                "Last Sync": device.last_sync_date_time.isoformat() if device.last_sync_date_time else "",
                "Applied Policies": ", ".join(device.compliance_policies) if device.compliance_policies else "None",
                "Policy Count": len(device.compliance_policies)
            })

        df = pd.DataFrame(data)

        # Calculate statistics
        total = len(devices)
        compliant = sum(1 for d in devices if "compliant" in d.compliance_state.lower() and "non" not in d.compliance_state.lower())
        non_compliant = total - compliant
        with_policies = sum(1 for d in devices if d.compliance_policies)

        stats = {
            "total_devices": total,
            "status_distribution": {
                "compliant": compliant,
                "non_compliant": non_compliant
            },
            "compliance_rate": (compliant / total * 100) if total > 0 else 0,
            "devices_with_policies": with_policies,
            "devices_without_policies": total - with_policies,
            "device_statistics": {
                "total_devices": total,
                "devices_requiring_attention": non_compliant,
                "average_compliance_score": (compliant / total * 100) if total > 0 else 0
            }
        }

        # Export to CSV
        csv_paths = []
        if export_to_csv and not df.empty:
            csv_path = self._export_to_csv(df, "compliance_policy")
            if csv_path:
                csv_paths.append(csv_path)

        print("\n   Report generated successfully!")

        return {
            "dataframe": df,
            "statistics": stats,
            "csv_paths": csv_paths,
            "generated_at": datetime.utcnow(),
            "raw_data": [d.to_dict() for d in devices] if include_raw_data else None
        }

    async def generate_os_patch_report(
        self,
        device_types: List[str] = None,
        export_to_csv: bool = True,
        include_raw_data: bool = False
    ) -> Dict[str, Any]:
        """
        Generate OS version and patch status report with detailed analysis.

        Args:
            device_types: Filter by device types
            export_to_csv: Whether to export to CSV
            include_raw_data: Whether to include raw data

        Returns:
            Dictionary with report data including patch status analysis
        """
        device_types = device_types or self.DEFAULT_DEVICE_TYPES

        print("\n" + "=" * 60)
        print("   OS VERSION / PATCH STATUS REPORT")
        print("=" * 60)

        # Step 1: Fetch devices from Intune
        print("\n[Step 1/4] Fetching devices from Microsoft Intune...")
        devices = await self.intune.get_managed_devices(device_types)

        if not devices:
            return {
                "dataframe": pd.DataFrame(),
                "statistics": {},
                "csv_path": None,
                "message": "No devices found",
                "generated_at": datetime.utcnow()
            }

        print(f"   Found {len(devices)} devices")

        # Step 2: Convert to device info dictionaries
        print("\n[Step 2/4] Preparing device information...")
        devices_info = []
        for device in devices:
            device_info = {
                "device_id": device.device_id,
                "device_name": device.device_name,
                "operating_system": device.operating_system.lower() if device.operating_system else "",
                "os_version": device.os_version or "",
                "build_number": "",  # Not always available from Intune
                "manufacturer": device.manufacturer,
                "model": device.model,
                "serial_number": device.serial_number,
                "compliance_state": device.compliance_state,
                "management_agent": device.management_agent,
                "last_sync_date_time": device.last_sync_date_time,
                "user_principal_name": device.user_principal_name
            }
            devices_info.append(device_info)

        # Step 3: Check OS patch status
        print("\n[Step 3/4] Analyzing OS versions and patch status...")

        patch_checker = OSPatchChecker(self.auth, self.config)
        patch_statuses = await patch_checker.batch_check_patch_status(devices_info)

        if not patch_statuses:
            print("   No patch status results generated")
            return {
                "dataframe": pd.DataFrame(),
                "statistics": {},
                "csv_path": None,
                "message": "No patch status checks performed",
                "generated_at": datetime.utcnow()
            }

        # Step 4: Generate statistics and report
        print("\n[Step 4/4] Generating OS patch report...")

        statistics = patch_checker.generate_statistics(patch_statuses)
        report_text = patch_checker.generate_report_text(statistics)

        # Export to DataFrames
        summary_df, detailed_df, support_df = patch_checker.export_to_dataframe(patch_statuses)

        # Export to CSV if requested
        csv_paths = []
        if export_to_csv:
            # Ensure export directory exists
            os_patch_dir = self.export_dir / "os_patch"
            os_patch_dir.mkdir(parents=True, exist_ok=True)

            if not summary_df.empty:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                csv_path = os_patch_dir / f"os_patch_summary_{timestamp}.csv"
                summary_df.to_csv(csv_path, index=False, encoding='utf-8-sig')
                print(f"   Summary exported to: {csv_path}")
                csv_paths.append(str(csv_path))

            if not detailed_df.empty:
                # Limit detailed export to first 1000 rows to avoid huge files
                if len(detailed_df) > 1000:
                    print(f"   Detailed data has {len(detailed_df)} rows, exporting first 1000 only")
                    detailed_sample = detailed_df.head(1000)
                else:
                    detailed_sample = detailed_df

                csv_path = os_patch_dir / f"os_patch_detailed_{timestamp}.csv"
                detailed_sample.to_csv(csv_path, index=False, encoding='utf-8-sig')
                print(f"   Detailed exported to: {csv_path}")
                csv_paths.append(str(csv_path))

            if not support_df.empty:
                csv_path = os_patch_dir / f"os_support_matrix_{timestamp}.csv"
                support_df.to_csv(csv_path, index=False, encoding='utf-8-sig')
                print(f"   Support matrix exported to: {csv_path}")
                csv_paths.append(str(csv_path))

        print("\n   OS patch status report generated successfully!")

        return {
            "dataframe": summary_df,  # Primary dataframe is the summary
            "detailed_results": detailed_df,
            "support_matrix": support_df,
            "patch_statuses": patch_statuses,
            "statistics": statistics,
            "report_text": report_text,
            "csv_paths": csv_paths,
            "generated_at": datetime.utcnow(),
            "raw_data": [d.to_dict() for d in devices] if include_raw_data else None
        }

    async def generate_asset_tracking_report(
        self,
        device_types: List[str] = None,
        export_to_csv: bool = True,
        include_raw_data: bool = False
    ) -> Dict[str, Any]:
        """
        Generate asset tracking report with serial numbers.

        Args:
            device_types: Filter by device types
            export_to_csv: Whether to export to CSV
            include_raw_data: Whether to include raw data

        Returns:
            Dictionary with report data
        """
        device_types = device_types or self.DEFAULT_DEVICE_TYPES

        print("\n" + "=" * 60)
        print("   ASSET TRACKING REPORT")
        print("=" * 60)

        # Fetch devices
        print("\n[Step 1/2] Fetching devices from Microsoft Intune...")
        devices = await self.intune.get_managed_devices(device_types)

        if not devices:
            return {
                "dataframe": pd.DataFrame(),
                "statistics": {},
                "csv_path": None,
                "message": "No devices found"
            }

        print(f"   Found {len(devices)} devices")

        # Generate report
        print("\n[Step 2/2] Generating report...")

        # Build asset-focused DataFrame
        data = []
        for device in devices:
            data.append({
                "Device Name": device.device_name,
                "Serial Number": device.serial_number or "N/A",
                "Manufacturer": device.manufacturer,
                "Model": device.model,
                "Operating System": device.operating_system,
                "OS Version": device.os_version,
                "Azure AD Device ID": device.azure_ad_device_id,
                "Intune Device ID": device.device_id,
                "Assigned User": device.user_principal_name,
                "Enrollment Type": device.device_enrollment_type,
                "Last Sync": device.last_sync_date_time.isoformat() if device.last_sync_date_time else ""
            })

        df = pd.DataFrame(data)

        # Calculate asset statistics
        with_serial = sum(1 for d in devices if d.serial_number)
        without_serial = len(devices) - with_serial

        manufacturer_dist = {}
        for device in devices:
            mfr = device.manufacturer
            manufacturer_dist[mfr] = manufacturer_dist.get(mfr, 0) + 1

        model_dist = {}
        for device in devices:
            model = f"{device.manufacturer} {device.model}"
            model_dist[model] = model_dist.get(model, 0) + 1

        stats = {
            "total_devices": len(devices),
            "with_serial_number": with_serial,
            "without_serial_number": without_serial,
            "serial_coverage": (with_serial / len(devices) * 100) if devices else 0,
            "manufacturer_distribution": manufacturer_dist,
            "model_distribution": dict(sorted(model_dist.items(), key=lambda x: x[1], reverse=True)[:10])  # Top 10 models
        }

        # Export to CSV
        csv_path = None
        if export_to_csv and not df.empty:
            csv_path = self._export_to_csv(df, "asset_tracking")

        print("\n   Report generated successfully!")

        return {
            "dataframe": df,
            "statistics": stats,
            "csv_path": csv_path,
            "generated_at": datetime.utcnow(),
            "raw_data": [d.to_dict() for d in devices] if include_raw_data else None
        }

    def display_report_summary(self, report_data: Dict[str, Any], report_type: str) -> None:
        """Display report summary in console."""
        if not report_data or report_data.get("message") == "No devices found":
            print("\n   No report data to display")
            return

        stats = report_data.get("statistics", {})
        df = report_data.get("dataframe")

        print("\n" + "=" * 60)
        print(f"   {report_type.upper()} SUMMARY")
        print("=" * 60)

        if report_type == "encryption_status":
            encryption = stats.get("encryption", {})
            print(f"\nTotal Devices: {stats.get('total_devices', 0)}")
            print(f"Encrypted: {encryption.get('encrypted', 0)}")
            print(f"Not Encrypted: {encryption.get('not_encrypted', 0)}")
            print(f"Unknown: {encryption.get('unknown', 0)}")
            print(f"Encryption Rate: {encryption.get('encryption_rate', 0):.1f}%")

            current_rate = encryption.get('encryption_rate', 0)
            if current_rate >= self.compliance_threshold:
                print(f"\nStatus: COMPLIANT (Threshold: {self.compliance_threshold}%)")
            else:
                print(f"\nStatus: NON-COMPLIANT (Threshold: {self.compliance_threshold}%)")
                print(f"Required Improvement: {self.compliance_threshold - current_rate:.1f}%")

        elif report_type == "compliance_policy":
            print(f"\nTotal Devices: {stats.get('total_devices', 0)}")
            print(f"Compliant: {stats.get('compliant', 0)}")
            print(f"Non-Compliant: {stats.get('non_compliant', 0)}")
            print(f"Compliance Rate: {stats.get('compliance_rate', 0):.1f}%")
            print(f"Devices with Policies: {stats.get('devices_with_policies', 0)}")

        elif report_type == "os_patch":
            print(f"\nTotal Devices: {stats.get('total_devices', 0)}")
            print(f"Unique OS Versions: {stats.get('unique_versions', 0)}")
            print("\nOS Distribution:")
            for os_name, count in stats.get("os_distribution", {}).items():
                print(f"   {os_name}: {count}")

        elif report_type == "asset_tracking":
            print(f"\nTotal Devices: {stats.get('total_devices', 0)}")
            print(f"With Serial Number: {stats.get('with_serial_number', 0)}")
            print(f"Without Serial Number: {stats.get('without_serial_number', 0)}")
            print(f"Serial Coverage: {stats.get('serial_coverage', 0):.1f}%")
            print("\nTop Manufacturers:")
            for mfr, count in list(stats.get("manufacturer_distribution", {}).items())[:5]:
                print(f"   {mfr}: {count}")

        # Show CSV path
        csv_path = report_data.get("csv_path")
        if csv_path:
            print(f"\nFull report exported to: {csv_path}")

        # Show sample data
        if df is not None and not df.empty:
            print("\n" + "-" * 40)
            print("SAMPLE DATA (first 5 rows):")
            print("-" * 40)
            print(df.head(5).to_string(index=False))

        print("\n" + "=" * 60)

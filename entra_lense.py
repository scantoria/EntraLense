#!/usr/bin/env python3
"""
EntraLense - Azure AD User Activity & Security Audit Tool
Command-line tool for compliance and security teams.
CSV-focused output with filtering options.
"""

import asyncio
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
import pandas as pd

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from modules.config_manager import config_manager, EntraConfig
from modules.azure_auth import entra_auth, EntraAuth
from modules.user_reports import UserReports
from modules.console_ui import ConsoleUI
from modules.equipment_reports import EquipmentReports
from modules.setup_wizard import SetupWizard
from modules.entralense_logger import get_global_logger, open_logs_folder

logger = get_global_logger()


class EntraLense:
    """Main EntraLense application class"""

    config: Optional[EntraConfig]
    auth: Optional[EntraAuth]
    reports: Optional[UserReports]
    ui: Optional[ConsoleUI]

    def __init__(self):
        self.config = None
        self.auth = None
        self.reports = None
        self.ui = None
        self.is_running = True

    async def initialize(self):
        """Initialize the application"""
        logger.info("=" * 60)
        logger.info("EntraLense Application Starting")
        logger.info("=" * 60)
        print("Initializing EntraLense...")

        # Check for first-time setup using new SetupWizard
        setup_wizard = SetupWizard(dark_mode=True)
        if not setup_wizard.check_existing_config():
            logger.info("First-time setup required")
            temp_ui = ConsoleUI()
            temp_ui.clear_screen()
            temp_ui.print_header("Welcome to EntraLense v1.0")
            print("\n" + "=" * 60)
            print("First-time setup required")
            print("=" * 60)
            print("\nEntraLense needs to be configured with your Azure AD credentials.")
            print("This will take about 2-3 minutes.")

            input("\nPress Enter to start setup...")

            # Run setup wizard
            success = setup_wizard.run_wizard()
            if not success:
                logger.error("Setup wizard failed")
                print("Setup failed. Exiting application.")
                sys.exit(1)
            logger.info("Setup wizard completed successfully")

        # Load configuration
        logger.info("Loading configuration...")
        self.config = config_manager.load()

        if not config_manager.is_configured():
            logger.warning("Configuration incomplete, running setup wizard")
            print("Configuration needed. Running setup wizard...")
            self.config = config_manager.run_setup_wizard()

        # Initialize authentication
        logger.info("Initializing authentication...")
        print("🔐 Authenticating with Azure AD...")
        self.auth = entra_auth
        self.auth.config = self.config

        try:
            # Test authentication immediately
            await self.auth.authenticate()
            print("✅ Authentication successful!")
            logger.info("Authentication test successful")
        except Exception as e:
            logger.error(f"Authentication failed: {e}", exc_info=True)
            print(f"❌ Authentication failed: {e}")
            print("Please check your credentials and try again.")
            return False

        # Initialize UI and reports with export directory
        self.ui = ConsoleUI()
        export_dir = Path(self.config.export_path)
        self.reports = UserReports(self.auth, export_dir=export_dir)

        logger.info("EntraLense initialized successfully")
        print("✅ EntraLense initialized successfully!")
        return True

    async def main_menu(self):
        """Display main menu and handle user input"""
        assert self.ui is not None
        assert self.reports is not None

        while self.is_running:
            self.ui.clear_screen()
            self.ui.print_header("SECURITY COMPLIANCE PORTAL")

            menu_items = [
                ("1", "Users"),
                ("2", "Email"),
                ("3", "Equipment"),
                ("4", "Service Status Dashboard (Coming Soon)"),
                ("5", "Settings"),
                ("L", "View Logs"),
                ("9", "Reconfigure Credentials"),
                ("Q", "Quit")
            ]

            choice = self.ui.display_menu("Main Menu", menu_items)

            if choice.upper() == "Q":
                self.is_running = False
                self.ui.print_message("Goodbye!", "yellow")

            elif choice == "1":
                await self.show_users_menu()

            elif choice == "2":
                await self.show_email_menu()

            elif choice == "3":
                await self.show_equipment_menu()

            elif choice == "4":
                await self.service_dashboard_menu()

            elif choice == "5":
                await self.show_settings_menu()

            elif choice.upper() == "L":
                open_logs_folder()
                self.ui.print_message("Logs folder opened!", "success")
                await asyncio.sleep(1)

            elif choice == "9":
                await self.reconfigure_credentials()

            else:
                self.ui.print_message("Invalid selection!", "red")
                await asyncio.sleep(1)

    async def show_users_menu(self):
        """Display Users submenu"""
        assert self.ui is not None

        while True:
            self.ui.clear_screen()
            self.ui.print_header("USERS REPORTS")

            menu_items = [
                ("1", "Last login/activity (for account lifecycle compliance)"),
                ("2", "Privileged access inventory"),
                ("3", "MFA status"),
                ("4", "License assignment vs. usage"),
                ("B", "Back to Main Menu")
            ]

            choice = self.ui.display_menu("Select report", menu_items)

            if choice.upper() == "B":
                return

            elif choice == "1":
                await self.run_login_activity_report()

            elif choice == "2":
                await self.run_privileged_access_report()

            elif choice == "3":
                await self.run_mfa_status_report()

            elif choice == "4":
                await self.run_license_usage_report()

            else:
                self.ui.print_message("Invalid selection!", "red")
                await asyncio.sleep(1)

    async def show_email_menu(self):
        """Display Email submenu"""
        assert self.ui is not None

        while True:
            self.ui.clear_screen()
            self.ui.print_header("EMAIL REPORTS")

            menu_items = [
                ("1", "Mailbox sizes (for retention policy enforcement)"),
                ("2", "External sharing/forwarding rules (data loss prevention)"),
                ("3", "Distribution list membership (access control documentation)"),
                ("B", "Back to Main Menu")
            ]

            choice = self.ui.display_menu("Select report", menu_items)

            if choice.upper() == "B":
                return

            elif choice == "1":
                await self.run_mailbox_sizes_report()

            elif choice == "2":
                await self.run_external_sharing_report()

            elif choice == "3":
                await self.run_distribution_list_report()

            else:
                self.ui.print_message("Invalid selection!", "red")
                await asyncio.sleep(1)

    async def show_equipment_menu(self):
        """Display Equipment submenu"""
        assert self.ui is not None

        while True:
            self.ui.clear_screen()
            self.ui.print_header("EQUIPMENT REPORTS")

            menu_items = [
                ("1", "Device encryption status"),
                ("2", "Compliance policy adherence"),
                ("3", "OS version/patch status"),
                ("4", "Asset tracking (serial numbers, inventory, financials)"),
                ("5", "Search assets"),
                ("B", "Back to Main Menu")
            ]

            choice = self.ui.display_menu("Select report", menu_items)

            if choice.upper() == "B":
                return

            elif choice == "1":
                await self.run_encryption_status_report()

            elif choice == "2":
                await self.run_compliance_policy_report()

            elif choice == "3":
                await self.run_os_patch_report()

            elif choice == "4":
                await self.run_asset_tracking_report()

            elif choice == "5":
                await self._search_assets_menu()

            else:
                self.ui.print_message("Invalid selection!", "red")
                await asyncio.sleep(1)

    async def service_dashboard_menu(self) -> None:
        """Service Status Dashboard menu (coming soon)."""
        self.ui.clear_screen()
        self.ui.print_header("Service Status Dashboard")
        print("\nFeature Coming Soon!")
        print("\nThis feature will provide:")
        print("* Microsoft 365 Service Health monitoring")
        print("* Box.com status monitoring")
        print("* Real-time service status dashboard")
        print("* Automated incident reporting")
        print("\n" + "=" * 60)
        input("\nPress Enter to continue...")

    async def reconfigure_credentials(self) -> None:
        """Reconfigure Azure AD credentials."""
        setup_wizard = SetupWizard(dark_mode=self.config.dark_mode if self.config else True)
        setup_wizard.reconfigure_wizard()

        # Reload configuration after reconfigure
        self.config = config_manager.load()

        # Re-authenticate with new credentials
        if self.config and self.config.tenant_id and self.config.client_id:
            self.ui.print_message("Re-authenticating with new credentials...", "info")
            self.auth = entra_auth
            self.auth.config = self.config
            try:
                await self.auth.authenticate()
                self.ui.print_message("Authentication successful!", "success")
            except Exception as e:
                self.ui.print_message(f"Authentication failed: {e}", "error")
            self.ui.press_any_key()

    async def show_settings_menu(self) -> None:
        """Display Settings menu."""
        assert self.ui is not None

        while True:
            self.ui.clear_screen()
            self.ui.print_header("SETTINGS")

            menu_items = [
                ("1", f"Export Path: {self.config.export_path if self.config else './exports'}"),
                ("2", f"Dark Mode: {'On' if (self.config and self.config.dark_mode) else 'Off'}"),
                ("3", f"Max Users: {self.config.max_users if self.config else 5000}"),
                ("4", "View Current Configuration"),
                ("B", "Back to Main Menu")
            ]

            choice = self.ui.display_menu("Settings", menu_items)

            if choice.upper() == "B":
                return

            elif choice == "1":
                new_path = input("\nEnter new export path: ").strip()
                if new_path and self.config:
                    self.config.export_path = new_path
                    Path(new_path).mkdir(exist_ok=True)
                    config_manager.save()
                    self.ui.print_message("Export path updated!", "success")
                    self.ui.press_any_key()

            elif choice == "2":
                if self.config:
                    self.config.dark_mode = not self.config.dark_mode
                    config_manager.save()
                    self.ui.print_message(f"Dark mode {'enabled' if self.config.dark_mode else 'disabled'}!", "success")
                    self.ui.press_any_key()

            elif choice == "3":
                try:
                    new_max = int(input("\nEnter max users to fetch: ").strip())
                    if new_max > 0 and self.config:
                        self.config.max_users = new_max
                        config_manager.save()
                        self.ui.print_message("Max users updated!", "success")
                except ValueError:
                    self.ui.print_message("Invalid number!", "error")
                self.ui.press_any_key()

            elif choice == "4":
                self.ui.clear_screen()
                self.ui.print_header("Current Configuration")
                if self.config:
                    print(f"\nTenant ID: {self.config.tenant_id[:8]}..." if self.config.tenant_id else "Not set")
                    print(f"Client ID: {self.config.client_id[:8]}..." if self.config.client_id else "Not set")
                    print(f"Auth Method: {'Interactive' if self.config.use_interactive_auth else 'Client Secret'}")
                    print(f"Export Path: {self.config.export_path}")
                    print(f"Max Users: {self.config.max_users}")
                    print(f"Dark Mode: {self.config.dark_mode}")
                else:
                    print("\nNo configuration loaded.")
                print("\n" + "=" * 60)
                self.ui.press_any_key()

            else:
                self.ui.print_message("Invalid selection!", "red")
                await asyncio.sleep(1)

    async def run_encryption_status_report(self):
        """Generate device encryption status report"""
        assert self.ui is not None

        start_time = datetime.now()

        self.ui.clear_screen()
        self.ui.print_header("Device Encryption Status Report")

        try:
            # Initialize equipment reports
            export_dir = Path(self.config.export_path) / "equipment"
            equipment_reports = EquipmentReports(self.auth, export_dir=export_dir)

            # Generate the report
            result = await equipment_reports.generate_encryption_status_report(
                export_to_csv=False,  # Let user choose
                include_raw_data=True
            )

            df = result["dataframe"]
            stats = result["statistics"]

            # Calculate execution time
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            if df.empty:
                self.ui.print_message("\nNo devices found.", "yellow")
                self.ui.press_any_key()
                return

            # Display summary
            self.ui.clear_screen()
            self.ui.print_header("ENCRYPTION STATUS - RESULTS")

            encryption = stats.get("encryption", {})
            compliance = stats.get("compliance", {})

            print("\nSummary Statistics:")
            print(f"   Total devices: {stats.get('total_devices', 0)}")
            self.ui.print_message(f"   Encrypted: {encryption.get('encrypted', 0)}", "success")
            self.ui.print_message(f"   Not encrypted: {encryption.get('not_encrypted', 0)}", "red")
            print(f"   Unknown: {encryption.get('unknown', 0)}")
            print(f"   Encryption rate: {encryption.get('encryption_rate', 0):.1f}%")
            print(f"   Compliance rate: {compliance.get('compliance_rate', 0):.1f}%")
            print(f"   Duration: {duration:.2f} seconds")

            # Show view options menu
            while True:
                print("\nView Options:")
                print("1. Summary table")
                print("2. Non-encrypted devices only")
                print("3. OS distribution")
                print("4. Export to CSV")
                print("B. Back to menu")

                view_choice = self.ui.get_input("\nSelect view option: ", "B")

                if view_choice.upper() == "B":
                    return

                elif view_choice == "1":
                    # Summary table
                    print("\n" + "=" * 60)
                    self.ui.print_message("ALL DEVICES", "cyan")
                    print("=" * 60)
                    display_cols = ["Device Name", "Operating System", "Is Encrypted",
                                    "Encryption Method", "Compliance State", "User Principal Name"]
                    available_cols = [c for c in display_cols if c in df.columns]
                    print(df[available_cols].to_string(index=False))
                    self.ui.press_any_key()

                elif view_choice == "2":
                    # Non-encrypted devices only
                    non_encrypted_df = df[df["Is Encrypted"] == False]
                    print(f"\nNON-ENCRYPTED DEVICES ({len(non_encrypted_df)} found)")
                    print("=" * 60)
                    if not non_encrypted_df.empty:
                        display_cols = ["Device Name", "Operating System", "Encryption Details",
                                        "User Principal Name"]
                        available_cols = [c for c in display_cols if c in non_encrypted_df.columns]
                        print(non_encrypted_df[available_cols].to_string(index=False))
                    else:
                        self.ui.print_message("All devices are encrypted!", "success")
                    self.ui.press_any_key()

                elif view_choice == "3":
                    # OS distribution
                    print("\n" + "=" * 60)
                    self.ui.print_message("OS DISTRIBUTION", "cyan")
                    print("=" * 60)
                    os_dist = stats.get("os_distribution", {})
                    total = stats.get("total_devices", 1)
                    for os_name, count in sorted(os_dist.items(), key=lambda x: x[1], reverse=True):
                        pct = (count / total * 100) if total > 0 else 0
                        print(f"   {os_name}: {count} devices ({pct:.1f}%)")
                    self.ui.press_any_key()

                elif view_choice == "4":
                    # Export to CSV
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    export_dir = Path(self.config.export_path) / "equipment"
                    export_dir.mkdir(parents=True, exist_ok=True)
                    csv_path = export_dir / f"EncryptionStatus_{timestamp}.csv"
                    df.to_csv(csv_path, index=False, encoding='utf-8-sig')
                    self.ui.print_message(f"\nExported to: {csv_path}", "success")
                    self.ui.press_any_key()

                else:
                    self.ui.print_message("Invalid option", "yellow")
                    await asyncio.sleep(1)

        except Exception as e:
            self.ui.print_message(f"\nError: {e}", "red")
            import traceback
            traceback.print_exc()
            self.ui.press_any_key()

    async def run_compliance_policy_report(self):
        """Generate compliance policy adherence report with detailed policy checking"""
        assert self.ui is not None

        start_time = datetime.now()

        self.ui.clear_screen()
        self.ui.print_header("Compliance Policy Adherence Report")

        try:
            # Initialize equipment reports with config
            export_dir = Path(self.config.export_path) / "equipment"
            equipment_reports = EquipmentReports(self.auth, export_dir=export_dir, config=self.config)

            # Generate the report
            result = await equipment_reports.generate_compliance_policy_report(
                export_to_csv=False,
                include_raw_data=True
            )

            df = result.get("dataframe", pd.DataFrame())
            stats = result.get("statistics", {})
            report_text = result.get("report_text", "")
            detailed_df = result.get("detailed_results", pd.DataFrame())

            # Calculate execution time
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            if df.empty and detailed_df.empty:
                self.ui.print_message("\nNo devices found.", "yellow")
                self.ui.press_any_key()
                return

            # Display summary
            self.ui.clear_screen()
            self.ui.print_header("COMPLIANCE POLICY - RESULTS")

            # Get device statistics
            device_stats = stats.get("device_statistics", {})
            status_dist = stats.get("status_distribution", {})
            severity_dist = stats.get("severity_distribution", {})

            print("\nSummary Statistics:")
            print(f"   Total devices: {device_stats.get('total_devices', stats.get('total_devices', 0))}")
            print(f"   Total checks: {stats.get('total_checks', 0)}")
            self.ui.print_message(f"   Compliant checks: {status_dist.get('compliant', 0)}", "success")
            self.ui.print_message(f"   Non-compliant checks: {status_dist.get('non_compliant', 0)}", "red")
            print(f"   Compliance rate: {stats.get('compliance_rate', 0):.1f}%")
            print(f"   Devices requiring attention: {device_stats.get('devices_requiring_attention', 0)}")
            print(f"   Duration: {duration:.2f} seconds")

            # Show severity breakdown if available
            if severity_dist:
                print("\nIssues by Severity:")
                if severity_dist.get('critical', 0) > 0:
                    self.ui.print_message(f"   Critical: {severity_dist.get('critical', 0)}", "red")
                if severity_dist.get('high', 0) > 0:
                    self.ui.print_message(f"   High: {severity_dist.get('high', 0)}", "red")
                if severity_dist.get('medium', 0) > 0:
                    self.ui.print_message(f"   Medium: {severity_dist.get('medium', 0)}", "yellow")
                if severity_dist.get('low', 0) > 0:
                    print(f"   Low: {severity_dist.get('low', 0)}")

            # Show view options menu
            while True:
                print("\nView Options:")
                print("1. Device compliance summary")
                print("2. Detailed check results")
                print("3. Non-compliant devices only")
                print("4. Top compliance issues")
                print("5. Full report text")
                print("6. Export to CSV")
                print("B. Back to menu")

                view_choice = self.ui.get_input("\nSelect view option: ", "B")

                if view_choice.upper() == "B":
                    return

                elif view_choice == "1":
                    # Device compliance summary
                    print("\n" + "=" * 80)
                    self.ui.print_message("DEVICE COMPLIANCE SUMMARY", "cyan")
                    print("=" * 80)
                    if not df.empty:
                        display_cols = ["device_name", "platform", "compliance_score",
                                        "compliant_checks", "non_compliant_checks", "requires_attention"]
                        available_cols = [c for c in display_cols if c in df.columns]
                        if available_cols:
                            print(df[available_cols].to_string(index=False))
                        else:
                            print(df.to_string(index=False))
                    else:
                        print("No summary data available")
                    self.ui.press_any_key()

                elif view_choice == "2":
                    # Detailed check results
                    print("\n" + "=" * 80)
                    self.ui.print_message("DETAILED CHECK RESULTS", "cyan")
                    print("=" * 80)
                    if not detailed_df.empty:
                        display_cols = ["device_name", "policy_id", "status", "severity", "check_details"]
                        available_cols = [c for c in display_cols if c in detailed_df.columns]
                        if available_cols:
                            print(detailed_df[available_cols].head(50).to_string(index=False))
                            if len(detailed_df) > 50:
                                print(f"\n... and {len(detailed_df) - 50} more results")
                        else:
                            print(detailed_df.head(50).to_string(index=False))
                    else:
                        print("No detailed results available")
                    self.ui.press_any_key()

                elif view_choice == "3":
                    # Non-compliant devices only
                    print("\n" + "=" * 80)
                    self.ui.print_message("DEVICES REQUIRING ATTENTION", "cyan")
                    print("=" * 80)
                    if not df.empty and "requires_attention" in df.columns:
                        attention_df = df[df["requires_attention"] == True]
                        if not attention_df.empty:
                            display_cols = ["device_name", "platform", "compliance_score",
                                            "critical_issues", "high_issues", "attention_reasons"]
                            available_cols = [c for c in display_cols if c in attention_df.columns]
                            print(attention_df[available_cols].to_string(index=False))
                        else:
                            self.ui.print_message("All devices are compliant!", "success")
                    elif not detailed_df.empty and "status" in detailed_df.columns:
                        non_compliant = detailed_df[detailed_df["status"] == "non_compliant"]
                        if not non_compliant.empty:
                            display_cols = ["device_name", "policy_id", "severity", "check_details"]
                            available_cols = [c for c in display_cols if c in non_compliant.columns]
                            print(non_compliant[available_cols].to_string(index=False))
                        else:
                            self.ui.print_message("All checks passed!", "success")
                    else:
                        print("No compliance data available")
                    self.ui.press_any_key()

                elif view_choice == "4":
                    # Top compliance issues
                    print("\n" + "=" * 60)
                    self.ui.print_message("TOP COMPLIANCE ISSUES", "cyan")
                    print("=" * 60)
                    top_issues = stats.get("top_non_compliant_policies", {})
                    if top_issues:
                        for policy, count in top_issues.items():
                            print(f"   {policy}: {count} occurrences")
                    else:
                        self.ui.print_message("No compliance issues found!", "success")
                    self.ui.press_any_key()

                elif view_choice == "5":
                    # Full report text
                    print("\n")
                    if report_text:
                        print(report_text)
                    else:
                        print("No detailed report text available")
                    self.ui.press_any_key()

                elif view_choice == "6":
                    # Export to CSV
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    export_dir = Path(self.config.export_path) / "equipment" / "compliance"
                    export_dir.mkdir(parents=True, exist_ok=True)

                    files_exported = []

                    # Export summary
                    if not df.empty:
                        csv_path = export_dir / f"compliance_summary_{timestamp}.csv"
                        df.to_csv(csv_path, index=False, encoding='utf-8-sig')
                        files_exported.append(csv_path)

                    # Export detailed results
                    if not detailed_df.empty:
                        csv_path = export_dir / f"compliance_detailed_{timestamp}.csv"
                        detailed_df.to_csv(csv_path, index=False, encoding='utf-8-sig')
                        files_exported.append(csv_path)

                    # Export report text
                    if report_text:
                        txt_path = export_dir / f"compliance_report_{timestamp}.txt"
                        with open(txt_path, 'w', encoding='utf-8') as f:
                            f.write(report_text)
                        files_exported.append(txt_path)

                    if files_exported:
                        self.ui.print_message(f"\nExported {len(files_exported)} files to: {export_dir}", "success")
                        for f in files_exported:
                            print(f"   - {f.name}")
                    else:
                        self.ui.print_message("No data to export", "yellow")
                    self.ui.press_any_key()

                else:
                    self.ui.print_message("Invalid option", "yellow")
                    await asyncio.sleep(1)

        except Exception as e:
            self.ui.print_message(f"\nError: {e}", "red")
            import traceback
            traceback.print_exc()
            self.ui.press_any_key()

    async def run_os_patch_report(self):
        """Generate OS version/patch status report with detailed analysis"""
        assert self.ui is not None

        start_time = datetime.now()

        self.ui.clear_screen()
        self.ui.print_header("OS Version/Patch Status Report")

        try:
            # Initialize equipment reports with config
            export_dir = Path(self.config.export_path) / "equipment"
            equipment_reports = EquipmentReports(self.auth, export_dir=export_dir, config=self.config)

            # Generate the report
            result = await equipment_reports.generate_os_patch_report(
                export_to_csv=False,
                include_raw_data=True
            )

            df = result.get("dataframe", pd.DataFrame())
            stats = result.get("statistics", {})
            report_text = result.get("report_text", "")
            detailed_df = result.get("detailed_results", pd.DataFrame())
            patch_statuses = result.get("patch_statuses", [])

            # Calculate execution time
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            if df.empty:
                self.ui.print_message("\nNo devices found.", "yellow")
                self.ui.press_any_key()
                return

            # Display summary
            self.ui.clear_screen()
            self.ui.print_header("OS VERSION/PATCH STATUS - RESULTS")

            # Get key statistics
            summary = stats.get("summary", {})
            patch_metrics = stats.get("patch_metrics", {})
            status_dist = stats.get("status_distribution", {})
            vuln_dist = stats.get("vulnerability_distribution", {})
            compliance_scores = stats.get("compliance_scores", {})

            print("\nSummary Statistics:")
            print(f"   Total devices: {stats.get('total_devices', 0)}")
            print(f"   Patch compliance rate: {summary.get('patch_compliance_rate', 0):.1f}%")
            print(f"   Overall health: {summary.get('overall_health', 'Unknown')}")
            print(f"   Average compliance score: {compliance_scores.get('average', 0):.1f}%")
            print(f"   Duration: {duration:.2f} seconds")

            # Show patch status breakdown
            print("\nPatch Status:")
            self.ui.print_message(f"   Up to date: {status_dist.get('up_to_date', 0)}", "success")
            if status_dist.get('security_updates_available', 0) > 0:
                self.ui.print_message(f"   Security updates available: {status_dist.get('security_updates_available', 0)}", "yellow")
            if status_dist.get('feature_updates_available', 0) > 0:
                print(f"   Feature updates available: {status_dist.get('feature_updates_available', 0)}")
            if status_dist.get('outdated', 0) > 0:
                self.ui.print_message(f"   Outdated: {status_dist.get('outdated', 0)}", "red")
            if status_dist.get('unsupported', 0) > 0:
                self.ui.print_message(f"   Unsupported OS: {status_dist.get('unsupported', 0)}", "red")

            # Show vulnerability levels
            if vuln_dist.get('critical', 0) > 0 or vuln_dist.get('high', 0) > 0:
                print("\nVulnerability Levels:")
                if vuln_dist.get('critical', 0) > 0:
                    self.ui.print_message(f"   Critical: {vuln_dist.get('critical', 0)}", "red")
                if vuln_dist.get('high', 0) > 0:
                    self.ui.print_message(f"   High: {vuln_dist.get('high', 0)}", "red")
                if vuln_dist.get('medium', 0) > 0:
                    self.ui.print_message(f"   Medium: {vuln_dist.get('medium', 0)}", "yellow")

            # Show view options menu
            while True:
                print("\nView Options:")
                print("1. Device patch status summary")
                print("2. OS distribution breakdown")
                print("3. Devices needing attention")
                print("4. Compliance score distribution")
                print("5. Full report text")
                print("6. Export to CSV")
                print("B. Back to menu")

                view_choice = self.ui.get_input("\nSelect view option: ", "B")

                if view_choice.upper() == "B":
                    return

                elif view_choice == "1":
                    # Device patch status summary
                    print("\n" + "=" * 80)
                    self.ui.print_message("DEVICE PATCH STATUS SUMMARY", "cyan")
                    print("=" * 80)
                    if not df.empty:
                        display_cols = ["device_name", "os_name", "os_version", "release_name",
                                        "patch_status", "vulnerability_level", "patch_compliance_score", "is_supported"]
                        available_cols = [c for c in display_cols if c in df.columns]
                        if available_cols:
                            print(df[available_cols].to_string(index=False))
                        else:
                            print(df.to_string(index=False))
                    else:
                        print("No summary data available")
                    self.ui.press_any_key()

                elif view_choice == "2":
                    # OS distribution
                    print("\n" + "=" * 60)
                    self.ui.print_message("OS DISTRIBUTION", "cyan")
                    print("=" * 60)
                    os_dist = stats.get("os_distribution", {})
                    total = stats.get("total_devices", 1)
                    for os_name, count in sorted(os_dist.items(), key=lambda x: x[1], reverse=True):
                        pct = (count / total * 100) if total > 0 else 0
                        print(f"   {os_name}: {count} devices ({pct:.1f}%)")

                    # Also show support status by OS
                    print("\nSupport Status by OS:")
                    if patch_statuses:
                        supported_by_os = {}
                        unsupported_by_os = {}
                        for status in patch_statuses:
                            os_name = status.os_info.os_name
                            if status.os_info.is_supported:
                                supported_by_os[os_name] = supported_by_os.get(os_name, 0) + 1
                            else:
                                unsupported_by_os[os_name] = unsupported_by_os.get(os_name, 0) + 1

                        for os_name in set(list(supported_by_os.keys()) + list(unsupported_by_os.keys())):
                            supported = supported_by_os.get(os_name, 0)
                            unsupported = unsupported_by_os.get(os_name, 0)
                            if unsupported > 0:
                                self.ui.print_message(f"   {os_name}: {supported} supported, {unsupported} unsupported", "yellow")
                            else:
                                print(f"   {os_name}: {supported} supported")

                    self.ui.press_any_key()

                elif view_choice == "3":
                    # Devices needing attention
                    print("\n" + "=" * 80)
                    self.ui.print_message("DEVICES NEEDING ATTENTION", "cyan")
                    print("=" * 80)
                    attention = stats.get("devices_needing_attention", {})
                    if attention.get("count", 0) > 0:
                        print(f"Total devices needing attention: {attention['count']}\n")
                        for i, device in enumerate(attention.get("devices", [])[:10], 1):
                            print(f"{i}. {device['device_name']}")
                            print(f"   OS: {device['os']} {device['version']}")
                            print(f"   Issues: {', '.join(device['issues'])}")
                            print()
                        if attention['count'] > 10:
                            print(f"... and {attention['count'] - 10} more devices")
                    else:
                        self.ui.print_message("No devices needing attention!", "success")
                    self.ui.press_any_key()

                elif view_choice == "4":
                    # Compliance score distribution
                    print("\n" + "=" * 60)
                    self.ui.print_message("COMPLIANCE SCORE DISTRIBUTION", "cyan")
                    print("=" * 60)
                    distribution = compliance_scores.get("distribution", {})
                    total = stats.get("total_devices", 1)

                    self.ui.print_message(f"   Excellent (90-100%): {distribution.get('excellent_90_100', 0)}", "success")
                    print(f"   Good (80-89%): {distribution.get('good_80_89', 0)}")
                    self.ui.print_message(f"   Fair (70-79%): {distribution.get('fair_70_79', 0)}", "yellow")
                    self.ui.print_message(f"   Poor (60-69%): {distribution.get('poor_60_69', 0)}", "yellow")
                    self.ui.print_message(f"   Critical (<60%): {distribution.get('critical_below_60', 0)}", "red")

                    print(f"\n   Average Score: {compliance_scores.get('average', 0):.1f}%")
                    print(f"   Min Score: {compliance_scores.get('min', 0):.1f}%")
                    print(f"   Max Score: {compliance_scores.get('max', 0):.1f}%")
                    self.ui.press_any_key()

                elif view_choice == "5":
                    # Full report text
                    print("\n")
                    if report_text:
                        print(report_text)
                    else:
                        print("No detailed report text available")
                    self.ui.press_any_key()

                elif view_choice == "6":
                    # Export to CSV
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    export_dir = Path(self.config.export_path) / "equipment" / "os_patch"
                    export_dir.mkdir(parents=True, exist_ok=True)

                    files_exported = []

                    # Export summary
                    if not df.empty:
                        csv_path = export_dir / f"os_patch_summary_{timestamp}.csv"
                        df.to_csv(csv_path, index=False, encoding='utf-8-sig')
                        files_exported.append(csv_path)

                    # Export detailed results
                    if not detailed_df.empty:
                        # Limit to 1000 rows
                        if len(detailed_df) > 1000:
                            detailed_sample = detailed_df.head(1000)
                        else:
                            detailed_sample = detailed_df
                        csv_path = export_dir / f"os_patch_detailed_{timestamp}.csv"
                        detailed_sample.to_csv(csv_path, index=False, encoding='utf-8-sig')
                        files_exported.append(csv_path)

                    # Export report text
                    if report_text:
                        txt_path = export_dir / f"os_patch_report_{timestamp}.txt"
                        with open(txt_path, 'w', encoding='utf-8') as f:
                            f.write(report_text)
                        files_exported.append(txt_path)

                    if files_exported:
                        self.ui.print_message(f"\nExported {len(files_exported)} files to: {export_dir}", "success")
                        for f in files_exported:
                            print(f"   - {f.name}")
                    else:
                        self.ui.print_message("No data to export", "yellow")
                    self.ui.press_any_key()

                else:
                    self.ui.print_message("Invalid option", "yellow")
                    await asyncio.sleep(1)

        except Exception as e:
            self.ui.print_message(f"\nError: {e}", "red")
            import traceback
            traceback.print_exc()
            self.ui.press_any_key()

    async def run_asset_tracking_report(self):
        """Generate comprehensive asset tracking report with serial numbers,
        financial tracking, warranty management, and audit capabilities"""
        assert self.ui is not None

        start_time = datetime.now()

        self.ui.clear_screen()
        self.ui.print_header("Asset Tracking & Inventory Report")

        try:
            # Initialize equipment reports with config
            export_dir = Path(self.config.export_path) / "equipment"
            equipment_reports = EquipmentReports(self.auth, export_dir=export_dir, config=self.config)

            # Generate the report
            result = await equipment_reports.generate_asset_tracking_report(
                export_to_csv=False,
                include_raw_data=True
            )

            df = result["dataframe"]
            stats = result["statistics"]
            assets = result.get("assets", [])
            summary = result.get("summary")
            report_text = result.get("report_text", "")
            audit_report = result.get("audit_report", "")
            assets_df = result.get("assets_inventory", pd.DataFrame())
            financial_df = result.get("financial_details", pd.DataFrame())
            asset_tracker = result.get("asset_tracker")

            # Calculate execution time
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            if df.empty:
                self.ui.print_message("\nNo devices found.", "yellow")
                self.ui.press_any_key()
                return

            # Display summary
            self.ui.clear_screen()
            self.ui.print_header("ASSET TRACKING & INVENTORY - RESULTS")

            print("\nInventory Summary:")
            print(f"   Total devices: {stats.get('total_devices', 0)}")
            print(f"   With serial number: {stats.get('with_serial_number', 0)}")
            print(f"   Without serial number: {stats.get('without_serial_number', 0)}")
            print(f"   Serial coverage: {stats.get('serial_coverage', 0):.1f}%")
            print(f"   Duration: {duration:.2f} seconds")

            # Show extended statistics
            if summary:
                print("\nFinancial Summary:")
                self.ui.print_message(f"   Total Current Value: ${stats.get('total_current_value', 0):,.2f}", "success")
                print(f"   Total Purchase Value: ${stats.get('total_purchase_value', 0):,.2f}")
                print(f"   Total Depreciation: ${stats.get('total_depreciation', 0):,.2f}")

                if stats.get('assets_needing_attention', 0) > 0:
                    self.ui.print_message(f"\n   Assets Needing Attention: {stats.get('assets_needing_attention', 0)}", "red")

            # Show view options menu
            while True:
                print("\nView Options:")
                print("1. Summary table (all devices)")
                print("2. Asset type breakdown")
                print("3. Warranty status breakdown")
                print("4. Financial details")
                print("5. Assets needing attention")
                print("6. Audit report")
                print("7. Full inventory report")
                print("8. Search assets")
                print("9. Export to CSV")
                print("B. Back to menu")

                view_choice = self.ui.get_input("\nSelect view option: ", "B")

                if view_choice.upper() == "B":
                    return

                elif view_choice == "1":
                    # Summary table
                    print("\n" + "=" * 80)
                    self.ui.print_message("ALL DEVICES", "cyan")
                    print("=" * 80)
                    display_cols = ["Device Name", "Serial Number", "Manufacturer",
                                    "Model", "Operating System", "Assigned User"]
                    available_cols = [c for c in display_cols if c in df.columns]
                    print(df[available_cols].to_string(index=False))
                    self.ui.press_any_key()

                elif view_choice == "2":
                    # Asset type breakdown
                    print("\n" + "=" * 60)
                    self.ui.print_message("ASSET TYPE BREAKDOWN", "cyan")
                    print("=" * 60)
                    type_counts = stats.get("type_counts", {})
                    total = stats.get("total_devices", 1)
                    if type_counts:
                        for asset_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                            pct = (count / total * 100) if total > 0 else 0
                            print(f"   {asset_type.title()}: {count} devices ({pct:.1f}%)")
                    else:
                        # Fallback to manufacturer breakdown
                        mfr_dist = stats.get("manufacturer_distribution", {})
                        for mfr, count in sorted(mfr_dist.items(), key=lambda x: x[1], reverse=True):
                            pct = (count / total * 100) if total > 0 else 0
                            print(f"   {mfr}: {count} devices ({pct:.1f}%)")
                    self.ui.press_any_key()

                elif view_choice == "3":
                    # Warranty status breakdown
                    print("\n" + "=" * 60)
                    self.ui.print_message("WARRANTY STATUS BREAKDOWN", "cyan")
                    print("=" * 60)
                    warranty_counts = stats.get("warranty_counts", {})
                    total = stats.get("total_devices", 1)
                    if warranty_counts:
                        for status, count in sorted(warranty_counts.items()):
                            pct = (count / total * 100) if total > 0 else 0
                            status_display = status.replace('_', ' ').title()
                            if status == "expired":
                                self.ui.print_message(f"   {status_display}: {count} ({pct:.1f}%)", "red")
                            elif status == "expiring_soon":
                                self.ui.print_message(f"   {status_display}: {count} ({pct:.1f}%)", "yellow")
                            elif status == "active":
                                self.ui.print_message(f"   {status_display}: {count} ({pct:.1f}%)", "success")
                            else:
                                print(f"   {status_display}: {count} ({pct:.1f}%)")
                    else:
                        print("   No warranty data available")
                    self.ui.press_any_key()

                elif view_choice == "4":
                    # Financial details
                    print("\n" + "=" * 60)
                    self.ui.print_message("FINANCIAL DETAILS", "cyan")
                    print("=" * 60)
                    print(f"\n   Total Purchase Value: ${stats.get('total_purchase_value', 0):,.2f}")
                    print(f"   Total Current Value: ${stats.get('total_current_value', 0):,.2f}")
                    print(f"   Total Depreciation: ${stats.get('total_depreciation', 0):,.2f}")

                    purchase_val = stats.get('total_purchase_value', 0)
                    depreciation = stats.get('total_depreciation', 0)
                    if purchase_val > 0:
                        dep_rate = (depreciation / purchase_val * 100)
                        print(f"   Overall Depreciation Rate: {dep_rate:.1f}%")

                    # Show age distribution
                    age_dist = stats.get("assets_by_age", {})
                    if age_dist:
                        print("\n   Asset Age Distribution:")
                        for age_group, count in sorted(age_dist.items()):
                            pct = (count / stats.get('total_devices', 1) * 100) if stats.get('total_devices', 0) > 0 else 0
                            print(f"      {age_group}: {count} ({pct:.1f}%)")

                    # Show financial details table if available
                    if not financial_df.empty:
                        print("\n   Top 10 Assets by Value:")
                        print("-" * 60)
                        sorted_df = financial_df.sort_values("current_value", ascending=False).head(10)
                        display_cols = ["device_name", "asset_type", "purchase_price", "current_value"]
                        available_cols = [c for c in display_cols if c in sorted_df.columns]
                        if available_cols:
                            print(sorted_df[available_cols].to_string(index=False))

                    self.ui.press_any_key()

                elif view_choice == "5":
                    # Assets needing attention
                    print("\n" + "=" * 80)
                    self.ui.print_message("ASSETS NEEDING ATTENTION", "cyan")
                    print("=" * 80)

                    attention_count = stats.get('assets_needing_attention', 0)
                    if attention_count > 0:
                        print(f"\nTotal: {attention_count} assets require attention\n")

                        # Get attention assets
                        attention_assets = [a for a in assets if a.requires_attention]
                        for i, asset in enumerate(attention_assets[:15], 1):  # Show first 15
                            print(f"{i}. {asset.device_name}")
                            print(f"   Type: {asset.asset_type.value.title()}")
                            print(f"   Serial: {asset.serial_number[:20]}{'...' if len(asset.serial_number) > 20 else ''}")
                            self.ui.print_message(f"   Issues: {asset.attention_reason}", "yellow")
                            if i < len(attention_assets) and i < 15:
                                print()

                        if len(attention_assets) > 15:
                            print(f"\n... and {len(attention_assets) - 15} more assets")
                    else:
                        self.ui.print_message("No assets require immediate attention!", "success")

                    self.ui.press_any_key()

                elif view_choice == "6":
                    # Audit report
                    print("\n" + "=" * 80)
                    self.ui.print_message("AUDIT REPORT", "cyan")
                    print("=" * 80)
                    if audit_report:
                        print("\n" + audit_report)
                    else:
                        print("\nNo audit report available")
                    self.ui.press_any_key()

                elif view_choice == "7":
                    # Full inventory report
                    print("\n")
                    if report_text:
                        print(report_text)
                    else:
                        print("No detailed report text available")
                    self.ui.press_any_key()

                elif view_choice == "8":
                    # Search assets
                    await self._search_assets_menu(asset_tracker)

                elif view_choice == "9":
                    # Export to CSV
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    export_dir = Path(self.config.export_path) / "equipment" / "asset_tracking"
                    export_dir.mkdir(parents=True, exist_ok=True)

                    files_exported = []

                    # Export device list
                    if not df.empty:
                        csv_path = export_dir / f"device_list_{timestamp}.csv"
                        df.to_csv(csv_path, index=False, encoding='utf-8-sig')
                        files_exported.append(csv_path)

                    # Export asset inventory
                    if not assets_df.empty:
                        csv_path = export_dir / f"asset_inventory_{timestamp}.csv"
                        assets_df.to_csv(csv_path, index=False, encoding='utf-8-sig')
                        files_exported.append(csv_path)

                    # Export financial details
                    if not financial_df.empty:
                        csv_path = export_dir / f"asset_financial_{timestamp}.csv"
                        financial_df.to_csv(csv_path, index=False, encoding='utf-8-sig')
                        files_exported.append(csv_path)

                    # Export report text
                    if report_text:
                        txt_path = export_dir / f"asset_report_{timestamp}.txt"
                        with open(txt_path, 'w', encoding='utf-8') as f:
                            f.write(report_text)
                        files_exported.append(txt_path)

                    # Export audit report
                    if audit_report:
                        txt_path = export_dir / f"asset_audit_{timestamp}.txt"
                        with open(txt_path, 'w', encoding='utf-8') as f:
                            f.write(audit_report)
                        files_exported.append(txt_path)

                    if files_exported:
                        self.ui.print_message(f"\nExported {len(files_exported)} files to: {export_dir}", "success")
                        for f in files_exported:
                            print(f"   - {f.name}")
                    else:
                        self.ui.print_message("No data to export", "yellow")

                    self.ui.press_any_key()

                else:
                    self.ui.print_message("Invalid option", "yellow")
                    await asyncio.sleep(1)

        except Exception as e:
            self.ui.print_message(f"\nError: {e}", "red")
            import traceback
            traceback.print_exc()
            self.ui.press_any_key()

    async def _search_assets_menu(self, asset_tracker=None):
        """Interactive asset search submenu"""
        from modules.asset_tracker import AssetTracker, AssetType

        if not asset_tracker:
            export_dir = Path(self.config.export_path) / "equipment"
            equipment_reports = EquipmentReports(self.auth, export_dir=export_dir, config=self.config)
            asset_tracker = AssetTracker(self.auth, self.config)

        while True:
            print("\n" + "=" * 60)
            self.ui.print_message("ASSET SEARCH", "cyan")
            print("=" * 60)
            print("\n1. Search by serial number")
            print("2. Search by user/assignee")
            print("3. Search by asset type")
            print("B. Back")

            search_choice = self.ui.get_input("\nSelect search type: ", "B")

            if search_choice.upper() == "B":
                return

            elif search_choice == "1":
                # Search by serial number
                serial = self.ui.get_input("\nEnter serial number (or partial): ", "")
                if serial:
                    matches = asset_tracker.find_assets_by_serial(serial)
                    self._display_asset_search_results(matches, f"serial containing '{serial}'")
                else:
                    self.ui.print_message("No serial number entered", "yellow")

            elif search_choice == "2":
                # Search by user
                username = self.ui.get_input("\nEnter username (or partial): ", "")
                if username:
                    matches = asset_tracker.find_assets_by_user(username)
                    self._display_asset_search_results(matches, f"user containing '{username}'")
                else:
                    self.ui.print_message("No username entered", "yellow")

            elif search_choice == "3":
                # Search by type
                print("\nAvailable asset types:")
                print("1. Laptop")
                print("2. Desktop")
                print("3. Server")
                print("4. Tablet")
                print("5. Mobile")
                print("6. Other")

                type_choice = self.ui.get_input("\nSelect asset type: ", "1")
                type_map = {
                    "1": AssetType.LAPTOP,
                    "2": AssetType.DESKTOP,
                    "3": AssetType.SERVER,
                    "4": AssetType.TABLET,
                    "5": AssetType.MOBILE,
                    "6": AssetType.OTHER
                }

                if type_choice in type_map:
                    asset_type = type_map[type_choice]
                    matches = [a for a in asset_tracker.assets.values() if a.asset_type == asset_type]
                    self._display_asset_search_results(matches, f"type '{asset_type.value}'")
                else:
                    self.ui.print_message("Invalid selection", "yellow")

            else:
                self.ui.print_message("Invalid option", "yellow")

            self.ui.press_any_key()

    def _display_asset_search_results(self, matches, search_desc: str):
        """Display asset search results"""
        if not matches:
            self.ui.print_message(f"\nNo assets found with {search_desc}", "yellow")
            return

        self.ui.print_message(f"\nFound {len(matches)} assets with {search_desc}", "success")
        print("\n" + "=" * 80)

        for i, asset in enumerate(matches[:20], 1):  # Show first 20
            print(f"\n{i}. {asset.device_name}")
            print(f"   Serial: {asset.serial_number}")
            print(f"   Type: {asset.asset_type.value.title()}")
            print(f"   Manufacturer: {asset.manufacturer}")
            print(f"   Model: {asset.model}")
            print(f"   Assigned to: {asset.assigned_to or 'Unassigned'}")
            print(f"   Status: {asset.status.value.title()}")
            print(f"   Warranty: {asset.warranty_status.value.replace('_', ' ').title()}")

            if asset.requires_attention:
                self.ui.print_message(f"   Requires attention: {asset.attention_reason}", "yellow")

        if len(matches) > 20:
            print(f"\n... and {len(matches) - 20} more assets")

        print("\n" + "=" * 80)

    async def run_login_activity_report(self):
        """Generate login activity report (Limited Batch Mode)"""
        assert self.ui is not None
        assert self.reports is not None

        days = 30  # Default period
        start_time = datetime.now()

        self.ui.clear_screen()
        self.ui.print_header("Login Activity Report")

        try:
            # Call the report
            result = await self.reports.get_login_activity(
                days_back=days,
                specific_user=None,
                output_csv=False,  # Don't auto-export, let user choose
                max_users=None,
                include_raw_data=True
            )

            df = result["dataframe"]
            raw_data = result["raw_data"]
            users_processed = result["users_processed"]

            # Calculate execution time
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            if df.empty:
                self.ui.print_message("\nNo data returned.", "yellow")
                self.ui.press_any_key()
                return

            # Display summary
            print("\n" + "=" * 60)
            self.ui.print_message("                    REPORT SUMMARY", "yellow")
            print("=" * 60)
            print(f"\nProcessed: {users_processed} users")
            print(f"Duration: {duration:.2f} seconds")
            print(f"Period: Last {days} days")

            # Show view options menu
            while True:
                print("\nView Options:")
                print("1. Summary table")
                print("2. Raw API response (first user)")
                print("3. Export to CSV")
                print("B. Back to menu")

                view_choice = self.ui.get_input("\nSelect view option: ", "B")

                if view_choice.upper() == "B":
                    return

                elif view_choice == "1":
                    # Display summary table
                    print("\n" + "=" * 60)
                    self.ui.print_message("SUMMARY TABLE", "cyan")
                    print("=" * 60)
                    display_cols = ["User Principal Name", "Display Name", "Account Enabled", "Total Sign-Ins", "Last Sign-In"]
                    available_cols = [c for c in display_cols if c in df.columns]
                    print(df[available_cols].to_string(index=False))
                    self.ui.press_any_key()

                elif view_choice == "2":
                    # Show raw API response for first user with data
                    user_with_data = None
                    for user_data in raw_data:
                        if user_data.get("sign_ins"):
                            user_with_data = user_data
                            break

                    if user_with_data:
                        print(f"\nRaw API Response for: {user_with_data['user_principal_name']}")
                        print("=" * 60)
                        sign_ins = user_with_data["sign_ins"][:3]  # Show first 3
                        for i, signin in enumerate(sign_ins):
                            print(f"\n--- Sign-in {i+1} ---")
                            print(f"  Created: {signin.created_date_time}")
                            print(f"  App: {signin.app_display_name}")
                            print(f"  Status: {signin.status.error_code if signin.status else 'N/A'}")
                            print(f"  IP: {signin.ip_address}")
                            print(f"  Location: {signin.location.city if signin.location else 'N/A'}, {signin.location.country_or_region if signin.location else 'N/A'}")
                        print(f"\n(Showing first 3 of {len(user_with_data['sign_ins'])} sign-ins)")
                    else:
                        self.ui.print_message("No sign-in data available to display", "yellow")
                    self.ui.press_any_key()

                elif view_choice == "3":
                    # Export to CSV
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    csv_path = self.reports.export_dir / f"LoginReport_{timestamp}.csv"
                    df.to_csv(csv_path, index=False, encoding='utf-8-sig')
                    self.ui.print_message(f"\nExported to: {csv_path}", "success")
                    self.ui.press_any_key()

                else:
                    self.ui.print_message("Invalid option", "yellow")
                    await asyncio.sleep(1)

        except Exception as e:
            self.ui.print_message(f"\nError: {e}", "red")
            import traceback
            traceback.print_exc()
            self.ui.press_any_key()

    async def run_privileged_access_report(self):
        """Generate privileged access inventory report"""
        assert self.ui is not None
        assert self.reports is not None

        user_limit = None  # None = all users
        start_time = datetime.now()

        self.ui.clear_screen()
        self.ui.print_header("Privileged Access Inventory Report")

        try:
            # Call the report
            result = await self.reports.get_privileged_access_inventory(
                max_users=user_limit,
                include_raw_data=True
            )

            df = result["dataframe"]
            raw_data = result["raw_data"]
            users_scanned = result["users_scanned"]
            users_with_roles = result["users_with_roles"]
            high_risk_count = result["high_risk_count"]

            # Calculate execution time
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            # Display summary
            self.ui.clear_screen()
            self.ui.print_header("PRIVILEGED ACCESS INVENTORY - RESULTS")

            print("\nSummary Statistics:")
            print(f"   Users scanned: {users_scanned}")
            print(f"   Users with privileged roles: {users_with_roles}")
            print(f"   High-risk roles found: {high_risk_count}")
            print(f"   Duration: {duration:.2f} seconds")

            if df.empty:
                self.ui.print_message(f"\nNo users with privileged roles found in first {users_scanned} users", "yellow")
                self.ui.press_any_key()
                return

            # Show view options menu
            while True:
                print("\nView Options:")
                print("1. Summary table")
                print("2. Raw role data (first user with roles)")
                print("3. High-risk users only")
                print("4. Export to CSV")
                print("B. Back to menu")

                view_choice = self.ui.get_input("\nSelect view option: ", "B")

                if view_choice.upper() == "B":
                    return

                elif view_choice == "1":
                    # Summary table
                    print("\n" + "=" * 60)
                    self.ui.print_message("SUMMARY TABLE", "cyan")
                    print("=" * 60)
                    display_cols = ["User Principal Name", "Display Name", "Account Enabled",
                                    "Privileged Role Count", "High Risk Role Count", "Roles"]
                    available_cols = [c for c in display_cols if c in df.columns]
                    print(df[available_cols].to_string(index=False))
                    self.ui.press_any_key()

                elif view_choice == "2":
                    # Raw data view
                    if raw_data:
                        user_with_roles = raw_data[0]
                        print(f"\nRaw Role Data for: {user_with_roles['user_principal_name']}")
                        print("=" * 60)
                        for role in user_with_roles["roles"]:
                            print(f"\n  Role Name: {role['role_name']}")
                            print(f"  Role ID: {role['role_id']}")
                            print(f"  Role Type: {role['role_type']}")
                            print(f"  High Risk: {role['is_high_risk']}")
                            print(f"  Assignment Source: {role['assignment_source']}")
                    else:
                        self.ui.print_message("No role data available to display", "yellow")
                    self.ui.press_any_key()

                elif view_choice == "3":
                    # High-risk users only
                    high_risk_df = df[df["High Risk Role Count"] > 0]
                    print(f"\nHIGH-RISK USERS ({len(high_risk_df)} found)")
                    print("=" * 60)
                    if not high_risk_df.empty:
                        display_cols = ["User Principal Name", "Display Name", "High Risk Roles"]
                        available_cols = [c for c in display_cols if c in high_risk_df.columns]
                        print(high_risk_df[available_cols].to_string(index=False))
                    else:
                        self.ui.print_message("No high-risk users found", "yellow")
                    self.ui.press_any_key()

                elif view_choice == "4":
                    # Export to CSV
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    csv_path = self.reports.export_dir / f"PrivilegedAccess_{timestamp}.csv"
                    df.to_csv(csv_path, index=False, encoding='utf-8-sig')
                    self.ui.print_message(f"\nExported to: {csv_path}", "success")
                    self.ui.press_any_key()

                else:
                    self.ui.print_message("Invalid option", "yellow")
                    await asyncio.sleep(1)

        except Exception as e:
            self.ui.print_message(f"\nError: {e}", "red")
            import traceback
            traceback.print_exc()
            self.ui.press_any_key()

    async def run_mfa_status_report(self):
        """Generate MFA status compliance report"""
        assert self.ui is not None
        assert self.reports is not None

        start_time = datetime.now()

        self.ui.clear_screen()
        self.ui.print_header("MFA Status Report (Compliance)")

        try:
            # Call the report
            result = await self.reports.get_mfa_status(
                include_raw_data=True
            )

            df = result["dataframe"]
            raw_data = result["raw_data"]
            users_scanned = result["users_scanned"]
            compliant_count = result["compliant_count"]
            non_compliant_count = result["non_compliant_count"]

            # Calculate execution time
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            # Display summary
            self.ui.clear_screen()
            self.ui.print_header("MFA STATUS - RESULTS")

            print("\nSummary Statistics:")
            print(f"   Users scanned: {users_scanned}")
            self.ui.print_message(f"   Compliant users: {compliant_count}", "success")
            self.ui.print_message(f"   Non-compliant users: {non_compliant_count}", "red")
            print(f"   Duration: {duration:.2f} seconds")

            if df.empty:
                self.ui.print_message(f"\nNo users found", "yellow")
                self.ui.press_any_key()
                return

            # Show view options menu
            while True:
                print("\nView Options:")
                print("1. Summary table (all users)")
                print("2. Non-compliant users only")
                print("3. Raw MFA data (first non-compliant user)")
                print("4. Export to CSV")
                print("B. Back to menu")

                view_choice = self.ui.get_input("\nSelect view option: ", "B")

                if view_choice.upper() == "B":
                    return

                elif view_choice == "1":
                    # Summary table
                    print("\n" + "=" * 60)
                    self.ui.print_message("SUMMARY TABLE", "cyan")
                    print("=" * 60)
                    display_cols = ["User Principal Name", "Display Name", "Account Enabled",
                                    "MFA Registered", "MFA Compliant", "Methods Count", "Method Types"]
                    available_cols = [c for c in display_cols if c in df.columns]
                    print(df[available_cols].to_string(index=False))
                    self.ui.press_any_key()

                elif view_choice == "2":
                    # Non-compliant users only
                    non_compliant_df = df[df["MFA Compliant"] == False]
                    print(f"\nNON-COMPLIANT USERS ({len(non_compliant_df)} found)")
                    print("=" * 60)
                    if not non_compliant_df.empty:
                        display_cols = ["User Principal Name", "Display Name", "Method Types"]
                        available_cols = [c for c in display_cols if c in non_compliant_df.columns]
                        print(non_compliant_df[available_cols].to_string(index=False))
                    else:
                        self.ui.print_message("All scanned users are MFA compliant!", "success")
                    self.ui.press_any_key()

                elif view_choice == "3":
                    # Raw MFA data view
                    non_compliant_user = None
                    for user_data in raw_data:
                        if not user_data.get("is_compliant"):
                            non_compliant_user = user_data
                            break

                    if non_compliant_user:
                        print(f"\nRaw MFA Data for: {non_compliant_user['user_principal_name']}")
                        print("=" * 60)
                        print(f"  Display Name: {non_compliant_user['display_name']}")
                        print(f"  Account Enabled: {non_compliant_user['account_enabled']}")
                        print(f"  Method Types: {non_compliant_user['method_types']}")
                        print(f"\n  Raw Methods ({len(non_compliant_user['methods'])} total):")
                        for method in non_compliant_user['methods']:
                            method_type = method.odata_type if hasattr(method, 'odata_type') else type(method).__name__
                            print(f"    - {method_type}")
                    else:
                        self.ui.print_message("No non-compliant users or no raw data available", "yellow")
                    self.ui.press_any_key()

                elif view_choice == "4":
                    # Export to CSV
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    csv_path = self.reports.export_dir / f"MFA_Status_Report_{timestamp}.csv"
                    export_cols = ["User Principal Name", "Display Name", "Account Enabled",
                                   "MFA Registered", "MFA Compliant", "Methods Count",
                                   "Method Types", "Last MFA Activity"]
                    available_cols = [c for c in export_cols if c in df.columns]
                    df[available_cols].to_csv(csv_path, index=False, encoding='utf-8-sig')
                    self.ui.print_message(f"\nExported to: {csv_path}", "success")
                    self.ui.press_any_key()

                else:
                    self.ui.print_message("Invalid option", "yellow")
                    await asyncio.sleep(1)

        except Exception as e:
            self.ui.print_message(f"\nError: {e}", "red")
            import traceback
            traceback.print_exc()
            self.ui.press_any_key()

    async def run_license_usage_report(self):
        """Generate license assignment vs usage report"""
        assert self.ui is not None
        assert self.reports is not None

        user_limit = None  # None = all users
        start_time = datetime.now()

        self.ui.clear_screen()
        self.ui.print_header("License Assignment vs Usage Report")

        try:
            # Call the report
            result = await self.reports.get_license_usage(
                max_users=user_limit,
                include_raw_data=True
            )

            df = result["dataframe"]
            raw_data = result["raw_data"]
            users_scanned = result["users_scanned"]
            active_count = result["active_count"]
            inactive_count = result["inactive_count"]
            license_breakdown = result["license_breakdown"]

            # Calculate execution time
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            # Display summary
            self.ui.clear_screen()
            self.ui.print_header("LICENSE USAGE - RESULTS")

            print("\nSummary Statistics:")
            print(f"   Licensed users scanned: {users_scanned}")
            self.ui.print_message(f"   Active users: {active_count}", "success")
            self.ui.print_message(f"   Inactive users: {inactive_count}", "red")
            print(f"   Duration: {duration:.2f} seconds")

            if df.empty:
                self.ui.print_message("\nNo licensed users found", "yellow")
                self.ui.press_any_key()
                return

            # Show view options menu
            while True:
                print("\nView Options:")
                print("1. Summary table (all licensed users)")
                print("2. Inactive licensed users only")
                print("3. License types breakdown")
                print("4. Export to CSV")
                print("B. Back to menu")

                view_choice = self.ui.get_input("\nSelect view option: ", "B")

                if view_choice.upper() == "B":
                    return

                elif view_choice == "1":
                    # Summary table
                    print("\n" + "=" * 60)
                    self.ui.print_message("ALL LICENSED USERS", "cyan")
                    print("=" * 60)
                    display_cols = ["User Principal Name", "Display Name", "Account Enabled",
                                    "License Count", "Licenses Assigned", "Usage Status", "Last Sign-In"]
                    available_cols = [c for c in display_cols if c in df.columns]
                    print(df[available_cols].to_string(index=False))
                    self.ui.press_any_key()

                elif view_choice == "2":
                    # Inactive licensed users only
                    inactive_df = df[df["Has Activity"] == False]
                    print(f"\nINACTIVE LICENSED USERS ({len(inactive_df)} found)")
                    print("=" * 60)
                    if not inactive_df.empty:
                        display_cols = ["User Principal Name", "Display Name", "License Count",
                                        "Licenses Assigned", "Last Sign-In"]
                        available_cols = [c for c in display_cols if c in inactive_df.columns]
                        print(inactive_df[available_cols].to_string(index=False))
                    else:
                        self.ui.print_message("All licensed users are active!", "success")
                    self.ui.press_any_key()

                elif view_choice == "3":
                    # License type breakdown
                    print("\n" + "=" * 60)
                    self.ui.print_message("LICENSE TYPE BREAKDOWN", "cyan")
                    print("=" * 60)
                    if license_breakdown:
                        breakdown_data = []
                        for license_type, counts in license_breakdown.items():
                            breakdown_data.append({
                                "License Type": license_type,
                                "Total Users": counts["total"],
                                "Active Users": counts["active"],
                                "Inactive Users": counts["inactive"]
                            })
                        import pandas as pd
                        breakdown_df = pd.DataFrame(breakdown_data)
                        print(breakdown_df.to_string(index=False))
                    else:
                        print("No license breakdown data available")
                    self.ui.press_any_key()

                elif view_choice == "4":
                    # Export to CSV
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    csv_path = self.reports.export_dir / f"License_Usage_Report_{timestamp}.csv"
                    export_cols = ["User Principal Name", "Display Name", "Account Enabled",
                                   "License Count", "Licenses Assigned", "Has Activity",
                                   "Last Sign-In", "Usage Status"]
                    available_cols = [c for c in export_cols if c in df.columns]
                    df[available_cols].to_csv(csv_path, index=False, encoding='utf-8-sig')
                    self.ui.print_message(f"\nExported to: {csv_path}", "success")
                    self.ui.press_any_key()

                else:
                    self.ui.print_message("Invalid option", "yellow")
                    await asyncio.sleep(1)

        except Exception as e:
            self.ui.print_message(f"\nError: {e}", "red")
            import traceback
            traceback.print_exc()
            self.ui.press_any_key()

    async def run_mailbox_sizes_report(self):
        """Run the PowerShell Mailbox Sizes Report"""
        assert self.ui is not None

        self.ui.print_message("\nRunning Mailbox Sizes Report...", "yellow")

        try:
            # Get the path to the PowerShell script
            script_path = Path(__file__).parent / "SecurityCompliancePortal.ps1"

            # Run the PowerShell function with full terminal I/O passthrough
            ps_command = f'. "{script_path}"; Invoke-MailboxSizesReport'

            process = subprocess.run(
                ["pwsh", "-NoProfile", "-Command", ps_command],
                stdin=sys.stdin,
                stdout=sys.stdout,
                stderr=sys.stderr
            )

            if process.returncode != 0:
                self.ui.print_message("\nPowerShell report completed with warnings", "yellow")

        except FileNotFoundError:
            self.ui.print_message("\nError: PowerShell (pwsh) not found. Please install PowerShell Core.", "red")
            self.ui.press_any_key()
        except Exception as e:
            self.ui.print_message(f"\nError running PowerShell report: {e}", "red")
            self.ui.press_any_key()

    async def run_external_sharing_report(self):
        """Run the PowerShell External Sharing/Forwarding Rules Report"""
        assert self.ui is not None

        self.ui.print_message("\nRunning External Sharing/Forwarding Rules Report...", "yellow")

        try:
            # Get the path to the PowerShell script
            script_path = Path(__file__).parent / "SecurityCompliancePortal.ps1"

            # Run the PowerShell function with full terminal I/O passthrough
            ps_command = f'. "{script_path}"; Invoke-ExternalSharingReport'

            process = subprocess.run(
                ["pwsh", "-NoProfile", "-Command", ps_command],
                stdin=sys.stdin,
                stdout=sys.stdout,
                stderr=sys.stderr
            )

            if process.returncode != 0:
                self.ui.print_message("\nPowerShell report completed with warnings", "yellow")

        except FileNotFoundError:
            self.ui.print_message("\nError: PowerShell (pwsh) not found. Please install PowerShell Core.", "red")
            self.ui.press_any_key()
        except Exception as e:
            self.ui.print_message(f"\nError running PowerShell report: {e}", "red")
            self.ui.press_any_key()

    async def run_distribution_list_report(self):
        """Run the PowerShell Distribution List Membership Report"""
        assert self.ui is not None

        self.ui.print_message("\nRunning Distribution List Membership Report...", "yellow")

        try:
            # Get the path to the PowerShell script
            script_path = Path(__file__).parent / "SecurityCompliancePortal.ps1"

            # Run the PowerShell function with full terminal I/O passthrough
            ps_command = f'. "{script_path}"; Invoke-DistributionListReport'

            process = subprocess.run(
                ["pwsh", "-NoProfile", "-Command", ps_command],
                stdin=sys.stdin,
                stdout=sys.stdout,
                stderr=sys.stderr
            )

            if process.returncode != 0:
                self.ui.print_message("\nPowerShell report completed with warnings", "yellow")

        except FileNotFoundError:
            self.ui.print_message("\nError: PowerShell (pwsh) not found. Please install PowerShell Core.", "red")
            self.ui.press_any_key()
        except Exception as e:
            self.ui.print_message(f"\nError running PowerShell report: {e}", "red")
            self.ui.press_any_key()

    async def run_security_groups_report(self):
        """Generate security group membership report (CSV output)"""
        assert self.ui is not None
        assert self.reports is not None

        self.ui.clear_screen()
        self.ui.print_header("Security Group Membership Report")

        print("📋 Configure Security Group Report")
        print("-" * 40)

        # User filter
        print("👤 User Filter:")
        print("   1. All users")
        print("   2. Specific user")

        filter_choice = self.ui.get_input("Select (1 or 2): ", "1")

        specific_user = None
        if filter_choice == "2":
            specific_user = self.ui.get_input("Enter user email/UPN: ").strip()
            if not specific_user:
                print("❌ No user specified, defaulting to all users")

        print(f"\n🔐 Generating security group report...")
        print(f"   Scope: {'All users' if not specific_user else specific_user}")
        print()

        try:
            df = await self.reports.get_user_security_groups(
                specific_user=specific_user,
                output_csv=True  # Always output CSV
            )

            if df.empty:
                self.ui.print_message("⚠️ No data returned.", "yellow")
            else:
                print("\n✅ Report generation complete!")
                self._show_report_summary(df, "Security Groups")

        except Exception as e:
            self.ui.print_message(f"❌ Error: {e}", "red")
            import traceback
            traceback.print_exc()

        self.ui.press_any_key()

    async def run_user_status_report(self):
        """Generate user status report (CSV output)"""
        assert self.ui is not None
        assert self.reports is not None

        self.ui.clear_screen()
        self.ui.print_header("User Status Report")

        print("📋 Configure User Status Report")
        print("-" * 40)

        # User filter
        print("👤 User Filter:")
        print("   1. All users")
        print("   2. Specific user")

        filter_choice = self.ui.get_input("Select (1 or 2): ", "1")

        specific_user = None
        if filter_choice == "2":
            specific_user = self.ui.get_input("Enter user email/UPN: ").strip()
            if not specific_user:
                print("❌ No user specified, defaulting to all users")

        print(f"\n👥 Generating user status report...")
        print(f"   Scope: {'All users' if not specific_user else specific_user}")
        print()

        try:
            df = await self.reports.get_user_status_report(
                specific_user=specific_user,
                output_csv=True  # Always output CSV
            )

            if df.empty:
                self.ui.print_message("⚠️ No data returned.", "yellow")
            else:
                print("\n✅ Report generation complete!")
                self._show_report_summary(df, "User Status")

        except Exception as e:
            self.ui.print_message(f"❌ Error: {e}", "red")
            import traceback
            traceback.print_exc()

        self.ui.press_any_key()

    async def run_batch_all_reports(self):
        """Generate all reports at once (CSV output)"""
        assert self.ui is not None
        assert self.reports is not None

        self.ui.clear_screen()
        self.ui.print_header("Batch Report Generation")

        print("🚀 This will generate all available reports:")
        print("   • Login Activity (30 days)")
        print("   • User Status")
        print("   • Security Group Memberships")
        print()

        confirm = self.ui.get_input("Proceed? (y/n): ", "y")

        if confirm.lower() != 'y':
            print("❌ Cancelled.")
            self.ui.press_any_key()
            return

        print("\n⏳ Generating all reports...")
        print("-" * 40)

        try:
            results = await self.reports.get_all_reports(output_csv=True)

            print("\n" + "=" * 60)
            print("📊 BATCH REPORT SUMMARY")
            print("=" * 60)

            for report_name, df in results.items():
                if not df.empty:
                    print(f"   ✅ {report_name}: {len(df)} records")
                else:
                    print(f"   ⚠️ {report_name}: No data")

            print("=" * 60)
            print("\n✅ All reports generated and saved to exports folder!")

        except Exception as e:
            self.ui.print_message(f"❌ Error: {e}", "red")
            import traceback
            traceback.print_exc()

        self.ui.press_any_key()

    def _show_report_summary(self, df, report_type: str):
        """Show summary statistics for a report"""
        print("\n" + "=" * 60)
        print(f"📊 {report_type.upper()} SUMMARY")
        print("=" * 60)

        print(f"   Total Records: {len(df)}")

        # Report-specific summaries
        if report_type == "Login Activity":
            if "Activity Status" in df.columns:
                status_counts = df["Activity Status"].value_counts()
                print("\n   Activity Breakdown:")
                for status, count in status_counts.items():
                    pct = (count / len(df)) * 100
                    print(f"      {status}: {count} ({pct:.1f}%)")

        elif report_type == "User Status":
            if "Risk Level" in df.columns:
                risk_counts = df["Risk Level"].value_counts()
                print("\n   Risk Level Breakdown:")
                for risk, count in risk_counts.items():
                    pct = (count / len(df)) * 100
                    print(f"      {risk}: {count} ({pct:.1f}%)")

        elif report_type == "Security Groups":
            if "Group Name" in df.columns:
                unique_users = df["User Principal Name"].nunique()
                unique_groups = df["Group Name"].nunique()
                print(f"   Unique Users: {unique_users}")
                print(f"   Unique Groups: {unique_groups}")

        print("=" * 60)

    def show_configuration(self):
        """Display current configuration"""
        assert self.ui is not None
        assert self.config is not None

        self.ui.clear_screen()
        self.ui.print_header("Configuration Settings")

        print("🔧 Current Configuration:")
        print(f"   Tenant ID: {self.config.tenant_id}")
        print(f"   Client ID: {self.config.client_id}")
        print(f"   Auth Method: {'Interactive' if self.config.use_interactive_auth else 'Client Secret'}")
        print(f"   Export Path: {self.config.export_path}")
        print(f"   Max Users: {self.config.max_users}")

        print("\nOptions:")
        print("   1. Change credentials")
        print("   2. Change export path")
        print("   3. Back to main menu")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            self.config = config_manager.run_setup_wizard()
        elif choice == "2":
            new_path = input("Enter new export path: ").strip()
            if new_path:
                self.config.export_path = new_path
                config_manager.save()
                print("✅ Export path updated!")

        self.ui.press_any_key()

    async def run(self):
        """Main application entry point"""
        try:
            if await self.initialize():
                await self.main_menu()
        except KeyboardInterrupt:
            print("\n\n👋 Interrupted. Goodbye!")
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            print("Please check your configuration and try again.")


async def main():
    """Application entry point"""
    app = EntraLense()
    await app.run()


if __name__ == "__main__":
    # Handle Ctrl+C gracefully
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")

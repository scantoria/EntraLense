"""Professional setup wizard for EntraLense initialization."""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional

from modules.console_ui import ConsoleUI
from modules.azure_auth import EntraAuth


class SetupWizard:
    """Guided setup wizard for EntraLense configuration."""

    def __init__(self, dark_mode: bool = True):
        """
        Initialize setup wizard.

        Args:
            dark_mode: Use dark mode colors
        """
        self.ui = ConsoleUI(dark_mode)
        self.env_file = Path(".env")
        self.config_dir = Path("config")

    def display_permission_manifest(self) -> None:
        """Display required Azure AD permissions."""
        self.ui.clear_screen()
        self.ui.print_header("EntraLense v1.0 - Permission Manifest")

        print("\nREQUIRED AZURE AD APPLICATION PERMISSIONS")
        print("=" * 60)
        print("\nNavigate to: https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade")
        print("\nCreate a new App Registration, then add these Application permissions:")
        print("\n" + "=" * 60)

        permissions = [
            {
                "category": "User Reports",
                "permission": "User.Read.All",
                "reason": "User inventory and MFA compliance reporting"
            },
            {
                "category": "User Reports",
                "permission": "AuditLog.Read.All",
                "reason": "Sign-in activity and stale account tracking"
            },
            {
                "category": "Email/Exchange",
                "permission": "Exchange.Manage",
                "reason": "PowerShell-based mail flow and inbox auditing"
            },
            {
                "category": "Equipment",
                "permission": "DeviceManagementManagedDevices.Read.All",
                "reason": "Intune device inventory and serial numbers"
            },
            {
                "category": "Equipment",
                "permission": "DeviceManagementConfiguration.Read.All",
                "reason": "Compliance policy and patch status auditing"
            },
            {
                "category": "Service Health",
                "permission": "ServiceHealth.Read.All",
                "reason": "Upcoming Service Status Dashboard features"
            }
        ]

        # Group by category
        categories = {}
        for perm in permissions:
            category = perm["category"]
            if category not in categories:
                categories[category] = []
            categories[category].append(perm)

        # Display by category
        for category, perms in categories.items():
            print(f"\n[{category}]")
            print("-" * 40)
            for perm in perms:
                print(f"  * {perm['permission']}")
                print(f"    {perm['reason']}")

        print("\n" + "=" * 60)
        print("\nIMPORTANT NOTES:")
        print("1. All permissions require Admin Consent")
        print("2. Grant consent in the Azure Portal")
        print("3. Some features require Azure AD Premium licenses")
        print("4. Exchange.Manage requires separate Exchange Online admin consent")

        print("\n" + "=" * 60)
        input("\nPress Enter to continue to credential setup...")

    def collect_credentials(self) -> Dict[str, str]:
        """Collect Azure AD credentials from user."""
        self.ui.clear_screen()
        self.ui.print_header("Azure AD Credential Setup")

        print("\nEnter your Azure AD application credentials:")
        print("=" * 60)

        credentials = {}

        # Tenant ID
        print("\n[Azure AD Tenant ID]")
        print("   Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
        print("   Find in: Azure Portal > Azure Active Directory > Overview")
        credentials["tenant_id"] = input("\nEnter Tenant ID: ").strip()

        # Client ID
        print("\n\n[Application (Client) ID]")
        print("   From your App Registration overview")
        credentials["client_id"] = input("\nEnter Client ID: ").strip()

        # Client Secret
        print("\n\n[Client Secret]")
        print("   Create a new secret in your App Registration")
        print("   Copy the VALUE (not the Secret ID)")
        print("   NOTE: Input will be visible to allow pasting")

        secret = input("\nEnter Client Secret: ").strip()
        credentials["client_secret"] = secret

        return credentials

    def validate_credentials(self, credentials: Dict[str, str]) -> tuple:
        """
        Validate Azure AD credentials.

        Args:
            credentials: Dictionary with tenant_id, client_id, client_secret

        Returns:
            Tuple of (is_valid, error_message, user_info)
        """
        self.ui.print_message("\nValidating credentials with Azure AD...", "info")

        try:
            # Create temporary auth instance for validation
            from modules.config_manager import EntraConfig

            temp_config = EntraConfig()
            temp_config.tenant_id = credentials["tenant_id"]
            temp_config.client_id = credentials["client_id"]
            temp_config.client_secret = credentials["client_secret"]
            temp_config.use_interactive_auth = False

            auth = EntraAuth()

            # Test authentication
            is_valid = auth.authenticate(temp_config)

            if not is_valid:
                return False, "Authentication failed. Please check your credentials.", None

            # Test basic API call
            client = auth.get_client()
            if not client:
                return False, "Failed to create Graph API client.", None

            # Try to get current user/service principal info
            try:
                import asyncio

                async def get_org_info():
                    org_info = await client.organization.get()
                    return org_info

                org_info = asyncio.run(get_org_info())

                if org_info.value and len(org_info.value) > 0:
                    org = org_info.value[0]
                    user_data = {
                        "display_name": "Service Principal",
                        "organization": getattr(org, 'display_name', ''),
                        "tenant_id": getattr(org, 'id', '')
                    }

                    self.ui.print_message("Service Principal authenticated successfully!", "success")
                    return True, "", user_data

            except Exception as org_error:
                # Even if specific API calls fail, authentication might still be valid
                self.ui.print_message("Authentication succeeded but API test failed", "warning")
                self.ui.print_message(f"API Error: {org_error}", "warning")

                user_data = {
                    "display_name": "Authentication Valid",
                    "note": "Limited API permissions detected"
                }
                return True, f"Limited permissions: {org_error}", user_data

        except Exception as e:
            error_msg = str(e)

            # Provide helpful error messages
            if "AADSTS7000215" in error_msg:
                error_msg = "Invalid client secret. Please create a new secret in Azure Portal."
            elif "AADSTS700016" in error_msg:
                error_msg = "Application not found in directory. Check Client ID and Tenant ID."
            elif "AADSTS90002" in error_msg:
                error_msg = "Tenant not found. Please verify the Tenant ID."
            elif "AADSTS50079" in error_msg or "AADSTS50076" in error_msg:
                error_msg = "Multi-factor authentication required. Use Client Credentials flow instead."

            return False, error_msg, None

    def save_credentials(self, credentials: Dict[str, str]) -> bool:
        """
        Save credentials to .env file.

        Args:
            credentials: Dictionary with tenant_id, client_id, client_secret

        Returns:
            True if successful, False otherwise
        """
        try:
            env_content = f"""# EntraLense Configuration
# Generated by Setup Wizard

# Azure AD Authentication
ENTRA_TENANT_ID="{credentials['tenant_id']}"
ENTRA_CLIENT_ID="{credentials['client_id']}"
ENTRA_CLIENT_SECRET="{credentials['client_secret']}"

# Authentication Method (true=interactive, false=client secret)
ENTRA_USE_INTERACTIVE_AUTH="false"

# Application Settings
ENTRA_MAX_USERS="5000"
ENTRA_EXPORT_PATH="./exports"
ENTRA_DARK_MODE="true"

# Equipment Reports Settings
ENTRA_ENABLE_DEVICE_REPORTS="true"
ENTRA_DEVICE_BATCH_SIZE="100"
ENTRA_SCAN_TIMEOUT="30"
ENTRA_COMPLIANCE_THRESHOLD="95.0"
ENTRA_INCLUDE_INTUNE_DEVICES="true"
ENTRA_INCLUDE_ONPREM_DEVICES="true"

# Scanner Configuration
ENTRA_SCANNER_TYPE="graph_api"
ENTRA_SNMP_COMMUNITY="public"
ENTRA_SNMP_VERSION="2c"
"""

            with open(self.env_file, 'w', encoding='utf-8') as f:
                f.write(env_content)

            # Set secure permissions (Unix-like systems)
            if hasattr(os, 'chmod'):
                self.env_file.chmod(0o600)

            self.ui.print_message(f"Configuration saved to {self.env_file}", "success")
            self.ui.print_message("File permissions secured (readable only by you)", "info")

            return True

        except Exception as e:
            self.ui.print_message(f"Error saving configuration: {e}", "error")
            return False

    def setup_config_directory(self) -> None:
        """Setup configuration directory structure."""
        try:
            # Create config directory
            self.config_dir.mkdir(exist_ok=True)

            # Create config file if it doesn't exist
            config_file = self.config_dir / "entralense_config.json"
            if not config_file.exists():
                default_config = {
                    "last_setup": "initial",
                    "version": "1.0.0",
                    "features_enabled": {
                        "user_reports": True,
                        "email_reports": True,
                        "equipment_reports": True
                    }
                }

                import json
                with open(config_file, 'w', encoding='utf-8') as f:
                    json.dump(default_config, f, indent=2)

                # Secure permissions
                if hasattr(os, 'chmod'):
                    config_file.chmod(0o600)
                    self.config_dir.chmod(0o700)

            self.ui.print_message("Configuration directory created", "success")

        except Exception as e:
            self.ui.print_message(f"Could not create config directory: {e}", "warning")

    def display_success_screen(self, user_info: Dict[str, Any]) -> None:
        """Display setup completion screen."""
        self.ui.clear_screen()
        self.ui.print_header("Setup Complete!")

        print("\n" + "=" * 60)
        print("EntraLense is now configured and ready to use!")
        print("=" * 60)

        print(f"\nAuthenticated as: {user_info.get('display_name', 'Service Principal')}")

        if 'organization' in user_info:
            print(f"Organization: {user_info['organization']}")
        if 'user_principal_name' in user_info:
            print(f"User: {user_info['user_principal_name']}")

        print("\nConfiguration saved to:")
        print(f"   * {self.env_file.absolute()}")
        print(f"   * {self.config_dir.absolute()}/")

        print("\nNext Steps:")
        print("1. Run EntraLense to access the main menu")
        print("2. Generate your first compliance report")
        print("3. Explore all available features")

        print("\nNeed to update credentials later?")
        print("   Use [9] Reconfigure Credentials in the main menu")

        print("\n" + "=" * 60)
        print("\nFor help, refer to the documentation at:")
        print("   https://github.com/scantoria/EntraLense")

        print("\n" + "=" * 60)

    def run_wizard(self) -> bool:
        """
        Run the complete setup wizard.

        Returns:
            True if setup completed successfully, False otherwise
        """
        try:
            # Step 1: Display permission manifest
            self.display_permission_manifest()

            # Step 2: Collect credentials
            credentials = self.collect_credentials()

            # Step 3: Validate credentials
            is_valid, error_msg, user_info = self.validate_credentials(credentials)

            if not is_valid:
                self.ui.clear_screen()
                self.ui.print_header("Setup Failed")
                print(f"\nError: {error_msg}")
                print("\nPlease check:")
                print("1. App Registration exists in Azure Portal")
                print("2. Required permissions are granted (Admin Consent)")
                print("3. Client Secret is valid (not expired)")
                print("4. Tenant ID and Client ID are correct")
                print("\n" + "=" * 60)
                input("\nPress Enter to try again...")
                return False

            # Step 4: Save credentials
            if not self.save_credentials(credentials):
                return False

            # Step 5: Setup config directory
            self.setup_config_directory()

            # Step 6: Display success screen
            self.display_success_screen(user_info)

            input("\nPress Enter to launch EntraLense...")
            return True

        except KeyboardInterrupt:
            self.ui.print_message("\n\nSetup cancelled by user.", "warning")
            return False
        except Exception as e:
            self.ui.print_message(f"\nUnexpected error during setup: {e}", "error")
            return False

    def check_existing_config(self) -> bool:
        """
        Check if configuration already exists.

        Returns:
            True if configuration exists and is valid, False otherwise
        """
        # Check for .env file
        if not self.env_file.exists():
            return False

        # Check if .env has required variables
        try:
            from dotenv import load_dotenv
            load_dotenv()

            required_vars = ["ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET"]
            for var in required_vars:
                value = os.getenv(var)
                if not value or value in ["YOUR_TENANT_ID_HERE", "YOUR_CLIENT_ID_HERE"]:
                    return False

            return True

        except Exception:
            return False

    def reconfigure_wizard(self) -> None:
        """Run reconfiguration wizard for existing installations."""
        self.ui.clear_screen()
        self.ui.print_header("Reconfigure EntraLense Credentials")

        print("\nThis will update your Azure AD credentials.")
        print("Existing reports and configurations will be preserved.")

        confirm = input("\nContinue? (y/N): ").strip().lower()
        if confirm not in ['y', 'yes']:
            return

        # Backup existing .env file if it exists
        if self.env_file.exists():
            backup_file = self.env_file.with_suffix('.env.backup')
            import shutil
            try:
                shutil.copy2(self.env_file, backup_file)
                self.ui.print_message(f"Backup created: {backup_file}", "info")
            except Exception as e:
                self.ui.print_message(f"Could not create backup: {e}", "warning")

        # Run setup wizard
        success = self.run_wizard()

        if success:
            self.ui.print_message("\nReconfiguration complete!", "success")
        else:
            self.ui.print_message("\nReconfiguration failed.", "error")
            print("\nYou can:")
            print("1. Try the setup again")
            print("2. Restore from backup manually")
            print("3. Contact support")

        input("\nPress Enter to continue...")

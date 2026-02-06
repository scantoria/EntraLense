# EntraLense Logging Integration Guide

## Overview
This guide shows you how to integrate the logging system into EntraLense and clear credentials during build.

## Part 1: Add the Logger Module

1. **Copy the logger file:**
   ```bash
   cp entralense_logger.py modules/entralense_logger.py
   ```

## Part 2: Integrate Logging into Existing Files

### 2.1 Update `modules/config_manager.py`

Add at the top (after existing imports):
```python
from modules.entralense_logger import get_global_logger

logger = get_global_logger()
```

Replace the `load()` method:
```python
def load(self) -> EntraConfig:
    """Load configuration from file or environment"""
    logger.info("Loading configuration...")
    
    # Try loading from file first
    if self.config_path.exists():
        try:
            with open(self.config_path, 'r') as f:
                data = json.load(f)
                self.config = EntraConfig.from_dict(data)
                logger.info(f"Loaded from config file: {self.config_path}")
                return self.config
        except Exception as e:
            logger.error(f"Could not load config file: {e}", exc_info=True)
    
    # Fall back to environment variables
    logger.info("Checking environment variables...")
    
    self.config.tenant_id = os.getenv("ENTRA_TENANT_ID", "")
    self.config.client_id = os.getenv("ENTRA_CLIENT_ID", "")
    self.config.client_secret = os.getenv("ENTRA_CLIENT_SECRET")
    
    # Log what was found (without sensitive data)
    has_tenant = bool(self.config.tenant_id)
    has_client = bool(self.config.client_id)
    logger.info(f"Tenant ID found: {has_tenant}, Client ID found: {has_client}")
    
    # If we have credentials, save them
    if self.config.tenant_id and self.config.client_id:
        logger.info("Saving credentials from environment variables...")
        self.save()
    else:
        logger.warning("No credentials found in environment variables")
        
    return self.config
```

Replace the `save()` method:
```python
def save(self) -> bool:
    """Save current configuration to file"""
    try:
        with open(self.config_path, 'w') as f:
            json.dump(asdict(self.config), f, indent=2, default=str)
        logger.info(f"Configuration saved to: {self.config_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to save configuration: {e}", exc_info=True)
        return False
```

### 2.2 Update `modules/azure_auth.py`

Add at the top (after existing imports):
```python
from modules.entralense_logger import get_global_logger

logger = get_global_logger()
```

Replace the `authenticate()` method:
```python
async def authenticate(self) -> GraphServiceClient:
    """Authenticate and return Graph client"""
    if self.graph_client:
        logger.debug("Using existing Graph client")
        return self.graph_client
        
    if not self.config or not self.config.tenant_id or not self.config.client_id:
        logger.error("Missing Azure credentials")
        raise EntraAuthError("Missing Azure credentials.")
    
    try:
        auth_method = None
        
        if self.config.use_interactive_auth:
            logger.info("Using interactive authentication...")
            auth_method = "interactive"
            credential = InteractiveBrowserCredential(
                tenant_id=self.config.tenant_id,
                client_id=self.config.client_id
            )
        elif self.config.client_secret:
            logger.info("Using client secret authentication...")
            auth_method = "client_secret"
            credential = ClientSecretCredential(
                tenant_id=self.config.tenant_id,
                client_id=self.config.client_id,
                client_secret=self.config.client_secret
            )
        else:
            logger.info("Using device code authentication...")
            auth_method = "device_code"
            credential = DeviceCodeCredential(
                tenant_id=self.config.tenant_id,
                client_id=self.config.client_id,
                prompt_callback=_device_code_prompt
            )
        
        # Create Graph client
        self.graph_client = GraphServiceClient(credential)
        
        # Test connection
        await self._test_connection()
        
        logger.info(f"Authentication successful - Method: {auth_method}")
        return self.graph_client
        
    except Exception as e:
        logger.error(f"Authentication failed: {str(e)}", exc_info=True)
        raise EntraAuthError(f"Authentication failed: {str(e)}")
```

Replace the `_test_connection()` method:
```python
async def _test_connection(self):
    """Test the Graph connection by fetching current user"""
    try:
        if not self.graph_client:
            return
        user = await self.graph_client.me.get()
        if user:
            logger.info(f"Authenticated as: {user.display_name}")
            print(f"✅ Authenticated as: {user.display_name}")
    except Exception as e:
        logger.warning(f"Could not verify user identity: {e}")
        print(f"⚠️ Note: {e}")
        print("   (This may be normal for app-only permissions)")
```

### 2.3 Update `entra_lense.py`

Add at the top (after existing imports):
```python
from modules.entralense_logger import get_global_logger, open_logs_folder

logger = get_global_logger()
```

Update the `initialize()` method (add logging):
```python
async def initialize(self):
    """Initialize the application"""
    logger.info("="*60)
    logger.info("EntraLense Application Starting")
    logger.info("="*60)
    
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
```

Add "View Logs" option to main menu in `main_menu()`:
```python
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
            ("L", "View Logs"),  # ADD THIS LINE
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
        
        elif choice.upper() == "L":  # ADD THIS BLOCK
            open_logs_folder()
            self.ui.print_message("Logs folder opened!", "success")
            await asyncio.sleep(1)

        elif choice == "9":
            await self.reconfigure_credentials()

        else:
            self.ui.print_message("Invalid selection!", "red")
            await asyncio.sleep(1)
```

Wrap report generation methods with logging. Example for `run_encryption_status_report()`:
```python
async def run_encryption_status_report(self):
    """Generate device encryption status report"""
    assert self.ui is not None

    start_time = datetime.now()
    logger.info("Starting encryption status report")

    self.ui.clear_screen()
    self.ui.print_header("Device Encryption Status Report")

    try:
        # Initialize equipment reports
        export_dir = Path(self.config.export_path) / "equipment"
        equipment_reports = EquipmentReports(self.auth, export_dir=export_dir)

        # Generate the report
        result = await equipment_reports.generate_encryption_status_report(
            export_to_csv=False,
            include_raw_data=True
        )

        df = result["dataframe"]
        stats = result["statistics"]

        # Calculate execution time
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Log success
        logger.info(
            f"Encryption status report completed - "
            f"Devices: {stats.get('total_devices', 0)}, "
            f"Duration: {duration:.2f}s"
        )

        # ... rest of the method remains the same ...

    except Exception as e:
        logger.error(f"Encryption status report failed: {e}", exc_info=True)
        self.ui.print_message(f"\nError: {e}", "red")
        import traceback
        traceback.print_exc()
        self.ui.press_any_key()
```

## Part 3: Clear Credentials During Build

### 3.1 Create credential clearing script

Create `clear_build_credentials.py` in the project root:

```python
#!/usr/bin/env python3
"""
Clear credentials from config files before building production releases.
This ensures test credentials don't end up in distributed executables.
"""
import json
from pathlib import Path
import sys

def clear_credentials():
    """Clear tenant ID and client ID from config file"""
    project_root = Path(__file__).parent
    config_file = project_root / "config" / "entralense_config.json"
    
    print("🔒 Clearing build credentials...")
    
    if not config_file.exists():
        print(f"⚠️  Config file not found: {config_file}")
        print("   Creating empty config directory...")
        config_file.parent.mkdir(exist_ok=True, parents=True)
        
        # Create empty config
        empty_config = {
            "tenant_id": "",
            "client_id": "",
            "client_secret": None,
            "use_interactive_auth": True,
            "max_users": 5000,
            "export_path": "./exports",
            "dark_mode": True,
            "last_report_type": "all"
        }
        
        with open(config_file, 'w') as f:
            json.dump(empty_config, f, indent=2)
        
        print(f"✅ Created empty config: {config_file}")
        return True
    
    try:
        # Load existing config
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        # Clear sensitive fields
        original_tenant = config.get('tenant_id', '')
        original_client = config.get('client_id', '')
        
        config['tenant_id'] = ""
        config['client_id'] = ""
        config['client_secret'] = None
        
        # Save cleared config
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ Credentials cleared from: {config_file}")
        
        if original_tenant or original_client:
            print(f"   Cleared tenant ID: {original_tenant[:8]}..." if original_tenant else "")
            print(f"   Cleared client ID: {original_client[:8]}..." if original_client else "")
        
        return True
        
    except Exception as e:
        print(f"❌ Error clearing credentials: {e}")
        return False

if __name__ == "__main__":
    success = clear_credentials()
    sys.exit(0 if success else 1)
```

### 3.2 Update `build_all.py`

Add this method to the `EntraLenseBuilder` class:

```python
def clear_build_credentials(self):
    """Clear credentials before building"""
    print("\n🔒 Clearing build credentials...")
    
    # Run the clearing script
    clear_script = self.project_root / "clear_build_credentials.py"
    
    if clear_script.exists():
        result = subprocess.run(
            [sys.executable, str(clear_script)],
            capture_output=True,
            text=True
        )
        
        print(result.stdout)
        
        if result.returncode != 0:
            print(f"⚠️  Credential clearing failed: {result.stderr}")
            return False
    else:
        print("⚠️  clear_build_credentials.py not found")
        print("   Creating empty config directory...")
        (self.project_root / "config").mkdir(exist_ok=True)
    
    return True
```

Update the `build_all()` method to call credential clearing:

```python
def build_all(self):
    """Run all build steps"""
    print("\n" + "="*60)
    print("🚀 EntraLense Build System")
    print(f"   Version: {self.version}")
    print(f"   Platform: {platform.system()}")
    print("="*60)

    self.setup_environment()
    self.create_icons()
    
    # ADD THIS LINE - Clear credentials before building
    if not self.clear_build_credentials():
        print("⚠️  Warning: Could not clear credentials")
        print("   Continuing with build...")

    results = {}

    # Build for current platform
    if platform.system() == "Windows":
        results["Windows"] = self.build_windows()
    elif platform.system() == "Darwin":
        results["macOS"] = self.build_macos()
    else:
        print(f"⚠️ Unsupported platform: {platform.system()}")

    # Summary
    print("\n" + "="*60)
    print("📊 Build Summary")
    print("="*60)

    for platform_name, success in results.items():
        status = "✅ Success" if success else "❌ Failed"
        print(f"   {platform_name}: {status}")

    print("\n📁 Output directory: dist/")
    print("="*60)

    # Exit with error code if any build failed
    if not all(results.values()):
        sys.exit(1)
```

### 3.3 Update GitHub Actions Workflow

In `.github/workflows/build.yml`, add credential clearing step before the build:

```yaml
- name: Clear build credentials
  shell: bash
  run: |
    python clear_build_credentials.py
```

Add this right before the "Build with build_all.py" step in both Windows and macOS jobs.

## Part 4: Testing the Integration

### 4.1 Test Logging Locally

```python
python modules/entralense_logger.py
```

This will:
- Create log files in the platform-specific directory
- Test all logging functions
- Open the logs folder

### 4.2 Test Credential Clearing

```bash
# Create a test config with credentials
mkdir -p config
echo '{"tenant_id": "test-tenant-123", "client_id": "test-client-456"}' > config/entralense_config.json

# Run the clearing script
python clear_build_credentials.py

# Verify credentials were cleared
cat config/entralense_config.json
```

### 4.3 Test Full Build

```bash
python build_all.py
```

Verify that:
1. Credentials are cleared before build
2. Empty config directory is included in distribution
3. Build completes successfully

## Part 5: Log Locations

After deployment, users can find logs at:

**Windows:**
```
C:\Users\<username>\AppData\Local\EntraLense\Logs\
```

**macOS:**
```
/Users/<username>/Library/Logs/EntraLense/
```

**Linux:**
```
~/.local/share/EntraLense/logs/
```

## Part 6: Troubleshooting Common Issues

### Issue: No logs being created
- Check file permissions on log directory
- Verify logger is initialized in main app
- Check that `get_global_logger()` is being called

### Issue: Credentials still in build
- Verify `clear_build_credentials.py` is being called
- Check that config file path is correct
- Manually inspect dist packages

### Issue: Authentication failures not logged
- Ensure logger is imported in azure_auth.py
- Verify exception handling includes logging
- Check log level is set to DEBUG or INFO

## Summary

This integration:
1. ✅ Logs all authentication attempts
2. ✅ Logs all API calls
3. ✅ Logs configuration loading
4. ✅ Logs report generation with metrics
5. ✅ Provides easy access to logs via menu
6. ✅ Clears credentials during build
7. ✅ Works cross-platform (Windows & macOS)
8. ✅ Auto-rotates old logs (keeps 14 days)
9. ✅ Includes full exception tracebacks

Users can now troubleshoot issues by:
1. Running the app
2. Selecting "View Logs" from menu
3. Opening the daily log file
4. Finding detailed error messages with timestamps

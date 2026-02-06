# modules/config_manager.py
"""
Configuration manager for EntraLense.
Handles loading/saving settings for both development and compiled executable.
"""
import os
import json
import sys
import platform
from pathlib import Path
from typing import Dict, Optional, Any
from dataclasses import dataclass, asdict, field
from modules.entralense_logger import get_global_logger

logger = get_global_logger()

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Load .env from project root
    env_path = Path(__file__).parent.parent / '.env'
    load_dotenv(dotenv_path=env_path)
    print(f"✅ Loaded .env file from: {env_path}")
except ImportError:
    print("⚠️ python-dotenv not installed. Run: pip install python-dotenv")
except Exception as e:
    print(f"⚠️ Could not load .env file: {e}")

@dataclass
class EntraConfig:
    """Configuration data class for EntraLense"""
    tenant_id: str = ""
    client_id: str = ""
    client_secret: Optional[str] = None
    use_interactive_auth: bool = True
    max_users: int = 5000
    export_path: str = "./exports"
    dark_mode: bool = True
    last_report_type: str = "all"

    # Compliance Policy Settings
    compliance_check_types: list = field(default_factory=lambda: [
        "encryption", "password", "firewall", "antivirus",
        "screen_lock", "jailbreak", "minimum_os"
    ])
    compliance_severity_threshold: str = "medium"  # low, medium, high, critical
    compliance_report_format: str = "detailed"  # detailed, summary, executive
    compliance_alert_threshold: float = 80.0  # percent compliance threshold
    include_remediation_details: bool = True
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EntraConfig':
        """Create config from dictionary"""
        valid_keys = {k for k in cls.__annotations__}
        filtered_data = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered_data)

class ConfigManager:
    """Manages configuration loading, saving, and validation"""
    
    def __init__(self):
        self.config_path = self._get_config_path()
        self.config = EntraConfig()
        
    def _get_config_path(self) -> Path:
        """Get platform-specific config directory with proper frozen app handling"""
        if getattr(sys, 'frozen', False):
            # Running as compiled executable
            # Use the directory where the executable is located
            if platform.system() == 'Darwin':
                # macOS .app bundle: look in Contents/Resources
                base_dir = Path(sys.executable).parent.parent / "Resources"
                if not base_dir.exists():
                    base_dir = Path(sys.executable).parent
            else:
                # Windows: executable directory
                base_dir = Path(sys.executable).parent
        else:
            # Running as script
            base_dir = Path(__file__).parent.parent  # Go up to project root

        # Create config directory if it doesn't exist
        config_dir = base_dir / "config"
        config_dir.mkdir(exist_ok=True, parents=True)

        return config_dir / "entralense_config.json"
    
    def load(self) -> EntraConfig:
        """Load configuration from file or environment"""
        logger.info("Loading configuration...")
        print(f"📂 Loading configuration...")

        # Try loading from file first
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    data = json.load(f)
                    self.config = EntraConfig.from_dict(data)
                    logger.info(f"Loaded from config file: {self.config_path}")
                    print(f"✅ Loaded from config file: {self.config_path}")
                    return self.config
            except Exception as e:
                logger.error(f"Could not load config file: {e}", exc_info=True)
                print(f"⚠️ Could not load config file: {e}")

        # Fall back to environment variables
        logger.info("Checking environment variables...")
        print("🔍 Checking environment variables...")

        self.config.tenant_id = os.getenv("ENTRA_TENANT_ID", "")
        self.config.client_id = os.getenv("ENTRA_CLIENT_ID", "")
        self.config.client_secret = os.getenv("ENTRA_CLIENT_SECRET")

        # Log what was found (without sensitive data)
        has_tenant = bool(self.config.tenant_id)
        has_client = bool(self.config.client_id)
        logger.info(f"Tenant ID found: {has_tenant}, Client ID found: {has_client}")
        print(f"   Tenant ID loaded: {'Yes' if self.config.tenant_id else 'No'}")
        print(f"   Client ID loaded: {'Yes' if self.config.client_id else 'No'}")

        # If we have credentials, save them
        if self.config.tenant_id and self.config.client_id:
            logger.info("Saving credentials from environment variables...")
            print("💾 Saving credentials from environment variables...")
            self.save()
        else:
            logger.warning("No credentials found in environment variables")
            print("❌ No credentials found in environment variables.")
            print("   Make sure .env file exists in project root with:")
            print("   ENTRA_TENANT_ID=your-tenant-id")
            print("   ENTRA_CLIENT_ID=your-client-id")

        return self.config
    
    def save(self) -> bool:
        """Save current configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(asdict(self.config), f, indent=2, default=str)
            logger.info(f"Configuration saved to: {self.config_path}")
            print(f"✅ Configuration saved to: {self.config_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}", exc_info=True)
            print(f"❌ Failed to save configuration: {e}")
            return False
    
    def is_configured(self) -> bool:
        """Check if minimum configuration is present"""
        has_creds = bool(self.config.tenant_id and self.config.client_id)
        status = '✅ Ready' if has_creds else '❌ Missing credentials'
        print(f"🔐 Configuration status: {status}")
        return has_creds
    
    def run_setup_wizard(self) -> EntraConfig:
        """Interactive setup wizard for first-time configuration"""
        print("\n" + "="*60)
        print("          EntraLense Setup Wizard")
        print("="*60)
        
        print("\n📋 Azure App Registration Credentials:")
        print("1. Go to: https://portal.azure.com")
        print("2. Navigate to: Azure AD → App registrations")
        print("3. Select your app: EntraLense")
        print("4. Copy the following values:\n")
        
        self.config.tenant_id = input("Enter Tenant ID: ").strip()
        self.config.client_id = input("Enter Client ID: ").strip()
        
        # Ask about authentication method
        print("\n🔐 Authentication Method:")
        print("1. Interactive (Browser login - recommended for testing)")
        print("2. Client Secret (For automated/scheduled runs)")
        
        choice = input("\nSelect method (1 or 2): ").strip()
        
        if choice == "2":
            self.config.use_interactive_auth = False
            self.config.client_secret = input("Enter Client Secret: ").strip()
        else:
            self.config.use_interactive_auth = True
            self.config.client_secret = None
        
        # Ask about export preferences
        export_dir = input("\n📁 Export directory [default: ./exports]: ").strip()
        if export_dir:
            self.config.export_path = export_dir
            # Create directory if it doesn't exist
            Path(export_dir).mkdir(exist_ok=True)
        
        # Save configuration
        self.save()
        
        print(f"\n✅ Setup complete! Configuration saved.")
        print(f"📄 Config file: {self.config_path}")
        
        return self.config

# Create global instance
config_manager = ConfigManager()

# Test function
def test_config_module():
    """Test the config module"""
    print("\n🧪 Testing ConfigManager...")
    print(f"Current directory: {Path.cwd()}")
    print(f"Project root: {Path(__file__).parent.parent}")
    
    manager = ConfigManager()
    config = manager.load()
    
    print(f"\n📊 Configuration loaded:")
    print(f"   Tenant ID: {'✓' if config.tenant_id else '✗'} {config.tenant_id}")
    print(f"   Client ID: {'✓' if config.client_id else '✗'} {config.client_id}")
    print(f"   Config file: {manager.config_path}")
    
    print(f"\n🔐 Is Configured: {manager.is_configured()}")
    return config

if __name__ == "__main__":
    test_config_module()
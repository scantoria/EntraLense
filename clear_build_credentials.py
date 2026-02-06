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
    
    print("[LOCK] Clearing build credentials...")
    
    if not config_file.exists():
        print(f"[WARN] Config file not found: {config_file}")
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
            "last_report_type": "all",
            "compliance_check_types": [
                "encryption", "password", "firewall", "antivirus",
                "screen_lock", "jailbreak", "minimum_os"
            ],
            "compliance_severity_threshold": "medium",
            "compliance_report_format": "detailed",
            "compliance_alert_threshold": 80.0,
            "include_remediation_details": True
        }
        
        with open(config_file, 'w') as f:
            json.dump(empty_config, f, indent=2)
        
        print(f"[OK] Created empty config: {config_file}")
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
        
        print(f"[OK] Credentials cleared from: {config_file}")
        
        if original_tenant or original_client:
            print(f"   Cleared tenant ID: {original_tenant[:8]}..." if original_tenant else "")
            print(f"   Cleared client ID: {original_client[:8]}..." if original_client else "")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Error clearing credentials: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = clear_credentials()
    sys.exit(0 if success else 1)

# test_all_modules.py
"""
Test all EntraLense modules together.
"""
import asyncio
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

async def test_all():
    print("🧪 Testing all EntraLense modules...")
    print("=" * 50)
    
    try:
        # Test config manager
        from modules.config_manager import config_manager
        config = config_manager.load()
        print("✅ ConfigManager: PASS")
        
        # Test Azure auth
        from modules.azure_auth import entra_auth
        entra_auth.config = config
        
        if config_manager.is_configured():
            client = await entra_auth.authenticate()
            print("✅ AzureAuth: PASS")
            
            # Test reports
            from modules.user_reports import UserReports
            reports = UserReports(entra_auth)
            
            # Quick test - get small report
            df = await reports.get_login_activity(7)
            print(f"✅ UserReports: PASS ({len(df)} users)")
            
            # Test UI
            from modules.console_ui import ConsoleUI
            ui = ConsoleUI()
            ui.print_message("✅ ConsoleUI: PASS", "success")
            
            print("\n🎉 All modules working correctly!")
            return True
            
        else:
            print("❌ Config not set up. Run setup wizard.")
            return False
            
    except Exception as e:
        print(f"❌ Module test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_all())
    if success:
        print("\n🚀 Ready to run: python entra_lense.py")
    else:
        print("\n🔧 Fix the issues above first.")
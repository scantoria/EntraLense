# test_async_fix.py
import asyncio
import sys
from pathlib import Path

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

async def test_async():
    print("🧪 Testing async authentication...")
    
    from modules.config_manager import config_manager
    from modules.azure_auth import entra_auth
    from modules.user_reports import UserReports
    
    # Load config
    config = config_manager.load()
    
    if not config_manager.is_configured():
        print("❌ Config not set up")
        return False
    
    # Set config directly
    entra_auth.config = config
    
    try:
        print("1. Testing authentication...")
        client = await entra_auth.authenticate()
        print("   ✅ Auth passed")
        
        print("2. Testing user reports...")
        reports = UserReports(entra_auth)
        
        print("   Getting login activity...")
        df = await reports.get_login_activity(7)
        print(f"   ✅ Got {len(df)} users")
        
        if not df.empty:
            print("\nSample data:")
            print(df.head(3).to_string(index=False))
        
        print("\n🎉 All async tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_async())
    if success:
        print("\n🚀 Ready to run main application!")
    else:
        print("\n🔧 Fix issues above first.")
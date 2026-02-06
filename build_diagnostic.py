#!/usr/bin/env python3
"""
Diagnostic build for EntraLense - helps identify why standalone builds fail.
This version prints extensive debugging information before starting the app.
"""
import os
import sys
import platform
from pathlib import Path

def diagnostic_startup():
    """Print diagnostic information on startup"""
    print("=" * 80)
    print("EntraLense Diagnostic Build")
    print("=" * 80)
    print(f"\nPlatform: {platform.system()} {platform.release()}")
    print(f"Python: {sys.version}")
    print(f"Executable: {sys.executable}")
    print(f"Frozen: {getattr(sys, 'frozen', False)}")

    # Determine base path
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        base_path = Path(sys._MEIPASS)  # PyInstaller temp directory
        app_path = Path(sys.executable).parent
    else:
        # Running as script
        base_path = Path(__file__).parent
        app_path = base_path

    print(f"\nBase Path (sys._MEIPASS): {base_path}")
    print(f"App Path (executable dir): {app_path}")
    print(f"Current Working Directory: {Path.cwd()}")

    # Check for critical files/directories
    print("\n" + "=" * 80)
    print("File System Check")
    print("=" * 80)

    critical_paths = [
        ('modules/', 'modules'),
        ('config/', 'config'),
        ('data/', 'data'),
        ('.env', '.env file'),
        ('requirements.txt', 'requirements.txt')
    ]

    for rel_path, description in critical_paths:
        check_locations = [
            base_path / rel_path,
            app_path / rel_path,
            Path.cwd() / rel_path
        ]

        found = False
        for location in check_locations:
            if location.exists():
                print(f"  Found {description}: {location}")
                found = True
                break

        if not found:
            print(f"  Missing {description} in:")
            for location in check_locations:
                print(f"   - {location}")

    # Check environment variables
    print("\n" + "=" * 80)
    print("Environment Variables")
    print("=" * 80)

    env_vars = ['ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID', 'ENTRA_CLIENT_SECRET']
    for var in env_vars:
        value = os.getenv(var)
        if value:
            print(f"  {var}: {'*' * 8}... (set)")
        else:
            print(f"  {var}: Not set")

    # Check Python packages
    print("\n" + "=" * 80)
    print("Python Packages Check")
    print("=" * 80)

    required_packages = [
        'azure.identity',
        'msgraph',
        'pandas',
        'colorama',
        'dotenv'
    ]

    for package in required_packages:
        try:
            __import__(package)
            print(f"  {package}")
        except ImportError as e:
            print(f"  {package}: {e}")

    print("\n" + "=" * 80)
    print("Press Enter to continue or Ctrl+C to exit...")
    print("=" * 80)
    input()

if __name__ == "__main__":
    diagnostic_startup()

    # Import and run the main app
    try:
        from entra_lense import main
        import asyncio
        asyncio.run(main())
    except Exception as e:
        print("\n" + "=" * 80)
        print("FATAL ERROR")
        print("=" * 80)
        print(f"\n{e}")
        import traceback
        traceback.print_exc()
        print("\n" + "=" * 80)
        input("Press Enter to exit...")
        sys.exit(1)

# build_all.py
"""
Build EntraLense for all platforms.
Uses --onedir for stable builds that work on clean machines.
"""
import os
import sys
import shutil
import subprocess
from pathlib import Path
import platform

class EntraLenseBuilder:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.version = "1.0.0"

    def setup_environment(self):
        """Setup build environment"""
        print("Setting up build environment...")

        # Ensure directories exist
        directories = [
            "assets",
            "dist/windows",
            "dist/macos",
            "build/windows",
            "build/macos",
            "exports",
            "logs"
        ]

        for dir_path in directories:
            (self.project_root / dir_path).mkdir(parents=True, exist_ok=True)

        # Install build dependencies
        print("Installing build tools...")
        subprocess.run([
            sys.executable, "-m", "pip", "install",
            "--upgrade", "pip", "setuptools", "wheel"
        ])

        subprocess.run([
            sys.executable, "-m", "pip", "install",
            "pyinstaller", "colorama", "packaging"
        ])

    def create_icons(self):
        """Create placeholder icons if they don't exist"""
        assets_dir = self.project_root / "assets"

        # Create simple icons programmatically (placeholder)
        if not (assets_dir / "icon.ico").exists():
            print("Creating placeholder icons...")
            self.create_placeholder_icon()

    def create_placeholder_icon(self):
        """Create simple placeholder icon using Python"""
        try:
            from PIL import Image, ImageDraw

            # Create Windows .ico (multiple sizes)
            sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
            images = []

            for size in sizes:
                img = Image.new('RGB', size, (30, 136, 229))  # Azure blue
                draw = ImageDraw.Draw(img)

                # Draw "EL" logo
                draw.rectangle([(size[0]//4, size[1]//4),
                               (3*size[0]//4, 3*size[1]//4)],
                               fill=(255, 255, 255))
                draw.text((size[0]//3, size[1]//3), "EL",
                         fill=(30, 136, 229),
                         font_size=size[0]//3)

                images.append(img)

            # Save as .ico
            images[0].save(self.project_root / "assets" / "icon.ico",
                          format='ICO', sizes=[(img.width, img.height) for img in images])

            # Save macOS .icns (first image as PNG)
            images[-1].save(self.project_root / "assets" / "icon_256x256.png")

            print("Created placeholder icons")

        except ImportError:
            print("Install Pillow for better icons: pip install pillow")
            # Create empty files as fallback
            (self.project_root / "assets" / "icon.ico").touch()
            (self.project_root / "assets" / "icon_256x256.png").touch()

    def build_windows(self):
        """Build Windows executable"""
        print("\n" + "="*60)
        print("Building Windows Executable (--onedir)")
        print("="*60)

        # Clean previous builds
        for dir_path in ["dist/windows", "build/windows"]:
            shutil.rmtree(self.project_root / dir_path, ignore_errors=True)
            (self.project_root / dir_path).mkdir(parents=True, exist_ok=True)

        # PyInstaller command with --onedir
        icon_path = self.project_root / "assets" / "icon.ico"
        icon_arg = ["--icon", str(icon_path)] if icon_path.exists() else []

        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--name", "EntraLense",
            "--onedir",
            "--console",
            "--clean",
            "--distpath", "dist/windows",
            "--workpath", "build/windows",
            "--add-data", "modules;modules",
            "--add-data", "config;config",
            "--add-data", "data;data",
            *(["--add-data", ".env;."] if Path(".env").exists() else []),
            "--add-data", "SecurityCompliancePortal.ps1;.",
            "--hidden-import", "azure.identity",
            "--hidden-import", "azure.identity._internal",
            "--hidden-import", "azure.identity._credentials",
            "--hidden-import", "azure.identity._credentials.browser",
            "--hidden-import", "azure.identity._credentials.client_secret",
            "--hidden-import", "msgraph",
            "--hidden-import", "msgraph.generated",
            "--hidden-import", "msgraph.generated.users",
            "--hidden-import", "msgraph.generated.models",
            "--hidden-import", "pandas",
            "--hidden-import", "pandas._libs",
            "--hidden-import", "pandas._libs.tslibs",
            "--hidden-import", "colorama",
            "--hidden-import", "aiohttp",
            "--hidden-import", "aiohttp.client",
            "--hidden-import", "charset_normalizer",
            "--hidden-import", "dotenv",
            "--hidden-import", "python_dotenv",
            "--collect-all", "charset_normalizer",
            "--collect-all", "azure.identity",
            "--collect-all", "msgraph",
            *(["--upx-dir", "UPX"] if (self.project_root / "UPX").exists() else []),
            *icon_arg,
            "entra_lense.py"
        ]

        # Filter out None values
        cmd = [x for x in cmd if x is not None]

        print("Running PyInstaller...")
        print(f"Command: {' '.join(cmd[:10])}...")

        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)

        if result.returncode == 0:
            print("Windows build successful!")

            # Find the distribution directory
            dist_dir = self.project_root / "dist" / "windows" / "EntraLense"
            if dist_dir.exists():
                # Calculate total size
                total_size = sum(f.stat().st_size for f in dist_dir.rglob('*') if f.is_file())
                size_mb = total_size / (1024*1024)

                print(f"Distribution: {dist_dir.name}/")
                print(f"Total Size: {size_mb:.1f} MB")
                print(f"Location: {dist_dir.parent}")

                # Create portable package
                self.create_windows_portable(dist_dir)

                return True
        else:
            print("Windows build failed!")
            print("STDOUT:", result.stdout[-500:])
            print("STDERR:", result.stderr[-500:])

        return False

    def create_windows_portable(self, dist_dir: Path):
        """Create portable Windows package from --onedir build"""
        print("\nCreating portable package...")

        portable_dir = self.project_root / "dist" / "EntraLense_Windows_Portable"
        shutil.rmtree(portable_dir, ignore_errors=True)
        portable_dir.mkdir(parents=True, exist_ok=True)

        # Copy entire distribution directory
        shutil.copytree(dist_dir, portable_dir / "EntraLense", dirs_exist_ok=True)

        # Ensure config and data directories exist
        (portable_dir / "EntraLense" / "config").mkdir(exist_ok=True)
        (portable_dir / "EntraLense" / "data").mkdir(exist_ok=True)

        # Create exports and logs directories in parent
        (portable_dir / "exports").mkdir(exist_ok=True)
        (portable_dir / "logs").mkdir(exist_ok=True)

        # Create README
        readme_content = f"""# EntraLense - Windows Portable Version {self.version}

## Quick Start
1. Double-click `Launch.bat` or run `EntraLense\\EntraLense.exe`
2. Enter your Azure credentials when prompted
3. Use the menu to generate reports

## Directory Structure
- `EntraLense/` - Application files (DO NOT MODIFY)
- `exports/` - CSV reports will be saved here
- `logs/` - Application logs for troubleshooting
- `Launch.bat` - Easy launcher

## Azure Setup Required
Before first use, you need:
1. Azure Tenant ID
2. Azure Client ID
3. (Optional) Client Secret

Get these from: https://portal.azure.com > Azure AD > App registrations

## Troubleshooting
If the app fails to start:
1. Check `logs/` folder for error details
2. From the menu, press 'L' to open logs folder
3. Ensure you're running as Administrator if needed

## Support
Email: stephen.cantoria@thisbyte.com

---
EntraLense v{self.version} | The Full Stack and Beneath
"""

        (portable_dir / "README.txt").write_text(readme_content, encoding="utf-8")

        # Create batch file launcher
        batch_content = f"""@echo off
title EntraLense v{self.version}
echo ========================================
echo EntraLense - Azure AD Audit Tool
echo Version {self.version}
echo ========================================
echo.
echo Starting EntraLense...
echo.
cd /d "%~dp0"
start "" "EntraLense\\EntraLense.exe"
"""

        (portable_dir / "Launch.bat").write_text(batch_content)

        # Create ZIP archive
        import zipfile
        zip_path = self.project_root / "dist" / f"EntraLense_Windows_v{self.version}.zip"

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in portable_dir.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(portable_dir.parent)
                    zipf.write(file_path, arcname)

        print(f"Portable package: {zip_path.name}")
        print(f"Package size: {zip_path.stat().st_size / (1024*1024):.1f} MB")

        # Clean up
        shutil.rmtree(portable_dir, ignore_errors=True)

    def build_macos(self):
        """Build macOS executable"""
        print("\n" + "="*60)
        print("Building macOS Application (--onedir)")
        print("="*60)

        if platform.system() != "Darwin":
            print("macOS builds must be created on macOS")
            print("   Skipping macOS build...")
            return False

        # Clean previous builds
        for dir_path in ["dist/macos", "build/macos"]:
            shutil.rmtree(self.project_root / dir_path, ignore_errors=True)
            (self.project_root / dir_path).mkdir(parents=True, exist_ok=True)

        # Build with PyInstaller
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--name", "EntraLense",
            "--onedir",
            "--console",
            "--clean",
            "--distpath", "dist/macos",
            "--workpath", "build/macos",
            "--add-data", "modules:modules",
            "--add-data", "config:config",
            "--add-data", "data:data",
            *(["--add-data", ".env:."] if Path(".env").exists() else []),
            "--hidden-import", "azure.identity",
            "--hidden-import", "azure.identity._internal",
            "--hidden-import", "azure.identity._credentials",
            "--hidden-import", "azure.identity._credentials.browser",
            "--hidden-import", "azure.identity._credentials.client_secret",
            "--hidden-import", "msgraph",
            "--hidden-import", "msgraph.generated",
            "--hidden-import", "msgraph.generated.users",
            "--hidden-import", "msgraph.generated.models",
            "--hidden-import", "pandas",
            "--hidden-import", "pandas._libs",
            "--hidden-import", "pandas._libs.tslibs",
            "--hidden-import", "colorama",
            "--hidden-import", "aiohttp",
            "--hidden-import", "aiohttp.client",
            "--hidden-import", "charset_normalizer",
            "--hidden-import", "dotenv",
            "--hidden-import", "python_dotenv",
            "--collect-all", "charset_normalizer",
            "--collect-all", "azure.identity",
            "--collect-all", "msgraph",
            "entra_lense.py"
        ]

        # Filter out None values
        cmd = [x for x in cmd if x is not None]

        print("Running PyInstaller...")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)

        if result.returncode == 0:
            print("macOS build successful!")

            # Clean up build directory to free disk space before packaging
            shutil.rmtree(self.project_root / "build" / "macos", ignore_errors=True)

            # Find the distribution directory
            dist_dir = self.project_root / "dist" / "macos" / "EntraLense"
            if dist_dir.exists():
                # Calculate total size
                total_size = sum(f.stat().st_size for f in dist_dir.rglob('*') if f.is_file())
                size_mb = total_size / (1024*1024)

                print(f"Distribution: {dist_dir.name}/")
                print(f"Total Size: {size_mb:.1f} MB")

                # Make executable
                exec_file = dist_dir / "EntraLense"
                if exec_file.exists():
                    os.chmod(exec_file, 0o755)

                # Create DMG
                self.create_macos_dmg(dist_dir)

                return True
        else:
            print("macOS build failed!")
            print("STDERR:", result.stderr[-500:])

        return False

    def create_macos_dmg(self, dist_dir: Path):
        """Create macOS DMG file from --onedir build"""
        print("\nCreating macOS DMG...")

        try:
            # Create .app bundle structure
            app_name = "EntraLense.app"
            app_path = self.project_root / "dist" / app_name

            # Clean up old .app
            shutil.rmtree(app_path, ignore_errors=True)

            # Create .app structure
            (app_path / "Contents" / "MacOS").mkdir(parents=True, exist_ok=True)
            (app_path / "Contents" / "Resources").mkdir(parents=True, exist_ok=True)

            # Copy entire distribution directory into .app bundle
            shutil.copytree(dist_dir, app_path / "Contents" / "MacOS" / "EntraLense", dirs_exist_ok=True)

            # Create launcher script that runs the executable
            launcher_script = """#!/bin/bash
cd "$(dirname "$0")/EntraLense"
./EntraLense
"""
            launcher_path = app_path / "Contents" / "MacOS" / "launcher.sh"
            launcher_path.write_text(launcher_script)
            os.chmod(launcher_path, 0o755)

            # Create Info.plist pointing to launcher
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>EntraLense</string>
    <key>CFBundleDisplayName</key>
    <string>EntraLense</string>
    <key>CFBundleIdentifier</key>
    <string>com.thisbyte.entralense</string>
    <key>CFBundleVersion</key>
    <string>{self.version}</string>
    <key>CFBundleShortVersionString</key>
    <string>{self.version}</string>
    <key>CFBundleExecutable</key>
    <string>launcher.sh</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright 2026 ThisByte, LLC. All rights reserved.</string>
</dict>
</plist>
"""

            (app_path / "Contents" / "Info.plist").write_text(plist_content)

            # Create DMG using hdiutil
            dmg_name = f"EntraLense_v{self.version}.dmg"
            dmg_path = self.project_root / "dist" / dmg_name

            # Remove old DMG
            dmg_path.unlink(missing_ok=True)

            # Create DMG
            subprocess.run([
                "hdiutil", "create",
                "-volname", "EntraLense",
                "-srcfolder", str(app_path),
                "-ov", "-format", "UDZO",
                str(dmg_path)
            ], check=True)

            print(f"DMG created: {dmg_path.name}")
            print(f"DMG size: {dmg_path.stat().st_size / (1024*1024):.1f} MB")

            # Clean up .app
            shutil.rmtree(app_path, ignore_errors=True)

        except Exception as e:
            print(f"Could not create DMG: {e}")

    def clear_build_credentials(self):
        """Clear credentials before building"""
        print("\nClearing build credentials...")

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
                print(f"Credential clearing failed: {result.stderr}")
                return False
        else:
            print("clear_build_credentials.py not found")
            print("   Creating empty config directory...")
            (self.project_root / "config").mkdir(exist_ok=True)

        return True

    def build_all(self):
        """Run all build steps"""
        print("\n" + "="*60)
        print("EntraLense Build System")
        print(f"   Version: {self.version}")
        print(f"   Platform: {platform.system()}")
        print(f"   Mode: --onedir")
        print("="*60)

        self.setup_environment()
        self.create_icons()

        # Clear credentials before building
        if not self.clear_build_credentials():
            print("Warning: Could not clear credentials")
            print("   Continuing with build...")

        results = {}

        # Build for current platform
        if platform.system() == "Windows":
            results["Windows"] = self.build_windows()
        elif platform.system() == "Darwin":
            results["macOS"] = self.build_macos()
        else:
            print(f"Unsupported platform: {platform.system()}")

        # Summary
        print("\n" + "="*60)
        print("Build Summary")
        print("="*60)

        for platform_name, success in results.items():
            status = "Success" if success else "Failed"
            print(f"   {platform_name}: {status}")

        print(f"\nOutput directory: dist/")
        print("="*60)

        # Exit with error code if any build failed
        if not all(results.values()):
            sys.exit(1)


if __name__ == "__main__":
    builder = EntraLenseBuilder()
    builder.build_all()

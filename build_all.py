# build_all.py
"""
Build EntraLense for all platforms.
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
        print("🔧 Setting up build environment...")
        
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
        print("📦 Installing build tools...")
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
            print("🎨 Creating placeholder icons...")
            # You'll want to replace these with real icons later
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
            
            print("✅ Created placeholder icons")
            
        except ImportError:
            print("⚠️ Install Pillow for better icons: pip install pillow")
            # Create empty files as fallback
            (self.project_root / "assets" / "icon.ico").touch()
            (self.project_root / "assets" / "icon_256x256.png").touch()
    
    def build_windows(self):
        """Build Windows executable"""
        print("\n" + "="*60)
        print("🪟 Building Windows Executable")
        print("="*60)
        
        # Clean previous builds
        for dir_path in ["dist/windows", "build/windows"]:
            shutil.rmtree(self.project_root / dir_path, ignore_errors=True)
            (self.project_root / dir_path).mkdir(parents=True, exist_ok=True)
        
        # PyInstaller command
        icon_path = self.project_root / "assets" / "icon.ico"
        icon_arg = ["--icon", str(icon_path)] if icon_path.exists() else []
        
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--name", f"EntraLense_v{self.version}",
            "--onefile",
            "--console",
            "--clean",
            "--distpath", "dist/windows",
            "--workpath", "build/windows",
            "--add-data", "modules;modules",
            "--add-data", "config;config",
            "--add-data", "data;data",
            "--add-data", "SecurityCompliancePortal.ps1;.",
            "--hidden-import", "azure.identity",
            "--hidden-import", "azure.identity._internal",
            "--hidden-import", "azure.identity._credentials",
            "--hidden-import", "msgraph",
            "--hidden-import", "msgraph.generated",
            "--hidden-import", "pandas",
            "--hidden-import", "pandas._libs",
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
        
        print("🔨 Running PyInstaller...")
        print(f"Command: {' '.join(cmd[:10])}...")
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
        
        if result.returncode == 0:
            print("✅ Windows build successful!")
            
            # Find the executable
            exe_files = list((self.project_root / "dist/windows").glob("*.exe"))
            if exe_files:
                exe_path = exe_files[0]
                size_mb = exe_path.stat().st_size / (1024*1024)
                print(f"📁 Executable: {exe_path.name}")
                print(f"📏 Size: {size_mb:.1f} MB")
                print(f"📍 Location: {exe_path.parent}")
                
                # Create portable package
                self.create_windows_portable(exe_path)
                
                return True
        else:
            print("❌ Windows build failed!")
            print("STDOUT:", result.stdout[-500:])  # Last 500 chars
            print("STDERR:", result.stderr[-500:])
            
        return False
    
    def create_windows_portable(self, exe_path: Path):
        """Create portable Windows package"""
        print("\n📦 Creating portable package...")
        
        portable_dir = self.project_root / "dist" / "EntraLense_Portable_Windows"
        shutil.rmtree(portable_dir, ignore_errors=True)
        portable_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy executable
        shutil.copy2(exe_path, portable_dir / "EntraLense.exe")

        # Copy config and data directories
        if (self.project_root / "config").exists():
            shutil.copytree(self.project_root / "config", portable_dir / "config")
        else:
            (portable_dir / "config").mkdir(exist_ok=True)
        if (self.project_root / "data").exists():
            shutil.copytree(self.project_root / "data", portable_dir / "data")
        else:
            (portable_dir / "data").mkdir(exist_ok=True)
        if (self.project_root / "SecurityCompliancePortal.ps1").exists():
            shutil.copy2(self.project_root / "SecurityCompliancePortal.ps1", portable_dir / "SecurityCompliancePortal.ps1")

        # Create necessary directories
        (portable_dir / "exports").mkdir(exist_ok=True)
        (portable_dir / "logs").mkdir(exist_ok=True)
        
        # Create README
        readme_content = f"""# EntraLense - Portable Version {self.version}

## 🚀 Quick Start
1. Run `EntraLense.exe`
2. Enter your Azure credentials when prompted
3. Use the menu to generate reports

## 🔐 Azure Setup Required
Before first use, you need:
1. Azure Tenant ID
2. Azure Client ID
3. (Optional) Client Secret

Get these from: https://portal.azure.com → Azure AD → App registrations

## 📁 Directory Structure
- `EntraLense.exe` - Main application
- `config/` - Configuration files (auto-created)
- `exports/` - CSV reports (auto-created)
- `logs/` - Application logs (auto-created)

## ⚙️ First Run
On first launch, you'll be guided through:
1. Azure authentication setup
2. Export directory selection
3. Initial configuration

## 🔄 Updates
Check https://thisbyte.com/entralense for updates

## 📧 Support
Email: stephen.cantoria@thisbyte.com

---
EntraLense v{self.version} | The Full Stack and Beneath
"""
        
        (portable_dir / "README.txt").write_text(readme_content)
        
        # Create batch file for easy launching
        batch_content = """@echo off
echo EntraLense v1.0.0 - Azure AD Audit Tool
echo ========================================
echo.
echo Starting EntraLense...
echo.
echo If this is your first time, you'll need:
echo 1. Azure Tenant ID
echo 2. Azure Client ID
echo.
echo Press Ctrl+C to cancel, or...
pause
start "" "EntraLense.exe"
"""
        
        (portable_dir / "Launch.bat").write_text(batch_content)
        
        # Create ZIP archive
        import zipfile
        zip_path = self.project_root / "dist" / f"EntraLense_Windows_Portable_v{self.version}.zip"
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in portable_dir.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(portable_dir)
                    zipf.write(file_path, arcname)
        
        print(f"✅ Portable package: {zip_path.name}")
        print(f"📏 Package size: {zip_path.stat().st_size / (1024*1024):.1f} MB")
        
        # Clean up
        shutil.rmtree(portable_dir, ignore_errors=True)
    
    def build_macos(self):
        """Build macOS executable"""
        print("\n" + "="*60)
        print("🍎 Building macOS Application")
        print("="*60)
        
        if platform.system() != "Darwin":
            print("⚠️ macOS builds must be created on macOS")
            print("   Skipping macOS build...")
            return False
        
        # Clean previous builds
        for dir_path in ["dist/macos", "build/macos"]:
            shutil.rmtree(self.project_root / dir_path, ignore_errors=True)
            (self.project_root / dir_path).mkdir(parents=True, exist_ok=True)
        
        # Build with PyInstaller
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--name", f"EntraLense",
            "--onefile",
            "--console",
            "--clean",
            "--distpath", "dist/macos",
            "--workpath", "build/macos",
            "--add-data", "modules:modules",
            "--add-data", "config:config",
            "--add-data", "data:data",
            "--hidden-import", "azure.identity",
            "--hidden-import", "azure.identity._internal",
            "--hidden-import", "azure.identity._credentials",
            "--hidden-import", "msgraph",
            "--hidden-import", "msgraph.generated",
            "--hidden-import", "pandas",
            "--hidden-import", "pandas._libs",
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
        
        print("🔨 Running PyInstaller...")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
        
        if result.returncode == 0:
            print("✅ macOS build successful!")

            # Clean up build directory to free disk space before packaging
            shutil.rmtree(self.project_root / "build" / "macos", ignore_errors=True)

            # Find the executable
            dist_dir = self.project_root / "dist" / "macos"
            exec_files = [f for f in dist_dir.iterdir() if f.is_file() and not f.name.startswith('.')]

            if exec_files:
                exec_path = exec_files[0]
                os.chmod(exec_path, 0o755)  # Make executable

                size_mb = exec_path.stat().st_size / (1024*1024)
                print(f"📁 Executable: {exec_path.name}")
                print(f"📏 Size: {size_mb:.1f} MB")

                # Create DMG
                self.create_macos_dmg(exec_path)

                return True
        else:
            print("❌ macOS build failed!")
            print("STDERR:", result.stderr[-500:])
            
        return False
    
    def create_macos_dmg(self, exec_path: Path):
        """Create macOS DMG file"""
        print("\n💾 Creating macOS DMG...")
        
        try:
            import subprocess
            
            # Create .app bundle structure
            app_name = "EntraLense.app"
            app_path = self.project_root / "dist" / app_name
            
            # Clean up old .app if exists
            shutil.rmtree(app_path, ignore_errors=True)
            
            # Create .app structure
            (app_path / "Contents" / "MacOS").mkdir(parents=True, exist_ok=True)
            (app_path / "Contents" / "Resources").mkdir(parents=True, exist_ok=True)
            
            # Copy executable
            shutil.copy2(exec_path, app_path / "Contents" / "MacOS" / "EntraLense")
            os.chmod(app_path / "Contents" / "MacOS" / "EntraLense", 0o755)
            
            # Create Info.plist
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
    <string>EntraLense</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright © 2026 ThisByte, LLC. All rights reserved.</string>
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
            
            print(f"✅ DMG created: {dmg_path.name}")
            print(f"📏 DMG size: {dmg_path.stat().st_size / (1024*1024):.1f} MB")
            
            # Clean up .app
            shutil.rmtree(app_path, ignore_errors=True)
            
            # Create portable version
            self.create_macos_portable(exec_path)
            
        except Exception as e:
            print(f"⚠️ Could not create DMG: {e}")
            print("   Creating portable package instead...")
            self.create_macos_portable(exec_path)
    
    def create_macos_portable(self, exec_path: Path):
        """Create portable macOS package"""
        print("\n📦 Creating macOS portable package...")
        
        portable_dir = self.project_root / "dist" / "EntraLense_Portable_macOS"
        shutil.rmtree(portable_dir, ignore_errors=True)
        portable_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy executable
        shutil.copy2(exec_path, portable_dir / "EntraLense")
        os.chmod(portable_dir / "EntraLense", 0o755)

        # Copy config and data directories
        if (self.project_root / "config").exists():
            shutil.copytree(self.project_root / "config", portable_dir / "config")
        else:
            (portable_dir / "config").mkdir(exist_ok=True)
        if (self.project_root / "data").exists():
            shutil.copytree(self.project_root / "data", portable_dir / "data")
        else:
            (portable_dir / "data").mkdir(exist_ok=True)

        # Create necessary directories
        (portable_dir / "exports").mkdir(exist_ok=True)
        (portable_dir / "logs").mkdir(exist_ok=True)
        
        # Create README
        readme_content = f"""# EntraLense - macOS Portable Version {self.version}

## 🚀 Quick Start
1. Open Terminal
2. Navigate to this folder: `cd /path/to/EntraLense_Portable_macOS`
3. Run: `./EntraLense`
4. Or double-click `Launch.command`

## 🔧 First-Time Setup
If you get "permission denied":
```bash
chmod +x EntraLense
chmod +x Launch.command
```

## 🔐 Azure Setup Required
Before first use, you need:
1. Azure Tenant ID
2. Azure Client ID
3. (Optional) Client Secret

Get these from: https://portal.azure.com → Azure AD → App registrations

## 📁 Directory Structure
- `EntraLense` - Main application
- `Launch.command` - Double-click launcher
- `config/` - Configuration files (auto-created)
- `exports/` - CSV reports (auto-created)
- `logs/` - Application logs (auto-created)

## 🔄 Updates
Check https://thisbyte.com/entralense for updates

## 📧 Support
Email: stephen.cantoria@thisbyte.com

---
EntraLense v{self.version} | The Full Stack and Beneath
"""

        (portable_dir / "README.txt").write_text(readme_content)

        # Create launch script for macOS
        launch_content = """#!/bin/bash
echo "EntraLense v1.0.0 - Azure AD Audit Tool"
echo "========================================"
echo ""
cd "$(dirname "$0")"
./EntraLense
"""

        launch_path = portable_dir / "Launch.command"
        launch_path.write_text(launch_content)
        os.chmod(launch_path, 0o755)

        # Create ZIP archive
        import zipfile
        zip_path = self.project_root / "dist" / f"EntraLense_macOS_Portable_v{self.version}.zip"

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in portable_dir.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(portable_dir)
                    zipf.write(file_path, arcname)

        print(f"✅ Portable package: {zip_path.name}")
        print(f"📏 Package size: {zip_path.stat().st_size / (1024*1024):.1f} MB")

        # Clean up
        shutil.rmtree(portable_dir, ignore_errors=True)

    def build_all(self):
        """Run all build steps"""
        print("\n" + "="*60)
        print("🚀 EntraLense Build System")
        print(f"   Version: {self.version}")
        print(f"   Platform: {platform.system()}")
        print("="*60)

        self.setup_environment()
        self.create_icons()

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


if __name__ == "__main__":
    builder = EntraLenseBuilder()
    builder.build_all()
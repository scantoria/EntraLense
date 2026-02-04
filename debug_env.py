# debug_env.py
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file
load_dotenv()

print("🔍 Debug: Environment Variables")
print("=" * 50)

# Show current directory
print(f"Current directory: {Path.cwd()}")

# List .env files
env_files = list(Path.cwd().glob("*.env")) + list(Path.cwd().glob(".env"))
print(f"\n.env files found: {[f.name for f in env_files]}")

# Check for our variables
print("\nLooking for EntraLense variables:")
print(f"ENTRA_TENANT_ID: {os.getenv('ENTRA_TENANT_ID', 'NOT FOUND')}")
print(f"ENTRA_CLIENT_ID: {os.getenv('ENTRA_CLIENT_ID', 'NOT FOUND')}")
print(f"ENTRA_CLIENT_SECRET: {'FOUND' if os.getenv('ENTRA_CLIENT_SECRET') else 'NOT FOUND'}")

# Show all environment variables (filtered)
print("\nAll ENV variables (filtered for ENTRA/AZURE):")
for key, value in sorted(os.environ.items()):
    if any(k in key.upper() for k in ['ENTRA', 'AZURE', 'TENANT', 'CLIENT']):
        masked = value[:4] + "***" + value[-4:] if len(value) > 8 else "***"
        print(f"  {key}: {masked}")
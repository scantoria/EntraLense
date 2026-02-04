# setup_credentials.py
import os

# Set credentials directly
os.environ['ENTRA_TENANT_ID'] = 'c8916135-4eca-4f93-af7f-283d9952deac'
os.environ['ENTRA_CLIENT_ID'] = '12ea1c92-4506-42c4-9e34-4a9543cef92d'

print("✅ Credentials set in environment")
print(f"TENANT_ID: {os.getenv('ENTRA_TENANT_ID')}")
print(f"CLIENT_ID: {os.getenv('ENTRA_CLIENT_ID')}")

# Now test
from modules.config_manager import test_config_module
test_config_module()
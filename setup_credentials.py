# setup_credentials.py
import os

# Set your Azure credentials here (do NOT commit real values to source control)
os.environ['ENTRA_TENANT_ID'] = 'YOUR_TENANT_ID_HERE'
os.environ['ENTRA_CLIENT_ID'] = 'YOUR_CLIENT_ID_HERE'

print("Credentials set in environment")
print(f"TENANT_ID: {os.getenv('ENTRA_TENANT_ID')}")
print(f"CLIENT_ID: {os.getenv('ENTRA_CLIENT_ID')}")

# Now test
from modules.config_manager import test_config_module
test_config_module()

# EntraLense v1.0 - Setup Guide

## Quick Start

### For New Users:
1. Download EntraLense for your platform (Windows .exe or macOS executable)
2. Run the application
3. Follow the **Setup Wizard** to configure Azure AD credentials
4. Start generating compliance reports!

### For IT Administrators:
Follow the detailed setup instructions below for enterprise deployment.

## Detailed Setup Instructions

### Step 1: Azure AD App Registration

1. Navigate to: **https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade**
2. Click **"New registration"**
3. Enter a name: `EntraLense Compliance Tool`
4. Supported account types: **Accounts in this organizational directory only**
5. Redirect URI: Leave blank (we use client credentials)
6. Click **"Register"**

### Step 2: Configure API Permissions

Add these **Application Permissions**:

| Category | Permission | Reason |
|----------|------------|--------|
| User Reports | `User.Read.All` | User inventory and MFA compliance |
| User Reports | `AuditLog.Read.All` | Sign-in activity tracking |
| Email/Exchange | `Exchange.Manage` | PowerShell mail flow auditing |
| Equipment | `DeviceManagementManagedDevices.Read.All` | Intune device inventory |
| Equipment | `DeviceManagementConfiguration.Read.All` | Compliance policy auditing |
| Service Health | `ServiceHealth.Read.All` | Service status monitoring |

**Important:** Click **"Grant admin consent"** after adding permissions.

### Step 3: Create Client Secret

1. In your App Registration, go to **"Certificates & secrets"**
2. Click **"New client secret"**
3. Enter a description: `EntraLense Production`
4. Select expiry: **24 months** (recommended)
5. Click **"Add"**
6. **IMPORTANT:** Copy the **Secret Value** immediately (you won't see it again)

### Step 4: Application Setup

1. Run `EntraLense.exe` (Windows) or `./EntraLense` (macOS)
2. The Setup Wizard will automatically launch
3. Enter:
   - **Tenant ID**: From Azure AD Overview
   - **Client ID**: From App Registration Overview
   - **Client Secret**: The value you copied in Step 3
4. The wizard will validate your credentials
5. Configuration is saved securely to `.env` file

## Troubleshooting

### Common Issues:

#### "Invalid client secret"
- Create a new client secret in Azure Portal
- Ensure you're copying the **Value**, not the Secret ID
- Check if the secret has expired

#### "Application not found"
- Verify Tenant ID and Client ID are correct
- Ensure App Registration exists in the specified tenant
- Check for typos in the IDs

#### "Insufficient permissions"
- Admin consent is required for Application permissions
- Have an Azure AD administrator grant consent
- Verify all required permissions are added

#### "Multi-factor authentication required"
- Use Client Credentials flow (not interactive)
- Ensure you're using a client secret, not user credentials
- The service principal doesn't support MFA

### Advanced Configuration:

#### Manual .env File Creation
If you need to configure manually, create a `.env` file:

```env
ENTRA_TENANT_ID="your-tenant-id"
ENTRA_CLIENT_ID="your-client-id"
ENTRA_CLIENT_SECRET="your-client-secret"
ENTRA_USE_INTERACTIVE_AUTH="false"
```

#### Configuration File Location
- Primary: `.env` in application directory
- Backup: `config/entralense_config.json`
- Exports: `exports/` directory

## Security Considerations

### Credential Security
- `.env` file has restricted permissions (600)
- Client secrets are never displayed in logs
- No credentials are transmitted outside Azure AD
- Consider using Azure Key Vault for production

### Permission Principle
- All permissions are read-only
- Follows principle of least privilege
- Regular permission audits recommended

### Network Security
- Requires outbound HTTPS to login.microsoftonline.com and graph.microsoft.com
- No inbound ports required
- Supports proxy configurations via environment variables

## Updating Credentials

To update credentials after initial setup:

1. Run EntraLense
2. Select **Option 9: Reconfigure Credentials** from main menu
3. Follow the setup wizard
4. Existing reports and configurations are preserved

## Support

For additional help:
- Check the `docs/` directory for detailed guides
- Review error messages in the application
- Contact your Azure AD administrator
- Open an issue on GitHub: https://github.com/scantoria/EntraLense

## License Requirements

Some features require Azure AD licenses:
- Sign-in logs: Azure AD Premium P1/P2
- Intune device management: Microsoft Intune license
- Exchange Online reports: Exchange Online license

Check your organization's licensing before deployment.

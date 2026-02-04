# test_auth.py
"""
Test Azure AD authentication with your credentials.
"""
import asyncio
import os
from dotenv import load_dotenv
from azure.identity import InteractiveBrowserCredential, DeviceCodeCredential
from msgraph import GraphServiceClient

load_dotenv()

async def test_authentication():
    """Test Azure AD authentication"""
    print("🧪 Testing Azure AD Authentication...")
    print("=" * 50)

    # Your credentials from environment
    tenant_id = os.getenv("ENTRA_TENANT_ID")
    client_id = os.getenv("ENTRA_CLIENT_ID")

    if not tenant_id or not client_id:
        print("❌ Missing credentials in environment")
        print("TENANT_ID:", tenant_id)
        print("CLIENT_ID:", client_id)
        return False

    print(f"Tenant ID: {tenant_id}")
    print(f"Client ID: {client_id}")

    print("\n🔐 Choose authentication method:")
    print("1. Interactive (Browser will open)")
    print("2. Device Code (Copy code from terminal)")
    choice = input("Enter 1 or 2: ").strip()

    try:
        if choice == "2":
            print("\n📱 Using Device Code flow...")
            credential = DeviceCodeCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                prompt_callback=lambda x: print(
                    f"\n🔗 Please visit: {x.verification_uri}\n"
                    f"📝 Enter this code: {x.user_code}\n"
                )
            )
        else:
            print("\n🔐 Using Interactive authentication...")
            print("A browser window will open for you to sign in.")
            credential = InteractiveBrowserCredential(
                tenant_id=tenant_id,
                client_id=client_id
            )

        # Create Graph client
        graph_client = GraphServiceClient(credential)

        # Try to get current user (tests connection)
        print("\n📡 Testing Graph API connection...")
        user = await graph_client.me.get()

        print(f"✅ Authentication successful!")
        print(f"👤 User: {user.display_name}")
        print(f"📧 Email: {user.user_principal_name}")

        # Try to get a few users
        print("\n📋 Testing user enumeration...")
        users = await graph_client.users.get()
        print(f"✅ Found {len(users.value)} users in tenant")

        if users.value:
            print("\nFirst 3 users:")
            for i, user in enumerate(users.value[:3]):
                print(f"  {i+1}. {user.display_name} ({user.user_principal_name})")

        print("\n🎉 All tests passed! EntraLense is ready to go.")
        return True

    except Exception as e:
        print(f"\n❌ Authentication failed: {str(e)}")
        print("\n🔧 Troubleshooting steps:")
        print("1. Verify Tenant ID and Client ID are correct")
        print("2. Check Azure Portal → App registrations")
        print("3. Ensure API permissions are granted (User.Read.All, etc.)")
        print("4. Check if admin consent is required")
        print(f"\n📋 Error details: {type(e).__name__}")
        return False

async def main():
    """Main test function"""
    success = await test_authentication()
    if not success:
        print("\n🚫 Please fix the issues above before continuing.")
        print("Need help? Let me know the error message.")

if __name__ == "__main__":
    asyncio.run(main())

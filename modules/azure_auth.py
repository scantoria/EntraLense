# modules/azure_auth.py
"""
Azure AD authentication and Graph client management.
"""
from datetime import datetime
from typing import Optional, TYPE_CHECKING
from azure.identity import (
    InteractiveBrowserCredential,
    ClientSecretCredential,
    DeviceCodeCredential,
)
from msgraph.graph_service_client import GraphServiceClient

if TYPE_CHECKING:
    from modules.config_manager import EntraConfig

class EntraAuthError(Exception):
    """Custom exception for authentication errors"""
    pass

def _device_code_prompt(verification_uri: str, user_code: str, expires_on: datetime) -> None:
    """Display device code authentication prompt."""
    print(f"\n📱 Please visit: {verification_uri}")
    print(f"📝 Enter code: {user_code}\n")

class EntraAuth:
    """Manages Azure AD authentication and Graph client"""

    config: Optional["EntraConfig"]
    graph_client: Optional[GraphServiceClient]

    def __init__(self):
        self.config = None
        self.graph_client = None
        
    async def authenticate(self) -> GraphServiceClient:
        """Authenticate and return Graph client"""
        if self.graph_client:
            return self.graph_client
            
        if not self.config or not self.config.tenant_id or not self.config.client_id:
            raise EntraAuthError("Missing Azure credentials.")
        
        try:
            if self.config.use_interactive_auth:
                print("🔐 Using interactive authentication...")
                credential = InteractiveBrowserCredential(
                    tenant_id=self.config.tenant_id,
                    client_id=self.config.client_id
                )
            elif self.config.client_secret:
                print("🔐 Using client secret authentication...")
                credential = ClientSecretCredential(
                    tenant_id=self.config.tenant_id,
                    client_id=self.config.client_id,
                    client_secret=self.config.client_secret
                )
            else:
                # Fallback to device code flow
                print("🔐 Using device code authentication...")
                credential = DeviceCodeCredential(
                    tenant_id=self.config.tenant_id,
                    client_id=self.config.client_id,
                    prompt_callback=_device_code_prompt
                )
            
            # Create Graph client
            self.graph_client = GraphServiceClient(credential)
            
            # Test connection (await properly)
            await self._test_connection()
            
            return self.graph_client
            
        except Exception as e:
            raise EntraAuthError(f"Authentication failed: {str(e)}")
    
    async def _test_connection(self):
        """Test the Graph connection by fetching current user"""
        try:
            if not self.graph_client:
                return
            user = await self.graph_client.me.get()
            if user:
                print(f"✅ Authenticated as: {user.display_name}")
        except Exception as e:
            print(f"⚠️ Note: {e}")
            print("   (This may be normal for app-only permissions)")
    
    async def get_graph_client(self) -> GraphServiceClient:
        """Get or create Graph client"""
        if not self.graph_client:
            self.graph_client = await self.authenticate()  # AWAIT here
        return self.graph_client

# Global instance
entra_auth = EntraAuth()
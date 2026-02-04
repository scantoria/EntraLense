# EntraLense Project Design Document

## 1. System Overview

### 1.1 Purpose
EntraLense is a security compliance and auditing tool for Microsoft Entra ID (Azure AD) that generates CSV-based reports for compliance teams, security auditors, and IT administrators.

### 1.2 Architecture Style
**Layered Architecture** with the following tiers:
- Presentation Layer (Console UI)
- Business Logic Layer (Report Generation)
- Integration Layer (Azure AD Authentication & Graph API)
- Configuration Layer (Settings Management)

### 1.3 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      EntraLense Application                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Presentation Layer (console_ui.py)          │   │
│  │  - Interactive menu system                               │   │
│  │  - Color-coded output                                    │   │
│  │  - Progress display                                      │   │
│  │  - Table formatting                                      │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           Business Logic Layer (user_reports.py)         │   │
│  │  - Report generation logic                               │   │
│  │  - Data transformation                                   │   │
│  │  - CSV export                                            │   │
│  │  - Statistics calculation                                │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │            Integration Layer (azure_auth.py)             │   │
│  │  - Azure AD authentication                               │   │
│  │  - Microsoft Graph API client                            │   │
│  │  - Token management                                      │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │          Configuration Layer (config_manager.py)         │   │
│  │  - Credential storage                                    │   │
│  │  - Settings persistence                                  │   │
│  │  - Environment variable loading                          │   │
│  └─────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                      External Services                           │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │  Microsoft Graph │  │   Azure AD       │  │  PowerShell  │  │
│  │       API        │  │   (Entra ID)     │  │    Core      │  │
│  └──────────────────┘  └──────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Design

### 2.1 Main Application (entra_lense.py)

**Responsibilities:**
- Application entry point and lifecycle management
- Menu orchestration and navigation
- Async event loop management
- Report execution coordination

**Class: EntraLense**
```python
class EntraLense:
    """Main application controller"""

    def __init__(self):
        self.config: EntraConfig
        self.reports: UserReports
        self.ui: ConsoleUI

    async def run(self) -> None:
        """Main application loop"""

    async def main_menu(self) -> None:
        """Display and handle main menu"""

    async def users_menu(self) -> None:
        """User reports submenu"""

    async def email_menu(self) -> None:
        """Email reports submenu"""

    async def equipment_menu(self) -> None:
        """Equipment reports submenu"""
```

**Menu Structure:**
```
Main Menu
├── Users Reports
│   ├── Login Activity Report
│   ├── Privileged Access Inventory
│   ├── MFA Status Report
│   ├── License Usage Report
│   ├── User Security Groups
│   └── User Status Report
├── Email Reports
│   ├── Mailbox Sizes
│   ├── External Sharing Rules
│   └── Distribution Lists
├── Equipment Reports (Planned)
│   ├── Device Encryption Status
│   ├── Compliance Policy Status
│   ├── OS Version Report
│   └── Asset Tracking
├── Settings
└── Exit
```

---

### 2.2 Authentication Module (modules/azure_auth.py)

**Responsibilities:**
- Azure AD credential management
- Graph API client initialization
- Connection testing and validation

**Class: EntraAuth**
```python
class EntraAuth:
    """Azure AD authentication handler"""

    def __init__(self):
        self._client: GraphServiceClient = None
        self._credential: TokenCredential = None

    def authenticate(self, config: EntraConfig) -> bool:
        """Authenticate with Azure AD"""

    def get_client(self) -> GraphServiceClient:
        """Get authenticated Graph client (lazy initialization)"""

    async def test_connection(self) -> Dict[str, Any]:
        """Verify authentication and return user info"""
```

**Authentication Flows:**

```
┌─────────────────────────────────────────────────────────────┐
│                  Authentication Decision Flow                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────┐                                       │
│  │  Has Client      │──Yes──► Client Secret Credential      │
│  │  Secret?         │         (App-Only Flow)               │
│  └──────────────────┘                                       │
│           │ No                                               │
│           ▼                                                  │
│  ┌──────────────────┐                                       │
│  │  Interactive     │──Yes──► Interactive Browser           │
│  │  Auth Enabled?   │         Credential                    │
│  └──────────────────┘                                       │
│           │ No                                               │
│           ▼                                                  │
│  ┌──────────────────┐                                       │
│  │  Device Code     │                                       │
│  │  Credential      │                                       │
│  │  (Fallback)      │                                       │
│  └──────────────────┘                                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

### 2.3 Report Generation Module (modules/user_reports.py)

**Responsibilities:**
- Fetch data from Microsoft Graph API
- Transform and process data
- Generate statistics and summaries
- Export to CSV format

**Class: UserReports**
```python
class UserReports:
    """User report generation engine"""

    def __init__(self, auth: EntraAuth, config: EntraConfig):
        self.auth = auth
        self.config = config

    async def get_login_activity(self, **options) -> Dict[str, Any]:
        """Generate login activity report"""

    async def get_privileged_access_inventory(self, **options) -> Dict[str, Any]:
        """Generate privileged access report"""

    async def get_mfa_status(self, **options) -> Dict[str, Any]:
        """Generate MFA status report"""

    async def get_license_usage(self, **options) -> Dict[str, Any]:
        """Generate license usage report"""

    async def get_user_security_groups(self, **options) -> Dict[str, Any]:
        """Generate security groups report"""

    async def get_user_status_report(self, **options) -> Dict[str, Any]:
        """Generate user status report"""
```

**Report Return Structure:**
```python
{
    "dataframe": pd.DataFrame,      # Processed data
    "raw_data": List[Dict],         # Original API responses
    "statistics": {                 # Summary metrics
        "total_users": int,
        "processed": int,
        "errors": int,
        # Report-specific stats...
    },
    "csv_path": str | None,         # Export file path
    "generated_at": datetime        # Timestamp
}
```

---

### 2.4 Configuration Module (modules/config_manager.py)

**Responsibilities:**
- Load and save configuration
- Manage environment variables
- Provide setup wizard for first-time users

**Data Class: EntraConfig**
```python
@dataclass
class EntraConfig:
    tenant_id: str
    client_id: str
    client_secret: str = ""
    use_interactive_auth: bool = True
    max_users: int = 5000
    export_path: str = "./exports"
    dark_mode: bool = True
    last_report_type: str = ""
```

**Class: ConfigManager**
```python
class ConfigManager:
    """Configuration persistence manager"""

    CONFIG_FILE = "config/entralense_config.json"

    def load_config(self) -> EntraConfig:
        """Load configuration from file or environment"""

    def save_config(self, config: EntraConfig) -> None:
        """Persist configuration to file"""

    def interactive_setup(self) -> EntraConfig:
        """First-time setup wizard"""

    def _load_from_env(self) -> EntraConfig | None:
        """Load from environment variables"""
```

**Configuration Precedence:**
```
1. Saved JSON config file (config/entralense_config.json)
         │
         ▼ (if not found)
2. Environment variables (ENTRA_TENANT_ID, etc.)
         │
         ▼ (if not found)
3. Interactive setup wizard
```

---

### 2.5 Console UI Module (modules/console_ui.py)

**Responsibilities:**
- Terminal output formatting
- Color-coded messages
- Menu display and input handling
- Table rendering

**Class: ConsoleUI**
```python
class ConsoleUI:
    """Console presentation utilities"""

    def __init__(self, dark_mode: bool = True):
        self.dark_mode = dark_mode
        colorama.init(autoreset=True)

    def clear_screen(self) -> None:
        """Clear terminal screen"""

    def print_header(self, text: str) -> None:
        """Display styled header"""

    def print_message(self, text: str, msg_type: str = "info") -> None:
        """Display color-coded message"""

    def display_menu(self, options: List[str], title: str) -> int:
        """Display menu and get selection"""

    def print_table(self, data: List[List], headers: List[str]) -> None:
        """Render simple table"""
```

**Color Scheme:**
```
Message Type    Dark Mode           Light Mode
──────────────────────────────────────────────
info            Cyan                Blue
success         Green               Green
warning         Yellow              Yellow
error           Red                 Red
header          White (Bold)        Black (Bold)
```

---

## 3. Data Flow

### 3.1 Report Generation Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  User Input  │────►│  EntraLense  │────►│  UserReports │
│  (Menu)      │     │  (Main App)  │     │  (Logic)     │
└──────────────┘     └──────────────┘     └──────────────┘
                                                  │
                                                  ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  CSV File    │◄────│  DataFrame   │◄────│  Graph API   │
│  (Export)    │     │  (pandas)    │     │  (Data)      │
└──────────────┘     └──────────────┘     └──────────────┘
```

### 3.2 Authentication Flow

```
┌─────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────┐
│  Config │────►│  EntraAuth  │────►│   Azure     │────►│  Graph  │
│  Load   │     │  Init       │     │   Identity  │     │  Client │
└─────────┘     └─────────────┘     └─────────────┘     └─────────┘
                                           │
                                           ▼
                                    ┌─────────────┐
                                    │  Token      │
                                    │  (Cached)   │
                                    └─────────────┘
```

---

## 4. API Integration

### 4.1 Microsoft Graph API Endpoints

| Endpoint | Purpose | Method |
|----------|---------|--------|
| `/users` | User profiles | GET |
| `/users/{id}/signInActivity` | Sign-in timestamps | GET |
| `/users/{id}/memberOf` | Group/role membership | GET |
| `/users/{id}/authentication/methods` | MFA methods | GET |
| `/directoryRoles` | Directory role definitions | GET |
| `/auditLogs/signIns` | Sign-in audit logs | GET |

### 4.2 API Request Pattern

```python
async def fetch_users(client: GraphServiceClient) -> List[User]:
    """Fetch users with pagination handling"""
    users = []
    request = client.users.get(
        query_parameters=UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
            select=["id", "displayName", "userPrincipalName", "signInActivity"],
            top=999
        )
    )

    while request:
        response = await request
        users.extend(response.value)
        request = response.odata_next_link  # Handle pagination

    return users
```

---

## 5. File Structure

```
EntraLense/
├── entra_lense.py              # Main application entry point
├── modules/
│   ├── __init__.py             # Package initialization
│   ├── azure_auth.py           # Authentication module
│   ├── config_manager.py       # Configuration management
│   ├── console_ui.py           # Console UI utilities
│   └── user_reports.py         # Report generation engine
├── SecurityCompliancePortal.ps1 # PowerShell scripts
├── build_all.py                # Build automation
├── EntraLense.spec             # PyInstaller config
├── requirements.txt            # Python dependencies
├── .env                        # Environment variables (not in git)
├── config/                     # Runtime configuration
│   └── entralense_config.json  # Persisted settings
├── exports/                    # Generated CSV reports
├── logs/                       # Application logs
├── assets/                     # Icons and resources
│   ├── icon.ico               # Windows icon
│   └── icon.icns              # macOS icon
└── docs/                       # Documentation
    ├── PROJECT_PLAN.md
    ├── PROJECT_REQUIREMENTS.md
    └── PROJECT_DESIGN.md
```

---

## 6. Error Handling Strategy

### 6.1 Error Categories

| Category | Example | Handling |
|----------|---------|----------|
| Authentication | Invalid credentials | Display error, prompt re-auth |
| API | Rate limiting | Retry with exponential backoff |
| License | Premium required | Inform user, suggest alternatives |
| Network | Connection timeout | Retry with timeout, fail gracefully |
| Data | Missing field | Use default value, log warning |

### 6.2 Error Handling Pattern

```python
async def safe_api_call(operation: Callable) -> Optional[Any]:
    """Wrap API calls with error handling"""
    try:
        return await operation()
    except ODataError as e:
        if "Premium" in str(e):
            ui.print_message("Azure AD Premium license required", "warning")
        else:
            ui.print_message(f"API Error: {e.message}", "error")
        return None
    except Exception as e:
        ui.print_message(f"Unexpected error: {str(e)}", "error")
        logging.exception("API call failed")
        return None
```

---

## 7. Security Considerations

### 7.1 Credential Handling
- Client secrets stored in local JSON file with user-only permissions
- Support for environment variables (CI/CD friendly)
- Never log or display secrets in plain text
- Secrets excluded from version control via .gitignore

### 7.2 API Permissions
- Follow principle of least privilege
- Read-only permissions only
- No write/modify permissions required
- Document required permissions clearly

### 7.3 Data Protection
- Generated CSVs may contain PII
- User responsible for securing exports
- No data transmitted except to Microsoft Graph API

---

## 8. Performance Considerations

### 8.1 Current Implementation
- Sequential user processing
- Batch size limit (default: 5,000 users)
- Lazy-loaded Graph client

### 8.2 Future Optimizations
- Concurrent API requests using asyncio.gather()
- Response caching for repeated queries
- Incremental report updates (delta queries)
- Background report generation

---

## 9. Extensibility

### 9.1 Adding New Reports
1. Add method to `UserReports` class
2. Add menu option in `entra_lense.py`
3. Define required Graph API queries
4. Implement data transformation logic
5. Add to batch report generation

### 9.2 Adding New Authentication Methods
1. Extend `EntraAuth.authenticate()` method
2. Add configuration option in `EntraConfig`
3. Update setup wizard if needed

### 9.3 Adding New Export Formats
1. Create export method in `UserReports`
2. Add format selection to menu
3. Implement format-specific writer

---

## 10. Testing Strategy

### 10.1 Unit Tests
- Configuration loading/saving
- Data transformation logic
- UI formatting functions

### 10.2 Integration Tests
- Authentication flow
- API connectivity
- CSV export functionality

### 10.3 Manual Testing
- End-to-end report generation
- Menu navigation
- Error handling scenarios

---

## 11. Deployment

### 11.1 Development
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 entra_lense.py
```

### 11.2 Production (Standalone)
```bash
python3 build_all.py
# Outputs:
#   dist/windows/EntraLense.exe
#   dist/macos/EntraLense
```

### 11.3 Distribution
- Windows: Single .exe file
- macOS: Single executable or .app bundle
- No Python installation required for end users

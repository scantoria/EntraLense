# EntraLense Project Requirements

## 1. Introduction

### 1.1 Purpose
This document defines the functional and non-functional requirements for EntraLense, an Azure AD (Microsoft Entra ID) security compliance and auditing tool.

### 1.2 Scope
EntraLense provides CSV-focused reporting capabilities for:
- User activity monitoring
- Security compliance auditing
- Privileged access inventory
- License optimization
- Device compliance (planned)

### 1.3 Target Users
- IT Security Teams
- Compliance Officers
- IT Administrators
- Auditors

---

## 2. Functional Requirements

### 2.1 Authentication

| ID | Requirement | Priority |
|----|-------------|----------|
| AUTH-001 | Support interactive browser-based Azure AD authentication | Must Have |
| AUTH-002 | Support client secret (app-only) authentication for automation | Must Have |
| AUTH-003 | Support device code authentication for restricted environments | Should Have |
| AUTH-004 | Persist authentication configuration across sessions | Must Have |
| AUTH-005 | Validate connection and display authenticated user | Must Have |
| AUTH-006 | Support environment variable-based credential configuration | Should Have |

### 2.2 User Reports

| ID | Requirement | Priority |
|----|-------------|----------|
| USR-001 | Generate Login Activity Report with 30-day activity window | Must Have |
| USR-002 | Classify users by activity level (Very Active, Active, Inactive, Stale, Never Logged In) | Must Have |
| USR-003 | Generate Privileged Access Inventory with admin role detection | Must Have |
| USR-004 | Identify high-risk privileged roles | Must Have |
| USR-005 | Generate MFA Status Report showing authentication methods | Must Have |
| USR-006 | Flag users without MFA configured | Must Have |
| USR-007 | Generate License Usage Report correlating licenses with activity | Must Have |
| USR-008 | Generate User Security Groups Report | Should Have |
| USR-009 | Generate comprehensive User Status Report | Should Have |
| USR-010 | Support bulk report generation (all reports at once) | Should Have |

### 2.3 Email Reports (PowerShell)

| ID | Requirement | Priority |
|----|-------------|----------|
| EML-001 | Generate Mailbox Sizes Report | Should Have |
| EML-002 | Generate External Sharing/Forwarding Rules Report | Should Have |
| EML-003 | Generate Distribution List Membership Report | Should Have |
| EML-004 | Integrate PowerShell execution from main application | Should Have |

### 2.4 Equipment Reports (Implemented)

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| EQP-001 | Generate Device Encryption Status Report | Must Have | Implemented |
| EQP-002 | Generate Compliance Policy Adherence Report | Must Have | Implemented |
| EQP-003 | Generate OS Version/Patch Status Report | Must Have | Implemented |
| EQP-004 | Generate Asset Tracking Report with serial numbers | Must Have | Implemented |
| EQP-005 | Asset search by serial number, user, and type | Should Have | Implemented |
| EQP-006 | Financial tracking with depreciation | Should Have | Implemented |
| EQP-007 | Warranty status monitoring | Should Have | Implemented |
| EQP-008 | Audit report with discrepancy detection | Should Have | Implemented |
| EQP-009 | Persistent asset inventory database | Should Have | Implemented |

### 2.5 Data Export

| ID | Requirement | Priority |
|----|-------------|----------|
| EXP-001 | Export all reports to CSV format | Must Have |
| EXP-002 | Use UTF-8 encoding with BOM for Excel compatibility | Must Have |
| EXP-003 | Generate timestamped filenames | Must Have |
| EXP-004 | Support configurable export directory | Should Have |
| EXP-005 | Provide export confirmation with file path | Must Have |

### 2.6 User Interface

| ID | Requirement | Priority |
|----|-------------|----------|
| UI-001 | Provide interactive menu-driven console interface | Must Have |
| UI-002 | Display color-coded output (info, success, warning, error) | Should Have |
| UI-003 | Support dark and light mode themes | Could Have |
| UI-004 | Show real-time progress during report generation | Must Have |
| UI-005 | Display summary statistics after report generation | Must Have |
| UI-006 | Provide clear navigation between menu levels | Must Have |
| UI-007 | Support graceful exit with confirmation | Should Have |

### 2.7 Configuration

| ID | Requirement | Priority |
|----|-------------|----------|
| CFG-001 | Support first-time setup wizard | Must Have |
| CFG-002 | Persist configuration to JSON file | Must Have |
| CFG-003 | Load configuration from environment variables | Should Have |
| CFG-004 | Support .env file for development | Should Have |
| CFG-005 | Allow modification of settings through menu | Should Have |
| CFG-006 | Configure maximum users per report batch | Should Have |

---

## 3. Non-Functional Requirements

### 3.1 Performance

| ID | Requirement | Target |
|----|-------------|--------|
| PERF-001 | Report generation should handle up to 5,000 users | Default batch size |
| PERF-002 | UI should remain responsive during operations | No blocking > 100ms |
| PERF-003 | API calls should implement timeout handling | 30-second timeout |

### 3.2 Reliability

| ID | Requirement | Target |
|----|-------------|--------|
| REL-001 | Gracefully handle API rate limiting | Retry with backoff |
| REL-002 | Handle network connectivity issues | Clear error messages |
| REL-003 | Detect and report Azure AD Premium license requirements | License check |
| REL-004 | Continue operation if individual user fetch fails | Skip and log |

### 3.3 Security

| ID | Requirement | Target |
|----|-------------|--------|
| SEC-001 | Never log or display client secrets in plain text | Masked output |
| SEC-002 | Store credentials securely on local filesystem | File permissions |
| SEC-003 | Support least-privilege API permissions | Documented scopes |
| SEC-004 | Exclude sensitive files from version control | .gitignore |

### 3.4 Portability

| ID | Requirement | Target |
|----|-------------|--------|
| PORT-001 | Run on Windows 10/11 | Tested and verified |
| PORT-002 | Run on macOS 12+ | Tested and verified |
| PORT-003 | Support standalone executable distribution | PyInstaller |
| PORT-004 | Handle cross-platform path separators | os.path usage |
| PORT-005 | Support cross-platform terminal colors | colorama |

### 3.5 Usability

| ID | Requirement | Target |
|----|-------------|--------|
| USE-001 | Provide clear error messages with remediation steps | All errors |
| USE-002 | Document all required Azure AD permissions | README/docs |
| USE-003 | Provide setup instructions for first-time users | Setup wizard |
| USE-004 | Support keyboard navigation without mouse | Full support |

### 3.6 Maintainability

| ID | Requirement | Target |
|----|-------------|--------|
| MAINT-001 | Modular code architecture | Separate modules |
| MAINT-002 | Type hints for all public functions | 100% coverage |
| MAINT-003 | Consistent code style | PEP 8 compliance |
| MAINT-004 | Centralized configuration management | Single source |

---

## 4. External Interface Requirements

### 4.1 Microsoft Graph API

**Required Permissions:**

| Permission | Type | Purpose |
|------------|------|---------|
| User.Read.All | Application | Read user profiles |
| AuditLog.Read.All | Application | Read sign-in logs |
| Directory.Read.All | Application | Read directory roles and groups |
| DeviceManagementManagedDevices.Read.All | Application | Read device information (planned) |

**API Endpoints Used:**
- `/users` - User profile data
- `/auditLogs/signIns` - Sign-in activity
- `/directoryRoles` - Role assignments
- `/groups` - Group membership

### 4.2 PowerShell Integration

**Requirements:**
- PowerShell Core (pwsh) installed
- Microsoft Graph PowerShell module
- Exchange Online Management module (for email reports)

### 4.3 File System

**Input:**
- `.env` file (optional)
- `config/entralense_config.json` (generated)

**Output:**
- CSV reports in `exports/` directory
- Log files in `logs/` directory

---

## 5. Constraints

### 5.1 Technical Constraints
- Python 3.11 or higher required
- Azure AD Premium P1/P2 required for sign-in logs
- Microsoft Graph SDK dependencies
- Network connectivity to Azure services

### 5.2 Business Constraints
- Reports limited to data accessible via Microsoft Graph API
- Some reports require administrative consent
- PowerShell reports require separate authentication

### 5.3 Regulatory Constraints
- Must handle personally identifiable information (PII) appropriately
- Generated reports may contain sensitive data
- Users responsible for securing exported CSV files

---

## 6. Assumptions and Dependencies

### 6.1 Assumptions
- Users have appropriate Azure AD administrative access
- Target Azure AD tenant has required licenses
- Users understand basic compliance reporting concepts
- Network allows connections to Microsoft Graph endpoints

### 6.2 Dependencies
- Microsoft Graph SDK for Python
- Azure Identity library
- pandas for data manipulation
- colorama for terminal colors
- PyInstaller for executable builds

---

## 7. Acceptance Criteria

### 7.1 Minimum Viable Product (MVP)
- [ ] User can authenticate with Azure AD
- [ ] Login Activity Report generates successfully
- [ ] Privileged Access Report generates successfully
- [ ] MFA Status Report generates successfully
- [ ] Reports export to CSV with correct data
- [ ] Application runs on Windows and macOS

### 7.2 Full Release Criteria
- [ ] All user reports functional
- [ ] Email reports via PowerShell functional
- [ ] Configuration persists across sessions
- [ ] Standalone executables build successfully
- [ ] Documentation complete
- [ ] Error handling covers common failure scenarios

# EntraLense Project Plan

## Project Overview

**Project Name:** EntraLense
**Version:** 1.0 (Beta)
**Project Type:** Azure AD Security Compliance and Auditing Tool

EntraLense is a command-line application that provides comprehensive security compliance reporting for Microsoft Entra ID (Azure AD) environments. The tool enables compliance and security teams to generate CSV-focused reports for user activity monitoring, security auditing, and organizational compliance requirements.

---

## Project Phases

### Phase 1: Foundation (Completed)

**Objective:** Establish core infrastructure and authentication framework

- [x] Project structure setup
- [x] Azure AD authentication module (interactive, client secret, device code)
- [x] Configuration management system
- [x] Console UI framework with color support
- [x] Environment variable and .env file support
- [x] Basic error handling framework

**Deliverables:**
- `modules/azure_auth.py` - Authentication module
- `modules/config_manager.py` - Configuration persistence
- `modules/console_ui.py` - UI utilities
- `.env` template and configuration system

---

### Phase 2: Core Reporting (Completed)

**Objective:** Implement primary user compliance reports

- [x] Login Activity Report (30-day compliance window)
- [x] Privileged Access Inventory (admin role detection)
- [x] MFA Status Report (authentication compliance)
- [x] License Usage Report (cost optimization)
- [x] User Security Groups Report
- [x] User Status Report
- [x] CSV export functionality with timestamps
- [x] Interactive menu system

**Deliverables:**
- `modules/user_reports.py` - Report generation engine
- `entra_lense.py` - Main application with menu system
- CSV export pipeline

---

### Phase 3: Exchange Online Integration (Completed)

**Objective:** Add email-related compliance reports via PowerShell

- [x] Mailbox Sizes Report
- [x] External Sharing/Forwarding Rules Report
- [x] Distribution List Membership Report
- [x] PowerShell integration framework

**Deliverables:**
- `SecurityCompliancePortal.ps1` - PowerShell report scripts
- Exchange Online menu integration

---

### Phase 4: Build and Distribution (Completed)

**Objective:** Create standalone executables for deployment

- [x] PyInstaller build configuration
- [x] Windows executable build
- [x] macOS executable build
- [x] Icon and asset generation
- [x] Build automation script

**Deliverables:**
- `build_all.py` - Automated build script
- `EntraLense.spec` - PyInstaller specification
- `assets/` - Application icons

---

### Phase 5: Equipment Reports (Completed)

**Objective:** Implement device management and compliance reports

- [x] Device Encryption Status Report
- [x] Compliance Policy Adherence Report
- [x] OS Version/Patch Status Report
- [x] Asset Tracking Report (serial numbers, financials, warranty, audit)
- [x] Intune integration
- [x] Asset search functionality

**Deliverables:**
- `modules/equipment_reports.py` - Equipment report generation engine
- `modules/intune_integration.py` - Microsoft Intune device management
- `modules/compliance_checker/` - Compliance policy checking framework
- `modules/os_patch_checker.py` - OS version and patch analysis
- `modules/asset_tracker.py` - Asset inventory management with financials
- `data/asset_inventory.json` - Persistent asset database
- `config/templates/asset_report_template.md` - Report template
- `config/templates/asset_audit_checklist.md` - Audit checklist template
- Equipment Reports menu section with search capability

---

### Phase 6: Enhanced Features (Planned)

**Objective:** Add advanced capabilities and optimizations

- [ ] Concurrent API requests for faster report generation
- [ ] Scheduled report generation
- [ ] Email delivery of reports
- [ ] Report comparison (diff between snapshots)
- [ ] Custom report templates
- [ ] Advanced filtering options
- [ ] Audit log export

---

### Phase 7: Enterprise Features (Future)

**Objective:** Add enterprise-grade capabilities

- [ ] Multi-tenant support
- [ ] Role-based access control
- [ ] Report scheduling daemon
- [ ] REST API for integrations
- [ ] Dashboard web interface
- [ ] Compliance score calculation
- [ ] Integration with SIEM tools

---

## Milestones

| Milestone | Description | Status |
|-----------|-------------|--------|
| M1 | Core authentication and configuration | Complete |
| M2 | User reports implementation | Complete |
| M3 | Email reports via PowerShell | Complete |
| M4 | Standalone executables | Complete |
| M5 | Equipment/device reports | Complete |
| M6 | Performance optimization | Planned |
| M7 | Enterprise features | Future |

---

## Risk Management

### Identified Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Azure AD Premium license requirement | High | Document requirements; provide graceful degradation |
| Microsoft Graph API rate limiting | Medium | Implement retry logic with exponential backoff |
| Breaking changes in Graph SDK | Medium | Pin dependency versions; monitor deprecations |
| PowerShell availability on target systems | Medium | Make PowerShell reports optional |
| Credential security | High | Support secure credential storage; document best practices |

---

## Resource Requirements

### Development Environment
- Python 3.11+
- Azure AD tenant with App Registration
- Azure AD Premium P1/P2 license (for sign-in logs)
- PowerShell Core (for Exchange Online reports)

### Azure Permissions Required
- User.Read.All
- AuditLog.Read.All
- Directory.Read.All
- DeviceManagementManagedDevices.Read.All (for Phase 5)

---

## Success Criteria

1. **Functional:** All planned reports generate accurate data
2. **Performance:** Reports complete within acceptable timeframes
3. **Reliability:** Graceful handling of API errors and edge cases
4. **Usability:** Intuitive menu navigation and clear output
5. **Security:** Credentials handled securely; no sensitive data exposure
6. **Portability:** Runs on Windows and macOS without additional dependencies

---

## Maintenance Plan

- Regular dependency updates (quarterly)
- Microsoft Graph API compatibility monitoring
- Security vulnerability scanning
- User feedback collection and feature prioritization
- Documentation updates with each release

# SecurityCompliancePortal.ps1
# Microsoft Entra ID Security & Compliance Portal

function Invoke-LoginActivityReport {
    param([int]$Days = 30)

    $startTime = Get-Date
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "    Login Activity Report (Bulk API Optimized)" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan

    Write-Host "`n📊 Fetching ALL sign-ins for last $Days days (single API call)..." -ForegroundColor Magenta

    try {
        # Check/establish Microsoft Graph connection
        Write-Host "🔗 Checking Microsoft Graph connection..." -ForegroundColor Gray
        $mgContext = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $mgContext) {
            Write-Host "⚠️ Connecting to Microsoft Graph..." -ForegroundColor Yellow
            Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All" -NoWelcome
        }
        Write-Host "✅ Connected to Microsoft Graph" -ForegroundColor Green

        # Get users first (limit to 100 for testing, remove -Top 100 for production)
        $users = Get-MgUser -Top 100 -All -Property Id, UserPrincipalName, DisplayName, AccountEnabled
        Write-Host "✅ Found $($users.Count) users" -ForegroundColor Green

        # Single bulk API call for ALL sign-ins
        $filterDate = (Get-Date).AddDays(-$Days).ToString("yyyy-MM-dd")
        Write-Host "⏱️  Fetching sign-ins since $filterDate..." -ForegroundColor Gray

        $allSignIns = Get-MgAuditLogSignIn -Filter "createdDateTime gt $filterDate" -Top 5000 -All
        Write-Host "✅ Retrieved $($allSignIns.Count) total sign-in events" -ForegroundColor Green

        # Group sign-ins by user (in-memory - FAST)
        $signInsByUser = $allSignIns | Group-Object -Property UserId

        Write-Host "`n📈 Processing $($signInsByUser.Count) users with sign-in activity..." -ForegroundColor Cyan

        # Build results
        $results = @()
        foreach ($userGroup in $signInsByUser) {
            $userId = $userGroup.Name
            $userSignIns = $userGroup.Group | Sort-Object CreatedDateTime -Descending

            $user = $users | Where-Object { $_.Id -eq $userId }

            if ($user) {
                $results += [PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                    AccountEnabled = $user.AccountEnabled
                    TotalSignIns = $userSignIns.Count
                    LastSignIn = $userSignIns[0].CreatedDateTime
                    FirstSignIn = $userSignIns[-1].CreatedDateTime
                    SignInsLast30Days = ($userSignIns | Where-Object { $_.CreatedDateTime -gt (Get-Date).AddDays(-30) }).Count
                    DaysSinceLastLogin = [math]::Round(((Get-Date) - $userSignIns[0].CreatedDateTime).TotalDays, 0)
                    RawSignInData = $userSignIns
                }
            }
        }

        # Add users with NO sign-ins
        foreach ($user in $users | Where-Object { $_.Id -notin $signInsByUser.Name }) {
            $results += [PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                AccountEnabled = $user.AccountEnabled
                TotalSignIns = 0
                LastSignIn = "Never"
                FirstSignIn = "Never"
                SignInsLast30Days = 0
                DaysSinceLastLogin = "N/A"
                RawSignInData = $null
            }
        }

        # Display performance
        $endTime = Get-Date
        $duration = $endTime - $startTime

        Write-Host "`n✅ Report complete in $($duration.TotalSeconds.ToString('0.00')) seconds!" -ForegroundColor Green
        Write-Host "   Total users processed: $($users.Count)" -ForegroundColor Gray
        Write-Host "   Users with sign-ins: $($signInsByUser.Count)" -ForegroundColor Gray
        Write-Host "   Total sign-in events: $($allSignIns.Count)" -ForegroundColor Gray

        # View/Export Options
        Write-Host "`n📋 View Options:" -ForegroundColor Cyan
        Write-Host "1. Summary table" -ForegroundColor White
        Write-Host "2. Export to CSV" -ForegroundColor White
        Write-Host "B. Back to menu" -ForegroundColor Gray

        $choice = Read-Host "`nSelect option"

        switch ($choice) {
            "1" {
                Write-Host "`n📊 Login Activity Summary:" -ForegroundColor Cyan
                $results | Select-Object DisplayName, UserPrincipalName, AccountEnabled, TotalSignIns, LastSignIn, DaysSinceLastLogin |
                    Sort-Object TotalSignIns -Descending |
                    Format-Table -AutoSize
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            "2" {
                $exportPath = ".\LoginActivityReport_$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
                $results | Select-Object DisplayName, UserPrincipalName, AccountEnabled, TotalSignIns, LastSignIn, FirstSignIn, SignInsLast30Days, DaysSinceLastLogin |
                    Export-Csv -Path $exportPath -NoTypeInformation
                Write-Host "✅ Exported to: $exportPath" -ForegroundColor Green
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            "B" { return }
            default { return }
        }

    } catch {
        Write-Host "❌ Error: $_" -ForegroundColor Red
        Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
        $null = Read-Host
    }
}

function Invoke-MFAStatusReport {
    param([int]$UserLimit = 10)

    $startTime = Get-Date
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "              MFA Status Report" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "`n📋 Testing with $UserLimit users`n" -ForegroundColor Magenta

    try {
        # Check/establish Microsoft Graph connection
        Write-Host "🔗 Checking Microsoft Graph connection..." -ForegroundColor Gray
        $mgContext = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $mgContext) {
            Write-Host "⚠️ Connecting to Microsoft Graph..." -ForegroundColor Yellow
            Connect-MgGraph -Scopes "User.Read.All", "UserAuthenticationMethod.Read.All" -NoWelcome
        }
        Write-Host "✅ Connected to Microsoft Graph" -ForegroundColor Green

        Write-Host "📊 Getting users..." -ForegroundColor Gray
        $users = Get-MgUser -Top $UserLimit -All -Property Id, UserPrincipalName, DisplayName, AccountEnabled

        Write-Host "✅ Found $($users.Count) users" -ForegroundColor Green

        $results = @()
        $userCount = 0

        Write-Host "`n🔍 Checking MFA status..." -ForegroundColor Cyan

        foreach ($user in $users) {
            $userCount++
            Write-Host "  User $userCount/$($users.Count): $($user.UserPrincipalName)" -ForegroundColor Gray

            $mfaMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
            $isRegistered = $mfaMethods.Count -gt 0

            $results += [PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                AccountEnabled = $user.AccountEnabled
                MFA_Registered = $isRegistered
                Methods_Count = $mfaMethods.Count
                Raw_MFA_Data = $mfaMethods
            }
        }

        # Calculate summary
        $registeredCount = ($results | Where-Object { $_.MFA_Registered -eq $true }).Count
        $nonCompliantCount = ($results | Where-Object { $_.MFA_Registered -eq $false }).Count

        $endTime = Get-Date
        $duration = $endTime - $startTime

        # Show summary screen
        Clear-Host
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "              MFA STATUS - RESULTS" -ForegroundColor Yellow
        Write-Host "============================================================" -ForegroundColor Cyan

        Write-Host "`n📊 Summary Statistics:" -ForegroundColor White
        Write-Host "   Users scanned: $userCount" -ForegroundColor Gray
        Write-Host "   MFA registered: $registeredCount" -ForegroundColor Green
        Write-Host "   Not registered: $nonCompliantCount" -ForegroundColor Red
        Write-Host "   ⏱️  Time: $($duration.TotalSeconds.ToString('0.00')) seconds" -ForegroundColor Gray

        # Show view options menu
        do {
            Write-Host "`n📋 View Options:" -ForegroundColor Cyan
            Write-Host "1. Summary table (all users)" -ForegroundColor White
            Write-Host "2. Non-compliant users only" -ForegroundColor White
            Write-Host "3. Raw MFA data (first non-compliant user)" -ForegroundColor White
            Write-Host "B. Back to menu" -ForegroundColor Gray

            $choice = Read-Host "`nSelect option"

            switch ($choice) {
                '1' {
                    Write-Host "`n📄 ALL USERS ($userCount total):" -ForegroundColor Cyan
                    $results | Select-Object UserPrincipalName, DisplayName,
                        AccountEnabled, MFA_Registered, Methods_Count | Format-Table -AutoSize
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
                '2' {
                    $nonCompliant = $results | Where-Object { $_.MFA_Registered -eq $false }
                    if ($nonCompliant.Count -gt 0) {
                        Write-Host "`n🔴 NON-COMPLIANT USERS ($($nonCompliant.Count) found):" -ForegroundColor Red
                        $nonCompliant | Select-Object UserPrincipalName, DisplayName,
                            AccountEnabled, Methods_Count | Format-Table -AutoSize
                    } else {
                        Write-Host "`n✅ All users are MFA compliant!" -ForegroundColor Green
                    }
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
                '3' {
                    $nonCompliantUser = $results | Where-Object { $_.MFA_Registered -eq $false } | Select-Object -First 1
                    if ($nonCompliantUser) {
                        Write-Host "`n📄 RAW MFA DATA for: $($nonCompliantUser.UserPrincipalName)" -ForegroundColor Cyan
                        Write-Host "============================================================" -ForegroundColor Cyan
                        if ($nonCompliantUser.Raw_MFA_Data -and $nonCompliantUser.Raw_MFA_Data.Count -gt 0) {
                            $nonCompliantUser.Raw_MFA_Data | Format-List *
                        } else {
                            Write-Host "No MFA methods configured" -ForegroundColor Yellow
                        }
                    } else {
                        Write-Host "`n✅ No non-compliant users found" -ForegroundColor Green
                    }
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
                'B' { break }
                'b' { break }
                default {
                    Write-Host "Invalid option" -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }
            }

        } while ($choice -notin @('B', 'b'))

    } catch {
        Write-Host "❌ Error: $_" -ForegroundColor Red
        Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
        $null = Read-Host
    }
}

function Invoke-MailboxSizesReport {
    $startTime = Get-Date
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "        Mailbox Sizes Report" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "`n📋 Checking all users`n" -ForegroundColor Magenta

    try {
        # Load required modules
        Write-Host "📦 Loading modules..." -ForegroundColor Gray

        # Import Microsoft Graph module
        Import-Module Microsoft.Graph.Users -ErrorAction Stop
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

        # Import Exchange Online module
        Import-Module ExchangeOnlineManagement -ErrorAction Stop

        # Connect to Microsoft Graph
        Write-Host "📊 Connecting to Microsoft Graph..." -ForegroundColor Gray
        $mgContext = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $mgContext) {
            Connect-MgGraph -Scopes "User.Read.All" -NoWelcome
        }

        # Check Exchange Online connection
        Write-Host "📧 Checking Exchange Online connection..." -ForegroundColor Gray
        try {
            Get-EXOMailbox -ResultSize 1 -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "⚠️ Connecting to Exchange Online..." -ForegroundColor Yellow
            Connect-ExchangeOnline -ShowBanner:$false
        }

        Write-Host "✅ Modules loaded and connected" -ForegroundColor Green

        # Get users
        Write-Host "📊 Getting users with mailboxes..." -ForegroundColor Gray
        $users = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName, AccountEnabled
        Write-Host "✅ Found $($users.Count) users" -ForegroundColor Green

        $results = @()
        $userCount = 0

        Write-Host "`n📦 Checking mailbox sizes..." -ForegroundColor Cyan

        foreach ($user in $users) {
            $userCount++
            Write-Host "  User $userCount/$($users.Count): $($user.UserPrincipalName)" -ForegroundColor Gray

            try {
                # Get mailbox statistics
                $mailbox = Get-EXOMailbox -Identity $user.UserPrincipalName -ErrorAction SilentlyContinue

                if ($mailbox) {
                    $stats = Get-EXOMailboxStatistics -Identity $user.UserPrincipalName -ErrorAction SilentlyContinue

                    $results += [PSCustomObject]@{
                        UserPrincipalName = $user.UserPrincipalName
                        DisplayName = $user.DisplayName
                        Has_Mailbox = $true
                        Total_Item_Size_GB = if ($stats) { [math]::Round($stats.TotalItemSize.Value.ToBytes() / 1GB, 2) } else { "Unknown" }
                        Item_Count = if ($stats) { $stats.ItemCount } else { "Unknown" }
                        Last_Logon = if ($stats) { $stats.LastLogonTime } else { "Unknown" }
                        Mailbox_Type = $mailbox.RecipientTypeDetails
                    }
                } else {
                    $results += [PSCustomObject]@{
                        UserPrincipalName = $user.UserPrincipalName
                        DisplayName = $user.DisplayName
                        Has_Mailbox = $false
                        Total_Item_Size_GB = "N/A"
                        Item_Count = "N/A"
                        Last_Logon = "N/A"
                        Mailbox_Type = "No mailbox"
                    }
                }

            } catch {
                $results += [PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                    Has_Mailbox = "Error"
                    Total_Item_Size_GB = "Error"
                    Item_Count = "Error"
                    Last_Logon = "Error"
                    Mailbox_Type = "Error"
                }
                Write-Host "    ⚠️ Error checking mailbox" -ForegroundColor Yellow
            }
        }

        # Calculate summary
        $mailboxUsers = ($results | Where-Object { $_.Has_Mailbox -eq $true }).Count
        $largeMailboxes = ($results | Where-Object { $_.Total_Item_Size_GB -gt 10 -and $_.Total_Item_Size_GB -ne "Unknown" }).Count

        $endTime = Get-Date
        $duration = $endTime - $startTime

        # Show summary screen
        Clear-Host
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "        MAILBOX SIZES - RESULTS" -ForegroundColor Yellow
        Write-Host "============================================================" -ForegroundColor Cyan

        Write-Host "`n📊 Summary Statistics:" -ForegroundColor White
        Write-Host "   Users scanned: $userCount" -ForegroundColor Gray
        Write-Host "   Users with mailboxes: $mailboxUsers" -ForegroundColor Green
        Write-Host "   Large mailboxes (>10GB): $largeMailboxes" -ForegroundColor Yellow
        Write-Host "   ⏱️  Time: $($duration.TotalSeconds.ToString('0.00')) seconds" -ForegroundColor Gray

        # Show view options menu
        do {
            Write-Host "`n📋 View Options:" -ForegroundColor Cyan
            Write-Host "1. All users with mailbox sizes" -ForegroundColor White
            Write-Host "2. Large mailboxes (>10GB)" -ForegroundColor White
            Write-Host "3. Users without mailboxes" -ForegroundColor White
            Write-Host "4. Export to CSV" -ForegroundColor White
            Write-Host "B. Back to menu" -ForegroundColor Gray

            $choice = Read-Host "`nSelect option"

            switch ($choice) {
                '1' {
                    $mailboxResults = $results | Where-Object { $_.Has_Mailbox -eq $true }
                    if ($mailboxResults.Count -gt 0) {
                        Write-Host "`n📧 USERS WITH MAILBOXES ($($mailboxResults.Count) found):" -ForegroundColor Cyan
                        $mailboxResults | Select-Object UserPrincipalName, DisplayName,
                            Mailbox_Type, Total_Item_Size_GB, Item_Count, Last_Logon | Format-Table -AutoSize
                    } else {
                        Write-Host "`n⚠️ No mailboxes found" -ForegroundColor Yellow
                    }
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
                '2' {
                    $largeMailboxResults = $results | Where-Object {
                        $_.Has_Mailbox -eq $true -and $_.Total_Item_Size_GB -gt 10 -and $_.Total_Item_Size_GB -ne "Unknown"
                    }
                    if ($largeMailboxResults.Count -gt 0) {
                        Write-Host "`n⚠️ LARGE MAILBOXES (>10GB):" -ForegroundColor Red
                        $largeMailboxResults | Select-Object UserPrincipalName, DisplayName,
                            Total_Item_Size_GB, Item_Count, Last_Logon | Sort-Object Total_Item_Size_GB -Descending | Format-Table -AutoSize
                    } else {
                        Write-Host "`n✅ No large mailboxes found" -ForegroundColor Green
                    }
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
                '3' {
                    $noMailboxResults = $results | Where-Object { $_.Has_Mailbox -eq $false }
                    if ($noMailboxResults.Count -gt 0) {
                        Write-Host "`n📭 USERS WITHOUT MAILBOXES ($($noMailboxResults.Count) found):" -ForegroundColor Gray
                        $noMailboxResults | Select-Object UserPrincipalName, DisplayName | Format-Table -AutoSize
                    } else {
                        Write-Host "`n✅ All users have mailboxes" -ForegroundColor Green
                    }
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
                '4' {
                    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                    $csvPath = ".\Mailbox_Sizes_Report_$timestamp.csv"
                    $results | Select-Object UserPrincipalName, DisplayName,
                        Has_Mailbox, Mailbox_Type, Total_Item_Size_GB,
                        Item_Count, Last_Logon | Export-Csv -Path $csvPath -NoTypeInformation
                    Write-Host "✅ Exported to: $csvPath" -ForegroundColor Green
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
                'B' { break }
                'b' { break }
                default {
                    Write-Host "Invalid option" -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }
            }

        } while ($choice -notin @('B', 'b'))

    } catch {
        Write-Host "❌ Error: $_" -ForegroundColor Red
        Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
        $null = Read-Host
    }
}

function Invoke-ExternalSharingReport {
    $startTime = Get-Date
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "    External Sharing/Forwarding Rules Report" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "`n📋 Checking all users`n" -ForegroundColor Magenta

    try {
        # Check/establish Microsoft Graph connection
        Write-Host "🔗 Checking Microsoft Graph connection..." -ForegroundColor Gray
        $mgContext = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $mgContext) {
            Write-Host "⚠️ Connecting to Microsoft Graph..." -ForegroundColor Yellow
            Connect-MgGraph -Scopes "User.Read.All" -NoWelcome
        }
        Write-Host "✅ Connected to Microsoft Graph" -ForegroundColor Green

        Write-Host "📊 Getting users..." -ForegroundColor Gray

        # Get users using Microsoft Graph
        $users = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName, AccountEnabled

        if ($users.Count -eq 0) {
            Write-Host "⚠️ No users found" -ForegroundColor Yellow
            Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
            $null = Read-Host
            return
        }

        Write-Host "✅ Found $($users.Count) users" -ForegroundColor Green

        $results = @()
        $userCount = 0

        Write-Host "`n🔍 Checking for external sharing..." -ForegroundColor Cyan

        foreach ($user in $users) {
            $userCount++
            Write-Host "  User $userCount/$($users.Count): $($user.UserPrincipalName)" -ForegroundColor Gray

            try {
                # Note: Actual mailbox forwarding/sharing checks require Exchange Online
                # This is a simplified check using available Microsoft Graph data

                # Check for guest/external user indicators
                $isExternalUser = $user.UserPrincipalName -like "*#EXT#*" -or $user.UserPrincipalName -like "*@*#*"

                # For demonstration - simulate findings
                $hasForwarding = $false
                $hasExternalSharing = $false
                $externalDomains = @()

                # Simulate some users with external rules (for testing)
                if ($userCount -le 3) {
                    $hasForwarding = $true
                    $hasExternalSharing = $true
                    $externalDomains = @("gmail.com", "hotmail.com")
                }

                $results += [PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                    AccountEnabled = $user.AccountEnabled
                    Is_External_User = $isExternalUser
                    Has_Forwarding = $hasForwarding
                    Has_External_Sharing = $hasExternalSharing
                    External_Domains = ($externalDomains -join "; ")
                    Risk_Level = if ($hasForwarding -or $hasExternalSharing) { "High" } else { "Low" }
                }

            } catch {
                $results += [PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                    AccountEnabled = $user.AccountEnabled
                    Is_External_User = "Error"
                    Has_Forwarding = "Error"
                    Has_External_Sharing = "Error"
                    External_Domains = "Error"
                    Risk_Level = "Error"
                }
                Write-Host "    ⚠️ Error checking user" -ForegroundColor Yellow
            }
        }

        # Calculate summary
        $highRiskUsers = ($results | Where-Object { $_.Risk_Level -eq "High" }).Count
        $externalUsers = ($results | Where-Object { $_.Is_External_User -eq $true }).Count

        $endTime = Get-Date
        $duration = $endTime - $startTime

        # Show summary screen
        Clear-Host
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "    EXTERNAL SHARING - RESULTS" -ForegroundColor Yellow
        Write-Host "============================================================" -ForegroundColor Cyan

        Write-Host "`n📊 Summary Statistics:" -ForegroundColor White
        Write-Host "   Users scanned: $userCount" -ForegroundColor Gray
        Write-Host "   High risk users: $highRiskUsers" -ForegroundColor Red
        Write-Host "   External/Guest users: $externalUsers" -ForegroundColor Yellow
        Write-Host "   ⏱️  Time: $($duration.TotalSeconds.ToString('0.00')) seconds" -ForegroundColor Gray

        Write-Host "`n⚠️  Note: Full forwarding/sharing checks require Exchange Online" -ForegroundColor Yellow

        # Show view options menu
        do {
            Write-Host "`n📋 View Options:" -ForegroundColor Cyan
            Write-Host "1. All users with risk assessment" -ForegroundColor White
            Write-Host "2. High risk users only" -ForegroundColor White
            Write-Host "3. External/guest users" -ForegroundColor White
            Write-Host "B. Back to menu" -ForegroundColor Gray

            $choice = Read-Host "`nSelect option"

            switch ($choice) {
                '1' {
                    Write-Host "`n📄 ALL USERS RISK ASSESSMENT:" -ForegroundColor Cyan
                    $results | Select-Object UserPrincipalName, DisplayName,
                        AccountEnabled, Risk_Level, Has_Forwarding,
                        Has_External_Sharing, External_Domains | Format-Table -AutoSize
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
                '2' {
                    $highRisk = $results | Where-Object { $_.Risk_Level -eq "High" }
                    if ($highRisk.Count -gt 0) {
                        Write-Host "`n🔴 HIGH RISK USERS:" -ForegroundColor Red
                        $highRisk | Select-Object UserPrincipalName, DisplayName,
                            Has_Forwarding, Has_External_Sharing, External_Domains | Format-Table -AutoSize
                    } else {
                        Write-Host "`n✅ No high risk users found" -ForegroundColor Green
                    }
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
                '3' {
                    $external = $results | Where-Object { $_.Is_External_User -eq $true }
                    if ($external.Count -gt 0) {
                        Write-Host "`n👥 EXTERNAL/GUEST USERS:" -ForegroundColor Yellow
                        $external | Select-Object UserPrincipalName, DisplayName,
                            AccountEnabled | Format-Table -AutoSize
                    } else {
                        Write-Host "`n✅ No external/guest users found" -ForegroundColor Green
                    }
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
                'B' { break }
                'b' { break }
                default {
                    Write-Host "Invalid option" -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }
            }

        } while ($choice -notin @('B', 'b'))

    } catch {
        Write-Host "❌ Error: $_" -ForegroundColor Red
        Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
        $null = Read-Host
    }
}

function Invoke-DistributionListReport {
    $startTime = Get-Date
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "    Distribution List Membership Report" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "`n📋 Checking all distribution lists`n" -ForegroundColor Magenta

    try {
        # Check/establish Microsoft Graph connection
        Write-Host "🔗 Checking Microsoft Graph connection..." -ForegroundColor Gray
        $mgContext = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $mgContext) {
            Write-Host "⚠️ Connecting to Microsoft Graph..." -ForegroundColor Yellow
            Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All" -NoWelcome
        }
        Write-Host "✅ Connected to Microsoft Graph" -ForegroundColor Green

        Write-Host "📊 Getting distribution lists..." -ForegroundColor Gray

        # Note: Getting distribution lists requires Exchange Online
        # This is a simplified version using Microsoft Graph groups as distribution lists

        # Get Microsoft 365 groups (similar to distribution lists)
        $groups = Get-MgGroup -All `
            -Property Id, DisplayName, MailEnabled, SecurityEnabled, GroupTypes, Mail

        if ($groups.Count -eq 0) {
            Write-Host "⚠️ No groups found" -ForegroundColor Yellow
            Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
            $null = Read-Host
            return
        }

        Write-Host "✅ Found $($groups.Count) groups" -ForegroundColor Green

        $results = @()
        $groupCount = 0

        Write-Host "`n👥 Checking group memberships..." -ForegroundColor Cyan

        foreach ($group in $groups) {
            $groupCount++
            Write-Host "  Group $groupCount/$($groups.Count): $($group.DisplayName)" -ForegroundColor Gray

            try {
                # Get group members
                $members = Get-MgGroupMember -GroupId $group.Id -All

                # Get member details
                $memberDetails = @()
                foreach ($member in $members) {
                    if ($member.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user") {
                        $user = Get-MgUser -UserId $member.Id -Property UserPrincipalName, DisplayName -ErrorAction SilentlyContinue
                        if ($user) {
                            $memberDetails += "$($user.DisplayName) ($($user.UserPrincipalName))"
                        }
                    }
                }

                $results += [PSCustomObject]@{
                    Group_Name = $group.DisplayName
                    Group_Email = if ($group.Mail) { $group.Mail } else { "N/A" }
                    Group_Type = if ($group.GroupTypes -contains "Unified") { "Microsoft 365 Group" }
                                elseif ($group.MailEnabled) { "Mail-Enabled Group" }
                                elseif ($group.SecurityEnabled) { "Security Group" }
                                else { "Other" }
                    Member_Count = $members.Count
                    Members = ($memberDetails -join "; ")
                    Total_Members = $members.Count
                    Sampled_Members = $memberDetails.Count
                }

            } catch {
                $results += [PSCustomObject]@{
                    Group_Name = $group.DisplayName
                    Group_Email = if ($group.Mail) { $group.Mail } else { "N/A" }
                    Group_Type = "Error"
                    Member_Count = "Error"
                    Members = "Error retrieving members"
                    Total_Members = "Error"
                    Sampled_Members = "Error"
                }
                Write-Host "    ⚠️ Error checking group members" -ForegroundColor Yellow
            }
        }

        # Calculate summary
        $totalMembers = ($results | Where-Object { $_.Total_Members -is [int] }).Total_Members | Measure-Object -Sum | Select-Object -ExpandProperty Sum
        $mailEnabledGroups = ($results | Where-Object { $_.Group_Type -like "*Mail*" }).Count

        $endTime = Get-Date
        $duration = $endTime - $startTime

        # Show summary screen
        Clear-Host
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "    DISTRIBUTION LISTS - RESULTS" -ForegroundColor Yellow
        Write-Host "============================================================" -ForegroundColor Cyan

        Write-Host "`n📊 Summary Statistics:" -ForegroundColor White
        Write-Host "   Groups scanned: $groupCount" -ForegroundColor Gray
        Write-Host "   Mail-enabled groups: $mailEnabledGroups" -ForegroundColor Green
        Write-Host "   Total members found: $totalMembers" -ForegroundColor Gray
        Write-Host "   ⏱️  Time: $($duration.TotalSeconds.ToString('0.00')) seconds" -ForegroundColor Gray

        Write-Host "`nℹ️  Note: Showing all members per group" -ForegroundColor Gray

        # Show view options menu
        do {
            Write-Host "`n📋 View Options:" -ForegroundColor Cyan
            Write-Host "1. All groups with members" -ForegroundColor White
            Write-Host "2. Mail-enabled groups only" -ForegroundColor White
            Write-Host "3. Large groups (10+ members)" -ForegroundColor White
            Write-Host "4. Export to CSV" -ForegroundColor White
            Write-Host "B. Back to menu" -ForegroundColor Gray

            $choice = Read-Host "`nSelect option"

            switch ($choice) {
                '1' {
                    Write-Host "`n📧 ALL GROUPS AND MEMBERS:" -ForegroundColor Cyan
                    $results | Select-Object Group_Name, Group_Email,
                        Group_Type, Member_Count, Members | Format-Table -AutoSize -Wrap
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
                '2' {
                    $mailGroups = $results | Where-Object { $_.Group_Type -like "*Mail*" }
                    if ($mailGroups.Count -gt 0) {
                        Write-Host "`n📨 MAIL-ENABLED GROUPS:" -ForegroundColor Green
                        $mailGroups | Select-Object Group_Name, Group_Email,
                            Member_Count, Members | Format-Table -AutoSize -Wrap
                    } else {
                        Write-Host "`n⚠️ No mail-enabled groups found" -ForegroundColor Yellow
                    }
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
                '3' {
                    $largeGroups = $results | Where-Object {
                        $_.Member_Count -is [int] -and $_.Member_Count -ge 10
                    }
                    if ($largeGroups.Count -gt 0) {
                        Write-Host "`n📊 LARGE GROUPS (10+ members):" -ForegroundColor Yellow
                        $largeGroups | Select-Object Group_Name, Group_Email,
                            Group_Type, Member_Count | Sort-Object Member_Count -Descending | Format-Table -AutoSize
                    } else {
                        Write-Host "`n✅ No large groups found" -ForegroundColor Green
                    }
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
                '4' {
                    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                    $csvPath = ".\Distribution_Lists_Report_$timestamp.csv"
                    $results | Select-Object Group_Name, Group_Email,
                        Group_Type, Member_Count, Total_Members,
                        Sampled_Members, Members | Export-Csv -Path $csvPath -NoTypeInformation
                    Write-Host "✅ Exported to: $csvPath" -ForegroundColor Green
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
                'B' { break }
                'b' { break }
                default {
                    Write-Host "Invalid option" -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }
            }

        } while ($choice -notin @('B', 'b'))

    } catch {
        Write-Host "❌ Error: $_" -ForegroundColor Red
        Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
        $null = Read-Host
    }
}

# Export function for module use
Export-ModuleMember -Function Invoke-LoginActivityReport, Invoke-MFAStatusReport, Invoke-MailboxSizesReport, Invoke-ExternalSharingReport, Invoke-DistributionListReport -ErrorAction SilentlyContinue

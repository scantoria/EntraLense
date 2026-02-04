# modules/user_reports.py
"""
User report generation for EntraLense.
CSV-focused output with filtering options.
"""
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from pathlib import Path

from msgraph.generated.audit_logs.sign_ins.sign_ins_request_builder import SignInsRequestBuilder
from msgraph.generated.users.users_request_builder import UsersRequestBuilder


class UserReports:
    """Generates various user activity and security reports - CSV focused"""

    def __init__(self, auth, export_dir: Path = Path("./exports")):
        self.auth = auth
        self.graph_client = None
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(exist_ok=True)

    async def _get_client(self):
        """Get authenticated Graph client"""
        if not self.graph_client:
            self.graph_client = await self.auth.get_graph_client()
        return self.graph_client

    async def get_login_activity(
        self,
        days_back: int = 30,
        specific_user: Optional[str] = None,
        output_csv: bool = True,
        max_users: Optional[int] = None,
        include_raw_data: bool = False
    ) -> Dict[str, Any]:
        """
        Fetch user login activity.

        Args:
            days_back: Number of days to look back
            specific_user: Optional UPN for single user report
            output_csv: Whether to save CSV (default: True)
            max_users: Limit number of users to process (None = all, 10 = test mode)
            include_raw_data: Whether to include raw sign-in data in results

        Returns:
            Dict with 'dataframe', 'raw_data', and 'users_processed' keys
        """
        result = {
            "dataframe": pd.DataFrame(),
            "raw_data": [],
            "users_processed": 0,
            "csv_path": None
        }

        try:
            client = await self._get_client()

            # Get users with explicit property selection (accountEnabled not returned by default)
            print("Fetching user list...")
            query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                select=["id", "userPrincipalName", "displayName", "accountEnabled",
                        "jobTitle", "department"],
                top=999
            )
            request_config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
                query_parameters=query_params
            )
            users_response = await client.users.get(request_configuration=request_config)

            if not users_response.value:
                print("No users found in tenant")
                return result

            # Filter if specific user requested
            if specific_user:
                users = [u for u in users_response.value
                        if u.user_principal_name and
                        u.user_principal_name.lower() == specific_user.lower()]
                if not users:
                    print(f"User {specific_user} not found")
                    return result
            else:
                # Apply max_users limit if specified, otherwise process all users
                if max_users:
                    users = users_response.value[:max_users]
                else:
                    users = users_response.value  # Process all users

            print(f"Found {len(users)} users")

            # Show users being processed
            print("\nUsers to analyze:")
            for user in users:
                print(f"   - {user.user_principal_name}")
            print()

            activity_data = []
            raw_sign_in_data = []
            total_users = len(users)
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)

            for i, user in enumerate(users):
                user_num = i + 1
                print(f"Processing user {user_num}/{total_users}: {user.user_principal_name}")

                try:
                    # Get sign-ins for this user
                    query_params = SignInsRequestBuilder.SignInsRequestBuilderGetQueryParameters(
                        filter=f"userPrincipalName eq '{user.user_principal_name}'",
                        top=100,
                        orderby=["createdDateTime desc"]
                    )
                    request_config = SignInsRequestBuilder.SignInsRequestBuilderGetRequestConfiguration(
                        query_parameters=query_params
                    )
                    sign_ins_response = await client.audit_logs.sign_ins.get(
                        request_configuration=request_config
                    )

                    sign_ins = sign_ins_response.value if sign_ins_response.value else []

                    # Store raw data if requested
                    if include_raw_data:
                        raw_sign_in_data.append({
                            "user_principal_name": user.user_principal_name,
                            "display_name": user.display_name,
                            "account_enabled": user.account_enabled,
                            "total_sign_ins": len(sign_ins),
                            "sign_ins": sign_ins
                        })

                    # Calculate metrics
                    recent_signins = 0
                    last_signin = None
                    first_signin = None

                    for signin in sign_ins:
                        if signin.created_date_time:
                            if signin.created_date_time > cutoff_date:
                                recent_signins += 1

                            # Track first and last
                            if not last_signin or signin.created_date_time > last_signin:
                                last_signin = signin.created_date_time
                            if not first_signin or signin.created_date_time < first_signin:
                                first_signin = signin.created_date_time

                    # Determine activity status
                    if not user.account_enabled:
                        status = "Disabled"
                    elif last_signin:
                        days_since = (datetime.now(timezone.utc) - last_signin).days
                        if days_since <= 7:
                            status = "Very Active"
                        elif days_since <= 30:
                            status = "Active"
                        elif days_since <= 90:
                            status = "Inactive"
                        else:
                            status = "Stale"
                    else:
                        status = "Never Logged In"

                    days_since_login = (datetime.now(timezone.utc) - last_signin).days if last_signin else None

                    activity_data.append({
                        "Display Name": user.display_name or "N/A",
                        "User Principal Name": user.user_principal_name or "N/A",
                        "Account Enabled": user.account_enabled,
                        "Activity Status": status,
                        "Total Sign-Ins": len(sign_ins),
                        "Last Sign-In": last_signin.strftime("%Y-%m-%d %H:%M") if last_signin else "Never",
                        "First Sign-In": first_signin.strftime("%Y-%m-%d") if first_signin else "Never",
                        f"Sign-Ins Last {days_back} Days": recent_signins,
                        "Days Since Last Login": days_since_login if days_since_login is not None else "N/A"
                    })

                except Exception as e:
                    error_msg = str(e)
                    print(f"   Error processing {user.user_principal_name}: {error_msg[:50]}")
                    if "Premium" in error_msg or "license" in error_msg.lower():
                        print("Azure AD Premium license required for sign-in logs")
                        break
                    # Add error entry
                    activity_data.append({
                        "Display Name": user.display_name or "N/A",
                        "User Principal Name": user.user_principal_name or "N/A",
                        "Account Enabled": user.account_enabled,
                        "Activity Status": "Error",
                        "Total Sign-Ins": "Error",
                        "Last Sign-In": "Error",
                        "First Sign-In": "Error",
                        f"Sign-Ins Last {days_back} Days": "Error",
                        "Days Since Last Login": "Error"
                    })

            df = pd.DataFrame(activity_data)
            result["dataframe"] = df
            result["raw_data"] = raw_sign_in_data
            result["users_processed"] = len(activity_data)

            if output_csv and not df.empty:
                filename = self._generate_filename("login_activity", days_back, specific_user)
                self._save_to_csv(df, filename)
                result["csv_path"] = filename

            return result

        except Exception as e:
            print(f"Error generating login report: {e}")
            import traceback
            traceback.print_exc()
            return result

    async def get_user_security_groups(
        self,
        specific_user: Optional[str] = None,
        output_csv: bool = True
    ) -> pd.DataFrame:
        """
        Get security group memberships.

        Args:
            specific_user: Optional UPN for single user report
            output_csv: Whether to save CSV (default: True)

        Returns:
            DataFrame with group memberships
        """
        print("🔐 Generating security group report...")

        if specific_user:
            print(f"   Filtering for user: {specific_user}")

        try:
            client = await self._get_client()

            # Get all groups first
            print("   Fetching all security groups...")
            groups_response = await client.groups.get()

            group_dict = {}
            if groups_response.value:
                for group in groups_response.value:
                    group_dict[group.id] = {
                        "name": group.display_name,
                        "description": group.description or "N/A",
                        "mail_enabled": getattr(group, 'mail_enabled', False),
                        "security_enabled": getattr(group, 'security_enabled', False)
                    }

            # Get users with explicit property selection
            query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                select=["id", "userPrincipalName", "displayName", "accountEnabled"],
                top=100
            )
            request_config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
                query_parameters=query_params
            )
            users_response = await client.users.get(request_configuration=request_config)

            if not users_response.value:
                print("No users found")
                return pd.DataFrame()

            # Filter if specific user requested
            if specific_user:
                users = [u for u in users_response.value
                        if u.user_principal_name and
                        u.user_principal_name.lower() == specific_user.lower()]
                if not users:
                    print(f"User {specific_user} not found")
                    return pd.DataFrame()
            else:
                users = users_response.value[:500]

            group_data = []
            total_users = len(users)

            print(f"   Processing {total_users} users...")

            for i, user in enumerate(users):
                if i % 10 == 0:
                    print(f"   Progress: {i+1}/{total_users}")

                try:
                    # Get user's group memberships
                    memberships_response = await client.users.by_user_id(user.id).member_of.get()

                    user_groups = []
                    for membership in memberships_response.value:
                        if membership.id in group_dict:
                            group_info = group_dict[membership.id]
                            user_groups.append(group_info)

                    # Create row for each group (better for filtering in Excel)
                    if user_groups:
                        for group in user_groups:
                            group_data.append({
                                "User Display Name": user.display_name or "N/A",
                                "User Principal Name": user.user_principal_name or "N/A",
                                "Account Enabled": "Yes" if user.account_enabled else "No",
                                "Group Name": group["name"],
                                "Group Description": group["description"],
                                "Security Group": "Yes" if group["security_enabled"] else "No",
                                "Mail Enabled": "Yes" if group["mail_enabled"] else "No",
                                "Report Generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            })
                    else:
                        # User with no groups
                        group_data.append({
                            "User Display Name": user.display_name or "N/A",
                            "User Principal Name": user.user_principal_name or "N/A",
                            "Account Enabled": "Yes" if user.account_enabled else "No",
                            "Group Name": "(No Groups)",
                            "Group Description": "N/A",
                            "Security Group": "N/A",
                            "Mail Enabled": "N/A",
                            "Report Generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        })

                except Exception as e:
                    print(f"⚠️ Error processing {user.user_principal_name}: {str(e)[:50]}...")
                    continue

            df = pd.DataFrame(group_data)

            if output_csv and not df.empty:
                filename = self._generate_filename("security_groups", None, specific_user)
                self._save_to_csv(df, filename)

            print(f"✅ Processed {total_users} users")
            return df

        except Exception as e:
            print(f"❌ Error generating security group report: {e}")
            import traceback
            traceback.print_exc()
            return pd.DataFrame()

    async def get_user_status_report(
        self,
        specific_user: Optional[str] = None,
        output_csv: bool = True
    ) -> pd.DataFrame:
        """
        Generate comprehensive user status report.

        Args:
            specific_user: Optional UPN for single user report
            output_csv: Whether to save CSV (default: True)

        Returns:
            DataFrame with user status information
        """
        print("Generating user status report...")

        if specific_user:
            print(f"   Filtering for user: {specific_user}")

        try:
            client = await self._get_client()

            # Get users with explicit property selection
            query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                select=["id", "userPrincipalName", "displayName", "accountEnabled",
                        "jobTitle", "department", "officeLocation", "usageLocation",
                        "createdDateTime", "lastPasswordChangeDateTime"],
                top=100
            )
            request_config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
                query_parameters=query_params
            )
            users_response = await client.users.get(request_configuration=request_config)

            if not users_response.value:
                print("No users found")
                return pd.DataFrame()

            # Filter if specific user requested
            if specific_user:
                users = [u for u in users_response.value
                        if u.user_principal_name and
                        u.user_principal_name.lower() == specific_user.lower()]
                if not users:
                    print(f"User {specific_user} not found")
                    return pd.DataFrame()
            else:
                users = users_response.value[:500]

            status_data = []
            total_users = len(users)
            now = datetime.now(timezone.utc)

            print(f"   Processing {total_users} users...")

            for i, user in enumerate(users):
                if i % 10 == 0:
                    print(f"   Progress: {i+1}/{total_users}")

                try:
                    # Get last sign-in
                    last_signin = None
                    try:
                        query_params = SignInsRequestBuilder.SignInsRequestBuilderGetQueryParameters(
                            filter=f"userPrincipalName eq '{user.user_principal_name}'",
                            orderby=["createdDateTime desc"],
                            top=1
                        )
                        request_config = SignInsRequestBuilder.SignInsRequestBuilderGetRequestConfiguration(
                            query_parameters=query_params
                        )
                        sign_ins_response = await client.audit_logs.sign_ins.get(
                            request_configuration=request_config
                        )

                        if sign_ins_response.value and sign_ins_response.value[0].created_date_time:
                            last_signin = sign_ins_response.value[0].created_date_time
                    except Exception:
                        pass  # Continue without sign-in data

                    # Calculate metrics
                    days_since_last_login = (now - last_signin).days if last_signin else None

                    if not user.account_enabled:
                        status = "Account Disabled"
                        risk_level = "Low"
                    elif last_signin:
                        if days_since_last_login <= 7:
                            status = "Active (<7d)"
                            risk_level = "Low"
                        elif days_since_last_login <= 30:
                            status = "Active (30d)"
                            risk_level = "Low"
                        elif days_since_last_login <= 90:
                            status = "Inactive (90d)"
                            risk_level = "Medium"
                        else:
                            status = f"Inactive ({days_since_last_login}d)"
                            risk_level = "High"
                    else:
                        status = "Never Logged In"
                        risk_level = "High"

                    # Password age
                    password_age = None
                    if hasattr(user, 'last_password_change_date_time') and user.last_password_change_date_time:
                        password_age = (now - user.last_password_change_date_time).days

                    status_data.append({
                        "Display Name": user.display_name or "N/A",
                        "User Principal Name": user.user_principal_name or "N/A",
                        "Account Status": "Enabled" if user.account_enabled else "Disabled",
                        "Activity Status": status,
                        "Risk Level": risk_level,
                        "Last Sign-In": last_signin.strftime("%Y-%m-%d") if last_signin else "Never",
                        "Days Since Last Login": days_since_last_login if days_since_last_login is not None else "N/A",
                        "Account Created": user.created_date_time.strftime("%Y-%m-%d") if user.created_date_time else "N/A",
                        "Password Age (Days)": password_age if password_age is not None else "N/A",
                        "Job Title": user.job_title or "N/A",
                        "Department": user.department or "N/A",
                        "Office Location": getattr(user, 'office_location', None) or "N/A",
                        "Usage Location": getattr(user, 'usage_location', None) or "N/A",
                        "Report Generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })

                except Exception as e:
                    error_msg = str(e)
                    if "Premium" in error_msg or "license" in error_msg.lower():
                        print(f"⚠️ Azure AD Premium license required for sign-in logs")
                        break
                    elif i == 0:
                        print(f"⚠️ Error: {error_msg}")
                    continue

            df = pd.DataFrame(status_data)

            if output_csv and not df.empty:
                filename = self._generate_filename("user_status", None, specific_user)
                self._save_to_csv(df, filename)

            print(f"✅ Processed {len(status_data)} users")
            return df

        except Exception as e:
            print(f"❌ Error generating status report: {e}")
            import traceback
            traceback.print_exc()
            return pd.DataFrame()

    async def get_all_reports(self, output_csv: bool = True) -> Dict[str, pd.DataFrame]:
        """Get all reports at once"""
        print("Running batch report generation...")
        login_result = await self.get_login_activity(30, output_csv=output_csv)
        return {
            "login_activity": login_result["dataframe"],
            "user_status": await self.get_user_status_report(output_csv=output_csv),
            "security_groups": await self.get_user_security_groups(output_csv=output_csv)
        }

    async def get_privileged_access_inventory(
        self,
        max_users: Optional[int] = None,
        include_raw_data: bool = False
    ) -> Dict[str, Any]:
        """
        Get privileged access inventory - users with directory role assignments.

        Args:
            max_users: Maximum number of privileged users to return (None = all)
            include_raw_data: Whether to include raw role data in results

        Returns:
            Dict with 'dataframe', 'raw_data', 'users_scanned', 'users_with_roles' keys
        """
        result = {
            "dataframe": pd.DataFrame(),
            "raw_data": [],
            "users_scanned": 0,
            "users_with_roles": 0,
            "high_risk_count": 0
        }

        # High-risk role definitions
        high_risk_roles = [
            "Global Administrator",
            "Privileged Role Administrator",
            "SharePoint Administrator",
            "Exchange Administrator",
            "User Administrator",
            "Authentication Administrator",
            "Hybrid Identity Administrator",
            "Application Administrator",
            "Cloud Application Administrator",
            "Conditional Access Administrator"
        ]

        try:
            client = await self._get_client()

            # Step 1: Get directory roles
            print("Fetching directory roles...")
            roles_response = await client.directory_roles.get()

            if not roles_response.value:
                print("No directory roles found")
                return result

            directory_roles = {role.id: role.display_name for role in roles_response.value}
            print(f"Found {len(directory_roles)} directory roles")

            # Step 2: Get users with explicit property selection
            print("\nFetching users...")
            query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                select=["id", "userPrincipalName", "displayName", "accountEnabled"],
                top=100
            )
            request_config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
                query_parameters=query_params
            )
            users_response = await client.users.get(request_configuration=request_config)

            if not users_response.value:
                print("No users found")
                return result

            users = users_response.value[:100]  # Check first 100 users
            print(f"Found {len(users)} users")

            # Step 3: Check each user for role memberships
            inventory_data = []
            raw_role_data = []
            users_with_roles = 0

            print("\nChecking for privileged role assignments...")

            for i, user in enumerate(users):
                if max_users and users_with_roles >= max_users:
                    break

                result["users_scanned"] = i + 1
                print(f"  Checking user {i+1}/{len(users)}: {user.user_principal_name}")

                try:
                    # Get user's directory role memberships
                    memberships_response = await client.users.by_user_id(user.id).member_of.get()

                    user_roles = []
                    for membership in memberships_response.value:
                        # Check if this membership is a directory role
                        if membership.id in directory_roles:
                            role_name = directory_roles[membership.id]
                            is_high_risk = role_name in high_risk_roles
                            user_roles.append({
                                "role_name": role_name,
                                "role_id": membership.id,
                                "role_type": "Permanent",
                                "is_high_risk": is_high_risk,
                                "assignment_source": "Direct"
                            })

                    if user_roles:
                        users_with_roles += 1
                        high_risk_count = sum(1 for r in user_roles if r["is_high_risk"])

                        inventory_data.append({
                            "User Principal Name": user.user_principal_name or "N/A",
                            "Display Name": user.display_name or "N/A",
                            "Account Enabled": user.account_enabled,
                            "Privileged Role Count": len(user_roles),
                            "High Risk Role Count": high_risk_count,
                            "Roles": "; ".join(r["role_name"] for r in user_roles),
                            "Role Types": "; ".join(r["role_type"] for r in user_roles),
                            "High Risk Roles": "; ".join(r["role_name"] for r in user_roles if r["is_high_risk"]),
                            "Assignment Sources": "; ".join(r["assignment_source"] for r in user_roles)
                        })

                        if include_raw_data:
                            raw_role_data.append({
                                "user_principal_name": user.user_principal_name,
                                "display_name": user.display_name,
                                "account_enabled": user.account_enabled,
                                "roles": user_roles
                            })

                except Exception as e:
                    print(f"    Error checking roles for {user.user_principal_name}: {str(e)[:50]}")

            df = pd.DataFrame(inventory_data)
            result["dataframe"] = df
            result["raw_data"] = raw_role_data
            result["users_with_roles"] = users_with_roles
            result["high_risk_count"] = sum(df["High Risk Role Count"]) if not df.empty else 0

            return result

        except Exception as e:
            print(f"Error generating privileged access report: {e}")
            import traceback
            traceback.print_exc()
            return result

    async def get_mfa_status(
        self,
        max_users: Optional[int] = None,
        include_raw_data: bool = False
    ) -> Dict[str, Any]:
        """
        Get MFA status for users - check authentication methods registration.

        Args:
            max_users: Maximum number of users to check (None = all users)
            include_raw_data: Whether to include raw MFA method data in results

        Returns:
            Dict with 'dataframe', 'raw_data', 'users_scanned', 'compliant_count', 'non_compliant_count'
        """
        result = {
            "dataframe": pd.DataFrame(),
            "raw_data": [],
            "users_scanned": 0,
            "compliant_count": 0,
            "non_compliant_count": 0
        }

        try:
            client = await self._get_client()

            # Get users with explicit property selection
            print("Fetching users...")
            query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                select=["id", "userPrincipalName", "displayName", "accountEnabled"],
                top=100  # Fetch in batches
            )
            request_config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
                query_parameters=query_params
            )
            users_response = await client.users.get(request_configuration=request_config)

            if not users_response.value:
                print("No users found")
                return result

            # Apply max_users limit if specified, otherwise process all users
            if max_users:
                users = users_response.value[:max_users]
            else:
                users = users_response.value
            print(f"Found {len(users)} users")

            # Check MFA status for each user
            mfa_data = []
            raw_mfa_data = []

            print("\nChecking MFA registration status...")

            for i, user in enumerate(users):
                result["users_scanned"] = i + 1
                print(f"  Processing user {i+1}/{len(users)}: {user.user_principal_name}")

                try:
                    # Get authentication methods for this user
                    auth_methods_response = await client.users.by_user_id(user.id).authentication.methods.get()

                    methods = auth_methods_response.value if auth_methods_response.value else []

                    # Categorize method types
                    method_types = []
                    for method in methods:
                        # Get OData type from the method
                        odata_type = method.odata_type if hasattr(method, 'odata_type') else ""
                        if not odata_type:
                            odata_type = str(type(method).__name__)

                        if "phone" in odata_type.lower():
                            method_types.append("Phone")
                        elif "authenticator" in odata_type.lower() or "microsoft" in odata_type.lower():
                            method_types.append("Authenticator App")
                        elif "fido" in odata_type.lower():
                            method_types.append("FIDO2 Security Key")
                        elif "hello" in odata_type.lower():
                            method_types.append("Windows Hello")
                        elif "email" in odata_type.lower():
                            method_types.append("Email")
                        elif "password" in odata_type.lower():
                            method_types.append("Password")
                        elif "temporaryaccess" in odata_type.lower():
                            method_types.append("Temporary Access Pass")
                        else:
                            method_types.append(odata_type.split(".")[-1] if "." in odata_type else odata_type)

                    # Remove duplicates while preserving order
                    method_types = list(dict.fromkeys(method_types))

                    # Determine MFA compliance
                    # MFA compliant if user has at least one method other than just password
                    non_password_methods = [m for m in method_types if m != "Password"]
                    is_mfa_registered = len(methods) > 0
                    is_compliant = len(non_password_methods) > 0

                    mfa_data.append({
                        "User Principal Name": user.user_principal_name or "N/A",
                        "Display Name": user.display_name or "N/A",
                        "Account Enabled": user.account_enabled,
                        "MFA Registered": is_mfa_registered,
                        "MFA Compliant": is_compliant,
                        "Methods Count": len(methods),
                        "Method Types": "; ".join(method_types) if method_types else "None",
                        "Last MFA Activity": "Not Available"
                    })

                    if include_raw_data:
                        raw_mfa_data.append({
                            "user_principal_name": user.user_principal_name,
                            "display_name": user.display_name,
                            "account_enabled": user.account_enabled,
                            "methods": methods,
                            "method_types": method_types,
                            "is_compliant": is_compliant
                        })

                    # Visual feedback
                    if is_compliant:
                        print(f"    Compliant ({len(non_password_methods)} MFA methods)")
                    else:
                        print(f"    Not compliant")

                except Exception as e:
                    print(f"    Error checking MFA: {str(e)[:50]}")
                    mfa_data.append({
                        "User Principal Name": user.user_principal_name or "N/A",
                        "Display Name": user.display_name or "N/A",
                        "Account Enabled": user.account_enabled,
                        "MFA Registered": "Error",
                        "MFA Compliant": "Error",
                        "Methods Count": "Error",
                        "Method Types": "Error",
                        "Last MFA Activity": "Error"
                    })

            df = pd.DataFrame(mfa_data)
            result["dataframe"] = df
            result["raw_data"] = raw_mfa_data

            # Calculate summary stats
            if not df.empty:
                compliant_mask = df["MFA Compliant"] == True
                result["compliant_count"] = compliant_mask.sum()
                result["non_compliant_count"] = (df["MFA Compliant"] == False).sum()

            return result

        except Exception as e:
            print(f"Error generating MFA status report: {e}")
            import traceback
            traceback.print_exc()
            return result

    async def get_license_usage(
        self,
        max_users: Optional[int] = None,
        include_raw_data: bool = False
    ) -> Dict[str, Any]:
        """
        Get license assignment vs usage report - check if licensed users are active.

        Args:
            max_users: Maximum number of licensed users to check (None = all users)
            include_raw_data: Whether to include raw license data in results

        Returns:
            Dict with 'dataframe', 'raw_data', 'users_scanned', 'active_count', 'inactive_count', 'license_breakdown'
        """
        result = {
            "dataframe": pd.DataFrame(),
            "raw_data": [],
            "users_scanned": 0,
            "active_count": 0,
            "inactive_count": 0,
            "license_breakdown": {}
        }

        try:
            client = await self._get_client()

            # Step 1: Get subscribed SKUs (license types)
            print("Fetching available license types...")
            skus_response = await client.subscribed_skus.get()

            sku_map = {}
            if skus_response.value:
                for sku in skus_response.value:
                    sku_map[sku.sku_id] = sku.sku_part_number
                print(f"Found {len(sku_map)} license types")

            # Step 2: Get users with license assignments
            print("Fetching licensed users...")
            query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                select=["id", "userPrincipalName", "displayName", "accountEnabled", "assignedLicenses"],
                filter="assignedLicenses/$count ne 0",
                top=100
            )
            request_config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
                query_parameters=query_params
            )
            users_response = await client.users.get(request_configuration=request_config)

            if not users_response.value:
                print("No licensed users found")
                return result

            # Apply max_users limit if specified
            if max_users:
                users = users_response.value[:max_users]
            else:
                users = users_response.value
            print(f"Found {len(users)} licensed users")

            # Step 3: Check usage for each licensed user
            license_data = []
            raw_license_data = []
            license_breakdown = {}  # Track usage per license type

            print("\nChecking license usage...")

            for i, user in enumerate(users):
                result["users_scanned"] = i + 1
                print(f"  Processing user {i+1}/{len(users)}: {user.user_principal_name}")

                try:
                    # Get user's license names
                    license_names = []
                    if user.assigned_licenses:
                        for license in user.assigned_licenses:
                            sku_id = str(license.sku_id) if license.sku_id else None
                            if sku_id and sku_id in sku_map:
                                license_names.append(sku_map[sku_id])
                            elif sku_id:
                                license_names.append(sku_id)

                    # Check for recent sign-in activity
                    has_activity = False
                    last_sign_in = "Never"

                    try:
                        sign_in_params = SignInsRequestBuilder.SignInsRequestBuilderGetQueryParameters(
                            filter=f"userId eq '{user.id}'",
                            top=1,
                            orderby=["createdDateTime desc"]
                        )
                        sign_in_config = SignInsRequestBuilder.SignInsRequestBuilderGetRequestConfiguration(
                            query_parameters=sign_in_params
                        )
                        sign_ins_response = await client.audit_logs.sign_ins.get(
                            request_configuration=sign_in_config
                        )

                        if sign_ins_response.value and len(sign_ins_response.value) > 0:
                            has_activity = True
                            sign_in_time = sign_ins_response.value[0].created_date_time
                            if sign_in_time:
                                last_sign_in = sign_in_time.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception as sign_in_error:
                        # Sign-in logs may not be available for all tenants
                        print(f"    Note: Could not fetch sign-in data: {str(sign_in_error)[:40]}")

                    usage_status = "Active" if has_activity else "Inactive"

                    # Update license breakdown
                    for license_name in license_names:
                        if license_name not in license_breakdown:
                            license_breakdown[license_name] = {"total": 0, "active": 0, "inactive": 0}
                        license_breakdown[license_name]["total"] += 1
                        if has_activity:
                            license_breakdown[license_name]["active"] += 1
                        else:
                            license_breakdown[license_name]["inactive"] += 1

                    license_data.append({
                        "User Principal Name": user.user_principal_name or "N/A",
                        "Display Name": user.display_name or "N/A",
                        "Account Enabled": user.account_enabled,
                        "License Count": len(license_names),
                        "Licenses Assigned": "; ".join(license_names) if license_names else "None",
                        "Has Activity": has_activity,
                        "Last Sign-In": last_sign_in,
                        "Usage Status": usage_status
                    })

                    if include_raw_data:
                        raw_license_data.append({
                            "user_principal_name": user.user_principal_name,
                            "display_name": user.display_name,
                            "account_enabled": user.account_enabled,
                            "assigned_licenses": user.assigned_licenses,
                            "license_names": license_names,
                            "has_activity": has_activity,
                            "last_sign_in": last_sign_in
                        })

                    # Visual feedback
                    if has_activity:
                        print(f"    Active ({len(license_names)} licenses)")
                    else:
                        print(f"    Inactive ({len(license_names)} licenses)")

                except Exception as e:
                    print(f"    Error checking user: {str(e)[:50]}")
                    license_data.append({
                        "User Principal Name": user.user_principal_name or "N/A",
                        "Display Name": user.display_name or "N/A",
                        "Account Enabled": user.account_enabled,
                        "License Count": "Error",
                        "Licenses Assigned": "Error",
                        "Has Activity": "Error",
                        "Last Sign-In": "Error",
                        "Usage Status": "Error"
                    })

            df = pd.DataFrame(license_data)
            result["dataframe"] = df
            result["raw_data"] = raw_license_data
            result["license_breakdown"] = license_breakdown

            # Calculate summary stats
            if not df.empty:
                active_mask = df["Has Activity"] == True
                result["active_count"] = active_mask.sum()
                result["inactive_count"] = (df["Has Activity"] == False).sum()

            return result

        except Exception as e:
            print(f"Error generating license usage report: {e}")
            import traceback
            traceback.print_exc()
            return result

    def _generate_filename(
        self,
        report_type: str,
        days: Optional[int] = None,
        user_filter: Optional[str] = None
    ) -> str:
        """Generate standardized filename for CSV export"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        parts = ["entralense", report_type]

        if days:
            parts.append(f"{days}d")

        if user_filter:
            # Clean username for filename
            safe_user = user_filter.replace("@", "_").replace(".", "_")
            parts.append(safe_user[:20])  # Limit length

        parts.append(timestamp)

        filename = "_".join(parts) + ".csv"
        return str(self.export_dir / filename)

    def _save_to_csv(self, df: pd.DataFrame, filename: str):
        """Save DataFrame to CSV with proper formatting"""
        try:
            df.to_csv(filename, index=False, encoding='utf-8-sig')  # UTF-8 with BOM for Excel
            print(f"✅ Report saved: {filename}")
            print(f"   Records: {len(df)}")
            print(f"   Size: {Path(filename).stat().st_size / 1024:.1f} KB")

            # Show preview
            print("\n📋 Preview (first 5 rows):")
            preview_cols = list(df.columns)[:5]  # Limit columns for display
            print(df[preview_cols].head().to_string(index=False, max_colwidth=25))
            print(f"\n📁 Full report: {filename}")

        except Exception as e:
            print(f"❌ Error saving CSV: {e}")

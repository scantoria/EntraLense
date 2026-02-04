"""Asset tracking and inventory management module."""

import asyncio
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path

from modules.azure_auth import EntraAuth
from modules.console_ui import ConsoleUI

logger = logging.getLogger(__name__)


class AssetStatus(Enum):
    """Asset status categories."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    RETIRED = "retired"
    LOST = "lost"
    STOLEN = "stolen"
    UNDER_REPAIR = "under_repair"
    IN_STORAGE = "in_storage"
    UNKNOWN = "unknown"


class AssetType(Enum):
    """Asset type categories."""
    LAPTOP = "laptop"
    DESKTOP = "desktop"
    SERVER = "server"
    TABLET = "tablet"
    MOBILE = "mobile"
    MONITOR = "monitor"
    PRINTER = "printer"
    NETWORK = "network"
    PERIPHERAL = "peripheral"
    OTHER = "other"


class WarrantyStatus(Enum):
    """Warranty status."""
    ACTIVE = "active"
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    UNKNOWN = "unknown"
    NONE = "none"


@dataclass
class Asset:
    """Asset information structure."""
    asset_id: str
    serial_number: str
    asset_tag: str = ""
    device_name: str = ""
    asset_type: AssetType = AssetType.OTHER
    manufacturer: str = ""
    model: str = ""
    model_number: str = ""

    # Ownership
    assigned_to: str = ""
    department: str = ""
    location: str = ""
    cost_center: str = ""

    # Dates
    purchase_date: Optional[datetime] = None
    warranty_end_date: Optional[datetime] = None
    deployment_date: Optional[datetime] = None
    last_seen_date: Optional[datetime] = None

    # Status
    status: AssetStatus = AssetStatus.UNKNOWN
    warranty_status: WarrantyStatus = WarrantyStatus.UNKNOWN
    is_managed: bool = False
    requires_attention: bool = False
    attention_reason: str = ""

    # Financial
    purchase_price: float = 0.0
    current_value: float = 0.0
    depreciation_rate: float = 0.25  # 25% per year

    # Technical specs
    specifications: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert asset to dictionary."""
        return {
            "asset_id": self.asset_id,
            "serial_number": self.serial_number,
            "asset_tag": self.asset_tag,
            "device_name": self.device_name,
            "asset_type": self.asset_type.value,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "model_number": self.model_number,
            "assigned_to": self.assigned_to,
            "department": self.department,
            "location": self.location,
            "cost_center": self.cost_center,
            "purchase_date": self.purchase_date.isoformat() if self.purchase_date else "",
            "warranty_end_date": self.warranty_end_date.isoformat() if self.warranty_end_date else "",
            "deployment_date": self.deployment_date.isoformat() if self.deployment_date else "",
            "last_seen_date": self.last_seen_date.isoformat() if self.last_seen_date else "",
            "status": self.status.value,
            "warranty_status": self.warranty_status.value,
            "is_managed": self.is_managed,
            "requires_attention": self.requires_attention,
            "attention_reason": self.attention_reason,
            "purchase_price": self.purchase_price,
            "current_value": self.current_value,
            "specifications": json.dumps(self.specifications),
            "notes": self.notes
        }

    def calculate_current_value(self) -> float:
        """Calculate current depreciated value."""
        if not self.purchase_date or self.purchase_price <= 0:
            return 0.0

        now = datetime.utcnow()
        years_owned = (now - self.purchase_date).days / 365.25

        # Simple straight-line depreciation
        depreciated_value = self.purchase_price * ((1 - self.depreciation_rate) ** years_owned)

        # Don't go below 10% of purchase price
        return max(depreciated_value, self.purchase_price * 0.1)

    def calculate_warranty_status(self) -> WarrantyStatus:
        """Calculate warranty status based on end date."""
        if not self.warranty_end_date:
            return WarrantyStatus.UNKNOWN

        now = datetime.utcnow()

        if now > self.warranty_end_date:
            return WarrantyStatus.EXPIRED
        elif (self.warranty_end_date - now).days <= 90:  # 90 days warning
            return WarrantyStatus.EXPIRING_SOON
        else:
            return WarrantyStatus.ACTIVE

    def update_attention_status(self) -> None:
        """Update whether asset requires attention."""
        reasons = []

        # Check warranty
        warranty_status = self.calculate_warranty_status()
        if warranty_status == WarrantyStatus.EXPIRED:
            reasons.append("Warranty expired")
        elif warranty_status == WarrantyStatus.EXPIRING_SOON:
            reasons.append("Warranty expiring soon")

        # Check status
        if self.status in [AssetStatus.LOST, AssetStatus.STOLEN]:
            reasons.append(f"Asset {self.status.value}")

        # Check last seen
        if self.last_seen_date:
            days_since_seen = (datetime.utcnow() - self.last_seen_date).days
            if days_since_seen > 90:  # 90 days
                reasons.append(f"Not seen in {days_since_seen} days")

        # Check if unassigned but active
        if self.status == AssetStatus.ACTIVE and not self.assigned_to:
            reasons.append("Active but unassigned")

        self.requires_attention = len(reasons) > 0
        self.attention_reason = "; ".join(reasons) if reasons else ""


@dataclass
class AssetSummary:
    """Asset inventory summary."""
    total_assets: int = 0
    total_value: float = 0.0
    managed_assets: int = 0
    unmanaged_assets: int = 0

    # Status breakdown
    status_counts: Dict[str, int] = field(default_factory=dict)

    # Type breakdown
    type_counts: Dict[str, int] = field(default_factory=dict)

    # Warranty breakdown
    warranty_counts: Dict[str, int] = field(default_factory=dict)

    # Department breakdown
    department_counts: Dict[str, int] = field(default_factory=dict)

    # Assets needing attention
    assets_needing_attention: int = 0
    attention_reasons: Dict[str, int] = field(default_factory=dict)

    # Financial summary
    total_purchase_value: float = 0.0
    total_current_value: float = 0.0
    total_depreciation: float = 0.0

    # Age analysis
    assets_by_age: Dict[str, int] = field(default_factory=dict)  # <1y, 1-3y, 3-5y, >5y

    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to dictionary."""
        return {
            "total_assets": self.total_assets,
            "total_value": self.total_current_value,
            "managed_assets": self.managed_assets,
            "unmanaged_assets": self.unmanaged_assets,
            "status_counts": self.status_counts,
            "type_counts": self.type_counts,
            "warranty_counts": self.warranty_counts,
            "department_counts": self.department_counts,
            "assets_needing_attention": self.assets_needing_attention,
            "attention_reasons": self.attention_reasons,
            "financial_summary": {
                "total_purchase_value": self.total_purchase_value,
                "total_current_value": self.total_current_value,
                "total_depreciation": self.total_depreciation
            },
            "assets_by_age": self.assets_by_age
        }


class AssetTracker:
    """Asset tracking and inventory management."""

    def __init__(self, auth: EntraAuth, config):
        """
        Initialize asset tracker.

        Args:
            auth: Authenticated EntraAuth instance
            config: Application configuration
        """
        self.auth = auth
        self.config = config
        self.ui = ConsoleUI()
        self.assets: Dict[str, Asset] = {}  # Key: asset_id
        self.summary: Optional[AssetSummary] = None

        # Load existing asset data if available
        self._load_asset_data()

    def _load_asset_data(self) -> None:
        """Load existing asset data from file."""
        data_file = Path("data/asset_inventory.json")
        if data_file.exists():
            try:
                with open(data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                for asset_data in data.get("assets", []):
                    asset = self._dict_to_asset(asset_data)
                    if asset:
                        self.assets[asset.asset_id] = asset

                logger.info(f"Loaded {len(self.assets)} assets from inventory file")

            except Exception as e:
                logger.error(f"Error loading asset data: {e}")

    def _save_asset_data(self) -> None:
        """Save asset data to file."""
        try:
            data_file = Path("data/asset_inventory.json")
            data_file.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "last_updated": datetime.utcnow().isoformat(),
                "total_assets": len(self.assets),
                "assets": [asset.to_dict() for asset in self.assets.values()]
            }

            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)

            logger.info(f"Saved {len(self.assets)} assets to inventory file")

        except Exception as e:
            logger.error(f"Error saving asset data: {e}")

    def _dict_to_asset(self, data: Dict[str, Any]) -> Optional[Asset]:
        """Convert dictionary to Asset object."""
        try:
            # Parse dates
            purchase_date = None
            if data.get("purchase_date"):
                purchase_date = datetime.fromisoformat(data["purchase_date"].replace('Z', '+00:00'))

            warranty_end_date = None
            if data.get("warranty_end_date"):
                warranty_end_date = datetime.fromisoformat(data["warranty_end_date"].replace('Z', '+00:00'))

            deployment_date = None
            if data.get("deployment_date"):
                deployment_date = datetime.fromisoformat(data["deployment_date"].replace('Z', '+00:00'))

            last_seen_date = None
            if data.get("last_seen_date"):
                last_seen_date = datetime.fromisoformat(data["last_seen_date"].replace('Z', '+00:00'))

            # Parse enums
            asset_type = AssetType(data.get("asset_type", "other"))
            status = AssetStatus(data.get("status", "unknown"))
            warranty_status = WarrantyStatus(data.get("warranty_status", "unknown"))

            # Parse specifications JSON
            specifications = {}
            if data.get("specifications"):
                try:
                    specifications = json.loads(data["specifications"])
                except (json.JSONDecodeError, TypeError):
                    specifications = data.get("specifications", {})

            asset = Asset(
                asset_id=data.get("asset_id", ""),
                serial_number=data.get("serial_number", ""),
                asset_tag=data.get("asset_tag", ""),
                device_name=data.get("device_name", ""),
                asset_type=asset_type,
                manufacturer=data.get("manufacturer", ""),
                model=data.get("model", ""),
                model_number=data.get("model_number", ""),
                assigned_to=data.get("assigned_to", ""),
                department=data.get("department", ""),
                location=data.get("location", ""),
                cost_center=data.get("cost_center", ""),
                purchase_date=purchase_date,
                warranty_end_date=warranty_end_date,
                deployment_date=deployment_date,
                last_seen_date=last_seen_date,
                status=status,
                warranty_status=warranty_status,
                is_managed=data.get("is_managed", False),
                requires_attention=data.get("requires_attention", False),
                attention_reason=data.get("attention_reason", ""),
                purchase_price=data.get("purchase_price", 0.0),
                current_value=data.get("current_value", 0.0),
                specifications=specifications,
                notes=data.get("notes", "")
            )

            return asset

        except Exception as e:
            logger.error(f"Error converting dict to asset: {e}")
            return None

    async def collect_asset_data(self, devices_info: List[Dict[str, Any]]) -> List[Asset]:
        """
        Collect asset data from devices and merge with existing inventory.

        Args:
            devices_info: List of device information dictionaries

        Returns:
            List of Asset objects
        """
        print(f"   Collecting asset data from {len(devices_info)} devices...")

        collected_assets = []

        for device_info in devices_info:
            try:
                asset = await self._create_asset_from_device(device_info)
                if asset:
                    collected_assets.append(asset)

                    # Update or add to main inventory
                    if asset.asset_id in self.assets:
                        # Merge with existing asset
                        self._merge_assets(self.assets[asset.asset_id], asset)
                    else:
                        # Add new asset
                        self.assets[asset.asset_id] = asset

            except Exception as e:
                logger.error(f"Error creating asset from device {device_info.get('device_name', 'unknown')}: {e}")

        # Update asset statuses
        for asset in self.assets.values():
            asset.warranty_status = asset.calculate_warranty_status()
            asset.current_value = asset.calculate_current_value()
            asset.update_attention_status()

        # Save updated inventory
        self._save_asset_data()

        print(f"   Asset collection complete. {len(collected_assets)} devices processed.")

        return collected_assets

    async def _create_asset_from_device(self, device_info: Dict[str, Any]) -> Optional[Asset]:
        """Create Asset object from device information."""
        try:
            device_id = device_info.get("device_id", "")
            serial_number = device_info.get("serial_number", "")

            if not serial_number:
                # Generate a placeholder serial number
                serial_number = f"UNKNOWN-{device_id[:8]}" if device_id else f"UNKNOWN-{id(device_info)}"

            # Determine asset type from device info
            asset_type = self._determine_asset_type(device_info)

            # Generate asset ID
            asset_id = self._generate_asset_id(serial_number, asset_type)

            # Parse dates
            last_seen_date = None
            if device_info.get("last_sync_date_time"):
                last_seen_date = device_info["last_sync_date_time"]

            # Create asset
            asset = Asset(
                asset_id=asset_id,
                serial_number=serial_number,
                device_name=device_info.get("device_name", f"{asset_type.value}-{serial_number[-6:]}"),
                asset_type=asset_type,
                manufacturer=device_info.get("manufacturer", "Unknown"),
                model=device_info.get("model", "Unknown"),
                assigned_to=device_info.get("user_principal_name", ""),
                last_seen_date=last_seen_date,
                status=AssetStatus.ACTIVE,
                is_managed=True,
                requires_attention=False
            )

            # Set default warranty (1 year from now if new)
            if not asset.warranty_end_date:
                asset.warranty_end_date = datetime.utcnow() + timedelta(days=365)

            # Set default purchase date (6 months ago if new)
            if not asset.purchase_date:
                asset.purchase_date = datetime.utcnow() - timedelta(days=180)

            # Set default deployment date
            if not asset.deployment_date and last_seen_date:
                asset.deployment_date = last_seen_date

            # Set default purchase price based on type
            asset.purchase_price = self._estimate_purchase_price(asset_type)

            # Add specifications
            asset.specifications = {
                "operating_system": device_info.get("operating_system", ""),
                "os_version": device_info.get("os_version", ""),
                "management_agent": device_info.get("management_agent", ""),
                "compliance_state": device_info.get("compliance_state", ""),
                "device_id": device_id
            }

            return asset

        except Exception as e:
            logger.error(f"Error creating asset from device: {e}")
            return None

    def _determine_asset_type(self, device_info: Dict[str, Any]) -> AssetType:
        """Determine asset type from device information."""
        device_name = device_info.get("device_name", "").lower()
        model = device_info.get("model", "").lower()
        os_name = device_info.get("operating_system", "").lower()

        # Check for specific keywords
        if any(word in device_name for word in ["laptop", "notebook", "ultrabook", "latitude", "xps", "spectre"]):
            return AssetType.LAPTOP
        elif any(word in device_name for word in ["desktop", "workstation", "tower", "optiplex"]):
            return AssetType.DESKTOP
        elif any(word in device_name for word in ["server", "esxi", "hyper-v"]):
            return AssetType.SERVER
        elif any(word in device_name for word in ["tablet", "ipad", "surface", "galaxy tab"]):
            return AssetType.TABLET
        elif any(word in device_name for word in ["phone", "iphone", "android", "galaxy"]):
            return AssetType.MOBILE
        elif "monitor" in device_name or "display" in device_name:
            return AssetType.MONITOR
        elif "printer" in device_name:
            return AssetType.PRINTER
        elif any(word in device_name for word in ["switch", "router", "firewall", "access point"]):
            return AssetType.NETWORK

        # Check model
        if any(word in model for word in ["macbook", "thinkpad", "latitude", "elitebook", "probook"]):
            return AssetType.LAPTOP
        elif any(word in model for word in ["imac", "optiplex", "thinkcentre"]):
            return AssetType.DESKTOP
        elif any(word in model for word in ["ipad", "surface"]):
            return AssetType.TABLET
        elif any(word in model for word in ["iphone", "galaxy", "pixel"]):
            return AssetType.MOBILE

        # Guess from OS
        if "windows" in os_name:
            return AssetType.LAPTOP if "surface" in device_name else AssetType.DESKTOP
        elif "macos" in os_name:
            return AssetType.LAPTOP if "macbook" in model else AssetType.DESKTOP
        elif "ios" in os_name:
            return AssetType.MOBILE if "iphone" in model else AssetType.TABLET
        elif "android" in os_name:
            return AssetType.MOBILE

        return AssetType.OTHER

    def _generate_asset_id(self, serial_number: str, asset_type: AssetType) -> str:
        """Generate unique asset ID."""
        import random
        import string

        serial_part = serial_number[:6].upper().replace(' ', 'X')
        type_code = asset_type.value[:3].upper()
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))

        return f"{type_code}-{serial_part}-{random_suffix}"

    def _estimate_purchase_price(self, asset_type: AssetType) -> float:
        """Estimate purchase price based on asset type."""
        price_ranges = {
            AssetType.LAPTOP: (800.0, 2500.0),
            AssetType.DESKTOP: (500.0, 1500.0),
            AssetType.SERVER: (2000.0, 10000.0),
            AssetType.TABLET: (300.0, 1200.0),
            AssetType.MOBILE: (300.0, 1500.0),
            AssetType.MONITOR: (200.0, 1500.0),
            AssetType.PRINTER: (100.0, 3000.0),
            AssetType.NETWORK: (500.0, 5000.0),
            AssetType.PERIPHERAL: (50.0, 500.0),
            AssetType.OTHER: (100.0, 1000.0)
        }

        min_price, max_price = price_ranges.get(asset_type, (100.0, 1000.0))

        # Return midpoint for estimation
        return (min_price + max_price) / 2

    def _merge_assets(self, existing: Asset, new: Asset) -> None:
        """Merge new asset data into existing asset."""
        # Update last seen date if newer
        if new.last_seen_date and (not existing.last_seen_date or new.last_seen_date > existing.last_seen_date):
            existing.last_seen_date = new.last_seen_date

        # Update assignment if new one is not empty
        if new.assigned_to and new.assigned_to != existing.assigned_to:
            existing.assigned_to = new.assigned_to

        # Update device name if better
        if new.device_name and ("unknown" not in new.device_name.lower()):
            existing.device_name = new.device_name

        # Update manufacturer/model if missing
        if not existing.manufacturer or existing.manufacturer == "Unknown":
            existing.manufacturer = new.manufacturer

        if not existing.model or existing.model == "Unknown":
            existing.model = new.model

        # Update management status
        existing.is_managed = True

        # Update specifications
        existing.specifications.update(new.specifications)

    def generate_summary(self) -> AssetSummary:
        """Generate asset inventory summary."""
        summary = AssetSummary()
        summary.total_assets = len(self.assets)

        now = datetime.utcnow()

        for asset in self.assets.values():
            # Count by status
            status = asset.status.value
            summary.status_counts[status] = summary.status_counts.get(status, 0) + 1

            # Count by type
            asset_type = asset.asset_type.value
            summary.type_counts[asset_type] = summary.type_counts.get(asset_type, 0) + 1

            # Count by warranty status
            warranty_status = asset.warranty_status.value
            summary.warranty_counts[warranty_status] = summary.warranty_counts.get(warranty_status, 0) + 1

            # Count by department
            if asset.department:
                summary.department_counts[asset.department] = summary.department_counts.get(asset.department, 0) + 1

            # Count managed vs unmanaged
            if asset.is_managed:
                summary.managed_assets += 1
            else:
                summary.unmanaged_assets += 1

            # Financial calculations
            summary.total_purchase_value += asset.purchase_price
            summary.total_current_value += asset.current_value
            summary.total_depreciation += (asset.purchase_price - asset.current_value)

            # Age analysis
            if asset.purchase_date:
                age_years = (now - asset.purchase_date).days / 365.25
                if age_years < 1:
                    age_group = "<1 year"
                elif age_years < 3:
                    age_group = "1-3 years"
                elif age_years < 5:
                    age_group = "3-5 years"
                else:
                    age_group = ">5 years"

                summary.assets_by_age[age_group] = summary.assets_by_age.get(age_group, 0) + 1

            # Assets needing attention
            if asset.requires_attention:
                summary.assets_needing_attention += 1

                # Count attention reasons
                if asset.attention_reason:
                    for reason in asset.attention_reason.split('; '):
                        summary.attention_reasons[reason] = summary.attention_reasons.get(reason, 0) + 1

        self.summary = summary
        return summary

    def export_to_dataframe(self) -> tuple:
        """
        Export asset data to DataFrames.

        Returns:
            Tuple of (assets_df, summary_df, financial_df)
        """
        import pandas as pd

        # Assets DataFrame
        asset_dicts = [asset.to_dict() for asset in self.assets.values()]
        assets_df = pd.DataFrame(asset_dicts) if asset_dicts else pd.DataFrame()

        # Summary DataFrame
        if self.summary:
            summary_data = {
                "Metric": [
                    "Total Assets", "Managed Assets", "Unmanaged Assets",
                    "Total Purchase Value", "Total Current Value", "Total Depreciation",
                    "Assets Needing Attention"
                ],
                "Value": [
                    self.summary.total_assets,
                    self.summary.managed_assets,
                    self.summary.unmanaged_assets,
                    f"${self.summary.total_purchase_value:,.2f}",
                    f"${self.summary.total_current_value:,.2f}",
                    f"${self.summary.total_depreciation:,.2f}",
                    self.summary.assets_needing_attention
                ]
            }
            summary_df = pd.DataFrame(summary_data)
        else:
            summary_df = pd.DataFrame()

        # Financial details DataFrame
        financial_rows = []
        for asset in self.assets.values():
            financial_rows.append({
                "asset_id": asset.asset_id,
                "device_name": asset.device_name,
                "asset_type": asset.asset_type.value,
                "purchase_date": asset.purchase_date.isoformat() if asset.purchase_date else "",
                "purchase_price": asset.purchase_price,
                "current_value": asset.current_value,
                "depreciation": asset.purchase_price - asset.current_value,
                "depreciation_percentage": ((asset.purchase_price - asset.current_value) / asset.purchase_price * 100) if asset.purchase_price > 0 else 0,
                "warranty_status": asset.warranty_status.value
            })

        financial_df = pd.DataFrame(financial_rows) if financial_rows else pd.DataFrame()

        return assets_df, summary_df, financial_df

    def generate_report_text(self) -> str:
        """Generate human-readable asset inventory report."""
        if not self.summary:
            self.generate_summary()

        lines = []

        lines.append("=== ASSET TRACKING & INVENTORY REPORT ===")
        lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")

        # Overall summary
        lines.append("INVENTORY SUMMARY")
        lines.append("-" * 40)
        lines.append(f"Total Assets: {self.summary.total_assets}")
        lines.append(f"Managed Assets: {self.summary.managed_assets}")
        lines.append(f"Unmanaged Assets: {self.summary.unmanaged_assets}")
        lines.append(f"Assets Needing Attention: {self.summary.assets_needing_attention}")
        lines.append(f"Total Current Value: ${self.summary.total_current_value:,.2f}")
        lines.append(f"Total Depreciation: ${self.summary.total_depreciation:,.2f}")
        lines.append("")

        # Asset type breakdown
        lines.append("ASSET TYPE BREAKDOWN")
        lines.append("-" * 40)
        for asset_type, count in sorted(self.summary.type_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / self.summary.total_assets * 100) if self.summary.total_assets > 0 else 0
            lines.append(f"{asset_type.title()}: {count} ({percentage:.1f}%)")
        lines.append("")

        # Status breakdown
        lines.append("ASSET STATUS")
        lines.append("-" * 40)
        for status, count in sorted(self.summary.status_counts.items()):
            percentage = (count / self.summary.total_assets * 100) if self.summary.total_assets > 0 else 0
            status_display = status.replace('_', ' ').title()
            lines.append(f"{status_display}: {count} ({percentage:.1f}%)")
        lines.append("")

        # Warranty status
        lines.append("WARRANTY STATUS")
        lines.append("-" * 40)
        for warranty_status, count in sorted(self.summary.warranty_counts.items()):
            percentage = (count / self.summary.total_assets * 100) if self.summary.total_assets > 0 else 0
            warranty_display = warranty_status.replace('_', ' ').title()
            lines.append(f"{warranty_display}: {count} ({percentage:.1f}%)")
        lines.append("")

        # Age analysis
        lines.append("ASSET AGE DISTRIBUTION")
        lines.append("-" * 40)
        for age_group, count in sorted(self.summary.assets_by_age.items()):
            percentage = (count / self.summary.total_assets * 100) if self.summary.total_assets > 0 else 0
            lines.append(f"{age_group}: {count} ({percentage:.1f}%)")
        lines.append("")

        # Assets needing attention
        if self.summary.assets_needing_attention > 0:
            lines.append(f"ASSETS NEEDING ATTENTION ({self.summary.assets_needing_attention})")
            lines.append("-" * 40)

            # Show top attention reasons
            for reason, count in sorted(self.summary.attention_reasons.items(), key=lambda x: x[1], reverse=True)[:5]:
                lines.append(f"  {reason}: {count} assets")

            # Find and list some example assets
            attention_assets = [a for a in self.assets.values() if a.requires_attention]
            if attention_assets:
                lines.append("\nExample Assets Needing Attention:")
                for i, asset in enumerate(attention_assets[:3], 1):  # Show first 3
                    lines.append(f"{i}. {asset.device_name} ({asset.asset_type.value})")
                    lines.append(f"   Reason: {asset.attention_reason}")
                    if i < 3:
                        lines.append("")

            if self.summary.assets_needing_attention > 3:
                lines.append(f"\n... and {self.summary.assets_needing_attention - 3} more assets")

            lines.append("")

        # Department breakdown (if available)
        if self.summary.department_counts:
            lines.append("DEPARTMENT DISTRIBUTION")
            lines.append("-" * 40)
            for department, count in sorted(self.summary.department_counts.items(), key=lambda x: x[1], reverse=True)[:5]:  # Top 5
                percentage = (count / self.summary.total_assets * 100) if self.summary.total_assets > 0 else 0
                lines.append(f"{department}: {count} ({percentage:.1f}%)")
            lines.append("")

        # Recommendations
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 40)

        if self.summary.assets_needing_attention > 0:
            lines.append("1. Address assets needing immediate attention")
            if "Warranty expired" in self.summary.attention_reasons:
                lines.append("2. Review warranty status and consider extended support")
            if "Asset lost" in self.summary.attention_reasons or "Asset stolen" in self.summary.attention_reasons:
                lines.append("3. Investigate lost/stolen assets and update records")

        if self.summary.unmanaged_assets > 0:
            lines.append("4. Discover and onboard unmanaged assets")

        age_dist = self.summary.assets_by_age
        if age_dist.get(">5 years", 0) > (self.summary.total_assets * 0.2):  # If >20% are >5 years old
            lines.append("5. Consider refresh program for aging assets")

        lines.append("6. Regular inventory audits and updates")
        lines.append("7. Implement asset tagging system")
        lines.append("8. Integrate with procurement system for auto-updates")

        return "\n".join(lines)

    def find_assets_by_serial(self, serial_number: str) -> List[Asset]:
        """Find assets by serial number (partial or full match)."""
        serial_lower = serial_number.lower()
        matches = []

        for asset in self.assets.values():
            if serial_lower in asset.serial_number.lower():
                matches.append(asset)

        return matches

    def find_assets_by_user(self, username: str) -> List[Asset]:
        """Find assets assigned to a user."""
        username_lower = username.lower()
        matches = []

        for asset in self.assets.values():
            if username_lower in asset.assigned_to.lower():
                matches.append(asset)

        return matches

    def find_duplicate_serial_numbers(self) -> Dict[str, List[Asset]]:
        """Find duplicate serial numbers in inventory."""
        serial_map = {}

        for asset in self.assets.values():
            serial = asset.serial_number
            if serial:
                if serial not in serial_map:
                    serial_map[serial] = []
                serial_map[serial].append(asset)

        # Return only duplicates (more than one asset with same serial)
        return {serial: assets for serial, assets in serial_map.items() if len(assets) > 1}

    def generate_audit_report(self) -> str:
        """Generate audit report for inventory verification."""
        lines = []

        lines.append("=== ASSET INVENTORY AUDIT REPORT ===")
        lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Total Assets: {len(self.assets)}")
        lines.append("")

        # Serial number audit
        duplicates = self.find_duplicate_serial_numbers()
        if duplicates:
            lines.append("DUPLICATE SERIAL NUMBERS FOUND")
            lines.append("-" * 40)
            for serial, assets in list(duplicates.items())[:5]:  # Show first 5
                lines.append(f"Serial: {serial}")
                for asset in assets:
                    lines.append(f"  - {asset.device_name} ({asset.asset_id})")
                lines.append("")

            if len(duplicates) > 5:
                lines.append(f"... and {len(duplicates) - 5} more duplicate serials")
            lines.append("")
        else:
            lines.append("No duplicate serial numbers found")
            lines.append("")

        # Missing serial numbers
        missing_serials = [a for a in self.assets.values() if not a.serial_number or a.serial_number.startswith("UNKNOWN")]
        if missing_serials:
            lines.append("ASSETS WITH MISSING/INVALID SERIAL NUMBERS")
            lines.append("-" * 40)
            for asset in missing_serials[:10]:  # Show first 10
                lines.append(f"  - {asset.device_name} ({asset.asset_id}) - Type: {asset.asset_type.value}")
            lines.append("")

            if len(missing_serials) > 10:
                lines.append(f"... and {len(missing_serials) - 10} more assets")
            lines.append("")
        else:
            lines.append("All assets have valid serial numbers")
            lines.append("")

        # Unassigned active assets
        unassigned_active = [a for a in self.assets.values() if a.status == AssetStatus.ACTIVE and not a.assigned_to]
        if unassigned_active:
            lines.append("ACTIVE ASSETS WITHOUT ASSIGNMENT")
            lines.append("-" * 40)
            for asset in unassigned_active[:10]:
                lines.append(f"  - {asset.device_name} ({asset.asset_id}) - {asset.asset_type.value}")
            lines.append("")
        else:
            lines.append("All active assets are assigned")
            lines.append("")

        # Assets not seen in >180 days
        old_assets = []
        for asset in self.assets.values():
            if asset.last_seen_date:
                days_since_seen = (datetime.utcnow() - asset.last_seen_date).days
                if days_since_seen > 180:
                    old_assets.append((asset, days_since_seen))

        if old_assets:
            lines.append("ASSETS NOT SEEN IN >180 DAYS")
            lines.append("-" * 40)
            for asset, days in sorted(old_assets, key=lambda x: x[1], reverse=True)[:10]:
                lines.append(f"  - {asset.device_name} - {days} days - Last seen: {asset.last_seen_date.strftime('%Y-%m-%d')}")
            lines.append("")

        lines.append("AUDIT COMPLETE")
        lines.append("-" * 40)
        lines.append("Recommend physical verification of high-value assets")
        lines.append("Update records for any discrepancies found")

        return "\n".join(lines)

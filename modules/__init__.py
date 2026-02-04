# modules/__init__.py
"""
EntraLense modules package.
"""
from .azure_auth import entra_auth
from .config_manager import config_manager, EntraConfig
from .console_ui import ConsoleUI
from .user_reports import UserReports
from .intune_integration import IntuneIntegration, IntuneDevice
from .equipment_reports import EquipmentReports
from .asset_tracker import AssetTracker, Asset, AssetType, AssetStatus, WarrantyStatus

__all__ = [
    'entra_auth',
    'config_manager',
    'EntraConfig',
    'ConsoleUI',
    'UserReports',
    'IntuneIntegration',
    'IntuneDevice',
    'EquipmentReports',
    'AssetTracker',
    'Asset',
    'AssetType',
    'AssetStatus',
    'WarrantyStatus'
]

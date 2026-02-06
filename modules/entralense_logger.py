# modules/entralense_logger.py
"""
Cross-platform logging system for EntraLense.
Provides comprehensive error tracking and troubleshooting capabilities.
"""
import logging
import os
import sys
from pathlib import Path
from datetime import datetime
import platform
import traceback
from typing import Optional

class EntraLenseLogger:
    """Cross-platform logging system for EntraLense"""
    
    def __init__(self, name: str = "EntraLense"):
        """
        Initialize logger with platform-specific configuration
        
        Args:
            name: Logger name (default: "EntraLense")
        """
        self.name = name
        self.log_dir = self._get_log_directory()
        self.log_file = self._create_log_file()
        self.logger = self._setup_logger()
        
        # Log initialization
        self.logger.info("=" * 80)
        self.logger.info(f"EntraLense Logger Initialized")
        self.logger.info(f"Platform: {platform.system()} {platform.release()}")
        self.logger.info(f"Python: {sys.version}")
        self.logger.info(f"Log Directory: {self.log_dir}")
        self.logger.info(f"Log File: {self.log_file}")
        self.logger.info("=" * 80)
    
    def _get_log_directory(self) -> Path:
        """Get platform-specific log directory"""
        system = platform.system()
        
        if system == 'Windows':
            # Windows: C:\Users\<username>\AppData\Local\EntraLense\Logs\
            log_dir = Path(os.getenv('LOCALAPPDATA')) / "EntraLense" / "Logs"
        elif system == 'Darwin':  # macOS
            # macOS: /Users/<username>/Library/Logs/EntraLense/
            log_dir = Path.home() / "Library" / "Logs" / "EntraLense"
        else:  # Linux fallback
            # Linux: ~/.local/share/EntraLense/logs/
            log_dir = Path.home() / ".local" / "share" / "EntraLense" / "logs"
        
        # Create directory if it doesn't exist
        log_dir.mkdir(parents=True, exist_ok=True)
        
        return log_dir
    
    def _create_log_file(self) -> Path:
        """Create daily log file with timestamp"""
        timestamp = datetime.now().strftime('%Y%m%d')
        log_file = self.log_dir / f"entralense_{timestamp}.log"
        
        # Clean up old logs (keep last 14 days)
        self._cleanup_old_logs(days=14)
        
        return log_file
    
    def _cleanup_old_logs(self, days: int = 14):
        """Remove log files older than specified days"""
        try:
            cutoff_date = datetime.now().timestamp() - (days * 24 * 60 * 60)
            
            for log_file in self.log_dir.glob("entralense_*.log"):
                if log_file.stat().st_mtime < cutoff_date:
                    log_file.unlink()
                    print(f"Removed old log: {log_file.name}")
        except Exception as e:
            print(f"Warning: Could not clean up old logs: {e}")
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logger with file and console handlers"""
        logger = logging.getLogger(self.name)
        logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers to avoid duplicates
        logger.handlers.clear()
        
        # File handler - logs everything
        file_handler = logging.FileHandler(
            self.log_file, 
            encoding='utf-8',
            mode='a'  # Append mode
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        
        # Console handler - only warnings and errors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.WARNING)
        console_formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        
        # Add handlers
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def get_logger(self) -> logging.Logger:
        """Get the logger instance"""
        return self.logger
    
    def get_log_directory(self) -> Path:
        """Get the log directory path"""
        return self.log_dir
    
    def log_exception(self, exception: Exception, context: str = ""):
        """
        Log exception with full traceback
        
        Args:
            exception: The exception to log
            context: Additional context about where the exception occurred
        """
        error_msg = f"{context}: {str(exception)}" if context else str(exception)
        self.logger.error(error_msg, exc_info=True)
    
    def log_api_call(self, method: str, endpoint: str, status: Optional[str] = None, 
                     error: Optional[str] = None):
        """
        Log API call details
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            status: Response status
            error: Error message if failed
        """
        if error:
            self.logger.error(f"API Call Failed - {method} {endpoint} - Error: {error}")
        else:
            self.logger.info(f"API Call - {method} {endpoint} - Status: {status}")
    
    def log_auth_attempt(self, method: str, success: bool, error: Optional[str] = None):
        """
        Log authentication attempt
        
        Args:
            method: Auth method (interactive, client_secret, device_code)
            success: Whether auth succeeded
            error: Error message if failed
        """
        if success:
            self.logger.info(f"Authentication successful - Method: {method}")
        else:
            self.logger.error(f"Authentication failed - Method: {method} - Error: {error}")
    
    def log_config_load(self, source: str, has_tenant: bool, has_client: bool):
        """
        Log configuration loading
        
        Args:
            source: Config source (file, environment, wizard)
            has_tenant: Whether tenant ID is present
            has_client: Whether client ID is present
        """
        self.logger.info(
            f"Config loaded from {source} - Tenant ID: {has_tenant}, Client ID: {has_client}"
        )
    
    def log_report_generation(self, report_type: str, success: bool, 
                             records: int = 0, duration: float = 0.0, 
                             error: Optional[str] = None):
        """
        Log report generation
        
        Args:
            report_type: Type of report generated
            success: Whether generation succeeded
            records: Number of records in report
            duration: Time taken in seconds
            error: Error message if failed
        """
        if success:
            self.logger.info(
                f"Report generated - Type: {report_type}, Records: {records}, "
                f"Duration: {duration:.2f}s"
            )
        else:
            self.logger.error(
                f"Report failed - Type: {report_type} - Error: {error}"
            )


def open_logs_folder():
    """Open the logs folder in the system's file explorer"""
    logger_instance = EntraLenseLogger()
    log_dir = logger_instance.get_log_directory()
    
    system = platform.system()
    
    try:
        if system == 'Windows':
            os.startfile(log_dir)
        elif system == 'Darwin':  # macOS
            os.system(f'open "{log_dir}"')
        else:  # Linux
            os.system(f'xdg-open "{log_dir}"')
    except Exception as e:
        print(f"Error opening logs folder: {e}")
        print(f"Logs location: {log_dir}")


# Global logger instance
_global_logger: Optional[EntraLenseLogger] = None

def get_global_logger() -> logging.Logger:
    """Get or create the global logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = EntraLenseLogger()
    return _global_logger.get_logger()


# Test function
if __name__ == "__main__":
    print("Testing EntraLense Logger...")
    print(f"Platform: {platform.system()}")
    
    logger_system = EntraLenseLogger()
    logger = logger_system.get_logger()
    
    # Test various log levels
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    
    # Test exception logging
    try:
        raise ValueError("Test exception for logging")
    except Exception as e:
        logger_system.log_exception(e, "Test context")
    
    # Test specialized logging
    logger_system.log_api_call("GET", "/users", status="200")
    logger_system.log_auth_attempt("interactive", True)
    logger_system.log_config_load("file", True, True)
    logger_system.log_report_generation("Login Activity", True, 150, 2.5)
    
    print(f"\nLog file created at: {logger_system.log_file}")
    print(f"Log directory: {logger_system.log_dir}")
    
    # Open logs folder
    input("\nPress Enter to open logs folder...")
    open_logs_folder()

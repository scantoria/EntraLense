# modules/console_ui.py
"""
Console UI utilities for EntraLense.
Provides colored output, menus, and user interaction.
"""
import os
import sys
from colorama import init, Fore, Back, Style

# Initialize colorama for cross-platform colored text
init(autoreset=True)

class ConsoleUI:
    """Handles console UI elements: colors, menus, displays"""
    
    def __init__(self, dark_mode=True):
        self.dark_mode = dark_mode
        self.setup_colors()
    
    def setup_colors(self):
        """Setup color scheme based on mode"""
        if self.dark_mode:
            self.bg_color = Back.BLACK
            self.text_color = Fore.WHITE
            self.header_color = Fore.GREEN
            self.warning_color = Fore.YELLOW
            self.error_color = Fore.RED
            self.success_color = Fore.GREEN
            self.info_color = Fore.CYAN
        else:
            self.bg_color = Back.WHITE
            self.text_color = Fore.BLACK
            self.header_color = Fore.BLUE
            self.warning_color = Fore.YELLOW
            self.error_color = Fore.RED
            self.success_color = Fore.GREEN
            self.info_color = Fore.CYAN
    
    def clear_screen(self):
        """Clear console screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self, title: str):
        """Print application header"""
        print(f"{self.bg_color}{self.header_color}{'='*60}")
        print(f"{self.header_color}    {title}")
        print(f"{self.header_color}{'='*60}{Style.RESET_ALL}")
        print()
    
    def print_message(self, message: str, msg_type: str = "info"):
        """Print a colored message"""
        colors = {
            "info": self.info_color,
            "success": self.success_color,
            "warning": self.warning_color,
            "error": self.error_color,
            "yellow": Fore.YELLOW,
            "green": Fore.GREEN,
            "red": Fore.RED,
            "cyan": Fore.CYAN
        }
        
        color = colors.get(msg_type, self.text_color)
        print(f"{color}{message}{Style.RESET_ALL}")
    
    def display_menu(self, title: str, menu_items: list) -> str:
        """Display a menu and get user choice"""
        print(f"\n{self.header_color}{title}")
        print(f"{self.header_color}{'─' * len(title)}{Style.RESET_ALL}")
        
        for key, description in menu_items:
            print(f"  {self.info_color}{key}. {self.text_color}{description}")
        
        print()
        choice = input(f"{self.info_color}Select option: {Style.RESET_ALL}").strip()
        return choice
    
    def display_dataframe(self, df, title: str, max_rows: int = 20):
        """Display a pandas DataFrame in formatted table"""
        if df.empty:
            self.print_message("⚠️ No data available.", "warning")
            return
        
        print(f"\n{self.header_color}{title}")
        print(f"{self.header_color}{'─' * len(title)}{Style.RESET_ALL}")
        
        # Display first N rows
        display_df = df.head(max_rows)
        
        # Convert to string with formatting
        df_str = display_df.to_string(index=False)
        
        # Add subtle color to header row
        lines = df_str.split('\n')
        if lines:
            print(f"{self.info_color}{lines[0]}{Style.RESET_ALL}")  # Header row
            for line in lines[1:]:
                print(f"{self.text_color}{line}{Style.RESET_ALL}")
        
        # Show stats
        print(f"\n{self.info_color}Showing {len(display_df)} of {len(df)} rows")
        
        if len(df) > max_rows:
            self.print_message(f"⚠️  Truncated to first {max_rows} rows. Use export for full data.", "warning")
    
    def get_input(self, prompt: str, default: str = "") -> str:
        """Get user input with optional default value"""
        if default:
            prompt = f"{prompt} [{default}] "
        
        response = input(f"{self.info_color}{prompt}{Style.RESET_ALL}").strip()
        return response if response else default
    
    def press_any_key(self):
        """Wait for user to press any key"""
        input(f"\n{self.info_color}Press Enter to continue...{Style.RESET_ALL}")
    
    def print_table(self, data: list, headers: list | None = None):
        """Print a simple table"""
        if not data:
            return
        
        if headers:
            print(f"\n{self.info_color}{' | '.join(headers)}{Style.RESET_ALL}")
            print(f"{self.info_color}{'─' * sum(len(h) + 3 for h in headers)}{Style.RESET_ALL}")
        
        for row in data:
            if isinstance(row, dict) and headers:
                row_str = " | ".join(str(row.get(h, '')) for h in headers)
            else:
                row_str = " | ".join(str(item) for item in row)
            print(f"{self.text_color}{row_str}{Style.RESET_ALL}")

# Global instance for easy access
ui = ConsoleUI()
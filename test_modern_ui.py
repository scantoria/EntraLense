# test_modern_ui.py
from modules.console_ui import ConsoleUI

ui = ConsoleUI()

print("Testing modern ConsoleUI with Python 3.10+ type hints...")
ui.print_header("Modern Type Hints Test")

# Test with explicit types
menu_items: list[tuple[str, str]] = [
    ("1", "Option One"),
    ("2", "Option Two"),
    ("3", "Option Three")
]

choice = ui.display_menu("Test Menu", menu_items)
ui.print_message(f"You chose: {choice}", "success")

# Test table with headers
data: list[dict[str, str]] = [
    {"Name": "Alice", "Role": "Admin", "Status": "Active"},
    {"Name": "Bob", "Role": "User", "Status": "Inactive"},
    {"Name": "Charlie", "Role": "Admin", "Status": "Active"}
]

headers: list[str] = ["Name", "Role", "Status"]
ui.print_table(data, headers)

print("\n✅ All modern type hints working correctly!")
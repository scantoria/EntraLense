# test_ui.py
from modules.console_ui import ConsoleUI

ui = ConsoleUI()

print("Testing ConsoleUI...")
ui.print_header("Test Header")
ui.print_message("Info message", "info")
ui.print_message("Success message", "success")
ui.print_message("Warning message", "warning")
ui.print_message("Error message", "error")

# Test table printing
data = [
    {"Name": "Alice", "Role": "Admin", "Status": "Active"},
    {"Name": "Bob", "Role": "User", "Status": "Inactive"},
    {"Name": "Charlie", "Role": "Admin", "Status": "Active"}
]

print("\nTesting table print:")
ui.print_table(data, ["Name", "Role", "Status"])

print("\n✅ ConsoleUI working correctly!")
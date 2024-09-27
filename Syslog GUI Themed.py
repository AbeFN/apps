import re
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox

# Regular expression to extract relevant fields from log entries
log_pattern = re.compile(r"(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<severity>\w+)\s+"
                         r"src=(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+dst=(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
                         r"sport=(?P<src_port>\d+)\s+dport=(?P<dst_port>\d+)\s+msg=(?P<message>.+)")

# Dracula theme color constants
BACKGROUND_COLOR = "#282A36"
FOREGROUND_COLOR = "#F8F8F2"
ERROR_COLOR = "#FF5555"
WARNING_COLOR = "#F1FA8C"
INFO_COLOR = "#50FA7B"
TEXT_WIDGET_BG = "#44475A"
TEXT_WIDGET_FG = "#F8F8F2"


# Function to process a log line and extract the fields
def process_log_line(line):
    match = log_pattern.search(line)
    if match:
        date = match.group("date")
        severity = match.group("severity")
        src_ip = match.group("src_ip")
        dst_ip = match.group("dst_ip")
        src_port = match.group("src_port")
        dst_port = match.group("dst_port")
        message = match.group("message")

        # Format the log entry for display
        formatted_message = f"[{date}] {severity}\n" \
                            f"Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port}\n" \
                            f"Message: {message}\n"
        return severity, formatted_message
    return None


# Function to open and process a log file
def open_log_file():
    file_path = filedialog.askopenfilename(title="Select Log File",
                                           filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if not file_path:
        return

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            log_text.delete(1.0, tk.END)  # Clear the log text widget
            for line in file:
                result = process_log_line(line.strip())
                if result:
                    severity, formatted_message = result
                    # Display the log entry in different colors based on severity
                    if "ERROR" in severity:
                        log_text.insert(tk.END, formatted_message, "error")
                    elif "WARNING" in severity:
                        log_text.insert(tk.END, formatted_message, "warning")
                    else:
                        log_text.insert(tk.END, formatted_message, "info")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open file: {e}")


# Initialize the main application window with Dracula theme
def create_dracula_gui():
    root = tk.Tk()
    root.title("Syslog Viewer - Dracula Theme")
    root.geometry("800x600")
    root.configure(bg=BACKGROUND_COLOR)

    # Add a button to load a log file
    load_button = tk.Button(root, text="Load Log File", command=open_log_file,
                            bg=TEXT_WIDGET_BG, fg=FOREGROUND_COLOR)
    load_button.pack(pady=10)

    # Add a scrolled text widget to display the log content
    global log_text
    log_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Courier", 10),
                                         bg=TEXT_WIDGET_BG, fg=TEXT_WIDGET_FG,
                                         insertbackground=FOREGROUND_COLOR)
    log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Define custom text tags for color-coding log entries
    log_text.tag_config("error", foreground=ERROR_COLOR)
    log_text.tag_config("warning", foreground=WARNING_COLOR)
    log_text.tag_config("info", foreground=INFO_COLOR)

    # Start the Tkinter main loop
    root.mainloop()


# Run the GUI
if __name__ == "__main__":
    create_dracula_gui()

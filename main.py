import tkinter as tk
import tkinter.messagebox
from PIL import ImageTk
import customtkinter as ctk
import time
import datetime
import threading
import sys
import os
from websockets.sync.server import serve
from websockets.sync.client import connect
from send_recv import send, recv, connected, disconnected

# Constants
APP_WIDTH = 1100
APP_HEIGHT = 580
FONT_MONO = ("Courier New", 13, "normal")
COLOURS = {
    "you": "#85bd84",
    "friend": "#7c87d6",
    "alert": "#bf6767"
}

# Configure appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self._initialize_variables()
        self._configure_window()
        self._create_widgets()
        self._configure_widgets()

    def _initialize_variables(self):
        """Initialize instance variables."""
        self.history = []
        self.client = None
        self.server = None
        self.lines = 0

    def _configure_window(self):
        """Configure the main window properties."""
        self.icon_path = ImageTk.PhotoImage(file=os.path.join("assets", "logo.png"))
        self.wm_iconbitmap()
        self.iconphoto(False, self.icon_path)
        self.title("Disconnected")
        self.geometry(f"{APP_WIDTH}x{APP_HEIGHT}")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

    def _create_widgets(self):
        """Create the main widgets."""
        self.textbox = ctk.CTkTextbox(self, width=250)
        self.entry = ctk.CTkEntry(self, placeholder_text="Message")
        self.send_button = ctk.CTkButton(self, text="Send", command=self.send_message, fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))

    def _configure_widgets(self):
        """Configure the properties of the widgets."""
        self._configure_textbox()
        self._configure_entry()
        self._configure_send_button()

    def _configure_textbox(self):
        """Configure the textbox properties."""
        self.textbox.grid(row=0, column=0, columnspan=4, rowspan=3, padx=10, pady=10, sticky="nsew")
        self.textbox.configure(state="disabled", font=FONT_MONO)
        self.textbox.tag_config('colour_you', foreground=COLOURS["you"])
        self.textbox.tag_config('colour_friend', foreground=COLOURS["friend"])
        self.textbox.tag_config('colour_alert', foreground=COLOURS["alert"])

    def _configure_entry(self):
        """Configure the entry properties."""
        self.entry.configure(state="disabled")
        self.entry.grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")
        self.entry.bind('<Return>', lambda event: self.send_message())

    def _configure_send_button(self):
        """Configure the send button properties."""
        self.send_button.configure(state="disabled")
        self.send_button.grid(row=3, column=3, padx=10, pady=10, sticky="nsew")

    def recv_message(self, message, sender="Friend"):
        """Receive a message and update the chat history."""
        if not message:
            return
        self.history.append({"sender": sender, "message": message, "time": datetime.datetime.now()})
        self.update_chat()

    def update_chat(self):
        """Update the chat display with new messages."""
        self.textbox.configure(state="normal")
        new_messages = self.history[self.lines:]
        for message in new_messages:
            self._insert_message(message)
        self.lines = len(self.history)
        self.textbox.configure(state="disabled")
        self.textbox.see(tk.END)

    def _insert_message(self, message):
        """Insert a message into the textbox."""
        time_str = message['time'].strftime("%d/%m/%Y %H:%M:%S")
        sender = message['sender']
        content = message['message']
        if sender == "You":
            self.textbox.insert(tk.END, f"[{time_str}] {sender.ljust(6)} : {content}\n", "colour_you")
        elif sender == "Friend":
            self.textbox.insert(tk.END, f"[{time_str}] {sender.ljust(6)} : {content}\n", "colour_friend")
        elif sender == "Alert":
            self.textbox.insert(tk.END, f"[{time_str}] {sender.ljust(6)} : {content}\n", "colour_alert")
        elif sender == "Divider":
            self.textbox.insert(tk.END, f"{'-'*60}\n{content}\n{'-'*60}\n")
        else:
            self.textbox.insert(tk.END, f"{content}\n")

    def is_connected(self):
        """Check if the client and server are connected."""
        if self.client and self.client.state == 1 and self.server and self.server.state == 1:
            self._set_connected_state()
        else:
            self._set_disconnected_state()

    def _set_connected_state(self):
        """Set the UI to the connected state."""
        self.title("Connected")
        self.entry.configure(state="normal")
        self.send_button.configure(state="normal")
        self.recv_message("Two-way communication established", sender="Divider")
        connected(self.client)

    def _set_disconnected_state(self):
        """Set the UI to the disconnected state."""
        self.title("Disconnected")
        self.entry.configure(state="disabled")
        self.send_button.configure(state="disabled")
        disconnected()

    def send_message(self):
        """Send a message to the server."""
        message = self.entry.get().strip()
        if not message:
            return
        if self.client:
            self._try_send_message(message)
        else:
            self.recv_message("Client not connected", sender="Alert")

    def _try_send_message(self, message):
        """Attempt to send a message to the server."""
        try:
            parsed_message = send(message)
            self.client.send(parsed_message)
            self.recv_message(message, sender="You")
            self.entry.delete(0, tk.END)
        except Exception as e:
            print(e)
            self.recv_message(f"Failed to send message: {str(e)}", sender="Alert")

def handler(websocket):
    """Handle incoming messages from the client."""
    app.recv_message("Client connected", sender="Alert")
    app.server = websocket
    app.is_connected()
    while websocket.state:
        try:
            message = websocket.recv()
            decoded_message, sender = recv(message, app.client)
            app.recv_message(decoded_message, sender=sender)
        except Exception:
            break
    app.is_connected()

def run_server():
    """Run the WebSocket server."""
    hostname = host.split(":")[0]
    port = int(host.split(":")[1])

    with serve(handler, hostname, port, max_size=10 * 1024 * 1024) as server:
        app.recv_message(f"Server started listening on port {port}", sender="Alert")
        server.serve_forever()

def run_client():
    """Run the WebSocket client."""
    app.recv_message(f"Connecting to {target}", sender="Alert")
    while True:
        try:
            with connect(f"ws://{target}") as client:
                app.recv_message(f"Connected to {target}", sender="Alert")
                app.client = client
                app.is_connected()
                while client.state:
                    try:
                        message = client.recv()
                        decoded_message, sender = recv(message, app.client)
                        app.recv_message(decoded_message, sender=sender)
                    except Exception as e:
                        app.recv_message(f"Failed to decode message: {str(e)}", sender="Alert")
                        break
        except Exception as e:
            app.is_connected()
            app.recv_message(f"Failed to connect to server {target}: {str(e)}", sender="Alert")
            time.sleep(5)

def main(arg_target, arg_host):
    """Main function to start the application."""
    global app, target, host
    app = App()
    target = arg_target
    host = arg_host
    threading.Thread(target=run_server, daemon=True).start()
    threading.Thread(target=run_client, daemon=True).start()
    app.mainloop()

if __name__ == "__main__":
    arg_target, arg_host = None, None

    # Parse command line arguments
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == '--target':
            arg_target = sys.argv[i + 1]
        elif arg == '--host':
            arg_host = sys.argv[i + 1]

    # Check if required arguments are provided
    if not arg_host or not arg_target:
        print('Usage: python main.py --target <address:port> --host <address:port>')
    else:
        main(arg_target, arg_host)

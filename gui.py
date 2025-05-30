import tkinter as tk
from tkinter import ttk, messagebox, filedialog, colorchooser, font
import pyperclip
import os
from threading import Thread
try:
    from PIL import Image, ImageTk
except ImportError:
    ImageTk = None
try:
    import speech_recognition as sr
except ImportError:
    sr = None
import binascii
from queue import Queue
import uuid

# Placeholder for i18n (since _ is not defined)
def _(text):
    return text

# Constants
MAX_FILE_SIZE = 1000 * 1024  # 1000 KB

# Existing converter functions (unchanged from your original code)
def convert_text_to_binary(text, encoding='utf-8', encrypt=False, key=""):
    try:
        binary = ' '.join(format(ord(c), '08b') for c in text)
        return binary if not encrypt or not key else xor_encrypt(binary, key)
    except Exception as e:
        return None, str(e)

def convert_binary_to_text(binary, encoding='utf-8'):
    try:
        binary = binary.replace(' ', '')
        chars = [chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)]
        return ''.join(chars), None
    except Exception as e:
        return None, str(e)

def convert_text_to_hex(text, encoding='utf-8'):
    try:
        return text.encode(encoding).hex(), None
    except Exception as e:
        return None, str(e)

def convert_hex_to_text(hex_str, encoding='utf-8'):
    try:
        return bytes.fromhex(hex_str).decode(encoding), None
    except Exception as e:
        return None, str(e)

def convert_hex_to_binary(hex_str, encrypt=False, key=""):
    try:
        binary = ' '.join(format(int(hex_str[i:i+2], 16), '08b') for i in range(0, len(hex_str), 2))
        return binary if not encrypt or not key else xor_encrypt(binary, key), None
    except Exception as e:
        return None, str(e)

def convert_binary_to_hex(binary):
    try:
        binary = binary.replace(' ', '')
        hex_str = hex(int(binary, 2))[2:].zfill(len(binary)//4)
        return hex_str, None
    except Exception as e:
        return None, str(e)

def show_stats(text):
    return f"Length: {len(text)}\nWords: {len(text.split())}\nUnique chars: {len(set(text))}"

def save_to_file(text, file_path):
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(text)
        return f"Output saved to {file_path}"
    except Exception as e:
        return f"Error saving file: {e}"

def xor_encrypt(data, key):
    key = int(key)
    return ' '.join(format(ord(c) ^ key, '08b') if c != ' ' else c for c in data)

class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tip_window or not self.text:
            return
        x = self.widget.winfo_rootx() + 25
        y = self.widget.winfo_rooty() + 25
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = ttk.Label(tw, text=self.text, background="#ffffff", relief="solid", borderwidth=1, font=("Helvetica", 10))
        label.pack()

    def hide_tip(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

class ConverterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔄 Converter App")
        self.root.geometry("800x800")
        self.root.minsize(600, 600)
        self.root.resizable(True, True)

        self.themes = {
            "Dark": {
                "bg": "#1e272e",
                "fg": "#d2dae2",
                "input_bg": "#2f3640",
                "accent": "#00a8ff",
                "button_bg": "#40739e",
                "button_fg": "#f5f6fa",
                "error": "#e84118",
                "success": "#44bd32"
            },
            "Light": {
                "bg": "#f0f0f0",
                "fg": "#2f3640",
                "input_bg": "#ffffff",
                "accent": "#0097e6",
                "button_bg": "#4cd137",
                "button_fg": "#ffffff",
                "error": "#e84118",
                "success": "#44bd32"
            },
            "HighContrast": {
                "bg": "#000000",
                "fg": "#FFFFFF",
                "input_bg": "#333333",
                "accent": "#00FFFF",
                "button_bg": "#0000FF",
                "button_fg": "#FFFFFF",
                "error": "#FF5555",
                "success": "#55FF55"
            }
        }
        self.current_theme = "Dark"
        self.colors = self.themes[self.current_theme]

        self.history = []
        self.max_history_size = 100
        self.font_family = "Helvetica"
        self.font_size = 14
        self.input_fg = self.colors["fg"]
        self.input_bg = self.colors["input_bg"]
        self.output_fg = self.colors["fg"]
        self.output_bg = self.colors["input_bg"]
        self.image_label = None
        self.current_image = None
        self.full_result = ""
        self.result_queue = Queue()

        self.setup_style()
        self.setup_widgets()
        self.apply_theme()

        self.root.bind("<Configure>", self.on_resize)
        self.root.bind("<Control-h>", lambda e: self.set_theme("HighContrast"))

    def setup_style(self):
        self.style = ttk.Style(self.root)
        self.style.theme_use('clam')
        c = self.colors
        self.style.configure('TLabel', font=('Helvetica', 11, 'bold'), background=c["bg"], foreground=c["fg"])
        self.style.configure('TButton', font=('Helvetica', 11, 'bold'),
                            background=c["button_bg"], foreground=c["button_fg"])
        self.style.configure('Pressed.TButton', font=('Helvetica', 11, 'bold'),
                            background=c["accent"], foreground=c["button_fg"])
        self.style.configure('Hover.TButton', font=('Helvetica', 11, 'bold'),
                            background=c["accent"], foreground=c["button_fg"])
        self.style.configure('TEntry', font=('Helvetica', 11),
                            fieldbackground=c["input_bg"], foreground=c["fg"])
        self.style.configure('TCombobox', font=('Helvetica', 11),
                            fieldbackground=c["input_bg"], foreground=c["fg"])
        self.style.configure('TCheckbutton', font=('Helvetica', 11), background=c["bg"], foreground=c["fg"])
        self.style.configure('TNotebook', background=c["bg"])
        self.style.configure('TNotebook.Tab', font=('Helvetica', 11, 'bold'), padding=[12, 8], background=c["bg"], foreground=c["fg"])
        self.style.map('TButton',
                       background=[('active', c["accent"]), ('!disabled', c["button_bg"])],
                       foreground=[('active', c["button_fg"]), ('!disabled', c["button_fg"])])

    def setup_widgets(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Save Output", command=self.save_output, accelerator="Ctrl+S")
        file_menu.add_command(label="Save History", command=self.save_history)
        file_menu.add_command(label="Load History", command=self.load_history)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_exit, accelerator="Ctrl+Q")
        menubar.add_cascade(label="File", menu=file_menu)

        theme_menu = tk.Menu(menubar, tearoff=False)
        for theme in self.themes:
            theme_menu.add_radiobutton(label=f"{theme} Theme", command=lambda t=theme: self.set_theme(t), value=theme)
        menubar.add_cascade(label="Theme", menu=theme_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.canvas = tk.Canvas(self.root, bg=self.colors["bg"], highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.main_frame = ttk.Frame(self.canvas)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas_frame = self.canvas.create_window((0, 0), window=self.main_frame, anchor="nw")
        self.main_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.canvas_frame, width=self.canvas.winfo_width()))

        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)

        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(0, weight=8)
        self.main_frame.rowconfigure(1, weight=1)
        self.main_frame.rowconfigure(2, weight=1)

        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        self.tab_convert = ttk.Frame(self.notebook)
        self.tab_history = ttk.Frame(self.notebook)
        self.tab_custom = ttk.Frame(self.notebook)

        if ImageTk:
            try:
                self.icon_convert = ImageTk.PhotoImage(Image.open("convert.png").resize((16, 16)))
                self.icon_history = ImageTk.PhotoImage(Image.open("history.png").resize((16, 16)))
                self.icon_custom = ImageTk.PhotoImage(Image.open("custom.png").resize((16, 16)))
                self.notebook.add(self.tab_convert, image=self.icon_convert, text=" Converter", compound=tk.LEFT)
                self.notebook.add(self.tab_history, image=self.icon_history, text=" History", compound=tk.LEFT)
                self.notebook.add(self.tab_custom, image=self.icon_custom, text=" Customization", compound=tk.LEFT)
            except FileNotFoundError:
                self.notebook.add(self.tab_convert, text="🔄 Converter")
                self.notebook.add(self.tab_history, text="📜 History")
                self.notebook.add(self.tab_custom, text="🎨 Customization")
        else:
            self.notebook.add(self.tab_convert, text="🔄 Converter")
            self.notebook.add(self.tab_history, text="📜 History")
            self.notebook.add(self.tab_custom, text="🎨 Customization")

        self.build_converter_tab()
        self.build_history_tab()
        self.build_custom_tab()

        self.exit_btn = ttk.Button(self.main_frame, text="Exit", command=self.on_exit)
        self.exit_btn.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.exit_btn.configure(takefocus=True)
        Tooltip(self.exit_btn, "Exit the application (Ctrl+Q)")

        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief="sunken", anchor="w", font=("Helvetica", 9))
        self.status_bar.grid(row=2, column=0, sticky="ew")
        self.set_status("✅ Ready")

        for btn in [self.convert_btn, self.copy_btn, self.save_btn, self.stats_btn, self.exit_btn, self.browse_btn, self.clear_history_btn, self.apply_custom_btn, self.clear_all_btn, self.voice_btn]:
            btn.bind("<Enter>", lambda e, b=btn: b.configure(style="Hover.TButton"))
            btn.bind("<Leave>", lambda e, b=btn: b.configure(style="TButton"))
            btn.bind("<Button-1>", lambda e, b=btn: self.animate_button_press(b))

        self.root.bind("<Control-Return>", lambda e: self.convert())
        self.root.bind("<Control-c>", lambda e: self.copy_output())
        self.root.bind("<Control-s>", lambda e: self.save_output())
        self.root.bind("<Control-t>", lambda e: self.show_stats())
        self.root.bind("<Control-q>", lambda e: self.on_exit())
        self.root.bind("<Control-b>", lambda e: self.browse_file())
        self.root.bind("<Control-d>", lambda e: self.clear_history())
        self.root.bind("<Control-a>", lambda e: self.apply_customization())
        self.root.bind("<Control-h>", lambda e: self.set_theme("HighContrast"))
        self.root.bind("<Control-l>", lambda e: self.clear_all())
        self.root.bind("<Control-v>", lambda e: self.get_voice_input())

    def _on_mousewheel(self, event):
        delta = 0
        if event.num == 4:
            delta = -1
        elif event.num == 5:
            delta = 1
        elif event.delta:
            delta = -1 * (event.delta // 120)
        if delta:
            self.canvas.yview_scroll(delta, "units")

    def build_converter_tab(self):
        self.frame = self.tab_convert
        self.frame.columnconfigure(0, weight=3)
        self.frame.columnconfigure([1, 2, 3], weight=1)
        self.frame.columnconfigure(4, weight=0)
        self.frame.rowconfigure([2, 4], weight=3)
        self.frame.rowconfigure([0, 1, 3, 5, 6, 7, 8], weight=1)

        ttk.Label(self.frame, text="Upload Type:", font=('Helvetica', 11, 'bold')).grid(row=0, column=0, sticky="w", pady=(5, 0))
        self.upload_type = tk.StringVar(value="File")
        upload_types = ["File"]
        if ImageTk:
            upload_types.extend(["Image", "Video", "Audio"])
        else:
            upload_types.extend(["Video", "Audio"])
        self.upload_combo = ttk.Combobox(self.frame, textvariable=self.upload_type, state='readonly', width=20, font=("Helvetica", 11),
                                        values=upload_types)
        self.upload_combo.grid(row=0, column=1, sticky="w")
        self.upload_combo.configure(takefocus=True)
        self.upload_combo.bind("<<ComboboxSelected>>", self.update_upload_layout)
        Tooltip(self.upload_combo, "Select type of content to upload")

        self.file_frame = ttk.Frame(self.frame)
        self.file_frame.grid(row=1, column=0, columnspan=4, sticky='ew', pady=5, padx=5)
        self.file_frame.columnconfigure(1, weight=1)

        ttk.Label(self.file_frame, text="Select File (max 1000 KB):", font=('Helvetica', 11, 'bold')).grid(row=0, column=0, sticky='w')
        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(self.file_frame, textvariable=self.file_path_var, state='readonly')
        self.file_entry.grid(row=0, column=1, sticky='ew', padx=(5, 5))
        self.file_entry.configure(takefocus=True)
        Tooltip(self.file_entry, "Selected file path for processing")
        self.browse_btn = ttk.Button(self.file_frame, text="Browse...", command=self.browse_file)
        self.browse_btn.grid(row=0, column=2)
        self.browse_btn.configure(takefocus=True)
        Tooltip(self.browse_btn, "Select a file for processing (Ctrl+B)")

        ttk.Label(self.frame, text="Input:", font=('Helvetica', 11, 'bold')).grid(row=2, column=0, sticky="w")
        self.input_text = tk.Text(self.frame, height=8, width=80, font=(self.font_family, self.font_size), wrap="word", undo=True,
                                  fg=self.input_fg, bg=self.input_bg, insertbackground=self.colors["accent"])
        self.input_text.grid(row=3, column=0, columnspan=4, sticky="nsew", pady=(0, 10))
        self.input_text.configure(takefocus=True)
        input_scroll = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.input_text.yview)
        input_scroll.grid(row=3, column=4, sticky="ns", pady=(0, 10))
        self.input_text.configure(yscrollcommand=input_scroll.set)
        self.input_text.bind("<Control-z>", lambda event: self.input_text.edit_undo())
        self.input_text.bind("<Control-y>", lambda event: self.input_text.edit_redo())
        self.input_text.bind("<Control-Return>", lambda e: self.convert())
        self.input_text.bind("<KeyRelease>", self.validate_input)
        Tooltip(self.input_text, "Enter text or select a file for conversion (Ctrl+Enter to convert)")

        self.preview_frame = ttk.Frame(self.frame)
        self.preview_label = ttk.Label(self.preview_frame, text="Media Preview")
        self.preview_label.pack(pady=5)

        ttk.Label(self.frame, text="Output:", font=('Helvetica', 11, 'bold')).grid(row=5, column=0, sticky="w")
        self.output_text = tk.Text(self.frame, height=8, width=80, font=(self.font_family, self.font_size), wrap="word", undo=True,
                                   fg=self.output_fg, bg=self.output_bg, insertbackground=self.colors["accent"])
        self.output_text.grid(row=6, column=0, columnspan=4, sticky="nsew", pady=(0, 10))
        self.output_text.configure(takefocus=True)
        output_scroll = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.output_text.yview)
        output_scroll.grid(row=6, column=4, sticky="ns", pady=(0, 10))
        self.output_text.configure(yscrollcommand=output_scroll.set)
        self.output_text.configure(state="normal")
        self.output_text.bind("<Control-z>", lambda event: self.output_text.edit_undo())
        self.output_text.bind("<Control-y>", lambda event: self.output_text.edit_redo())
        self.output_text.bind("<Control-c>", lambda e: self.copy_output())
        Tooltip(self.output_text, "View conversion results here (Ctrl+C to copy)")

        ttk.Label(self.frame, text="Conversion Type:", font=('Helvetica', 11, 'bold')).grid(row=7, column=0, sticky="w", pady=(5, 0))
        self.conv_type = tk.StringVar(value="Text → Binary")
        self.conv_combo = ttk.Combobox(self.frame, textvariable=self.conv_type, state='readonly', width=20, font=("Helvetica", 11),
                                      values=[
                                          "Text → Binary",
                                          "Binary → Text",
                                          "Text → Hex",
                                          "Hex → Text",
                                          "Hex → Binary",
                                          "Binary → Hex"
                                      ])
        self.conv_combo.grid(row=8, column=0, sticky="w")
        self.conv_combo.configure(takefocus=True)
        Tooltip(self.conv_combo, "Select conversion type")

        ttk.Label(self.frame, text="Encoding:", font=('Helvetica', 11, 'bold')).grid(row=7, column=1, sticky="w", padx=(10, 0), pady=(5, 0))
        self.encoding = tk.StringVar(value="utf-8")
        self.enc_combo = ttk.Combobox(self.frame, textvariable=self.encoding, state='readonly', width=10, font=("Helvetica", 11),
                                     values=["ascii", "utf-8", "latin-1", "utf-16"])
        self.enc_combo.grid(row=8, column=1, sticky="w", padx=(10, 0))
        self.enc_combo.configure(takefocus=True)
        Tooltip(self.enc_combo, "Select text encoding")

        self.encrypt_var = tk.BooleanVar()
        self.encrypt_chk = ttk.Checkbutton(self.frame, text="Encrypt Output (XOR)", variable=self.encrypt_var, command=self.toggle_key_entry)
        self.encrypt_chk.grid(row=7, column=2, sticky="w", padx=(10, 0), pady=(5, 0))
        self.encrypt_chk.configure(takefocus=True)
        Tooltip(self.encrypt_chk, "Enable XOR encryption for output")

        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(self.frame, textvariable=self.key_var, font=("Helvetica", 11), width=20, state='disabled')
        self.key_entry.grid(row=8, column=2, sticky="w", padx=(10, 0))
        self.key_entry.configure(takefocus=True)
        Tooltip(self.key_entry, "Enter numeric encryption key for XOR")

        self.btns_frame = ttk.Frame(self.frame)
        self.btns_frame.grid(row=9, column=0, columnspan=4, pady=20, sticky="nsew")
        self.btns_frame.columnconfigure([0, 1, 2, 3, 4, 5], weight=1)  # Adjusted for voice button
        self.btns_frame.rowconfigure(0, weight=1)

        self.convert_btn = ttk.Button(self.btns_frame, text="Convert", command=self.convert)
        self.convert_btn.grid(row=0, column=0, padx=5, sticky='ew')
        self.convert_btn.configure(takefocus=True)
        Tooltip(self.convert_btn, "Convert input content (Ctrl+Enter)")

        self.copy_btn = ttk.Button(self.btns_frame, text="Copy Output", command=self.copy_output)
        self.copy_btn.grid(row=0, column=1, padx=5, sticky='ew')
        self.copy_btn.configure(takefocus=True)
        Tooltip(self.copy_btn, "Copy output to clipboard (Ctrl+C)")

        self.save_btn = ttk.Button(self.btns_frame, text="Save Output", command=self.save_output)
        self.save_btn.grid(row=0, column=2, padx=5, sticky='ew')
        self.save_btn.configure(takefocus=True)
        Tooltip(self.save_btn, "Save output to a file (Ctrl+S)")

        self.stats_btn = ttk.Button(self.btns_frame, text="Show Input Stats", command=self.show_stats)
        self.stats_btn.grid(row=0, column=3, padx=5, sticky='ew')
        self.stats_btn.configure(takefocus=True)
        Tooltip(self.stats_btn, "Show input statistics (Ctrl+T)")

        self.clear_all_btn = ttk.Button(self.btns_frame, text="Clear All", command=self.clear_all)
        self.clear_all_btn.grid(row=0, column=4, padx=5, sticky='ew')
        self.clear_all_btn.configure(takefocus=True)
        Tooltip(self.clear_all_btn, "Clear input and output (Ctrl+L)")

        self.voice_btn = ttk.Button(self.btns_frame, text="Voice Input", command=self.get_voice_input)
        self.voice_btn.grid(row=0, column=5, padx=5, sticky='ew')
        self.voice_btn.configure(takefocus=True)
        Tooltip(self.voice_btn, "Capture text via voice input (Ctrl+V)")

        self.update_upload_layout(None)

    def get_voice_input(self):
        def process_voice():
            if not sr:
                self.root.after(0, lambda: messagebox.showerror("Error", "Voice input requires speech_recognition library."))
                self.root.after(0, lambda: self.set_status("❌ Voice input not available: speech_recognition not installed.", error=True))
                return
            recognizer = sr.Recognizer()
            with sr.Microphone() as source:
                self.root.after(0, lambda: self.set_status("🎤 Listening for voice input..."))
                recognizer.adjust_for_ambient_noise(source)
                try:
                    audio = recognizer.listen(source, timeout=5)
                    text = recognizer.recognize_google(audio)
                    self.root.after(0, lambda: self.input_text.delete("1.0", tk.END))
                    self.root.after(0, lambda: self.input_text.insert(tk.END, text))
                    self.root.after(0, lambda: self.set_status(f"✅ Recognized voice input: {text}", timeout=3000))
                except sr.WaitTimeoutError:
                    self.root.after(0, lambda: messagebox.showwarning("Warning", "No speech detected within 5 seconds."))
                    self.root.after(0, lambda: self.set_status("❌ No speech detected.", error=True))
                except sr.UnknownValueError:
                    self.root.after(0, lambda: messagebox.showwarning("Warning", "Could not understand the audio."))
                    self.root.after(0, lambda: self.set_status("❌ Could not understand audio.", error=True))
                except Exception as e:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Voice recognition failed: {e}"))
                    self.root.after(0, lambda: self.set_status(f"❌ Voice recognition failed: {e}", error=True))
            self.root.after(0, lambda: self.root.config(cursor=""))
        self.root.config(cursor="wait")
        Thread(target=process_voice, daemon=True).start()

    # Remaining methods (unchanged from original code)
    def clear_all(self):
        self.input_text.configure(state="normal")
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.file_path_var.set("")
        self.full_result = ""
        if self.image_label:
            self.image_label.destroy()
            self.image_label = None
        self.preview_frame.grid_forget()
        self.set_status("✅ Input and output cleared.", timeout=3000)

    def update_upload_layout(self, event):
        upload_type = self.upload_type.get()
        if self.image_label:
            self.image_label.destroy()
            self.image_label = None
        self.preview_frame.grid_forget()

        self.input_text.configure(state="normal")
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.file_path_var.set("")
        self.full_result = ""

        if upload_type == "File":
            self.file_frame.grid(row=1, column=0, columnspan=4, sticky='ew', pady=5, padx=5)
            self.input_text.grid(row=3, column=0, columnspan=4, sticky="nsew", pady=(0, 10))
            self.convert_btn.configure(text="Convert")
            Tooltip(self.convert_btn, "Convert input text or file (Ctrl+Enter)")
            self.stats_btn.grid(row=0, column=3, padx=5, sticky='ew')
            self.conv_combo.configure(values=[
                "Text → Binary", "Binary → Text",
                "Text → Hex", "Hex → Text",
                "Hex → Binary", "Binary → Hex"
            ])
            self.conv_type.set("Text → Binary")
        elif upload_type == "Image":
            self.file_frame.grid(row=1, column=0, columnspan=4, sticky='ew', pady=5, padx=5)
            self.input_text.grid_forget()
            self.preview_frame.grid(row=3, column=0, columnspan=4, sticky="nsew", pady=(0, 10))
            self.convert_btn.configure(text="Convert Image")
            Tooltip(self.convert_btn, "Convert image to binary/hex (Ctrl+Enter)")
            self.stats_btn.grid_forget()
            self.conv_combo.configure(values=["Image → Binary", "Image → Hex"])
            self.conv_type.set("Image → Binary")
            if self.file_path_var.get():
                self.show_image_preview()
        else:
            self.file_frame.grid(row=1, column=0, columnspan=4, sticky='ew', pady=5, padx=5)
            self.input_text.grid_forget()
            self.convert_btn.configure(text="Convert " + upload_type)
            Tooltip(self.convert_btn, f"Convert {upload_type.lower()} to binary/hex (Ctrl+Enter)")
            self.stats_btn.grid_forget()
            self.conv_combo.configure(values=[f"{upload_type} → Binary", f"{upload_type} → Hex"])
            self.conv_type.set(f"{upload_type} → Binary")

    def show_image_preview(self):
        if not ImageTk:
            self.set_status("❌ Image preview requires PIL.", error=True)
            return
        file_path = self.file_path_var.get()
        try:
            image = Image.open(file_path)
            image.verify()
            image = Image.open(file_path)
            image.thumbnail((300, 300))
            self.current_image = ImageTk.PhotoImage(image)
            if self.image_label:
                self.image_label.destroy()
            self.image_label = ttk.Label(self.preview_frame, image=self.current_image)
            self.image_label.pack()
        except Exception as e:
            self.set_status(f"❌ Failed to load image: {e}", error=True)

    def browse_file(self):
        upload_type = self.upload_type.get()
        if upload_type == "File":
            file_path = filedialog.askopenfilename(
                title="Select a file for processing (max 1000 KB)",
                filetypes=[
                    ("Text Files", "*.txt *.csv *.log *.json *.xml *.md"),
                    ("Binary Files", "*.bin"),
                    ("All Files", "*.*")
                ]
            )
        elif upload_type == "Image":
            file_path = filedialog.askopenfilename(
                title="Select an image file",
                filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp")]
            )
        elif upload_type == "Video":
            file_path = filedialog.askopenfilename(
                title="Select a video file",
                filetypes=[("Video Files", "*.mp4 *.avi *.mkv")]
            )
        else:
            file_path = filedialog.askopenfilename(
                title="Select an audio file",
                filetypes=[("Audio Files", "*.mp3 *.wav")]
            )

        if file_path:
            if not os.path.exists(file_path):
                messagebox.showerror("File Error", f"File '{file_path}' does not exist.")
                self.set_status("❌ File does not exist.", error=True)
                return
            if not os.access(file_path, os.R_OK):
                messagebox.showerror("File Error", f"File '{file_path}' is not readable. Check permissions.")
                self.set_status("❌ File is not readable.", error=True)
                return
            if os.path.getsize(file_path) > MAX_FILE_SIZE:
                messagebox.showerror("File Error", f"Selected file exceeds {MAX_FILE_SIZE / 1024} KB limit.")
                self.set_status("❌ File too large.", error=True)
                return
            self.file_path_var.set(file_path)
            self.input_text.delete(1.0, tk.END)
            if upload_type == "File":
                try:
                    with open(file_path, 'r', encoding=self.encoding.get(), errors='replace') as f:
                        preview = f.read(1024)  # Read up to 1 KB for preview
                        self.input_text.insert(tk.END, preview)
                        self.input_text.configure(state="normal")
                except UnicodeDecodeError as e:
                    messagebox.showerror("Error", f"Cannot decode file with {self.encoding.get()} encoding: {e}. Try a different encoding.")
                    self.set_status(f"❌ Encoding error: {e}", error=True)
                except Exception as e:
                    messagebox.showerror("Error", f"Cannot preview file: {e}")
                    self.set_status(f"❌ File preview failed: {e}", error=True)
            elif upload_type == "Image":
                self.show_image_preview()
            self.set_status(f"✅ Selected {upload_type.lower()}: {os.path.basename(file_path)}")

    def build_history_tab(self):
        frame = self.tab_history
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        ttk.Label(frame, text="Conversion History:", font=('Helvetica', 11, 'bold')).pack(anchor="w", padx=10, pady=5)
        self.history_listbox = tk.Listbox(frame, font=(self.font_family, self.font_size), height=30, selectmode=tk.SINGLE,
                                          bg=self.colors["input_bg"], fg=self.colors["fg"])
        self.history_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.history_listbox.bind("<Double-Button-1>", self.load_history_item)
        self.history_listbox.configure(takefocus=True)
        Tooltip(self.history_listbox, "Double-click to load a history item")

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        self.clear_history_btn = ttk.Button(btn_frame, text="Clear History", command=self.clear_history)
        self.clear_history_btn.pack(side=tk.LEFT)
        self.clear_history_btn.configure(takefocus=True)
        Tooltip(self.clear_history_btn, "Clear all conversion history (Ctrl+D)")

    def build_custom_tab(self):
        frame = self.tab_custom
        frame.columnconfigure(0, weight=1)

        ttk.Label(frame, text="Customize Font and Colors", font=("Helvetica", 14, 'bold')).pack(pady=10)

        form_frame = ttk.Frame(frame, padding=10)
        form_frame.pack(fill=tk.BOTH, expand=True)
        form_frame.columnconfigure(1, weight=1)

        ttk.Label(form_frame, text="Font Family:", font=('Helvetica', 11, 'bold')).grid(row=0, column=0, sticky="w")
        self.available_fonts = sorted(set(font.families()))
        self.font_family_var = tk.StringVar(value=self.font_family)
        self.font_family_combo = ttk.Combobox(form_frame, textvariable=self.font_family_var, values=self.available_fonts, state="readonly", width=30)
        self.font_family_combo.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.font_family_combo.configure(takefocus=True)
        Tooltip(self.font_family_combo, "Select font family for text areas")

        ttk.Label(form_frame, text="Font Size:", font=('Helvetica', 11, 'bold')).grid(row=1, column=0, sticky="w")
        self.font_size_var = tk.IntVar(value=self.font_size)
        self.font_size_spin = ttk.Spinbox(form_frame, from_=8, to=40, textvariable=self.font_size_var, width=5)
        self.font_size_spin.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        self.font_size_spin.configure(takefocus=True)
        Tooltip(self.font_size_spin, "Adjust font size (8-40)")

        ttk.Label(form_frame, text="Input Text Color:", font=('Helvetica', 11, 'bold')).grid(row=2, column=0, sticky="w")
        self.input_fg_btn = ttk.Button(form_frame, text="Select Color", command=self.pick_input_fg_color)
        self.input_fg_btn.grid(row=2, column=1, sticky="w", padx=5, pady=5)
        self.input_fg_btn.configure(takefocus=True)
        Tooltip(self.input_fg_btn, "Choose input text color")

        ttk.Label(form_frame, text="Input Background Color:", font=('Helvetica', 11, 'bold')).grid(row=3, column=0, sticky="w")
        self.input_bg_btn = ttk.Button(form_frame, text="Select Color", command=self.pick_input_bg_color)
        self.input_bg_btn.grid(row=3, column=1, sticky="w", padx=5, pady=5)
        self.input_bg_btn.configure(takefocus=True)
        Tooltip(self.input_bg_btn, "Choose input background color")

        ttk.Label(form_frame, text="Output Text Color:", font=('Helvetica', 11, 'bold')).grid(row=4, column=0, sticky="w")
        self.output_fg_btn = ttk.Button(form_frame, text="Select Color", command=self.pick_output_fg_color)
        self.output_fg_btn.grid(row=4, column=1, sticky="w", padx=5, pady=5)
        self.output_fg_btn.configure(takefocus=True)
        Tooltip(self.output_fg_btn, "Choose output text color")

        ttk.Label(form_frame, text="Output Background Color:", font=('Helvetica', 11, 'bold')).grid(row=5, column=0, sticky="w")
        self.output_bg_btn = ttk.Button(form_frame, text="Select Color", command=self.pick_output_bg_color)
        self.output_bg_btn.grid(row=5, column=1, sticky="w", padx=5, pady=5)
        self.output_bg_btn.configure(takefocus=True)
        Tooltip(self.output_bg_btn, "Choose output background color")

        self.apply_custom_btn = ttk.Button(form_frame, text="Apply Customization", command=self.apply_customization)
        self.apply_custom_btn.grid(row=6, column=0, columnspan=2, pady=20)
        self.apply_custom_btn.configure(takefocus=True)
        Tooltip(self.apply_custom_btn, "Apply font and color changes (Ctrl+A)")

    def pick_input_fg_color(self):
        color = colorchooser.askcolor(title="Choose Input Text Color")
        if color[1]:
            self.input_fg = color[1]

    def pick_input_bg_color(self):
        color = colorchooser.askcolor(title="Choose Input Background Color")
        if color[1]:
            self.input_bg = color[1]

    def pick_output_fg_color(self):
        color = colorchooser.askcolor(title="Choose Output Text Color")
        if color[1]:
            self.output_fg = color[1]

    def pick_output_bg_color(self):
        color = colorchooser.askcolor(title="Choose Output Background Color")
        if color[1]:
            self.output_bg = color[1]

    def apply_customization(self):
        new_family = self.font_family_var.get()
        new_size = self.font_size_var.get()
        if new_family and new_family != self.font_family:
            self.font_family = new_family
        if new_size and new_size != self.font_size:
            self.font_size = int(new_size)

        new_font = (self.font_family, self.font_size)
        self.input_text.configure(font=new_font, fg=self.input_fg, bg=self.input_bg, insertbackground=self.colors["accent"])
        self.output_text.configure(font=new_font, fg=self.output_fg, bg=self.output_bg, insertbackground=self.colors["accent"])
        self.history_listbox.configure(font=new_font, bg=self.input_bg, fg=self.input_fg)
        self.set_status("✅ Customization Applied.", timeout=3000)

    def set_status(self, message, error=False, timeout=5000):
        prefix = "❌ " if error else "✅ "
        self.status_var.set(prefix + message)
        fg = self.colors["error"] if error else self.colors["success"]
        self.status_bar.configure(foreground=fg)
        if timeout:
            def reset_status():
                self.status_var.set("✅ Ready")
                self.status_bar.configure(foreground=self.colors["fg"])
            self.root.after(timeout, reset_status)

    def toggle_key_entry(self):
        if self.encrypt_var.get():
            self.key_entry.configure(state="normal")
        else:
            self.key_entry.configure(state="disabled")
            self.key_var.set('')
        Tooltip(self.key_entry, "Enter numeric encryption key for XOR" if self.encrypt_var.get() else "Encryption key disabled")

    def validate_input(self, event):
        conv_type = self.conv_type.get()
        text = self.input_text.get("1.0", tk.END).strip()
        if conv_type in ["Binary → Text", "Binary → Hex"] and text:
            if not all(c in '01 ' for c in text):
                self.set_status("❌ Invalid binary input: Use only 0s and 1s.", error=True)
        elif conv_type in ["Hex → Text", "Hex → Binary"] and text:
            if not all(c in '0123456789abcdefABCDEF ' for c in text):
                self.set_status("❌ Invalid hex input: Use only 0-9, a-f, A-F.", error=True)

    def add_history(self, entry, full_result):
        entry_bytes = entry.encode('utf-8', errors='ignore')[:100]
        truncated_entry = entry_bytes.decode('utf-8', errors='ignore') + "..." if len(entry_bytes) == 100 else entry
        if len(self.history) >= self.max_history_size:
            self.history.pop(0)
            self.history_listbox.delete(0)
        self.history.append((truncated_entry, full_result))
        self.history_listbox.insert(tk.END, truncated_entry)

    def clear_history(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to clear the history?"):
            self.history.clear()
            self.history_listbox.delete(0, tk.END)
            self.set_status("✅ History cleared.", timeout=3000)

    def save_history(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    for entry, _ in self.history:
                        f.write(entry + "\n")
                self.set_status(f"✅ History saved to {file_path}", timeout=3000)
            except Exception as e:
                messagebox.showerror("Error", f"Error saving history: {e}")
                self.set_status("❌ Failed to save history.", error=True)

    def load_history(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.history.clear()
                    self.history_listbox.delete(0, tk.END)
                    for line in f:
                        self.add_history(line.strip(), line.strip())
                self.set_status(f"✅ History loaded from {file_path}", timeout=3000)
            except Exception as e:
                messagebox.showerror("Error", f"Error loading history: {e}")
                self.set_status("❌ Failed to load history.", error=True)

    def load_history_item(self, event):
        idx = self.history_listbox.curselection()
        if idx:
            entry, full_result = self.history[idx[0]]
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, full_result)
            self.full_result = full_result
            self.notebook.select(self.tab_convert)
            self.set_status("✅ Loaded history item to output.", timeout=3000)

    def animate_button_press(self, button):
        self.root.after(0, lambda: button.configure(style="Pressed.TButton"))
        self.root.after(100, lambda: button.configure(style="TButton"))

    def process_file_chunked(self, file_path, conv_type, encrypt=False, key="", encoding='utf-8'):
        CHUNK_SIZE = 4096
        result = []
        total_bytes = 0
        try:
            with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    total_bytes += len(chunk.encode(encoding))
                    if total_bytes > MAX_FILE_SIZE:
                        return None, None, f"File size exceeds {MAX_FILE_SIZE / 1024} KB limit"
                    if conv_type == "Text → Binary":
                        chunk_result = convert_text_to_binary(chunk, encoding, encrypt, key)
                        if isinstance(chunk_result, tuple):
                            return None, None, chunk_result[1]
                        result.append(chunk_result)
                    elif conv_type == "Text → Hex":
                        chunk_result, error = convert_text_to_hex(chunk, encoding)
                        if error:
                            return None, None, error
                        result.append(chunk_result)
                    else:
                        return None, None, "File conversion only supports Text → Binary or Text → Hex"
            full_result = ''.join(result)
            display_result = full_result[:10000] + "..." if len(full_result) > 10000 else full_result
            return display_result, full_result, f"{os.path.basename(file_path)} ({total_bytes} bytes)"
        except Exception as e:
            return None, None, f"Error processing file: {e}"

    def convert(self):
        def process_conversion():
            try:
                self.root.after(0, lambda: self.convert_btn.configure(state="disabled"))
                self.root.after(0, lambda: self.root.config(cursor="wait"))
                self.root.after(0, lambda: self.set_status("✅ Converting..."))
                file_path = self.file_path_var.get().strip()
                upload_type = self.upload_type.get()
                encrypt = self.encrypt_var.get()
                key = self.key_var.get().strip()
                encoding = self.encoding.get()
                conv_type = self.conv_type.get()

                if encrypt and not key:
                    self.root.after(0, lambda: messagebox.showwarning("Encryption Key Missing", "Please enter an encryption key."))
                    self.root.after(0, lambda: self.set_status("❌ Encryption key missing.", error=True))
                    self.root.after(0, lambda: self.convert_btn.configure(state="normal"))
                    self.root.after(0, lambda: self.root.config(cursor=""))
                    return
                if encrypt and not key.isdigit():
                    self.root.after(0, lambda: messagebox.showwarning("Invalid Key", "Encryption key must be numeric."))
                    self.root.after(0, lambda: self.set_status("❌ Invalid encryption key.", error=True))
                    self.root.after(0, lambda: self.convert_btn.configure(state="normal"))
                    self.root.after(0, lambda: self.root.config(cursor=""))
                    return

                if file_path:
                    if not os.path.isfile(file_path):
                        self.root.after(0, lambda: messagebox.showerror("File Error", f"File '{file_path}' does not exist."))
                        self.root.after(0, lambda: self.set_status("❌ File not found.", error=True))
                        self.root.after(0, lambda: self.convert_btn.configure(state="normal"))
                        self.root.after(0, lambda: self.root.config(cursor=""))
                        return
                    if upload_type == "File":
                        display_result, full_result, info = self.process_file_chunked(file_path, conv_type, encrypt, key, encoding)
                        if full_result is None:
                            self.root.after(0, lambda: messagebox.showerror("File Processing Error", info))
                            self.root.after(0, lambda: self.set_status(f"❌ {info}", error=True))
                            self.root.after(0, lambda: self.convert_btn.configure(state="normal"))
                            self.root.after(0, lambda: self.root.config(cursor=""))
                            return
                        self.result_queue.put((display_result, full_result, f"[Batch File] {info} -> {display_result}", f"✅ Processed file: {info} | Output copied to clipboard."))
                        self.root.after(0, self.update_ui_after_conversion)
                        return
                    else:
                        with open(file_path, 'rb') as f:
                            data = f.read(MAX_FILE_SIZE)
                        if upload_type == "Image":
                            try:
                                with Image.open(file_path) as img:
                                    img.verify()
                            except Exception as e:
                                self.root.after(0, lambda: self.set_status(f"❌ Invalid image file: {e}", error=True))
                                self.root.after(0, lambda: self.convert_btn.configure(state="normal"))
                                self.root.after(0, lambda: self.root.config(cursor=""))
                                return
                        if conv_type.endswith("→ Binary"):
                            full_result = binascii.b2a_base64(data).decode('ascii').strip()
                            if encrypt and key:
                                full_result = xor_encrypt(full_result, key)
                            display_result = full_result[:10000] + "..." if len(full_result) > 10000 else full_result
                        else:
                            full_result = data.hex()
                            display_result = full_result[:10000] + "..." if len(full_result) > 10000 else full_result
                        self.result_queue.put((display_result, full_result, f"[{upload_type} -> {conv_type.split('→')[-1].strip()}] {os.path.basename(file_path)} -> {display_result}", f"✅ Processed {upload_type.lower()}: {os.path.basename(file_path)}"))
                        self.root.after(0, self.update_ui_after_conversion)
                        return

                if upload_type == "File":
                    input_text = self.input_text.get("1.0", tk.END).strip()
                    if not input_text:
                        self.root.after(0, lambda: messagebox.showwarning("Warning", "Input field is empty and no file selected."))
                        self.root.after(0, lambda: self.convert_btn.configure(state="normal"))
                        self.root.after(0, lambda: self.root.config(cursor=""))
                        return

                    result = ""
                    error = None
                    if conv_type == "Text → Binary":
                        result = convert_text_to_binary(input_text, encoding, encrypt, key)
                    elif conv_type == "Binary → Text":
                        result, error = convert_binary_to_text(input_text, encoding)
                    elif conv_type == "Text → Hex":
                        result, error = convert_text_to_hex(input_text, encoding)
                    elif conv_type == "Hex → Text":
                        result, error = convert_hex_to_text(input_text, encoding)
                    elif conv_type == "Hex → Binary":
                        result, error = convert_hex_to_binary(input_text, encrypt, key)
                    else:
                        result, error = convert_binary_to_hex(input_text)

                    if error:
                        self.root.after(0, lambda: messagebox.showerror("Conversion Error", error))
                        self.root.after(0, lambda: self.set_status(f"❌ {error}", error=True))
                        self.root.after(0, lambda: self.convert_btn.configure(state="normal"))
                        self.root.after(0, lambda: self.root.config(cursor=""))
                        return

                    display_result = result[:10000] + "..." if len(result) > 10000 else result
                    self.result_queue.put((display_result, result, f"[{conv_type}] {input_text[:50]}... -> {display_result}", "✅ Conversion successful."))
                    self.root.after(0, self.update_ui_after_conversion)
                else:
                    self.root.after(0, lambda: messagebox.showwarning("Warning", "Please select a file for conversion."))
                    self.root.after(0, lambda: self.convert_btn.configure(state="normal"))
                    self.root.after(0, lambda: self.root.config(cursor=""))
            except Exception as exc:
                self.root.after(0, lambda: self.convert_btn.configure(state="normal"))
                self.root.after(0, lambda: self.root.config(cursor=""))
                self.root.after(0, lambda: messagebox.showerror("Error", f"An unexpected error occurred:\n{exc}"))
                self.root.after(0, lambda: self.set_status("❌ Conversion failed.", error=True))

        Thread(target=process_conversion, daemon=True).start()

    def update_ui_after_conversion(self):
        try:
            display_result, full_result, history_entry, status_message = self.result_queue.get_nowait()
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, display_result)
            self.full_result = full_result
            pyperclip.copy(full_result)
            self.add_history(history_entry, full_result)
            self.input_text.delete("1.0", tk.END)
            self.input_text.configure(state="normal")
            self.convert_btn.configure(state="normal")
            self.root.config(cursor="")
            self.set_status(status_message, timeout=3000)
        except Queue.Empty:
            self.root.after(100, self.update_ui_after_conversion)

    def copy_output(self):
        output_text = self.full_result or self.output_text.get("1.0", tk.END).strip()
        if output_text:
            try:
                pyperclip.copy(output_text)
                self.set_status("✅ Output copied to clipboard.", timeout=3000)
            except Exception:
                self.set_status("❌ Clipboard copying failed.", error=True, timeout=3000)
        else:
            self.root.after(0, lambda: messagebox.showinfo("Info", "There is no output to copy."))

    def save_output(self):
        output_text = self.full_result or self.output_text.get("1.0", tk.END).strip()
        if not output_text:
            self.root.after(0, lambda: messagebox.showinfo("Info", "No output to save."))
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            message = save_to_file(output_text, file_path)
            self.root.after(0, lambda: messagebox.showinfo("Save Result", message))
            self.set_status(f"✅ Saved output to {file_path}", timeout=3000)

    def show_stats(self):
        upload_type = self.upload_type.get()
        if upload_type == "File":
            input_text = self.input_text.get("1.0", tk.END).strip()
            if not input_text:
                self.root.after(0, lambda: messagebox.showinfo("Info", "No input provided to show stats."))
                return
            stats = show_stats(input_text)
            self.root.after(0, lambda: messagebox.showinfo("Input Text Statistics", stats))
        else:
            self.root.after(0, lambda: messagebox.showinfo("Info", f"Statistics not available for {upload_type.lower()}."))

    def set_theme(self, name):
        if name in self.themes:
            self.current_theme = name
            self.colors = self.themes[name]
            self.input_fg = self.colors["fg"]
            self.input_bg = self.colors["input_bg"]
            self.output_fg = self.colors["fg"]
            self.output_bg = self.colors["input_bg"]
            self.apply_theme()
            self.apply_customization()
            self.canvas.configure(bg=self.colors["bg"])
            self.set_status(f"✅ Theme switched to {name}.", timeout=3000)

    def apply_theme(self):
        c = self.colors
        self.root.configure(bg=c["bg"])
        self.style.configure('TLabel', background=c["bg"], foreground=c["fg"])
        self.style.configure('TButton', background=c["button_bg"], foreground=c["button_fg"])
        self.style.configure('Pressed.TButton', background=c["accent"], foreground=c["button_fg"])
        self.style.configure('Hover.TButton', background=c["accent"], foreground=c["button_fg"])
        self.style.map('TButton', background=[('active', c["accent"]), ('!disabled', c["button_bg"])],
                       foreground=[('active', c["button_fg"]), ('!disabled', c["button_fg"])])
        self.style.configure('TCheckbutton', background=c["bg"], foreground=c["fg"])
        self.style.configure('TCombobox', fieldbackground=c["input_bg"], foreground=c["fg"], background=c["bg"], arrowcolor=c["fg"])
        self.style.map('TCombobox', fieldbackground=[('readonly', c["input_bg"])], background=[('readonly', c["bg"])])
        self.style.configure('TEntry', fieldbackground=c["input_bg"], foreground=c["fg"])
        self.style.configure('TNotebook', background=c["bg"])
        self.style.configure('TNotebook.Tab', background=c["bg"], foreground=c["fg"])

        self.input_text.configure(bg=self.input_bg, fg=self.input_fg, insertbackground=c["accent"])
        self.output_text.configure(bg=self.output_bg, fg=self.output_fg, insertbackground=c["accent"])
        self.history_listbox.configure(bg=c["input_bg"], fg=c["fg"])
        self.key_entry.configure(background=c["input_bg"], foreground=c["fg"])
        self.file_entry.configure(background=c["input_bg"], foreground=c["fg"])
        self.canvas.configure(bg=c["bg"])
        self.status_bar.configure(background=c["bg"])

    def on_resize(self, event):
        width = self.root.winfo_width()
        if width > 1200:
            new_font_size = min(self.font_size + 4, 18)
        elif width < 800:
            new_font_size = max(self.font_size - 2, 12)
        else:
            new_font_size = self.font_size
        if new_font_size != self.font_size:
            self.font_size = new_font_size
            self.font_size_var.set(new_font_size)
            self.apply_customization()

    def on_exit(self):
        if messagebox.askokcancel("Quit", "Do you really want to exit?"):
            self.root.destroy()

    def show_about(self):
        messagebox.showinfo("About", "Text & Binary Converter\nCreated with Tkinter\nSupports text, binary, hex, and media conversions\nBy BLACKBOX AI")

if __name__ == "__main__":
    root = tk.Tk()
    app = ConverterApp(root)
    root.mainloop()

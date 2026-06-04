from __future__ import annotations

import sys
import threading
import traceback
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, X, filedialog, messagebox, ttk
import tkinter as tk

from PIL import Image, ImageTk

try:
    import cv2
except Exception:
    cv2 = None

from stego_carriers import (
    can_open_as_image,
    carrier_label,
    embed_for_file,
    extract_from_file,
    is_pdf_file,
    is_video_file,
    suggested_output_path,
)
from stego_constants import MEDIA_FILETYPES
from stego_core import (
    decrypt_text_input,
    log_exception,
    log_traceback_text,
    parse_hex,
    validate_image_limits,
    validate_payload_size,
    validate_source_file,
)


APP_BACKGROUND = "#020D1F"
APP_BACKGROUND_RGBA = (2, 13, 31, 255)
PANEL_BACKGROUND = "#111c2e"


def asset_path(file_name: str) -> Path:
    base_path = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base_path / "assets" / file_name


class AnimatedGlobe(tk.Label):
    def __init__(self, parent: tk.Misc, size: int = 112, frame_ms: int = 55) -> None:
        super().__init__(parent, bg=APP_BACKGROUND, bd=0, highlightthickness=0)
        self.size = size
        self.frame_ms = frame_ms
        self.render_scale = 3
        self.render_size = self.size * self.render_scale
        self.angle = 0
        self.after_id: str | None = None
        self.photo_image: ImageTk.PhotoImage | None = None
        self.base_image = self._load_base_image()
        self.bind("<Destroy>", self._stop_animation)
        self._animate()

    def _load_base_image(self) -> Image.Image | None:
        image = None
        for file_name in ("greynoc_globe_1024.png", "greynoc_globe_256.png"):
            try:
                with Image.open(asset_path(file_name)) as source:
                    image = source.convert("RGBA")
                break
            except Exception:
                continue
        if image is None:
            return None

        image.thumbnail((self.render_size, self.render_size), Image.Resampling.LANCZOS)
        canvas = Image.new("RGBA", (self.render_size, self.render_size), (0, 0, 0, 0))
        canvas.alpha_composite(image, ((self.render_size - image.width) // 2, (self.render_size - image.height) // 2))
        return canvas

    def _animate(self) -> None:
        if self.base_image is None:
            return

        rotated = self.base_image.rotate(self.angle, resample=Image.Resampling.BICUBIC)
        high_res_frame = Image.new("RGBA", (self.render_size, self.render_size), APP_BACKGROUND_RGBA)
        high_res_frame.alpha_composite(rotated)
        frame = high_res_frame.resize((self.size, self.size), Image.Resampling.LANCZOS)
        self.photo_image = ImageTk.PhotoImage(frame)
        self.configure(image=self.photo_image)
        self.angle = (self.angle + 2) % 360
        self.after_id = self.after(self.frame_ms, self._animate)

    def _stop_animation(self, _event: tk.Event) -> None:
        if self.after_id is not None:
            try:
                self.after_cancel(self.after_id)
            except tk.TclError:
                pass
            self.after_id = None


class StegoStudioApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()

        self.title("GreyNOC Stego Studio")
        self.geometry("980x680")
        self.minsize(820, 560)
        self.configure(bg=APP_BACKGROUND)

        self.app_icon_image: tk.PhotoImage | None = None
        self.window_bar_icon_image: ImageTk.PhotoImage | None = None
        self.brand_logo_image: ImageTk.PhotoImage | None = None
        self.splash_globe_image: ImageTk.PhotoImage | None = None
        self.splash_window: tk.Toplevel | None = None
        self.extract_preview_image: ImageTk.PhotoImage | None = None
        self.inject_preview_image: ImageTk.PhotoImage | None = None
        self.extract_path: Path | None = None
        self.inject_path: Path | None = None
        self.payload_mode = tk.StringVar(value="message")
        self.extract_password_var = tk.StringVar()
        self.inject_password_var = tk.StringVar()
        self.text_decrypt_password_var = tk.StringVar()
        self.allow_plain_var = tk.BooleanVar(value=False)
        self.drag_start_x = 0
        self.drag_start_y = 0
        self.resize_start_x = 0
        self.resize_start_y = 0
        self.resize_start_width = 0
        self.resize_start_height = 0
        self.normal_geometry = ""
        self.is_maximized = False
        self.worker_active = False

        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("Root.TFrame", background=APP_BACKGROUND)
        self.style.configure("Panel.TFrame", background=PANEL_BACKGROUND, relief="flat")
        self.style.configure(
            "Title.TLabel",
            background=APP_BACKGROUND,
            foreground="#eef7ff",
            font=("Segoe UI", 22, "bold"),
        )
        self.style.configure("Muted.TLabel", background=APP_BACKGROUND, foreground="#9fb2c7", font=("Segoe UI", 10))
        self.style.configure("PanelTitle.TLabel", background=PANEL_BACKGROUND, foreground="#eef7ff", font=("Segoe UI", 11, "bold"))
        self.style.configure("PanelText.TLabel", background=PANEL_BACKGROUND, foreground="#b9cbe0", font=("Segoe UI", 10))
        self.style.configure("Status.TLabel", background=PANEL_BACKGROUND, foreground="#7bdfff", font=("Segoe UI", 10, "bold"))
        self.style.configure("Danger.TLabel", background=PANEL_BACKGROUND, foreground="#ff9aa2", font=("Segoe UI", 10, "bold"))
        self.style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=(14, 8))
        self.style.configure("Ghost.TButton", font=("Segoe UI", 10), padding=(12, 7))
        self.style.configure("TNotebook", background=APP_BACKGROUND, borderwidth=0)
        self.style.configure("TNotebook.Tab", padding=(16, 8), font=("Segoe UI", 10, "bold"))
        self.style.configure("TRadiobutton", background="#111c2e", foreground="#d7ecff", font=("Segoe UI", 10))
        self.style.configure("TCheckbutton", background="#111c2e", foreground="#d7ecff", font=("Segoe UI", 10))
        self.style.configure("TEntry", fieldbackground="#08111f", foreground="#eef7ff", insertcolor="#eef7ff")

        self.configure_window_icon()
        self.withdraw()
        self.show_splash()
        self.configure_frameless_window()
        self._build_ui()
        self.after(1100, self.close_splash)

        if len(sys.argv) > 1:
            start_path = Path(sys.argv[1])
            if start_path.exists():
                self.after(100, lambda: self.load_extract_file(start_path))

    def _build_ui(self) -> None:
        shell = ttk.Frame(self, style="Root.TFrame")
        shell.pack(fill=BOTH, expand=True)

        self.build_window_bar(shell)

        root = ttk.Frame(shell, style="Root.TFrame", padding=(24, 14, 24, 24))
        root.pack(fill=BOTH, expand=True)

        header = ttk.Frame(root, style="Root.TFrame")
        header.pack(fill=X)

        self.brand_logo_image = self.load_photo_asset("greynoc_brand.png", 86)
        if self.brand_logo_image is not None:
            tk.Label(header, image=self.brand_logo_image, bg=APP_BACKGROUND, bd=0).pack(side=LEFT, padx=(0, 14))

        title_block = ttk.Frame(header, style="Root.TFrame")
        title_block.pack(side=LEFT, fill=X, expand=True)
        ttk.Label(title_block, text="GreyNOC Stego Studio", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            title_block,
            text="Extract or inject hidden payloads in images, videos, and PDFs.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(4, 0))

        AnimatedGlobe(header, size=112).pack(side="right", padx=(18, 0))

        notebook = ttk.Notebook(root)
        notebook.pack(fill=BOTH, expand=True, pady=(22, 0))
        notebook.add(self._build_extract_tab(notebook), text="Extract")
        notebook.add(self._build_text_decrypt_tab(notebook), text="Decrypt Text")
        notebook.add(self._build_inject_tab(notebook), text="Inject")

        self.build_resize_grip(shell)

    def show_splash(self) -> None:
        splash = tk.Toplevel(self)
        splash.overrideredirect(True)
        splash.configure(bg=APP_BACKGROUND)
        splash.attributes("-topmost", True)

        width = 430
        height = 360
        x = self.winfo_screenwidth() // 2 - width // 2
        y = self.winfo_screenheight() // 2 - height // 2
        splash.geometry(f"{width}x{height}+{x}+{y}")

        frame = tk.Frame(splash, bg=APP_BACKGROUND, bd=0, highlightthickness=1, highlightbackground="#1d9fff")
        frame.pack(fill=BOTH, expand=True)

        self.splash_globe_image = self.load_photo_asset("greynoc_globe_1024.png", 190)
        if self.splash_globe_image is None:
            self.splash_globe_image = self.load_photo_asset("greynoc_globe_256.png", 190)
        if self.splash_globe_image is not None:
            tk.Label(frame, image=self.splash_globe_image, bg=APP_BACKGROUND, bd=0).pack(pady=(34, 14))

        tk.Label(
            frame,
            text="GreyNOC Stego Studio",
            bg=APP_BACKGROUND,
            fg="#eef7ff",
            font=("Segoe UI", 22, "bold"),
        ).pack()
        tk.Label(
            frame,
            text="Secure media payload tools",
            bg=APP_BACKGROUND,
            fg="#7bdfff",
            font=("Segoe UI", 10, "bold"),
        ).pack(pady=(7, 0))

        self.splash_window = splash

    def close_splash(self) -> None:
        if self.splash_window is not None:
            try:
                self.splash_window.destroy()
            except tk.TclError:
                pass
            self.splash_window = None
        self.deiconify()
        self.lift()

    def _build_extract_tab(self, parent: ttk.Notebook) -> ttk.Frame:
        tab = ttk.Frame(parent, style="Root.TFrame", padding=(0, 18, 0, 0))
        tab.columnconfigure(0, weight=4)
        tab.columnconfigure(1, weight=5)
        tab.rowconfigure(0, weight=1)

        left_panel = ttk.Frame(tab, style="Panel.TFrame", padding=16)
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        left_panel.rowconfigure(1, weight=1)
        left_panel.columnconfigure(0, weight=1)

        extract_header = ttk.Frame(left_panel, style="Panel.TFrame")
        extract_header.grid(row=0, column=0, sticky="we")
        extract_header.columnconfigure(0, weight=1)
        ttk.Label(extract_header, text="Carrier", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Button(extract_header, text="Open File", style="Ghost.TButton", command=self.pick_extract_file).grid(row=0, column=1, sticky="e")

        self.extract_preview = tk.Label(
            left_panel,
            bg="#08111f",
            fg="#9fb2c7",
            text="No file selected",
            font=("Segoe UI", 12),
            width=32,
            height=16,
            bd=0,
        )
        self.extract_preview.grid(row=1, column=0, sticky="nsew", pady=(12, 12))
        self.extract_preview.bind("<Double-Button-1>", lambda _event: self.pick_extract_file())

        self.extract_path_label = ttk.Label(left_panel, text="", style="PanelText.TLabel", wraplength=360)
        self.extract_path_label.grid(row=2, column=0, sticky="we")

        right_panel = ttk.Frame(tab, style="Panel.TFrame", padding=16)
        right_panel.grid(row=0, column=1, sticky="nsew")
        right_panel.columnconfigure(0, weight=1)
        right_panel.rowconfigure(4, weight=1)
        right_panel.rowconfigure(7, weight=1)

        ttk.Label(right_panel, text="Status", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        self.extract_status_label = ttk.Label(right_panel, text="Waiting for file", style="Status.TLabel")
        self.extract_status_label.grid(row=1, column=0, sticky="w", pady=(6, 14))

        password_frame = ttk.Frame(right_panel, style="Panel.TFrame")
        password_frame.grid(row=2, column=0, sticky="we", pady=(0, 18))
        password_frame.columnconfigure(1, weight=1)
        ttk.Label(password_frame, text="Password", style="PanelText.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 10))
        ttk.Entry(password_frame, textvariable=self.extract_password_var, show="*").grid(row=0, column=1, sticky="we")

        message_header = ttk.Frame(right_panel, style="Panel.TFrame")
        message_header.grid(row=3, column=0, sticky="new")
        message_header.columnconfigure(0, weight=1)
        ttk.Label(message_header, text="Message", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Button(message_header, text="Copy", style="Ghost.TButton", command=lambda: self.copy_from(self.extract_message_text, self.extract_status_label)).grid(row=0, column=1, sticky="e")

        self.extract_message_text = self.make_text(right_panel, height=5, font_size=12)
        self.extract_message_text.grid(row=4, column=0, sticky="nsew", pady=(8, 18))

        hex_header = ttk.Frame(right_panel, style="Panel.TFrame")
        hex_header.grid(row=6, column=0, sticky="new")
        hex_header.columnconfigure(0, weight=1)
        ttk.Label(hex_header, text="Hex", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Button(hex_header, text="Copy", style="Ghost.TButton", command=lambda: self.copy_from(self.extract_hex_text, self.extract_status_label)).grid(row=0, column=1, sticky="e")

        self.extract_hex_text = self.make_text(right_panel, height=6, font_size=11)
        self.extract_hex_text.grid(row=7, column=0, sticky="nsew", pady=(8, 0))
        return tab

    def _build_text_decrypt_tab(self, parent: ttk.Notebook) -> ttk.Frame:
        tab = ttk.Frame(parent, style="Root.TFrame", padding=(0, 18, 0, 0))
        tab.columnconfigure(0, weight=1)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(0, weight=1)

        left_panel = ttk.Frame(tab, style="Panel.TFrame", padding=16)
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        left_panel.columnconfigure(0, weight=1)
        left_panel.rowconfigure(1, weight=1)

        input_header = ttk.Frame(left_panel, style="Panel.TFrame")
        input_header.grid(row=0, column=0, sticky="new")
        input_header.columnconfigure(0, weight=1)
        ttk.Label(input_header, text="Encrypted Text", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Button(
            input_header,
            text="Clear",
            style="Ghost.TButton",
            command=self.clear_text_decrypt,
        ).grid(row=0, column=1, sticky="e")

        self.text_decrypt_input_text = self.make_text(left_panel, height=12, font_size=11)
        self.text_decrypt_input_text.grid(row=1, column=0, sticky="nsew", pady=(8, 12))

        password_frame = ttk.Frame(left_panel, style="Panel.TFrame")
        password_frame.grid(row=2, column=0, sticky="we")
        password_frame.columnconfigure(1, weight=1)
        ttk.Label(password_frame, text="Password", style="PanelText.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 10))
        password_entry = ttk.Entry(password_frame, textvariable=self.text_decrypt_password_var, show="*")
        password_entry.grid(row=0, column=1, sticky="we")
        ttk.Button(
            password_frame,
            text="Decrypt Text",
            style="Accent.TButton",
            command=self.decrypt_text_value,
        ).grid(row=0, column=2, sticky="e", padx=(10, 0))

        self.text_decrypt_status_label = ttk.Label(left_panel, text="Waiting for encrypted text", style="Status.TLabel")
        self.text_decrypt_status_label.grid(row=3, column=0, sticky="w", pady=(12, 0))

        right_panel = ttk.Frame(tab, style="Panel.TFrame", padding=16)
        right_panel.grid(row=0, column=1, sticky="nsew")
        right_panel.columnconfigure(0, weight=1)
        right_panel.rowconfigure(1, weight=1)
        right_panel.rowconfigure(4, weight=1)

        message_header = ttk.Frame(right_panel, style="Panel.TFrame")
        message_header.grid(row=0, column=0, sticky="new")
        message_header.columnconfigure(0, weight=1)
        ttk.Label(message_header, text="Message", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Button(
            message_header,
            text="Copy",
            style="Ghost.TButton",
            command=lambda: self.copy_from(self.text_decrypt_message_text, self.text_decrypt_status_label),
        ).grid(row=0, column=1, sticky="e")

        self.text_decrypt_message_text = self.make_text(right_panel, height=7, font_size=12)
        self.text_decrypt_message_text.grid(row=1, column=0, sticky="nsew", pady=(8, 18))

        hex_header = ttk.Frame(right_panel, style="Panel.TFrame")
        hex_header.grid(row=3, column=0, sticky="new")
        hex_header.columnconfigure(0, weight=1)
        ttk.Label(hex_header, text="Hex", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Button(
            hex_header,
            text="Copy",
            style="Ghost.TButton",
            command=lambda: self.copy_from(self.text_decrypt_hex_text, self.text_decrypt_status_label),
        ).grid(row=0, column=1, sticky="e")

        self.text_decrypt_hex_text = self.make_text(right_panel, height=7, font_size=11)
        self.text_decrypt_hex_text.grid(row=4, column=0, sticky="nsew", pady=(8, 0))
        return tab

    def _build_inject_tab(self, parent: ttk.Notebook) -> ttk.Frame:
        tab = ttk.Frame(parent, style="Root.TFrame", padding=(0, 18, 0, 0))
        tab.columnconfigure(0, weight=4)
        tab.columnconfigure(1, weight=5)
        tab.rowconfigure(0, weight=1)

        left_panel = ttk.Frame(tab, style="Panel.TFrame", padding=16)
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        left_panel.rowconfigure(1, weight=1)
        left_panel.columnconfigure(0, weight=1)

        inject_header = ttk.Frame(left_panel, style="Panel.TFrame")
        inject_header.grid(row=0, column=0, sticky="we")
        inject_header.columnconfigure(0, weight=1)
        ttk.Label(inject_header, text="Source File", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Button(inject_header, text="Open File", style="Ghost.TButton", command=self.pick_inject_file).grid(row=0, column=1, sticky="e")

        self.inject_preview = tk.Label(
            left_panel,
            bg="#08111f",
            fg="#9fb2c7",
            text="No source selected",
            font=("Segoe UI", 12),
            width=32,
            height=16,
            bd=0,
        )
        self.inject_preview.grid(row=1, column=0, sticky="nsew", pady=(12, 12))
        self.inject_preview.bind("<Double-Button-1>", lambda _event: self.pick_inject_file())

        self.inject_path_label = ttk.Label(left_panel, text="", style="PanelText.TLabel", wraplength=360)
        self.inject_path_label.grid(row=2, column=0, sticky="we")

        right_panel = ttk.Frame(tab, style="Panel.TFrame", padding=16)
        right_panel.grid(row=0, column=1, sticky="nsew")
        right_panel.columnconfigure(0, weight=1)
        right_panel.rowconfigure(2, weight=1)
        right_panel.rowconfigure(5, weight=1)

        ttk.Label(right_panel, text="Payload", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")

        mode_row = ttk.Frame(right_panel, style="Panel.TFrame")
        mode_row.grid(row=1, column=0, sticky="we", pady=(8, 8))
        ttk.Radiobutton(mode_row, text="Message", variable=self.payload_mode, value="message", command=self.update_payload_preview).pack(side=LEFT, padx=(0, 16))
        ttk.Radiobutton(mode_row, text="Hex", variable=self.payload_mode, value="hex", command=self.update_payload_preview).pack(side=LEFT)

        self.inject_payload_text = self.make_text(right_panel, height=7, font_size=12)
        self.inject_payload_text.grid(row=2, column=0, sticky="nsew")
        self.inject_payload_text.bind("<KeyRelease>", lambda _event: self.update_payload_preview())

        password_frame = ttk.Frame(right_panel, style="Panel.TFrame")
        password_frame.grid(row=3, column=0, sticky="we", pady=(12, 0))
        password_frame.columnconfigure(1, weight=1)
        ttk.Label(password_frame, text="Password", style="PanelText.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 10))
        password_entry = ttk.Entry(password_frame, textvariable=self.inject_password_var, show="*")
        password_entry.grid(row=0, column=1, sticky="we")
        password_entry.bind("<KeyRelease>", lambda _event: self.update_payload_preview())
        ttk.Checkbutton(
            password_frame,
            text="Allow unprotected legacy save",
            variable=self.allow_plain_var,
            command=self.update_payload_preview,
        ).grid(row=1, column=1, sticky="w", pady=(6, 0))

        preview_header = ttk.Frame(right_panel, style="Panel.TFrame")
        preview_header.grid(row=4, column=0, sticky="new", pady=(18, 0))
        preview_header.columnconfigure(0, weight=1)
        ttk.Label(preview_header, text="Hex Preview", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Button(preview_header, text="Copy", style="Ghost.TButton", command=lambda: self.copy_from(self.inject_hex_preview_text, self.inject_status_label)).grid(row=0, column=1, sticky="e")

        self.inject_hex_preview_text = self.make_text(right_panel, height=5, font_size=11)
        self.inject_hex_preview_text.grid(row=5, column=0, sticky="nsew", pady=(8, 12))

        ttk.Label(
            right_panel,
            text="Images save as PNG pixel LSB. PDFs and videos use a file trailer carrier.",
            style="PanelText.TLabel",
            wraplength=440,
        ).grid(row=6, column=0, sticky="we", pady=(0, 12))

        bottom_row = ttk.Frame(right_panel, style="Panel.TFrame")
        bottom_row.grid(row=7, column=0, sticky="we")
        bottom_row.columnconfigure(0, weight=1)
        self.inject_status_label = ttk.Label(bottom_row, text="Waiting for source file", style="Status.TLabel")
        self.inject_status_label.grid(row=0, column=0, sticky="w")
        ttk.Button(bottom_row, text="Save Encoded File", style="Accent.TButton", command=self.save_encoded_file).grid(row=0, column=1, sticky="e")

        self.set_text(self.inject_payload_text, "Save the Humans.")
        self.update_payload_preview()
        return tab

    def configure_frameless_window(self) -> None:
        self.overrideredirect(True)
        self.bind("<Map>", self.restore_frameless_after_minimize)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def build_window_bar(self, parent: tk.Misc) -> None:
        bar = tk.Frame(parent, bg=APP_BACKGROUND, height=32, bd=0, highlightthickness=0)
        bar.pack(fill=X)
        bar.pack_propagate(False)
        self.bind_window_drag(bar)

        self.window_bar_icon_image = self.load_photo_asset("greynoc_app_icon.png", 20)
        if self.window_bar_icon_image is not None:
            icon_label = tk.Label(bar, image=self.window_bar_icon_image, bg=APP_BACKGROUND, bd=0)
            icon_label.pack(side=LEFT, padx=(10, 7))
            self.bind_window_drag(icon_label)

        title_label = tk.Label(
            bar,
            text="GreyNOC Stego Studio",
            bg=APP_BACKGROUND,
            fg="#b9cbe0",
            font=("Segoe UI", 9),
            bd=0,
        )
        title_label.pack(side=LEFT, fill=X, expand=True, anchor="w")
        self.bind_window_drag(title_label)

        self.make_window_control(bar, "X", self.destroy, "#4b1622", "#ffccd4").pack(side=RIGHT, fill="y")
        self.make_window_control(bar, "[]", self.toggle_maximize, "#102542", "#d7ecff").pack(side=RIGHT, fill="y")
        self.make_window_control(bar, "_", self.minimize_window, "#102542", "#d7ecff").pack(side=RIGHT, fill="y")

    @staticmethod
    def make_window_control(parent: tk.Misc, text: str, command, active_bg: str, active_fg: str) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=APP_BACKGROUND,
            fg="#d7ecff",
            activebackground=active_bg,
            activeforeground=active_fg,
            bd=0,
            width=5,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            takefocus=False,
        )

    def build_resize_grip(self, parent: tk.Misc) -> None:
        grip = tk.Frame(parent, width=16, height=16, bg=APP_BACKGROUND, bd=0, highlightthickness=0, cursor="size_nw_se")
        grip.place(relx=1.0, rely=1.0, anchor="se")
        grip.bind("<ButtonPress-1>", self.start_window_resize)
        grip.bind("<B1-Motion>", self.resize_window)

    def bind_window_drag(self, widget: tk.Widget) -> None:
        widget.bind("<ButtonPress-1>", self.start_window_drag)
        widget.bind("<B1-Motion>", self.drag_window)
        widget.bind("<Double-Button-1>", self.toggle_maximize)

    def start_window_drag(self, event: tk.Event) -> None:
        self.drag_start_x = event.x
        self.drag_start_y = event.y

    def drag_window(self, event: tk.Event) -> None:
        if self.is_maximized:
            return
        x = event.x_root - self.drag_start_x
        y = event.y_root - self.drag_start_y
        self.geometry(f"+{x}+{y}")

    def minimize_window(self) -> None:
        self.overrideredirect(False)
        self.iconify()

    def restore_frameless_after_minimize(self, _event: tk.Event) -> None:
        if self.state() == "normal":
            self.after(10, lambda: self.overrideredirect(True))

    def toggle_maximize(self, _event: tk.Event | None = None) -> None:
        if self.is_maximized:
            self.geometry(self.normal_geometry)
            self.is_maximized = False
            return

        self.normal_geometry = self.geometry()
        x, y, width, height = self.get_work_area()
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.is_maximized = True

    def get_work_area(self) -> tuple[int, int, int, int]:
        if sys.platform == "win32":
            try:
                import ctypes

                class Rect(ctypes.Structure):
                    _fields_ = [
                        ("left", ctypes.c_long),
                        ("top", ctypes.c_long),
                        ("right", ctypes.c_long),
                        ("bottom", ctypes.c_long),
                    ]

                rect = Rect()
                ctypes.windll.user32.SystemParametersInfoW(48, 0, ctypes.byref(rect), 0)
                return rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top
            except Exception:
                pass

        return 0, 0, self.winfo_screenwidth(), self.winfo_screenheight()

    def start_window_resize(self, event: tk.Event) -> None:
        if self.is_maximized:
            return
        self.resize_start_x = event.x_root
        self.resize_start_y = event.y_root
        self.resize_start_width = self.winfo_width()
        self.resize_start_height = self.winfo_height()

    def resize_window(self, event: tk.Event) -> None:
        if self.is_maximized:
            return
        minimum_width, minimum_height = self.minsize()
        width = max(minimum_width, self.resize_start_width + event.x_root - self.resize_start_x)
        height = max(minimum_height, self.resize_start_height + event.y_root - self.resize_start_y)
        self.geometry(f"{width}x{height}")

    def configure_window_icon(self) -> None:
        try:
            self.app_icon_image = tk.PhotoImage(file=str(asset_path("greynoc_app_icon.png")))
            self.iconphoto(True, self.app_icon_image)
        except Exception:
            self.app_icon_image = None

    @staticmethod
    def load_photo_asset(file_name: str, size: int) -> ImageTk.PhotoImage | None:
        try:
            with Image.open(asset_path(file_name)) as source:
                image = source.convert("RGBA")
        except Exception:
            return None

        image.thumbnail((size, size), Image.Resampling.LANCZOS)
        canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        canvas.alpha_composite(image, ((size - image.width) // 2, (size - image.height) // 2))
        return ImageTk.PhotoImage(canvas)

    @staticmethod
    def make_text(parent: ttk.Frame, height: int, font_size: int) -> tk.Text:
        return tk.Text(
            parent,
            height=height,
            bg="#08111f",
            fg="#eef7ff",
            insertbackground="#eef7ff",
            selectbackground="#1e88e5",
            font=("Consolas", font_size),
            relief="flat",
            wrap="word",
            padx=10,
            pady=10,
        )

    def run_worker(self, status_label: ttk.Label, busy_message: str, worker, on_success) -> None:
        if self.worker_active:
            self.set_status(status_label, "Another operation is already running.", ok=False)
            return

        self.worker_active = True
        self.set_status(status_label, busy_message, ok=True)

        def target() -> None:
            try:
                result = worker()
                error = None
                traceback_text = ""
            except Exception as exc:
                result = None
                error = exc
                traceback_text = traceback.format_exc()

            def finish() -> None:
                self.worker_active = False
                if error is not None:
                    self.set_status(status_label, str(error), ok=False)
                    log_traceback_text(traceback_text)
                    return
                on_success(result)

            self.after(0, finish)

        threading.Thread(target=target, daemon=True).start()

    def pick_extract_file(self) -> None:
        file_name = filedialog.askopenfilename(title="Open encoded media", filetypes=MEDIA_FILETYPES)
        if file_name:
            self.load_extract_file(Path(file_name))

    def pick_inject_file(self) -> None:
        file_name = filedialog.askopenfilename(title="Open source media", filetypes=MEDIA_FILETYPES)
        if file_name:
            self.load_inject_file(Path(file_name))

    def load_extract_file(self, file_path: Path) -> None:
        self.extract_path = file_path
        self.extract_path_label.configure(text=str(file_path))
        self.clear_extract_outputs()
        self.set_status(self.extract_status_label, "Reading file", ok=True)
        self.update_idletasks()

        try:
            self.render_preview(file_path, self.extract_preview, "extract")
            password = self.extract_password_var.get()
        except Exception as exc:
            self.set_status(self.extract_status_label, str(exc), ok=False)
            log_exception()
            return

        def worker() -> tuple[str, str, str]:
            return extract_from_file(file_path, password)

        def on_success(result: tuple[str, str, str]) -> None:
            hex_value, message, mode = result
            self.set_text(self.extract_message_text, message)
            self.set_text(self.extract_hex_text, hex_value)
            self.set_status(self.extract_status_label, f"Payload verified: {mode}", ok=True)

        self.run_worker(self.extract_status_label, "Extracting payload", worker, on_success)

    def load_inject_file(self, file_path: Path) -> None:
        self.inject_path = file_path
        self.inject_path_label.configure(text=str(file_path))
        self.set_status(self.inject_status_label, f"Source loaded: {carrier_label(file_path)}", ok=True)
        try:
            self.render_preview(file_path, self.inject_preview, "inject")
            self.update_payload_preview()
        except Exception as exc:
            self.inject_path = None
            self.set_status(self.inject_status_label, str(exc), ok=False)
            log_exception()

    def render_preview(self, file_path: Path, label: tk.Label, slot: str) -> None:
        validate_source_file(file_path)
        if is_pdf_file(file_path):
            self.set_placeholder(label, slot, f"PDF selected\n\n{file_path.name}")
            return

        if is_video_file(file_path):
            preview = self.video_preview_frame(file_path)
            if preview is None:
                self.set_placeholder(label, slot, f"Video selected\n\n{file_path.name}")
                return
        else:
            with Image.open(file_path) as image:
                validate_image_limits(image)
                image.thumbnail((360, 360), Image.Resampling.LANCZOS)
                preview = image.convert("RGBA")

        photo_image = ImageTk.PhotoImage(preview)
        if slot == "extract":
            self.extract_preview_image = photo_image
        else:
            self.inject_preview_image = photo_image
        label.configure(image=photo_image, text="", width=360, height=360)

    def video_preview_frame(self, video_path: Path) -> Image.Image | None:
        if cv2 is None:
            return None

        capture = cv2.VideoCapture(str(video_path))
        try:
            ok, frame = capture.read()
            if not ok or frame is None:
                return None
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            image = Image.fromarray(frame)
            image.thumbnail((360, 360), Image.Resampling.LANCZOS)
            return image.convert("RGBA")
        finally:
            capture.release()

    def set_placeholder(self, label: tk.Label, slot: str, text: str) -> None:
        if slot == "extract":
            self.extract_preview_image = None
        else:
            self.inject_preview_image = None
        label.configure(image="", text=text, width=32, height=16)

    def get_inject_payload(self) -> bytes:
        value = self.inject_payload_text.get("1.0", END).strip()
        if self.payload_mode.get() == "hex":
            payload = parse_hex(value)
            validate_payload_size(payload)
            return payload
        if not value:
            raise ValueError("Message payload is empty.")
        payload = value.encode("utf-8")
        validate_payload_size(payload)
        return payload

    def get_inject_password(self) -> str:
        password = self.inject_password_var.get()
        if password:
            return password
        if self.allow_plain_var.get():
            return ""
        raise ValueError("Enter a password or enable unprotected legacy save.")

    def update_payload_preview(self) -> None:
        try:
            payload = self.get_inject_payload()
            self.set_text(self.inject_hex_preview_text, payload.hex(" ").upper())
            if self.inject_path is None:
                self.set_status(self.inject_status_label, "Waiting for source file", ok=True)
            elif not self.inject_password_var.get() and not self.allow_plain_var.get():
                self.set_status(self.inject_status_label, "Ready payload. Enter a password before saving.", ok=True)
            else:
                protection = "password-protected" if self.inject_password_var.get() else "unprotected legacy"
                self.set_status(
                    self.inject_status_label,
                    f"Ready: {len(payload)} bytes | {carrier_label(self.inject_path)} | {protection}",
                    ok=True,
                )
        except Exception as exc:
            self.set_text(self.inject_hex_preview_text, "")
            self.set_status(self.inject_status_label, str(exc), ok=False)

    def save_encoded_file(self) -> None:
        if self.inject_path is None:
            self.set_status(self.inject_status_label, "Choose a source file first.", ok=False)
            return

        try:
            payload = self.get_inject_payload()
            password = self.get_inject_password()
        except Exception as exc:
            self.set_status(self.inject_status_label, str(exc), ok=False)
            return

        file_name = filedialog.asksaveasfilename(
            title="Save encoded media",
            defaultextension=".png" if can_open_as_image(self.inject_path) else self.inject_path.suffix,
            initialfile=suggested_output_path(self.inject_path).name,
            filetypes=[("PNG image", "*.png")] if can_open_as_image(self.inject_path) else MEDIA_FILETYPES,
        )
        if not file_name:
            return

        source_path = self.inject_path
        requested_output_path = Path(file_name)

        def worker() -> tuple[str, Path, str, str, str]:
            mode, final_output_path = embed_for_file(source_path, requested_output_path, payload, password)
            verified_hex, verified_message, verified_mode = extract_from_file(final_output_path, password)
            return mode, final_output_path, verified_hex, verified_message, verified_mode

        def on_success(result: tuple[str, Path, str, str, str]) -> None:
            mode, final_output_path, verified_hex, verified_message, verified_mode = result
            self.set_text(self.inject_hex_preview_text, verified_hex)
            self.set_status(self.inject_status_label, f"Saved {mode}: {final_output_path.name}", ok=True)
            self.extract_path = final_output_path
            self.extract_path_label.configure(text=str(final_output_path))
            self.set_text(self.extract_message_text, verified_message)
            self.set_text(self.extract_hex_text, verified_hex)
            self.set_status(self.extract_status_label, f"Payload verified: {verified_mode}", ok=True)

        self.run_worker(self.inject_status_label, "Saving encoded file", worker, on_success)

    def decrypt_text_value(self) -> None:
        encrypted_value = self.text_decrypt_input_text.get("1.0", END).strip()
        password = self.text_decrypt_password_var.get()
        if not encrypted_value:
            self.set_status(self.text_decrypt_status_label, "Enter encrypted text first.", ok=False)
            return
        if not password:
            self.set_status(self.text_decrypt_status_label, "Password is required for encrypted text.", ok=False)
            return

        self.set_text(self.text_decrypt_message_text, "")
        self.set_text(self.text_decrypt_hex_text, "")

        def worker() -> tuple[str, str]:
            return decrypt_text_input(encrypted_value, password)

        def on_success(result: tuple[str, str]) -> None:
            hex_value, message = result
            self.set_text(self.text_decrypt_message_text, message)
            self.set_text(self.text_decrypt_hex_text, hex_value)
            self.set_status(self.text_decrypt_status_label, f"Text decrypted: {len(bytes.fromhex(hex_value.replace(' ', '')))} bytes", ok=True)

        self.run_worker(self.text_decrypt_status_label, "Decrypting text", worker, on_success)

    def clear_text_decrypt(self) -> None:
        self.set_text(self.text_decrypt_input_text, "")
        self.set_text(self.text_decrypt_message_text, "")
        self.set_text(self.text_decrypt_hex_text, "")
        self.set_status(self.text_decrypt_status_label, "Waiting for encrypted text", ok=True)

    def clear_extract_outputs(self) -> None:
        self.set_text(self.extract_message_text, "")
        self.set_text(self.extract_hex_text, "")

    @staticmethod
    def set_status(label: ttk.Label, value: str, ok: bool) -> None:
        label.configure(text=value, style="Status.TLabel" if ok else "Danger.TLabel")

    @staticmethod
    def set_text(widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", END)
        widget.insert("1.0", value)

    def copy_from(self, widget: tk.Text, status_label: ttk.Label) -> None:
        value = widget.get("1.0", END).strip()
        if not value:
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.set_status(status_label, "Copied", ok=True)


def main() -> None:
    try:
        app = StegoStudioApp()
        app.mainloop()
    except Exception as exc:
        messagebox.showerror("GreyNOC Stego Studio", str(exc))


if __name__ == "__main__":
    main()

"""
RequiemFS - Raw Disk Forensic Recovery Visualizer
Phase 3: The Dashboard

New in this version:
  - Keyboard shortcuts: Ctrl+O to load, F5 to scan, Ctrl+E to export
  - Export Report: saves a JSON + text summary of everything found
  - Scan Stats: shows MB/s throughput, scan time, file count
  - Clickable sector map: click any sector to jump the hex view there
  - Entropy display: reports Shannon entropy per sector in findings
  - FOUND_TYPE: shows whether recovered file is JPEG, PNG, or PDF
  - Entropy Heatmap: visualizes the data density of the raw disk
  - Go to Offset: jump directly to any hex address
"""
import os, sys, threading, queue, subprocess, math, json, datetime, time
import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk

SECTOR_SIZE = 512
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FORENSICS_EXE = os.path.join(SCRIPT_DIR, "forensics.exe")

# Color palette
C = {
    "bg0": "#080b10", "bg1": "#0d1117", "bg2": "#161b22", "bg3": "#1c2128",
    "border": "#30363d", "t1": "#e6edf3", "t2": "#8b949e", "t3": "#484f58",
    "green": "#00ff41", "cyan": "#00d4ff", "red": "#ff4444",
    "yellow": "#ffcc00", "orange": "#ff8800",
}
SC = {
    "empty": (10, 14, 20), "noise": (26, 31, 44), "scanned": (16, 30, 20),
    "scanning": (0, 180, 220), "jpeg": (0, 220, 55), "header": (220, 180, 0),
    "gif": (220, 0, 180)
}


class RequiemFSApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("RequiemFS - Raw Disk Forensic Recovery Visualizer")
        self.geometry("1380x860")
        self.minsize(1100, 650)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.configure(fg_color=C["bg0"])

        self.disk_data = None
        self.disk_path = None
        self.num_sectors = 0
        self.sector_states = []
        self.scan_running = False
        self.scan_queue = queue.Queue()
        self.found_regions = []
        self.recovered_files = []
        self.map_cols = 128
        self.map_rows = 0
        self.map_img_tk = None
        self.recovered_img_tk = None
        self.map_scale = 1          # pixel scale for click-to-sector math
        self.map_render_x = 0       # where the map image is drawn on canvas
        self.map_render_y = 0
        self.current_file_type = "?" # track what type of file we're carving
        self.entropy_data = {}       # sector_num -> entropy value
        self.scan_stats = {"time": 0, "count": 0, "mb_per_sec": 0}
        self.scan_wall_start = 0    # wall clock time when scan started
        self.map_view_mode = "normal" # "normal" or "entropy"

        self._build_ui()
        self._bind_shortcuts()

    # ── UI Construction ──────────────────────────────────────────────
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=0, minsize=250)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=0, minsize=290)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self._build_titlebar()
        self._build_sidebar()
        self._build_center()
        self._build_right()

    def _build_titlebar(self):
        fr = ctk.CTkFrame(self, height=48, fg_color=C["bg1"], corner_radius=0)
        fr.grid(row=0, column=0, columnspan=3, sticky="ew")
        fr.grid_propagate(False)
        ctk.CTkLabel(fr, text="REQUIEM FS",
                     font=ctk.CTkFont("Consolas", 20, "bold"),
                     text_color=C["green"]).pack(side="left", padx=16)
        ctk.CTkLabel(fr, text="Raw Disk Forensic Recovery Visualizer",
                     font=ctk.CTkFont("Consolas", 11),
                     text_color=C["t2"]).pack(side="left", padx=8)
        self.status_lbl = ctk.CTkLabel(fr, text="IDLE",
                                       font=ctk.CTkFont("Consolas", 11),
                                       text_color=C["t3"])
        self.status_lbl.pack(side="right", padx=16)

    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, fg_color=C["bg1"], corner_radius=0,
                          border_width=1, border_color=C["border"])
        sb.grid(row=1, column=0, sticky="nsew")

        self._section(sb, "DISK OPERATIONS")
        self.load_btn = ctk.CTkButton(sb, text="Load Disk Image",
                                      font=ctk.CTkFont("Consolas", 12),
                                      fg_color=C["bg3"], hover_color=C["border"],
                                      border_width=1, border_color=C["border"],
                                      height=38, command=self.load_disk_image)
        self.load_btn.pack(padx=14, pady=4, fill="x")

        self.scan_btn = ctk.CTkButton(sb, text="Run Forensic Scan  [F5]",
                                      font=ctk.CTkFont("Consolas", 12, "bold"),
                                      fg_color="#0d2e0d", hover_color="#164016",
                                      border_width=1, border_color=C["green"],
                                      text_color=C["green"], height=42,
                                      command=self.run_scan, state="disabled")
        self.scan_btn.pack(padx=14, pady=4, fill="x")

        self.export_btn = ctk.CTkButton(sb, text="Export Report  [Ctrl+E]",
                                        font=ctk.CTkFont("Consolas", 11),
                                        fg_color="#1a1a2e", hover_color="#252545",
                                        border_width=1, border_color=C["cyan"],
                                        text_color=C["cyan"], height=34,
                                        command=self.export_report, state="disabled")
        self.export_btn.pack(padx=14, pady=(0, 4), fill="x")

        self._sep(sb)
        self._section(sb, "DISK INFO")
        info_fr = ctk.CTkFrame(sb, fg_color=C["bg2"], corner_radius=6)
        info_fr.pack(padx=14, pady=4, fill="x")
        self.info_vals = {}
        for k in ("File", "Size", "Sectors", "Status"):
            r = ctk.CTkFrame(info_fr, fg_color="transparent")
            r.pack(fill="x", padx=8, pady=1)
            ctk.CTkLabel(r, text=f"{k}:", font=ctk.CTkFont("Consolas", 10),
                         text_color=C["t3"], anchor="w", width=55).pack(side="left")
            v = ctk.CTkLabel(r, text="--", font=ctk.CTkFont("Consolas", 10),
                             text_color=C["t1"], anchor="w")
            v.pack(side="left", fill="x", expand=True)
            self.info_vals[k] = v

        self._sep(sb)
        self._section(sb, "SCAN PROGRESS")
        self.prog_bar = ctk.CTkProgressBar(sb, progress_color=C["green"],
                                           fg_color=C["bg2"], height=6)
        self.prog_bar.pack(padx=14, pady=4, fill="x")
        self.prog_bar.set(0)
        self.prog_lbl = ctk.CTkLabel(sb, text="0%",
                                     font=ctk.CTkFont("Consolas", 10),
                                     text_color=C["t3"])
        self.prog_lbl.pack(padx=14, anchor="w")

        # scan stats - shows throughput + time after each run
        stats_fr = ctk.CTkFrame(sb, fg_color=C["bg2"], corner_radius=6)
        stats_fr.pack(padx=14, pady=4, fill="x")
        self.stat_vals = {}
        for k in ("Time", "Speed", "Found"):
            r = ctk.CTkFrame(stats_fr, fg_color="transparent")
            r.pack(fill="x", padx=8, pady=1)
            ctk.CTkLabel(r, text=f"{k}:", font=ctk.CTkFont("Consolas", 9),
                         text_color=C["t3"], anchor="w", width=40).pack(side="left")
            v = ctk.CTkLabel(r, text="--", font=ctk.CTkFont("Consolas", 9),
                             text_color=C["cyan"], anchor="w")
            v.pack(side="left")
            self.stat_vals[k] = v

        self._sep(sb)
        self._section(sb, "CONSOLE")
        self.console = tk.Text(sb, bg=C["bg0"], fg=C["green"],
                               font=("Consolas", 8), relief="flat",
                               borderwidth=0, wrap="word", height=10,
                               insertbackground=C["green"], state="disabled")
        self.console.pack(padx=14, pady=4, fill="both", expand=True)
        for t, c in [("info", C["cyan"]), ("ok", C["green"]),
                     ("warn", C["yellow"]), ("err", C["red"])]:
            self.console.tag_configure(t, foreground=c)

    def _build_center(self):
        ct = ctk.CTkFrame(self, fg_color=C["bg0"], corner_radius=0)
        ct.grid(row=1, column=1, sticky="nsew")
        ct.grid_rowconfigure(0, weight=3)
        ct.grid_rowconfigure(1, weight=2)
        ct.grid_columnconfigure(0, weight=1)

        # Sector map
        mf = ctk.CTkFrame(ct, fg_color=C["bg1"], corner_radius=8,
                          border_width=1, border_color=C["border"])
        mf.grid(row=0, column=0, sticky="nsew", padx=6, pady=(6, 3))
        hdr = ctk.CTkFrame(mf, fg_color="transparent", height=28)
        hdr.pack(fill="x", padx=10, pady=(6, 0))
        ctk.CTkLabel(hdr, text="SECTOR MAP",
                     font=ctk.CTkFont("Consolas", 11, "bold"),
                     text_color=C["t2"]).pack(side="left")
        self.map_info = ctk.CTkLabel(hdr, text="",
                                     font=ctk.CTkFont("Consolas", 9),
                                     text_color=C["t3"])
        self.map_info.pack(side="right", padx=10)

        self.entropy_btn = ctk.CTkButton(hdr, text="Heatmap: OFF",
                                         font=ctk.CTkFont("Consolas", 9),
                                         width=80, height=20,
                                         fg_color=C["bg2"], hover_color=C["border"],
                                         command=self.toggle_heatmap)
        self.entropy_btn.pack(side="right")
        self.map_canvas = tk.Canvas(mf, bg=C["bg0"], highlightthickness=0)
        self.map_canvas.pack(fill="both", expand=True, padx=8, pady=8)
        # clicking a sector jumps the hex viewer to that part of the disk
        self.map_canvas.bind("<Button-1>", self._on_map_click)
        ctk.CTkLabel(mf, text="Click any sector to inspect",
                     font=ctk.CTkFont("Consolas", 8),
                     text_color=C["t3"]).pack(pady=(0, 4))

        # Hex viewer
        hf = ctk.CTkFrame(ct, fg_color=C["bg1"], corner_radius=8,
                           border_width=1, border_color=C["border"])
        hf.grid(row=1, column=0, sticky="nsew", padx=6, pady=(3, 6))
        hdr2 = ctk.CTkFrame(hf, fg_color="transparent", height=28)
        hdr2.pack(fill="x", padx=10, pady=(6, 0))
        ctk.CTkLabel(hdr2, text="HEX DUMP",
                     font=ctk.CTkFont("Consolas", 11, "bold"),
                     text_color=C["t2"]).pack(side="left")
        
        self.hex_offset_lbl = ctk.CTkLabel(hdr2, text="",
                                           font=ctk.CTkFont("Consolas", 9),
                                           text_color=C["t3"])
        self.hex_offset_lbl.pack(side="right", padx=10)

        # go to offset feature
        self.goto_entry = ctk.CTkEntry(hdr2, width=80, height=20,
                                       font=ctk.CTkFont("Consolas", 9),
                                       placeholder_text="0x...")
        self.goto_entry.pack(side="right")
        self.goto_entry.bind("<Return>", self.go_to_offset)
        ctk.CTkLabel(hdr2, text="Go to:", font=ctk.CTkFont("Consolas", 9),
                     text_color=C["t3"]).pack(side="right", padx=4)

        hex_container = ctk.CTkFrame(hf, fg_color=C["bg0"], corner_radius=4)
        hex_container.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        self.hex_text = tk.Text(hex_container, bg=C["bg0"], fg=C["t1"],
                                font=("Consolas", 10), relief="flat",
                                borderwidth=0, wrap="none", state="disabled",
                                insertbackground=C["green"],
                                selectbackground=C["border"])
        hex_sb = tk.Scrollbar(hex_container, command=self.hex_text.yview,
                              bg=C["bg2"], troughcolor=C["bg0"])
        self.hex_text.configure(yscrollcommand=hex_sb.set)
        hex_sb.pack(side="right", fill="y")
        self.hex_text.pack(side="left", fill="both", expand=True)
        for t, c in [("offset", C["cyan"]), ("zero", C["t3"]),
                     ("data", C["t1"]), ("jpeg", C["green"]),
                     ("header", C["yellow"]), ("ascii", C["t3"]),
                     ("scanhl", C["cyan"])]:
            self.hex_text.tag_configure(t, foreground=c)
        self.hex_text.tag_configure("jpeg_bg", background="#0a2a0a")
        self.hex_text.tag_configure("header_bg", background="#2a2500",
                                    foreground=C["yellow"])

    def _build_right(self):
        rp = ctk.CTkFrame(self, fg_color=C["bg1"], corner_radius=0,
                          border_width=1, border_color=C["border"])
        rp.grid(row=1, column=2, sticky="nsew")

        self._section(rp, "RECOVERED FILES")
        self.file_list = ctk.CTkTextbox(rp, font=ctk.CTkFont("Consolas", 10),
                                        fg_color=C["bg2"], height=100,
                                        text_color=C["green"],
                                        corner_radius=6)
        self.file_list.pack(padx=12, pady=4, fill="x")
        self.file_list.configure(state="disabled")

        self._sep(rp)
        self._section(rp, "IMAGE PREVIEW")
        self.preview_frame = ctk.CTkFrame(rp, fg_color=C["bg0"],
                                          corner_radius=6, height=260)
        self.preview_frame.pack(padx=12, pady=4, fill="x")
        self.preview_frame.pack_propagate(False)
        self.preview_label = ctk.CTkLabel(self.preview_frame, text="No image",
                                          font=ctk.CTkFont("Consolas", 10),
                                          text_color=C["t3"])
        self.preview_label.pack(expand=True)

        self._sep(rp)
        self._section(rp, "LEGEND")
        legend_fr = ctk.CTkFrame(rp, fg_color=C["bg2"], corner_radius=6)
        legend_fr.pack(padx=12, pady=4, fill="x")
        legends = [("Empty", SC["empty"]), ("Noise", SC["noise"]),
                   ("Scanned", SC["scanned"]), ("JPEG/PDF", SC["jpeg"]),
                   ("GIF Data", SC["gif"]), ("Header/Footer", SC["header"])]
        for name, rgb in legends:
            row = ctk.CTkFrame(legend_fr, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=1)
            hex_c = "#{:02x}{:02x}{:02x}".format(*rgb)
            swatch = tk.Canvas(row, width=12, height=12, bg=hex_c,
                               highlightthickness=1,
                               highlightbackground=C["border"])
            swatch.pack(side="left", padx=(0, 6))
            ctk.CTkLabel(row, text=name, font=ctk.CTkFont("Consolas", 10),
                         text_color=C["t2"]).pack(side="left")

        self._sep(rp)
        self._section(rp, "FINDINGS")
        self.findings_text = ctk.CTkTextbox(rp, font=ctk.CTkFont("Consolas", 9),
                                            fg_color=C["bg2"],
                                            text_color=C["yellow"],
                                            corner_radius=6)
        self.findings_text.pack(padx=12, pady=4, fill="both", expand=True)
        self.findings_text.configure(state="disabled")

    # ── Helpers ──────────────────────────────────────────────────────
    def _section(self, parent, text):
        ctk.CTkLabel(parent, text=text,
                     font=ctk.CTkFont("Consolas", 10, "bold"),
                     text_color=C["t2"]).pack(padx=14, pady=(10, 2), anchor="w")

    def _sep(self, parent):
        ctk.CTkFrame(parent, height=1, fg_color=C["border"]).pack(
            fill="x", padx=14, pady=6)

    def log(self, msg, tag="info"):
        self.console.configure(state="normal")
        self.console.insert("end", msg + "\n", tag)
        self.console.see("end")
        self.console.configure(state="disabled")

    # ── Sector Map Rendering ─────────────────────────────────────────
    def _init_sector_map(self):
        self.map_rows = math.ceil(self.num_sectors / self.map_cols)
        total = self.map_cols * self.map_rows
        self.sector_states = []
        for i in range(total):
            if i < self.num_sectors:
                off = i * SECTOR_SIZE
                chunk = self.disk_data[off:off + 16]
                is_noise = any(b != 0 for b in chunk)
                self.sector_states.append("noise" if is_noise else "empty")
            else:
                self.sector_states.append("empty")
        self._render_sector_map()

    def _render_sector_map(self):
        if self.map_rows == 0:
            return
        img = Image.new("RGB", (self.map_cols, self.map_rows))
        pixels = img.load()
        for i, state in enumerate(self.sector_states):
            x = i % self.map_cols
            y = i // self.map_cols
            
            if self.map_view_mode == "entropy" and i in self.entropy_data:
                # render heat map based on entropy
                # 0.0 -> blue, 4.0 -> green, 8.0 -> red
                val = self.entropy_data[i]
                if val < 4.0:
                    intensity = int((val / 4.0) * 255)
                    pixels[x, y] = (0, intensity, 255 - intensity)
                else:
                    intensity = int(((val - 4.0) / 4.0) * 255)
                    pixels[x, y] = (intensity, 255 - intensity, 0)
            else:
                pixels[x, y] = SC.get(state, SC["empty"])
        cw = self.map_canvas.winfo_width() or 600
        ch = self.map_canvas.winfo_height() or 400
        scale_x = max(1, cw // self.map_cols)
        scale_y = max(1, ch // self.map_rows)
        scale = max(1, min(scale_x, scale_y))
        img = img.resize((self.map_cols * scale, self.map_rows * scale),
                         Image.NEAREST)
        self.map_img_tk = ImageTk.PhotoImage(img)
        self.map_canvas.delete("all")
        self.map_canvas.create_image(cw // 2, ch // 2, image=self.map_img_tk)
        self.map_info.configure(
            text=f"{self.map_cols}x{self.map_rows}  |  {self.num_sectors} sectors")

    # ── Hex Dump Rendering ───────────────────────────────────────────
    def _render_hex_region(self, start_offset, length=2048):
        if not self.disk_data:
            return
        self.hex_text.configure(state="normal")
        self.hex_text.delete("1.0", "end")
        end = min(start_offset + length, len(self.disk_data))
        jpeg_set = set()
        header_set = set()
        for rs, re_ in self.found_regions:
            for o in range(rs, min(re_ + 1, len(self.disk_data))):
                jpeg_set.add(o)
            header_set.add(rs)
            header_set.add(rs + 1)
            if re_ > 0:
                header_set.add(re_)
                header_set.add(re_ - 1)

        for row_off in range(start_offset, end, 16):
            # Offset column
            self.hex_text.insert("end", f"{row_off:08X}  ", "offset")
            # Hex bytes
            row_bytes = self.disk_data[row_off:row_off + 16]
            for j, b in enumerate(row_bytes):
                addr = row_off + j
                if addr in header_set:
                    tag = "header_bg"
                elif addr in jpeg_set:
                    tag = "jpeg_bg"
                elif b == 0:
                    tag = "zero"
                else:
                    tag = "data"
                sep = "  " if j == 8 else " "
                self.hex_text.insert("end", f"{b:02X}", tag)
                self.hex_text.insert("end", sep)
            # ASCII column
            self.hex_text.insert("end", " |", "ascii")
            for b in row_bytes:
                ch = chr(b) if 32 <= b < 127 else "."
                self.hex_text.insert("end", ch, "ascii")
            self.hex_text.insert("end", "|\n", "ascii")

        self.hex_text.configure(state="disabled")
        self.hex_offset_lbl.configure(
            text=f"Offset: 0x{start_offset:08X} - 0x{end:08X}")

    # ── Load Disk Image ──────────────────────────────────────────────
    def load_disk_image(self):
        path = filedialog.askopenfilename(
            title="Select Raw Disk Image",
            filetypes=[("Disk Images", "*.img *.raw *.dd *.bin"),
                       ("All Files", "*.*")])
        if not path:
            return
        self.log(f"Loading: {path}", "info")
        self.status_lbl.configure(text="LOADING...", text_color=C["cyan"])
        self.update_idletasks()

        with open(path, "rb") as f:
            self.disk_data = f.read()
        self.disk_path = path
        self.num_sectors = len(self.disk_data) // SECTOR_SIZE
        self.found_regions = []
        self.recovered_files = []

        size_mb = len(self.disk_data) / (1024 * 1024)
        fname = os.path.basename(path)
        self.info_vals["File"].configure(text=fname[:20])
        self.info_vals["Size"].configure(text=f"{size_mb:.2f} MB")
        self.info_vals["Sectors"].configure(text=str(self.num_sectors))
        self.info_vals["Status"].configure(text="Loaded",
                                           text_color=C["green"])

        self._init_sector_map()
        self._render_hex_region(0, 4096)
        self.scan_btn.configure(state="normal")
        self.status_lbl.configure(text="READY", text_color=C["green"])
        self.log(f"Loaded {fname} ({size_mb:.2f} MB, {self.num_sectors} sectors)", "ok")

    # ── Run Forensic Scan ────────────────────────────────────────────
    def run_scan(self):
        if self.scan_running or not self.disk_data:
            return
        if not os.path.isfile(FORENSICS_EXE):
            self.log(f"ERROR: {FORENSICS_EXE} not found. Compile forensics.c first!", "err")
            return

        self.scan_running = True
        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.status_lbl.configure(text="SCANNING", text_color=C["yellow"])
        self.found_regions = []
        self.recovered_files = []
        self.prog_bar.set(0)

        self.file_list.configure(state="normal")
        self.file_list.delete("1.0", "end")
        self.file_list.configure(state="disabled")
        self.findings_text.configure(state="normal")
        self.findings_text.delete("1.0", "end")
        self.findings_text.configure(state="disabled")

        self.log("Starting forensic scan...", "warn")

        t = threading.Thread(target=self._scan_worker, daemon=True)
        t.start()
        self.after(50, self._process_queue)

    def _scan_worker(self):
        out_dir = os.path.join(SCRIPT_DIR, "recovered")
        os.makedirs(out_dir, exist_ok=True)
        try:
            proc = subprocess.Popen(
                [FORENSICS_EXE, self.disk_path, out_dir],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                bufsize=1, universal_newlines=True)
            for line in proc.stdout:
                line = line.strip()
                if line:
                    self.scan_queue.put(("line", line))
            proc.wait()
            for line in proc.stderr:
                line = line.strip()
                if line:
                    self.scan_queue.put(("stderr", line))
        except Exception as e:
            self.scan_queue.put(("error", str(e)))
        self.scan_queue.put(("done", None))

    def _process_queue(self):
        batch = 0
        current_start = None
        while not self.scan_queue.empty() and batch < 20:
            batch += 1
            kind, data = self.scan_queue.get_nowait()

            if kind == "line":
                if data.startswith("SCANNING:"):
                    offset = int(data.split(":")[1].strip(), 16)
                    progress = offset / len(self.disk_data) if self.disk_data else 0
                    self.prog_bar.set(min(progress, 1.0))
                    self.prog_lbl.configure(text=f"{int(progress * 100)}%")
                    sec = offset // SECTOR_SIZE
                    # Mark scanned sectors
                    for s in range(max(0, sec - 128), sec):
                        if s < len(self.sector_states):
                            if self.sector_states[s] not in ("jpeg", "header"):
                                self.sector_states[s] = "scanned"

                elif data.startswith("FOUND_TYPE:"):
                    # the C engine tells us what kind of file it found
                    self.current_file_type = data.split(":", 1)[1].strip()

                elif data.startswith("FOUND_START:"):
                    offset = int(data.split(":")[1].strip(), 16)
                    current_start = offset
                    sec = offset // SECTOR_SIZE
                    if sec < len(self.sector_states):
                        self.sector_states[sec] = "header"
                    self.log(f"{self.current_file_type} header found at 0x{offset:08X}", "ok")
                    self.findings_text.configure(state="normal")
                    self.findings_text.insert("end",
                        f"[{self.current_file_type}] Start 0x{offset:08X} (Sector {sec})\n")
                    self.findings_text.configure(state="disabled")

                elif data.startswith("ENTROPY:"):
                    # store entropy values so we can display them
                    parts = data.split()
                    if len(parts) == 3:
                        sec_num = int(parts[1])
                        ent_val = float(parts[2])
                        self.entropy_data[sec_num] = ent_val

                elif data.startswith("FOUND_END:"):
                    offset = int(data.split(":")[1].strip(), 16)
                    if current_start is not None:
                        self.found_regions.append((current_start, offset))
                        s_start = current_start // SECTOR_SIZE
                        s_end = offset // SECTOR_SIZE
                        
                        # choose color state based on file type
                        state_val = "jpeg"
                        if self.current_file_type == "GIF":
                            state_val = "gif"
                            
                        for s in range(s_start, min(s_end + 1, len(self.sector_states))):
                            self.sector_states[s] = state_val
                        if s_start < len(self.sector_states):
                            self.sector_states[s_start] = "header"
                        if s_end < len(self.sector_states):
                            self.sector_states[s_end] = "header"
                        self._render_hex_region(current_start, 2048)
                    sec = offset // SECTOR_SIZE
                    self.log(f"{self.current_file_type} footer found at 0x{offset:08X}", "ok")
                    self.findings_text.configure(state="normal")
                    sz = offset - (current_start or 0)
                    self.findings_text.insert("end",
                        f"[EOI] End   0x{offset:08X} ({sz} bytes)\n\n")
                    self.findings_text.configure(state="disabled")
                    current_start = None

                elif data.startswith("RECOVERED:"):
                    fpath = data.split(":", 1)[1].strip()
                    self.recovered_files.append(fpath)
                    self.file_list.configure(state="normal")
                    self.file_list.insert("end",
                        f"  {os.path.basename(fpath)}\n")
                    self.file_list.configure(state="disabled")
                    self.log(f"Recovered: {os.path.basename(fpath)}", "ok")
                    self._show_preview(fpath)

                elif data.startswith("SCAN_TIME:"):
                    # C engine reports how long the scan took
                    elapsed = float(data.split(":")[1].strip())
                    self.scan_stats["time"] = elapsed

                elif data.startswith("SCAN_COMPLETE:"):
                    count = int(data.split(":")[1].strip())
                    self.scan_stats["count"] = count
                    self.log(f"Scan complete. {count} file(s) recovered.", "ok")

            elif kind == "stderr":
                self.log(data, "info")

            elif kind == "error":
                self.log(f"ERROR: {data}", "err")

            elif kind == "done":
                self.scan_running = False
                self.scan_btn.configure(state="normal", text="Run Forensic Scan  [F5]")
                self.prog_bar.set(1.0)
                self.prog_lbl.configure(text="100%")
                self.status_lbl.configure(text="COMPLETE",
                                          text_color=C["green"])
                self.info_vals["Status"].configure(
                    text=f"{len(self.recovered_files)} recovered",
                    text_color=C["green"])
                # update the stats panel
                wall_elapsed = time.time() - self.scan_wall_start
                disk_mb = len(self.disk_data) / (1024 * 1024) if self.disk_data else 0
                mbps = disk_mb / wall_elapsed if wall_elapsed > 0 else 0
                self.scan_stats["mb_per_sec"] = mbps
                self.stat_vals["Time"].configure(text=f"{wall_elapsed:.2f}s")
                self.stat_vals["Speed"].configure(text=f"{mbps:.1f} MB/s")
                self.stat_vals["Found"].configure(
                    text=f"{self.scan_stats['count']} file(s)")
                # enable export now that we have results
                self.export_btn.configure(state="normal")
                self._render_sector_map()
                self.log(f"--- Done in {wall_elapsed:.2f}s at {mbps:.1f} MB/s ---", "warn")
                return

        # Periodically re-render the sector map during scan
        if batch > 0:
            self._render_sector_map()

        if self.scan_running:
            self.after(60, self._process_queue)

    # ── Image Preview ────────────────────────────────────────────────
    def _show_preview(self, path):
        try:
            img = Image.open(path)
            # Fit into preview frame
            max_w, max_h = 260, 240
            img.thumbnail((max_w, max_h), Image.LANCZOS)
            self.recovered_img_tk = ImageTk.PhotoImage(img)
            self.preview_label.configure(image=self.recovered_img_tk,
                                         text="")
        except Exception as e:
            self.preview_label.configure(text=f"Cannot preview:\n{e}",
                                         image=None)
            self.log(f"Preview error: {e}", "warn")

    # ── Keyboard Shortcuts ───────────────────────────────────────────
    def _bind_shortcuts(self):
        # Ctrl+O = load disk, F5 = scan, Ctrl+E = export
        self.bind("<Control-o>", lambda e: self.load_disk_image())
        self.bind("<F5>", lambda e: self.run_scan())
        self.bind("<Control-e>", lambda e: self.export_report())

    # ── Map Heatmap Toggle ───────────────────────────────────────────
    def toggle_heatmap(self):
        if self.map_view_mode == "normal":
            self.map_view_mode = "entropy"
            self.entropy_btn.configure(text="Heatmap: ON", fg_color=C["orange"])
        else:
            self.map_view_mode = "normal"
            self.entropy_btn.configure(text="Heatmap: OFF", fg_color=C["bg2"])
        self._render_sector_map()

    # ── Go to Offset ─────────────────────────────────────────────────
    def go_to_offset(self, event=None):
        val = self.goto_entry.get().strip()
        if not val or not self.disk_data:
            return
        
        try:
            # handle hex or decimal
            if val.lower().startswith("0x"):
                offset = int(val, 16)
            else:
                offset = int(val)
                
            # snap to 16-byte boundary for hex viewer alignment
            offset = offset - (offset % 16)
            
            if offset >= len(self.disk_data):
                offset = len(self.disk_data) - 1024
                
            self._render_hex_region(offset, 4096)
            self.log(f"Jumped to offset 0x{offset:08X}", "info")
            
        except ValueError:
            self.log(f"Invalid offset: {val}", "err")

    # ── Sector Map Click -> Jump Hex View ────────────────────────────
    def _on_map_click(self, event):
        """Click a pixel on the sector map to jump the hex dump there."""
        if not self.disk_data or self.map_scale == 0:
            return

        # figure out which sector was clicked
        # the image is centered on the canvas so we need to account for offset
        cw = self.map_canvas.winfo_width()
        ch = self.map_canvas.winfo_height()
        img_w = self.map_cols * self.map_scale
        img_h = self.map_rows * self.map_scale
        x_off = (cw - img_w) // 2
        y_off = (ch - img_h) // 2

        px = (event.x - x_off) // self.map_scale
        py = (event.y - y_off) // self.map_scale

        if 0 <= px < self.map_cols and 0 <= py < self.map_rows:
            sector = py * self.map_cols + px
            byte_offset = sector * SECTOR_SIZE
            if byte_offset < len(self.disk_data):
                self._render_hex_region(byte_offset, 4096)
                self.log(f"Jumped to sector {sector} (0x{byte_offset:08X})", "info")

    # ── Export Report ────────────────────────────────────────────────
    def export_report(self):
        """Save a JSON + plain text forensic report of everything found."""
        if not self.found_regions and not self.recovered_files:
            messagebox.showinfo("Export Report", "Nothing to export yet. Run a scan first.")
            return

        save_path = filedialog.asksaveasfilename(
            title="Save Forensic Report",
            defaultextension=".json",
            filetypes=[("JSON Report", "*.json"), ("Text Report", "*.txt"),
                       ("All Files", "*.*")])
        if not save_path:
            return

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # build the report data
        report = {
            "tool": "RequiemFS",
            "timestamp": timestamp,
            "disk_image": self.disk_path,
            "disk_size_mb": round(len(self.disk_data) / (1024*1024), 2) if self.disk_data else 0,
            "total_sectors": self.num_sectors,
            "scan_time_sec": round(self.scan_stats.get("time", 0), 3),
            "throughput_mb_per_sec": round(self.scan_stats.get("mb_per_sec", 0), 2),
            "recovered_files": [
                {
                    "filename": os.path.basename(f),
                    "path": f,
                    "size_bytes": os.path.getsize(f) if os.path.exists(f) else 0
                }
                for f in self.recovered_files
            ],
            "found_regions": [
                {
                    "start_offset": hex(s),
                    "end_offset": hex(e),
                    "start_sector": s // SECTOR_SIZE,
                    "end_sector": e // SECTOR_SIZE,
                    "size_bytes": e - s
                }
                for s, e in self.found_regions
            ],
            "entropy_samples": [
                {"sector": k, "entropy": round(v, 4)}
                for k, v in sorted(self.entropy_data.items())
            ]
        }

        if save_path.endswith(".txt"):
            # plain text version - easier to read for humans
            with open(save_path, "w") as f:
                f.write("=" * 60 + "\n")
                f.write("  RequiemFS - Forensic Recovery Report\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Generated : {timestamp}\n")
                f.write(f"Disk Image: {self.disk_path}\n")
                f.write(f"Disk Size : {report['disk_size_mb']} MB\n")
                f.write(f"Sectors   : {self.num_sectors}\n")
                f.write(f"Scan Time : {report['scan_time_sec']}s ({report['throughput_mb_per_sec']} MB/s)\n")
                f.write(f"\n--- RECOVERED FILES ({len(self.recovered_files)}) ---\n")
                for rf in report["recovered_files"]:
                    f.write(f"  {rf['filename']}  ({rf['size_bytes']} bytes)\n")
                f.write(f"\n--- CARVED REGIONS ({len(self.found_regions)}) ---\n")
                for reg in report["found_regions"]:
                    f.write(f"  {reg['start_offset']} -> {reg['end_offset']}  "
                            f"Sectors {reg['start_sector']}-{reg['end_sector']}  "
                            f"({reg['size_bytes']} bytes)\n")
        else:
            with open(save_path, "w") as f:
                json.dump(report, f, indent=2)

        self.log(f"Report saved: {os.path.basename(save_path)}", "ok")
        messagebox.showinfo("Export Report",
                            f"Saved to:\n{save_path}")

    # override run_scan to capture wall time
    def run_scan(self):
        if self.scan_running or not self.disk_data:
            return
        if not os.path.isfile(FORENSICS_EXE):
            self.log(f"ERROR: {FORENSICS_EXE} not found. Compile forensics.c first!", "err")
            return

        self.scan_running = True
        self.scan_wall_start = time.time()  # start the wall clock
        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.status_lbl.configure(text="SCANNING", text_color=C["yellow"])
        self.found_regions = []
        self.recovered_files = []
        self.entropy_data = {}
        self.current_file_type = "?"
        self.scan_stats = {"time": 0, "count": 0, "mb_per_sec": 0}
        self.prog_bar.set(0)

        self.file_list.configure(state="normal")
        self.file_list.delete("1.0", "end")
        self.file_list.configure(state="disabled")
        self.findings_text.configure(state="normal")
        self.findings_text.delete("1.0", "end")
        self.findings_text.configure(state="disabled")

        for k in ("Time", "Speed", "Found"):
            self.stat_vals[k].configure(text="--")

        self.log("Starting forensic scan...", "warn")

        t = threading.Thread(target=self._scan_worker, daemon=True)
        t.start()
        self.after(50, self._process_queue)

    # need to override _render_sector_map to store scale for click math
    def _render_sector_map(self):
        if self.map_rows == 0:
            return
        img = Image.new("RGB", (self.map_cols, self.map_rows))
        pixels = img.load()
        for i, state in enumerate(self.sector_states):
            x = i % self.map_cols
            y = i // self.map_cols
            pixels[x, y] = SC.get(state, SC["empty"])
        cw = self.map_canvas.winfo_width() or 600
        ch = self.map_canvas.winfo_height() or 400
        scale_x = max(1, cw // self.map_cols)
        scale_y = max(1, ch // self.map_rows)
        self.map_scale = max(1, min(scale_x, scale_y))  # store for click math
        img = img.resize((self.map_cols * self.map_scale, self.map_rows * self.map_scale),
                         Image.NEAREST)
        self.map_img_tk = ImageTk.PhotoImage(img)
        self.map_canvas.delete("all")
        self.map_canvas.create_image(cw // 2, ch // 2, image=self.map_img_tk)
        self.map_info.configure(
            text=f"{self.map_cols}x{self.map_rows}  |  {self.num_sectors} sectors")


if __name__ == "__main__":
    app = RequiemFSApp()
    app.mainloop()

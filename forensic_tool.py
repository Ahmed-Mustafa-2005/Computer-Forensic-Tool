"""
forensic_tool.py

GUI front-end for the Disk & Registry Forensic Analysis Tool.

All heavy lifting lives in forensic_backend.py; this file is a thin
Tkinter layer that:
  - collects examiner/case info and informed consent before anything runs
  - runs long operations on background threads, cancellably, so the UI
    never freezes and never traps the user in a stuck dialog
    - offers a simple "Open Evidence" flow that shows filesystem metadata for
        any selected file, and parses supported disk-image files when possible
  - lets the user search the results pane and verify a file's hash on demand
  - exports everything collected, plus the chain-of-custody log, as an
    HTML report with a plain-language summary up top
"""

import os
import sys
import json
import queue
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog

import forensic_backend as backend


GETTING_STARTED = """Getting started
================
1. Scan Local Drive(s)  — inventory a local drive: space, file system, file counts and types.
2. Open Evidence         — select any file to view its filesystem metadata.
                            Supported disk images are also parsed for partitions, files,
                            deleted entries, and extension/content mismatches.
3. Scan Registry         — collect system info, UI settings, and installed software.
4. Export Report         — save everything collected this session as one HTML report.

Every action here is written to the chain-of-custody log automatically
(Tools -> View Chain of Custody). Long-running scans can be cancelled from
their progress window at any time.
"""


# ---------------------------------------------------------------------------
# Small reusable widgets
# ---------------------------------------------------------------------------
class Tooltip:
    """Minimal hover tooltip — no external dependency needed for this."""

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _event=None):
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 10
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tip, text=self.text, bg="#333", fg="white", relief="solid",
                borderwidth=1, padx=6, pady=3, wraplength=280, justify="left").pack()

    def _hide(self, _event=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


# ---------------------------------------------------------------------------
# Consent / case-setup dialog — shown before any data collection happens
# ---------------------------------------------------------------------------
class ConsentDialog(tk.Toplevel):
    DISCLOSURE = (
        "This tool can read and record, on the machine or image you point it at:\n\n"
        "  • Directory and file listings, file counts and types\n"
        "  • Installed-software and system information from the Windows Registry\n"
        "  • Disk / volume metadata (file system, capacity, free space)\n"
        "  • The content of any disk image you analyze, including files that have\n"
        "    been deleted but are still recoverable\n\n"
        "Everything collected is written to a local debug log and, if you\n"
        "export one, an HTML report. Only run this against systems and\n"
        "images you are authorized to examine."
    )

    def __init__(self, parent):
        super().__init__(parent)
        self.title("Forensic Analysis Tool — Case Setup")
        self.geometry("520x440")
        self.resizable(False, False)
        self.configure(bg="black")
        self.result = None  # (examiner, case_number) or None if cancelled

        self.protocol("WM_DELETE_WINDOW", self._cancel)

        tk.Label(self, text="Before you begin", bg="black", fg="white",
                font=("Segoe UI", 12, "bold")).pack(pady=(15, 5))
        tk.Message(self, text=self.DISCLOSURE, width=470, bg="black", fg="white",
                  justify="left").pack(padx=15, pady=5)

        form = tk.Frame(self, bg="black")
        form.pack(pady=10, fill="x", padx=15)

        tk.Label(form, text="Examiner name:", bg="black", fg="white").grid(row=0, column=0, sticky="w", pady=3)
        self.examiner_var = tk.StringVar()
        tk.Entry(form, textvariable=self.examiner_var, width=35).grid(row=0, column=1, pady=3)

        tk.Label(form, text="Case number:", bg="black", fg="white").grid(row=1, column=0, sticky="w", pady=3)
        self.case_var = tk.StringVar()
        tk.Entry(form, textvariable=self.case_var, width=35).grid(row=1, column=1, pady=3)

        self.consent_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            self, text="I have read the above and am authorized to examine this system/image.",
            variable=self.consent_var, bg="black", fg="white", selectcolor="black",
            wraplength=470, justify="left", command=self._update_button_state,
        ).pack(padx=15, pady=10)

        btn_frame = tk.Frame(self, bg="black")
        btn_frame.pack(pady=10)
        self.continue_btn = tk.Button(btn_frame, text="Continue", state="disabled",
                                      command=self._accept, bg="black", fg="white")
        self.continue_btn.pack(side="left", padx=5)
        tk.Button(btn_frame, text="Cancel", command=self._cancel, bg="black", fg="white").pack(side="left", padx=5)

        for var in (self.examiner_var, self.case_var):
            var.trace_add("write", lambda *a: self._update_button_state())

        self.transient(parent)
        self.grab_set()
        self.wait_window(self)

    def _update_button_state(self):
        ok = bool(self.examiner_var.get().strip()) and bool(self.case_var.get().strip()) and self.consent_var.get()
        self.continue_btn.config(state="normal" if ok else "disabled")

    def _accept(self):
        self.result = (self.examiner_var.get().strip(), self.case_var.get().strip())
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()


# ---------------------------------------------------------------------------
# Evidence source chooser removed: Open Evidence selects one file directly.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Hash verification dialog
# ---------------------------------------------------------------------------
class VerifyHashDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Verify File Hash")
        self.geometry("480x180")
        self.resizable(False, False)
        self.configure(bg="black")
        self.result = None  # (file_path, expected_hash) or None

        self.protocol("WM_DELETE_WINDOW", self.destroy)

        self.path_var = tk.StringVar()
        row = tk.Frame(self, bg="black")
        row.pack(fill="x", padx=15, pady=(15, 5))
        tk.Label(row, text="File:", bg="black", fg="white", width=8, anchor="w").pack(side="left")
        tk.Entry(row, textvariable=self.path_var, width=40).pack(side="left", padx=5)
        tk.Button(row, text="Browse…", bg="black", fg="white", command=self._browse).pack(side="left")

        row2 = tk.Frame(self, bg="black")
        row2.pack(fill="x", padx=15, pady=5)
        tk.Label(row2, text="Expected hash\n(MD5/SHA1/SHA256):", bg="black", fg="white",
                justify="left").pack(side="left")
        self.hash_var = tk.StringVar()
        tk.Entry(row2, textvariable=self.hash_var, width=40).pack(side="left", padx=5)

        btns = tk.Frame(self, bg="black")
        btns.pack(pady=15)
        tk.Button(btns, text="Verify", bg="black", fg="white", command=self._accept).pack(side="left", padx=5)
        tk.Button(btns, text="Cancel", bg="black", fg="white", command=self.destroy).pack(side="left", padx=5)

        self.transient(parent)
        self.grab_set()
        self.wait_window(self)

    def _browse(self):
        path = filedialog.askopenfilename(title="Select File to Verify")
        if path:
            self.path_var.set(path)

    def _accept(self):
        if not self.path_var.get().strip() or not self.hash_var.get().strip():
            messagebox.showwarning("Missing info", "Please provide both a file and an expected hash.")
            return
        self.result = (self.path_var.get().strip(), self.hash_var.get().strip())
        self.destroy()


# ---------------------------------------------------------------------------
# Progress dialog + cancellable background-job runner
# ---------------------------------------------------------------------------
class ProgressDialog(tk.Toplevel):
    def __init__(self, parent, title, determinate=True, cancel_event=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("420x140")
        self.resizable(False, False)
        self.configure(bg="black")
        self.protocol("WM_DELETE_WINDOW", lambda: None)  # only the Cancel button may close this

        self.label_var = tk.StringVar(value="Working…")
        tk.Label(self, textvariable=self.label_var, bg="black", fg="white").pack(pady=(15, 8))

        mode = "determinate" if determinate else "indeterminate"
        self.bar = ttk.Progressbar(self, mode=mode, length=370, maximum=100)
        self.bar.pack(pady=5)
        if not determinate:
            self.bar.start(15)

        self.cancel_event = cancel_event
        if cancel_event is not None:
            self.cancel_btn = tk.Button(self, text="Cancel", bg="black", fg="white", command=self._cancel)
            self.cancel_btn.pack(pady=(8, 0))

        self.transient(parent)
        self.grab_set()
        self.update_idletasks()

    def _cancel(self):
        self.cancel_event.set()
        self.cancel_btn.config(state="disabled")
        self.set_label("Cancelling… (finishing current step)")

    def set_progress(self, pct):
        self.bar["value"] = pct

    def set_label(self, text):
        self.label_var.set(text)


class BackgroundJob:
    """
    Runs work_fn(progress_cb, cancel_event) on a background thread and reports
    back to the GUI thread safely via polling. `total` passed to progress_cb
    may be None for indeterminate progress. If work_fn raises
    backend.OperationCancelled, on_cancelled is called instead of on_error.
    """

    def __init__(self, root, work_fn, on_success, on_error, dialog_title="Working",
                determinate=True, cancellable=True, on_cancelled=None):
        self.root = root
        self.on_success = on_success
        self.on_error = on_error
        self.on_cancelled = on_cancelled or (lambda msg: messagebox.showinfo("Cancelled", msg))
        self.progress_queue = queue.Queue()
        self.result_box = {}
        self.cancel_event = threading.Event()

        self.dialog = ProgressDialog(root, dialog_title, determinate=determinate,
                                     cancel_event=self.cancel_event if cancellable else None)

        def progress_cb(current, total=None, label=None):
            self.progress_queue.put((current, total, label))

        def worker():
            try:
                result = work_fn(progress_cb, self.cancel_event)
                self.result_box["status"] = "ok"
                self.result_box["result"] = result
            except backend.OperationCancelled as e:
                self.result_box["status"] = "cancelled"
                self.result_box["message"] = str(e)
            except Exception as e:
                backend.logger.exception("Background job failed")
                self.result_box["status"] = "error"
                self.result_box["error"] = str(e)

        threading.Thread(target=worker, daemon=True).start()
        self.root.after(100, self._poll)

    def _poll(self):
        while True:
            try:
                current, total, label = self.progress_queue.get_nowait()
            except queue.Empty:
                break
            if total:
                self.dialog.set_progress(min(100, int(current / total * 100)))
            if label:
                self.dialog.set_label(label)

        status = self.result_box.get("status")
        if status:
            self.dialog.destroy()
            if status == "ok":
                self.on_success(self.result_box["result"])
            elif status == "cancelled":
                self.on_cancelled(self.result_box["message"])
            else:
                self.on_error(self.result_box["error"])
            return

        self.root.after(100, self._poll)


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------
class ForensicApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Forensic Analysis Tool")
        self.window.configure(bg="black")
        self.window.geometry("880x680")

        consent = ConsentDialog(self.window)
        if not consent.result:
            self.window.destroy()
            sys.exit(0)
        examiner, case_number = consent.result
        self.coc = backend.ChainOfCustody(examiner, case_number)

        self.session_data = {
            "drives": {}, "evidence_metadata": None, "image_analysis": None, "registry_info": None
        }
        self._busy = False
        self.buttons = []

        self._build_menu()
        self._build_ui()
        self._append(GETTING_STARTED)

    # ---- Menu ---------------------------------------------------------------
    def _build_menu(self):
        menubar = tk.Menu(self.window)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Report…", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.window.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Calculate File Hash…", command=self.calculate_hash_action)
        tools_menu.add_command(label="Verify File Hash…", command=self.verify_hash_action)
        tools_menu.add_command(label="Open Logs Folder", command=self.open_logs_folder)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Chain of Custody Log", command=self.view_coc)
        view_menu.add_command(label="Clear Results Pane", command=lambda: self.result_text.delete(1.0, tk.END))
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Getting Started", command=lambda: self._append("\n" + GETTING_STARTED))
        menubar.add_cascade(label="Help", menu=help_menu)

        self.window.config(menu=menubar)

    # ---- UI construction ------------------------------------------------------
    def _build_ui(self):
        top = tk.Frame(self.window, bg="black")
        top.pack(fill="x", pady=5)

        def add_btn(parent, text, command, tooltip=None):
            b = tk.Button(parent, text=text, command=command, bg="black", fg="white")
            b.pack(side="left", padx=5)
            self.buttons.append(b)
            if tooltip:
                Tooltip(b, tooltip)
            return b

        add_btn(top, "Scan Local Drive(s)", self.show_drive_buttons,
               "Inventory a local drive: space, file system, file counts and types.")
        add_btn(top, "Open Evidence", self.open_evidence_action,
               "Analyze a disk image — a single file or a set of split segments.")
        add_btn(top, "Scan Registry", self.registry_info_action,
               "Collect system info, UI settings, and installed software from the registry.")
        add_btn(top, "Export Report", self.export_report,
               "Save everything collected this session as one HTML report.")

        self.drive_frame = tk.Frame(self.window, bg="black")
        self.drive_frame.pack(fill="x", pady=5)

        search_frame = tk.Frame(self.window, bg="black")
        search_frame.pack(fill="x", pady=5)
        tk.Label(search_frame, text="Search:", bg="black", fg="white").pack(side="left", padx=(5, 2))
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side="left", padx=2)
        search_entry.bind("<Return>", lambda e: self.find_next())
        tk.Button(search_frame, text="Find All", command=self.find_next, bg="black", fg="white").pack(side="left", padx=5)
        tk.Button(search_frame, text="Clear", command=self.clear_search, bg="black", fg="white").pack(side="left", padx=2)

        self.result_text = scrolledtext.ScrolledText(self.window, width=100, height=32, bg="black", fg="white")
        self.result_text.pack(pady=10, padx=10, fill="both", expand=True)
        self.result_text.tag_config("search_hit", background="#553300", foreground="white")

        self.status_var = tk.StringVar(
            value=f"Case {self.coc.case_number} — Examiner {self.coc.examiner} — "
                 f"Debug log: {backend.DEBUG_LOG_PATH}"
        )
        tk.Label(self.window, textvariable=self.status_var, bg="black", fg="#888", anchor="w").pack(
            fill="x", padx=10, pady=(0, 5)
        )

    def _set_busy(self, busy):
        self._busy = busy
        state = "disabled" if busy else "normal"
        for b in self.buttons:
            b.config(state=state)

    def _append(self, text):
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)

    # ---- Search ----------------------------------------------------------------
    def find_next(self):
        term = self.search_var.get()
        self.result_text.tag_remove("search_hit", "1.0", tk.END)
        if not term:
            return
        start = "1.0"
        count = tk.IntVar()
        first_match = None
        while True:
            pos = self.result_text.search(term, start, stopindex=tk.END, count=count, nocase=True)
            if not pos:
                break
            end = f"{pos}+{count.get()}c"
            self.result_text.tag_add("search_hit", pos, end)
            if first_match is None:
                first_match = pos
            start = end
        if first_match:
            self.result_text.see(first_match)
        else:
            messagebox.showinfo("Search", f"'{term}' not found.")

    def clear_search(self):
        self.search_var.set("")
        self.result_text.tag_remove("search_hit", "1.0", tk.END)

    # ---- Drive analysis ----------------------------------------------------------
    def show_drive_buttons(self):
        for w in self.drive_frame.winfo_children():
            w.destroy()
        drives = backend.list_logical_drives()
        if not drives:
            tk.Label(self.drive_frame, text="No logical drives detected.", bg="black", fg="white").pack()
            return
        for d in drives:
            tk.Button(self.drive_frame, text=f"Analyze {d}", bg="black", fg="white",
                     command=lambda d=d: self.analyze_single_drive(d)).pack(side="left", padx=3)
        tk.Button(self.drive_frame, text="Analyze All", bg="black", fg="white",
                 command=self.analyze_all_drives_action).pack(side="left", padx=3)

    def analyze_single_drive(self, drive_path):
        if self._busy:
            return
        self._set_busy(True)

        def work(progress_cb, cancel_event):
            progress_cb(0, None, f"Analyzing {drive_path}…")
            info, error = backend.analyze_drive(drive_path, coc=self.coc, cancel_event=cancel_event,
                                                progress_cb=progress_cb)
            if error:
                raise RuntimeError(error)
            return {drive_path: info}

        def on_success(result):
            self._set_busy(False)
            self.session_data["drives"].update(result)
            for drive, info in result.items():
                self._append(f"Information for {drive}:\n{json.dumps(info, indent=2)}\n\n")

        def on_error(err):
            self._set_busy(False)
            messagebox.showerror("Error", err)

        def on_cancelled(msg):
            self._set_busy(False)
            self._append(f"[Cancelled] {msg}\n\n")

        BackgroundJob(self.window, work, on_success, on_error,
                     dialog_title=f"Analyzing {drive_path}", determinate=False, on_cancelled=on_cancelled)

    def analyze_all_drives_action(self):
        if self._busy:
            return
        self._set_busy(True)

        def work(progress_cb, cancel_event):
            drives = backend.list_logical_drives()
            results = {}
            for i, d in enumerate(drives, 1):
                progress_cb(i - 1, len(drives), f"Analyzing {d}…")
                info, error = backend.analyze_drive(d, coc=self.coc, cancel_event=cancel_event)
                results[d] = info if not error else {"error": error}
                progress_cb(i, len(drives))
            return results

        def on_success(results):
            self._set_busy(False)
            self.session_data["drives"].update(results)
            for drive, info in results.items():
                self._append(f"Information for {drive}:\n{json.dumps(info, indent=2)}\n\n")

        def on_error(err):
            self._set_busy(False)
            messagebox.showerror("Error", err)

        def on_cancelled(msg):
            self._set_busy(False)
            self._append(f"[Cancelled] {msg}\n\n")

        BackgroundJob(self.window, work, on_success, on_error,
                     dialog_title="Analyzing all drives", determinate=True, on_cancelled=on_cancelled)

    # ---- Open Evidence ------------------------------------------------------------
    def open_evidence_action(self):
        if self._busy:
            return

        evidence_path = filedialog.askopenfilename(
            title="Select Evidence File",
            filetypes=[("All files", "*.*")],
        )
        if evidence_path:
            self.coc.log_event("EVIDENCE_SELECTED", f"Evidence file selected: {evidence_path}")
            self._run_file_analysis(evidence_path)

    def _run_file_analysis(self, evidence_path):
        self._set_busy(True)

        def work(progress_cb, cancel_event):
            metadata, metadata_error = backend.analyze_file_metadata(
                evidence_path, coc=self.coc, progress_cb=progress_cb, cancel_event=cancel_event
            )
            if metadata_error:
                raise RuntimeError(metadata_error)

            image_extensions = {".dd", ".img", ".raw", ".001", ".e01", ".ex01", ".s01", ".l01"}
            is_image = metadata["file_extension"] in image_extensions or backend.is_probably_ewf(evidence_path)
            analysis = None
            if is_image:
                analysis, analyze_error = backend.analyze_image(
                    evidence_path, coc=self.coc, progress_cb=progress_cb, cancel_event=cancel_event,
                    calculate_hashes=False,
                )
                if analyze_error:
                    raise RuntimeError(analyze_error)
            return {"metadata": metadata, "analysis": analysis}

        def on_success(payload):
            self._set_busy(False)
            self.session_data["evidence_metadata"] = payload["metadata"]
            self.session_data["image_analysis"] = payload["analysis"]
            self._append(f"Evidence metadata:\n{json.dumps(payload['metadata'], indent=2)}\n\n")
            if payload["analysis"]:
                self._append(f"Disk image analysis:\n{json.dumps(payload['analysis'], indent=2)}\n\n")

            if messagebox.askyesno("Save JSON", "Save this analysis to a JSON file as well?"):
                json_path = filedialog.asksaveasfilename(defaultextension=".json", title="Save Image Info As JSON")
                if json_path:
                    err = backend.save_to_json(payload["analysis"], json_path)
                    if err:
                        messagebox.showerror("Error", err)
                    else:
                        messagebox.showinfo("Success", f"Analysis saved to {json_path}")

        def on_error(err):
            self._set_busy(False)
            messagebox.showerror("Error", err)

        def on_cancelled(msg):
            self._set_busy(False)
            self._append(f"[Cancelled] {msg}\n\n")

        BackgroundJob(self.window, work, on_success, on_error,
                     dialog_title="Analyzing image", determinate=True, on_cancelled=on_cancelled)

    # ---- Registry -------------------------------------------------------------------
    def registry_info_action(self):
        if self._busy:
            return
        self._set_busy(True)

        def work(progress_cb, cancel_event):
            progress_cb(0, None, "Reading registry…")
            return backend.retrieve_registry_info(coc=self.coc)

        def on_success(info):
            self._set_busy(False)
            self.session_data["registry_info"] = info
            self.result_text.delete(1.0, tk.END)
            self._append(info)

        def on_error(err):
            self._set_busy(False)
            messagebox.showerror("Error", err)

        BackgroundJob(self.window, work, on_success, on_error,
                     dialog_title="Reading registry", determinate=False, cancellable=False)

    # ---- Hash verification ------------------------------------------------------------
    def calculate_hash_action(self):
        if self._busy:
            return
        file_path = filedialog.askopenfilename(title="Select File to Hash")
        if not file_path:
            return
        reference_hash = simpledialog.askstring(
            "Optional Integrity Check",
            "Enter a known MD5, SHA-1, or SHA-256 hash to compare\n"
            "against this file, or leave it blank to calculate only:",
            parent=self.window,
        )
        if reference_hash is None:
            reference_hash = ""
        self.coc.log_event("HASH_FILE_SELECTED", f"File selected for hash calculation: {file_path}")
        self._set_busy(True)

        def work(progress_cb, cancel_event):
            def hash_progress(current, total):
                progress_cb(current, total, "Calculating MD5, SHA-1, and SHA-256…")

            result, error = backend.calculate_file_hash(
                file_path, expected_hash=reference_hash, coc=self.coc,
                progress_cb=hash_progress, cancel_event=cancel_event,
            )
            if error:
                raise RuntimeError(error)
            return result

        def on_success(result):
            self._set_busy(False)
            self._append(f"Calculated hashes for {file_path}:\n{json.dumps(result, indent=2)}\n\n")
            integrity = result["integrity"]
            integrity_text = integrity["status"]
            if integrity["status"] in ("MATCH", "MISMATCH"):
                integrity_text += f" ({integrity['algorithm'].upper()})"
            messagebox.showinfo(
                "File Hashes and Integrity",
                f"SHA-256:\n{result['algorithms']['sha256']}\n\n"
                f"SHA-1:\n{result['algorithms']['sha1']}\n\n"
                f"MD5:\n{result['algorithms']['md5']}\n\n"
                f"Integrity: {integrity_text}",
            )

        def on_error(err):
            self._set_busy(False)
            messagebox.showerror("Error", err)

        def on_cancelled(msg):
            self._set_busy(False)
            self._append(f"[Cancelled] {msg}\n\n")

        BackgroundJob(self.window, work, on_success, on_error,
                     dialog_title="Calculating file hashes", determinate=True,
                     on_cancelled=on_cancelled)

    def verify_hash_action(self):
        if self._busy:
            return
        dialog = VerifyHashDialog(self.window)
        if not dialog.result:
            return
        file_path, expected_hash = dialog.result

        self._set_busy(True)

        def work(progress_cb, cancel_event):
            def hash_progress(current, total):
                progress_cb(current, total, "Hashing file…")

            result, error = backend.verify_file_hash(file_path, expected_hash, coc=self.coc,
                                                      progress_cb=hash_progress, cancel_event=cancel_event)
            if error:
                raise RuntimeError(error)
            return result

        def on_success(result):
            self._set_busy(False)
            if result["match"]:
                messagebox.showinfo("Hash Verified", f"MATCH — {result['algorithm'].upper()} hash confirmed.")
            else:
                messagebox.showwarning(
                    "Hash Mismatch",
                    f"MISMATCH!\nExpected: {result['expected']}\nActual:   {result['actual']}"
                )
            self._append(f"Hash verification for {file_path}:\n{json.dumps(result, indent=2)}\n\n")

        def on_error(err):
            self._set_busy(False)
            messagebox.showerror("Error", err)

        def on_cancelled(msg):
            self._set_busy(False)
            self._append(f"[Cancelled] {msg}\n\n")

        BackgroundJob(self.window, work, on_success, on_error,
                     dialog_title="Verifying hash", determinate=True, on_cancelled=on_cancelled)

    # ---- Report / chain of custody / logs -----------------------------------------------
    def export_report(self):
        output_path = filedialog.asksaveasfilename(defaultextension=".html", title="Save Report As")
        if not output_path:
            return
        try:
            backend.generate_html_report(self.coc, self.session_data, output_path)
            messagebox.showinfo("Success", f"Report saved to {output_path}")
        except Exception as e:
            backend.logger.exception("Error generating report")
            messagebox.showerror("Error", f"Failed to generate report: {e}")

    def view_coc(self):
        self.result_text.delete(1.0, tk.END)
        self._append(self.coc.as_text())

    def open_logs_folder(self):
        try:
            if sys.platform.startswith("win"):
                os.startfile(backend.LOG_DIR)  # noqa: S606 - Windows-only tool by design
            else:
                subprocess.Popen(["xdg-open", backend.LOG_DIR])
        except Exception as e:
            messagebox.showinfo("Logs Folder", f"Logs are stored at:\n{backend.LOG_DIR}\n\n({e})")

    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    ForensicApp().run()

from __future__ import annotations

import queue
import shutil
import tempfile
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from main import (
    DEFAULT_CIPHER,
    LOCKED_SUFFIX,
    LockError,
    PasswordPolicy,
    SUPPORTED_CIPHERS,
    V2_FORMAT_VERSION,
    created_time,
    decrypt_for_open,
    default_locked_path,
    detect_file_version,
    lock_path,
    open_with_default_app,
    read_locked_metadata,
    unlock_path,
    validate_password_policy,
)


APP_NAME = "Python File Locker"


class PasswordDialog(simpledialog.Dialog):
    def __init__(self, parent: tk.Misc, title: str, confirm: bool = False, policy: PasswordPolicy | None = None):
        self.confirm = confirm
        self.policy = policy
        self.password_var = tk.StringVar()
        self.confirm_var = tk.StringVar()
        super().__init__(parent, title)

    def body(self, master: tk.Frame):
        ttk.Label(master, text="Password").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        password_entry = ttk.Entry(master, textvariable=self.password_var, show="*", width=36)
        password_entry.grid(row=0, column=1, sticky="ew", padx=6, pady=6)

        if self.confirm:
            ttk.Label(master, text="Confirm").grid(row=1, column=0, sticky="w", padx=6, pady=6)
            ttk.Entry(master, textvariable=self.confirm_var, show="*", width=36).grid(
                row=1,
                column=1,
                sticky="ew",
                padx=6,
                pady=6,
            )

        master.columnconfigure(1, weight=1)
        return password_entry

    def validate(self) -> bool:
        password = self.password_var.get()
        if not password:
            messagebox.showerror(APP_NAME, "Password cannot be empty.", parent=self)
            return False
        if self.policy is not None:
            try:
                validate_password_policy(password, self.policy)
            except LockError as exc:
                messagebox.showerror(APP_NAME, str(exc), parent=self)
                return False
        if self.confirm and password != self.confirm_var.get():
            messagebox.showerror(APP_NAME, "Passwords do not match.", parent=self)
            return False
        self.result = password
        return True


class LockerApp(ttk.Frame):
    def __init__(self, master: tk.Tk):
        super().__init__(master, padding=16)
        self.master = master
        self.task_queue: queue.Queue = queue.Queue()
        self.busy = False
        self.temp_dirs: list[Path] = []

        self.lock_source_var = tk.StringVar()
        self.lock_output_var = tk.StringVar()
        self.lock_force_var = tk.BooleanVar(value=False)
        self.lock_key_file_var = tk.StringVar()
        self.lock_cipher_var = tk.StringVar(value=DEFAULT_CIPHER)
        self.lock_compress_var = tk.BooleanVar(value=False)
        self.lock_secure_delete_var = tk.BooleanVar(value=False)

        self.open_locked_var = tk.StringVar()
        self.open_key_file_var = tk.StringVar()

        self.unlock_locked_var = tk.StringVar()
        self.unlock_output_var = tk.StringVar()
        self.unlock_force_var = tk.BooleanVar(value=False)
        self.unlock_key_file_var = tk.StringVar()

        self.info_locked_var = tk.StringVar()
        self.info_key_file_var = tk.StringVar()

        self.status_var = tk.StringVar(value="Ready")

        self._build_ui()
        self.after(100, self._process_task_queue)

    def _build_ui(self) -> None:
        self.grid(row=0, column=0, sticky="nsew")
        self.master.rowconfigure(0, weight=1)
        self.master.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)

        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text=APP_NAME, font=("Segoe UI", 18, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(header, text="Lock files, images, videos, and folders with a password.").grid(
            row=1,
            column=0,
            sticky="w",
            pady=(2, 0),
        )

        notebook = ttk.Notebook(self)
        notebook.grid(row=1, column=0, sticky="nsew")

        notebook.add(self._build_lock_tab(notebook), text="Lock")
        notebook.add(self._build_open_tab(notebook), text="Open")
        notebook.add(self._build_unlock_tab(notebook), text="Unlock")
        notebook.add(self._build_info_tab(notebook), text="Info")

        footer = ttk.Frame(self)
        footer.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        footer.columnconfigure(0, weight=1)
        ttk.Label(footer, textvariable=self.status_var).grid(row=0, column=0, sticky="w")
        self.progress = ttk.Progressbar(footer, mode="indeterminate", length=160)
        self.progress.grid(row=0, column=1, sticky="e")

        log_frame = ttk.LabelFrame(self, text="Activity")
        log_frame.grid(row=3, column=0, sticky="nsew", pady=(12, 0))
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        self.log_text = tk.Text(log_frame, height=6, wrap="word", state="disabled")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scroll.set)

    def _build_lock_tab(self, parent: ttk.Notebook) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=12)
        tab.columnconfigure(1, weight=1)

        ttk.Label(tab, text="File or folder").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(tab, textvariable=self.lock_source_var).grid(row=0, column=1, sticky="ew", pady=6)
        ttk.Button(tab, text="Browse File", command=self._choose_lock_file).grid(row=0, column=2, padx=(8, 0), pady=6)
        ttk.Button(tab, text="Browse Folder", command=self._choose_lock_folder).grid(row=0, column=3, padx=(8, 0), pady=6)

        ttk.Label(tab, text="Output").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(tab, textvariable=self.lock_output_var).grid(row=1, column=1, sticky="ew", pady=6)
        ttk.Button(tab, text="Default", command=self._set_default_lock_output).grid(row=1, column=2, padx=(8, 0), pady=6)
        ttk.Checkbutton(tab, text="Replace existing", variable=self.lock_force_var).grid(
            row=1,
            column=3,
            sticky="w",
            padx=(8, 0),
            pady=6,
        )

        ttk.Label(tab, text="Key file").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(tab, textvariable=self.lock_key_file_var).grid(row=2, column=1, sticky="ew", pady=6)
        ttk.Button(tab, text="Browse", command=lambda: self._choose_key_file(self.lock_key_file_var)).grid(
            row=2,
            column=2,
            padx=(8, 0),
            pady=6,
        )

        ttk.Label(tab, text="Cipher").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Combobox(
            tab,
            textvariable=self.lock_cipher_var,
            values=SUPPORTED_CIPHERS,
            state="readonly",
            width=24,
        ).grid(row=3, column=1, sticky="w", pady=6)
        ttk.Checkbutton(tab, text="Compress", variable=self.lock_compress_var).grid(
            row=3,
            column=2,
            sticky="w",
            padx=(8, 0),
            pady=6,
        )
        ttk.Checkbutton(tab, text="Secure delete", variable=self.lock_secure_delete_var).grid(
            row=3,
            column=3,
            sticky="w",
            padx=(8, 0),
            pady=6,
        )

        ttk.Button(tab, text="Lock Selected Item", command=self._lock_selected).grid(
            row=4,
            column=1,
            sticky="e",
            pady=(16, 0),
        )
        return tab

    def _build_open_tab(self, parent: ttk.Notebook) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=12)
        tab.columnconfigure(1, weight=1)

        ttk.Label(tab, text="Locked file").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(tab, textvariable=self.open_locked_var).grid(row=0, column=1, sticky="ew", pady=6)
        ttk.Button(tab, text="Browse", command=lambda: self._choose_locked_file(self.open_locked_var)).grid(
            row=0,
            column=2,
            padx=(8, 0),
            pady=6,
        )

        ttk.Label(tab, text="Key file").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(tab, textvariable=self.open_key_file_var).grid(row=1, column=1, sticky="ew", pady=6)
        ttk.Button(tab, text="Browse", command=lambda: self._choose_key_file(self.open_key_file_var)).grid(
            row=1,
            column=2,
            padx=(8, 0),
            pady=6,
        )

        actions = ttk.Frame(tab)
        actions.grid(row=2, column=1, sticky="e", pady=(16, 0))
        ttk.Button(actions, text="Open or Play", command=self._open_locked_item).grid(row=0, column=0)
        ttk.Button(actions, text="Clean Temporary Copies", command=self._cleanup_temp_dirs).grid(
            row=0,
            column=1,
            padx=(8, 0),
        )
        return tab

    def _build_unlock_tab(self, parent: ttk.Notebook) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=12)
        tab.columnconfigure(1, weight=1)

        ttk.Label(tab, text="Locked file").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(tab, textvariable=self.unlock_locked_var).grid(row=0, column=1, sticky="ew", pady=6)
        ttk.Button(tab, text="Browse", command=lambda: self._choose_locked_file(self.unlock_locked_var)).grid(
            row=0,
            column=2,
            padx=(8, 0),
            pady=6,
        )

        ttk.Label(tab, text="Output").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(tab, textvariable=self.unlock_output_var).grid(row=1, column=1, sticky="ew", pady=6)
        ttk.Button(tab, text="Default", command=self._set_default_unlock_output).grid(row=1, column=2, padx=(8, 0), pady=6)
        ttk.Checkbutton(tab, text="Replace existing", variable=self.unlock_force_var).grid(
            row=1,
            column=3,
            sticky="w",
            padx=(8, 0),
            pady=6,
        )

        ttk.Label(tab, text="Key file").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(tab, textvariable=self.unlock_key_file_var).grid(row=2, column=1, sticky="ew", pady=6)
        ttk.Button(tab, text="Browse", command=lambda: self._choose_key_file(self.unlock_key_file_var)).grid(
            row=2,
            column=2,
            padx=(8, 0),
            pady=6,
        )

        ttk.Button(tab, text="Unlock Permanently", command=self._unlock_selected).grid(
            row=3,
            column=1,
            sticky="e",
            pady=(16, 0),
        )
        return tab

    def _build_info_tab(self, parent: ttk.Notebook) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=12)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(1, weight=1)

        ttk.Label(tab, text="Locked file").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(tab, textvariable=self.info_locked_var).grid(row=0, column=1, sticky="ew", pady=6)
        ttk.Button(tab, text="Browse", command=lambda: self._choose_locked_file(self.info_locked_var)).grid(
            row=0,
            column=2,
            padx=(8, 0),
            pady=6,
        )
        ttk.Button(tab, text="Show Info", command=self._show_info).grid(row=0, column=3, padx=(8, 0), pady=6)

        ttk.Label(tab, text="Key file").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(tab, textvariable=self.info_key_file_var).grid(row=1, column=1, sticky="ew", pady=6)
        ttk.Button(tab, text="Browse", command=lambda: self._choose_key_file(self.info_key_file_var)).grid(
            row=1,
            column=2,
            padx=(8, 0),
            pady=6,
        )

        self.info_text = tk.Text(tab, height=8, wrap="word", state="disabled")
        self.info_text.grid(row=2, column=0, columnspan=4, sticky="nsew", pady=(12, 0))
        return tab

    def _path_from_var(self, value: tk.StringVar, label: str) -> Path:
        raw_path = value.get().strip().strip('"')
        if not raw_path:
            raise LockError(f"Choose a {label} first.")
        return Path(raw_path).expanduser()

    def _choose_lock_file(self) -> None:
        selected = filedialog.askopenfilename(title="Choose a file to lock")
        if selected:
            self.lock_source_var.set(selected)
            self._set_default_lock_output()

    def _choose_lock_folder(self) -> None:
        selected = filedialog.askdirectory(title="Choose a folder to lock")
        if selected:
            self.lock_source_var.set(selected)
            self._set_default_lock_output()

    def _choose_locked_file(self, target_var: tk.StringVar) -> None:
        selected = filedialog.askopenfilename(
            title="Choose a locked file",
            filetypes=[("Locked files", f"*{LOCKED_SUFFIX}"), ("All files", "*.*")],
        )
        if selected:
            target_var.set(selected)

    def _choose_key_file(self, target_var: tk.StringVar) -> None:
        selected = filedialog.askopenfilename(title="Choose a key file")
        if selected:
            target_var.set(selected)

    def _key_file_or_none(self, value: tk.StringVar) -> str | None:
        key_file = value.get().strip().strip('"')
        return key_file or None

    def _set_default_lock_output(self) -> None:
        try:
            source = self._path_from_var(self.lock_source_var, "file or folder")
        except LockError:
            return
        self.lock_output_var.set(str(default_locked_path(source)))

    def _set_default_unlock_output(self) -> None:
        try:
            locked_path = self._path_from_var(self.unlock_locked_var, "locked file")
            header = read_locked_metadata(locked_path)
            self.unlock_output_var.set(str(locked_path.with_name(header["name"])))
        except Exception as exc:
            self._show_error(exc)

    def _ask_password(self, title: str, confirm: bool = False, policy: PasswordPolicy | None = None) -> str | None:
        dialog = PasswordDialog(self.master, title, confirm=confirm, policy=policy)
        return dialog.result

    def _lock_selected(self) -> None:
        try:
            source = self._path_from_var(self.lock_source_var, "file or folder")
            output = Path(self.lock_output_var.get().strip().strip('"')).expanduser() if self.lock_output_var.get().strip() else default_locked_path(source)
        except LockError as exc:
            self._show_error(exc)
            return

        if not messagebox.askyesno(
            APP_NAME,
            "Locking encrypts this item and removes the original after encryption succeeds. Continue?",
            parent=self.master,
        ):
            return

        password = self._ask_password("Create Password", confirm=True, policy=PasswordPolicy())
        if password is None:
            return

        def work():
            lock_path(
                source,
                output,
                password,
                self.lock_force_var.get(),
                key_file=self._key_file_or_none(self.lock_key_file_var),
                cipher=self.lock_cipher_var.get(),
                compress=self.lock_compress_var.get(),
                secure_delete=self.lock_secure_delete_var.get(),
            )
            return source, output

        self._run_task("Locking item...", work, self._after_lock)

    def _open_locked_item(self) -> None:
        try:
            locked_path = self._path_from_var(self.open_locked_var, "locked file")
        except LockError as exc:
            self._show_error(exc)
            return

        password = self._ask_password("Open Locked Item")
        if password is None:
            return

        def work():
            temp_root = Path(tempfile.mkdtemp(prefix="pylocker-open-"))
            try:
                opened_path = decrypt_for_open(
                    locked_path,
                    temp_root,
                    password,
                    key_file=self._key_file_or_none(self.open_key_file_var),
                )
                open_with_default_app(opened_path)
                return locked_path, opened_path, temp_root
            except Exception:
                shutil.rmtree(temp_root, ignore_errors=True)
                raise

        self._run_task("Opening item...", work, self._after_open)

    def _unlock_selected(self) -> None:
        try:
            locked_path = self._path_from_var(self.unlock_locked_var, "locked file")
            output_text = self.unlock_output_var.get().strip().strip('"')
            output = Path(output_text).expanduser() if output_text else None
        except LockError as exc:
            self._show_error(exc)
            return

        password = self._ask_password("Unlock Permanently")
        if password is None:
            return

        def work():
            output_path = unlock_path(
                locked_path,
                output,
                password,
                self.unlock_force_var.get(),
                key_file=self._key_file_or_none(self.unlock_key_file_var),
            )
            return locked_path, output_path

        self._run_task("Unlocking item...", work, self._after_unlock)

    def _show_info(self) -> None:
        try:
            locked_path = self._path_from_var(self.info_locked_var, "locked file")
        except LockError as exc:
            self._show_error(exc)
            return

        try:
            needs_password = detect_file_version(locked_path) == V2_FORMAT_VERSION
        except Exception as exc:
            self._show_error(exc)
            return

        password = self._ask_password("Show Locked Item Info") if needs_password else None
        if needs_password and password is None:
            return

        def work():
            header = read_locked_metadata(
                locked_path,
                password,
                key_file=self._key_file_or_none(self.info_key_file_var),
            )
            return locked_path, header

        self._run_task("Reading info...", work, self._after_info)

    def _run_task(self, label: str, func, on_success) -> None:
        if self.busy:
            messagebox.showinfo(APP_NAME, "Please wait for the current action to finish.", parent=self.master)
            return

        self.busy = True
        self.status_var.set(label)
        self.progress.start(12)

        def worker() -> None:
            try:
                result = func()
            except Exception as exc:
                self.task_queue.put(("error", exc))
            else:
                self.task_queue.put(("success", on_success, result))

        threading.Thread(target=worker, daemon=True).start()

    def _process_task_queue(self) -> None:
        try:
            while True:
                message = self.task_queue.get_nowait()
                kind = message[0]
                self.busy = False
                self.progress.stop()
                self.status_var.set("Ready")

                if kind == "error":
                    self._show_error(message[1])
                else:
                    _kind, on_success, result = message
                    on_success(result)
        except queue.Empty:
            pass
        finally:
            self.after(100, self._process_task_queue)

    def _after_lock(self, result) -> None:
        source, output = result
        self._log(f"Locked {source}")
        self._log(f"Created {output}")
        messagebox.showinfo(APP_NAME, f"Locked successfully:\n{output}", parent=self.master)

    def _after_open(self, result) -> None:
        locked_path, opened_path, temp_root = result
        self.temp_dirs.append(temp_root)
        self._log(f"Opened {locked_path}")
        self._log(f"Temporary copy: {opened_path}")
        messagebox.showinfo(
            APP_NAME,
            "Opened with the default app.\n\nTemporary copies stay available while this app is open.",
            parent=self.master,
        )

    def _after_unlock(self, result) -> None:
        locked_path, output_path = result
        self._log(f"Unlocked {locked_path}")
        self._log(f"Restored to {output_path}")
        messagebox.showinfo(APP_NAME, f"Unlocked successfully:\n{output_path}", parent=self.master)

    def _after_info(self, result) -> None:
        locked_path, header = result
        details = "\n".join(
            [
                f"Version: {header['version']}",
                f"Path: {locked_path}",
                f"Type: {header['kind']}",
                f"Original name: {header['name']}",
                f"Created: {created_time(header)}",
                f"Cipher: {header['cipher']}",
                self._format_kdf(header),
                f"Compression: {header.get('compression', 'legacy none')}",
                f"Key file required: {header.get('key_file_required', False)}",
            ]
        )
        self.info_text.configure(state="normal")
        self.info_text.delete("1.0", "end")
        self.info_text.insert("1.0", details)
        self.info_text.configure(state="disabled")
        self._log(f"Read info for {locked_path}")

    def _cleanup_temp_dirs(self, silent: bool = False) -> None:
        removed = 0
        failed: list[Path] = []
        for temp_dir in list(self.temp_dirs):
            if not temp_dir.exists():
                self.temp_dirs.remove(temp_dir)
                continue
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                failed.append(temp_dir)
            else:
                removed += 1
                self.temp_dirs.remove(temp_dir)

        if not silent:
            if failed:
                messagebox.showwarning(
                    APP_NAME,
                    "Some temporary copies could not be removed. Close any viewers or players and try again.",
                    parent=self.master,
                )
            else:
                messagebox.showinfo(APP_NAME, f"Removed {removed} temporary folder(s).", parent=self.master)
        if removed:
            self._log(f"Removed {removed} temporary folder(s)")

    def _log(self, message: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _show_error(self, exc: Exception) -> None:
        message = str(exc) or exc.__class__.__name__
        self._log(f"Error: {message}")
        messagebox.showerror(APP_NAME, message, parent=self.master)

    def _format_kdf(self, header: dict) -> str:
        kdf = header.get("kdf")
        if isinstance(kdf, dict):
            return f"KDF: {kdf['name']} ({kdf['memory_kib']} KiB, {kdf['iterations']} iterations, {kdf['lanes']} lanes)"
        return f"KDF: {kdf} ({header.get('iterations', 'unknown')} iterations)"

    def close(self) -> None:
        self._cleanup_temp_dirs(silent=True)
        self.master.destroy()


def main() -> None:
    root = tk.Tk()
    root.title(APP_NAME)
    root.geometry("820x560")
    root.minsize(720, 480)

    style = ttk.Style(root)
    if "vista" in style.theme_names():
        style.theme_use("vista")

    app = LockerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.close)
    root.mainloop()


if __name__ == "__main__":
    main()

"""Admin view — create a poll (title, description, dynamic options) and release it."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import VoteNetApp


class AdminView(ttk.Frame):
    def __init__(self, parent: ttk.Widget, app: "VoteNetApp") -> None:
        super().__init__(parent)
        self.app = app
        self.option_vars: list[tk.StringVar] = []
        self._build()

    def _build(self) -> None:
        # Header
        header = ttk.Frame(self)
        header.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(header, text="Create poll", font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT)
        ttk.Button(header, text="Back", command=self.app.show_dashboard).pack(side=tk.RIGHT)

        # Form
        form = ttk.LabelFrame(self, text="Poll details", padding=12)
        form.pack(fill=tk.X, pady=4)

        self.title_var = tk.StringVar()
        self.desc_var = tk.StringVar()

        ttk.Label(form, text="Title").grid(row=0, column=0, sticky=tk.W, pady=4)
        ttk.Entry(form, textvariable=self.title_var, width=50).grid(row=0, column=1, sticky=tk.EW, pady=4)
        ttk.Label(form, text="Description").grid(row=1, column=0, sticky=tk.NW, pady=4)
        desc_entry = tk.Text(form, width=50, height=3)
        desc_entry.grid(row=1, column=1, sticky=tk.EW, pady=4)
        self._desc_widget = desc_entry
        form.columnconfigure(1, weight=1)

        # Options editor
        opt_frame = ttk.LabelFrame(self, text="Options (at least 2)", padding=12)
        opt_frame.pack(fill=tk.BOTH, expand=True, pady=4)
        self.options_host = ttk.Frame(opt_frame)
        self.options_host.pack(fill=tk.BOTH, expand=True)
        self._add_option_entry()
        self._add_option_entry()

        opt_btns = ttk.Frame(opt_frame)
        opt_btns.pack(pady=4)
        ttk.Button(opt_btns, text="+ Add option", command=self._add_option_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(opt_btns, text="- Remove last", command=self._remove_option_entry).pack(side=tk.LEFT, padx=2)

        # Action buttons
        actions = ttk.Frame(self)
        actions.pack(pady=8)
        ttk.Button(actions, text="Create poll", command=self._on_create).pack(side=tk.LEFT, padx=4)

    # ------------------------------------------------------------------
    def _add_option_entry(self) -> None:
        var = tk.StringVar()
        self.option_vars.append(var)
        row = ttk.Frame(self.options_host)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text=f"Option {len(self.option_vars)}:").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Entry(row, textvariable=var, width=40).pack(side=tk.LEFT, fill=tk.X, expand=True)

    def _remove_option_entry(self) -> None:
        if len(self.option_vars) <= 2:
            return
        self.option_vars.pop()
        kids = self.options_host.winfo_children()
        if kids:
            kids[-1].destroy()

    def _collect(self) -> tuple[str, str, list[str]] | None:
        title = self.title_var.get().strip()
        description = self._desc_widget.get("1.0", tk.END).strip()
        options = [v.get().strip() for v in self.option_vars if v.get().strip()]
        if not title:
            messagebox.showerror("Create poll", "Title is required", parent=self)
            return None
        if len(options) < 2:
            messagebox.showerror("Create poll", "At least 2 non-empty options are required", parent=self)
            return None
        return title, description, options

    def _on_create(self) -> None:
        data = self._collect()
        if data is None:
            return
        title, description, options = data
        poll_id = self.app.api.create_poll(title, description, options)
        if poll_id is None:
            messagebox.showerror("Create poll", "Server rejected the poll", parent=self)
            return
        # Offer to release immediately.
        if messagebox.askyesno("Poll created", f"Poll '{title}' created.\n\nOpen the voting window now?", parent=self):
            ok = self.app.api.release_poll(poll_id)
            if not ok:
                messagebox.showwarning("Release", "Could not release the poll (already open?)", parent=self)
        self.app.api.refresh_polls()
        self.app.show_dashboard()

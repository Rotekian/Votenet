"""Notifications log — rolling feed of trades, cascades, vote responses, results."""

from __future__ import annotations

import datetime as _dt
import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING

from ..controller import Notification

if TYPE_CHECKING:
    from .app import VoteNetApp


# Colour per notification kind for quick scanning.
KIND_COLORS = {
    "info": "#444",
    "vote": "#06a",
    "trade": "#060",
    "cascade": "#a00",
    "results": "#504",
    "error": "#c00",
}


class LogView(ttk.Frame):
    def __init__(self, parent: ttk.Widget, app: "VoteNetApp",
                 existing: list[Notification]) -> None:
        super().__init__(parent)
        self.app = app
        self._build()
        for n in existing:
            self.append(n)

    def _build(self) -> None:
        header = ttk.Frame(self)
        header.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(header, text="< Back", command=self.app.show_dashboard).pack(side=tk.LEFT)
        ttk.Label(header, text="Notifications",
                  font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT, padx=12)
        ttk.Button(header, text="Clear", command=self._clear).pack(side=tk.RIGHT)

        self.text = tk.Text(self, wrap=tk.WORD, state=tk.DISABLED,
                            font=("Segoe UI", 10), padx=8, pady=6)
        self.text.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        scroll = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        # Configure color tags
        for kind, color in KIND_COLORS.items():
            self.text.tag_configure(kind, foreground=color)

    def append(self, n: Notification) -> None:
        ts = _dt.datetime.now().strftime("%H:%M:%S")
        self.text.config(state=tk.NORMAL)
        self.text.insert(tk.END, f"[{ts}] ", "info")
        self.text.insert(tk.END, f"{n.title}: ", n.kind)
        self.text.insert(tk.END, f"{n.detail}\n", "info")
        self.text.see(tk.END)
        self.text.config(state=tk.DISABLED)

    def _clear(self) -> None:
        self.text.config(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.config(state=tk.DISABLED)

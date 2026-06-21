"""Login screen — host/port/username/password, connects on submit."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from typing import TYPE_CHECKING

from ... import config

if TYPE_CHECKING:
    from .app import VoteNetApp


class LoginView(ttk.Frame):
    def __init__(self, parent: ttk.Widget, app: "VoteNetApp") -> None:
        super().__init__(parent)
        self.app = app
        self._build()

    def _build(self) -> None:
        # Title
        title = ttk.Label(self, text="VoteNet", font=("Segoe UI", 22, "bold"))
        title.pack(pady=(24, 4))
        sub = ttk.Label(self, text="Anonymous onion-routed voting",
                        font=("Segoe UI", 10), foreground="gray")
        sub.pack(pady=(0, 24))

        # Form card
        card = ttk.LabelFrame(self, text="Sign in", padding=18)
        card.pack(padx=40, pady=8, fill=tk.X)

        self.host_var = tk.StringVar(value=config.HOST)
        self.port_var = tk.StringVar(value=str(config.PORT))
        self.user_var = tk.StringVar()
        self.pass_var = tk.StringVar()

        rows = [
            ("Host", self.host_var),
            ("Port", self.port_var),
            ("Username", self.user_var),
            ("Password", self.pass_var),
        ]
        for i, (label, var) in enumerate(rows):
            ttk.Label(card, text=label).grid(row=i, column=0, sticky=tk.W, pady=4, padx=(0, 8))
            entry = ttk.Entry(card, textvariable=var, width=28)
            if label == "Password":
                entry.config(show="*")
            entry.grid(row=i, column=1, sticky=tk.EW, pady=4)
        card.columnconfigure(1, weight=1)

        # Buttons
        btns = ttk.Frame(self)
        btns.pack(pady=16)
        ttk.Button(btns, text="Sign in", command=self._on_login).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Quit", command=self.app._on_close).pack(side=tk.LEFT, padx=4)

        # Account hint
        hint = ttk.Label(
            self,
            text="Seeded accounts: admin/admin, alice/alice, bob/bob, carol/carol, dave/dave, eve/eve",
            foreground="gray", wraplength=520, justify=tk.CENTER,
        )
        hint.pack(pady=(8, 0))

        # Bind Enter to login
        self.bind_all("<Return>", lambda _: self._on_login())

    def _on_login(self) -> None:
        host = self.host_var.get().strip()
        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            messagebox.showerror("Login", "Port must be a number", parent=self)
            return
        username = self.user_var.get().strip()
        password = self.pass_var.get()
        if not username:
            messagebox.showerror("Login", "Enter a username", parent=self)
            return
        try:
            self.api().login(host, port, username, password)
        except ValueError as e:
            messagebox.showerror("Login failed", str(e), parent=self)
            return
        except Exception as e:
            messagebox.showerror("Connection failed", str(e), parent=self)
            return
        self.unbind_all("<Return>")
        self.app.show_dashboard()

    def api(self):
        return self.app.api

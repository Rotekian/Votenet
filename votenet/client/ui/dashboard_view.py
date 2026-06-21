"""Dashboard — poll list, my token count, navigation buttons."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import VoteNetApp


class DashboardView(ttk.Frame):
    def __init__(self, parent: ttk.Widget, app: "VoteNetApp") -> None:
        super().__init__(parent)
        self.app = app
        self._build()
        self.refresh()

    def _build(self) -> None:
        c = self.controller()

        # Header bar
        header = ttk.Frame(self)
        header.pack(fill=tk.X, pady=(0, 8))
        who = f"{c.username} ({c.role})" if c.username else "unknown"
        self.user_label = ttk.Label(header, text=f"Signed in: {who}",
                                    font=("Segoe UI", 11, "bold"))
        self.user_label.pack(side=tk.LEFT)
        ttk.Button(header, text="Sign out", command=self._sign_out).pack(side=tk.RIGHT)

        # Token summary
        self.token_label = ttk.Label(self, text="", font=("Segoe UI", 10))
        self.token_label.pack(anchor=tk.W, pady=(0, 8))

        # Navigation buttons
        nav = ttk.Frame(self)
        nav.pack(fill=tk.X, pady=(0, 8))
        if c.is_admin():
            ttk.Button(nav, text="+ New poll (admin)", command=self.app.show_admin).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(nav, text="Trade tokens", command=self.app.show_trade).pack(side=tk.LEFT, padx=4)
        ttk.Button(nav, text="Notifications", command=self.app.show_log).pack(side=tk.LEFT, padx=4)
        ttk.Button(nav, text="Refresh", command=self._refresh_action).pack(side=tk.LEFT, padx=4)

        # Auto-trade toggle (right-aligned). Drives the AutoTrader: when on, the
        # client periodically proposes REAL + CHAFF trades to random peers and
        # auto-accepts incoming offers, generating untrackable trade traffic.
        auto_frame = ttk.Frame(nav)
        auto_frame.pack(side=tk.RIGHT)
        self.auto_var = tk.BooleanVar(value=self.app.autotrader.enabled)
        self.auto_check = ttk.Checkbutton(
            auto_frame, text="Auto-trade", variable=self.auto_var,
            command=self._toggle_autotrade,
        )
        self.auto_check.pack(side=tk.RIGHT)
        self.auto_status = ttk.Label(auto_frame, text="(off)", foreground="gray",
                                     width=10)
        self.auto_status.pack(side=tk.RIGHT, padx=(0, 4))

        # Poll list
        list_frame = ttk.LabelFrame(self, text="Polls", padding=8)
        list_frame.pack(fill=tk.BOTH, expand=True)
        cols = ("title", "status", "options", "tokens")
        self.tree = ttk.Treeview(list_frame, columns=cols, show="tree headings", height=14)
        self.tree.heading("#0", text="ID")
        self.tree.heading("title", text="Title")
        self.tree.heading("status", text="Status")
        self.tree.heading("options", text="Options")
        self.tree.heading("tokens", text="My tokens")
        self.tree.column("#0", width=70, stretch=False)
        self.tree.column("title", width=200)
        self.tree.column("status", width=90, anchor=tk.CENTER)
        self.tree.column("options", width=200)
        self.tree.column("tokens", width=70, anchor=tk.CENTER)
        self.tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<Double-1>", self._on_poll_double)

        hint = ttk.Label(self, text="Double-click a poll to open it.",
                         foreground="gray")
        hint.pack(anchor=tk.W, pady=(4, 0))

    # ------------------------------------------------------------------
    def controller(self):
        return self.app.controller

    def _refresh_action(self) -> None:
        self.app.api.refresh_polls()

    def _sign_out(self) -> None:
        # Simple: quit to login. (Connection stays; you can sign in again.)
        self.app.show_login()

    def _on_poll_double(self, _event) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        poll_id = sel[0]
        self.app.show_poll(poll_id)

    def _toggle_autotrade(self) -> None:
        on = self.app.autotrader.toggle()
        self.auto_var.set(on)
        self.auto_status.config(text="(on)" if on else "(off)",
                                foreground="#060" if on else "gray")

    # ------------------------------------------------------------------
    def refresh(self) -> None:
        c = self.controller()
        who = f"{c.username} ({c.role})" if c.username else "unknown"
        self.user_label.config(text=f"Signed in: {who}")
        n_tokens = len(c.held_tokens)
        n_awaiting = len(c.awaiting_reissue)
        # Keep the auto-trade checkbox in sync (e.g. toggled from another view).
        self.auto_var.set(self.app.autotrader.enabled)
        self.auto_status.config(text="(on)" if self.app.autotrader.enabled else "(off)",
                                foreground="#060" if self.app.autotrader.enabled else "gray")
        extra = f"  ({n_awaiting} awaiting reissue)" if n_awaiting else ""
        # Anonymization indicator: am I holding a non-original token?
        anon = c.has_anonymized()
        anon_tag = "  [anonymized]" if anon else "  [original token]"
        anon_color = "#060" if anon else "#a00"
        self.token_label.config(text=f"Vote tokens held: {n_tokens}{extra}{anon_tag}",
                                foreground=anon_color)
        # Rebuild tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        for poll_id, p in c.polls.items():
            status = self._poll_status(poll_id, p)
            options = ", ".join(p.get("options", []))
            n_my_tokens = len(c.tokens_for_poll(poll_id))
            self.tree.insert("", tk.END, iid=poll_id, text=poll_id[:8],
                             values=(p.get("title", ""), status, options, n_my_tokens))

    def _poll_status(self, poll_id: str, p: dict) -> str:
        if poll_id in self.app.controller.results:
            return "Results"
        if poll_id in self.app.controller.open_windows:
            return "Open"
        if p.get("closed"):
            return "Closed"
        if p.get("released"):
            return "Released"
        return "Draft"

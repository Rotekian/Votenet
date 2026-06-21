"""Trade view — P2P bearer-token trades, REAL or CHAFF.

REAL: pick one of your held tokens and a recipient peer; the recipient will
verify the signature and check spendability before accepting.
CHAFF: knowingly exchange fabricated tokens to generate anonymizing noise.

All trade traffic flows through opaque Relay blobs the server cannot read.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from typing import TYPE_CHECKING

from ... import trade

if TYPE_CHECKING:
    from .app import VoteNetApp


class TradeView(ttk.Frame):
    def __init__(self, parent: ttk.Widget, app: "VoteNetApp") -> None:
        super().__init__(parent)
        self.app = app
        self._build()
        self.refresh()

    def controller(self):
        return self.app.controller

    def _build(self) -> None:
        header = ttk.Frame(self)
        header.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(header, text="< Back", command=self.app.show_dashboard).pack(side=tk.LEFT)
        ttk.Label(header, text="Trade vote tokens (P2P)",
                  font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT, padx=12)
        # Auto-trade toggle (right side of header).
        right = ttk.Frame(header)
        right.pack(side=tk.RIGHT)
        self.auto_var = tk.BooleanVar(value=self.app.autotrader.enabled)
        ttk.Checkbutton(right, text="Auto-trade", variable=self.auto_var,
                        command=self._toggle_autotrade).pack(side=tk.RIGHT)
        self.anon_label = ttk.Label(right, text="", foreground="gray")
        self.anon_label.pack(side=tk.RIGHT, padx=(0, 8))

        body = ttk.LabelFrame(self, text="Send a trade offer", padding=12)
        body.pack(fill=tk.X, pady=4)

        ttk.Label(body, text="Your token:").grid(row=0, column=0, sticky=tk.W, pady=4)
        self.token_combo = ttk.Combobox(body, state="readonly", width=40)
        self.token_combo.grid(row=0, column=1, sticky=tk.EW, pady=4)

        ttk.Label(body, text="Recipient peer:").grid(row=1, column=0, sticky=tk.W, pady=4)
        self.peer_combo = ttk.Combobox(body, state="readonly", width=40)
        self.peer_combo.grid(row=1, column=1, sticky=tk.EW, pady=4)

        ttk.Label(body, text="Kind:").grid(row=2, column=0, sticky=tk.W, pady=4)
        self.kind_var = tk.StringVar(value=trade.TradeKind.REAL.value)
        kind_box = ttk.Frame(body)
        kind_box.grid(row=2, column=1, sticky=tk.W, pady=4)
        ttk.Radiobutton(kind_box, text="Real (verify + check spendable)",
                        value=trade.TradeKind.REAL.value, variable=self.kind_var).pack(side=tk.LEFT)
        ttk.Radiobutton(kind_box, text="Chaff (anonymizing noise)",
                        value=trade.TradeKind.CHAFF.value, variable=self.kind_var).pack(side=tk.LEFT, padx=8)

        body.columnconfigure(1, weight=1)
        ttk.Button(body, text="Send offer", command=self._on_offer).grid(row=3, column=1, sticky=tk.W, pady=8)

        # Notes
        notes = ttk.LabelFrame(self, text="How trading works", padding=10)
        notes.pack(fill=tk.X, pady=8)
        ttk.Label(notes, text=(
            "• Trades are fully peer-to-peer: the server only forwards opaque encrypted blobs.\n"
            "• REAL offers carry a genuine signed token; the recipient verifies it and runs an\n"
            "  anonymous 'check spendable' query before accepting.\n"
            "• CHAFF offers knowingly swap fake tokens to generate anonymizing traffic noise.\n"
            "• Incoming offers appear in the Notifications panel. Token holdings update as\n"
            "  offers are exchanged."
        ), justify=tk.LEFT, foreground="gray").pack(anchor=tk.W)

    # ------------------------------------------------------------------
    def refresh(self) -> None:
        c = self.controller()
        # Tokens
        token_labels = []
        for st in c.held_tokens.values():
            token_labels.append(f"{st.token.token_id[:8]} (poll {st.token.poll_id[:6]})")
        self.token_combo["values"] = token_labels
        if token_labels and not self.token_combo.get():
            self.token_combo.current(0)
        # Peers
        peer_labels = [f"{pid[:8]} ({name})" for pid, name in c.online_peers.items()]
        self.peer_combo["values"] = peer_labels

    # ------------------------------------------------------------------
    def _on_offer(self) -> None:
        c = self.controller()
        if not c.held_tokens:
            messagebox.showinfo("Trade", "You hold no tokens to trade.", parent=self)
            return
        token_idx = self.token_combo.current()
        peer_idx = self.peer_combo.current()
        if token_idx < 0 or peer_idx < 0:
            messagebox.showwarning("Trade", "Select a token and a recipient.", parent=self)
            return
        my_token = list(c.held_tokens.values())[token_idx]
        recipient_id = list(c.online_peers.keys())[peer_idx]
        kind = trade.TradeKind(self.kind_var.get())
        try:
            offer_id = self.app.api.offer_trade(my_token, recipient_id, kind)
        except Exception as e:
            messagebox.showerror("Trade", f"Failed to send offer: {e}", parent=self)
            return
        verb = "REAL" if kind == trade.TradeKind.REAL else "CHAFF"
        messagebox.showinfo(
            "Offer sent",
            f"{verb} trade offer sent to {recipient_id[:8]}.\n"
            f"(offer id: {offer_id[:8]})\n\n"
            f"The recipient will see it in their Notifications panel.",
            parent=self,
        )

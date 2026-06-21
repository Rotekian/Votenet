"""Poll detail view — vote UI (radio options + Vote button) and results display.

When the poll's window is open and the user holds a token, the options are
selectable and the Vote button is enabled. Voting submits via the onion path
(``ClientAPI.cast_vote``); the eventual ``VoteResponse`` is surfaced by the
controller as a notification.

When the poll is closed, the results table (totals + percentages) and a
simple text bar chart are shown.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .app import VoteNetApp


class PollView(ttk.Frame):
    def __init__(self, parent: ttk.Widget, app: "VoteNetApp", poll_id: str) -> None:
        super().__init__(parent)
        self.app = app
        self.poll_id = poll_id
        self.choice_var = tk.StringVar()
        self._build()
        self.refresh()

    def controller(self):
        return self.app.controller

    def _poll(self) -> Optional[dict]:
        return self.controller().polls.get(self.poll_id)

    def _build(self) -> None:
        header = ttk.Frame(self)
        header.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(header, text="< Back", command=self.app.show_dashboard).pack(side=tk.LEFT)
        self.title_label = ttk.Label(header, text="", font=("Segoe UI", 14, "bold"))
        self.title_label.pack(side=tk.LEFT, padx=12)
        self.status_label = ttk.Label(header, text="", font=("Segoe UI", 10, "bold"))
        self.status_label.pack(side=tk.RIGHT)

        self.desc_label = ttk.Label(self, text="", wraplength=640, justify=tk.LEFT, foreground="gray")
        self.desc_label.pack(anchor=tk.W, pady=(0, 8))

        # Vote area
        self.vote_frame = ttk.LabelFrame(self, text="Cast your vote", padding=12)
        self.vote_frame.pack(fill=tk.X, pady=4)
        self.options_host = ttk.Frame(self.vote_frame)
        self.options_host.pack(fill=tk.X)
        self.token_label = ttk.Label(self.vote_frame, text="", foreground="gray")
        self.token_label.pack(anchor=tk.W, pady=(4, 4))
        ttk.Button(self.vote_frame, text="Vote", command=self._on_vote).pack(anchor=tk.W)

        # Results area
        self.results_frame = ttk.LabelFrame(self, text="Results", padding=12)
        self.results_text = tk.Text(self.results_frame, width=80, height=14, wrap=tk.WORD,
                                    state=tk.DISABLED, font=("Consolas", 10))
        self.results_text.pack(fill=tk.BOTH, expand=True)

    # ------------------------------------------------------------------
    def refresh(self) -> None:
        p = self._poll()
        if p is None:
            self.title_label.config(text="(unknown poll)")
            return
        self.title_label.config(text=p.get("title", ""))
        self.desc_label.config(text=p.get("description", ""))
        c = self.controller()
        if self.poll_id in c.results:
            self.status_label.config(text="CLOSED — RESULTS")
            self.vote_frame.pack_forget()
            self.results_frame.pack(fill=tk.BOTH, expand=True, pady=4)
            self._render_results(c.results[self.poll_id])
        elif self.poll_id in c.open_windows:
            self.status_label.config(text="OPEN — accepting votes")
            self.results_frame.pack_forget()
            self.vote_frame.pack(fill=tk.X, pady=4)
            self._render_vote_options(p)
        else:
            self.status_label.config(text="Draft / not open")
            self.vote_frame.pack_forget()
            self.results_frame.pack_forget()

    def _render_vote_options(self, p: dict) -> None:
        for child in self.options_host.winfo_children():
            child.destroy()
        options = p.get("options", [])
        first = options[0] if options else None
        self.choice_var.set(first if first else "")
        for opt in options:
            ttk.Radiobutton(self.options_host, text=opt, value=opt,
                            variable=self.choice_var).pack(anchor=tk.W)
        my_tokens = self.controller().tokens_for_poll(self.poll_id)
        n = len(my_tokens)
        if n == 0:
            self.token_label.config(text="You hold no vote token for this poll. "
                                         "Trade for one, or wait for reissue after a cascade.",
                                    foreground="#a00")
        else:
            self.token_label.config(text=f"You hold {n} token(s). Vote will be onion-routed.",
                                    foreground="#080")

    def _render_results(self, results: dict) -> None:
        totals: dict = results.get("totals", {})
        pct: dict = results.get("percentages", {})
        voted = results.get("voted", 0)
        eligible = results.get("eligible", 0)
        turnout = results.get("turnout", 0.0)
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete("1.0", tk.END)
        w = self.results_text
        w.insert(tk.END, f"{results.get('title','')}\n", "h")
        w.insert(tk.END, f"Turnout: {voted}/{eligible} voters ({turnout}%)\n\n")
        # Bar chart
        max_count = max(totals.values()) if totals else 0
        bar_width = 36
        for opt in results.get("options", []):
            count = totals.get(opt, 0)
            p = pct.get(opt, 0.0)
            filled = int(round(bar_width * (count / max_count))) if max_count else 0
            bar = "█" * filled + "·" * (bar_width - filled)
            w.insert(tk.END, f"{opt:<24} {bar} {count:>3}  ({p}%)\n")
        w.insert(tk.END, "\n")
        w.tag_add("h", "1.0", "1.end")
        w.tag_config("h", font=("Segoe UI", 12, "bold"))
        self.results_text.config(state=tk.DISABLED)

    # ------------------------------------------------------------------
    def _on_vote(self) -> None:
        choice = self.choice_var.get()
        if not choice:
            messagebox.showwarning("Vote", "Select an option first", parent=self)
            return
        try:
            nonce = self.app.api.cast_vote(self.poll_id, choice)
        except RuntimeError as e:
            messagebox.showerror("Vote", str(e), parent=self)
            return
        messagebox.showinfo(
            "Vote submitted",
            f"Your vote for '{choice}' was submitted via the onion path.\n\n"
            f"You'll be notified when the server confirms it.\n"
            f"(reply nonce: {nonce[:8]})",
            parent=self,
        )
        self.refresh()

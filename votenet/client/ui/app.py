"""The VoteNet client application shell.

Owns the :class:`tk.Tk` root, the network/controller/api stack, and the frame
router. A single ``after(50, ...)`` pump drains inbound messages from the
background network thread and forwards them to the controller; the controller
in turn fires notifications + state-change callbacks that views subscribe to.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Optional

from ... import config
from ..api import ClientAPI
from ..autotrader import AutoTrader
from ..controller import ClientController, Notification
from ..net import ClientNet, load_or_create_identity
from .login_view import LoginView
from .dashboard_view import DashboardView
from .admin_view import AdminView
from .poll_view import PollView
from .trade_view import TradeView
from .log_view import LogView

if TYPE_CHECKING:
    pass


class VoteNetApp:
    """Top-level application controller."""

    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("VoteNet")
        self.root.geometry("780x620")
        self.root.minsize(680, 540)
        try:
            style = ttk.Style()
            style.theme_use("clam")
        except Exception:
            pass

        # Network stack
        identity = load_or_create_identity()
        self.net = ClientNet(identity=identity)
        self.net.start()
        self.controller = ClientController(self.net)
        self.controller.attach()
        self.api = ClientAPI(self.net, self.controller)
        self.autotrader = AutoTrader(self.api, self.controller)

        # GUI-side callbacks from controller (run on main thread)
        self.controller.on_notify = self._on_notify
        self.controller.on_state_change = self._on_state_change

        # Container that hosts the active view
        self.container = ttk.Frame(self.root, padding=8)
        self.container.pack(fill=tk.BOTH, expand=True)
        self._current_view: Optional[ttk.Frame] = None

        # Notification log accumulator
        self._notifications: list[Notification] = []
        self._log_view: Optional[LogView] = None

        self.show_login()
        self._pump()  # start the message pump
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # View routing
    # ------------------------------------------------------------------
    def _clear_container(self) -> None:
        if self._current_view is not None:
            self._current_view.destroy()
            self._current_view = None

    def show_login(self) -> None:
        self._clear_container()
        self._current_view = LoginView(self.container, self)
        self._current_view.pack(fill=tk.BOTH, expand=True)

    def show_dashboard(self) -> None:
        self._clear_container()
        self._current_view = DashboardView(self.container, self)
        self._current_view.pack(fill=tk.BOTH, expand=True)

    def show_admin(self) -> None:
        self._clear_container()
        self._current_view = AdminView(self.container, self)
        self._current_view.pack(fill=tk.BOTH, expand=True)

    def show_poll(self, poll_id: str) -> None:
        self._clear_container()
        self._current_view = PollView(self.container, self, poll_id)
        self._current_view.pack(fill=tk.BOTH, expand=True)

    def show_trade(self) -> None:
        self._clear_container()
        self._current_view = TradeView(self.container, self)
        self._current_view.pack(fill=tk.BOTH, expand=True)

    def show_log(self) -> None:
        self._clear_container()
        self._log_view = LogView(self.container, self, list(self._notifications))
        self._current_view = self._log_view
        self._current_view.pack(fill=tk.BOTH, expand=True)

    # ------------------------------------------------------------------
    # Notification feed
    # ------------------------------------------------------------------
    def _on_notify(self, n: Notification) -> None:
        self._notifications.append(n)
        if self._log_view is not None:
            self._log_view.append(n)

    def _on_state_change(self) -> None:
        # Tell the current view to refresh itself from the controller.
        if self._current_view is not None and hasattr(self._current_view, "refresh"):
            try:
                self._current_view.refresh()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Message pump: background thread -> main thread
    # ------------------------------------------------------------------
    def _pump(self) -> None:
        for msg in self.net.poll_incoming():
            self.controller.handle_message(msg)
        # Drive the auto-trader from the same loop so it only runs on the GUI
        # thread and pauses naturally while a modal dialog is open.
        self.autotrader.tick()
        self.root.after(50, self._pump)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def _on_close(self) -> None:
        try:
            self.net.stop()
        except Exception:
            pass
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()

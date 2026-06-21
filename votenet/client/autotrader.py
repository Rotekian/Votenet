"""Auto-trading driver.

When toggled on, the :class:`AutoTrader` periodically proposes trades to
random online peers. Roughly half are CHAFF (anonymizing noise — fake tokens,
skipping verification by design) and half are REAL (genuine held tokens). For
REAL trades it picks one of the controller's held tokens.

The driver lives on the GUI side and is pumped by the app's ``after()`` loop:
the app calls :meth:`AutoTrader.tick` every ~200ms, and the trader decides
whether an interval has elapsed and proposes a trade if so.

The full 1:1 swap (propose -> accept -> holdings update) is implemented across
this module, :mod:`votenet.client.api`, and :mod:`votenet.client.controller`:

* PROPOSE  A -> B : sealed :class:`TradeMessage` with A's token/chaff.
* ACCEPT   B -> A : B verifies (REAL) or skips (CHAFF), adopts A's item, sends
                    back its own counter item.
* COMPLETE A      : A adopts B's counter item (REAL) or notes the CHAFF round.

The controller decides acceptance based on the ``auto_accept_trades`` flag,
which the GUI toggles together with auto-propose under a single "auto-trade"
switch. This means two auto-trading clients will complete swaps automatically,
producing a steady stream of untrackable trade traffic.
"""

from __future__ import annotations

import logging
import random
import time
from typing import TYPE_CHECKING, Optional

from .. import config, trade
from ..tokens import SignedToken

if TYPE_CHECKING:
    from .api import ClientAPI
    from .controller import ClientController

log = logging.getLogger("votenet.client.autotrader")


class AutoTrader:
    """Periodically proposes REAL and CHAFF trades to random peers."""

    def __init__(self, api: "ClientAPI", controller: "ClientController") -> None:
        self.api = api
        self.controller = controller
        self.enabled = False
        self._last_propose = 0.0
        self._rng = random.Random()

    # ------------------------------------------------------------------
    # Toggle
    # ------------------------------------------------------------------
    def enable(self) -> None:
        if not self.enabled:
            self.enabled = True
            self.controller.auto_accept_trades = True
            self._last_propose = time.monotonic()
            log.info("auto-trading enabled")

    def disable(self) -> None:
        if self.enabled:
            self.enabled = False
            self.controller.auto_accept_trades = False
            log.info("auto-trading disabled")

    def toggle(self) -> bool:
        if self.enabled:
            self.disable()
        else:
            self.enable()
        return self.enabled

    # ------------------------------------------------------------------
    # Driven by the app's after() loop
    # ------------------------------------------------------------------
    def tick(self) -> None:
        """Called frequently by the GUI.

        Proposes a trade only if the interval elapsed AND we are not yet
        anonymized. Once we hold a token that isn't our original, we stop
        proposing — one successful swap is enough — but we keep ACCEPTING
        incoming trades (handled in the controller) so that other clients can
        still anonymize against us.
        """
        if not self.enabled:
            return
        # Auto-accepting stays on regardless of anonymization state.
        self.controller.auto_accept_trades = True
        if self.controller.has_anonymized():
            return  # anonymized: stop proposing, keep accepting
        now = time.monotonic()
        if now - self._last_propose < config.AUTO_TRADE_INTERVAL_SECONDS:
            return
        self._last_propose = now
        try:
            self._propose_one()
        except Exception:
            log.exception("auto-trade propose failed")

    def _propose_one(self) -> None:
        peers = list(self.controller.online_peers.keys())
        peers = [p for p in peers if p != self.api.net.identity.pubkey_id]
        if not peers:
            return  # no one to trade with
        recipient = self._rng.choice(peers)
        decide_chaff = self._rng.random() < config.AUTO_TRADE_CHAFF_PROBABILITY
        held = list(self.controller.held_tokens.values())
        if decide_chaff or not held:
            # CHAFF round: swap fake tokens purely for noise. Even with no held
            # tokens we can emit chaff to contribute to the anonymity set while
            # we wait for a REAL swap to anonymize us.
            self.api.offer_chaff(recipient)
            return
        # REAL round: offer one of our genuine tokens. Prefer shedding an
        # original so this swap anonymizes us in one step.
        originals = [st for st in held if st.token.token_id in self.controller.original_token_ids]
        token = (originals or held)[0]
        self.api.offer_trade(token, recipient, trade.TradeKind.REAL)

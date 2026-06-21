"""Usage banner for ``python -m votenet``."""

USAGE = """\
VoteNet — anonymous onion-routed voting system.

Run the server:
    python -m votenet.server

Run a client (launch several for admin + voters + traders):
    python -m votenet.client

See README.md for the seeded accounts and a full scenario walkthrough.
"""


def main() -> None:
    print(USAGE)


if __name__ == "__main__":
    main()

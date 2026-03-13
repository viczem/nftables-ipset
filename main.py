import argparse
import ipaddress
import os
import sqlite3
import sys
from pathlib import Path
from typing import Optional, Set

if "DIR" in os.environ:
    DIR = Path(os.environ["DIR"]).expanduser().resolve()
else:
    DIR = Path(__file__).resolve().parent
    DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DIR / "nftables-ipset.db"


def init_db(conn: sqlite3.Connection):
    """Create the table (if missing) and apply performance‑oriented PRAGMAs."""
    conn.execute(  # sql
        """
        CREATE TABLE IF NOT EXISTS ipv4_addresses (
            ip         TEXT    NOT NULL UNIQUE,
            created_at DATETIME DEFAULT (datetime('now')) NOT NULL,
            metadata   TEXT
        );
        """
    )

    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")


def export_blocklist(
    conn: sqlite3.Connection,
    output_path: Path = DIR / "20-blocklist-ipv4.nft",
) -> None:
    """
    Export every stored IPv4 address to a file suitable for inclusion in an
    nftables configuration.  The file will contain:

        add element inet blocklists blocklist_ipv4 {
            1.2.3.4,
            5.6.7.8,
            …
        }
    """

    # ------------------------------------------------------------------
    # 1. Load everything from the DB (both plain IPs and CIDR blocks)
    # ------------------------------------------------------------------
    rows = conn.execute(  # sql
        "SELECT ip FROM ipv4_addresses ORDER BY ip;"
    ).fetchall()
    subnets: list[ipaddress.IPv4Network] = []
    hosts: list[str] = []

    for (ip_str,) in rows:
        if "/" in ip_str:  # treat it as a network
            try:
                subnets.append(ipaddress.IPv4Network(ip_str, strict=False))
            except Exception as exc:
                raise ValueError(f"Invalid CIDR entry in DB: {ip_str}") from exc
        else:  # plain host address
            hosts.append(ip_str)

    # ---------------------------------------------------------------
    # 2. Drop every host that belongs to *any* of the collected nets
    # ---------------------------------------------------------------
    filtered_hosts = [
        h for h in hosts if not any(ipaddress.IPv4Address(h) in net for net in subnets)
    ]

    # ---------------------------------------------------------------
    # 3. Build the final, ordered list.
    # ---------------------------------------------------------------
    # Convert the network objects back to their canonical string form.
    subnet_strs = [str(net) for net in subnets]

    ips = sorted(subnet_strs, reverse=True) + sorted(filtered_hosts, reverse=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("add element inet blocklists blocklist_ipv4 {\n")
        for i, ip in enumerate(ips):
            # Append a comma after every entry except the last one
            suffix = "," if i < len(ips) - 1 else ""
            f.write(f"    {ip}{suffix}\n")
        f.write("}\n")

    print(f"Blocklist exported to {output_path}")


def insert_ip4(conn: sqlite3.Connection, ip: str, metadata: Optional[str]):
    """Insert a new IPv4 address with optional comment metadata."""

    cur = conn.cursor()
    try:
        cur.execute(  # sql
            "INSERT OR IGNORE INTO ipv4_addresses (ip, metadata) VALUES (?, ?);",
            (ip, metadata),
        )
        conn.commit()
        print(f"Inserted {ip}")
    except sqlite3.IntegrityError:
        print(f"IP {ip} already exists – not inserted.")


def batch_insert_ip4(conn: sqlite3.Connection, rows: Set[str], metadata: Optional[str]):
    """
    Insert the given rows in a single transaction.
    Returns the number of rows actually inserted (duplicates are ignored).
    """
    if not rows:
        return 0

    conn.execute("BEGIN;")

    try:
        conn.executemany(  # sql
            "INSERT OR IGNORE INTO ipv4_addresses (ip, metadata) VALUES (?, ?);",
            ((_, metadata) for _ in rows),
        )
    except sqlite3.DatabaseError as e:
        conn.rollback()
        raise RuntimeError(f"Batch insert failed: {e}") from e
    else:
        conn.commit()

    inserted = conn.execute("SELECT total_changes();").fetchone()[0]
    print(f"Inserted {inserted}")


def remove_ip4(conn: sqlite3.Connection, ip: str):
    """Delete a single IPv4 address."""
    cur = conn.cursor()
    cur.execute(  # sql
        "DELETE FROM ipv4_addresses WHERE ip = ?;", (ip,)
    )
    conn.commit()
    if cur.rowcount:
        print(f"Removed {ip}")
    else:
        print(f"IP {ip} not found – nothing removed.")


def batch_remove_ip4(conn: sqlite3.Connection, rows: Set[str]):
    """Delete many IPv4 addresses in a single transaction."""
    if not rows:
        return 0

    conn.execute("BEGIN;")
    try:
        conn.executemany(  # sql
            "DELETE FROM ipv4_addresses WHERE ip = ?;",
            ((ip,) for ip in rows),
        )
    except sqlite3.DatabaseError as e:
        conn.rollback()
        raise RuntimeError(f"Batch remove failed: {e}") from e
    else:
        conn.commit()

    removed = conn.execute("SELECT total_changes();").fetchone()[0]
    print(f"Removed {removed}")


def read_interactive() -> Set[str]:
    """
    Read lines from stdin until an **empty line** or **EOF** is encountered.
    Returns a set of validated ip.
    """
    rows: Set[str] = set()

    while True:
        try:
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            sys.exit(1)

        if line is None:
            continue

        # EOF (Ctrl‑D) returns '' – treat it like an empty line
        if line == "":
            break

        # Empty line (just a newline) ends input as well
        if line.rstrip("\n") == "":
            break

        line = line.strip()
        tokens = [_.strip() for _ in line.replace(",", " ").split() if _.strip()]
        for token in tokens:
            try:
                ip = validate_ip_v4(token)
            except ValueError as e:
                print(f"{e} – line ignored")
                continue
            rows.add(ip)

    return rows


def validate_ip_v4(ip_str: str) -> str:
    """Raise ValueError if `ip_str` is not a valid IPv4 address."""
    try:
        ipaddress.IPv4Network(ip_str, strict=False)
        return ip_str
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise ValueError(f"Invalid IPv4 address or network: {ip_str}") from exc


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Manage an IPv blocklist stored in a SQLite database. "
            "The location of the database directory can be overridden with the "
            "environment variable DIR (default: the script's directory)."
        ),
        epilog=f"[DIR]: {DIR}, [DB_PATH]: {DB_PATH}",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-a",
        "--add",
        dest="add_ip",
        metavar="IP",
        help="Add a single IP address (metadata optional via -m).",
    )
    group.add_argument(
        "-A",
        "--batch-add",
        dest="batch_add",
        action="store_true",
        help="Add many IPs from stdin (empty line / Ctrl‑D ends).",
    )
    group.add_argument(
        "-r",
        "--remove",
        dest="remove_ip",
        metavar="IP",
        help="Remove a single IP address.",
    )
    group.add_argument(
        "-R",
        "--batch-remove",
        dest="batch_remove",
        action="store_true",
        help="Read many IPs from stdin (empty line / Ctrl‑D ends) and delete them.",
    )
    parser.add_argument(
        "-m",
        "--metadata",
        dest="metadata",
        default=None,
        help="If supplied, this string will be stored as the metadata for EVERY IP "
        "added (overrides per‑line comments).",
    )
    parser.add_argument(
        "-e",
        "--export",
        dest="export",
        action="store_true",
        help="Export all stored IPs to 20-blocklist-ipv4.nft (nftables format).",
    )
    args = parser.parse_args()

    if not any(
        (
            args.add_ip,
            args.batch_add,
            args.remove_ip,
            args.batch_remove,
            args.export,
        )
    ):
        parser.print_help()
        return

    with sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
        init_db(conn)

        # ---------- Export blocklist ----------
        if args.export:
            export_blocklist(conn)
            return

        # ---------- Single‑add ----------
        if args.add_ip:
            ip = validate_ip_v4(args.add_ip)
            insert_ip4(conn, ip, args.metadata)
            export_blocklist(conn)
            return

        # ---------- Batch‑add ----------
        if args.batch_add:
            ipset = read_interactive()
            if not ipset:
                print("No valid IPs read – nothing to add.")
                return
            batch_insert_ip4(conn, ipset, args.metadata)
            export_blocklist(conn)
            return

        # ---------- Single‑remove ----------
        if args.remove_ip:
            ip = validate_ip_v4(args.remove_ip)
            remove_ip4(conn, ip)
            export_blocklist(conn)
            return

        # ---------- Batch‑remove ----------
        if args.batch_remove:
            ipset = read_interactive()
            if not ipset:
                print("No valid IPs read – nothing to remove.")
                return
            batch_remove_ip4(conn, ipset)
            export_blocklist(conn)


if __name__ == "__main__":
    main()

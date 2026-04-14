import argparse
import ipaddress
import os
import sqlite3
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

if "DIR" in os.environ:
    DIR = Path(os.environ["DIR"]).expanduser().resolve()
else:
    DIR = Path(__file__).resolve().parent
    DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DIR / "nftables-ipset.db"


# ---------------------------------------------------------------------------
# Database schema & helpers
# ---------------------------------------------------------------------------


def init_db(conn: sqlite3.Connection) -> None:
    """Create the required tables and set SQLite pragmas.

    Two tables are used:

    * ``ip_addresses`` – stores individual host IPs.
    * ``ip_networks`` – stores network prefixes. The ``ip`` column stores the
      network address (e.g. ``158.94.208.0``) and ``subnet`` stores the prefix
      length (e.g. ``24``). ``updated_at`` is refreshed when the stored prefix
      is expanded (e.g. from ``/24`` to ``/22``).

    The function is idempotent – it can be called on every start‑up.
    """
    # Hosts
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_addresses (
            ip         TEXT    NOT NULL UNIQUE,
            version    TEXT    NOT NULL,   -- 'ipv4' or 'ipv6'
            created_at DATETIME DEFAULT (datetime('now')) NOT NULL,
            metadata   TEXT
        );
        """
    )
    # Networks
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_networks (
            ip         TEXT    NOT NULL,
            version    TEXT    NOT NULL,   -- 'ipv4' or 'ipv6'
            subnet     INTEGER NOT NULL,   -- prefix length
            created_at DATETIME DEFAULT (datetime('now')) NOT NULL,
            updated_at DATETIME DEFAULT (datetime('now')) NOT NULL,
            PRIMARY KEY (ip, version)
        );
        """
    )
    # Performance‑oriented pragmas
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")


def _insert_network(conn: sqlite3.Connection, net_str: str, version: str) -> None:
    net = ipaddress.ip_network(net_str, strict=False)
    base_ip = str(net.network_address)
    prefix = net.prefixlen

    cur = conn.cursor()

    # Check if the new network is already covered by an existing broader network
    cur.execute("SELECT ip, subnet FROM ip_networks WHERE version = ?;", (version,))
    existing_rows = cur.fetchall()
    for existing_ip, existing_prefix in existing_rows:
        existing_net = ipaddress.ip_network(
            f"{existing_ip}/{existing_prefix}", strict=False
        )
        if (
            net.version == existing_net.version
            and int(existing_net.network_address) <= int(net.network_address)
            and int(existing_net.broadcast_address) >= int(net.broadcast_address)
        ):
            print(
                f"Ignored network {base_ip}/{prefix}; covered by existing {existing_ip}/{existing_prefix} ({version})"
            )
            conn.commit()
            return

    # Delete any existing networks that are subnets of the new network (more specific)
    for existing_ip, existing_prefix in existing_rows:
        existing_net = ipaddress.ip_network(
            f"{existing_ip}/{existing_prefix}", strict=False
        )
        if (
            net.version == existing_net.version
            and int(existing_net.network_address) >= int(net.network_address)
            and int(existing_net.broadcast_address) <= int(net.broadcast_address)
        ):
            cur.execute(
                "DELETE FROM ip_networks WHERE ip = ? AND version = ?;",
                (existing_ip, version),
            )

    # Insert or update the exact network entry
    cur.execute(
        "SELECT subnet FROM ip_networks WHERE ip = ? AND version = ?;",
        (base_ip, version),
    )
    row = cur.fetchone()
    if row is None:
        cur.execute(
            "INSERT INTO ip_networks (ip, version, subnet) VALUES (?, ?, ?);",
            (base_ip, version, prefix),
        )
        conn.commit()
        print(f"Inserted network {base_ip}/{prefix} ({version})")
    else:
        existing = row[0]
        if prefix < existing:
            cur.execute(
                """
                UPDATE ip_networks
                SET subnet = ?, updated_at = datetime('now')
                WHERE ip = ? AND version = ?;
                """,
                (prefix, base_ip, version),
            )
            conn.commit()
            print(
                f"Updated network {base_ip}/{existing} -> {base_ip}/{prefix} ({version})"
            )
        else:
            print(
                f"Ignored network {base_ip}/{prefix}; existing /{existing} is broader."
            )


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def validate_ip(ip_str: str) -> tuple[str, str]:
    """
    Validate any IPv4 or IPv6 address/network.
    Returns a tuple ``(original_input, version)`` where ``version`` is ``ipv4``
    or ``ipv6``. ``ipaddress.ip_network`` is used with ``strict=False`` so that
    both hosts (e.g. ``1.2.3.4``) and networks (e.g. ``1.2.3.0/24``) are accepted.
    """
    try:
        net = ipaddress.ip_network(ip_str, strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise ValueError(f"Invalid IP address or network: {ip_str}") from exc

    version = "ipv4" if net.version == 4 else "ipv6"
    return ip_str, version


# ---------------------------------------------------------------------------
# CRUD operations
# ---------------------------------------------------------------------------


def insert_ip(
    conn: sqlite3.Connection, ip: str, version: str, metadata: str | None
) -> None:
    """
    Insert a host IP or delegate to ``_insert_network`` when a CIDR is supplied.
    """
    if "/" in ip:
        _insert_network(conn, ip, version)
        return

    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT OR IGNORE INTO ip_addresses (ip, version, metadata) VALUES (?, ?, ?);",
            (ip, version, metadata),
        )
        conn.commit()
        print(f"Inserted {ip} ({version})")
    except sqlite3.IntegrityError:
        print(f"IP {ip} already exists – not inserted.")


def batch_insert_ip(
    conn: sqlite3.Connection, rows: set[str], metadata: str | None
) -> int:
    """
    Insert many entries. Networks are handled individually (because they need
    conditional upserts) while plain hosts are bulk‑inserted for speed.
    Returns the number of rows affected according to SQLite's ``total_changes``.
    """
    if not rows:
        return 0

    hosts_to_insert: list[tuple[str, str]] = []

    for raw in rows:
        try:
            ip_norm, ver = validate_ip(raw)
        except ValueError as e:
            print(f"{e} – line ignored")
            continue

        if "/" in ip_norm:
            _insert_network(conn, ip_norm, ver)
        else:
            hosts_to_insert.append((ip_norm, ver))

    # Bulk insert hosts
    if hosts_to_insert:
        conn.execute("BEGIN;")
        try:
            conn.executemany(
                "INSERT OR IGNORE INTO ip_addresses (ip, version, metadata) VALUES (?, ?, ?);",
                ((ip, ver, metadata) for ip, ver in hosts_to_insert),
            )
        except sqlite3.DatabaseError as e:
            conn.rollback()
            raise RuntimeError(f"Batch insert failed: {e}") from e
        else:
            conn.commit()

    inserted = conn.execute("SELECT total_changes();").fetchone()[0]
    print(f"Inserted {inserted}")
    return inserted


# ---------------------------------------------------------------------------
# Updated CRUD helpers – these definitions replace the earlier versions.
# ---------------------------------------------------------------------------


def remove_ip(conn: sqlite3.Connection, ip: str) -> None:
    """Delete a host IP *or* a network.

    The function validates the supplied ``ip`` (which may be a plain address or a
    CIDR network) using :func:`validate_ip`.  If the string contains a ``/`` it
    is treated as a network and the entry is removed from ``ip_networks`` using
    the *network address* (base IP).  Otherwise the entry is a host and is
    removed from ``ip_addresses``.
    """
    ip_norm, version = validate_ip(ip)

    cur = conn.cursor()
    if "/" in ip_norm:
        net = ipaddress.ip_network(ip_norm, strict=False)
        base_ip = str(net.network_address)
        cur.execute(
            "DELETE FROM ip_networks WHERE ip = ? AND version = ?;",
            (base_ip, version),
        )
        conn.commit()
        if cur.rowcount:
            print(f"Removed network {base_ip}/{net.prefixlen} ({version})")
        else:
            print(
                f"Network {base_ip}/{net.prefixlen} ({version}) not found – nothing removed."
            )
    else:
        cur.execute(
            "DELETE FROM ip_addresses WHERE ip = ? AND version = ?;",
            (ip_norm, version),
        )
        conn.commit()
        if cur.rowcount:
            print(f"Removed {ip_norm} ({version})")
        else:
            print(f"{ip_norm} ({version}) not found – nothing removed.")


def batch_remove_ip(conn: sqlite3.Connection, rows: set[str]) -> int:
    """Bulk delete of host IPs **and** CIDR networks.

    Each entry is validated with :func:`validate_ip`.  Networks are identified
    by the presence of a ``/`` and are removed from ``ip_networks`` using the
    network address.  Hosts are removed from ``ip_addresses``.  The function
    returns the total number of rows removed across both tables.
    """
    if not rows:
        return 0

    hosts_to_delete: list[tuple[str, str]] = []
    nets_to_delete: list[tuple[str, str]] = []

    for raw in rows:
        try:
            ip_norm, ver = validate_ip(raw)
        except ValueError as e:
            print(f"{e} – line ignored")
            continue

        if "/" in ip_norm:
            net = ipaddress.ip_network(ip_norm, strict=False)
            base_ip = str(net.network_address)
            nets_to_delete.append((base_ip, ver))
        else:
            hosts_to_delete.append((ip_norm, ver))

    conn.execute("BEGIN;")
    try:
        if hosts_to_delete:
            conn.executemany(
                "DELETE FROM ip_addresses WHERE ip = ? AND version = ?;",
                hosts_to_delete,
            )
        if nets_to_delete:
            conn.executemany(
                "DELETE FROM ip_networks WHERE ip = ? AND version = ?;",
                nets_to_delete,
            )
    except sqlite3.DatabaseError as e:
        conn.rollback()
        raise RuntimeError(f"Batch remove failed: {e}") from e
    else:
        conn.commit()

    total_removed = conn.execute("SELECT total_changes();").fetchone()[0]
    print(f"Removed {total_removed}")
    return total_removed


# ---------------------------------------------------------------------------
# Export logic
# ---------------------------------------------------------------------------


def _export_one_family(
    conn: sqlite3.Connection, family: str, output_path: Path
) -> None:
    """
    Export a single address family (``ipv4`` or ``ipv6``) to a nftables set file.
    Hosts are taken from ``ip_addresses``; networks are reconstructed from
    ``ip_networks``.
    """
    # Hosts
    host_rows = conn.execute(
        "SELECT ip FROM ip_addresses WHERE version = ? ORDER BY ip;",
        (family,),
    ).fetchall()
    hosts = [row[0] for row in host_rows]

    # Networks – rebuild CIDR strings
    net_rows = conn.execute(
        "SELECT ip, subnet FROM ip_networks WHERE version = ?;",
        (family,),
    ).fetchall()
    networks = [f"{ip}/{subnet}" for ip, subnet in net_rows]

    # Convert everything to ipaddress objects for filtering
    if family == "ipv4":
        ip_cls = ipaddress.IPv4Address
        net_objs = [ipaddress.IPv4Network(c, strict=False) for c in networks]
    else:
        ip_cls = ipaddress.IPv6Address
        net_objs = [ipaddress.IPv6Network(c, strict=False) for c in networks]

    # Remove hosts that are already covered by a network
    filtered_hosts = [h for h in hosts if not any(ip_cls(h) in net for net in net_objs)]

    # Prepare final sorted list (networks first, then hosts)
    final = sorted([str(net) for net in net_objs], reverse=True) + sorted(
        filtered_hosts, reverse=True
    )

    if not final:
        if output_path.is_file():
            try:
                output_path.unlink()
                print(f"Removed stale {family.upper()} blocklist file {output_path}")
            except OSError as exc:
                print(
                    f"Failed to remove stale {family.upper()} blocklist file {output_path}: {exc}"
                )
        else:
            print(f"No {family.upper()} entries – no blocklist file generated.")
        return

    with open(output_path, "w", encoding="utf-8") as f:
        set_name = f"blocklist_{family}"
        f.write(f"add element inet blocklists {set_name} {{\n")
        for i, entry in enumerate(final):
            suffix = "," if i < len(final) - 1 else ""
            f.write(f"    {entry}{suffix}\n")
        f.write("}\n")

    print(f"{family.upper()} blocklist exported to {output_path}")


def export_blocklist(conn: sqlite3.Connection) -> None:
    """Export both IPv4 and IPv6 blocklists."""
    _export_one_family(conn, "ipv4", DIR / "20-blocklist-ipv4.nft")
    _export_one_family(conn, "ipv6", DIR / "20-blocklist-ipv6.nft")


# ---------------------------------------------------------------------------
# Interactive helpers
# ---------------------------------------------------------------------------


def read_interactive() -> set[str]:
    """Read lines from stdin until an empty line or EOF."""
    rows: set[str] = set()
    while True:
        try:
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            sys.exit(1)

        if not line or line.rstrip("\n") == "":
            break

        tokens = [t.strip() for t in line.replace(",", " ").split() if t.strip()]
        rows.update(tokens)
    return rows


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Manage an IP blocklist (IPv4 & IPv6) stored in a SQLite database. "
            "The DB location can be overridden with the DIR environment variable."
        ),
        epilog=f"[DIR]: {DIR}, [DB_PATH]: {DB_PATH}",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-a",
        "--add",
        dest="add_ip",
        metavar="IP",
        help="Add a single IP address or network.",
    )
    group.add_argument(
        "-A",
        "--batch-add",
        dest="batch_add",
        action="store_true",
        help="Add many IPs/networks from stdin.",
    )
    group.add_argument(
        "-r",
        "--remove",
        dest="remove_ip",
        metavar="IP",
        help="Remove a single IP address (hosts only).",
    )
    group.add_argument(
        "-R",
        "--batch-remove",
        dest="batch_remove",
        action="store_true",
        help="Remove many IPs from stdin.",
    )
    parser.add_argument(
        "-m",
        "--metadata",
        dest="metadata",
        default=None,
        help="Metadata stored for every added host IP.",
    )
    parser.add_argument(
        "-e",
        "--export",
        dest="export",
        action="store_true",
        help="Export blocklists to nftables files.",
    )
    args = parser.parse_args()

    if not any(
        (args.add_ip, args.batch_add, args.remove_ip, args.batch_remove, args.export)
    ):
        parser.print_help()
        return

    with sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
        init_db(conn)

        if args.export:
            export_blocklist(conn)
            return

        if args.add_ip:
            ip_norm, ver = validate_ip(args.add_ip)
            insert_ip(conn, ip_norm, ver, args.metadata)
            export_blocklist(conn)
            return

        if args.batch_add:
            ipset = read_interactive()
            if ipset:
                batch_insert_ip(conn, ipset, args.metadata)
                export_blocklist(conn)
            else:
                print("No IPs read – nothing to add.")
            return

        if args.remove_ip:
            remove_ip(conn, args.remove_ip)
            export_blocklist(conn)
            return

        if args.batch_remove:
            ipset = read_interactive()
            if ipset:
                batch_remove_ip(conn, ipset)
                export_blocklist(conn)
            else:
                print("No IPs read – nothing to remove.")
            return


if __name__ == "__main__":
    main()

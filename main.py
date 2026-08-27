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

    Three tables are used:

    * ``ip_addresses`` – stores individual host IPs.
    * ``ip_addresses_exclude`` – stores host IPs that must not be blocked.
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
            comment    TEXT,
            PRIMARY KEY (ip, version)
        );
        """
    )
    # Hosts that must never be added to the blocklist
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_addresses_exclude (
            ip         TEXT    NOT NULL UNIQUE,
            version    TEXT    NOT NULL,   -- 'ipv4' or 'ipv6'
            created_at DATETIME DEFAULT (datetime('now')) NOT NULL,
            comment    TEXT,
            PRIMARY KEY (ip, version)
        );
        """
    )
    # Networks
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_networks (
            ip         TEXT    NOT NULL UNIQUE,
            version    TEXT    NOT NULL,   -- 'ipv4' or 'ipv6'
            subnet     INTEGER NOT NULL,   -- prefix length
            created_at DATETIME DEFAULT (datetime('now')) NOT NULL,
            updated_at DATETIME DEFAULT (datetime('now')) NOT NULL,
            comment    TEXT,
            PRIMARY KEY (ip, version)
        );
        """
    )
    # Performance‑oriented pragmas
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")


def _insert_network(
    conn: sqlite3.Connection,
    net_str: str,
    version: str,
    comment: str | None,
    commit: bool = True,
) -> None:
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
            if commit:
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
        "SELECT subnet, comment FROM ip_networks WHERE ip = ? AND version = ?;",
        (base_ip, version),
    )
    row = cur.fetchone()
    if row is None:
        cur.execute(
            "INSERT INTO ip_networks (ip, version, subnet, comment) VALUES (?, ?, ?, ?);",
            (base_ip, version, prefix, comment),
        )
        if commit:
            conn.commit()
        print(f"Inserted network {base_ip}/{prefix} ({version})")
    else:
        existing_sub = row[0]
        existing_comment = row[1]
        if prefix < existing_sub:
            cur.execute(
                """
                UPDATE ip_networks
                SET subnet = ?, updated_at = datetime('now'), comment = ?
                WHERE ip = ? AND version = ?;
                """,
                (prefix, base_ip, version, comment if comment else existing_comment),
            )
            if commit:
                conn.commit()
            print(
                f"Updated network {base_ip}/{existing_sub} -> {base_ip}/{prefix} ({version})"
            )
        else:
            print(
                f"Ignored network {base_ip}/{prefix}; existing /{existing_sub} is broader."
            )
            if commit:
                conn.commit()


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


def validate_host_ip(ip_str: str) -> tuple[str, str]:
    """Validate and normalize an individual IPv4 or IPv6 address."""
    if "/" in ip_str:
        raise ValueError(f"CIDR networks cannot be added to exclude: {ip_str}")

    try:
        address = ipaddress.ip_address(ip_str)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip_str}") from exc

    version = "ipv4" if address.version == 4 else "ipv6"
    return str(address), version


def _find_blocklist_conflict(
    conn: sqlite3.Connection, ip: str, version: str
) -> str | None:
    """Return the blocklist entry that contains an address, if any."""
    address = ipaddress.ip_address(ip)

    host_rows = conn.execute(
        "SELECT ip FROM ip_addresses WHERE version = ?;", (version,)
    ).fetchall()
    for (blocked_ip,) in host_rows:
        if ipaddress.ip_address(blocked_ip) == address:
            return blocked_ip

    network_rows = conn.execute(
        "SELECT ip, subnet FROM ip_networks WHERE version = ?;", (version,)
    ).fetchall()
    for network_ip, prefix in network_rows:
        network = ipaddress.ip_network(f"{network_ip}/{prefix}", strict=False)
        if address in network:
            return str(network)

    return None


def _find_exclude_conflict(
    conn: sqlite3.Connection, ip: str, version: str
) -> str | None:
    """Return an excluded host covered by a blocklist candidate, if any."""
    candidate = ipaddress.ip_network(ip, strict=False)
    rows = conn.execute(
        "SELECT ip FROM ip_addresses_exclude WHERE version = ?;", (version,)
    ).fetchall()
    for (excluded_ip,) in rows:
        if ipaddress.ip_address(excluded_ip) in candidate:
            return excluded_ip

    return None


def _matching_host_rows(
    conn: sqlite3.Connection, table: str, ip: str, version: str
) -> list[tuple[str, str]]:
    """Return stored host rows that are semantically equal to an address."""
    if table not in {"ip_addresses", "ip_addresses_exclude"}:
        raise ValueError(f"Unsupported host table: {table}")

    address = ipaddress.ip_address(ip)
    rows = conn.execute(
        f"SELECT ip FROM {table} WHERE version = ?;", (version,)
    ).fetchall()
    return [
        (stored_ip, version)
        for (stored_ip,) in rows
        if ipaddress.ip_address(stored_ip) == address
    ]


# ---------------------------------------------------------------------------
# CRUD operations
# ---------------------------------------------------------------------------


def insert_ip(
    conn: sqlite3.Connection, ip: str, version: str, comment: str | None
) -> None:
    """
    Insert a host IP or delegate to ``_insert_network`` when a CIDR is supplied.
    """
    conn.execute("BEGIN IMMEDIATE;")
    try:
        excluded_ip = _find_exclude_conflict(conn, ip, version)
        if excluded_ip is not None:
            raise ValueError(
                f"Cannot add {ip} to blocklist; it contains excluded IP {excluded_ip}. "
                "Remove the exclusion manually with --remove first."
            )

        if "/" in ip:
            _insert_network(conn, ip, version, comment)
            return

        cur = conn.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO ip_addresses (ip, version, comment) VALUES (?, ?, ?);",
            (ip, version, comment),
        )
        conn.commit()
        print(f"Inserted {ip} ({version})")
    except (sqlite3.DatabaseError, ValueError):
        conn.rollback()
        raise


def batch_insert_ip(
    conn: sqlite3.Connection, rows: list[str], comment: str | None
) -> int:
    """
    Insert many entries. Networks are handled individually (because they need
    conditional upserts) while plain hosts are bulk‑inserted for speed.
    Returns the number of rows affected according to SQLite's ``total_changes``.
    """
    if not rows:
        return 0

    hosts_to_insert: list[tuple[str, str]] = []
    before = conn.total_changes
    conn.execute("BEGIN IMMEDIATE;")

    try:
        for raw in rows:
            try:
                ip_norm, ver = validate_ip(raw)
            except ValueError as e:
                print(f"{e} – line ignored")
                continue

            excluded_ip = _find_exclude_conflict(conn, ip_norm, ver)
            if excluded_ip is not None:
                print(
                    f"Warning: {ip_norm} was not added to blocklist because it "
                    f"contains excluded IP {excluded_ip}. Remove the exclusion "
                    "manually with --remove first."
                )
                continue

            if "/" in ip_norm:
                _insert_network(conn, ip_norm, ver, comment, commit=False)
            else:
                hosts_to_insert.append((ip_norm, ver))

        if hosts_to_insert:
            conn.executemany(
                "INSERT OR IGNORE INTO ip_addresses (ip, version, comment) VALUES (?, ?, ?);",
                ((ip, ver, comment) for ip, ver in hosts_to_insert),
            )
    except sqlite3.DatabaseError as e:
        conn.rollback()
        raise RuntimeError(f"Batch insert failed: {e}") from e
    else:
        conn.commit()

    inserted = conn.total_changes - before
    print(f"Inserted {inserted}")
    return inserted


def insert_exclude(
    conn: sqlite3.Connection, ip: str, version: str, comment: str | None
) -> None:
    """Add a host IP to the exclude list after checking the blocklist."""
    conn.execute("BEGIN IMMEDIATE;")
    try:
        conflict = _find_blocklist_conflict(conn, ip, version)
        if conflict is not None:
            raise ValueError(
                f"Cannot exclude {ip}; it is blocked by {conflict}. "
                "Remove that blocklist entry manually, then repeat the command."
            )

        before = conn.total_changes
        conn.execute(
            "INSERT OR IGNORE INTO ip_addresses_exclude (ip, version, comment) VALUES (?, ?, ?);",
            (ip, version, comment),
        )
        conn.commit()
    except (sqlite3.DatabaseError, ValueError):
        conn.rollback()
        raise
    if conn.total_changes > before:
        print(f"Inserted excluded IP {ip} ({version})")
    else:
        print(f"Excluded IP {ip} ({version}) already exists – not inserted.")


def batch_insert_exclude(
    conn: sqlite3.Connection, rows: list[str], comment: str | None
) -> int:
    """Add valid, unblocked host IPs to the exclude list in input order."""
    inserted = 0
    conn.execute("BEGIN IMMEDIATE;")
    try:
        for raw in rows:
            try:
                ip_norm, ver = validate_host_ip(raw)
            except ValueError as exc:
                print(f"Warning: {exc} – line ignored")
                continue

            conflict = _find_blocklist_conflict(conn, ip_norm, ver)
            if conflict is not None:
                print(
                    f"Warning: {ip_norm} was not excluded because it is blocked by "
                    f"{conflict}. Remove that blocklist entry manually, then repeat "
                    "the command."
                )
                continue

            before = conn.total_changes
            conn.execute(
                "INSERT OR IGNORE INTO ip_addresses_exclude (ip, version, comment) VALUES (?, ?, ?);",
                (ip_norm, ver, comment),
            )
            if conn.total_changes > before:
                inserted += 1
    except sqlite3.DatabaseError:
        conn.rollback()
        raise
    else:
        conn.commit()

    print(f"Inserted excluded IPs: {inserted}")
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
        blocklist_rows = _matching_host_rows(
            conn, "ip_addresses", ip_norm, version
        )
        exclude_rows = _matching_host_rows(
            conn, "ip_addresses_exclude", ip_norm, version
        )
        cur.executemany(
            "DELETE FROM ip_addresses WHERE ip = ? AND version = ?;",
            blocklist_rows,
        )
        cur.executemany(
            "DELETE FROM ip_addresses_exclude WHERE ip = ? AND version = ?;",
            exclude_rows,
        )
        conn.commit()
        if blocklist_rows or exclude_rows:
            print(
                f"Removed {ip_norm} ({version}); blocklist: {len(blocklist_rows)}, "
                f"exclude: {len(exclude_rows)}."
            )
        else:
            print(f"{ip_norm} ({version}) not found – nothing removed.")


def batch_remove_ip(conn: sqlite3.Connection, rows: list[str]) -> int:
    """Bulk delete of host IPs **and** CIDR networks.

    Each entry is validated with :func:`validate_ip`.  Networks are identified
    by the presence of a ``/`` and are removed from ``ip_networks`` using the
    network address. Hosts are removed from both address tables. The function
    returns the total number of rows removed across all tables.
    """
    if not rows:
        return 0

    blocked_hosts_to_delete: list[tuple[str, str]] = []
    excluded_hosts_to_delete: list[tuple[str, str]] = []
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
            blocked_hosts_to_delete.extend(
                _matching_host_rows(conn, "ip_addresses", ip_norm, ver)
            )
            excluded_hosts_to_delete.extend(
                _matching_host_rows(conn, "ip_addresses_exclude", ip_norm, ver)
            )

    conn.execute("BEGIN;")
    try:
        if blocked_hosts_to_delete:
            conn.executemany(
                "DELETE FROM ip_addresses WHERE ip = ? AND version = ?;",
                blocked_hosts_to_delete,
            )
        if excluded_hosts_to_delete:
            conn.executemany(
                "DELETE FROM ip_addresses_exclude WHERE ip = ? AND version = ?;",
                excluded_hosts_to_delete,
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
        f.write(f"flush set inet blocklists {set_name}\n")
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


def read_interactive() -> list[str]:
    """Read lines from stdin until an empty line or EOF."""
    rows: list[str] = []
    seen: set[str] = set()
    while True:
        try:
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            sys.exit(1)

        if not line or line.rstrip("\n") == "":
            break

        tokens = [t.strip() for t in line.replace(",", " ").split() if t.strip()]
        for token in tokens:
            if token not in seen:
                rows.append(token)
                seen.add(token)
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
        "-x",
        "--exclude",
        dest="exclude_ip",
        metavar="IP",
        help="Add a host IP to the exclude list.",
    )
    group.add_argument(
        "-X",
        "--batch-exclude",
        dest="batch_exclude",
        action="store_true",
        help="Add many host IPs to the exclude list from stdin.",
    )
    group.add_argument(
        "-r",
        "--remove",
        dest="remove_ip",
        metavar="IP",
        help="Remove a host IP from blocklist/exclude or remove a network.",
    )
    group.add_argument(
        "-R",
        "--batch-remove",
        dest="batch_remove",
        action="store_true",
        help="Remove many IPs from stdin.",
    )
    parser.add_argument(
        "-c",
        "--comment",
        dest="comment",
        default=None,
        help="Comment stored for every added or excluded host IP.",
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
        (
            args.add_ip,
            args.batch_add,
            args.exclude_ip,
            args.batch_exclude,
            args.remove_ip,
            args.batch_remove,
            args.export,
        )
    ):
        parser.print_help()
        return

    with sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
        init_db(conn)

        if args.export:
            export_blocklist(conn)
            return

        if args.add_ip:
            try:
                ip_norm, ver = validate_ip(args.add_ip)
                insert_ip(conn, ip_norm, ver, args.comment)
            except ValueError as exc:
                parser.exit(1, f"Error: {exc}\n")
            export_blocklist(conn)
            return

        if args.batch_add:
            ipset = read_interactive()
            if ipset:
                batch_insert_ip(conn, ipset, args.comment)
                export_blocklist(conn)
            else:
                print("No IPs read – nothing to add.")
            return

        if args.exclude_ip:
            try:
                ip_norm, ver = validate_host_ip(args.exclude_ip)
                insert_exclude(conn, ip_norm, ver, args.comment)
            except ValueError as exc:
                parser.exit(1, f"Error: {exc}\n")
            return

        if args.batch_exclude:
            ipset = read_interactive()
            if ipset:
                batch_insert_exclude(conn, ipset, args.comment)
            else:
                print("No IPs read – nothing to exclude.")
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

import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path


def _run_cli(
    args: list[str], dir_path: Path, input_text: str | None = None
) -> subprocess.CompletedProcess:
    """
    Execute the CLI entry point using ``uv run`` with the ``DIR`` environment
    variable pointing at ``dir_path`` (a temporary directory that holds the
    SQLite database and generated ``.nft`` files).

    ``args`` should be the argument list *excluding* the script name, e.g.
    ``["-a", "1.2.3.4"]``.
    """

    project_root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "DIR": str(dir_path)}
    cmd = ["uv", "run", "nftables-ipset"] + args

    return subprocess.run(
        cmd,
        cwd=str(project_root),
        env=env,
        capture_output=True,
        text=True,
        input=input_text,
    )


class TestCliZeroDependency(unittest.TestCase):
    def setUp(self):
        # Each test gets its own temporary directory that acts as ``DIR``.
        self.temp_dir = Path(tempfile.mkdtemp())
        self.db_path = self.temp_dir / "nftables-ipset.db"

    def tearDown(self):
        # Clean up the temporary directory after the test finishes.
        for child in self.temp_dir.rglob("*"):
            try:
                child.unlink()
            except Exception:
                pass
        try:
            self.temp_dir.rmdir()
        except Exception:
            pass

    def _open_db(self):
        return sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)

    def test_add_single_ipv4(self):
        result = _run_cli(["-a", "192.0.2.1"], self.temp_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with self._open_db() as conn:
            row = conn.execute(
                "SELECT ip, version FROM ip_addresses WHERE ip = ?",
                ("192.0.2.1",),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row, ("192.0.2.1", "ipv4"))

        nft_file = self.temp_dir / "20-blocklist-ipv4.nft"
        self.assertTrue(nft_file.is_file())
        self.assertEqual(
            nft_file.read_text(encoding="utf-8"),
            "flush set inet blocklists blocklist_ipv4\n"
            "add element inet blocklists blocklist_ipv4 {\n"
            "    192.0.2.1\n"
            "}\n",
        )

    def test_add_single_ipv6(self):
        result = _run_cli(["-a", "2001:db8::1"], self.temp_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with self._open_db() as conn:
            row = conn.execute(
                "SELECT ip, version FROM ip_addresses WHERE ip = ?",
                ("2001:db8::1",),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row, ("2001:db8::1", "ipv6"))

        nft_file = self.temp_dir / "20-blocklist-ipv6.nft"
        self.assertTrue(nft_file.is_file())
        self.assertEqual(
            nft_file.read_text(encoding="utf-8"),
            "flush set inet blocklists blocklist_ipv6\n"
            "add element inet blocklists blocklist_ipv6 {\n"
            "    2001:db8::1\n"
            "}\n",
        )

    def test_add_ipv4_network(self):
        result = _run_cli(["-a", "198.51.100.0/24"], self.temp_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with self._open_db() as conn:
            row = conn.execute(
                "SELECT ip, subnet, version FROM ip_networks WHERE ip = ?",
                ("198.51.100.0",),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row, ("198.51.100.0", 24, "ipv4"))

        nft_file = self.temp_dir / "20-blocklist-ipv4.nft"
        self.assertTrue(nft_file.is_file())
        self.assertIn("198.51.100.0/24", nft_file.read_text(encoding="utf-8"))

    def test_exclude_ipv4_with_comment(self):
        comment = "must remain reachable"
        result = _run_cli(
            ["-x", "203.0.113.20", "-c", comment], self.temp_dir
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with self._open_db() as conn:
            row = conn.execute(
                "SELECT ip, version, comment FROM ip_addresses_exclude WHERE ip = ?",
                ("203.0.113.20",),
            ).fetchone()
        self.assertEqual(row, ("203.0.113.20", "ipv4", comment))

    def test_exclude_rejects_cidr(self):
        result = _run_cli(["-x", "203.0.113.0/24"], self.temp_dir)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CIDR networks cannot be added to exclude", result.stderr)
        with self._open_db() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM ip_addresses_exclude"
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_exclude_rejects_blocked_host(self):
        add_result = _run_cli(["-a", "203.0.113.30"], self.temp_dir)
        self.assertEqual(add_result.returncode, 0, msg=add_result.stderr)

        result = _run_cli(["-x", "203.0.113.30"], self.temp_dir)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("it is blocked by 203.0.113.30", result.stderr)
        with self._open_db() as conn:
            row = conn.execute(
                "SELECT ip FROM ip_addresses_exclude WHERE ip = ?",
                ("203.0.113.30",),
            ).fetchone()
        self.assertIsNone(row)

    def test_exclude_rejects_ip_inside_blocked_network(self):
        add_result = _run_cli(["-a", "198.51.100.0/24"], self.temp_dir)
        self.assertEqual(add_result.returncode, 0, msg=add_result.stderr)

        result = _run_cli(["-x", "198.51.100.42"], self.temp_dir)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("it is blocked by 198.51.100.0/24", result.stderr)

    def test_batch_exclude_skips_conflicts_and_cidr(self):
        add_host = _run_cli(["-a", "203.0.113.40"], self.temp_dir)
        self.assertEqual(add_host.returncode, 0, msg=add_host.stderr)
        add_network = _run_cli(["-a", "2001:db8:1::/48"], self.temp_dir)
        self.assertEqual(add_network.returncode, 0, msg=add_network.stderr)

        result = _run_cli(
            ["-X", "-c", "protected"],
            self.temp_dir,
            "192.0.2.10\n203.0.113.40\n2001:db8:1::5\n192.0.2.0/24\n2001:db8::10\n",
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Warning: 203.0.113.40 was not excluded", result.stdout)
        self.assertIn("Warning: 2001:db8:1::5 was not excluded", result.stdout)
        self.assertIn("CIDR networks cannot be added to exclude", result.stdout)
        with self._open_db() as conn:
            rows = conn.execute(
                "SELECT ip, version, comment FROM ip_addresses_exclude ORDER BY ip"
            ).fetchall()
        self.assertEqual(
            rows,
            [
                ("192.0.2.10", "ipv4", "protected"),
                ("2001:db8::10", "ipv6", "protected"),
            ],
        )

    def test_excluded_ip_cannot_be_added_to_blocklist(self):
        exclude_result = _run_cli(["-x", "203.0.113.50"], self.temp_dir)
        self.assertEqual(exclude_result.returncode, 0, msg=exclude_result.stderr)

        host_result = _run_cli(["-a", "203.0.113.50"], self.temp_dir)
        network_result = _run_cli(["-a", "203.0.113.0/24"], self.temp_dir)

        self.assertNotEqual(host_result.returncode, 0)
        self.assertNotEqual(network_result.returncode, 0)
        self.assertIn("excluded IP 203.0.113.50", host_result.stderr)
        self.assertIn("excluded IP 203.0.113.50", network_result.stderr)
        with self._open_db() as conn:
            host_count = conn.execute("SELECT COUNT(*) FROM ip_addresses").fetchone()[0]
            network_count = conn.execute("SELECT COUNT(*) FROM ip_networks").fetchone()[0]
        self.assertEqual(host_count, 0)
        self.assertEqual(network_count, 0)

    def test_batch_add_skips_entries_covering_excluded_ip(self):
        exclude_result = _run_cli(["-x", "2001:db8::20"], self.temp_dir)
        self.assertEqual(exclude_result.returncode, 0, msg=exclude_result.stderr)

        result = _run_cli(
            ["-A"],
            self.temp_dir,
            "2001:db8::20\n2001:db8::/64\n2001:db9::20\n",
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("contains excluded IP 2001:db8::20", result.stdout)
        with self._open_db() as conn:
            rows = conn.execute(
                "SELECT ip FROM ip_addresses WHERE version = 'ipv6'"
            ).fetchall()
            networks = conn.execute(
                "SELECT ip FROM ip_networks WHERE version = 'ipv6'"
            ).fetchall()
        self.assertEqual(rows, [("2001:db9::20",)])
        self.assertEqual(networks, [])

    def test_remove_deletes_excluded_ip(self):
        exclude_result = _run_cli(["-x", "192.0.2.60"], self.temp_dir)
        self.assertEqual(exclude_result.returncode, 0, msg=exclude_result.stderr)

        remove_result = _run_cli(["-r", "192.0.2.60"], self.temp_dir)

        self.assertEqual(remove_result.returncode, 0, msg=remove_result.stderr)
        with self._open_db() as conn:
            row = conn.execute(
                "SELECT ip FROM ip_addresses_exclude WHERE ip = ?",
                ("192.0.2.60",),
            ).fetchone()
        self.assertIsNone(row)

    def test_remove_matches_equivalent_ipv6_spelling(self):
        add_result = _run_cli(["-a", "2001:0db8::60"], self.temp_dir)
        self.assertEqual(add_result.returncode, 0, msg=add_result.stderr)

        remove_result = _run_cli(["-r", "2001:db8::60"], self.temp_dir)

        self.assertEqual(remove_result.returncode, 0, msg=remove_result.stderr)
        with self._open_db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM ip_addresses").fetchone()[0]
        self.assertEqual(count, 0)

    def test_batch_remove_deletes_excluded_ips(self):
        exclude_result = _run_cli(
            ["-X"], self.temp_dir, "192.0.2.70\n2001:db8::70\n"
        )
        self.assertEqual(exclude_result.returncode, 0, msg=exclude_result.stderr)

        remove_result = _run_cli(
            ["-R"], self.temp_dir, "192.0.2.70\n2001:db8::70\n"
        )

        self.assertEqual(remove_result.returncode, 0, msg=remove_result.stderr)
        with self._open_db() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM ip_addresses_exclude"
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_add_ipv6_network(self):
        result = _run_cli(["-a", "2001:db8:abcd::/48"], self.temp_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with self._open_db() as conn:
            row = conn.execute(
                "SELECT ip, subnet, version FROM ip_networks WHERE ip = ?",
                ("2001:db8:abcd::",),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row, ("2001:db8:abcd::", 48, "ipv6"))

        nft_file = self.temp_dir / "20-blocklist-ipv6.nft"
        self.assertTrue(nft_file.is_file())
        self.assertIn("2001:db8:abcd::/48", nft_file.read_text(encoding="utf-8"))

    def test_nft_file_not_created_when_no_entries_for_family(self):
        # Add only an IPv4 host; IPv6 blocklist should not be generated.
        result = _run_cli(["-a", "203.0.113.5"], self.temp_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        ipv6_nft = self.temp_dir / "20-blocklist-ipv6.nft"
        self.assertFalse(ipv6_nft.exists())

    def test_network_expansion_updates_existing_entry(self):
        # Insert a /24 first.
        result1 = _run_cli(["-a", "192.0.2.0/24"], self.temp_dir)
        self.assertEqual(result1.returncode, 0, msg=result1.stderr)

        # Insert a broader /22 that encompasses the previous /24.
        result2 = _run_cli(["-a", "192.0.2.0/22"], self.temp_dir)
        self.assertEqual(result2.returncode, 0, msg=result2.stderr)

        with self._open_db() as conn:
            rows = conn.execute(
                "SELECT ip, subnet FROM ip_networks WHERE ip = ? AND version = ?",
                ("192.0.0.0", "ipv4"),
            ).fetchall()
        # There should be exactly one row and its prefix should be the broader /22.
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0], ("192.0.0.0", 22))

        # The exported nft file must contain the updated /22 entry and not the /24.
        nft_file = self.temp_dir / "20-blocklist-ipv4.nft"
        self.assertTrue(nft_file.is_file())
        content = nft_file.read_text(encoding="utf-8")
        self.assertIn("192.0.0.0/22", content)
        self.assertNotIn("192.0.2.0/24", content)

    def test_host_inside_existing_network_not_exported(self):
        # First add a network that covers the later host.
        result_net = _run_cli(["-a", "192.168.0.0/22"], self.temp_dir)
        self.assertEqual(result_net.returncode, 0, msg=result_net.stderr)

        # Now add a host that lies inside the above network.
        result_host = _run_cli(["-a", "192.168.2.4"], self.temp_dir)
        self.assertEqual(result_host.returncode, 0, msg=result_host.stderr)

        # Verify the host is stored in the ip_addresses table.
        with self._open_db() as conn:
            host_row = conn.execute(
                "SELECT ip, version FROM ip_addresses WHERE ip = ?",
                ("192.168.2.4",),
            ).fetchone()
        self.assertIsNotNone(host_row)
        self.assertEqual(host_row, ("192.168.2.4", "ipv4"))

        # Verify the network entry exists.
        with self._open_db() as conn:
            net_row = conn.execute(
                "SELECT ip, subnet, version FROM ip_networks WHERE ip = ?",
                ("192.168.0.0",),
            ).fetchone()
        self.assertIsNotNone(net_row)
        self.assertEqual(net_row, ("192.168.0.0", 22, "ipv4"))

        # The exported .nft file should contain only the network, not the host.
        nft_file = self.temp_dir / "20-blocklist-ipv4.nft"
        self.assertTrue(nft_file.is_file())
        content = nft_file.read_text(encoding="utf-8")
        self.assertIn("192.168.0.0/22", content)
        self.assertNotIn("192.168.2.4", content)

    def test_ignored_subnetwork_insert(self):
        # Insert a broader network first.
        add_res1 = _run_cli(["-a", "192.0.0.0/22"], self.temp_dir)
        self.assertEqual(add_res1.returncode, 0, msg=add_res1.stderr)

        # Attempt to insert a more specific network that is covered by the existing one.
        add_res2 = _run_cli(["-a", "192.0.2.0/24"], self.temp_dir)
        self.assertEqual(add_res2.returncode, 0, msg=add_res2.stderr)

        # Verify the database still contains only the original /22 entry.
        with self._open_db() as conn:
            rows = conn.execute(
                "SELECT ip, subnet FROM ip_networks WHERE version = ? ORDER BY ip",
                ("ipv4",),
            ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], ("192.0.0.0", 22))

        # Exported .nft file should contain only the /22 network.
        nft_file = self.temp_dir / "20-blocklist-ipv4.nft"
        self.assertTrue(nft_file.is_file())
        content = nft_file.read_text(encoding="utf-8")
        self.assertIn("192.0.0.0/22", content)
        self.assertNotIn("192.0.2.0/24", content)

    def test_remove_single_ipv4(self):
        # Add a host IP first.
        add_res = _run_cli(["-a", "203.0.113.10"], self.temp_dir)
        self.assertEqual(add_res.returncode, 0, msg=add_res.stderr)

        # Verify it exists in the DB.
        with self._open_db() as conn:
            row = conn.execute(
                "SELECT ip FROM ip_addresses WHERE ip = ?",
                ("203.0.113.10",),
            ).fetchone()
        self.assertIsNotNone(row)

        # Now remove it.
        rm_res = _run_cli(["-r", "203.0.113.10"], self.temp_dir)
        self.assertEqual(rm_res.returncode, 0, msg=rm_res.stderr)

        # It should be gone from the DB.
        with self._open_db() as conn:
            row = conn.execute(
                "SELECT ip FROM ip_addresses WHERE ip = ?",
                ("203.0.113.10",),
            ).fetchone()
        self.assertIsNone(row)

        # The IPv4 blocklist file must have been removed because no entries remain.
        nft_file = self.temp_dir / "20-blocklist-ipv4.nft"
        self.assertFalse(nft_file.exists())

    def test_remove_network_ipv4(self):
        # Add a network first.
        add_res = _run_cli(["-a", "198.51.100.0/24"], self.temp_dir)
        self.assertEqual(add_res.returncode, 0, msg=add_res.stderr)

        # Verify it exists in ip_networks.
        with self._open_db() as conn:
            row = conn.execute(
                "SELECT ip, subnet FROM ip_networks WHERE ip = ? AND version = ?",
                ("198.51.100.0", "ipv4"),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row, ("198.51.100.0", 24))

        # Remove the network using the same CLI – the remove command works for networks as well.
        rm_res = _run_cli(["-r", "198.51.100.0/24"], self.temp_dir)
        self.assertEqual(rm_res.returncode, 0, msg=rm_res.stderr)

        # It should be gone from ip_networks.
        with self._open_db() as conn:
            row = conn.execute(
                "SELECT ip FROM ip_networks WHERE ip = ? AND version = ?",
                ("198.51.100.0", "ipv4"),
            ).fetchone()
        self.assertIsNone(row)

        # The IPv4 blocklist file must have been removed because there are no remaining entries.
        nft_file = self.temp_dir / "20-blocklist-ipv4.nft"
        self.assertFalse(nft_file.exists())

    def test_remove_last_ipv6_entry_cleans_file(self):
        # Add an IPv6 host.
        add_res = _run_cli(["-a", "2001:db8::5"], self.temp_dir)
        self.assertEqual(add_res.returncode, 0, msg=add_res.stderr)

        # Ensure the file was created.
        nft_file = self.temp_dir / "20-blocklist-ipv6.nft"
        self.assertTrue(nft_file.is_file())

        # Remove it.
        rm_res = _run_cli(["-r", "2001:db8::5"], self.temp_dir)
        self.assertEqual(rm_res.returncode, 0, msg=rm_res.stderr)

        # Verify the entry disappeared.
        with self._open_db() as conn:
            row = conn.execute(
                "SELECT ip FROM ip_addresses WHERE ip = ?",
                ("2001:db8::5",),
            ).fetchone()
        self.assertIsNone(row)

        # The IPv6 blocklist file must have been removed.
        self.assertFalse(nft_file.exists())

    def test_add_ipv4_with_comment(self):
        """Add a single IPv4 host with a comment and verify it is stored.

        The CLI accepts a ``-c/--comment`` flag that should be persisted in the
        ``comment`` column of the ``ip_addresses`` table.  The comment is not
        exported to the ``.nft`` file (the current implementation only writes
        the IP address), but the presence of the flag must not break the
        insertion logic.
        """
        comment = "blocked because of abuse"
        result = _run_cli(["-a", "203.0.113.42", "-c", comment], self.temp_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with self._open_db() as conn:
            row = conn.execute(
                "SELECT ip, version, comment FROM ip_addresses WHERE ip = ?",
                ("203.0.113.42",),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row, ("203.0.113.42", "ipv4", comment))

        # The blocklist file should still be generated and contain the IP.
        nft_file = self.temp_dir / "20-blocklist-ipv4.nft"
        self.assertTrue(nft_file.is_file())
        self.assertIn("203.0.113.42", nft_file.read_text(encoding="utf-8"))

    def test_add_ipv4_network_with_comment(self):
        """Add a single IPv4 network with a comment and verify persistence.

        The comment should be stored in the ``comment`` column of the
        ``ip_networks`` table.  As with host comments, it is not exported to the
        nft file, but the insertion must succeed without affecting the export.
        """
        comment = "spam source"
        result = _run_cli(["-a", "198.51.100.0/24", "-c", comment], self.temp_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with self._open_db() as conn:
            row = conn.execute(
                "SELECT ip, subnet, version, comment FROM ip_networks WHERE ip = ?",
                ("198.51.100.0",),
            ).fetchone()
        self.assertIsNotNone(row)
        # Expected tuple: (ip, subnet, version, comment)
        self.assertEqual(row, ("198.51.100.0", 24, "ipv4", comment))

        nft_file = self.temp_dir / "20-blocklist-ipv4.nft"
        self.assertTrue(nft_file.is_file())
        self.assertIn("198.51.100.0/24", nft_file.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

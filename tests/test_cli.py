import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path


def _run_cli(args: list[str], dir_path: Path) -> subprocess.CompletedProcess:
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
        self.assertIn("192.0.2.1", nft_file.read_text(encoding="utf-8"))

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
        self.assertIn("2001:db8::1", nft_file.read_text(encoding="utf-8"))

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


if __name__ == "__main__":
    unittest.main()

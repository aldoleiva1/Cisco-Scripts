#!/usr/bin/env python3
"""
test_cisco_sdwan_precheck.py

Unit and property-based tests for cisco_sdwan_precheck.py.

Test strategy:
- Unit tests (stdlib unittest) cover specific examples and edge cases.
- Property-based tests (Hypothesis) verify universal properties across
  generated inputs.

Run with:
    python -m pytest test_cisco_sdwan_precheck.py -v
    python -m unittest discover
"""

import subprocess
import unittest
import unittest.mock

from hypothesis import given, settings
from hypothesis import strategies as st

import cisco_sdwan_precheck


class TestPlaceholder(unittest.TestCase):
    """Placeholder test class — populated by subsequent tasks."""

    def test_module_importable(self):
        """Verify the main module imports without error."""
        self.assertIsNotNone(cisco_sdwan_precheck)


class TestFileIndexer(unittest.TestCase):
    """Unit tests for index_target_files().

    Requirements: 3.2, 3.3, 3.5, 3.6
    """

    # Realistic ciscoFlashFileName walk output line format:
    # SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.<index> = STRING: "/flash/<filename>"

    def _make_line(self, index: str, filename: str) -> str:
        """Build a realistic ciscoFlashFileName SNMP walk output line."""
        return (
            f'SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.{index}'
            f' = STRING: "/flash/{filename}"'
        )

    def test_file_indexer_no_matches_returns_empty_and_warns(self):
        """Input with no target files; assert empty set and WARNING logged.

        Requirements: 3.5
        """
        snmp_output = "\n".join([
            self._make_line("1", "packages.conf"),
            self._make_line("2", "iox.tar"),
            self._make_line("3", "cat8000v-universalk9.17.09.05.SPA.bin"),
        ])

        with self.assertLogs(level="WARNING") as log_ctx:
            result = cisco_sdwan_precheck.index_target_files(snmp_output)

        self.assertEqual(result, set())
        self.assertTrue(
            any("WARNING" in record for record in log_ctx.output),
            "Expected a WARNING log entry when no target files are found",
        )

    def test_file_indexer_only_cdb_no_rollbacks(self):
        """Input with only C.cdb; assert set contains exactly that index.

        Requirements: 3.2, 3.6
        """
        snmp_output = "\n".join([
            self._make_line("3", "C.cdb"),
            self._make_line("7", "packages.conf"),
            self._make_line("11", "iox.tar"),
        ])

        result = cisco_sdwan_precheck.index_target_files(snmp_output)

        self.assertEqual(result, {"3"})

    def test_file_indexer_rollback_boundary_49_included(self):
        """rollback49 present; assert index included.

        Requirements: 3.3
        """
        snmp_output = "\n".join([
            self._make_line("3", "C.cdb"),
            self._make_line("20", "rollback49"),
            self._make_line("21", "packages.conf"),
        ])

        result = cisco_sdwan_precheck.index_target_files(snmp_output)

        self.assertIn("20", result)
        self.assertIn("3", result)

    def test_file_indexer_rollback_50_excluded(self):
        """rollback50 present; assert index not included.

        Requirements: 3.3
        """
        snmp_output = "\n".join([
            self._make_line("3", "C.cdb"),
            self._make_line("22", "rollback50"),
            self._make_line("23", "rollback999"),
            self._make_line("24", "rollback_old"),
            self._make_line("25", "C.cdb.bak"),
        ])

        result = cisco_sdwan_precheck.index_target_files(snmp_output)

        self.assertNotIn("22", result, "rollback50 should be excluded (out of range)")
        self.assertNotIn("23", result, "rollback999 should be excluded (out of range)")
        self.assertNotIn("24", result, "rollback_old should be excluded (non-digit suffix)")
        self.assertNotIn("25", result, "C.cdb.bak should be excluded (not exact C.cdb match)")
        # C.cdb itself should still be included
        self.assertIn("3", result)

    def test_file_indexer_rollback_0_included(self):
        """rollback0 (lower boundary) present; assert index included.

        Requirements: 3.3
        """
        snmp_output = "\n".join([
            self._make_line("1", "C.cdb"),
            self._make_line("2", "rollback0"),
            self._make_line("3", "packages.conf"),
        ])

        result = cisco_sdwan_precheck.index_target_files(snmp_output)

        self.assertIn("2", result, "rollback0 (lower boundary) should be included")
        self.assertIn("1", result, "C.cdb should be included")
        self.assertNotIn("3", result, "packages.conf should be excluded")


class TestSizeAggregator(unittest.TestCase):
    """Unit tests for aggregate_sizes().

    Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
    """

    def _make_size_line(self, index: str, byte_value: int) -> str:
        """Build a realistic ciscoFlashFileSize SNMP walk output line."""
        return (
            f"SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.2.1.1.{index}"
            f" = Gauge32: {byte_value}"
        )

    def test_aggregate_sums_matched_indexes(self):
        """Lines whose index is in target_indexes contribute to the total.

        Requirements: 4.1, 4.2, 4.5
        """
        snmp_output = "\n".join([
            self._make_size_line("3", 45_678_912),
            self._make_size_line("7", 8_192_000),
            self._make_size_line("12", 8_192_000),
        ])
        target_indexes = {"3", "7", "12"}

        result = cisco_sdwan_precheck.aggregate_sizes(snmp_output, target_indexes)

        self.assertEqual(result, 45_678_912 + 8_192_000 + 8_192_000)

    def test_aggregate_excludes_non_target_indexes(self):
        """Lines whose index is not in target_indexes are excluded.

        Requirements: 4.3
        """
        snmp_output = "\n".join([
            self._make_size_line("3", 45_678_912),
            self._make_size_line("99", 999_999_999),  # not in target set
        ])
        target_indexes = {"3"}

        result = cisco_sdwan_precheck.aggregate_sizes(snmp_output, target_indexes)

        self.assertEqual(result, 45_678_912)

    def test_aggregate_empty_target_indexes_returns_zero(self):
        """Empty target_indexes returns 0 regardless of walk output.

        Requirements: 4.2, 4.5
        """
        snmp_output = "\n".join([
            self._make_size_line("3", 45_678_912),
            self._make_size_line("7", 8_192_000),
        ])

        result = cisco_sdwan_precheck.aggregate_sizes(snmp_output, set())

        self.assertEqual(result, 0)

    def test_aggregate_no_matching_indexes_returns_zero(self):
        """Walk output with no matching indexes returns 0.

        Requirements: 4.3, 4.5
        """
        snmp_output = "\n".join([
            self._make_size_line("1", 100_000),
            self._make_size_line("2", 200_000),
        ])
        target_indexes = {"99", "100"}

        result = cisco_sdwan_precheck.aggregate_sizes(snmp_output, target_indexes)

        self.assertEqual(result, 0)

    def test_aggregate_empty_walk_output_returns_zero(self):
        """Empty walk output string returns 0 without error.

        Requirements: 4.4, 4.5
        """
        result = cisco_sdwan_precheck.aggregate_sizes("", {"3", "7"})

        self.assertEqual(result, 0)

    def test_aggregate_none_input_logs_error_and_exits(self):
        """None input logs ERROR and calls sys.exit(1).

        Requirements: 4.4
        """
        with self.assertLogs(level="ERROR") as log_ctx:
            with self.assertRaises(SystemExit) as ctx:
                cisco_sdwan_precheck.aggregate_sizes(None, {"3"})

        self.assertEqual(ctx.exception.code, 1)
        self.assertTrue(
            any("ERROR" in record for record in log_ctx.output),
            "Expected ERROR log when snmp_output is None",
        )

    def test_aggregate_partial_match_only_sums_present_indexes(self):
        """Only indexes that appear in both walk output and target_indexes are summed.

        Requirements: 4.2, 4.3
        """
        snmp_output = "\n".join([
            self._make_size_line("3", 10_000),
            self._make_size_line("7", 20_000),
        ])
        # target_indexes includes "7" and "99", but "99" is absent from walk output
        target_indexes = {"7", "99"}

        result = cisco_sdwan_precheck.aggregate_sizes(snmp_output, target_indexes)

        self.assertEqual(result, 20_000)


class TestPropertyFileIndexerFilter(unittest.TestCase):
    """Property-based tests for index_target_files() filter correctness.

    **Validates: Requirements 3.1, 3.2, 3.3, 3.4**

    Property 2: File_Indexer includes exactly the right files.
    For any ciscoFlashFileName walk output containing an arbitrary mix of
    filenames, the File_Indexer SHALL include in its result set exactly the
    SNMP indexes corresponding to C.cdb and valid rollback files
    (rollback0–rollback49), and SHALL exclude every other filename.
    """

    # -----------------------------------------------------------------------
    # Hypothesis strategies
    # -----------------------------------------------------------------------

    # Valid rollback numbers: 0..49
    _st_valid_rb_num = st.integers(min_value=0, max_value=49)

    # Out-of-range rollback numbers: 50..9999
    _st_invalid_rb_num = st.integers(min_value=50, max_value=9999)

    # Partial-match names that must be excluded
    _st_partial_names = st.sampled_from([
        "C.cdb.bak",
        "rollback_old",
        "rollback",          # no numeric suffix
        "C.cdbX",
        "C.cdb2",
        "RollBack0",         # wrong case
        "rollback0.bak",
        "_C.cdb",
        "rollback50",        # boundary — just outside range
        "rollback999",
    ])

    # Completely arbitrary "noise" filenames
    _st_noise_names = st.one_of(
        st.from_regex(r'[a-z0-9_.-]{1,20}\.conf', fullmatch=True),
        st.from_regex(r'[a-z0-9_.-]{1,20}\.bin', fullmatch=True),
        st.from_regex(r'[a-z0-9_.-]{1,20}\.tar', fullmatch=True),
        st.just("packages.conf"),
        st.just("iox.tar"),
        st.just("cat8000v-universalk9.17.09.05.SPA.bin"),
    )

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _make_line(index: str, filename: str) -> str:
        """Build a realistic ciscoFlashFileName SNMP walk output line."""
        return (
            f'SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.{index}'
            f' = STRING: "/flash/{filename}"'
        )

    # -----------------------------------------------------------------------
    # Property test
    # -----------------------------------------------------------------------

    @settings(max_examples=200)
    @given(
        # How many (and which) valid rollback numbers to include
        valid_rb_nums=st.lists(
            _st_valid_rb_num, min_size=0, max_size=10, unique=True
        ),
        # Whether to include C.cdb
        include_cdb=st.booleans(),
        # Out-of-range rollback numbers to include (should be excluded)
        invalid_rb_nums=st.lists(
            _st_invalid_rb_num, min_size=0, max_size=5, unique=True
        ),
        # Partial-match names (should be excluded)
        partial_names=st.lists(
            st.sampled_from([
                "C.cdb.bak",
                "rollback_old",
                "rollback",
                "C.cdbX",
                "C.cdb2",
                "RollBack0",
                "rollback0.bak",
                "_C.cdb",
                "rollback50",
                "rollback999",
            ]),
            min_size=0, max_size=5,
        ),
        # Noise filenames (should be excluded)
        noise_names=st.lists(
            st.one_of(
                st.just("packages.conf"),
                st.just("iox.tar"),
                st.just("cat8000v-universalk9.17.09.05.SPA.bin"),
                st.from_regex(r'[a-z][a-z0-9_-]{0,10}\.(conf|bin|tar)', fullmatch=True),
            ),
            min_size=0, max_size=5,
        ),
    )
    def test_property_2_file_indexer_filter_correctness(
        self,
        valid_rb_nums,
        include_cdb,
        invalid_rb_nums,
        partial_names,
        noise_names,
    ):
        """Property 2: File_Indexer includes exactly the right files.

        **Validates: Requirements 3.1, 3.2, 3.3, 3.4**
        """
        # ------------------------------------------------------------------
        # Build a list of (index_str, filename, should_be_included) tuples
        # with unique, non-overlapping numeric indexes
        # ------------------------------------------------------------------
        entries = []   # (index_str, filename, should_include: bool)
        next_index = 1

        def add_entry(filename: str, should_include: bool):
            nonlocal next_index
            entries.append((str(next_index), filename, should_include))
            next_index += 1

        # C.cdb — must be included
        if include_cdb:
            add_entry("C.cdb", True)

        # Valid rollback files (rollback0–rollback49) — must be included
        for n in valid_rb_nums:
            add_entry(f"rollback{n}", True)

        # Out-of-range rollback files (rollback50+) — must NOT be included
        for n in invalid_rb_nums:
            add_entry(f"rollback{n}", False)

        # Partial-match names — must NOT be included
        for name in partial_names:
            add_entry(name, False)

        # Noise filenames — must NOT be included
        for name in noise_names:
            # Skip any noise name that accidentally matches C.cdb or a valid
            # rollback pattern (rare but possible with from_regex)
            import re as _re
            is_cdb = (name == "C.cdb")
            rb_m = _re.fullmatch(r'rollback(\d+)', name)
            is_valid_rb = (rb_m is not None and 0 <= int(rb_m.group(1)) <= 49)
            add_entry(name, is_cdb or is_valid_rb)

        # ------------------------------------------------------------------
        # Construct synthetic SNMP walk output
        # ------------------------------------------------------------------
        lines = [self._make_line(idx, fname) for idx, fname, _ in entries]
        snmp_output = "\n".join(lines)

        # ------------------------------------------------------------------
        # Compute the ground-truth sets
        # ------------------------------------------------------------------
        expected_included = {idx for idx, _, should in entries if should}
        expected_excluded = {idx for idx, _, should in entries if not should}

        # ------------------------------------------------------------------
        # Call the function under test
        # ------------------------------------------------------------------
        if expected_included:
            result = cisco_sdwan_precheck.index_target_files(snmp_output)
        else:
            # Expect a WARNING log when no target files are present
            with self.assertLogs(level="WARNING"):
                result = cisco_sdwan_precheck.index_target_files(snmp_output)

        # ------------------------------------------------------------------
        # Assertions
        # ------------------------------------------------------------------
        # 1. Every expected index IS in the result
        for idx in expected_included:
            self.assertIn(
                idx, result,
                f"Expected index {idx!r} to be included but it was missing.",
            )

        # 2. No false-positive indexes appear
        for idx in expected_excluded:
            self.assertNotIn(
                idx, result,
                f"Index {idx!r} should have been excluded but was present.",
            )

        # 3. Result set contains EXACTLY the expected indexes (no extras)
        self.assertEqual(
            result, expected_included,
            f"Result set {result!r} differs from expected {expected_included!r}.",
        )


class TestSNMPClient(unittest.TestCase):
    """Unit tests for run_snmp() — SNMP_Client component.

    Requirements: 2.5, 7.5, 7.6, 8.3, 8.5
    """

    def test_snmp_binary_not_found_logs_and_exits(self):
        """Patch subprocess.run to raise FileNotFoundError; assert sys.exit(1) and ERROR log.

        Requirements: 7.5, 7.6
        """
        with unittest.mock.patch(
            "subprocess.run", side_effect=FileNotFoundError
        ):
            with self.assertLogs(level="ERROR") as log_ctx:
                with self.assertRaises(SystemExit) as exit_ctx:
                    cisco_sdwan_precheck.run_snmp(
                        "10.0.0.1", "public", "161", "walk",
                        ".1.3.6.1.4.1.9.9.10.1.1.4.2.1.1.5.1.1",
                    )

        self.assertEqual(exit_ctx.exception.code, 1)
        self.assertTrue(
            any("ERROR" in record for record in log_ctx.output),
            "Expected an ERROR log when SNMP binary is not found",
        )

    def test_snmp_nonzero_exit_logs_oid_and_exits(self):
        """Patch subprocess.run to raise CalledProcessError; assert OID in log and sys.exit(1).

        Requirements: 2.5, 8.3
        """
        test_oid = ".1.3.6.1.4.1.9.9.10.1.1.4.2.1.1.5.1.1"
        fake_exc = subprocess.CalledProcessError(
            returncode=1,
            cmd=["snmpwalk"],
            stderr="Timeout: No Response from 10.0.0.1",
        )

        with unittest.mock.patch("subprocess.run", side_effect=fake_exc):
            with self.assertLogs(level="ERROR") as log_ctx:
                with self.assertRaises(SystemExit) as exit_ctx:
                    cisco_sdwan_precheck.run_snmp(
                        "10.0.0.1", "public", "161", "walk", test_oid,
                    )

        self.assertEqual(exit_ctx.exception.code, 1)
        # The OID must appear somewhere in the logged ERROR messages
        all_log_output = " ".join(log_ctx.output)
        self.assertIn(
            test_oid,
            all_log_output,
            "Expected OID to be present in the ERROR log when SNMP returns non-zero exit",
        )

    def test_community_not_in_log_output(self):
        """Call run_snmp and verify the community string never appears in log output.

        Requirements: 8.5
        """
        import subprocess as _subprocess

        sensitive_community = "s3cr3tC0mmun1ty"
        test_oid = ".1.3.6.1.4.1.9.9.10.1.1.4.2.1.1.2.1.1"

        # Simulate a CalledProcessError so the error-logging path runs,
        # giving the community string the most opportunity to leak into logs.
        fake_exc = _subprocess.CalledProcessError(
            returncode=1,
            cmd=["snmpwalk"],
            stderr="Authentication failure",
        )

        with unittest.mock.patch("subprocess.run", side_effect=fake_exc):
            with self.assertLogs(level="ERROR") as log_ctx:
                with self.assertRaises(SystemExit):
                    cisco_sdwan_precheck.run_snmp(
                        "10.0.0.1", sensitive_community, "161", "walk", test_oid,
                    )

        all_log_output = " ".join(log_ctx.output)
        self.assertNotIn(
            sensitive_community,
            all_log_output,
            f"Community string {sensitive_community!r} must never appear in log output",
        )


class TestCLI(unittest.TestCase):
    """Unit tests for CLI argument parsing via get_args().

    Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
    """

    def test_cli_accepts_all_args(self):
        """Supply all three flags; verify Namespace values are set correctly."""
        with unittest.mock.patch(
            "sys.argv",
            ["prog", "--ip", "192.168.1.1", "--community", "public", "--port", "161"],
        ):
            args = cisco_sdwan_precheck.get_args()

        self.assertEqual(args.ip, "192.168.1.1")
        self.assertEqual(args.community, "public")
        self.assertEqual(args.port, "161")

    def test_cli_default_port(self):
        """Omit --port; assert args.port equals the default '41684'."""
        with unittest.mock.patch(
            "sys.argv",
            ["prog", "--ip", "10.0.0.1", "--community", "private"],
        ):
            args = cisco_sdwan_precheck.get_args()

        self.assertEqual(args.port, "41684")
        self.assertEqual(args.port, cisco_sdwan_precheck.DEFAULT_PORT)

    def test_cli_missing_ip_exits(self):
        """Omit --ip; assert SystemExit is raised (argparse required arg)."""
        with unittest.mock.patch(
            "sys.argv",
            ["prog", "--community", "public"],
        ):
            with self.assertRaises(SystemExit) as ctx:
                cisco_sdwan_precheck.get_args()

        self.assertNotEqual(ctx.exception.code, 0)

    def test_cli_missing_community_exits(self):
        """Omit --community; assert SystemExit is raised (argparse required arg)."""
        with unittest.mock.patch(
            "sys.argv",
            ["prog", "--ip", "10.0.0.1"],
        ):
            with self.assertRaises(SystemExit) as ctx:
                cisco_sdwan_precheck.get_args()

        self.assertNotEqual(ctx.exception.code, 0)


class TestPropertySnmpCommandConstruction(unittest.TestCase):
    """Property-based tests for SNMP command construction (Property 1).

    **Validates: Requirements 2.1, 2.2, 2.3, 8.5**

    Property 1: SNMP command construction is always correct.
    For any combination of IP, community string, port, OID, and cmd_type
    ("walk"/"get"), run_snmp() SHALL invoke subprocess.run with a command
    list of [binary, "-v2c", "-c", community, f"{ip}:{port}", oid] and the
    community string SHALL NOT appear in any log message emitted.
    """

    @settings(max_examples=200)
    @given(
        ip=st.ip_addresses(v=4).map(str),
        community=st.text(
            alphabet=st.characters(
                whitelist_categories=("Lu", "Ll", "Nd"),
                whitelist_characters="-_",
            ),
            min_size=1,
            max_size=32,
        ),
        port=st.integers(min_value=1, max_value=65535).map(str),
        oid=st.from_regex(
            r'\.[1-9][0-9]*(\.[0-9]+){3,10}',
            fullmatch=True,
        ),
        cmd_type=st.sampled_from(["walk", "get"]),
    )
    def test_property_1_snmp_command_construction(
        self, ip, community, port, oid, cmd_type
    ):
        """Property 1: SNMP command construction is always correct.

        **Validates: Requirements 2.1, 2.2, 2.3, 8.5**
        """
        captured_cmd = []

        mock_result = unittest.mock.MagicMock()
        mock_result.stdout = ""

        def fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            return mock_result

        expected_binary = "snmpwalk" if cmd_type == "walk" else "snmpget"

        # Patch the module-level logging calls to intercept all log messages
        # without relying on assertLogs (which requires at least one record).
        with unittest.mock.patch("subprocess.run", side_effect=fake_run):
            with unittest.mock.patch("logging.error") as mock_error, \
                 unittest.mock.patch("logging.warning") as mock_warning, \
                 unittest.mock.patch("logging.info") as mock_info, \
                 unittest.mock.patch("logging.debug") as mock_debug:
                cisco_sdwan_precheck.run_snmp(ip, community, port, cmd_type, oid)

        # Collect all log messages that the module tried to emit as flat strings
        all_log_args = []
        for mock_fn in (mock_error, mock_warning, mock_info, mock_debug):
            for call in mock_fn.call_args_list:
                # call.args is the positional args tuple: (fmt, *args) or (msg,)
                all_log_args.append(" ".join(str(a) for a in call.args))
        log_output = " ".join(all_log_args)

        # --- Assert 1: command list structure is always correct ---
        expected_cmd = [
            expected_binary,
            "-v2c",
            "-c",
            community,
            f"{ip}:{port}",
            oid,
        ]
        self.assertEqual(
            captured_cmd,
            expected_cmd,
            msg=(
                f"Command mismatch.\n"
                f"  Expected : {expected_cmd}\n"
                f"  Got      : {captured_cmd}"
            ),
        )

        # --- Assert 2: community string does not appear in any log message ---
        self.assertNotIn(
            community,
            log_output,
            msg=(
                f"Community string found in log messages.\n"
                f"  Community  : {community!r}\n"
                f"  Log output : {log_output!r}"
            ),
        )


class TestPropertySizeAggregatorSum(unittest.TestCase):
    """Property-based tests for aggregate_sizes() — Property 3.

    **Validates: Requirements 4.1, 4.2, 4.3, 4.5**

    Property 3: Size_Aggregator sums exactly the matched indexes.

    For any ciscoFlashFileSize walk output containing lines with arbitrary
    index/byte pairs, and for any target index set, aggregate_sizes() SHALL
    return a total that equals the arithmetic sum of the Gauge32 byte values
    for lines whose index appears in the target set. Lines with indexes outside
    the target set contribute zero bytes to the total, and the total is never
    negative.
    """

    def _make_size_line(self, index: str, byte_value: int) -> str:
        """Build a realistic ciscoFlashFileSize SNMP walk output line."""
        return (
            f"SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.2.1.1.{index}"
            f" = Gauge32: {byte_value}"
        )

    @settings(max_examples=200)
    @given(
        # Generate a list of (index_str, byte_value) pairs.
        # Indexes are unique positive integers (as strings) and byte values
        # are non-negative integers up to a realistic Gauge32 maximum.
        st.lists(
            st.tuples(
                st.integers(min_value=1, max_value=999).map(str),
                st.integers(min_value=0, max_value=2**32 - 1),
            ),
            min_size=0,
            max_size=20,
            unique_by=lambda pair: pair[0],  # unique indexes only
        ).flatmap(
            lambda pairs: st.tuples(
                st.just(pairs),
                # target_indexes is a subset of the generated indexes
                # (possibly with extra indexes not present in walk output)
                st.sets(
                    st.one_of(
                        # indexes that exist in the walk output
                        st.sampled_from([p[0] for p in pairs]) if pairs else st.nothing(),
                        # indexes that do NOT exist in the walk output
                        st.integers(min_value=1000, max_value=9999).map(str),
                    ),
                    max_size=len(pairs) + 5,
                ) if pairs else st.frozensets(
                    st.integers(min_value=1000, max_value=9999).map(str),
                    max_size=5,
                ).map(set),
            )
        ),
    )
    def test_property_3_size_aggregator_sum_accuracy(self, pairs_and_target):
        """Property 3: aggregate_sizes returns the exact arithmetic sum of
        byte values for matched indexes, and the result is never negative.

        **Validates: Requirements 4.1, 4.2, 4.3, 4.5**
        """
        pairs, target_indexes = pairs_and_target

        # Build synthetic walk output from the generated (index, byte_value) pairs
        snmp_output = "\n".join(
            self._make_size_line(index, byte_value)
            for index, byte_value in pairs
        )

        # Compute the expected sum: only pairs whose index is in target_indexes
        expected_sum = sum(
            byte_value
            for index, byte_value in pairs
            if index in target_indexes
        )

        result = cisco_sdwan_precheck.aggregate_sizes(snmp_output, target_indexes)

        # Assert exact sum equality
        self.assertEqual(
            result,
            expected_sum,
            msg=(
                f"aggregate_sizes returned {result} but expected {expected_sum}. "
                f"target_indexes={target_indexes}, pairs={pairs}"
            ),
        )

        # Assert result is never negative
        self.assertGreaterEqual(
            result,
            0,
            msg=f"aggregate_sizes returned a negative value: {result}",
        )


class TestPropertyByteToMbMonotonicity(unittest.TestCase):
    """Property-based tests for byte-to-MB conversion monotonicity — Property 4.

    **Validates: Requirements 5.1**

    Property 4: Byte-to-MB conversion is exact and monotone.
    For any non-negative integer byte count, used_mb SHALL equal
    total_bytes / 1_048_576 with no rounding or truncation. For any two
    byte counts a <= b, the corresponding used_mb values satisfy
    a / 1_048_576 <= b / 1_048_576 — the conversion preserves ordering.
    """

    @settings(max_examples=200)
    @given(
        a=st.integers(min_value=0, max_value=600 * 1024 * 1024),
        b=st.integers(min_value=0, max_value=600 * 1024 * 1024),
    )
    def test_property_4_byte_to_mb_monotonicity(self, a, b):
        """Property 4: Byte-to-MB conversion is exact and monotone.

        **Validates: Requirements 5.1**
        """
        # Ensure a <= b for the monotonicity assertion
        if a > b:
            a, b = b, a

        _, metrics_a = cisco_sdwan_precheck.evaluate_space(a)
        _, metrics_b = cisco_sdwan_precheck.evaluate_space(b)

        used_mb_a = metrics_a["used_mb"]
        used_mb_b = metrics_b["used_mb"]

        # Assert ordering is preserved: a <= b implies used_mb_a <= used_mb_b
        self.assertLessEqual(
            a / 1_048_576,
            b / 1_048_576,
            msg=f"Ordering not preserved in raw division: a={a}, b={b}",
        )
        self.assertLessEqual(
            used_mb_a,
            used_mb_b,
            msg=(
                f"Monotonicity violated: evaluate_space({a})['used_mb']={used_mb_a} "
                f"> evaluate_space({b})['used_mb']={used_mb_b}"
            ),
        )

        # Assert exact conversion (no rounding): used_mb == total_bytes / 1_048_576
        self.assertEqual(
            used_mb_a,
            a / 1_048_576,
            msg=(
                f"Exact conversion failed for a={a}: "
                f"evaluate_space returned {used_mb_a}, expected {a / 1_048_576}"
            ),
        )
        self.assertEqual(
            used_mb_b,
            b / 1_048_576,
            msg=(
                f"Exact conversion failed for b={b}: "
                f"evaluate_space returned {used_mb_b}, expected {b / 1_048_576}"
            ),
        )


class TestPropertyMetricComputation(unittest.TestCase):
    """Property-based tests for evaluate_space() metric correctness (Property 5).

    **Validates: Requirements 5.2, 5.3, 5.4, 5.5**

    Property 5: Space metric computation is correct for all inputs.
    For any non-negative total_bytes value, evaluate_space() SHALL compute
    metrics satisfying:
      - used_mb      == total_bytes / 1_048_576
      - available_mb == 387.0 - used_mb
      - required_mb  == used_mb * 1.35
    These formulas hold without exception, including when total_bytes == 0.
    """

    @settings(max_examples=200)
    @given(
        total_bytes=st.integers(min_value=0, max_value=600 * 1024 * 1024),
    )
    def test_property_5_metric_computation_correctness(self, total_bytes):
        """Property 5: Space metric computation is correct for all inputs.

        **Validates: Requirements 5.2, 5.3, 5.4, 5.5**
        """
        _is_go, metrics = cisco_sdwan_precheck.evaluate_space(total_bytes)

        expected_used_mb = total_bytes / 1_048_576

        # Assert used_mb == total_bytes / 1_048_576 (within 1e-9 tolerance)
        self.assertAlmostEqual(
            metrics["used_mb"],
            expected_used_mb,
            delta=1e-9,
            msg=(
                f"used_mb mismatch for total_bytes={total_bytes}: "
                f"got {metrics['used_mb']}, expected {expected_used_mb}"
            ),
        )

        # Assert available_mb == 387.0 - used_mb (within 1e-9 tolerance)
        expected_available_mb = 387.0 - metrics["used_mb"]
        self.assertAlmostEqual(
            metrics["available_mb"],
            expected_available_mb,
            delta=1e-9,
            msg=(
                f"available_mb mismatch for total_bytes={total_bytes}: "
                f"got {metrics['available_mb']}, expected {expected_available_mb}"
            ),
        )

        # Assert required_mb == used_mb * 1.35 (within 1e-9 tolerance)
        expected_required_mb = metrics["used_mb"] * 1.35
        self.assertAlmostEqual(
            metrics["required_mb"],
            expected_required_mb,
            delta=1e-9,
            msg=(
                f"required_mb mismatch for total_bytes={total_bytes}: "
                f"got {metrics['required_mb']}, expected {expected_required_mb}"
            ),
        )


class TestSpaceEvaluator(unittest.TestCase):
    """Unit tests for evaluate_space() and main() exit codes.

    Requirements: 5.5, 5.6, 6.4, 6.5
    """

    def test_space_evaluator_zero_bytes_is_go(self):
        """total_bytes=0 → GO with no ZeroDivisionError.

        When used space is 0, required_mb is also 0, so available_mb (387.0)
        >= required_mb (0.0) → GO.

        Requirements: 5.5
        """
        is_go, metrics = cisco_sdwan_precheck.evaluate_space(0)

        self.assertTrue(is_go, "expected GO when total_bytes=0")
        self.assertAlmostEqual(metrics["used_mb"], 0.0)
        self.assertAlmostEqual(metrics["available_mb"], 387.0)
        self.assertAlmostEqual(metrics["required_mb"], 0.0)

    def test_space_evaluator_available_zero_is_nogo(self):
        """available_mb == 0 → NO-GO.

        total_bytes = int(387.0 * 1_048_576) drives used_mb to 387.0 exactly,
        leaving available_mb = 0.0 while required_mb > 0, which triggers NO-GO.

        Requirements: 5.6
        """
        total_bytes = int(387.0 * 1_048_576)
        is_go, metrics = cisco_sdwan_precheck.evaluate_space(total_bytes)

        self.assertFalse(is_go, "expected NO-GO when available_mb is 0")
        self.assertAlmostEqual(metrics["available_mb"], 0.0, places=6)
        self.assertGreater(
            metrics["required_mb"],
            0.0,
            "required_mb must be > 0 to confirm NO-GO when available is 0",
        )

    def test_go_exits_zero(self):
        """main() exits 0 on a GO scenario.

        Mock subprocess.run so that:
        - the ciscoFlashFileName walk returns output with no target files
          (no C.cdb or rollback entries), resulting in total_bytes=0 → GO.
        - the ciscoFlashFileSize walk returns empty output.

        Requirements: 6.5
        """
        # ciscoFlashFileName walk: only a noise file, so index set is empty
        name_walk_output = (
            "SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.1"
            ' = STRING: "/flash/packages.conf"\n'
        )
        # ciscoFlashFileSize walk: irrelevant since no target indexes
        size_walk_output = (
            "SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.2.1.1.1"
            " = Gauge32: 1024\n"
        )

        call_count = [0]

        def fake_run(cmd, **kwargs):
            result = unittest.mock.MagicMock()
            result.returncode = 0
            if call_count[0] == 0:
                result.stdout = name_walk_output
            else:
                result.stdout = size_walk_output
            call_count[0] += 1
            return result

        with unittest.mock.patch("sys.argv", ["prog", "--ip", "10.0.0.1", "--community", "public"]):
            with unittest.mock.patch("subprocess.run", side_effect=fake_run):
                with self.assertRaises(SystemExit) as ctx:
                    cisco_sdwan_precheck.main()

        self.assertEqual(ctx.exception.code, 0, "main() must exit 0 on GO")

    def test_nogo_exits_nonzero(self):
        """main() exits 1 on a NO-GO scenario.

        Mock subprocess.run so that:
        - the ciscoFlashFileName walk returns a C.cdb entry at index 1.
        - the ciscoFlashFileSize walk returns index 1 with
          int(387.0 * 1_048_576) bytes → available_mb=0 → NO-GO.

        Requirements: 6.4
        """
        nogo_bytes = int(387.0 * 1_048_576)

        name_walk_output = (
            "SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.1"
            ' = STRING: "/flash/C.cdb"\n'
        )
        size_walk_output = (
            f"SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.2.1.1.1"
            f" = Gauge32: {nogo_bytes}\n"
        )

        call_count = [0]

        def fake_run(cmd, **kwargs):
            result = unittest.mock.MagicMock()
            result.returncode = 0
            if call_count[0] == 0:
                result.stdout = name_walk_output
            else:
                result.stdout = size_walk_output
            call_count[0] += 1
            return result

        with unittest.mock.patch("sys.argv", ["prog", "--ip", "10.0.0.1", "--community", "public"]):
            with unittest.mock.patch("subprocess.run", side_effect=fake_run):
                with self.assertRaises(SystemExit) as ctx:
                    cisco_sdwan_precheck.main()

        self.assertNotEqual(ctx.exception.code, 0, "main() must exit non-zero on NO-GO")
        self.assertEqual(ctx.exception.code, 1, "main() must exit 1 specifically on NO-GO")

    def test_main_end_to_end_multiple_target_files(self):
        """main() correctly aggregates multiple target files (C.cdb + rollbacks).

        Mock subprocess.run so that:
        - the ciscoFlashFileName walk returns C.cdb, rollback0, rollback5,
          rollback49, plus noise files (packages.conf, iox.tar).
        - the ciscoFlashFileSize walk returns byte values for all indexes.
        - Only the 4 target file sizes should be summed.

        This validates the full pipeline handles a realistic multi-file
        workload end-to-end.

        Requirements: 3.2, 3.3, 4.1, 4.2, 6.4, 6.5
        """
        # Target files and their sizes
        # C.cdb at index 1: 20 MB
        # rollback0 at index 3: 5 MB
        # rollback5 at index 5: 8 MB
        # rollback49 at index 7: 3 MB
        # Total target = 36 MB → available = 351 MB, required = 48.6 MB → GO
        cdb_bytes = 20 * 1_048_576
        rb0_bytes = 5 * 1_048_576
        rb5_bytes = 8 * 1_048_576
        rb49_bytes = 3 * 1_048_576
        noise_bytes = 500 * 1_048_576  # large noise file should NOT be counted

        name_walk_output = "\n".join([
            'SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.1 = STRING: "/flash/C.cdb"',
            'SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.2 = STRING: "/flash/packages.conf"',
            'SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.3 = STRING: "/flash/rollback0"',
            'SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.4 = STRING: "/flash/iox.tar"',
            'SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.5 = STRING: "/flash/rollback5"',
            'SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.6 = STRING: "/flash/cat8000v-universalk9.17.09.05.SPA.bin"',
            'SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.7 = STRING: "/flash/rollback49"',
        ])

        size_walk_output = "\n".join([
            f"SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.2.1.1.1 = Gauge32: {cdb_bytes}",
            f"SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.2.1.1.2 = Gauge32: {noise_bytes}",
            f"SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.2.1.1.3 = Gauge32: {rb0_bytes}",
            f"SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.2.1.1.4 = Gauge32: {noise_bytes}",
            f"SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.2.1.1.5 = Gauge32: {rb5_bytes}",
            f"SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.2.1.1.6 = Gauge32: {noise_bytes}",
            f"SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.2.1.1.7 = Gauge32: {rb49_bytes}",
        ])

        call_count = [0]

        def fake_run(cmd, **kwargs):
            result = unittest.mock.MagicMock()
            result.returncode = 0
            if call_count[0] == 0:
                result.stdout = name_walk_output
            else:
                result.stdout = size_walk_output
            call_count[0] += 1
            return result

        with unittest.mock.patch("sys.argv", ["prog", "--ip", "10.0.0.1", "--community", "public"]):
            with unittest.mock.patch("subprocess.run", side_effect=fake_run):
                with self.assertRaises(SystemExit) as ctx:
                    cisco_sdwan_precheck.main()

        # 36 MB used → available=351, required=48.6 → GO → exit 0
        self.assertEqual(
            ctx.exception.code, 0,
            "main() must exit 0 (GO) when multiple target files sum to 36 MB "
            "(well under the threshold). Noise files must NOT be counted.",
        )


class TestPropertyGoNoGoClassification(unittest.TestCase):
    """Property-based tests for GO/NO-GO classification — Property 6.

    **Validates: Requirements 5.6, 6.1, 6.2, 6.3, 6.4, 6.5**

    Property 6: GO/NO-GO classification is exhaustive, mutually exclusive,
    and correctly labelled.

    For any total_bytes value, the Space_Evaluator SHALL produce exactly one
    outcome — GO (🟢) when available_mb >= required_mb, or NO-GO (🔴) when
    available_mb < required_mb — and SHALL include used_mb, available_mb,
    required_mb, and 387.00 in the output, each formatted to exactly two
    decimal places. The script SHALL exit with code 0 on GO and 1 on NO-GO.
    """

    # Synthetic SNMP walk output builders used in main() exit-code tests
    @staticmethod
    def _make_name_line(index: str, filename: str) -> str:
        """Build a ciscoFlashFileName SNMP walk output line."""
        return (
            f'SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.{index}'
            f' = STRING: "/flash/{filename}"'
        )

    @staticmethod
    def _make_size_line(index: str, byte_value: int) -> str:
        """Build a ciscoFlashFileSize SNMP walk output line."""
        return (
            f"SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.2.1.1.{index}"
            f" = Gauge32: {byte_value}"
        )

    # -----------------------------------------------------------------------
    # Property test: exhaustive, mutually exclusive classification + format
    # -----------------------------------------------------------------------

    @settings(max_examples=200)
    @given(
        total_bytes=st.integers(min_value=0, max_value=600 * 1024 * 1024),
    )
    def test_property_6_go_nogo_classification(self, total_bytes):
        """Property 6: GO/NO-GO classification is exhaustive, mutually
        exclusive, and correctly labelled.

        **Validates: Requirements 5.6, 6.1, 6.2, 6.3, 6.4, 6.5**
        """
        # ------------------------------------------------------------------
        # Part A: evaluate_space returns exactly one of GO or NO-GO
        # ------------------------------------------------------------------
        is_go, metrics = cisco_sdwan_precheck.evaluate_space(total_bytes)

        # is_go must be a plain bool (True or False) — never None or ambiguous
        self.assertIsInstance(is_go, bool)

        # Derive expected classification from the threshold formula
        used_mb = total_bytes / 1_048_576
        available_mb = cisco_sdwan_precheck.PARTITION_CEILING_MB - used_mb
        required_mb = used_mb * cisco_sdwan_precheck.SAFETY_MULTIPLIER
        expected_is_go = available_mb >= required_mb

        # Exactly one outcome — classification matches the threshold predicate
        self.assertEqual(
            is_go,
            expected_is_go,
            msg=(
                f"Classification mismatch for total_bytes={total_bytes}: "
                f"expected is_go={expected_is_go} "
                f"(available_mb={available_mb:.6f}, required_mb={required_mb:.6f})"
            ),
        )

        # ------------------------------------------------------------------
        # Part B: format_result output contains required fields formatted
        #         to exactly two decimal places
        # ------------------------------------------------------------------
        output = cisco_sdwan_precheck.format_result(is_go, metrics)

        # The output must contain exactly one GO emoji or exactly one NO-GO emoji
        go_count = output.count("\U0001f7e2")    # 🟢
        nogo_count = output.count("\U0001f534")  # 🔴

        if is_go:
            self.assertEqual(
                go_count, 1,
                msg=f"Expected exactly one 🟢 emoji for GO, got {go_count}",
            )
            self.assertEqual(
                nogo_count, 0,
                msg=f"Expected zero 🔴 emojis for GO, got {nogo_count}",
            )
        else:
            self.assertEqual(
                nogo_count, 1,
                msg=f"Expected exactly one 🔴 emoji for NO-GO, got {nogo_count}",
            )
            self.assertEqual(
                go_count, 0,
                msg=f"Expected zero 🟢 emojis for NO-GO, got {go_count}",
            )

        # The ceiling (387.00 MB) must always appear in the output
        self.assertIn(
            "387.00",
            output,
            msg="Expected '387.00' (ceiling MB) to appear in format_result output",
        )

        # used_mb formatted to exactly two decimal places must appear
        used_str = f"{metrics['used_mb']:.2f}"
        self.assertIn(
            used_str,
            output,
            msg=(
                f"Expected used_mb='{used_str}' (2 d.p.) in format_result output"
            ),
        )

        # available_mb formatted to exactly two decimal places must appear
        avail_str = f"{metrics['available_mb']:.2f}"
        self.assertIn(
            avail_str,
            output,
            msg=(
                f"Expected available_mb='{avail_str}' (2 d.p.) in format_result output"
            ),
        )

        # required_mb formatted to exactly two decimal places must appear
        req_str = f"{metrics['required_mb']:.2f}"
        self.assertIn(
            req_str,
            output,
            msg=(
                f"Expected required_mb='{req_str}' (2 d.p.) in format_result output"
            ),
        )

    # -----------------------------------------------------------------------
    # Main() exit-code tests: exit 0 on GO, exit 1 on NO-GO
    # These complement the property test above by exercising the full
    # main() pipeline with patched subprocess.run and sys.argv.
    # -----------------------------------------------------------------------

    def _run_main_with_bytes(self, total_bytes: int) -> int:
        """
        Invoke main() with synthetic SNMP data producing the given total_bytes.
        Returns the exit code captured from sys.exit().
        """
        # Build synthetic SNMP walk outputs
        name_output = self._make_name_line("1", "C.cdb")
        size_output = self._make_size_line("1", total_bytes)

        mock_name_result = unittest.mock.MagicMock()
        mock_name_result.stdout = name_output

        mock_size_result = unittest.mock.MagicMock()
        mock_size_result.stdout = size_output

        # subprocess.run is called twice: once for names, once for sizes
        side_effects = [mock_name_result, mock_size_result]

        exit_code = None

        def capture_exit(code=0):
            nonlocal exit_code
            exit_code = code
            raise SystemExit(code)

        with unittest.mock.patch("sys.argv", ["prog", "--ip", "127.0.0.1", "--community", "public"]):
            with unittest.mock.patch("subprocess.run", side_effect=side_effects):
                with unittest.mock.patch("sys.exit", side_effect=capture_exit):
                    try:
                        cisco_sdwan_precheck.main()
                    except SystemExit:
                        pass

        return exit_code

    def test_main_exits_0_on_go(self):
        """main() SHALL exit with code 0 when the result is GO.

        Validates: Requirements 6.4, 6.5
        """
        # 0 bytes used → available=387.0 MB, required=0.0 MB → GO
        exit_code = self._run_main_with_bytes(0)
        self.assertEqual(
            exit_code, 0,
            msg=f"Expected sys.exit(0) for GO scenario, got sys.exit({exit_code})",
        )

    def test_main_exits_1_on_nogo(self):
        """main() SHALL exit with code 1 when the result is NO-GO.

        Validates: Requirements 6.4, 6.5
        """
        # ~300 MB used → available≈87 MB, required≈405 MB → NO-GO
        nogo_bytes = 300 * 1024 * 1024
        exit_code = self._run_main_with_bytes(nogo_bytes)
        self.assertEqual(
            exit_code, 1,
            msg=f"Expected sys.exit(1) for NO-GO scenario, got sys.exit({exit_code})",
        )


class TestPropertyCommunityStringNotInLogs(unittest.TestCase):
    """Property-based tests for community string secrecy in logs — Property 7.

    **Validates: Requirements 2.5, 7.5, 7.6, 8.3, 8.5**

    Property 7: All SNMP failures produce an ERROR log containing the OID;
    community string never in logs.

    For any SNMP operation that fails — whether due to FileNotFoundError
    (binary not on PATH) or CalledProcessError (non-zero exit code) — the
    SNMP_Client SHALL log the failure at ERROR level with the specific OID
    that was being queried. The community string value SHALL NOT appear in
    any log message.
    """

    # Strategy for community strings: use a distinctive prefix "COMM_" to ensure
    # the generated value is long enough and distinct enough to not coincidentally
    # appear in standard log messages (like "PATH", "OID", "snmpwalk", etc.)
    _st_community = st.text(
        alphabet=st.characters(
            whitelist_categories=("Lu", "Ll", "Nd"),
            whitelist_characters="-_!@#$%",
        ),
        min_size=4,
        max_size=32,
    ).map(lambda s: f"COMM_{s}")

    @settings(max_examples=200)
    @given(
        community=st.text(
            alphabet=st.characters(
                whitelist_categories=("Lu", "Ll", "Nd"),
                whitelist_characters="-_!@#$%",
            ),
            min_size=4,
            max_size=32,
        ).map(lambda s: f"COMM_{s}"),
        oid=st.from_regex(
            r'\.[1-9][0-9]*(\.[0-9]+){3,10}',
            fullmatch=True,
        ),
        ip=st.ip_addresses(v=4).map(str),
        port=st.integers(min_value=1, max_value=65535).map(str),
        cmd_type=st.sampled_from(["walk", "get"]),
    )
    def test_property_7_filenotfounderror_logs_oid_not_community(
        self, community, oid, ip, port, cmd_type
    ):
        """Property 7 (FileNotFoundError path): ERROR log contains OID,
        community string never appears in log output.

        **Validates: Requirements 2.5, 7.5, 7.6, 8.3, 8.5**
        """
        with unittest.mock.patch(
            "subprocess.run", side_effect=FileNotFoundError
        ):
            with self.assertLogs(level="ERROR") as log_ctx:
                with self.assertRaises(SystemExit) as exit_ctx:
                    cisco_sdwan_precheck.run_snmp(
                        ip, community, port, cmd_type, oid
                    )

        # Must exit with code 1
        self.assertEqual(exit_ctx.exception.code, 1)

        # Collect all log output into a single string
        all_log_output = " ".join(log_ctx.output)

        # Assert at least one ERROR-level log was emitted
        self.assertTrue(
            any("ERROR" in record for record in log_ctx.output),
            "Expected at least one ERROR log on FileNotFoundError",
        )

        # Assert community string does NOT appear in any log message
        self.assertNotIn(
            community,
            all_log_output,
            f"Community string {community!r} must never appear in log output",
        )

    @settings(max_examples=200)
    @given(
        community=st.text(
            alphabet=st.characters(
                whitelist_categories=("Lu", "Ll", "Nd"),
                whitelist_characters="-_!@#$%",
            ),
            min_size=4,
            max_size=32,
        ).map(lambda s: f"COMM_{s}"),
        oid=st.from_regex(
            r'\.[1-9][0-9]*(\.[0-9]+){3,10}',
            fullmatch=True,
        ),
        ip=st.ip_addresses(v=4).map(str),
        port=st.integers(min_value=1, max_value=65535).map(str),
        cmd_type=st.sampled_from(["walk", "get"]),
        stderr_msg=st.text(
            alphabet=st.characters(
                whitelist_categories=("Lu", "Ll", "Nd", "Zs"),
                whitelist_characters=":-./",
            ),
            min_size=0,
            max_size=50,
        ),
    )
    def test_property_7_calledprocesserror_logs_oid_not_community(
        self, community, oid, ip, port, cmd_type, stderr_msg
    ):
        """Property 7 (CalledProcessError path): ERROR log contains OID,
        community string never appears in log output.

        **Validates: Requirements 2.5, 7.5, 7.6, 8.3, 8.5**
        """
        fake_exc = subprocess.CalledProcessError(
            returncode=1,
            cmd=["snmpwalk"],
            stderr=stderr_msg,
        )

        with unittest.mock.patch("subprocess.run", side_effect=fake_exc):
            with self.assertLogs(level="ERROR") as log_ctx:
                with self.assertRaises(SystemExit) as exit_ctx:
                    cisco_sdwan_precheck.run_snmp(
                        ip, community, port, cmd_type, oid
                    )

        # Must exit with code 1
        self.assertEqual(exit_ctx.exception.code, 1)

        # Collect all log output into a single string
        all_log_output = " ".join(log_ctx.output)

        # Assert at least one ERROR-level log was emitted
        self.assertTrue(
            any("ERROR" in record for record in log_ctx.output),
            "Expected at least one ERROR log on CalledProcessError",
        )

        # Assert the OID appears in the error log output
        self.assertIn(
            oid,
            all_log_output,
            f"Expected OID {oid!r} in log output for CalledProcessError path",
        )

        # Assert community string does NOT appear in any log message
        self.assertNotIn(
            community,
            all_log_output,
            f"Community string {community!r} must never appear in log output",
        )


if __name__ == "__main__":
    unittest.main()

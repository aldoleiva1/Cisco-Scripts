#!/usr/bin/env python3
"""
cisco_sdwan_precheck.py — Cisco Catalyst 8000 SD-WAN Storage Pre-Check Utility

Performs a point-in-time storage health check on Cisco Catalyst 8000 series
routers running IOS XE SD-WAN before performing an image upgrade.

The script walks the Cisco Flash MIB via SNMPv2c to identify and size the
files that matter for the upgrade: the confd configuration database (C.cdb)
and any active rollback entries (rollback0–rollback49). It aggregates their
byte sizes, converts to megabytes, and produces an unambiguous GO or NO-GO
decision against a fixed 387 MB partition ceiling with a 1.35x safety
multiplier.

Execution environments:
  - External Linux monitoring server: query router management IP over the network
  - Cisco Guestshell: on-device container, query 127.0.0.1 or internal vMI

Usage:
    python3 cisco_sdwan_precheck.py --ip <router-ip> \\
                                    --community <snmp-community> \\
                                    [--port <udp-port>]

Requirements: Python 3.6+, net-snmp tools (snmpwalk) on PATH.
No third-party Python packages required.
"""

import argparse
import logging
import re
import subprocess
import sys

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

PARTITION_CEILING_MB: float = 387.0
# Fixed .sdwaninstaller partition size for Catalyst 8000 SD-WAN.
# Does NOT change across IOS XE SD-WAN releases within the supported train.

SAFETY_MULTIPLIER: float = 1.35
# Headroom factor: 1.25 (Cisco architecture overhead) + 0.10 (compression buffer).
# Required_Space_MB = Used_Space_MB * 1.35

DEFAULT_PORT: str = "41684"
# Default SNMP UDP port for Cisco SD-WAN management plane SNMP access.

OID_FLASH_FILE_NAME: str = ".1.3.6.1.4.1.9.9.10.1.1.4.2.1.1.5.1.1"
# ciscoFlashFileName subtree — CISCO-FLASH-MIB

OID_FLASH_FILE_SIZE: str = ".1.3.6.1.4.1.9.9.10.1.1.4.2.1.1.2.1.1"
# ciscoFlashFileSize subtree — Gauge32 values in bytes

MAX_ROLLBACK_INDEX: int = 49
# Maximum rollback file index accepted (rollback0 through rollback49)

# ---------------------------------------------------------------------------
# Compiled regex patterns (module level for performance)
# ---------------------------------------------------------------------------

FILENAME_PATTERN = re.compile(
    r'\.5\.1\.1\.(\d+)\s+=\s+STRING:\s+"[^"]*?([^/"]+)"'
)
# group(1) = SNMP index string
# group(2) = filename (last path component, no slashes)

FILESIZE_PATTERN = re.compile(r'\.2\.1\.1\.(\d+)\s+=\s+Gauge32:\s+(\d+)')
# group(1) = SNMP index string
# group(2) = byte count as string

ROLLBACK_PATTERN = re.compile(r'^rollback(\d+)$')
# Matches rollback files; group(1) = numeric suffix for range check [0, 49]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def get_args() -> argparse.Namespace:
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Cisco SD-WAN Storage Pre-Check — "
            "determines GO/NO-GO before an IOS XE SD-WAN image upgrade "
            "by querying the Cisco Flash MIB via SNMPv2c."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--ip",
        required=True,
        metavar="ROUTER_IP",
        help="Target router IP address (use 127.0.0.1 inside Guestshell).",
    )
    parser.add_argument(
        "--community",
        required=True,
        metavar="COMMUNITY",
        help="SNMPv2c read-only community string.",
    )
    parser.add_argument(
        "--port",
        default=DEFAULT_PORT,
        metavar="UDP_PORT",
        help="SNMP UDP port.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def configure_logging() -> None:
    """Configure the root logger to emit INFO+ to stderr with timestamps."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Component 1: SNMP_Client
# ---------------------------------------------------------------------------

def run_snmp(ip: str, community: str, port: str, cmd_type: str, oid: str) -> str:
    """
    Execute an SNMP command against the target router.

    Parameters:
        ip        : target router IP
        community : SNMPv2c community string (never logged)
        port      : SNMP UDP port string
        cmd_type  : "walk" or "get"
        oid       : dotted-decimal OID string

    Returns:
        stdout string from the SNMP command

    Raises:
        SystemExit(1) after logging ERROR for:
          - FileNotFoundError  (binary not on PATH)
          - CalledProcessError (non-zero exit code)
    """
    binary = "snmpwalk" if cmd_type == "walk" else "snmpget"
    cmd = [binary, "-v2c", "-c", community, f"{ip}:{port}", oid]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except FileNotFoundError:
        logging.error(
            "SNMP binary '%s' not found on PATH. "
            "Install net-snmp tools and ensure they are on PATH.",
            binary,
        )
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        logging.error(
            "SNMP %s failed for OID %s: %s",
            cmd_type,
            oid,
            exc.stderr.strip(),
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Component 2: File_Indexer
# ---------------------------------------------------------------------------

def index_target_files(snmp_output: str) -> set:
    """
    Parse ciscoFlashFileName walk output.

    Returns:
        set of string index values for C.cdb and rollback0–rollback49.
        Logs WARNING and returns empty set if no matches found.
    """
    target_indexes = set()
    for line in snmp_output.splitlines():
        match = FILENAME_PATTERN.search(line)
        if not match:
            continue
        index, filename = match.group(1), match.group(2)
        if filename == "C.cdb":
            target_indexes.add(index)
        else:
            rb_match = ROLLBACK_PATTERN.fullmatch(filename)
            if rb_match and 0 <= int(rb_match.group(1)) <= MAX_ROLLBACK_INDEX:
                target_indexes.add(index)

    if not target_indexes:
        logging.warning(
            "No target files (C.cdb or rollback0–rollback49) found in "
            "ciscoFlashFileName walk output. Used space will be treated as 0."
        )
    return target_indexes


# ---------------------------------------------------------------------------
# Component 3: Size_Aggregator
# ---------------------------------------------------------------------------

def aggregate_sizes(snmp_output: str, target_indexes: set) -> int:
    """
    Parse ciscoFlashFileSize walk output.

    Returns:
        Total bytes (int) for all matched indexes.
        Returns 0 if target_indexes is empty or no indexes match.
    """
    if snmp_output is None:
        logging.error(
            "ciscoFlashFileSize walk returned None — cannot aggregate sizes."
        )
        sys.exit(1)

    total_bytes = 0
    for line in snmp_output.splitlines():
        match = FILESIZE_PATTERN.search(line)
        if match and match.group(1) in target_indexes:
            total_bytes += int(match.group(2))
    return total_bytes


# ---------------------------------------------------------------------------
# Component 4: Space_Evaluator
# ---------------------------------------------------------------------------

def evaluate_space(total_bytes: int) -> tuple:
    """
    Convert bytes to MB and compute GO/NO-GO threshold.

    Returns:
        (is_go: bool, metrics: dict)
        metrics keys: used_mb, available_mb, required_mb, ceiling_mb
    """
    used_mb = total_bytes / 1_048_576
    available_mb = PARTITION_CEILING_MB - used_mb
    required_mb = used_mb * SAFETY_MULTIPLIER
    is_go = available_mb >= required_mb
    metrics = {
        "used_mb": used_mb,
        "available_mb": available_mb,
        "required_mb": required_mb,
        "ceiling_mb": PARTITION_CEILING_MB,
    }
    return is_go, metrics


def format_result(is_go: bool, metrics: dict) -> str:
    """
    Render the GO/NO-GO output string with emoji prefix and metric values
    formatted to exactly two decimal places.
    """
    used = metrics["used_mb"]
    avail = metrics["available_mb"]
    req = metrics["required_mb"]
    ceil_mb = metrics["ceiling_mb"]

    separator = "=" * 60
    thin_sep = "-" * 60

    if is_go:
        decision_line = (
            f"\U0001f7e2 GO \u2014 Safe to proceed with upgrade.\n"
            f"   Available ({avail:.2f} MB) >= Required ({req:.2f} MB)"
        )
    else:
        decision_line = (
            f"\U0001f534 NO-GO \u2014 Insufficient space for upgrade.\n"
            f"   Available ({avail:.2f} MB) < Required ({req:.2f} MB)"
        )

    lines = [
        separator,
        "  Cisco SD-WAN Storage Pre-Check \u2014 Point-in-Time Inventory",
        separator,
        "",
        thin_sep,
        "  Metric Calculations",
        thin_sep,
        f"  Used Space         : {used:>8.2f} MB",
        f"  Available Space    : {avail:>8.2f} MB"
        f"   ({ceil_mb:.2f} MB ceiling \u2212 used)",
        f"  Required Headroom  : {req:>8.2f} MB"
        f"   (used \u00d7 {SAFETY_MULTIPLIER} safety multiplier)",
        thin_sep,
        "",
        decision_line,
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def main() -> None:
    """Main entry point — orchestrates the three-phase pre-check pipeline."""
    configure_logging()
    args = get_args()

    # Phase 1: File Indexing
    logging.info("Walking ciscoFlashFileName OID: %s", OID_FLASH_FILE_NAME)
    name_raw = run_snmp(args.ip, args.community, args.port, "walk", OID_FLASH_FILE_NAME)
    target_indexes = index_target_files(name_raw)
    logging.info("Discovered %d target file(s)", len(target_indexes))

    # Phase 2: Size Aggregation
    logging.info("Walking ciscoFlashFileSize OID: %s", OID_FLASH_FILE_SIZE)
    size_raw = run_snmp(args.ip, args.community, args.port, "walk", OID_FLASH_FILE_SIZE)
    total_bytes = aggregate_sizes(size_raw, target_indexes)
    used_mb = total_bytes / 1_048_576
    logging.info("Aggregated byte total: %d bytes (%.2f MB)", total_bytes, used_mb)

    # Phase 3: Evaluation and Output
    is_go, metrics = evaluate_space(total_bytes)
    print(format_result(is_go, metrics))

    if is_go:
        logging.info("Result: GO \u2014 safe to proceed with upgrade.")
        sys.exit(0)
    else:
        logging.error("Result: NO-GO \u2014 insufficient space for upgrade.")
        sys.exit(1)


if __name__ == "__main__":
    main()

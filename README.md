# Cisco SD-WAN Storage Pre-Check

A point-in-time storage health check for **Cisco Catalyst 8000 series routers running IOS XE SD-WAN** before performing an image upgrade.

## Why This Exists

Cisco Catalyst 8000 SD-WAN routers have a fixed-size `.sdwaninstaller` partition (387 MB) used during IOS XE image upgrades for staging rollback files and the confd configuration database (`C.cdb`). If this partition lacks sufficient free space when an upgrade is initiated, the upgrade can fail mid-process — a known risk that may require manual recovery or TAC engagement.

This script answers one question before you commit to an upgrade:

> **Is there enough space on the `.sdwaninstaller` partition to safely stage the upgrade?**

It queries the router's Cisco Flash MIB via SNMPv2c, identifies the files that consume partition space (`C.cdb` and `rollback0`–`rollback49`), sums their sizes, applies a 1.35× safety multiplier (covering Cisco architecture overhead + compression buffer), and returns a clear **GO** or **NO-GO** decision.

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│  Phase 1: File Indexing                                 │
│  Walk ciscoFlashFileName OID → identify C.cdb and       │
│  rollback0–rollback49 by SNMP index                     │
├─────────────────────────────────────────────────────────┤
│  Phase 2: Size Aggregation                              │
│  Walk ciscoFlashFileSize OID → sum byte sizes for       │
│  matched indexes only                                   │
├─────────────────────────────────────────────────────────┤
│  Phase 3: Evaluation                                    │
│  Convert to MB, apply 1.35× multiplier, compare         │
│  against 387 MB ceiling → GO or NO-GO                   │
└─────────────────────────────────────────────────────────┘
```

### Decision Logic Explained

The script doesn't know the size of the new IOS XE image you're installing — what it checks is whether the **partition has enough room** for the upgrade process to complete safely.

Here's the logic:

```
Used_MB       = sum(C.cdb + rollback files) / 1,048,576
Available_MB  = 387.0 - Used_MB
Required_MB   = Used_MB × 1.35  (safety headroom for staging/decompression)

GO     → Available_MB >= Required_MB  (exit code 0)
NO-GO  → Available_MB <  Required_MB  (exit code 1)
```

**Why this works:** During an IOS XE SD-WAN upgrade, the router needs temporary space on the `.sdwaninstaller` partition to stage rollback snapshots and decompress image components. The 1.35× multiplier is a design-time safety factor chosen to provide headroom for architecture overhead and compression buffers. Adjust `SAFETY_MULTIPLIER` in the script if your operational experience suggests a different value.

The GO result means: *"There is enough free space on the partition for the upgrade staging process to succeed."* It's safe to proceed with installing your target image (e.g., 17.18.5).

The NO-GO result means: *"The existing rollback files and C.cdb are consuming too much space — the upgrade process will likely fail during staging."*

**Important:** This check validates partition headroom, not whether the target image itself will fit on `bootflash:`. Image file storage uses a separate, much larger filesystem. This script specifically addresses the known failure mode where the constrained `.sdwaninstaller` partition runs out of space mid-upgrade.

## Requirements

- **Python 3.6+** (standard library only — no pip packages needed for runtime)
- **net-snmp tools** (`snmpwalk` binary on PATH)
- **SNMPv2c read access** to the target router

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/aldoleiva1/Cisco-Scripts.git
cd Cisco-Scripts
```

### 2. Run from a Remote Linux/macOS Host

```bash
python3 cisco_sdwan_precheck.py \
    --ip 10.1.1.1 \
    --community your_community_string \
    --port 161
```

### 3. Run from Cisco Guestshell (On-Device)

```bash
python3 cisco_sdwan_precheck.py \
    --ip 127.0.0.1 \
    --community your_community_string \
    --port 41684
```

## CLI Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--ip` | Yes | — | Target router IP. Use `127.0.0.1` inside Guestshell. |
| `--community` | Yes | — | SNMPv2c read-only community string. |
| `--port` | No | `41684` | SNMP UDP port. Use `161` for standard remote access. |

## Environment Variables to Adjust

The script uses module-level constants. If your environment differs from the defaults, edit these values in `cisco_sdwan_precheck.py`:

| Constant | Default | When to Change |
|----------|---------|----------------|
| `PARTITION_CEILING_MB` | `387.0` | Only if Cisco changes the `.sdwaninstaller` partition size in a future release. |
| `SAFETY_MULTIPLIER` | `1.35` | Adjust based on operational experience. This is a design-time safety factor for staging headroom. |
| `DEFAULT_PORT` | `"41684"` | If your SD-WAN management plane uses a different SNMP port. Standard SNMP is `161`. |
| `MAX_ROLLBACK_INDEX` | `49` | If rollback file range changes. Currently `rollback0`–`rollback49`. |

## Output Examples

### GO Result

```
============================================================
  Cisco SD-WAN Storage Pre-Check — Point-in-Time Inventory
============================================================

------------------------------------------------------------
  Metric Calculations
------------------------------------------------------------
  Used Space         :    45.23 MB
  Available Space    :   341.77 MB   (387.00 MB ceiling − used)
  Required Headroom  :    61.06 MB   (used × 1.35 safety multiplier)
------------------------------------------------------------

🟢 GO — Safe to proceed with upgrade.
   Available (341.77 MB) >= Required (61.06 MB)
```

### NO-GO Result

```
============================================================
  Cisco SD-WAN Storage Pre-Check — Point-in-Time Inventory
============================================================

------------------------------------------------------------
  Metric Calculations
------------------------------------------------------------
  Used Space         :   298.50 MB
  Available Space    :    88.50 MB   (387.00 MB ceiling − used)
  Required Headroom  :   403.00 MB   (used × 1.35 safety multiplier)
------------------------------------------------------------

🔴 NO-GO — Insufficient space for upgrade.
   Available (88.50 MB) < Required (403.00 MB)
```

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| `0` | GO — safe to proceed | Continue with the IOS XE image upgrade. |
| `1` | NO-GO — insufficient space | Clear rollback files or free partition space before upgrading. See [Next Steps on NO-GO](#next-steps-on-no-go). |

## Next Steps on NO-GO

If the script returns NO-GO, the partition needs space freed before upgrading. The commands below are typical for IOS XE SD-WAN — **verify they apply to your software version before running them:**

1. **Clear old rollback files** from IOS XE CLI (verify syntax for your version):
   ```
   request platform software sdwan rollback clean
   ```

2. **Verify space was freed** by re-running the pre-check:
   ```bash
   python3 cisco_sdwan_precheck.py --ip <router-ip> --community <community> --port <port>
   ```

3. **If still NO-GO**, investigate which files are consuming space:
   ```
   dir bootflash:.sdwaninstaller/
   ```
   Consider removing stale backup files or contacting Cisco TAC if the configuration database itself exceeds safe thresholds.

4. **Proceed with upgrade only after receiving a GO result.**

## Deploying to Cisco Guestshell

Guestshell is a Linux container running directly on the router with localhost SNMP access to the host IOS XE instance. The examples below show common deployment patterns — **verify paths and package manager commands match your Guestshell version.**

### Option A: SCP from a Jump Host

```bash
# From your workstation/jump host (adjust destination path for your environment):
scp cisco_sdwan_precheck.py admin@<router-ip>:cisco_sdwan_precheck.py

# Then from the router CLI, enter Guestshell and run:
guestshell
python3 /bootflash/cisco_sdwan_precheck.py \
    --ip 127.0.0.1 --community <community> --port 41684
```

### Option B: TFTP Transfer

```bash
# On the router IOS XE CLI:
copy tftp://<tftp-server>/cisco_sdwan_precheck.py bootflash:

# Then from Guestshell:
guestshell
python3 /bootflash/cisco_sdwan_precheck.py \
    --ip 127.0.0.1 --community <community> --port 41684
```

### Option C: FTP Transfer

```bash
# On the router IOS XE CLI:
copy ftp://<user>:<password>@<ftp-server>/cisco_sdwan_precheck.py bootflash:

# Then from Guestshell:
guestshell
python3 /bootflash/cisco_sdwan_precheck.py \
    --ip 127.0.0.1 --community <community> --port 41684
```

### Guestshell Prerequisites

1. **Guestshell must be enabled:**
   ```
   guestshell enable
   ```

2. **SNMP must be configured on the router:**
   ```
   snmp-server community <community> RO
   ```

3. **Python 3 must be available inside Guestshell:**
   ```bash
   # Inside Guestshell — verify Python is present:
   python3 --version
   ```

4. **net-snmp tools must be available inside Guestshell:**
   ```bash
   which snmpwalk
   # If not found, install (package manager may vary by Guestshell version):
   sudo yum install -y net-snmp-utils   # CentOS-based Guestshell
   # or
   sudo dnf install -y net-snmp-utils   # newer versions
   ```

5. **Verify SNMP connectivity from Guestshell:**
   ```bash
   snmpwalk -v2c -c <community> 127.0.0.1:41684 .1.3.6.1.2.1.1.1.0
   ```
   If this returns the router's sysDescr, you're ready to run the script.

## Running the Tests

### When to Run Tests

Run the test suite:
- **After cloning** — to verify everything works in your Python environment before deploying to a router
- **After modifying constants** — if you change `PARTITION_CEILING_MB`, `SAFETY_MULTIPLIER`, or `MAX_ROLLBACK_INDEX`, run tests to confirm nothing breaks
- **After any code changes** — the property-based tests act as a safety net, catching edge cases you might not think to check manually
- **During development** — if you're extending the script (adding new file patterns, changing thresholds, etc.)

You do NOT need to run tests on the router itself. Tests are a development/validation step you run on your workstation.

### How to Run

```bash
# Install test dependencies (one time)
pip install -r requirements-test.txt

# Run all tests with verbose output
python -m pytest test_cisco_sdwan_precheck.py -v

# Or with unittest directly
python -m unittest test_cisco_sdwan_precheck -v
```

### What the Results Tell You

**All 33 tests pass** = the script's logic is correct and safe to deploy. Specifically:

| Test Category | What It Proves |
|---------------|----------------|
| CLI parsing (4 tests) | Arguments are validated correctly; missing required args cause a clean exit |
| SNMP client (3 tests) | Errors (binary not found, timeout) produce useful log messages and never leak the community string |
| File indexer (5 tests) | Only `C.cdb` and `rollback0`–`rollback49` are counted; everything else is ignored |
| Size aggregator (7 tests) | Byte totals are summed accurately; no overcounting, no undercounting |
| Space evaluator (3 tests) | GO/NO-GO threshold math is correct; exit codes are right |
| Property tests (7 tests, 200 random inputs each) | The above guarantees hold for *any* possible input, not just the handful of examples in unit tests |

**If a test fails**, the output tells you exactly which guarantee broke. For example:
- A file indexer test failing means the script might include/exclude the wrong files
- A property test failing gives you the exact input that broke the invariant (Hypothesis's "shrinking" finds the minimal failing case)

**Bottom line:** Green test suite = you can trust the GO/NO-GO answer the script gives you on a real router.

## Project Structure

```
Cisco-Scripts/
├── cisco_sdwan_precheck.py      # Main script (zero external dependencies)
├── test_cisco_sdwan_precheck.py # Unit + property-based test suite
├── requirements-test.txt        # Test-only dependency (hypothesis)
└── README.md                    # This file
```

## Security Notes

- The SNMP community string is **never logged** — this is verified by property-based tests that generate random community strings and assert they never appear in any log output.
- The script uses SNMPv2c (cleartext). Ensure SNMP traffic is confined to a management VRF or out-of-band network.
- SNMPv3 with authentication/encryption would require script modification (not currently supported).

## Compatibility

This script queries standard CISCO-FLASH-MIB OIDs (ciscoFlashFileName / ciscoFlashFileSize) that are present across the Catalyst 8000 family running IOS XE SD-WAN. It should work on any platform that exposes these OIDs, but validate in your environment before relying on it.

| Platform | Expected to Work | Validated on Real Hardware |
|----------|-----------------|---------------------------|
| Catalyst 8000v (CSR1000v SD-WAN) | Yes | Not yet |
| Catalyst 8200 Series | Yes | Not yet |
| Catalyst 8300 Series | Yes | Not yet |
| Catalyst 8500 Series | Yes | Not yet |
| IOS XE SD-WAN 17.x train | Yes | Not yet |

**How to validate:** Run the script against a non-production router and compare the output against manual `dir bootflash:.sdwaninstaller/` results. If the file list and sizes match, you're good.

If you validate on a platform, update this table and submit a PR.

## License

Internal use. See your organization's licensing policy.

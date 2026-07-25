#!/usr/bin/env python3
"""
nutanix_stig_harden.py

Automated DISA STIG hardening for Nutanix clusters, implementing Phases 1
through 3 and Phase 9 of the STIG Hardening Runbook for Nutanix Cloud
Infrastructure (AOS, AHV, and Prism Central 7.x and above).

The script connects over SSH to the cluster virtual IP and to Prism Central,
discovers which security parameters the running AOS build actually supports,
captures a full baseline, applies only the parameters that differ from the
selected hardening profile, and writes a rollback manifest containing only the
parameters it changed.

Design notes:
  - Dry run is the default. Nothing is written to the cluster unless --apply
    is passed.
  - Parameter support is discovered at runtime from the ncli help output, so
    the script does not send flags that a given AOS release does not accept.
  - Cluster lockdown, directory services, client certificate authentication,
    certificate replacement, and data at rest encryption are deliberately NOT
    automated. Those steps carry lockout or data loss risk and are handled as
    gated, interactive, precondition-checked operations or left to the runbook.

Exit codes:
    0   success, no failures
    1   preflight validation failed
    2   completed with one or more failures
    3   connection or authentication error
    4   configuration error
    5   aborted by operator

Requires: Python 3.8 or later, paramiko
"""

import argparse
import configparser
import csv
import getpass
import ipaddress
import json
import os
import re
import shlex
import smtplib
import socket
import sys
import time
from datetime import datetime
from email.message import EmailMessage

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_VERSION = "1.1"

# All paths are resolved relative to the script location so that the tool
# behaves identically under CRON, Windows Task Scheduler, and interactive use.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(SCRIPT_DIR, "nutanix_stig_harden.ini")
# The local Control Center sets NTNX_STIG_DATA_DIR for each operation so every
# run receives an isolated evidence directory. Standalone CLI behavior is
# unchanged when the variable is absent.
DATA_DIR = os.environ.get("NTNX_STIG_DATA_DIR", SCRIPT_DIR)
LOG_DIR = os.path.join(DATA_DIR, "logs")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
ROLLBACK_DIR = os.path.join(DATA_DIR, "rollback")
REPORT_DIR = os.path.join(DATA_DIR, "reports")

DEFAULT_LOG_RETENTION_DAYS = 30
DEFAULT_SSH_TIMEOUT = 30
DEFAULT_CMD_TIMEOUT = 300
DEFAULT_VERIFY_TIMEOUT = 120
DEFAULT_VERIFY_INTERVAL = 10
MIN_AOS_MAJOR = 7

MANUAL_CONTROLS = [
    "Export an external SCC/SCAP scan and complete the STIG Viewer checklist.",
    "Configure and visually verify the Prism Element and Prism Central web banners.",
    "Validate CVM/AHV/PCVM propagation on every node or VM in the deployment.",
    "Remove or rotate factory/default credentials and validate vaulted break-glass access.",
    "Stage and test individual SSH keys, then perform cluster lockdown in a separate window.",
    "Configure PCVM/CVM SSH allowlists and SSH security level using the release-specific guide.",
    "Configure LDAPS, least-privilege RBAC, CAC/PIV, revocation checking, and session timeout.",
    "Replace self-signed certificates and externally validate the complete trust chain.",
    "Decide, configure, and escrow data-at-rest encryption/KMS only with ISSO approval.",
    "Validate management-network segmentation, upstream ACLs, and Flow policies.",
    "Confirm syslog events arrive at the SIEM with correct time, severity, and retention.",
    "Run NCC, functional regression, evidence-package, POA&M, and ISSO sign-off activities.",
    "Customize and verify the SSH DoD banner files on every AHV, CVM, and PCVM "
    "before enabling the banner parameter.",
    "Confirm the installed AOS/AHV release is eligible for the required STIG "
    "baseline and document any vendor-stated compliance limitation.",
    "Approve and stage CVM/PCVM SSH security levels, IP restrictions, and minimal "
    "allowlists with tested console recovery before activation.",
    "Keep security-configuration Lock Status disabled until the final reviewed "
    "configuration is accepted; enabling it requires Nutanix Support to unlock.",
    "Enable fapolicy only under a strict organization policy after compatibility "
    "and performance testing.",
    "Enable DoDIN additional controls only with ISSO approval and tested account "
    "recovery because an incorrect password can permanently lock the account.",
    "Review and disposition the AHV Enable user core dump field when advertised; "
    "the Security Guide 7.5 section lists it but does not define a hardening "
    "command for the Control Center to send safely.",
]

# Each scope maps to its own ncli namespace. Prism Central uses a separate
# command family from the cluster, and AHV hosts are configured cluster wide
# through the hypervisor namespace executed from any CVM.
SCOPES = {
    "cvm": {
        "label": "Controller VM",
        "get_cmd": "ncli cluster get-cvm-security-config",
        "set_cmd": "ncli cluster edit-cvm-security-params",
        "target": "cluster",
    },
    "ahv": {
        "label": "AHV Hypervisor",
        "get_cmd": "ncli cluster get-hypervisor-security-config",
        "set_cmd": "ncli cluster edit-hypervisor-security-params",
        "target": "cluster",
    },
    "pcvm": {
        "label": "Prism Central VM",
        "get_cmd": "ncli cluster get-pcvm-security-config",
        "set_cmd": "ncli cluster edit-pcvm-security-params",
        "target": "prism_central",
    },
}

# Canonical parameter registry.
#
# "cli" is the ncli flag name. "labels" holds the display label prefixes seen
# in ncli get output. Nutanix truncates long labels with an ellipsis, for
# example "Enable High Strength P... : false", so matching is done on prefix
# rather than exact string equality.
PARAMS = {
    "enable_aide": {
        "cli": "enable-aide",
        "labels": ["enable aide"],
        "type": "bool",
        "desc": "File and directory integrity checking",
    },
    "enable_core": {
        "cli": "enable-core",
        "labels": ["enable core"],
        "type": "bool",
        "desc": "User space core dump generation",
    },
    "enable_kernel_core": {
        "cli": "enable-kernel-core",
        "labels": ["enable kernel core"],
        "type": "bool",
        "desc": "Kernel core dump generation",
    },
    "enable_high_strength_password": {
        "cli": "enable-high-strength-password",
        "labels": ["enable high strength p", "enable high strength password"],
        "type": "bool",
        "desc": "DoD password complexity, aging, and history",
    },
    "enable_banner": {
        "cli": "enable-banner",
        "labels": ["enable banner"],
        "type": "bool",
        "desc": "Standard Mandatory DoD Notice and Consent Banner",
    },
    "enable_itlb_multihit_mitigation": {
        "cli": "enable-itlb-multihit-mitigation",
        "labels": [
            "enable itlb multihit m",
            "enable itlb multihit mitigation",
        ],
        "type": "bool",
        "desc": "AHV iTLB Multihit processor vulnerability mitigation",
    },
    "enable_retbleed_mitigation": {
        "cli": "enable-retbleed-mitigation",
        "labels": [
            "enable retbleed mitiga",
            "enable retbleed mitigation",
        ],
        "type": "bool",
        "desc": "AHV Retbleed speculative-execution mitigation",
    },
    "enable_memory_poison": {
        "cli": "enable-memory-poison",
        "labels": ["enable memory poison"],
        "type": "bool",
        "desc": "AHV freed-memory poisoning",
    },
    "enable_page_poison": {
        "cli": "enable-page-poison",
        "labels": ["enable page poison"],
        "type": "bool",
        "desc": "Poisons freed memory pages",
    },
    "enable_slub_debug": {
        "cli": "enable-slub-debug",
        "labels": ["enable slub debug"],
        "type": "bool",
        "desc": "Kernel slab allocator debugging and validation",
    },
    "enable_processor_mitigations": {
        "cli": "enable-processor-mitigations",
        "cli_aliases": [
            "enable-processor-mitigations",
            "enable-kernel-mitigations",
        ],
        "labels": [
            "enable processor mitig",
            "enable processor mitigations",
            "enable kernel mitig",
            "enable kernel mitigations",
        ],
        "type": "bool",
        "desc": "Speculative execution mitigations",
    },
    "enable_fapolicy": {
        "cli": "enable-fapolicy",
        "labels": ["enable fapolicy"],
        "type": "bool",
        "desc": "Application execution allowlisting",
    },
    "enable_dodin_additional_controls": {
        "cli": "enable-dodin-additional-controls",
        "cli_aliases": [
            "enable-dodin-additional-controls",
            "enable-dodin-mode",
            "enable-dodin-opts",
        ],
        "labels": [
            "enable dodin additiona",
            "enable dodin additional",
            "enable dodin mode",
        ],
        "type": "bool",
        "desc": "Additional DoDIN APL controls",
    },
    "enable_snmpv3_only": {
        "cli": "enable-snmpv3-only",
        "labels": ["enable snmpv3 only"],
        "type": "bool",
        "desc": "Disables SNMP v1 and v2c",
    },
    "schedule": {
        "cli": "schedule",
        "labels": ["schedule"],
        "type": "enum",
        "desc": "SCMA assessment and self heal frequency",
    },
}

# Hardening profiles. Values are the desired end state for each parameter.
# A profile only declares intent. The script filters every profile against the
# parameters the running AOS build reports as supported for that scope.
PROFILES = {
    "REPORT_ONLY": {},
    "STIG_STANDARD": {
        "schedule": "DAILY",
        "enable_aide": True,
        "enable_high_strength_password": True,
        "enable_banner": True,
        "enable_snmpv3_only": True,
        "enable_core": False,
        "enable_kernel_core": False,
    },
    "STIG_HIGH": {
        "schedule": "DAILY",
        "enable_aide": True,
        "enable_high_strength_password": True,
        "enable_banner": True,
        "enable_core": False,
        "enable_kernel_core": False,
        "enable_page_poison": True,
        "enable_slub_debug": True,
        "enable_processor_mitigations": True,
        "enable_itlb_multihit_mitigation": True,
        "enable_retbleed_mitigation": True,
        "enable_memory_poison": True,
        "enable_snmpv3_only": True,
    },
    "DODIN_APL": {
        "schedule": "HOURLY",
        "enable_aide": True,
        "enable_high_strength_password": True,
        "enable_banner": True,
        "enable_core": False,
        "enable_kernel_core": False,
        "enable_page_poison": True,
        "enable_slub_debug": True,
        "enable_processor_mitigations": True,
        "enable_itlb_multihit_mitigation": True,
        "enable_retbleed_mitigation": True,
        "enable_memory_poison": True,
        "enable_snmpv3_only": True,
    },
}

PROFILE_NOTES = {
    "REPORT_ONLY": "Capture baseline and report drift. Makes no changes.",
    "STIG_STANDARD": "Core STIG controls with minimal performance impact.",
    "STIG_HIGH": "Adds release-supported memory and processor mitigations.",
    "DODIN_APL": (
        "STIG_HIGH plus hourly SCMA; lockout-prone DoDIN options remain manual."
    ),
}

SAMPLE_CONFIG = """\
# nutanix_stig_harden.ini
# Configuration for nutanix_stig_harden.py
#
# Credentials may also be supplied on the command line or by environment
# variable. Precedence is: command line, then environment, then this file.
# Environment variables: NTNX_STIG_USER, NTNX_STIG_PASSWORD, NTNX_STIG_KEYFILE
#
# Protect this file. On Linux, chmod 600. On Windows, restrict the ACL to the
# service account that runs the scheduled task.

[cluster]
# Cluster virtual IP or the address of any CVM.
host = 10.10.10.100
username = nutanix
# Use key based authentication wherever possible. If the cluster is already in
# lockdown mode, key authentication is the only option that will work.
ssh_key_file = /home/svc_stig/.ssh/id_ed25519
ssh_key_passphrase =
password =
port = 22

[prism_central]
# Leave host blank to skip Prism Central hardening entirely.
host = 10.10.10.150
username = nutanix
ssh_key_file = /home/svc_stig/.ssh/id_ed25519
ssh_key_passphrase =
password =
port = 22

[options]
# Hardening profile: REPORT_ONLY, STIG_STANDARD, STIG_HIGH, DODIN_APL
profile = STIG_STANDARD
# Comma separated scopes to process: cvm, ahv, pcvm
scopes = cvm,ahv,pcvm
# Days to retain CSV logs, backups, and rollback manifests.
log_retention_days = 30
# Seconds to wait for a single ncli command to return.
command_timeout = 300
# Seconds to wait for applied security parameters to read back as compliant.
verification_timeout = 120
verification_interval = 10
# Explicit path to ncli. Leave blank to resolve through a login shell.
ncli_path =
# Host key verification is strict by default. Populate the user's known_hosts
# file before connecting. Use auto-add only for a controlled first connection.
host_key_policy = reject
known_hosts_file =
# Run the full NCC health check during preflight. This is thorough and slow.
full_health_check = false
# Minimum number of configured DNS and NTP servers required to pass preflight.
min_name_servers = 2
min_ntp_servers = 2

[syslog]
# Set enabled to true to configure remote syslog forwarding (Phase 9).
enabled = false
server_name = SIEM01
server_ip = 10.20.5.40
port = 514
protocol = tcp
relp_enabled = true
# Comma separated module names. Run "ncli rsyslog-config add-module help" on
# the target to confirm the module list supported by your AOS release.
modules = AUDIT,API_AUDIT,PRISM

[email]
enabled = false
smtp_server = smtp.example.com
smtp_port = 25
use_tls = false
username =
password =
sender = nutanix-stig@example.com
recipients = isso@example.com,platform-team@example.com
subject_prefix = [Nutanix STIG]
"""


# ---------------------------------------------------------------------------
# Console output helpers
# ---------------------------------------------------------------------------

class Console:
    """Console writer with optional quiet mode for scheduled execution."""

    def __init__(self, quiet=False):
        self.quiet = quiet

    def _emit(self, prefix, message):
        if not self.quiet:
            print("%s %s" % (prefix, message))

    def info(self, message):
        self._emit("[*]", message)

    def ok(self, message):
        self._emit("[+]", message)

    def warn(self, message):
        self._emit("[!]", message)

    def error(self, message):
        # Errors always print, even in quiet mode, and go to stderr so that a
        # scheduler capturing streams separately still surfaces them.
        print("[X] %s" % message, file=sys.stderr)

    def header(self, message):
        if not self.quiet:
            print("")
            print("=" * 74)
            print(message)
            print("=" * 74)

    def section(self, message):
        if not self.quiet:
            print("")
            print("-- %s" % message)


# ---------------------------------------------------------------------------
# CSV run logging with automatic retention
# ---------------------------------------------------------------------------

class RunLogger:
    """Writes a per run CSV change log and prunes files past the retention window."""

    FIELDS = [
        "timestamp", "run_id", "target_host", "target_type", "scope",
        "phase", "parameter", "previous_value", "target_value",
        "action", "status", "message",
    ]

    def __init__(self, run_id, retention_days, console):
        self.run_id = run_id
        self.retention_days = retention_days
        self.console = console
        self.rows = []
        _ensure_dir(LOG_DIR)
        self.path = os.path.join(LOG_DIR, "stig_run_%s.csv" % run_id)
        with open(self.path, "w", newline="", encoding="utf-8") as handle:
            csv.DictWriter(handle, fieldnames=self.FIELDS).writeheader()

    def record(self, target_host, target_type, scope, phase, parameter,
               previous_value, target_value, action, status, message=""):
        row = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "run_id": self.run_id,
            "target_host": target_host,
            "target_type": target_type,
            "scope": scope,
            "phase": phase,
            "parameter": parameter,
            "previous_value": _fmt(previous_value),
            "target_value": _fmt(target_value),
            "action": action,
            "status": status,
            "message": message,
        }
        self.rows.append(row)
        with open(self.path, "a", newline="", encoding="utf-8") as handle:
            csv.DictWriter(handle, fieldnames=self.FIELDS).writerow(row)

    def counts(self):
        tally = {}
        for row in self.rows:
            tally[row["status"]] = tally.get(row["status"], 0) + 1
        return tally

    def prune(self):
        """Delete logs, backups, and rollback manifests past the retention window."""
        cutoff = time.time() - (self.retention_days * 86400)
        removed = 0
        for directory in (LOG_DIR, BACKUP_DIR, ROLLBACK_DIR, REPORT_DIR):
            if not os.path.isdir(directory):
                continue
            for name in os.listdir(directory):
                path = os.path.join(directory, name)
                if not os.path.isfile(path):
                    continue
                try:
                    if os.path.getmtime(path) < cutoff:
                        os.remove(path)
                        removed += 1
                except OSError:
                    # A file we cannot stat or remove is not fatal to the run.
                    continue
        if removed:
            self.console.info("Retention: removed %d file(s) older than %d days"
                              % (removed, self.retention_days))


# ---------------------------------------------------------------------------
# SSH transport
# ---------------------------------------------------------------------------

class NutanixSSH:
    """Thin SSH wrapper around paramiko for running ncli on a CVM or PCVM."""

    def __init__(self, host, username, password=None, key_file=None,
                 key_passphrase=None, port=22, ncli_path="",
                 host_key_policy="reject", known_hosts_file="",
                 command_timeout=DEFAULT_CMD_TIMEOUT, console=None):
        self.host = host
        self.username = username
        self.password = password
        self.key_file = key_file
        self.key_passphrase = key_passphrase or None
        self.port = port
        self.ncli_path = ncli_path
        self.host_key_policy = host_key_policy
        self.known_hosts_file = known_hosts_file
        self.command_timeout = command_timeout
        self.console = console or Console()
        self.client = None
        self.used_key_auth = False

    def connect(self):
        if not PARAMIKO_AVAILABLE:
            raise RuntimeError("paramiko is not installed. Run: pip install paramiko")

        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        if self.known_hosts_file:
            expanded_hosts = os.path.expanduser(self.known_hosts_file)
            if not os.path.isfile(expanded_hosts):
                raise RuntimeError("Known-hosts file not found: %s" % expanded_hosts)
            self.client.load_host_keys(expanded_hosts)

        if self.host_key_policy == "auto-add":
            self.console.warn(
                "SSH host key auto-add is enabled. Independently verify the CVM/PCVM "
                "fingerprint before using this mode in production.")
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            self.client.set_missing_host_key_policy(paramiko.RejectPolicy())

        pkey = None
        if self.key_file:
            expanded = os.path.expanduser(self.key_file)
            if not os.path.isfile(expanded):
                raise RuntimeError("SSH key file not found: %s" % expanded)
            pkey = self._load_key(expanded)

        try:
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password if not pkey else None,
                pkey=pkey,
                timeout=DEFAULT_SSH_TIMEOUT,
                banner_timeout=DEFAULT_SSH_TIMEOUT,
                auth_timeout=DEFAULT_SSH_TIMEOUT,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.AuthenticationException as exc:
            raise RuntimeError("Authentication failed for %s@%s: %s"
                               % (self.username, self.host, exc))
        except (paramiko.SSHException, socket.error) as exc:
            raise RuntimeError("SSH connection to %s failed: %s" % (self.host, exc))

        self.used_key_auth = pkey is not None
        return self

    @staticmethod
    def _load_key(path):
        """Try each supported key format until one loads."""
        last_error = None
        key_classes = [
            getattr(paramiko, name, None)
            for name in ("Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey")
        ]
        for key_class in (item for item in key_classes if item is not None):
            try:
                return key_class.from_private_key_file(path)
            except Exception as exc:  # noqa: BLE001 - try the next key type
                last_error = exc
        raise RuntimeError("Unable to load private key %s: %s" % (path, last_error))

    def run(self, command, timeout=None):
        """Execute a command in a login shell and return (rc, stdout, stderr)."""
        if self.client is None:
            raise RuntimeError("SSH session is not connected")

        # A login shell is used so that the nutanix user profile is sourced and
        # ncli resolves on PATH. An explicit ncli_path in the config overrides
        # this for environments with a nonstandard layout.
        if self.ncli_path and command.startswith("ncli "):
            command = shlex.quote(self.ncli_path) + command[len("ncli"):]
        wrapped = "bash -lc %s" % _shell_quote(command)

        try:
            stdin, stdout, stderr = self.client.exec_command(
                wrapped, timeout=timeout or self.command_timeout)
            stdin.close()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            rc = stdout.channel.recv_exit_status()
            return rc, out, err
        except (paramiko.SSHException, socket.error, TimeoutError) as exc:
            raise RuntimeError(
                "Remote command failed on %s: %s (%s)"
                % (self.host, command, exc))

    def close(self):
        if self.client:
            try:
                self.client.close()
            except Exception:  # noqa: BLE001 - closing must never raise
                pass
            self.client = None


# ---------------------------------------------------------------------------
# ncli output parsing
# ---------------------------------------------------------------------------

def normalize_label(raw):
    """Reduce an ncli display label to a comparable lowercase token string."""
    label = raw.strip().lower()
    label = label.replace(".", " ")
    label = re.sub(r"[^a-z0-9 ]+", " ", label)
    label = re.sub(r"\s+", " ", label).strip()
    return label


def parse_security_config(output):
    """
    Parse the key and value pairs from an ncli get-*-security-config response.

    ncli truncates long labels with an ellipsis, so the parsed label is matched
    against the registry by longest prefix rather than exact equality. Any line
    that does not map to a known parameter is retained under its raw label so
    that the baseline capture stays complete for evidence purposes.
    """
    parsed = {}
    unmapped = {}

    for line in output.splitlines():
        if ":" not in line:
            continue
        raw_label, raw_value = line.split(":", 1)
        label = normalize_label(raw_label)
        value = raw_value.strip()
        if not label:
            continue

        matched_key = None
        matched_len = -1
        for key, meta in PARAMS.items():
            for candidate in meta["labels"]:
                candidate_norm = normalize_label(candidate)
                # The observed label may be the truncated form of the candidate
                # or the candidate may be the truncated form of the observed.
                if label.startswith(candidate_norm) or candidate_norm.startswith(label):
                    if len(candidate_norm) > matched_len:
                        matched_key = key
                        matched_len = len(candidate_norm)

        if matched_key:
            parsed[matched_key] = _coerce(value, PARAMS[matched_key]["type"])
        else:
            unmapped[label] = value

    return parsed, unmapped


def discover_supported_params(session, scope):
    """
    Read ncli help and return canonical keys mapped to the accepted CLI spelling.

    This is the guard against version drift. Sending an unsupported flag makes
    ncli reject the whole command, so anything not advertised is skipped and
    logged rather than attempted.
    """
    set_cmd = SCOPES[scope]["set_cmd"]
    rc, out, err = session.run("%s help" % set_cmd)
    help_text = (out + "\n" + err).lower()

    supported = {}
    for key, meta in PARAMS.items():
        for cli_name in _cli_names(meta):
            if re.search(
                    r"(?<![a-z0-9])%s(?![a-z0-9-])"
                    % re.escape(cli_name), help_text):
                supported[key] = cli_name
                break

    if not supported:
        # If help parsing yields nothing the output format has changed. Fall
        # back to whatever the get command reported so the run can continue,
        # and let the caller warn about the degraded discovery.
        return None
    return supported


# ---------------------------------------------------------------------------
# Preflight validation
# ---------------------------------------------------------------------------

def platform_stig_advisories(version, scopes, target_type):
    """Return non-blocking product-version compliance advisories."""
    if (
        target_type == "cluster"
        and "ahv" in scopes
        and re.match(r"^7\.5(?:\.|$)", version or "")
    ):
        return [
            "AOS 7.5 with AHV scope detected. Confirm the AHV release and "
            "document the Nutanix Security Guide 7.5 RHEL 9 STIG limitation "
            "before treating this run as compliance evidence."
        ]
    return []


def preflight(session, options, console, logger, target_type):
    """
    Validate that the target is safe to modify. Returns (passed, findings).

    A hard failure blocks the run. A soft finding is recorded and reported but
    does not stop execution, because some checks reflect design decisions that
    the operator may have already accepted.
    """
    findings = []
    blocking_findings = set()

    def add_finding(message, blocking=False):
        findings.append(message)
        if blocking:
            blocking_findings.add(message)

    console.section("Preflight validation on %s" % session.host)

    # AOS or Prism Central version.
    rc, out, err = session.run("ncli cluster info")
    version = None
    if rc != 0:
        add_finding("Unable to query platform version: %s"
                    % (err or out).strip()[:160], blocking=True)
    else:
        for line in out.splitlines():
            if "version" in line.lower() and ":" in line:
                candidate = line.split(":", 1)[1].strip()
                match = re.match(r"^(\d+)\.(\d+)", candidate)
                if match:
                    version = candidate
                    if int(match.group(1)) < MIN_AOS_MAJOR:
                        add_finding(
                            "Version %s is below the supported baseline of %d.x"
                            % (candidate, MIN_AOS_MAJOR), blocking=True)
                    break
    if version:
        console.ok("Version: %s" % version)
        for advisory in platform_stig_advisories(
            version, options["scopes"], target_type
        ):
            add_finding(advisory)
    elif rc == 0:
        add_finding("Unable to determine the AOS or Prism Central version",
                    blocking=True)

    # Cluster service state. Anything not UP means do not proceed.
    rc, out, err = session.run("cluster status")
    down = [ln.strip() for ln in out.splitlines()
            if "DOWN" in ln.upper() or "CRASH" in ln.upper()]
    if rc != 0 or not out.strip():
        add_finding("Unable to verify cluster service state: %s"
                    % (err or out).strip()[:160], blocking=True)
    elif down:
        add_finding("Cluster services are not fully up: %s"
                    % "; ".join(down[:5]), blocking=True)
    else:
        console.ok("Cluster services are up")

    # Data resiliency. Hardening triggers rolling service restarts through
    # SCMA, so the cluster must be able to tolerate a node outage.
    if target_type == "cluster":
        rc, out, err = session.run(
            "ncli cluster get-domain-fault-tolerance-status type=node")
        ft_match = re.search(
            r"Current\s+Fault\s+Tolerance\s*:\s*(\d+)", out, re.I)
        if rc != 0:
            add_finding("Unable to query data resiliency: %s"
                        % (err or out).strip()[:160], blocking=True)
        elif not ft_match:
            add_finding("Unable to parse current fault tolerance from ncli output",
                        blocking=True)
        elif int(ft_match.group(1)) < 1:
            add_finding("Current fault tolerance is 0. Resolve before hardening.",
                        blocking=True)
        else:
            console.ok("Data resiliency check passed (fault tolerance %s)"
                       % ft_match.group(1))

    # DNS and NTP redundancy. A single entry is a STIG finding in its own right
    # and will also break Kerberos and certificate validation later.
    for label, command, hint, minimum in (
        ("name server", "ncli cluster get-name-servers", "name server",
         options["min_name_servers"]),
        ("NTP server", "ncli cluster get-ntp-servers", "ntp server",
         options["min_ntp_servers"]),
    ):
        rc, out, err = session.run(command)
        if rc != 0:
            add_finding("Unable to query configured %ss: %s"
                        % (label, (err or out).strip()[:160]), blocking=True)
            continue
        count = _count_list_values(out, hint)
        if count < minimum:
            add_finding("Only %d %s(s) configured, %d required"
                        % (count, label, minimum), blocking=True)
        else:
            console.ok("%s count: %d" % (label.capitalize(), count))

    # Optional full NCC pass. This is thorough and slow, so it is opt in.
    if options["full_health_check"]:
        console.info("Running full NCC health check. This can take 20 minutes or more.")
        rc, out, err = session.run("ncc health_checks run_all", timeout=3600)
        fails = len(re.findall(r"\bFAIL\b", out))
        warns = len(re.findall(r"\bWARN\b", out))
        if rc != 0:
            add_finding("NCC command failed: %s"
                        % (err or out).strip()[:160], blocking=True)
        if fails:
            add_finding("NCC reported %d FAIL result(s)" % fails, blocking=True)
        if warns:
            add_finding("NCC reported %d WARN result(s)" % warns)
        console.ok("NCC complete: %d FAIL, %d WARN" % (fails, warns))

    for finding in findings:
        console.warn(finding)
        logger.record(session.host, target_type, "-", "preflight", "-", "", "",
                      "check", "FAIL" if finding in blocking_findings else "WARN",
                      finding)

    if not findings:
        console.ok("Preflight passed with no findings")
        logger.record(session.host, target_type, "-", "preflight", "-", "", "",
                      "check", "PASS", "No findings")

    return (not blocking_findings), findings


# ---------------------------------------------------------------------------
# Baseline capture
# ---------------------------------------------------------------------------

def capture_baseline(session, scopes, run_id, console, target_type,
                     artifact_label="baseline"):
    """
    Capture the current security configuration and supporting cluster state.

    The backup file name carries the hostname so that evidence from multiple
    clusters can be collected into one archive without collision.
    """
    _ensure_dir(BACKUP_DIR)
    hostname = _resolve_hostname(session)

    baseline = {
        "run_id": run_id,
        "captured_at": datetime.now().isoformat(timespec="seconds"),
        "host": session.host,
        "hostname": hostname,
        "target_type": target_type,
        "scopes": {},
        "supporting": {},
    }

    for scope in scopes:
        rc, out, err = session.run(SCOPES[scope]["get_cmd"])
        if rc != 0:
            console.warn("Could not read %s config: %s" % (scope, (err or out).strip()[:160]))
            baseline["scopes"][scope] = {"error": (err or out).strip(), "raw": out}
            continue
        parsed, unmapped = parse_security_config(out)
        baseline["scopes"][scope] = {
            "parsed": parsed,
            "unmapped": unmapped,
            "raw": out,
        }
        console.ok("Captured %s baseline: %d known parameter(s)" % (scope, len(parsed)))

    # Supporting evidence artifacts referenced by the runbook.
    for name, command in (
        ("cluster_info", "ncli cluster info"),
        ("cluster_params", "ncli cluster get-params"),
        ("rsyslog", "ncli rsyslog-config ls"),
        ("authconfig", "ncli authconfig list-directory"),
        ("ssl_certificate", "ncli ssl-certificate ls"),
    ):
        rc, out, err = session.run(command)
        baseline["supporting"][name] = out if rc == 0 else (err or out)

    filename = "%s_%s_%s_%s.json" % (
        _safe_name(hostname), target_type, _safe_name(artifact_label), run_id)
    path = os.path.join(BACKUP_DIR, filename)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(baseline, handle, indent=2)

    console.ok("%s snapshot written to %s"
               % (artifact_label.capitalize(), path))
    return baseline, path


# ---------------------------------------------------------------------------
# Apply phase
# ---------------------------------------------------------------------------

def build_plan(baseline, scope, profile_name, supported, console):
    """
    Compare the captured baseline to the profile and return the change list.

    Only parameters that differ are included, which keeps the run idempotent
    and keeps the rollback manifest limited to what actually changed.
    """
    desired = PROFILES[profile_name]
    current = baseline["scopes"].get(scope, {}).get("parsed", {})
    plan = []
    skipped = []

    for key, target_value in desired.items():
        if supported is not None and key not in supported:
            skipped.append((key, "not supported on this release for scope %s" % scope))
            continue
        cli_name = (
            supported[key]
            if isinstance(supported, dict)
            else PARAMS[key]["cli"]
        )
        if key not in current:
            # Never write a value that cannot be read first. Without a trusted
            # current value the script cannot prove the delta or roll it back.
            skipped.append((
                key,
                "current value was not present in the baseline; safe rollback "
                "cannot be guaranteed",
            ))
            continue
        if current[key] != target_value:
            plan.append({
                "key": key,
                "cli": cli_name,
                "current": current[key],
                "target": target_value,
            })

    return plan, skipped


def apply_plan(session, scope, plan, run_id, apply_changes, logger, console,
               target_type):
    """Execute the change plan and return the list of applied changes."""
    set_cmd = SCOPES[scope]["set_cmd"]
    applied = []
    failures = 0

    for change in plan:
        value = _to_cli(change["target"], PARAMS[change["key"]]["type"])
        command = "%s %s=%s" % (set_cmd, change["cli"], value)

        if not apply_changes:
            console.info("DRY RUN  %s  (%s -> %s)"
                         % (command, _fmt(change["current"]), _fmt(change["target"])))
            logger.record(session.host, target_type, scope, "harden", change["key"],
                          change["current"], change["target"], "dry-run", "PLANNED",
                          command)
            continue

        rc, out, err = session.run(command)
        combined = (out + " " + err).strip()

        if rc == 0 and "error" not in combined.lower():
            console.ok("%s: %s -> %s"
                       % (change["key"], _fmt(change["current"]), _fmt(change["target"])))
            logger.record(session.host, target_type, scope, "harden", change["key"],
                          change["current"], change["target"], "set", "SUCCESS",
                          combined[:200])
            applied.append(change)
        else:
            failures += 1
            console.error("%s failed: %s" % (change["key"], combined[:200]))
            logger.record(session.host, target_type, scope, "harden", change["key"],
                          change["current"], change["target"], "set", "FAILED",
                          combined[:200])

    return applied, failures


def verify_applied_changes(session, scope, applied, options, logger, console,
                           target_type):
    """Read back applied parameters until they converge or the timeout expires."""
    if not applied:
        return [], []

    timeout = max(0, options["verification_timeout"])
    interval = max(1, options["verification_interval"])
    deadline = time.monotonic() + timeout
    pending = {change["key"]: change for change in applied}
    verified = []
    last_values = {}
    last_error = ""

    console.info("Verifying %d applied %s parameter(s) by read-back"
                 % (len(applied), scope))

    while pending:
        rc, out, err = session.run(SCOPES[scope]["get_cmd"])
        if rc == 0:
            parsed, _ = parse_security_config(out)
            last_values = parsed
            last_error = ""
            for key, change in list(pending.items()):
                if parsed.get(key) == change["target"]:
                    verified.append(change)
                    del pending[key]
                    console.ok("Verified %s=%s"
                               % (key, _fmt(change["target"])))
                    logger.record(
                        session.host, target_type, scope, "verify", key,
                        change["target"], change["target"], "read-back", "PASS",
                        "Post-change value matches the requested value")
        else:
            last_error = (err or out).strip()[:200]

        if not pending or time.monotonic() >= deadline:
            break
        time.sleep(min(interval, max(0, deadline - time.monotonic())))

    unverified = []
    for key, change in pending.items():
        observed = last_values.get(key)
        reason = (
            "read-back failed: %s" % last_error
            if last_error
            else "observed %s after %d second verification window"
                 % (_fmt(observed) or "<missing>", timeout)
        )
        unverified.append((change, reason))
        console.error("Verification failed for %s: %s" % (key, reason))
        logger.record(
            session.host, target_type, scope, "verify", key, observed,
            change["target"], "read-back", "FAILED", reason)

    return verified, unverified


def write_rollback_manifest(session, run_id, target_type, applied_by_scope, console):
    """
    Persist a manifest containing only the parameters this run changed.

    Rollback deliberately does not restore the entire baseline. Restoring
    everything would revert unrelated changes made by other administrators
    between the baseline capture and the rollback.
    """
    if not any(applied_by_scope.values()):
        return None

    _ensure_dir(ROLLBACK_DIR)
    hostname = _resolve_hostname(session)
    manifest = {
        "run_id": run_id,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "host": session.host,
        "hostname": hostname,
        "target_type": target_type,
        "changes": {
            scope: [
                {"key": c["key"], "cli": c["cli"],
                 "previous": c["current"], "applied": c["target"]}
                for c in changes
            ]
            for scope, changes in applied_by_scope.items() if changes
        },
    }
    filename = "%s_%s_rollback_%s.json" % (_safe_name(hostname), target_type, run_id)
    path = os.path.join(ROLLBACK_DIR, filename)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
    console.ok("Rollback manifest written to %s" % path)
    return path


def execute_rollback(session, manifest_path, apply_changes, options, logger, console):
    """Revert only the parameters recorded in a rollback manifest."""
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    console.header("Rollback from %s" % os.path.basename(manifest_path))
    console.info("Original run: %s on %s" % (manifest["run_id"], manifest["host"]))

    failures = 0
    for scope, changes in manifest.get("changes", {}).items():
        if scope not in SCOPES:
            console.error("Rollback manifest contains unknown scope: %s" % scope)
            failures += 1
            continue
        set_cmd = SCOPES[scope]["set_cmd"]
        reverted = []
        for change in changes:
            if change.get("key") not in PARAMS:
                console.error("Rollback manifest contains unknown parameter: %s"
                              % change.get("key"))
                failures += 1
                continue
            previous = change["previous"]
            if previous is None:
                console.warn("%s/%s had no recorded previous value. Skipping."
                             % (scope, change["key"]))
                logger.record(session.host, manifest["target_type"], scope,
                              "rollback", change["key"], None, None, "skip",
                              "SKIPPED", "No recorded previous value")
                continue

            value = _to_cli(previous, PARAMS[change["key"]]["type"])
            manifest_cli = change.get("cli")
            cli_name = (
                manifest_cli
                if manifest_cli in _cli_names(PARAMS[change["key"]])
                else PARAMS[change["key"]]["cli"]
            )
            command = "%s %s=%s" % (
                set_cmd, cli_name, value)

            if not apply_changes:
                console.info("DRY RUN  %s" % command)
                logger.record(session.host, manifest["target_type"], scope,
                              "rollback", change["key"], change["applied"],
                              previous, "dry-run", "PLANNED", command)
                continue

            rc, out, err = session.run(command)
            combined = (out + " " + err).strip()
            if rc == 0 and "error" not in combined.lower():
                console.ok("Reverted %s to %s" % (change["key"], _fmt(previous)))
                logger.record(session.host, manifest["target_type"], scope,
                              "rollback", change["key"], change["applied"],
                              previous, "set", "SUCCESS", combined[:200])
                reverted.append({
                    "key": change["key"],
                    "cli": cli_name,
                    "current": change["applied"],
                    "target": previous,
                })
            else:
                failures += 1
                console.error("Rollback of %s failed: %s" % (change["key"], combined[:200]))
                logger.record(session.host, manifest["target_type"], scope,
                              "rollback", change["key"], change["applied"],
                              previous, "set", "FAILED", combined[:200])
        if apply_changes and reverted:
            _, unverified = verify_applied_changes(
                session, scope, reverted, options, logger, console,
                manifest["target_type"])
            failures += len(unverified)
    return failures


# ---------------------------------------------------------------------------
# Phase 9: syslog forwarding
# ---------------------------------------------------------------------------

def configure_syslog(session, syslog_cfg, apply_changes, logger, console, target_type):
    """Configure remote syslog forwarding and attach the required log modules."""
    console.section("Phase 9: syslog forwarding on %s" % session.host)

    name = syslog_cfg["server_name"]
    existing_rc, existing_out, _ = session.run("ncli rsyslog-config ls")
    already_present = name.lower() in existing_out.lower()

    commands = []
    if not already_present:
        commands.append(
            "ncli rsyslog-config add-server name=%s ip-address=%s port=%s "
            "network-protocol=%s relp-enabled=%s"
            % (name, syslog_cfg["server_ip"], syslog_cfg["port"],
               syslog_cfg["protocol"], str(syslog_cfg["relp_enabled"]).lower()))
    else:
        console.info("Syslog server %s already present. Skipping creation." % name)

    for module in syslog_cfg["modules"]:
        commands.append(
            "ncli rsyslog-config add-module server-name=%s module-name=%s level=INFO"
            % (name, module.strip().upper()))

    commands.append("ncli rsyslog-config set-status enable=true")

    failures = 0
    for command in commands:
        if not apply_changes:
            console.info("DRY RUN  %s" % command)
            logger.record(session.host, target_type, "syslog", "syslog", "-", "", "",
                          "dry-run", "PLANNED", command)
            continue
        rc, out, err = session.run(command)
        combined = (out + " " + err).strip()
        # Re-adding an existing module is not a failure worth aborting on.
        if rc == 0 or "already" in combined.lower():
            console.ok(command.split("ncli ", 1)[-1][:70])
            logger.record(session.host, target_type, "syslog", "syslog", "-", "", "",
                          "set", "SUCCESS", combined[:200])
        else:
            failures += 1
            console.error("Syslog command failed: %s" % combined[:200])
            logger.record(session.host, target_type, "syslog", "syslog", "-", "", "",
                          "set", "FAILED", combined[:200])

    if apply_changes:
        rc_servers, out_servers, err_servers = session.run("ncli rsyslog-config ls")
        rc_modules, out_modules, err_modules = session.run(
            "ncli rsyslog-config ls-modules")
        verification_checks = [
            (
                "server",
                rc_servers == 0
                and name.lower() in out_servers.lower()
                and syslog_cfg["server_ip"].lower() in out_servers.lower(),
                err_servers or out_servers,
            ),
        ]
        for module in syslog_cfg["modules"]:
            verification_checks.append((
                "module:%s" % module.strip().upper(),
                rc_modules == 0
                and module.strip().upper() in out_modules.upper(),
                err_modules or out_modules,
            ))

        for item, passed, evidence in verification_checks:
            if passed:
                console.ok("Verified syslog %s by read-back" % item)
                logger.record(
                    session.host, target_type, "syslog", "verify", item, "",
                    "present", "read-back", "PASS", str(evidence)[:200])
            else:
                failures += 1
                console.error("Syslog verification failed for %s" % item)
                logger.record(
                    session.host, target_type, "syslog", "verify", item, "",
                    "present", "read-back", "FAILED", str(evidence)[:200])
    return failures


# ---------------------------------------------------------------------------
# Gated high risk operations
# ---------------------------------------------------------------------------

def evaluate_lockdown_readiness(session, console):
    """
    Report whether the cluster meets the preconditions for lockdown.

    Cluster lockdown is not applied by this script. It removes password based
    access and a mistake here strands administrators. The script reports
    readiness so the operator can execute Phase 4 deliberately, per runbook.
    """
    console.section("Phase 4 readiness assessment (reporting only)")

    ready = True

    if session.used_key_auth:
        console.ok("This session authenticated with an SSH key")
    else:
        console.warn("This session authenticated with a password. Key based access "
                     "is unproven on this host.")
        ready = False

    rc, out, err = session.run("ncli cluster list-public-keys")
    key_lines = [ln for ln in out.splitlines() if ":" in ln and ln.strip()]
    if rc == 0 and key_lines:
        console.ok("Cluster has %d registered public key entry line(s)" % len(key_lines))
    else:
        console.warn("No registered public keys found. Lockdown would strand access.")
        ready = False

    rc, out, _ = session.run("ncli cluster get-params")
    if re.search(r"lockdown.*:\s*true", out, re.I):
        console.info("Lockdown mode already appears enabled")

    if ready:
        console.ok("Preconditions look satisfied. Execute Phase 4 manually per runbook "
                   "section 8, in a dedicated window, with console access confirmed.")
    else:
        console.warn("Preconditions NOT satisfied. Do not attempt cluster lockdown.")

    return ready


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def build_summary(run_id, profile, apply_changes, results, logger):
    """Assemble the plain text run summary used for console and email output."""
    lines = []
    lines.append("Nutanix STIG Hardening Run Summary")
    lines.append("=" * 60)
    lines.append("Run ID       : %s" % run_id)
    lines.append("Started      : %s" % results.get("started", ""))
    lines.append("Completed    : %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("Profile      : %s" % profile)
    lines.append("Mode         : %s" % ("APPLY" if apply_changes else "DRY RUN"))
    lines.append("Approval     : %s" % results.get("approval_id", "not applicable"))
    lines.append("Executed by  : %s@%s" % (getpass.getuser(), socket.gethostname()))
    lines.append("")
    if results.get("fatal_error"):
        lines.append("Fatal error  : %s" % results["fatal_error"])
        lines.append("")
    if results.get("rollback"):
        rollback = results["rollback"]
        lines.append("Rollback     : %s" % rollback.get("manifest", ""))
        lines.append("Target       : %s" % rollback.get("host", ""))
        lines.append("Failures     : %d" % rollback.get("failures", 0))
        lines.append("")

    for target in results.get("targets", []):
        lines.append("-" * 60)
        lines.append("Target       : %s (%s)" % (target["host"], target["type"]))
        lines.append("Preflight    : %s" % target["preflight"])
        if target.get("findings"):
            for finding in target["findings"]:
                lines.append("  finding    : %s" % finding)
        lines.append("Baseline     : %s" % target.get("baseline_path", "not captured"))
        for scope, detail in target.get("scopes", {}).items():
            lines.append(
                "  scope %-5s : %d planned, %d applied, %d verified, "
                "%d failed, %d skipped"
                % (scope, detail["planned"], detail["applied"],
                   detail.get("verified", 0), detail["failed"],
                   detail["skipped"]))
            for key, reason in detail.get("skip_detail", []):
                lines.append("      skip   : %s (%s)" % (key, reason))
            for key, reason in detail.get("verification_failures", []):
                lines.append("      verify : %s (%s)" % (key, reason))
        if target.get("rollback_path"):
            lines.append("Rollback     : %s" % target["rollback_path"])
        if target.get("postchange_path"):
            lines.append("Post-change  : %s" % target["postchange_path"])
        if target.get("syslog_failures") is not None:
            lines.append("Syslog       : %s"
                         % ("verified" if target["syslog_failures"] == 0
                            else "%d failure(s)" % target["syslog_failures"]))
        if target.get("lockdown_ready") is not None:
            lines.append("Phase 4 ready: %s" % ("yes" if target["lockdown_ready"] else "no"))
        lines.append("")

    tally = logger.counts()
    lines.append("-" * 60)
    lines.append("Log records  : %s" % (", ".join("%s=%d" % (k, v)
                                                  for k, v in sorted(tally.items()))
                                        or "none"))
    lines.append("CSV log      : %s" % logger.path)
    lines.append("")
    lines.append("Manual or externally validated controls remaining")
    lines.append("-" * 60)
    for item in MANUAL_CONTROLS:
        lines.append("  - %s" % item)
    lines.append("")
    lines.append("Reminder: verify the configuration after every AOS or Prism Central "
                 "upgrade and after every expand cluster operation.")
    return "\n".join(lines)


def write_reports(run_id, profile, apply_changes, results, logger, summary):
    """Write stable text and JSON reports for the evidence package."""
    _ensure_dir(REPORT_DIR)
    text_path = os.path.join(REPORT_DIR, "stig_report_%s.txt" % run_id)
    json_path = os.path.join(REPORT_DIR, "stig_report_%s.json" % run_id)
    with open(text_path, "w", encoding="utf-8") as handle:
        handle.write(summary)
        handle.write("\n")
    payload = {
        "run_id": run_id,
        "profile": profile,
        "mode": "APPLY" if apply_changes else "DRY RUN",
        "approval_id": results.get("approval_id"),
        "csv_log": logger.path,
        "manual_controls_remaining": MANUAL_CONTROLS,
        "results": results,
    }
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    return text_path, json_path


def send_email(email_cfg, subject, body, console):
    """Send the run summary. Failure to send never fails the run itself."""
    try:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = email_cfg["sender"]
        message["To"] = ", ".join(email_cfg["recipients"])
        message.set_content(body)

        server = smtplib.SMTP(email_cfg["smtp_server"], email_cfg["smtp_port"], timeout=30)
        try:
            if email_cfg["use_tls"]:
                server.starttls()
            if email_cfg["username"]:
                server.login(email_cfg["username"], email_cfg["password"])
            server.send_message(message)
        finally:
            server.quit()
        console.ok("Summary emailed to %s" % ", ".join(email_cfg["recipients"]))
        return True
    except Exception as exc:  # noqa: BLE001 - email is best effort
        console.warn("Email delivery failed: %s" % exc)
        return False


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)


def _shell_quote(value):
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def _safe_name(value):
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(value))[:64] or "unknown"


def _cli_names(meta):
    """Return the release-specific accepted spellings for a parameter."""
    names = meta.get("cli_aliases") or [meta["cli"]]
    return list(dict.fromkeys(names))


def _coerce(value, value_type):
    if value_type == "bool":
        lowered = value.strip().lower()
        if lowered in ("true", "yes", "enabled", "1"):
            return True
        if lowered in ("false", "no", "disabled", "0"):
            return False
        return value.strip()
    return value.strip()


def _to_cli(value, value_type):
    if value_type == "bool" or isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _fmt(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _count_list_values(output, label_hint):
    """
    Count entries in an ncli list style response.

    ncli returns list values either as one comma separated value on a single
    line or as the same label repeated across several lines, depending on the
    subcommand and release. This counts unique non-empty tokens from the value
    side of every line whose label contains the hint, which handles both.
    """
    hint = label_hint.lower()
    tokens = set()
    for line in output.splitlines():
        if ":" not in line:
            continue
        raw_label, raw_value = line.split(":", 1)
        if hint not in normalize_label(raw_label):
            continue
        for token in re.split(r"[,\s]+", raw_value.strip()):
            token = token.strip().strip(",")
            if token and token.lower() not in ("none", "n/a", "-"):
                tokens.add(token)
    return len(tokens)


def _resolve_hostname(session):
    rc, out, _ = session.run("hostname")
    name = out.strip().splitlines()[0].strip() if out.strip() else ""
    return name or session.host


def _cfg_get(parser, section, option, fallback=""):
    if parser.has_option(section, option):
        return parser.get(section, option).strip()
    return fallback


def _cfg_bool(parser, section, option, fallback=False):
    raw = _cfg_get(parser, section, option, "")
    if raw == "":
        return fallback
    return raw.strip().lower() in ("true", "yes", "1", "on")


def _cfg_int(parser, section, option, fallback):
    raw = _cfg_get(parser, section, option, "")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return fallback


# ---------------------------------------------------------------------------
# Interactive profile menu
# ---------------------------------------------------------------------------

def choose_profile(console):
    """Menu driven profile selection for interactive use."""
    names = list(PROFILES.keys())
    print("")
    print("Select a hardening profile:")
    for index, name in enumerate(names, start=1):
        print("  %d) %-14s %s" % (index, name, PROFILE_NOTES[name]))
    print("  q) Quit")
    while True:
        choice = input("Selection: ").strip().lower()
        if choice == "q":
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(names):
            return names[int(choice) - 1]
        print("Invalid selection.")


# ---------------------------------------------------------------------------
# Target processing
# ---------------------------------------------------------------------------

def process_target(session, target_type, scopes, options, apply_changes,
                   run_id, logger, console, syslog_cfg):
    """Run preflight, baseline, plan, apply, and reporting for one target."""
    result = {
        "host": session.host,
        "type": target_type,
        "preflight": "SKIPPED",
        "findings": [],
        "scopes": {},
        "failures": 0,
    }

    passed, findings = preflight(session, options, console, logger, target_type)
    result["preflight"] = "PASS" if passed else "FAIL"
    result["findings"] = findings
    if not passed and apply_changes:
        console.error("Preflight failed on %s. No changes attempted." % session.host)
        result["failures"] += 1
        result["changes_blocked"] = True
        return result
    if not passed:
        console.warn("Preflight failed, but this is a dry run. Continuing with "
                     "read-only collection; no remote changes can be made.")

    baseline, baseline_path = capture_baseline(session, scopes, run_id, console,
                                               target_type)
    result["baseline_path"] = baseline_path

    applied_by_scope = {}
    for scope in scopes:
        console.section("%s: %s" % (SCOPES[scope]["label"], options["profile"]))

        scope_baseline = baseline["scopes"].get(scope, {})
        if scope_baseline.get("error") or not scope_baseline.get("parsed"):
            reason = (
                "baseline could not establish trusted current values; no "
                "changes are safe for this scope"
            )
            console.error("%s: %s" % (scope, reason))
            logger.record(session.host, target_type, scope, "harden", "-", "", "",
                          "skip", "FAILED", reason)
            result["failures"] += 1
            result["scopes"][scope] = {
                "planned": 0,
                "applied": 0,
                "verified": 0,
                "failed": 1,
                "skipped": len(PROFILES[options["profile"]]),
                "skip_detail": [
                    (key, reason) for key in PROFILES[options["profile"]]
                ],
                "verification_failures": [],
            }
            applied_by_scope[scope] = []
            continue

        discovery_failures = 0
        supported = (
            discover_supported_params(session, scope)
            if PROFILES[options["profile"]]
            else {}
        )
        if supported is None:
            supported = {}
            discovery_failures = 1
            message = (
                "Parameter help discovery returned no recognized flags for %s. "
                "Failing closed: every write for this scope will be skipped."
            ) % scope
            console.warn(message)
            logger.record(session.host, target_type, scope, "discovery", "-", "", "",
                          "check", "FAILED", message)

        plan, skipped = build_plan(baseline, scope, options["profile"], supported, console)

        for key, reason in skipped:
            console.warn("Skipping %s: %s" % (key, reason))
            logger.record(session.host, target_type, scope, "harden", key, "", "",
                          "skip", "SKIPPED", reason)

        if not plan:
            console.ok("Already compliant with %s. No changes required."
                       % options["profile"])

        applied, failures = apply_plan(session, scope, plan, run_id, apply_changes,
                                       logger, console, target_type)
        failures += discovery_failures
        verified = []
        verification_failures = []
        if apply_changes and applied:
            verified, verification_failures = verify_applied_changes(
                session, scope, applied, options, logger, console, target_type)
            failures += len(verification_failures)

        applied_by_scope[scope] = applied
        result["failures"] += failures
        result["scopes"][scope] = {
            "planned": len(plan),
            "applied": len(applied),
            "verified": len(verified),
            "failed": failures,
            "skipped": len(skipped),
            "skip_detail": skipped,
            "verification_failures": [
                (change["key"], reason)
                for change, reason in verification_failures
            ],
        }

    if apply_changes:
        result["rollback_path"] = write_rollback_manifest(
            session, run_id, target_type, applied_by_scope, console)

    if syslog_cfg and syslog_cfg["enabled"]:
        syslog_failures = configure_syslog(
            session, syslog_cfg, apply_changes, logger, console, target_type)
        result["syslog_failures"] = syslog_failures
        result["failures"] += syslog_failures

    if apply_changes:
        _, postchange_path = capture_baseline(
            session, scopes, run_id, console, target_type,
            artifact_label="postchange")
        result["postchange_path"] = postchange_path

    if target_type == "cluster":
        result["lockdown_ready"] = evaluate_lockdown_readiness(session, console)

    return result


# ---------------------------------------------------------------------------
# Argument parsing and configuration assembly
# ---------------------------------------------------------------------------

def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="nutanix_stig_harden.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Automated DISA STIG hardening for Nutanix clusters "
                    "(AOS, AHV, Prism Central 7.x and above).",
        epilog="""\
Examples:
  Generate a sample configuration file:
    nutanix_stig_harden.py --generate-config

  Dry run against a cluster using the config file:
    nutanix_stig_harden.py --config nutanix_stig_harden.ini

  Apply the STIG_HIGH profile to CVM and AHV only:
    nutanix_stig_harden.py --config prod.ini --profile STIG_HIGH \\
        --scopes cvm,ahv --apply

  Scheduled non-interactive run:
    nutanix_stig_harden.py --config prod.ini --profile STIG_STANDARD \\
        --apply --non-interactive --approval-id CHG0123456 --quiet

  Roll back only the parameters a prior run changed:
    nutanix_stig_harden.py --config prod.ini \\
        --rollback rollback/cluster01_cluster_rollback_20260723T140212.json --apply

Scheduling:
  CRON (weekly compliance drift check, dry run, emailed summary):
    0 3 * * 0 /usr/bin/python3 /opt/ntnx/nutanix_stig_harden.py \\
        --config /opt/ntnx/prod.ini --non-interactive --quiet

  Windows Task Scheduler:
    Program:   C:\\Python312\\python.exe
    Arguments: C:\\ntnx\\nutanix_stig_harden.py --config C:\\ntnx\\prod.ini
               --non-interactive --quiet
    Start in:  C:\\ntnx
""")

    parser.add_argument("--config", default=DEFAULT_CONFIG,
                        help="Path to the INI configuration file")
    parser.add_argument("--generate-config", action="store_true",
                        help="Write a sample configuration file and exit")
    parser.add_argument("--profile", choices=sorted(PROFILES.keys()),
                        help="Hardening profile. Overrides the config file.")
    parser.add_argument("--scopes",
                        help="Comma separated scopes: cvm, ahv, pcvm")
    parser.add_argument("--cluster-host",
                        help="Cluster virtual IP or CVM address. Overrides config.")
    parser.add_argument("--pc-host",
                        help="Prism Central address. Overrides config.")
    parser.add_argument("--username", help="SSH username. Overrides config.")
    parser.add_argument("--password",
                        help="SSH password. Prefer key auth or the "
                             "NTNX_STIG_PASSWORD environment variable.")
    parser.add_argument("--key-file", help="SSH private key path. Overrides config.")
    parser.add_argument("--apply", action="store_true",
                        help="Execute changes. Without this flag the run is a dry run.")
    parser.add_argument(
        "--approval-id",
        help="CAB/change-record identifier. Required for non-interactive apply "
             "and recorded in the report.")
    parser.add_argument("--rollback", metavar="MANIFEST",
                        help="Revert only the parameters recorded in a manifest")
    parser.add_argument("--full-health-check", action="store_true",
                        help="Run the full NCC health check during preflight")
    parser.add_argument("--no-email", action="store_true",
                        help="Suppress the summary email for this run")
    parser.add_argument("--non-interactive", action="store_true",
                        help="Never prompt. Required for scheduled execution.")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress informational console output")
    parser.add_argument("--log-retention-days", type=int,
                        help="Override the log and backup retention window")
    parser.add_argument("--version", action="version",
                        version="nutanix_stig_harden.py %s" % SCRIPT_VERSION)
    return parser.parse_args(argv)


def load_configuration(args, console):
    """Merge the INI file, environment variables, and command line arguments."""
    parser = configparser.ConfigParser()
    if os.path.isfile(args.config):
        parser.read(args.config)
    elif args.config != DEFAULT_CONFIG:
        raise RuntimeError("Configuration file not found: %s" % args.config)
    else:
        console.warn("No configuration file found. Using command line values only.")

    env_user = os.environ.get("NTNX_STIG_USER", "")
    env_pass = os.environ.get("NTNX_STIG_PASSWORD", "")
    env_key = os.environ.get("NTNX_STIG_KEYFILE", "")

    def target_cfg(section, host_override):
        target_prefix = "CLUSTER" if section == "cluster" else "PC"
        target_user = os.environ.get(
            "NTNX_STIG_%s_USER" % target_prefix, "")
        target_pass = os.environ.get(
            "NTNX_STIG_%s_PASSWORD" % target_prefix, "")
        target_key = os.environ.get(
            "NTNX_STIG_%s_KEYFILE" % target_prefix, "")
        return {
            "host": host_override or _cfg_get(parser, section, "host"),
            "username": args.username or target_user or env_user
                        or _cfg_get(parser, section, "username", "nutanix"),
            "password": args.password or target_pass or env_pass
                        or _cfg_get(parser, section, "password"),
            "key_file": args.key_file or target_key or env_key
                        or _cfg_get(parser, section, "ssh_key_file"),
            "key_passphrase": _cfg_get(parser, section, "ssh_key_passphrase"),
            "port": _cfg_int(parser, section, "port", 22),
        }

    cluster = target_cfg("cluster", args.cluster_host)
    prism_central = target_cfg("prism_central", args.pc_host)

    scopes_raw = args.scopes or _cfg_get(parser, "options", "scopes", "cvm,ahv,pcvm")
    scopes = [s.strip().lower() for s in scopes_raw.split(",") if s.strip()]
    for scope in scopes:
        if scope not in SCOPES:
            raise RuntimeError("Unknown scope '%s'. Valid scopes: %s"
                               % (scope, ", ".join(sorted(SCOPES))))

    options = {
        "profile": args.profile or _cfg_get(parser, "options", "profile", ""),
        "scopes": scopes,
        "log_retention_days": (
            args.log_retention_days
            if args.log_retention_days is not None
            else _cfg_int(parser, "options", "log_retention_days",
                          DEFAULT_LOG_RETENTION_DAYS)
        ),
        "command_timeout": _cfg_int(parser, "options", "command_timeout",
                                    DEFAULT_CMD_TIMEOUT),
        "verification_timeout": _cfg_int(
            parser, "options", "verification_timeout", DEFAULT_VERIFY_TIMEOUT),
        "verification_interval": _cfg_int(
            parser, "options", "verification_interval", DEFAULT_VERIFY_INTERVAL),
        "ncli_path": _cfg_get(parser, "options", "ncli_path"),
        "host_key_policy": _cfg_get(
            parser, "options", "host_key_policy", "reject").lower(),
        "known_hosts_file": _cfg_get(parser, "options", "known_hosts_file"),
        "full_health_check": args.full_health_check
                             or _cfg_bool(parser, "options", "full_health_check", False),
        "min_name_servers": _cfg_int(parser, "options", "min_name_servers", 2),
        "min_ntp_servers": _cfg_int(parser, "options", "min_ntp_servers", 2),
    }
    if options["host_key_policy"] not in ("reject", "auto-add"):
        raise RuntimeError("host_key_policy must be 'reject' or 'auto-add'")
    for name in ("log_retention_days", "command_timeout",
                 "verification_interval", "min_name_servers",
                 "min_ntp_servers"):
        if options[name] < 1:
            raise RuntimeError("%s must be at least 1" % name)
    if options["verification_timeout"] < 0:
        raise RuntimeError("verification_timeout cannot be negative")

    syslog_cfg = {
        "enabled": _cfg_bool(parser, "syslog", "enabled", False),
        "server_name": _cfg_get(parser, "syslog", "server_name", "SIEM01"),
        "server_ip": _cfg_get(parser, "syslog", "server_ip"),
        "port": _cfg_int(parser, "syslog", "port", 514),
        "protocol": _cfg_get(parser, "syslog", "protocol", "tcp"),
        "relp_enabled": _cfg_bool(parser, "syslog", "relp_enabled", True),
        "modules": [m.strip() for m in
                    _cfg_get(parser, "syslog", "modules", "AUDIT,API_AUDIT,PRISM").split(",")
                    if m.strip()],
    }
    if syslog_cfg["enabled"] and not syslog_cfg["server_ip"]:
        raise RuntimeError("Syslog is enabled but no server_ip is configured")
    if syslog_cfg["enabled"]:
        if not re.match(r"^[A-Za-z0-9._-]{1,64}$", syslog_cfg["server_name"]):
            raise RuntimeError(
                "Syslog server_name may contain only letters, numbers, dot, "
                "underscore, and hyphen")
        try:
            ipaddress.ip_address(syslog_cfg["server_ip"])
        except ValueError:
            raise RuntimeError("Syslog server_ip must be a valid IPv4 or IPv6 address")
        if not 1 <= syslog_cfg["port"] <= 65535:
            raise RuntimeError("Syslog port must be between 1 and 65535")
        if syslog_cfg["protocol"].lower() not in ("tcp", "udp"):
            raise RuntimeError("Syslog protocol must be tcp or udp")
        for module in syslog_cfg["modules"]:
            if not re.match(r"^[A-Za-z0-9_.-]{1,64}$", module):
                raise RuntimeError("Invalid syslog module name: %s" % module)

    email_cfg = {
        "enabled": _cfg_bool(parser, "email", "enabled", False) and not args.no_email,
        "smtp_server": _cfg_get(parser, "email", "smtp_server"),
        "smtp_port": _cfg_int(parser, "email", "smtp_port", 25),
        "use_tls": _cfg_bool(parser, "email", "use_tls", False),
        "username": _cfg_get(parser, "email", "username"),
        "password": _cfg_get(parser, "email", "password"),
        "sender": _cfg_get(parser, "email", "sender"),
        "recipients": [r.strip() for r in
                       _cfg_get(parser, "email", "recipients").split(",") if r.strip()],
        "subject_prefix": _cfg_get(parser, "email", "subject_prefix", "[Nutanix STIG]"),
    }
    if email_cfg["enabled"] and not email_cfg["recipients"]:
        console.warn("Email is enabled but no recipients are configured. Disabling.")
        email_cfg["enabled"] = False

    return cluster, prism_central, options, syslog_cfg, email_cfg


def open_session(cfg, options, console, label):
    """Create and connect an SSH session for one target."""
    if not cfg["host"]:
        return None
    console.info("Connecting to %s at %s" % (label, cfg["host"]))
    session = NutanixSSH(
        host=cfg["host"],
        username=cfg["username"],
        password=cfg["password"] or None,
        key_file=cfg["key_file"] or None,
        key_passphrase=cfg["key_passphrase"] or None,
        port=cfg["port"],
        ncli_path=options["ncli_path"],
        host_key_policy=options["host_key_policy"],
        known_hosts_file=options["known_hosts_file"],
        command_timeout=options["command_timeout"],
        console=console,
    )
    session.connect()
    console.ok("Connected to %s (%s auth)"
               % (cfg["host"], "key" if session.used_key_auth else "password"))
    return session


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    console = Console(quiet=args.quiet)

    if args.generate_config:
        if os.path.exists(args.config):
            console.error("Refusing to overwrite existing file: %s" % args.config)
            return 4
        with open(args.config, "w", encoding="utf-8") as handle:
            handle.write(SAMPLE_CONFIG)
        try:
            os.chmod(args.config, 0o600)
        except OSError:
            # chmod is not meaningful on all platforms. Not fatal.
            pass
        print("Sample configuration written to %s" % args.config)
        print("Edit the file, restrict its permissions, then rerun without "
              "--generate-config.")
        return 0

    if not PARAMIKO_AVAILABLE:
        console.error("paramiko is required. Install it with: pip install paramiko")
        return 4

    try:
        cluster_cfg, pc_cfg, options, syslog_cfg, email_cfg = \
            load_configuration(args, console)
    except RuntimeError as exc:
        console.error(str(exc))
        return 4

    # A rollback does not use a hardening profile, but REPORT_ONLY keeps the
    # summary and configuration model explicit.
    if args.rollback and not options["profile"]:
        options["profile"] = "REPORT_ONLY"

    # Profile selection. Interactive runs get the menu when nothing is set.
    if not options["profile"]:
        if args.non_interactive:
            console.error("No profile specified and --non-interactive is set")
            return 4
        selected = choose_profile(console)
        if not selected:
            console.warn("Aborted by operator")
            return 5
        options["profile"] = selected

    if options["profile"] not in PROFILES:
        console.error("Unknown profile: %s" % options["profile"])
        return 4
    if not options["scopes"] and not args.rollback:
        console.error("At least one scope is required")
        return 4
    if args.apply and options["profile"] == "REPORT_ONLY" and not args.rollback:
        console.error("REPORT_ONLY cannot be combined with --apply")
        return 4
    if args.apply and args.non_interactive and not args.approval_id:
        console.error("--approval-id is required with --apply --non-interactive")
        return 4

    cluster_scopes = [s for s in options["scopes"]
                      if SCOPES[s]["target"] == "cluster"]
    pc_scopes = [s for s in options["scopes"]
                 if SCOPES[s]["target"] == "prism_central"]
    if not args.rollback:
        if cluster_scopes and not cluster_cfg["host"]:
            console.error("Cluster scopes requested but no cluster host is configured")
            return 4
        if pc_scopes and not pc_cfg["host"]:
            console.error("PCVM scope requested but no Prism Central host is configured")
            return 4

    run_id = datetime.now().strftime("%Y%m%dT%H%M%S")
    logger = RunLogger(run_id, options["log_retention_days"], console)
    apply_changes = bool(args.apply)
    approval_id = args.approval_id or (
        "interactive confirmation" if apply_changes else "not applicable")

    console.header("Nutanix STIG Hardening  |  run %s  |  %s"
                   % (run_id, "APPLY" if apply_changes else "DRY RUN"))
    console.info("Profile: %s (%s)" % (options["profile"],
                                       PROFILE_NOTES[options["profile"]]))
    console.info("Scopes : %s" % ", ".join(options["scopes"]))

    # Final confirmation before any write to a production cluster.
    if apply_changes and not args.non_interactive:
        print("")
        if args.rollback:
            print("This run will modify the rollback target using manifest:")
            print("  %s" % args.rollback)
        else:
            print("This run will modify security parameters on:")
            if cluster_cfg["host"]:
                print("  cluster        : %s" % cluster_cfg["host"])
            if pc_cfg["host"] and "pcvm" in options["scopes"]:
                print("  prism central  : %s" % pc_cfg["host"])
        answer = input("Type APPLY to proceed: ").strip()
        if answer != "APPLY":
            console.warn("Aborted by operator")
            return 5

    results = {
        "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "approval_id": approval_id,
        "targets": [],
    }
    total_failures = 0
    sessions = []
    connection_error = False

    try:
        # Rollback mode short circuits the normal flow.
        if args.rollback:
            manifest_path = args.rollback
            if not os.path.isfile(manifest_path):
                manifest_path = os.path.join(ROLLBACK_DIR, args.rollback)
            if not os.path.isfile(manifest_path):
                console.error("Rollback manifest not found: %s" % args.rollback)
                return 4

            try:
                with open(manifest_path, "r", encoding="utf-8") as handle:
                    manifest = json.load(handle)
            except (OSError, ValueError) as exc:
                raise RuntimeError("Unable to read rollback manifest: %s" % exc)
            if manifest.get("target_type") not in ("cluster", "prism_central"):
                raise RuntimeError("Rollback manifest has an invalid target_type")
            if not manifest.get("host") or not isinstance(
                    manifest.get("changes"), dict):
                raise RuntimeError("Rollback manifest is missing host or changes")
            target_cfg = pc_cfg if manifest.get("target_type") == "prism_central" \
                else cluster_cfg
            if not target_cfg["host"]:
                target_cfg = dict(target_cfg)
                target_cfg["host"] = manifest["host"]

            session = open_session(target_cfg, options, console, "rollback target")
            sessions.append(session)
            rollback_failures = execute_rollback(
                session, manifest_path, apply_changes, options, logger, console)
            total_failures += rollback_failures
            results["rollback"] = {
                "manifest": manifest_path,
                "host": target_cfg["host"],
                "failures": rollback_failures,
            }
        else:
            if cluster_scopes:
                session = open_session(cluster_cfg, options, console, "cluster")
                sessions.append(session)
                result = process_target(session, "cluster", cluster_scopes, options,
                                        apply_changes, run_id, logger, console,
                                        syslog_cfg)
                results["targets"].append(result)
                total_failures += result["failures"]

            if pc_scopes:
                session = open_session(pc_cfg, options, console, "prism central")
                sessions.append(session)
                # Prism Central has no syslog handling here. Configure it in a
                # separate run against the PCVM if required by the design.
                result = process_target(session, "prism_central", pc_scopes, options,
                                        apply_changes, run_id, logger, console, None)
                results["targets"].append(result)
                total_failures += result["failures"]

    except RuntimeError as exc:
        console.error(str(exc))
        results["fatal_error"] = str(exc)
        total_failures += 1
        connection_error = True
    except KeyboardInterrupt:
        console.error("Interrupted by operator")
        return 5
    finally:
        for session in sessions:
            if session:
                session.close()

    results["completed"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary = build_summary(run_id, options["profile"], apply_changes, results, logger)
    text_report, json_report = write_reports(
        run_id, options["profile"], apply_changes, results, logger, summary)
    if not args.quiet:
        print("")
        print(summary)
        print("")
        print("Text report   : %s" % text_report)
        print("JSON report   : %s" % json_report)

    if email_cfg["enabled"]:
        subject = "%s %s %s run %s (%d failure(s))" % (
            email_cfg["subject_prefix"], options["profile"],
            "APPLY" if apply_changes else "DRY RUN", run_id, total_failures)
        send_email(email_cfg, subject, summary, console)

    logger.prune()

    if connection_error:
        console.error("Run failed during connection or remote execution. See %s"
                      % text_report)
        return 3

    preflight_failed = any(
        target.get("preflight") == "FAIL" for target in results["targets"])
    if preflight_failed:
        console.error("Preflight failed. No remote changes were made for blocked "
                      "targets. See %s" % text_report)
        return 1

    if total_failures:
        console.error("Run completed with %d failure(s). See %s"
                      % (total_failures, text_report))
        return 2

    console.ok("Run complete. Log: %s" % logger.path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

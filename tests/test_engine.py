import configparser
import importlib.util
import json
import os
import shlex
import socket
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TEST_DEPS = os.path.join(HERE, "testdeps")
sys.path.insert(0, TEST_DEPS)

import paramiko  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "nutanix_stig_harden",
    os.path.join(HERE, os.pardir, "app", "core", "nutanix_stig_harden.py"))
stig = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stig)


class MockState:
    def __init__(self):
        self.commands = []
        self.overrides = {}
        self.ignore_edits = False
        self.security = {
            "cvm": {
                "schedule": "WEEKLY",
                "enable_aide": False,
                "enable_high_strength_password": False,
                "enable_banner": False,
                "enable_core": True,
                "enable_kernel_core": True,
            },
            "ahv": {
                "schedule": "WEEKLY",
                "enable_aide": False,
                "enable_high_strength_password": False,
                "enable_banner": False,
                "enable_core": True,
                "enable_kernel_core": True,
            },
        }

    @staticmethod
    def _unwrap(command):
        words = shlex.split(command)
        if len(words) == 3 and words[:2] == ["bash", "-lc"]:
            return words[2]
        return command

    def _security_output(self, scope):
        return "\n".join(
            "%s : %s" % (
                stig.PARAMS[key]["cli"],
                str(value).lower() if isinstance(value, bool) else value,
            )
            for key, value in self.security[scope].items()
        ) + "\n"

    def handle(self, wrapped_command):
        command = self._unwrap(wrapped_command)
        self.commands.append(command)
        if command in self.overrides:
            return self.overrides[command]

        static = {
            "hostname": (0, "mock-cvm-01\n", ""),
            "ncli cluster info": (0, "AOS Version : 7.3.1\n", ""),
            "cluster status": (0, "mock-cvm-01: UP\n", ""),
            "ncli cluster get-domain-fault-tolerance-status type=node": (
                0, "Current Fault Tolerance : 1\n", ""),
            "ncli cluster get-name-servers": (
                0, "Name Servers : 10.0.0.10, 10.0.0.11\n", ""),
            "ncli cluster get-ntp-servers": (
                0, "NTP Servers : 10.0.0.20, 10.0.0.21\n", ""),
            "ncli cluster get-params": (0, "Lockdown Mode : false\n", ""),
            "ncli rsyslog-config ls": (0, "Status : disabled\n", ""),
            "ncli authconfig list-directory": (0, "Directory : corp.example\n", ""),
            "ncli ssl-certificate ls": (0, "Certificate : mock\n", ""),
            "ncli cluster list-public-keys": (0, "Name : admin-key\n", ""),
        }
        if command in static:
            return static[command]

        for scope in ("cvm", "ahv"):
            get_cmd = stig.SCOPES[scope]["get_cmd"]
            set_cmd = stig.SCOPES[scope]["set_cmd"]
            if command == get_cmd:
                return 0, self._security_output(scope), ""
            if command == "%s help" % set_cmd:
                flags = " ".join(
                    "--%s" % stig.PARAMS[key]["cli"]
                    for key in self.security[scope]
                )
                return 0, "Options: %s\n" % flags, ""
            if command.startswith(set_cmd + " "):
                assignment = command[len(set_cmd) + 1:]
                cli_name, raw_value = assignment.split("=", 1)
                key = next(
                    key for key, meta in stig.PARAMS.items()
                    if meta["cli"] == cli_name)
                if not self.ignore_edits:
                    self.security[scope][key] = stig._coerce(
                        raw_value, stig.PARAMS[key]["type"])
                return 0, "Successfully updated\n", ""

        return 127, "", "unknown mock command: %s" % command


class MockSSHServer(paramiko.ServerInterface):
    def __init__(self, state):
        self.state = state

    def check_auth_password(self, username, password):
        if username == "nutanix" and password == "mock-password":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        command_text = command.decode("utf-8", errors="replace")

        def respond():
            # Allow the server-side exec request success packet to reach the
            # client before sending command output.
            time.sleep(0.02)
            rc, out, err = self.state.handle(command_text)
            if out:
                channel.send(out.encode("utf-8"))
            if err:
                channel.send_stderr(err.encode("utf-8"))
            channel.send_exit_status(rc)
            channel.shutdown_write()

        threading.Thread(target=respond, daemon=True).start()
        return True


class MockSSHListener:
    def __init__(self, state):
        self.state = state
        self.key = paramiko.RSAKey.generate(2048)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(5)
        self.port = self.socket.getsockname()[1]
        self.transport = None
        self.channels = []
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _serve(self):
        try:
            client, _ = self.socket.accept()
        except OSError:
            return
        self.transport = paramiko.Transport(client)
        self.transport.add_server_key(self.key)
        self.transport.start_server(server=MockSSHServer(self.state))
        while self.transport.is_active():
            channel = self.transport.accept(timeout=0.2)
            if channel is not None:
                self.channels.append(channel)

    def close(self):
        if self.transport is not None:
            self.transport.close()
        self.socket.close()
        self.thread.join(timeout=2)

    def write_known_hosts(self, path):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "[127.0.0.1]:%d %s %s\n"
                % (self.port, self.key.get_name(), self.key.get_base64()))


class ScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = self.temp.name
        stig.LOG_DIR = os.path.join(root, "logs")
        stig.BACKUP_DIR = os.path.join(root, "backups")
        stig.ROLLBACK_DIR = os.path.join(root, "rollback")
        stig.REPORT_DIR = os.path.join(root, "reports")

    def tearDown(self):
        self.temp.cleanup()

    def _write_config(self, server):
        known_hosts = os.path.join(self.temp.name, "known_hosts")
        server.write_known_hosts(known_hosts)
        path = os.path.join(self.temp.name, "mock.ini")
        parser = configparser.ConfigParser()
        parser["cluster"] = {
            "host": "127.0.0.1",
            "username": "nutanix",
            "password": "mock-password",
            "port": str(server.port),
        }
        parser["prism_central"] = {"host": ""}
        parser["options"] = {
            "profile": "STIG_STANDARD",
            "scopes": "cvm,ahv",
            "host_key_policy": "reject",
            "known_hosts_file": known_hosts,
            "verification_timeout": "0",
            "verification_interval": "1",
            "min_name_servers": "2",
            "min_ntp_servers": "2",
        }
        parser["syslog"] = {"enabled": "false"}
        parser["email"] = {"enabled": "false"}
        with open(path, "w", encoding="utf-8") as handle:
            parser.write(handle)
        return path

    def test_build_plan_never_applies_unknown_current_value(self):
        baseline = {"scopes": {"cvm": {"parsed": {"enable_aide": False}}}}
        plan, skipped = stig.build_plan(
            baseline, "cvm", "STIG_STANDARD",
            set(stig.PROFILES["STIG_STANDARD"]), stig.Console(quiet=True))
        self.assertEqual([item["key"] for item in plan], ["enable_aide"])
        self.assertIn("enable_banner", [key for key, _ in skipped])

    def test_release_specific_parameter_alias_is_discovered(self):
        class Session:
            @staticmethod
            def run(command):
                return 0, "Options: enable-kernel-mitigations\n", ""

        supported = stig.discover_supported_params(Session(), "cvm")
        self.assertEqual(
            supported["enable_processor_mitigations"],
            "enable-kernel-mitigations")
        parsed, _ = stig.parse_security_config(
            "Enable Kernel Mitigations : false\n")
        self.assertIs(parsed["enable_processor_mitigations"], False)

    def test_real_ssh_dry_run_sends_no_edit_commands(self):
        state = MockState()
        server = MockSSHListener(state).start()
        try:
            config = self._write_config(server)
            rc = stig.main(["--config", config, "--non-interactive", "--quiet"])
        finally:
            server.close()
        self.assertEqual(rc, 0)
        self.assertFalse(any(" edit-" in cmd and "=" in cmd
                             for cmd in state.commands))
        self.assertTrue(any(cmd == "ncli cluster info" for cmd in state.commands))

    def test_real_ssh_apply_requires_approval_and_verifies_readback(self):
        state = MockState()
        server = MockSSHListener(state).start()
        try:
            config = self._write_config(server)
            rc = stig.main([
                "--config", config,
                "--apply", "--non-interactive", "--approval-id", "CHG-TEST-001",
                "--quiet",
            ])
        finally:
            server.close()
        self.assertEqual(rc, 0)
        self.assertTrue(any("edit-cvm-security-params" in cmd
                            for cmd in state.commands))
        self.assertTrue(state.security["cvm"]["enable_aide"])
        self.assertEqual(state.security["cvm"]["schedule"], "DAILY")
        report_files = os.listdir(stig.REPORT_DIR)
        json_path = os.path.join(
            stig.REPORT_DIR,
            next(name for name in report_files if name.endswith(".json")))
        with open(json_path, "r", encoding="utf-8") as handle:
            report = json.load(handle)
        self.assertEqual(report["approval_id"], "CHG-TEST-001")
        for target in report["results"]["targets"]:
            for scope in target["scopes"].values():
                self.assertEqual(scope["applied"], scope["verified"])

    def test_noninteractive_apply_without_approval_is_rejected_locally(self):
        state = MockState()
        server = MockSSHListener(state).start()
        try:
            config = self._write_config(server)
            rc = stig.main([
                "--config", config, "--apply", "--non-interactive", "--quiet"])
        finally:
            server.close()
        self.assertEqual(rc, 4)
        self.assertEqual(state.commands, [])

    def test_apply_is_blocked_when_preflight_cannot_verify_health(self):
        state = MockState()
        state.overrides["cluster status"] = (1, "", "cluster status unavailable")
        server = MockSSHListener(state).start()
        try:
            config = self._write_config(server)
            rc = stig.main([
                "--config", config,
                "--apply", "--non-interactive", "--approval-id", "CHG-TEST-002",
                "--quiet",
            ])
        finally:
            server.close()
        self.assertEqual(rc, 1)
        self.assertFalse(any(" edit-" in cmd and "=" in cmd
                             for cmd in state.commands))

    def test_apply_fails_when_readback_does_not_confirm_change(self):
        state = MockState()
        state.ignore_edits = True
        server = MockSSHListener(state).start()
        try:
            config = self._write_config(server)
            rc = stig.main([
                "--config", config,
                "--apply", "--non-interactive", "--approval-id", "CHG-TEST-003",
                "--quiet",
            ])
        finally:
            server.close()
        self.assertEqual(rc, 2)
        report_files = os.listdir(stig.REPORT_DIR)
        json_path = os.path.join(
            stig.REPORT_DIR,
            next(name for name in report_files if name.endswith(".json")))
        with open(json_path, "r", encoding="utf-8") as handle:
            report = json.load(handle)
        self.assertTrue(any(
            scope["verification_failures"]
            for target in report["results"]["targets"]
            for scope in target["scopes"].values()
        ))


if __name__ == "__main__":
    unittest.main(verbosity=2)

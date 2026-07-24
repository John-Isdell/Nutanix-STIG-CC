import importlib.util
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

HERE = Path(__file__).parent
MODULE_PATH = HERE.parent / "control_center.py"
SPEC = importlib.util.spec_from_file_location("universal_controller", MODULE_PATH)
controller = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(controller)


class UniversalControllerSafetyTests(unittest.TestCase):
    def test_progress_callback_does_not_echo_subprocess_output(self):
        received = []
        output = io.StringIO()
        with redirect_stdout(output):
            controller.emit(
                "https://user:secret@example.invalid/package",
                received.append,
            )
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(
            received,
            ["https://user:secret@example.invalid/package"],
        )

    def test_stop_refuses_to_interrupt_cluster_operation(self):
        state = {"pid": 12345, "url": "http://127.0.0.1:1234", "instance_id": "x"}
        health = {"operation_running": True, "instance_id": "x", "local_only": True}
        with mock.patch.object(controller, "running_state", return_value=(state, health)):
            with mock.patch.object(controller, "terminate_pid") as terminate:
                with self.assertRaises(controller.ControlCenterError):
                    controller.stop_service()
                terminate.assert_not_called()

    def test_emergency_stop_is_explicit(self):
        state = {"pid": 12345, "url": "http://127.0.0.1:1234", "instance_id": "x"}
        health = {"operation_running": True, "instance_id": "x", "local_only": True}
        with mock.patch.object(controller, "running_state", return_value=(state, health)):
            with mock.patch.object(controller, "terminate_pid") as terminate:
                with mock.patch.object(controller, "health", return_value=None):
                    with mock.patch.object(controller, "clear_state"):
                        controller.stop_service(force_stop=True)
                terminate.assert_called_once_with(12345)

    def test_health_requires_exact_instance_identity(self):
        with mock.patch.object(
            controller,
            "urlopen",
        ) as opened:
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.__exit__.return_value = False
            opened.return_value = response
            with mock.patch.object(
                controller.json,
                "load",
                return_value={
                    "status": "ok",
                    "instance_id": "different",
                    "local_only": True,
                },
            ):
                result = controller.health(
                    {
                        "url": "http://127.0.0.1:1234",
                        "instance_id": "expected",
                    }
                )
        self.assertIsNone(result)

    def test_product_install_registers_and_opens_supervisor(self):
        marker = {"kind": "test registration"}
        with mock.patch.object(controller, "install_dependencies") as install:
            with mock.patch.object(
                controller.supervisor_setup,
                "register_supervisor",
                return_value=marker,
            ) as register:
                with mock.patch.object(controller.webbrowser, "open") as opened:
                    result = controller.install_product()
        self.assertEqual(result, marker)
        install.assert_called_once()
        register.assert_called_once()
        opened.assert_called_once_with(
            controller.supervisor_setup.SUPERVISOR_URL,
            new=2,
        )

    def test_product_uninstall_preserves_data_and_removes_registration(self):
        with mock.patch.object(controller, "stop_service") as stop:
            with mock.patch.object(
                controller.supervisor_setup,
                "unregister_supervisor",
            ) as unregister:
                with mock.patch.object(
                    controller.supervisor_setup,
                    "stop_supervisor_process",
                ) as stop_supervisor:
                    controller.uninstall_product()
        stop.assert_called_once_with(force_stop=False, progress=None)
        unregister.assert_called_once_with(controller.ROOT, progress=None)
        stop_supervisor.assert_called_once_with(controller.ROOT, progress=None)


if __name__ == "__main__":
    unittest.main(verbosity=2)

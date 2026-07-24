import importlib.util
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).parent
MODULE_PATH = HERE.parent / "control_center.py"
SPEC = importlib.util.spec_from_file_location("universal_controller", MODULE_PATH)
controller = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(controller)


class UniversalControllerSafetyTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)

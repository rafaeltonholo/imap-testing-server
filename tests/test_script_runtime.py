from __future__ import annotations

import importlib
import inspect
from pathlib import Path
import sys
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPOSITORY_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


class DockerCommandRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        sys.modules.pop("lib", None)
        self.lib = importlib.import_module("lib")

    def test_docker_exec_uses_only_root_compose_dovecot_service(self) -> None:
        supports_timeout = "timeout" in inspect.signature(self.lib.docker_exec).parameters
        invocation_options: dict[str, object] = {"check": False, "capture": True}
        expected_run_options: dict[str, object] = {
            "check": False,
            "capture_output": True,
            "text": True,
        }
        if supports_timeout:
            invocation_options["timeout"] = 7.5
            expected_run_options["timeout"] = 7.5
        with mock.patch.object(self.lib.subprocess, "run") as run:
            self.lib.docker_exec(
                ["doveadm", "user", "dev@local.test"],
                **invocation_options,
            )

        run.assert_called_once_with(
            [
                "docker",
                "compose",
                "-f",
                str(REPOSITORY_ROOT / "docker-compose.yml"),
                "exec",
                "-T",
                "dovecot",
                "doveadm",
                "user",
                "dev@local.test",
            ],
            **expected_run_options,
        )

    def test_docker_cp_uses_only_root_compose_dovecot_service(self) -> None:
        with mock.patch.object(self.lib.subprocess, "run") as run:
            self.lib.docker_cp("/tmp/message.eml", "/tmp/message.eml")

        run.assert_called_once_with(
            [
                "docker",
                "compose",
                "-f",
                str(REPOSITORY_ROOT / "docker-compose.yml"),
                "cp",
                "/tmp/message.eml",
                "dovecot:/tmp/message.eml",
            ],
            check=True,
            capture_output=True,
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import base64
import json
import os
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path

from biometric_app.models import VerificationResult


class FingerprintService:
    """Futronic FS80 enrollment and matching through the official FTRAPI SDK."""

    TEMPLATE_VERSION = 4
    ALGORITHM_NAME = "Futronic FTRAPI minutiae"
    ENROLLMENT_SAMPLE_COUNT = 3

    def __init__(self) -> None:
        project_root = Path(__file__).resolve().parents[2]
        helper_directory = (
            project_root
            / "tools"
            / "FutronicCaptureHelper"
            / "bin"
            / "Release"
            / "net8.0"
            / "win-x86"
            / "publish"
        )
        self.helper_path = helper_directory / "FutronicCaptureHelper.exe"
        self.helper_dll_path = helper_directory / "FutronicCaptureHelper.dll"
        self.dotnet_root = project_root / "tools" / "dotnet-x86"
        self._scanner_info: str | None = None

    def is_sdk_available(self) -> bool:
        if not self.helper_dll_path.exists():
            self._scanner_info = f"Futronic recognition helper not found at {self.helper_dll_path}"
            return False

        probe = self._run_helper(
            ["--sdk-probe"],
            allow_failure=True,
            timeout=20,
        )
        if probe["success"]:
            self._scanner_info = "Futronic FS80 and official recognition SDK detected."
            return True

        self._scanner_info = probe["message"]
        return False

    def load_sdk(self) -> None:
        if not self.helper_dll_path.exists():
            raise RuntimeError(
                "The Futronic recognition helper is missing. Rebuild or reinstall BioAccess."
            )
        if not self.dotnet_root.exists():
            raise RuntimeError(
                "The bundled 32-bit fingerprint runtime is missing. Rebuild or reinstall BioAccess."
            )

    def enroll_template(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> bytes:
        """Capture the same finger three times and return one official SDK template."""
        self.load_sdk()
        result = self._run_helper(
            ["--sdk-enroll"],
            allow_failure=False,
            timeout=180,
            progress_callback=progress_callback,
        )
        payload = self._parse_json_output(result["stdout"], "enrollment")
        self._validate_official_template(payload)
        if int(payload.get("sample_count", 0)) != self.ENROLLMENT_SAMPLE_COUNT:
            raise RuntimeError(
                "Futronic enrollment did not complete all three fingerprint samples."
            )
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def verify_against_database(
        self,
        enrolled_users: list[dict],
    ) -> VerificationResult:
        """Capture once and identify the live finger against encrypted DB templates."""
        self.load_sdk()

        candidates: list[dict[str, object]] = []
        candidate_users: dict[int, dict] = {}
        legacy_count = 0
        invalid_count = 0

        for user in enrolled_users:
            stored_template = user.get("fingerprint_template")
            if not stored_template:
                continue
            try:
                payload = self._deserialize_template(stored_template)
                if int(payload.get("version", 0)) != self.TEMPLATE_VERSION:
                    legacy_count += 1
                    continue
                self._validate_official_template(payload)
                user_id = int(user["id"])
                candidates.append(
                    {
                        "id": user_id,
                        "templateBase64": payload["template_base64"],
                    }
                )
                candidate_users[user_id] = user
            except (KeyError, TypeError, ValueError, RuntimeError):
                invalid_count += 1

        if not candidates:
            if legacy_count:
                return VerificationResult(
                    False,
                    (
                        "Only older fingerprint records were found. Re-enroll the person "
                        "with the official Futronic three-scan enrollment before verification."
                    ),
                )
            if invalid_count:
                return VerificationResult(
                    False,
                    "Stored fingerprint records are invalid and must be re-enrolled.",
                )
            return VerificationResult(False, "No official Futronic fingerprint templates found.")

        request = json.dumps({"candidates": candidates}, separators=(",", ":"))
        result = self._run_helper(
            ["--sdk-identify"],
            input_text=request,
            allow_failure=False,
            timeout=60,
        )
        payload = self._parse_json_output(result["stdout"], "identification")
        matches = payload.get("matches")
        if not isinstance(matches, list):
            raise RuntimeError("Futronic identification returned an invalid match list.")
        if not matches:
            return VerificationResult(
                False,
                (
                    "Fingerprint not recognized by the official Futronic matcher "
                    "(security setting: maximum false acceptance rate 1 in 100,000)."
                ),
            )

        valid_matches: list[tuple[int, int]] = []
        for match in matches:
            try:
                matched_id = int(match["id"])
                far_attained = int(match["far"])
            except (KeyError, TypeError, ValueError):
                continue
            if matched_id in candidate_users:
                valid_matches.append((matched_id, far_attained))

        if not valid_matches:
            return VerificationResult(
                False,
                "The fingerprint SDK returned a record that is not in the current database set.",
            )

        valid_matches.sort(key=lambda item: item[1])
        if len(valid_matches) > 1:
            return VerificationResult(
                False,
                (
                    "Fingerprint identification was ambiguous. No access was granted; "
                    "re-enroll the affected fingerprint records."
                ),
                candidate_user_ids=tuple(item[0] for item in valid_matches),
            )

        matched_id, far_attained = valid_matches[0]
        matched_user = candidate_users[matched_id]
        return VerificationResult(
            True,
            (
                f"Fingerprint confirmed for {matched_user.get('full_name', 'registered user')} "
                f"by the official Futronic matcher (FAR score {far_attained})."
            ),
            matched_id,
        )

    def _run_helper(
        self,
        arguments: list[str],
        *,
        allow_failure: bool,
        timeout: int,
        input_text: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> dict:
        self.load_sdk()
        command = [
            str(self.dotnet_root / "dotnet.exe"),
            str(self.helper_dll_path),
            *arguments,
        ]
        try:
            if progress_callback is not None:
                return self._run_helper_with_progress(
                    command,
                    timeout=timeout,
                    input_text=input_text,
                    allow_failure=allow_failure,
                    progress_callback=progress_callback,
                )

            result = subprocess.run(
                command,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=self._helper_environment(),
                cwd=str(self.helper_dll_path.parent),
            )
        except subprocess.TimeoutExpired as exc:
            message = (
                "Fingerprint capture timed out. Lift the finger, place it flat on the "
                "scanner, and try again."
            )
            if not allow_failure:
                raise RuntimeError(message) from exc
            return {"success": False, "stdout": "", "message": message}
        except OSError as exc:
            message = f"Fingerprint recognition helper could not start: {exc}"
            if not allow_failure:
                raise RuntimeError(message) from exc
            return {"success": False, "stdout": "", "message": message}

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        if result.returncode != 0 and not allow_failure:
            raise RuntimeError(stderr or stdout or "Futronic recognition failed.")

        return {
            "success": result.returncode == 0,
            "stdout": stdout,
            "message": stderr or stdout or "Futronic helper returned no output.",
        }

    def _run_helper_with_progress(
        self,
        command: list[str],
        *,
        timeout: int,
        input_text: str | None,
        allow_failure: bool,
        progress_callback: Callable[[str], None],
    ) -> dict:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=self._helper_environment(),
            cwd=str(self.helper_dll_path.parent),
        )
        if input_text is not None and process.stdin is not None:
            process.stdin.write(input_text)
            process.stdin.close()

        stderr_lines: list[str] = []

        def read_progress() -> None:
            if process.stderr is None:
                return
            for raw_line in process.stderr:
                line = raw_line.strip()
                if not line:
                    continue
                stderr_lines.append(line)
                try:
                    progress_callback(line)
                except Exception:
                    continue

        reader = threading.Thread(
            target=read_progress,
            name="FutronicProgressReader",
            daemon=True,
        )
        reader.start()
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait(timeout=5)
            reader.join(timeout=2)
            last_state = (
                f" Last scanner instruction: {stderr_lines[-1]}"
                if stderr_lines
                else " The SDK did not report a scanner instruction."
            )
            message = (
                "Fingerprint capture timed out."
                f"{last_state} Lift the finger completely, reconnect the FS80 if it is "
                "not lighting, and try again."
            )
            if not allow_failure:
                raise RuntimeError(message) from exc
            return {"success": False, "stdout": "", "message": message}

        reader.join(timeout=2)
        stdout = process.stdout.read().strip() if process.stdout is not None else ""
        stderr = "\n".join(stderr_lines).strip()
        if return_code != 0 and not allow_failure:
            raise RuntimeError(stderr or stdout or "Futronic recognition failed.")
        return {
            "success": return_code == 0,
            "stdout": stdout,
            "message": stderr or stdout or "Futronic helper returned no output.",
        }

    def _helper_environment(self) -> dict[str, str]:
        essential_keys = (
            "SystemRoot",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
            "PROCESSOR_ARCHITECTURE",
            "PROCESSOR_ARCHITEW6432",
        )
        environment = {
            key: value
            for key in essential_keys
            if (value := os.environ.get(key))
        }
        environment["DOTNET_ROOT_X86"] = str(self.dotnet_root)
        environment["DOTNET_ROOT"] = str(self.dotnet_root)

        path_entries = [str(self.helper_dll_path.parent), str(self.dotnet_root)]
        system_root = environment.get("SystemRoot") or environment.get("WINDIR")
        if system_root:
            path_entries.extend(
                [
                    str(Path(system_root) / "System32"),
                    str(Path(system_root)),
                    str(Path(system_root) / "System32" / "Wbem"),
                ]
            )
        environment["PATH"] = os.pathsep.join(path_entries)
        return environment

    @staticmethod
    def _parse_json_output(stdout: str, operation: str) -> dict:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Futronic {operation} returned invalid data."
            ) from exc
        if not isinstance(payload, dict) or not payload.get("success"):
            raise RuntimeError(f"Futronic {operation} did not complete successfully.")
        return payload

    @staticmethod
    def _deserialize_template(template_bytes: bytes) -> dict:
        try:
            payload = json.loads(template_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Stored fingerprint template is invalid.") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Stored fingerprint template is invalid.")
        return payload

    def _validate_official_template(self, payload: dict) -> None:
        if int(payload.get("version", 0)) != self.TEMPLATE_VERSION:
            raise RuntimeError("Fingerprint template version is not supported.")
        if payload.get("algorithm") != self.ALGORITHM_NAME:
            raise RuntimeError("Fingerprint template algorithm is not supported.")
        encoded = payload.get("template_base64")
        if not isinstance(encoded, str) or not encoded:
            raise RuntimeError("Fingerprint template data is missing.")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise RuntimeError("Fingerprint template data is invalid.") from exc
        if not 100 <= len(decoded) <= 4096:
            raise RuntimeError("Fingerprint template size is invalid.")

"""Read-only import check for the isolated local Roxy helper."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
HELPER = ROOT / "roxy-helper"
REQUIRED = (
    "_clear_otp_inputs", "_click_continue", "_has_access_token",
    "_is_email_verification_page", "_submit_email_and_wait_next",
    "_type_otp", "_wait_after_email_otp_submit",
)


def main() -> None:
    sys.dont_write_bytecode = True
    settings = json.loads((ROOT / "roxy.local.json").read_text(encoding="utf-8"))
    allowed = {
        "ROXY_API_BASE", "ROXY_WORKSPACE_ID", "ROXY_PROJECT_ID",
        "REPO0810_ROXY_LEGACY_ROOT", "REPO0810_ROXY_PYTHON",
    }
    if set(settings) != allowed or not all(isinstance(v, str) and v for v in settings.values()):
        raise RuntimeError("Unexpected or incomplete local Roxy configuration")
    os.environ.update(settings)
    blocked: list[str] = []
    local_ipv6_probes: list[str] = []

    def audit(event, args):
        # urllib3 briefly binds ::1:0 and closes it to detect IPv6 support.
        # This is not an outbound connection or a listening service.
        if event == "socket.bind" and args[1] == ("::1", 0):
            caller = sys._getframe(1)
            if (caller.f_code.co_name == "_has_ipv6"
                    and Path(caller.f_code.co_filename).as_posix().endswith("urllib3/util/connection.py")):
                local_ipv6_probes.append("urllib3 IPv6 capability check")
                return
        if event in {"socket.connect", "socket.bind", "subprocess.Popen", "sqlite3.connect", "os.system"}:
            blocked.append(event)
            raise RuntimeError("Helper preflight denied side effect: " + event)
        if event != "open":
            return
        path, mode, flags = args
        if isinstance(path, (str, bytes)):
            file = Path(os.fsdecode(path))
            if file.name == ".env" and file.resolve() != (HELPER / ".env").resolve():
                blocked.append("foreign env access")
                raise RuntimeError("Helper tried to read unrelated environment configuration")
            if file.suffix.lower() in {".db", ".sqlite", ".sqlite3"}:
                blocked.append("database access")
                raise RuntimeError("Helper tried to open a database")
        writes = isinstance(mode, str) and any(c in mode for c in "wax+")
        writes |= isinstance(flags, int) and bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
        if writes:
            blocked.append("filesystem write")
            raise RuntimeError("Helper preflight denied filesystem write")

    sys.addaudithook(audit)
    from webui.roxy_config import require_roxy_configuration
    from webui import roxy_worker

    configuration = require_roxy_configuration()
    helper = roxy_worker._legacy_module()
    missing = [name for name in REQUIRED if not callable(getattr(helper, name, None))]
    if missing or blocked:
        raise RuntimeError(f"Roxy helper preflight failed: missing={missing}; blocked={blocked}")
    if not Path(helper.__file__).resolve().is_relative_to(HELPER.resolve()):
        raise RuntimeError("Roxy helper resolved outside the isolated directory")
    if not Path(sys.modules["config"].__file__).resolve().is_relative_to(HELPER.resolve()):
        raise RuntimeError("Configuration resolved outside the isolated directory")
    if "core.registration_service" in sys.modules:
        raise RuntimeError("Unrelated registration service was imported")
    print(json.dumps({
        "configuration_valid": True,
        "helper_import_ok": True,
        "helper_root": str(configuration.legacy_root),
        "required_methods": len(REQUIRED),
        "side_effect_attempts": len(blocked),
        "local_ipv6_capability_probes": len(local_ipv6_probes),
    }))


if __name__ == "__main__":
    main()


import subprocess
import shutil

from pathlib import Path

from config.settings import WIREGUARD_INTERFACE

WIREGUARD_EXE = Path(
    r"C:\Program Files\WireGuard\wireguard.exe"
)


class WireGuardManager:

    def __init__(self):

        self.executable = self._find_executable()

    def _find_executable(self):

        if WIREGUARD_EXE.exists():
            return str(WIREGUARD_EXE)

        executable = shutil.which("wireguard.exe")

        if executable:
            return executable

        raise FileNotFoundError(
            "WireGuard não encontrado."
        )

    def install_tunnel(self, config_path):

        path = Path(config_path).resolve()

        if not path.exists():
            raise FileNotFoundError(
                "Arquivo de configuração não encontrado."
            )

        if path.suffix.lower() != ".conf":
            raise ValueError(
                "O arquivo precisa possuir extensão .conf."
            )

        subprocess.run(
            [
                self.executable,
                "/installtunnelservice",
                str(path)
            ],
            check=True,
            timeout=30,
            capture_output=True,
            text=True
        )

    def uninstall_tunnel(self):

        subprocess.run(
            [
                self.executable,
                "/uninstalltunnelservice",
                WIREGUARD_INTERFACE
            ],
            check=True,
            timeout=30,
            capture_output=True,
            text=True
        )

    def get_status(self):

        result = subprocess.run(
            [
                "sc.exe",
                "query",
                f"WireGuardTunnel${WIREGUARD_INTERFACE}"
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

        return result.stdout

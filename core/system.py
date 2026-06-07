"""Contexto del sistema: helpers para leer ficheros, ejecutar comandos y
cachear información cara de obtener (config de sshd, login.defs, etc.)."""

import os
import shutil
import subprocess


# Valores por defecto de OpenSSH para directivas relevantes (cuando no se puede
# usar `sshd -T` y la directiva no aparece explícita en el fichero).
SSHD_DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "x11forwarding": "no",
    "maxauthtries": "6",
    "permitemptypasswords": "no",
    "pubkeyauthentication": "yes",
    "strictmodes": "yes",
    "logingracetime": "120",
}


class Ctx:
    def __init__(self):
        self.cache = {}

    # --- primitivas ---
    def run(self, cmd, timeout=15):
        try:
            p = subprocess.run(
                cmd,
                shell=isinstance(cmd, str),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return p.returncode, p.stdout, p.stderr
        except Exception as e:  # noqa: BLE001
            return 1, "", str(e)

    def read_file(self, path):
        try:
            with open(path, "r", errors="replace") as fh:
                return fh.read()
        except (OSError, PermissionError):
            return None

    def which(self, name):
        return shutil.which(name)

    def is_root(self):
        return hasattr(os, "geteuid") and os.geteuid() == 0

    # --- información del sistema (cacheada) ---
    @property
    def distro(self):
        if "distro" not in self.cache:
            info = {}
            data = self.read_file("/etc/os-release") or ""
            for line in data.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    info[k] = v.strip().strip('"')
            self.cache["distro"] = info
        return self.cache["distro"]

    def distro_name(self):
        d = self.distro
        return d.get("PRETTY_NAME") or d.get("NAME") or "Linux desconocido"

    def family(self):
        """Familia de la distribución: 'debian', 'rhel', 'arch' o 'unknown'."""
        if "family" not in self.cache:
            d = self.distro
            idl = (d.get("ID", "") + " " + d.get("ID_LIKE", "")).lower()
            fam = "unknown"
            if any(x in idl for x in ("debian", "ubuntu", "kali", "mint")):
                fam = "debian"
            elif any(x in idl for x in ("rhel", "fedora", "centos", "rocky", "almalinux", "suse")):
                fam = "rhel"
            elif "arch" in idl:
                fam = "arch"
            self.cache["family"] = fam
        return self.cache["family"]

    # --- helpers de systemd ---
    def has_systemd(self):
        return bool(self.which("systemctl"))

    def service_active(self, name):
        rc, out, _ = self.run(["systemctl", "is-active", name])
        return out.strip() == "active"

    def service_enabled(self, name):
        rc, out, _ = self.run(["systemctl", "is-enabled", name])
        return out.strip() == "enabled"

    def unit_present(self, name):
        rc, out, _ = self.run(["systemctl", "is-enabled", name])
        return out.strip() in (
            "enabled", "disabled", "static", "masked", "indirect",
            "generated", "enabled-runtime", "alias",
        )

    def sysctl(self, key):
        """Valor de un parámetro sysctl, o None si no existe."""
        path = "/proc/sys/" + key.replace(".", "/")
        v = self.read_file(path)
        if v is not None:
            v = v.strip()
            return v.split()[0] if v else ""
        rc, out, _ = self.run(["sysctl", "-n", key])
        return out.strip() if rc == 0 else None

    def ssh_installed(self):
        return bool(self.which("sshd")) or self.read_file("/etc/ssh/sshd_config") is not None

    def sshd_config(self):
        """Devuelve (config_dict, effective_bool).

        Intenta la configuración efectiva con `sshd -T`; si no, parsea el
        fichero aplicando los valores por defecto de OpenSSH.
        """
        if "sshd" in self.cache:
            return self.cache["sshd"]

        cfg = dict(SSHD_DEFAULTS)
        effective = False

        if self.which("sshd"):
            rc, out, _ = self.run(["sshd", "-T"])
            if rc == 0 and out.strip():
                effective = True
                for line in out.splitlines():
                    parts = line.split(None, 1)
                    if parts:
                        cfg[parts[0].lower()] = parts[1].strip() if len(parts) > 1 else ""

        if not effective:
            text = self.read_file("/etc/ssh/sshd_config")
            if text:
                for line in text.splitlines():
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    parts = s.split(None, 1)
                    if len(parts) == 2:
                        cfg[parts[0].lower()] = parts[1].strip()

        self.cache["sshd"] = (cfg, effective)
        return self.cache["sshd"]

    def login_defs(self):
        if "login_defs" not in self.cache:
            d = {}
            text = self.read_file("/etc/login.defs") or ""
            for line in text.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split(None, 1)
                if len(parts) == 2:
                    d[parts[0].upper()] = parts[1].strip()
            self.cache["login_defs"] = d
        return self.cache["login_defs"]

"""Doble de test: un Ctx falso que finge el estado del sistema.

Sobrescribe solo las primitivas (read_file, which, run, is_root, sysctl,
familia y servicios), de modo que la lógica de alto nivel real de Ctx
(parseo de sshd_config, login.defs, etc.) se ejecuta tal cual en los tests.
"""

from hardenix.core.system import Ctx


class FakeCtx(Ctx):
    def __init__(self, files=None, sysctls=None, bins=None, root=True,
                 family="debian", active=None, enabled=None, present=None):
        super().__init__()
        self._files = files or {}
        self._sysctls = sysctls or {}
        self._bins = set(bins or [])
        self._root = root
        self._family = family
        self._active = set(active or [])
        self._enabled = set(enabled or [])
        self._present = set(present or [])

    # primitivas
    def read_file(self, path):
        return self._files.get(path)

    def which(self, name):
        return ("/usr/bin/" + name) if name in self._bins else None

    def is_root(self):
        return self._root

    def run(self, cmd, timeout=15):
        return (1, "", "")

    # información del sistema
    def family(self):
        return self._family

    def distro_name(self):
        return "TestOS"

    def sysctl(self, key):
        return self._sysctls.get(key)

    # systemd
    def has_systemd(self):
        return True

    def service_active(self, name):
        return name in self._active

    def service_enabled(self, name):
        return name in self._enabled

    def unit_present(self, name):
        return name in self._present or name in self._enabled or name in self._active

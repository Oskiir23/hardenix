"""Motor de remediación: aplica correcciones respaldando cada cambio para
poder revertirlo (rollback).

Cada check remediable implementa `remediate(self, ctx, rem)` y usa los
helpers del objeto `Remediator`, que registra automáticamente una copia de
seguridad (snapshot) de todo lo que toca.
"""

import base64
import json
import os
import stat
from datetime import datetime


SYSCTL_DROPIN = "/etc/sysctl.d/60-hardenix.conf"


def backups_root(ctx):
    if ctx.is_root():
        base = "/var/lib/hardenix/backups"
    else:
        base = os.path.expanduser("~/.local/share/hardenix/backups")
    return base


class Remediator:
    """Aplica cambios y guarda lo necesario para revertirlos."""

    def __init__(self, ctx, dry_run=False):
        self.ctx = ctx
        self.dry = dry_run
        self._files = {}        # path -> snapshot dict (capturado una sola vez)
        self._sysctl_old = {}   # key -> valor de runtime previo
        self.changes = []       # lista de (tipo, objetivo, detalle) para mostrar
        self.notes = []         # acciones manuales recomendadas (p. ej. reload)

    # --- captura de copias de seguridad ---
    def _snap_file(self, path):
        if path in self._files:
            return
        if os.path.exists(path):
            st = os.stat(path)
            try:
                with open(path, "rb") as fh:
                    content = fh.read()
            except OSError:
                content = b""
            self._files[path] = {
                "path": path,
                "existed": True,
                "mode": stat.S_IMODE(st.st_mode),
                "uid": st.st_uid,
                "gid": st.st_gid,
                "content_b64": base64.b64encode(content).decode(),
            }
        else:
            self._files[path] = {"path": path, "existed": False}

    def note(self, text):
        if text not in self.notes:
            self.notes.append(text)

    def _ensure_parent(self, path):
        parent = os.path.dirname(path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)

    # --- helpers de cambio ---
    def set_directive(self, path, key, value):
        """Establece 'key value' en un fichero estilo clave-valor (sshd_config,
        login.defs). Reemplaza la directiva si existe, la añade si no."""
        self._snap_file(path)
        text = self.ctx.read_file(path) or ""
        out, done = [], False
        for line in text.splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                parts = s.split(None, 1)
                if parts and parts[0].lower() == key.lower():
                    if not done:
                        out.append(f"{key} {value}")
                        done = True
                    continue
            out.append(line)
        if not done:
            out.append(f"{key} {value}")
        new = "\n".join(out) + "\n"
        self.changes.append(("file", path, f"{key} {value}"))
        if not self.dry:
            self._ensure_parent(path)
            with open(path, "w") as fh:
                fh.write(new)

    def set_sshd(self, key, value):
        self.set_directive("/etc/ssh/sshd_config", key, value)
        self.note("Recarga el servicio SSH para aplicar: sudo systemctl reload ssh")

    def set_login_defs(self, key, value):
        self.set_directive("/etc/login.defs", key, value)

    def write_sysctl(self, key, value):
        old = self.ctx.sysctl(key)
        self._sysctl_old.setdefault(key, old)
        self._snap_file(SYSCTL_DROPIN)
        text = self.ctx.read_file(SYSCTL_DROPIN) or "# Parámetros de seguridad — Hardenix\n"
        out, done = [], False
        for line in text.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and s.split("=", 1)[0].strip() == key:
                if not done:
                    out.append(f"{key} = {value}")
                    done = True
                continue
            out.append(line)
        if not done:
            out.append(f"{key} = {value}")
        new = "\n".join(out) + "\n"
        self.changes.append(("sysctl", key, value))
        if not self.dry:
            self._ensure_parent(SYSCTL_DROPIN)
            with open(SYSCTL_DROPIN, "w") as fh:
                fh.write(new)
            self.ctx.run(["sysctl", "-w", f"{key}={value}"])

    def chmod(self, path, mode):
        self._snap_file(path)
        self.changes.append(("mode", path, oct(mode)))
        if not self.dry:
            os.chmod(path, mode)

    def chown_root(self, path):
        self._snap_file(path)
        self.changes.append(("owner", path, "root"))
        if not self.dry:
            os.chown(path, 0, os.stat(path).st_gid)

    # --- persistencia del snapshot ---
    def has_changes(self):
        return bool(self.changes)

    def save_snapshot(self):
        now = datetime.now()
        snap_id = now.strftime("%Y%m%d-%H%M%S") + f"-{now.microsecond // 1000:03d}"
        manifest = {
            "id": snap_id,
            "created": datetime.now().isoformat(timespec="seconds"),
            "changes": self.changes,
            "files": list(self._files.values()),
            "sysctl": [{"key": k, "old": v} for k, v in self._sysctl_old.items()],
        }
        root = backups_root(self.ctx)
        os.makedirs(root, exist_ok=True)
        with open(os.path.join(root, snap_id + ".json"), "w") as fh:
            json.dump(manifest, fh, indent=2, ensure_ascii=False)
        return snap_id


# --- rollback ---
def list_snapshots(ctx):
    root = backups_root(ctx)
    if not os.path.isdir(root):
        return []
    out = []
    for name in sorted(os.listdir(root)):
        if name.endswith(".json"):
            try:
                with open(os.path.join(root, name)) as fh:
                    out.append(json.load(fh))
            except (OSError, ValueError):
                pass
    return out


def load_snapshot(ctx, snap_id=None):
    snaps = list_snapshots(ctx)
    if not snaps:
        return None
    if snap_id is None:
        return snaps[-1]
    for s in snaps:
        if s["id"] == snap_id:
            return s
    return None


def rollback(ctx, manifest, dry_run=False):
    """Revierte un snapshot: restaura ficheros y valores sysctl previos."""
    actions = []
    for f in manifest.get("files", []):
        path = f["path"]
        if f["existed"]:
            actions.append(("restaurar", path))
            if not dry_run:
                content = base64.b64decode(f["content_b64"])
                with open(path, "wb") as fh:
                    fh.write(content)
                os.chmod(path, f["mode"])
                try:
                    os.chown(path, f["uid"], f["gid"])
                except (OSError, PermissionError):
                    pass
        else:
            actions.append(("eliminar", path))
            if not dry_run and os.path.exists(path):
                os.remove(path)
    for s in manifest.get("sysctl", []):
        if s["old"] is not None:
            actions.append(("sysctl", f"{s['key']}={s['old']}"))
            if not dry_run:
                ctx.run(["sysctl", "-w", f"{s['key']}={s['old']}"])
    return actions

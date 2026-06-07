"""Historial de auditorías en disco, para el dashboard y la tendencia."""

import json
import os
from datetime import datetime


def history_dir(ctx):
    if ctx.is_root():
        base = "/var/lib/hardenix/history"
    else:
        base = os.path.expanduser("~/.local/share/hardenix/history")
    return base


def save_history(ctx, data):
    d = history_dir(ctx)
    os.makedirs(d, exist_ok=True)
    now = datetime.now()
    hid = now.strftime("%Y%m%d-%H%M%S") + f"-{now.microsecond // 1000:03d}"
    with open(os.path.join(d, hid + ".json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)
    return hid


def list_history(ctx, full=False):
    d = history_dir(ctx)
    if not os.path.isdir(d):
        return []
    items = []
    for name in sorted(os.listdir(d)):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(d, name), encoding="utf-8") as fh:
                obj = json.load(fh)
        except (OSError, ValueError):
            continue
        if full:
            items.append(obj)
        else:
            items.append({
                "id": name[:-5],
                "generated": obj.get("generated"),
                "score": obj.get("score"),
                "summary": obj.get("summary"),
            })
    return items

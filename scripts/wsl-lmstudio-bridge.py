#!/usr/bin/env python3
"""Puente TCP para usar LM Studio (Windows) desde WSL.

LM Studio escucha por defecto solo en 127.0.0.1, que NO es accesible desde
WSL2. Este puente se ejecuta EN WINDOWS, escucha en 0.0.0.0:<listen> y reenvía
el tráfico a 127.0.0.1:<target>, de modo que desde WSL puedes apuntar a la IP
del host de Windows.

Uso:

    # 1) En Windows (deja esta ventana abierta):
    python scripts/wsl-lmstudio-bridge.py            # 0.0.0.0:1235 -> 127.0.0.1:1234

    # 2) En WSL:
    HOST=$(ip route show default | awk '{print $3}')
    python3 -m hardenix audit --ai --ai-url "http://$HOST:1235/v1"

Alternativa sin puente: activar "Serve on Local Network" en LM Studio (hace que
escuche en 0.0.0.0) y apuntar directamente a la IP del host en el puerto 1234.
"""

import argparse
import socket
import threading


def _pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _handle(client, target):
    try:
        upstream = socket.create_connection(target)
    except OSError:
        client.close()
        return
    threading.Thread(target=_pipe, args=(client, upstream), daemon=True).start()
    _pipe(upstream, client)
    for sock in (client, upstream):
        try:
            sock.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description="Puente TCP LM Studio para WSL.")
    ap.add_argument("--listen-host", default="0.0.0.0")
    ap.add_argument("--listen-port", type=int, default=1235)
    ap.add_argument("--target-host", default="127.0.0.1")
    ap.add_argument("--target-port", type=int, default=1234)
    args = ap.parse_args()

    target = (args.target_host, args.target_port)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.listen_host, args.listen_port))
    srv.listen(50)
    print(f"Puente activo: {args.listen_host}:{args.listen_port} -> "
          f"{args.target_host}:{args.target_port}  (Ctrl+C para salir)")
    try:
        while True:
            client, _ = srv.accept()
            threading.Thread(target=_handle, args=(client, target), daemon=True).start()
    except KeyboardInterrupt:
        print("\nPuente detenido.")


if __name__ == "__main__":
    main()

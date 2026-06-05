# Usar la IA local (`--ai`) desde WSL

Si ejecutas Hardenix dentro de **WSL** pero **LM Studio corre en Windows**, hay un
detalle de red: LM Studio escucha por defecto en `127.0.0.1:1234`, y ese
`localhost` **no es accesible desde WSL2** (cada uno tiene su propio `localhost`).

Tienes dos formas de resolverlo.

## Opción A — "Serve on Local Network" (recomendada, permanente)

1. En **LM Studio** → pestaña *Developer / Local Server*.
2. Activa **"Serve on Local Network"** (hace que escuche en `0.0.0.0`).
3. Pulsa **Start Server**.
4. Desde WSL, obtén la IP del host de Windows y apunta Hardenix a ella:

```bash
HOST=$(ip route show default | awk '{print $3}')   # p. ej. 172.20.192.1
python3 -m hardenix audit --ai --ai-url "http://$HOST:1234/v1"
```

## Opción B — Puente TCP (sin cambiar ajustes de LM Studio)

Incluido en el repo: [`scripts/wsl-lmstudio-bridge.py`](../scripts/wsl-lmstudio-bridge.py).
Se ejecuta **en Windows**, escucha en `0.0.0.0:1235` y reenvía a `127.0.0.1:1234`.

```bash
# 1) En Windows (deja la ventana abierta):
python scripts\wsl-lmstudio-bridge.py            # 0.0.0.0:1235 -> 127.0.0.1:1234

# 2) En WSL:
HOST=$(ip route show default | awk '{print $3}')
python3 -m hardenix audit --ai --ai-url "http://$HOST:1235/v1"
```

## Comprobar la conexión

```bash
HOST=$(ip route show default | awk '{print $3}')
curl -s "http://$HOST:1235/v1/models"     # debe devolver la lista de modelos
```

## Notas

- La IP del host (`172.20.x.1`) **puede cambiar** al reiniciar WSL/Windows; por eso
  se calcula con `ip route` en lugar de fijarla.
- Para mejores explicaciones en español, usa un modelo **instruct generalista**
  (Llama/Mistral/Qwen Instruct). Los modelos de *código* funcionan, pero a veces
  cuelan algún carácter de otro alfabeto (Hardenix los filtra igualmente).
- Si el servidor no está disponible, `--ai` simplemente se omite y la auditoría
  continúa con normalidad.

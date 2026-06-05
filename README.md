# 🛡️ Hardenix

**Auditor y endurecedor de seguridad para Linux** — escanea tu sistema contra buenas prácticas (estilo CIS Benchmark), te da una **puntuación de seguridad**, y (próximamente) **corrige** lo inseguro con copia de seguridad y *rollback*.

No es "otro script de checks": el objetivo es **auditar → puntuar → arreglar → volver a puntuar**, con informe antes/después y explicaciones en lenguaje claro.

```
  HARDENIX  ·  auditoría de endurecimiento Linux
  Sistema: Kali GNU/Linux Rolling

  [FALLO]  MEDIA    Autenticación por contraseña deshabilitada (solo claves)
          actual:   PasswordAuthentication yes
          esperado: PasswordAuthentication no
  [ OK ]  ALTA     ASLR activado (randomize_va_space = 2)
  ...

  8 OK   6 fallos   1 n/a
  Puntuación de seguridad:  71/100
  █████████████████████░░░░░░░░░
```

## ¿Por qué es diferente?

La mayoría de auditores (Lynis, etc.) solo **avisan**. Hardenix busca:

- ✅ **Auditoría con puntuación** ponderada por severidad.
- 🔧 **Remediación con rollback** — aplica el *fix* y guarda copia para deshacer.
- 📊 **Informe antes/después** (terminal + HTML) — ideal para demostrar mejora.
- 🤖 **Explicaciones con IA local** (vía LM Studio) — cada fallo explicado en español, sin enviar datos a la nube.
- 🐧 Pensado para **multi-distro** (Debian/Ubuntu y RHEL).

## Qué comprueba (Fase 1)

| Categoría | Ejemplos |
|-----------|----------|
| **SSH** | login de root, autenticación por clave, `MaxAuthTries`, X11, contraseñas vacías |
| **Kernel (sysctl)** | ASLR, SYN cookies, ICMP redirects, *reverse path filtering* |
| **Cuentas** | caducidad de contraseña, `UMASK`, contraseñas vacías, UID 0 único |
| **Permisos** | `/etc/shadow`, `/etc/passwd` |

## Uso

Requiere Python 3.8+. La auditoría base **no necesita dependencias**.

```bash
# Auditar el sistema
python3 -m hardenix audit

# Salida en JSON (para integrar en otras herramientas)
python3 -m hardenix audit --json

# Ver qué corregiría (vista previa, no cambia nada)
sudo python3 -m hardenix fix

# Aplicar las correcciones (respalda cada cambio antes)
sudo python3 -m hardenix fix --yes

# Incluir también fixes con riesgo de bloqueo (p. ej. SSH solo-claves)
sudo python3 -m hardenix fix --yes --incluir-riesgo

# Deshacer el último conjunto de cambios
sudo python3 -m hardenix rollback --yes
sudo python3 -m hardenix rollback --list        # ver snapshots
```

> Ejecútalo con `sudo` para que apliquen todos los checks y se puedan escribir
> los cambios. Por seguridad, `fix` **solo previsualiza** salvo que añadas `--yes`,
> y omite los fixes peligrosos salvo `--incluir-riesgo`.

## Hoja de ruta

- [x] **Fase 1** — Motor de checks, scoring e informe en terminal
- [x] **Fase 2** — Remediación automática con copia de seguridad y *rollback*
- [ ] **Fase 3** — Informe HTML con comparativa antes/después
- [ ] **Fase 4** — Explicaciones con IA local (LM Studio)
- [ ] **Fase 5** — Más checks (firewall, servicios, auditd) y soporte multi-distro
- [ ] **Fase 6** — Dashboard web

## Aviso

Hardenix modifica configuración de seguridad del sistema. Pruébalo siempre primero
en una máquina de pruebas o VM. El autor no se responsabiliza de un uso indebido.

## Licencia

MIT © Óscar Carretero Hilillo

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CHICO SP Obfuscator v3.2

Ofuscador reversible para scripts Python y Bash/POSIX Shell.

Objetivos:
- Compatibilidad con Linux, Termux, macOS y Windows para la interfaz Python.
- No utilizar eval para ejecutar el contenido desempaquetado.
- No depender de npm ni de bash-obfuscate.
- Restaurar únicamente archivos generados por esta herramienta.

Nota: la ofuscación dificulta la lectura, pero no sustituye cifrado ni protege
secretos embebidos frente a un analista con acceso al archivo ejecutable.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import marshal
import os
import re
import secrets
import shutil
import stat
import sys
import textwrap
import time
import webbrowser
import zlib
from pathlib import Path
from pprint import pformat
from typing import Callable

APP_NAME = "CHICO SP Obfuscator"
VERSION = "3.2"
AUTHOR = "CHICO_SP"
GITHUB_URL = "https://github.com/CHICO-CP"
TELEGRAM_URL = "https://t.me/CHICO_CP"

SHELL_MARKER = "__GDSH_PAYLOAD_BELOW__"
SHELL_FORMAT = "GDSH1"
PYTHON_FORMAT = "GDPY1"
DEFAULT_CHUNK_SIZE = 76

# Método Emoji original de CHICO_SP. Cada emoji representa un dígito decimal.
alphabet = [
    "\U0001f600",
    "\U0001f603",
    "\U0001f604",
    "\U0001f601",
    "\U0001f605",
    "\U0001f923",
    "\U0001f602",
    "\U0001f609",
    "\U0001f60A",
    "\U0001f61b",
]

MAX_STR_LEN = 70
OFFSET = 10


class Color:
    enabled = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    @classmethod
    def code(cls, value: str) -> str:
        return value if cls.enabled else ""

    RESET = "\033[0m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    WHITE = "\033[0;37m"


def c(value: str) -> str:
    return Color.code(value)


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def slow_print(text: str, delay: float = 0.0) -> None:
    if delay <= 0:
        print(text)
        return
    for char in text + "\n":
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)


def logo() -> str:
    return f"""{c(Color.GREEN)}╔═══╗──────────────────╔╗
{c(Color.YELLOW)}║╔═╗║──────────────────║║
{c(Color.RED)}║╚═╝╠╗─╔╗╔══╦═╗╔══╦══╦═╝╠══╗
{c(Color.CYAN)}║╔══╣║─║║║║═╣╔╗╣╔═╣╔╗║╔╗║║═╣
{c(Color.GREEN)}║║──║╚═╝║║║═╣║║║╚═╣╚╝║╚╝║║═╣
{c(Color.YELLOW)}╚╝──╚═╗╔╝╚══╩╝╚╩══╩══╩══╩══╝
{c(Color.RED)}────╔═╝║
{c(Color.CYAN)}────╚══╝ V{VERSION}
{c(Color.YELLOW)}[{AUTHOR}]{c(Color.RESET)}"""


def info(message: str) -> None:
    print(f"{c(Color.YELLOW)}[+]{c(Color.RESET)} {message}")


def success(message: str) -> None:
    print(f"{c(Color.GREEN)}[✓]{c(Color.RESET)} {message}")


def error(message: str) -> None:
    print(f"{c(Color.RED)}[!]{c(Color.RESET)} {message}")


def ask(prompt: str) -> str:
    return input(f"{c(Color.GREEN)}[?]{c(Color.RESET)} {prompt}").strip()


def pause() -> None:
    try:
        input("\nPresiona Enter para continuar...")
    except EOFError:
        pass


def read_existing_file(prompt: str) -> Path:
    while True:
        raw = ask(prompt).strip('"\'')
        path = Path(raw).expanduser()
        if path.is_file():
            return path.resolve()
        error(f"No existe el archivo: {path}")


def choose_output_path(input_path: Path, default_suffix: str) -> Path:
    default_name = input_path.with_name(f"{input_path.stem}{default_suffix}{input_path.suffix}")
    raw = ask(f"Archivo de salida [{default_name}]: ")
    output = Path(raw.strip('"\'')).expanduser() if raw else default_name
    output = output.resolve()

    if output == input_path:
        raise ValueError("El archivo de salida no puede ser el mismo que el de entrada.")

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        answer = ask(f"{output} ya existe. ¿Sobrescribir? [s/N]: ").lower()
        if answer not in {"s", "si", "sí", "y", "yes"}:
            raise FileExistsError("Operación cancelada; no se sobrescribió el archivo.")
    return output


def atomic_write(path: Path, data: bytes, executable: bool = False) -> None:
    temp_path = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        temp_path.write_bytes(data)
        if executable and os.name != "nt":
            current = temp_path.stat().st_mode
            temp_path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def wrap_text(value: str, width: int = DEFAULT_CHUNK_SIZE) -> str:
    return "\n".join(textwrap.wrap(value, width=width, break_long_words=True))


def random_identifier(prefix: str = "_gd") -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


def detect_shell(source: bytes) -> str:
    first_line = source.splitlines()[0].decode("utf-8", errors="ignore") if source else ""
    return "bash" if "bash" in first_line else "sh"


def make_shell_loader(source: bytes, target_shell: str) -> bytes:
    if target_shell not in {"bash", "sh"}:
        raise ValueError("El intérprete debe ser 'bash' o 'sh'.")

    compressed = gzip.compress(source, compresslevel=9, mtime=0)
    payload = base64.b64encode(compressed).decode("ascii")
    digest = hashlib.sha256(source).hexdigest()

    # Identificadores aleatorios: no agregan seguridad criptográfica, pero evitan
    # que todos los loaders generados tengan exactamente la misma estructura.
    tmp_var = random_identifier("_tmp")
    b64_var = random_identifier("_b64")
    gz_var = random_identifier("_gz")
    line_var = random_identifier("_line")
    hash_var = random_identifier("_hash")
    status_var = random_identifier("_status")
    shell_var = random_identifier("_shell")

    loader = f'''#!/bin/sh
# Generated by {APP_NAME} v{VERSION}
# GDOFUSCATOR_FORMAT={SHELL_FORMAT}
# GDOFUSCATOR_TARGET={target_shell}
# GDOFUSCATOR_SHA256={digest}
# La ofuscación no equivale a cifrado de secretos.

set -u
umask 077

{tmp_var}="${{TMPDIR:-/tmp}}/.gdsh.$$"
{b64_var}="${{{tmp_var}}}.b64"
{gz_var}="${{{tmp_var}}}.gz"
{hash_var}="{digest}"
{shell_var}="{target_shell}"

_gd_cleanup() {{
    rm -f "${{{tmp_var}}}" "${{{b64_var}}}" "${{{gz_var}}}" 2>/dev/null || true
}}
trap _gd_cleanup EXIT HUP INT TERM

{line_var}=$(awk '/^{SHELL_MARKER}$/ {{ print NR + 1; exit }}' "$0")
if [ -z "${{{line_var}}}" ]; then
    printf '%s\n' "Error: payload no encontrado." >&2
    exit 70
fi

tail -n +"${{{line_var}}}" "$0" | tr -d '\\r\\n' > "${{{b64_var}}}"

if command -v base64 >/dev/null 2>&1; then
    if ! base64 -d "${{{b64_var}}}" > "${{{gz_var}}}" 2>/dev/null; then
        if ! base64 -D "${{{b64_var}}}" > "${{{gz_var}}}" 2>/dev/null; then
            printf '%s\n' "Error: no se pudo decodificar Base64." >&2
            exit 71
        fi
    fi
elif command -v openssl >/dev/null 2>&1; then
    openssl base64 -d -A -in "${{{b64_var}}}" -out "${{{gz_var}}}" || exit 71
elif command -v python3 >/dev/null 2>&1; then
    python3 - "${{{b64_var}}}" "${{{gz_var}}}" <<'PY_GD_B64'
import base64, pathlib, sys
pathlib.Path(sys.argv[2]).write_bytes(base64.b64decode(pathlib.Path(sys.argv[1]).read_bytes()))
PY_GD_B64
else
    printf '%s\n' "Error: se requiere base64, openssl o python3." >&2
    exit 72
fi

if command -v gzip >/dev/null 2>&1; then
    gzip -dc "${{{gz_var}}}" > "${{{tmp_var}}}" || exit 73
elif command -v busybox >/dev/null 2>&1; then
    busybox gzip -dc "${{{gz_var}}}" > "${{{tmp_var}}}" || exit 73
elif command -v python3 >/dev/null 2>&1; then
    python3 - "${{{gz_var}}}" "${{{tmp_var}}}" <<'PY_GD_GZIP'
import gzip, pathlib, sys
pathlib.Path(sys.argv[2]).write_bytes(gzip.decompress(pathlib.Path(sys.argv[1]).read_bytes()))
PY_GD_GZIP
else
    printf '%s\n' "Error: se requiere gzip, busybox o python3." >&2
    exit 74
fi

chmod 700 "${{{tmp_var}}}" 2>/dev/null || true

if command -v sha256sum >/dev/null 2>&1; then
    _gd_actual=$(sha256sum "${{{tmp_var}}}" | awk '{{print $1}}')
elif command -v shasum >/dev/null 2>&1; then
    _gd_actual=$(shasum -a 256 "${{{tmp_var}}}" | awk '{{print $1}}')
elif command -v openssl >/dev/null 2>&1; then
    _gd_actual=$(openssl dgst -sha256 "${{{tmp_var}}}" | awk '{{print $NF}}')
else
    _gd_actual=""
fi

if [ -n "$_gd_actual" ] && [ "$_gd_actual" != "${{{hash_var}}}" ]; then
    printf '%s\n' "Error: integridad SHA-256 inválida." >&2
    exit 75
fi

if [ "${{{shell_var}}}" = "bash" ]; then
    if ! command -v bash >/dev/null 2>&1; then
        printf '%s\n' "Error: el payload requiere Bash." >&2
        exit 76
    fi
    bash "${{{tmp_var}}}" "$@"
else
    sh "${{{tmp_var}}}" "$@"
fi
{status_var}=$?
_gd_cleanup
trap - EXIT HUP INT TERM
exit "${{{status_var}}}"

{SHELL_MARKER}
{wrap_text(payload)}
'''
    return loader.encode("utf-8")


def restore_shell_loader(loader: bytes) -> bytes:
    text = loader.decode("utf-8", errors="strict")
    marker = f"\n{SHELL_MARKER}\n"
    if marker not in text:
        raise ValueError("El archivo no contiene un payload GDSH compatible.")

    header, encoded = text.split(marker, 1)
    if f"GDOFUSCATOR_FORMAT={SHELL_FORMAT}" not in header:
        raise ValueError("Formato Shell desconocido o no compatible.")

    compact = re.sub(r"\s+", "", encoded)
    try:
        compressed = base64.b64decode(compact, validate=True)
        source = gzip.decompress(compressed)
    except Exception as exc:
        raise ValueError(f"Payload Shell dañado: {exc}") from exc

    match = re.search(r"^# GDOFUSCATOR_SHA256=([0-9a-f]{64})$", header, flags=re.MULTILINE)
    if match:
        actual = hashlib.sha256(source).hexdigest()
        if actual != match.group(1):
            raise ValueError("La comprobación SHA-256 del payload Shell falló.")
    return source


def make_python_marshal_loader(source_text: str, source_name: str) -> str:
    code = compile(source_text, source_name, "exec", dont_inherit=True, optimize=2)
    payload = base64.b85encode(zlib.compress(marshal.dumps(code), level=9)).decode("ascii")
    digest = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    variable = random_identifier("_payload")

    chunks = textwrap.wrap(payload, width=90)
    literal = "\n    ".join(repr(chunk) for chunk in chunks)
    return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Generated by {APP_NAME} v{VERSION}
# GDOFUSCATOR_FORMAT={PYTHON_FORMAT}-MARSHAL
# GDOFUSCATOR_SHA256={digest}
# Requiere una versión compatible de Python {sys.version_info.major}.{sys.version_info.minor}.

import base64 as _b64
import marshal as _marshal
import zlib as _zlib

{variable} = (
    {literal}
)
exec(_marshal.loads(_zlib.decompress(_b64.b85decode({variable}.encode("ascii")))))
'''


def make_python_base64_loader(source_text: str) -> str:
    payload = base64.b64encode(zlib.compress(source_text.encode("utf-8"), level=9)).decode("ascii")
    digest = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    variable = random_identifier("_payload")
    chunks = textwrap.wrap(payload, width=88)
    assignments = "\n".join(f'{variable} += "{chunk}"' for chunk in chunks)

    return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Generated by {APP_NAME} v{VERSION}
# GDOFUSCATOR_FORMAT={PYTHON_FORMAT}-BASE64
# GDOFUSCATOR_SHA256={digest}

import base64 as _b64
import zlib as _zlib

{variable} = ""
{assignments}
_source = _zlib.decompress(_b64.b64decode({variable})).decode("utf-8")
exec(compile(_source, "<chico_sp_obfuscated>", "exec"))
'''


def make_python_chico_variable_loader(source_text: str) -> str:
    """Conserva y mejora el método clásico CHICO_SP basado en Base64.

    El contenido Base64 se divide en fragmentos y cada carácter se representa
    mediante escapes hexadecimales. Se mantiene el identificador histórico
    ``CHICO_SP`` repetido 50 veces para no eliminar la función original.
    """
    source_bytes = source_text.encode("utf-8")
    payload = base64.b64encode(source_bytes).decode("ascii")
    digest = hashlib.sha256(source_bytes).hexdigest()
    variable = "CHICO_SP" * 50

    assignments: list[str] = [f'{variable} = b""']
    for chunk in textwrap.wrap(payload, width=OFFSET):
        escaped = "".join(f"\\x{ord(char):02x}" for char in chunk)
        assignments.append(f'{variable} += b"{escaped}"')

    joined_assignments = "\n".join(assignments)
    return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Generated by {APP_NAME} v{VERSION}
# GDOFUSCATOR_FORMAT={PYTHON_FORMAT}-CHICO-VARIABLE
# GDOFUSCATOR_SHA256={digest}
# Método clásico CHICO_SP mejorado; Base64 reversible.

import base64 as _chico_b64
import hashlib as _chico_hash

{joined_assignments}
_chico_raw = _chico_b64.b64decode({variable}, validate=True)
if _chico_hash.sha256(_chico_raw).hexdigest() != "{digest}":
    raise RuntimeError("El contenido ofuscado está dañado o fue modificado.")
_chico_source = _chico_raw.decode("utf-8")
exec(compile(_chico_source, "<chico_sp_variable>", "exec"), globals(), globals())
'''


def chunk_string(in_s: str, n: int) -> str:
    """Divide la cadena como en el método Emoji original."""
    return "\n".join(
        "{}\\".format(in_s[i : i + n]) for i in range(0, len(in_s), n)
    ).rstrip("\\")


def encode_string(in_s: str, emoji_alphabet: list[str]) -> str:
    """Codifica Python usando exactamente los 10 emojis del método original.

    Cada carácter se convierte a su código Unicode decimal y cada dígito decimal
    se sustituye por un emoji. El archivo generado reconstruye los números, usa
    ``chr`` para recuperar el código y lo ejecuta.
    """
    d1 = dict(enumerate(emoji_alphabet))
    d2 = {value: key for key, value in d1.items()}
    encoded = "  ".join(
        " ".join(d1[int(digit)] for digit in str(ord(char)))
        for char in in_s
    )
    return (
        'exec("".join(map(chr,[int("".join(str({}[i]) for i in x.split())) for x in\n'
        '"{}"\n.split("  ")])))\n'.format(
            pformat(d2),
            chunk_string(encoded, MAX_STR_LEN),
        )
    )


def make_python_emoji_loader(source_text: str) -> str:
    """Genera el mismo formato Emoji decimal usado por la versión original."""
    digest = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    encoded_loader = encode_string(source_text, alphabet)
    header = (
        "#!/usr/bin/env python3\n"
        "# -*- coding: utf-8 -*-\n"
        f"# Generated by {APP_NAME} v{VERSION}\n"
        f"# GDOFUSCATOR_FORMAT={PYTHON_FORMAT}-EMOJI-LEGACY\n"
        f"# GDOFUSCATOR_SHA256={digest}\n"
        "# Método Emoji original CHICO_SP: 10 emojis para dígitos decimales.\n\n"
    )
    return header + encoded_loader


def read_python_source(path: Path) -> str:
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("El archivo Python debe estar codificado en UTF-8.") from exc


def action_obfuscate_shell() -> None:
    input_path = read_existing_file("Archivo Bash/Shell de entrada: ")
    source = input_path.read_bytes()
    detected = detect_shell(source)
    chosen = ask(f"Intérprete objetivo [bash/sh] (detectado: {detected}): ").lower() or detected
    if chosen not in {"bash", "sh"}:
        raise ValueError("Selecciona únicamente 'bash' o 'sh'.")

    output_path = choose_output_path(input_path, "_enc")
    atomic_write(output_path, make_shell_loader(source, chosen), executable=True)
    success(f"Shell ofuscado guardado en: {output_path}")
    info(f'Ejecución normal: bash "{output_path.name}" [argumentos]')
    info("El código fuente queda comprimido y codificado dentro del archivo.")


def action_restore_shell() -> None:
    input_path = read_existing_file("Archivo Shell generado por esta herramienta: ")
    output_path = choose_output_path(input_path, "_restored")
    source = restore_shell_loader(input_path.read_bytes())
    atomic_write(output_path, source, executable=True)
    success(f"Shell restaurado guardado en: {output_path}")


def action_obfuscate_python(factory: Callable[..., str], label: str) -> None:
    input_path = read_existing_file("Archivo Python de entrada: ")
    source = read_python_source(input_path)
    output_path = choose_output_path(input_path, f"_{label}")

    if factory is make_python_marshal_loader:
        result = factory(source, input_path.name)
    else:
        result = factory(source)

    atomic_write(output_path, result.encode("utf-8"), executable=True)
    success(f"Python ofuscado guardado en: {output_path}")


def show_about() -> None:
    clear_screen()
    print(logo())
    print(f"\nHerramienta : {APP_NAME}")
    print(f"Versión     : {VERSION}")
    print(f"Autor       : {AUTHOR}")
    print(f"GitHub      : {GITHUB_URL}")
    print(f"Telegram    : {TELEGRAM_URL}")
    print("\nLos métodos incluidos son ofuscación reversible, no cifrado seguro.")
    pause()


def open_more_tools() -> None:
    if not webbrowser.open(GITHUB_URL):
        info(f"Abre manualmente: {GITHUB_URL}")


def show_menu() -> None:
    clear_screen()
    print(logo())
    print()
    print(f"{c(Color.GREEN)}[1]{c(Color.RESET)} Ofuscar Bash/Shell ejecutable (_enc.sh)")
    print(f"{c(Color.GREEN)}[2]{c(Color.RESET)} Restaurar Bash/Shell generado por la herramienta")
    print(f"{c(Color.GREEN)}[3]{c(Color.RESET)} Ofuscar Python: Marshal + Zlib + Base85")
    print(f"{c(Color.GREEN)}[4]{c(Color.RESET)} Ofuscar Python: variable CHICO_SP + Base64")
    print(f"{c(Color.GREEN)}[5]{c(Color.RESET)} Ofuscar Python: Zlib + Base64")
    print(f"{c(Color.GREEN)}[6]{c(Color.RESET)} Ofuscar Python: Emoji original (10 símbolos)")
    print(f"{c(Color.GREEN)}[7]{c(Color.RESET)} Más herramientas")
    print(f"{c(Color.GREEN)}[8]{c(Color.RESET)} Acerca de")
    print(f"{c(Color.GREEN)}[0]{c(Color.RESET)} Salir")


def main() -> int:
    actions: dict[str, Callable[[], None]] = {
        "1": action_obfuscate_shell,
        "01": action_obfuscate_shell,
        "2": action_restore_shell,
        "02": action_restore_shell,
        "3": lambda: action_obfuscate_python(make_python_marshal_loader, "marshal"),
        "03": lambda: action_obfuscate_python(make_python_marshal_loader, "marshal"),
        "4": lambda: action_obfuscate_python(make_python_chico_variable_loader, "chico_var"),
        "04": lambda: action_obfuscate_python(make_python_chico_variable_loader, "chico_var"),
        "5": lambda: action_obfuscate_python(make_python_base64_loader, "base64"),
        "05": lambda: action_obfuscate_python(make_python_base64_loader, "base64"),
        "6": lambda: action_obfuscate_python(make_python_emoji_loader, "emoji"),
        "06": lambda: action_obfuscate_python(make_python_emoji_loader, "emoji"),
        "7": open_more_tools,
        "07": open_more_tools,
        "8": show_about,
        "08": show_about,
    }

    while True:
        show_menu()
        choice = ask("Selecciona una opción: ")
        if choice == "0":
            return 0

        action = actions.get(choice)
        if action is None:
            error("Opción inválida.")
            time.sleep(1)
            continue

        try:
            action()
        except (ValueError, FileExistsError, OSError) as exc:
            error(str(exc))
        except KeyboardInterrupt:
            print()
            info("Operación cancelada.")
        except Exception as exc:
            error(f"Error inesperado: {exc}")

        if choice not in {"8", "08"}:
            pause()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        info("Gracias por usar la herramienta.")
        raise SystemExit(130)

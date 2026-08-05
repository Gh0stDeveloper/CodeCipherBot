"""Wrappers ejecutables para lenguajes interpretados.

Estos formatos son ofuscación reversible. Un archivo que se ejecuta sin una
clave externa debe incluir todo lo necesario para recuperar su carga.
"""

from __future__ import annotations

import base64
import marshal
import re
import zlib
from dataclasses import dataclass
from pathlib import PurePath


class RunnableError(ValueError):
    pass


@dataclass(frozen=True)
class RunnableResult:
    content: str
    filename: str
    language: str
    method: str


LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript_node",
    ".cjs": "javascript_node",
    ".html": "html",
    ".htm": "html",
    ".php": "php",
    ".sh": "bash",
    ".bash": "bash",
    ".ps1": "powershell",
    ".rb": "ruby",
    ".pl": "perl",
    ".lua": "lua",
}

COMPILED_EXTENSIONS = {
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".go": "Go",
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cs": "C#",
    ".rs": "Rust",
    ".swift": "Swift",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".mjs": "JavaScript ES Modules",
}

LANGUAGE_LABELS = {
    "python": "Python",
    "javascript_node": "JavaScript para Node.js",
    "javascript_browser": "JavaScript para navegador",
    "html": "HTML",
    "php": "PHP",
    "bash": "Bash",
    "powershell": "PowerShell",
    "ruby": "Ruby",
    "perl": "Perl",
    "lua": "Lua",
}

MARKER_RE = re.compile(r"CODECIPHER:([A-Z_]+):([A-Z0-9_]+):V1")
PAYLOAD_RE = re.compile(
    r"(?:\$_CODECIPHER_PAYLOAD|_CODECIPHER_PAYLOAD)\s*=\s*"
    r"['\"]([A-Za-z0-9+/=]+)['\"]",
    flags=re.DOTALL,
)
EMOJI_PAYLOAD_RE = re.compile(
    r"_CODECIPHER_EMOJI_PAYLOAD\s*=\s*'''(.*?)'''",
    flags=re.DOTALL,
)
MULTILAYER_PAYLOAD_RE = re.compile(
    r"_CODECIPHER_MULTILAYER_PAYLOAD\s*=\s*['\"]([^'\"]+)['\"]",
)
EMOJI_ALPHABET = (
    "😀", "😃", "😄", "😁", "😆", "😅", "😂", "🙂",
    "🙃", "😉", "😊", "😎", "🤓", "🧐", "🤖", "👻",
)
MAX_UNWRAPPED_BYTES = 30 * 1024 * 1024


def _safe_basename(filename: str) -> str:
    name = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
    return name or "script.txt"


def detect_language(filename: str, source: str = "") -> str | None:
    extension = PurePath(_safe_basename(filename)).suffix.lower()
    if extension in LANGUAGE_EXTENSIONS:
        return LANGUAGE_EXTENSIONS[extension]
    first_line = source.splitlines()[0].lower() if source.splitlines() else ""
    if "python" in first_line:
        return "python"
    if "bash" in first_line or first_line.endswith("/sh"):
        return "bash"
    if "pwsh" in first_line or "powershell" in first_line:
        return "powershell"
    if "ruby" in first_line:
        return "ruby"
    if "perl" in first_line:
        return "perl"
    if "lua" in first_line:
        return "lua"
    if "<?php" in source[:200].lower():
        return "php"
    return None


def compiled_language(filename: str) -> str | None:
    return COMPILED_EXTENSIONS.get(PurePath(_safe_basename(filename)).suffix.lower())


def _payload(source: str, compress: bool = False) -> str:
    data = source.encode("utf-8")
    if compress:
        data = zlib.compress(data, level=9)
    return base64.b64encode(data).decode("ascii")


def _python(source: str, filename: str, method: str) -> str:
    if method == "marshal":
        compiled = compile(source, filename, "exec")
        payload = base64.b64encode(marshal.dumps(compiled)).decode("ascii")
        return (
            "# CODECIPHER:PYTHON:MARSHAL:V1\n"
            "import base64 as _cc_b64, marshal as _cc_marshal\n"
            f"_CODECIPHER_PAYLOAD = {payload!r}\n"
            "exec(_cc_marshal.loads(_cc_b64.b64decode(_CODECIPHER_PAYLOAD)))\n"
        )
    compressed = method == "zlib"
    payload = _payload(source, compressed)
    imports = "import base64 as _cc_b64"
    decode = "_cc_b64.b64decode(_CODECIPHER_PAYLOAD)"
    marker = "ZLIB" if compressed else "BASE64"
    if compressed:
        imports += ", zlib as _cc_zlib"
        decode = f"_cc_zlib.decompress({decode})"
    return (
        f"# CODECIPHER:PYTHON:{marker}:V1\n"
        f"{imports}\n"
        f"_CODECIPHER_PAYLOAD = {payload!r}\n"
        f"_cc_source = {decode}.decode('utf-8')\n"
        "exec(compile(_cc_source, __file__, 'exec'), globals(), globals())\n"
    )


def _python_emoji(source: str) -> str:
    payload = "".join(
        EMOJI_ALPHABET[int(character, 16)]
        for character in source.encode("utf-8").hex()
    )
    chunks = "\n".join(
        payload[index:index + 96]
        for index in range(0, len(payload), 96)
    )
    return (
        "# CODECIPHER:PYTHON:EMOJI:V1\n"
        f"_cc_alphabet = {EMOJI_ALPHABET!r}\n"
        f"_CODECIPHER_EMOJI_PAYLOAD = '''{chunks}'''\n"
        "_cc_hex = ''.join(format(_cc_alphabet.index(char), 'x') "
        "for char in _CODECIPHER_EMOJI_PAYLOAD if char in _cc_alphabet)\n"
        "_cc_source = bytes.fromhex(_cc_hex).decode('utf-8')\n"
        "exec(compile(_cc_source, __file__, 'exec'), globals(), globals())\n"
    )


def _python_multilayer(source: str) -> str:
    data = source.encode("utf-8")
    for _ in range(3):
        data = base64.b85encode(zlib.compress(data, level=9))
    payload = data.decode("ascii")
    return (
        "# CODECIPHER:PYTHON:MULTILAYER:V1\n"
        "import base64 as _cc_b64, zlib as _cc_zlib\n"
        f"_CODECIPHER_MULTILAYER_PAYLOAD = {payload!r}\n"
        "_cc_data = _CODECIPHER_MULTILAYER_PAYLOAD.encode('ascii')\n"
        "for _cc_layer in range(3):\n"
        "    _cc_data = _cc_zlib.decompress(_cc_b64.b85decode(_cc_data))\n"
        "exec(compile(_cc_data.decode('utf-8'), __file__, 'exec'), globals(), globals())\n"
    )


def _javascript_node(source: str) -> str:
    payload = _payload(source)
    return (
        "/* CODECIPHER:JAVASCRIPT_NODE:BASE64:V1 */\n"
        f"const _CODECIPHER_PAYLOAD = {payload!r};\n"
        "const _ccSource = Buffer.from(_CODECIPHER_PAYLOAD, 'base64').toString('utf8');\n"
        "module._compile(_ccSource, __filename);\n"
    )


def _javascript_browser(source: str) -> str:
    payload = _payload(source)
    return (
        "/* CODECIPHER:JAVASCRIPT_BROWSER:BASE64:V1 */\n"
        f"const _CODECIPHER_PAYLOAD = {payload!r};\n"
        "const _ccBytes = Uint8Array.from(atob(_CODECIPHER_PAYLOAD), c => c.charCodeAt(0));\n"
        "(0, eval)(new TextDecoder().decode(_ccBytes));\n"
    )


def _html(source: str) -> str:
    payload = _payload(source)
    return (
        "<!doctype html>\n"
        "<meta charset=\"utf-8\">\n"
        "<!-- CODECIPHER:HTML:BASE64:V1 -->\n"
        "<script>\n"
        f"const _CODECIPHER_PAYLOAD = {payload!r};\n"
        "const _ccBytes = Uint8Array.from(atob(_CODECIPHER_PAYLOAD), c => c.charCodeAt(0));\n"
        "const _ccSource = new TextDecoder().decode(_ccBytes);\n"
        "document.open(); document.write(_ccSource); document.close();\n"
        "</script>\n"
    )


def _php(source: str) -> str:
    payload = _payload(source)
    return (
        "<?php\n"
        "// CODECIPHER:PHP:BASE64:V1\n"
        f"$_CODECIPHER_PAYLOAD = '{payload}';\n"
        "$_cc_source = base64_decode($_CODECIPHER_PAYLOAD, true);\n"
        "if ($_cc_source === false) { throw new RuntimeException('Carga invalida'); }\n"
        "eval('?>' . $_cc_source);\n"
        "?>\n"
    )


def _bash(source: str) -> str:
    payload = _payload(source)
    return (
        "#!/usr/bin/env bash\n"
        "# CODECIPHER:BASH:BASE64:V1\n"
        f"_CODECIPHER_PAYLOAD='{payload}'\n"
        "if base64 --help 2>&1 | grep -q -- '--decode'; then\n"
        "  _cc_source=$(printf '%s' \"$_CODECIPHER_PAYLOAD\" | base64 --decode)\n"
        "else\n"
        "  _cc_source=$(printf '%s' \"$_CODECIPHER_PAYLOAD\" | base64 -D)\n"
        "fi\n"
        "eval \"$_cc_source\"\n"
    )


def _powershell(source: str) -> str:
    payload = _payload(source)
    return (
        "# CODECIPHER:POWERSHELL:BASE64:V1\n"
        f"$_CODECIPHER_PAYLOAD = '{payload}'\n"
        "$_ccSource = [Text.Encoding]::UTF8.GetString("
        "[Convert]::FromBase64String($_CODECIPHER_PAYLOAD))\n"
        "& ([ScriptBlock]::Create($_ccSource)) @args\n"
    )


def _ruby(source: str, filename: str) -> str:
    payload = _payload(source)
    return (
        "# CODECIPHER:RUBY:BASE64:V1\n"
        "require 'base64'\n"
        f"_CODECIPHER_PAYLOAD = '{payload}'\n"
        "eval(Base64.strict_decode64(_CODECIPHER_PAYLOAD), TOPLEVEL_BINDING, __FILE__)\n"
    )


def _perl(source: str) -> str:
    payload = _payload(source)
    return (
        "#!/usr/bin/env perl\n"
        "# CODECIPHER:PERL:BASE64:V1\n"
        "use MIME::Base64 qw(decode_base64);\n"
        f"my $_CODECIPHER_PAYLOAD = '{payload}';\n"
        "my $_cc_source = decode_base64($_CODECIPHER_PAYLOAD);\n"
        "eval $_cc_source;\ndie $@ if $@;\n"
    )


def _lua(source: str, filename: str) -> str:
    payload = _payload(source)
    return (
        "-- CODECIPHER:LUA:BASE64:V1\n"
        f"local _CODECIPHER_PAYLOAD = '{payload}'\n"
        "local _cc_alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'\n"
        "local function _cc_decode(data)\n"
        "  data=string.gsub(data,'[^'.._cc_alphabet..'=]','')\n"
        "  return (data:gsub('.', function(x)\n"
        "    if x=='=' then return '' end\n"
        "    local r,f='',(_cc_alphabet:find(x)-1)\n"
        "    for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end\n"
        "    return r\n"
        "  end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)\n"
        "    if #x~=8 then return '' end\n"
        "    local c=0\n"
        "    for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end\n"
        "    return string.char(c)\n"
        "  end))\n"
        "end\n"
        "local _cc_loader = load or loadstring\n"
        f"local _cc_chunk, _cc_error = _cc_loader(_cc_decode(_CODECIPHER_PAYLOAD), '@{filename}')\n"
        "assert(_cc_chunk, _cc_error)\n"
        "return _cc_chunk()\n"
    )


def protect_code(
    source: str,
    filename: str,
    language: str | None = None,
    method: str = "base64",
) -> RunnableResult:
    safe_name = _safe_basename(filename)
    selected = language or detect_language(safe_name, source)
    if not selected:
        compiled = compiled_language(safe_name)
        if compiled:
            raise RunnableError(
                f"{compiled} necesita compilación o empaquetado. El bot puede proteger su fuente, "
                "pero no convertirla en un ejecutable portable sin toolchain."
            )
        raise RunnableError(
            "No se pudo detectar un lenguaje ejecutable. Usa una extensión compatible."
        )
    if selected not in LANGUAGE_LABELS:
        raise RunnableError("Lenguaje no compatible.")
    if method not in {"base64", "zlib", "marshal", "emoji", "multilayer"}:
        raise RunnableError("Método ejecutable no compatible.")
    if method in {"zlib", "marshal", "emoji", "multilayer"} and selected != "python":
        raise RunnableError(
            "Zlib, Marshal, Emoji y multicapa ejecutables están disponibles para Python."
        )

    if selected == "python":
        if method == "emoji":
            output = _python_emoji(source)
        elif method == "multilayer":
            output = _python_multilayer(source)
        else:
            output = _python(source, safe_name, method)
    elif selected == "javascript_node":
        output = _javascript_node(source)
    elif selected == "javascript_browser":
        output = _javascript_browser(source)
    elif selected == "html":
        output = _html(source)
    elif selected == "php":
        output = _php(source)
    elif selected == "bash":
        output = _bash(source)
    elif selected == "powershell":
        output = _powershell(source)
    elif selected == "ruby":
        output = _ruby(source, safe_name)
    elif selected == "perl":
        output = _perl(source)
    elif selected == "lua":
        output = _lua(source, safe_name)
    else:  # pragma: no cover - protegido por el registro
        raise RunnableError("Lenguaje no compatible.")

    stem = PurePath(safe_name).stem or "script"
    suffix = PurePath(safe_name).suffix or ".txt"
    return RunnableResult(
        content=output,
        filename=f"protected_{stem}{suffix}",
        language=selected,
        method=method,
    )


def unwrap_code(wrapper: str, original_filename: str = "decoded.txt") -> RunnableResult:
    marker = MARKER_RE.search(wrapper)
    if not marker:
        raise RunnableError("No se encontró un marcador CodeCipher ejecutable.")
    language_marker, method = marker.groups()
    if method == "MARSHAL":
        raise RunnableError(
            "Marshal conserva bytecode ejecutable, pero no contiene el código fuente original."
        )
    try:
        if method == "EMOJI":
            emoji_match = EMOJI_PAYLOAD_RE.search(wrapper)
            if not emoji_match:
                raise RunnableError("La carga Emoji está incompleta.")
            symbols = [
                character
                for character in emoji_match.group(1)
                if not character.isspace()
            ]
            if len(symbols) % 2 or any(
                character not in EMOJI_ALPHABET for character in symbols
            ):
                raise RunnableError("La carga Emoji está dañada.")
            hexadecimal = "".join(
                format(EMOJI_ALPHABET.index(character), "x")
                for character in symbols
            )
            data = bytes.fromhex(hexadecimal)
        elif method == "MULTILAYER":
            multilayer_match = MULTILAYER_PAYLOAD_RE.search(wrapper)
            if not multilayer_match:
                raise RunnableError("La carga multicapa está incompleta.")
            data = multilayer_match.group(1).encode("ascii")
            for _ in range(3):
                data = _safe_zlib_decompress(base64.b85decode(data))
        else:
            payload_match = PAYLOAD_RE.search(wrapper)
            if not payload_match:
                raise RunnableError("La carga ejecutable está incompleta.")
            data = base64.b64decode(payload_match.group(1), validate=True)
            if method == "ZLIB":
                data = _safe_zlib_decompress(data)
        if len(data) > MAX_UNWRAPPED_BYTES:
            raise RunnableError("La carga supera el límite de seguridad.")
        source = data.decode("utf-8")
    except (ValueError, zlib.error, UnicodeDecodeError) as exc:
        raise RunnableError("La carga ejecutable está dañada.") from exc

    language = language_marker.lower()
    stem = PurePath(_safe_basename(original_filename)).stem or "script"
    suffix_by_language = {
        "python": ".py",
        "javascript_node": ".js",
        "javascript_browser": ".js",
        "html": ".html",
        "php": ".php",
        "bash": ".sh",
        "powershell": ".ps1",
        "ruby": ".rb",
        "perl": ".pl",
        "lua": ".lua",
    }
    return RunnableResult(
        content=source,
        filename=f"decoded_{stem}{suffix_by_language.get(language, '.txt')}",
        language=language,
        method=method.lower(),
    )


def _safe_zlib_decompress(data: bytes) -> bytes:
    try:
        decompressor = zlib.decompressobj()
        result = decompressor.decompress(data, MAX_UNWRAPPED_BYTES + 1)
        if decompressor.unconsumed_tail or len(result) > MAX_UNWRAPPED_BYTES:
            raise RunnableError("La capa descomprimida supera el límite.")
        result += decompressor.flush(
            max(1, MAX_UNWRAPPED_BYTES + 1 - len(result))
        )
        if not decompressor.eof or len(result) > MAX_UNWRAPPED_BYTES:
            raise RunnableError("La capa comprimida está incompleta o es demasiado grande.")
        return result
    except zlib.error as exc:
        raise RunnableError("La capa Zlib está dañada.") from exc

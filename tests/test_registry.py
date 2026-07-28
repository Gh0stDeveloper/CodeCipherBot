from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from codecipher.registry import ProcessingError, process
from codecipher.runnable import protect_code, unwrap_code


class RunnableWrapperTests(unittest.TestCase):
    def test_every_text_wrapper_can_be_unwrapped_without_execution(self) -> None:
        source = 'print("Hola, 世界")\n'
        fixtures = {
            "python": "script.py",
            "javascript_node": "script.js",
            "javascript_browser": "script.js",
            "html": "index.html",
            "php": "script.php",
            "bash": "script.sh",
            "powershell": "script.ps1",
            "ruby": "script.rb",
            "perl": "script.pl",
            "lua": "script.lua",
        }
        for language, filename in fixtures.items():
            with self.subTest(language=language):
                wrapper = protect_code(source, filename, language)
                recovered = unwrap_code(wrapper.content, filename)
                self.assertEqual(recovered.content, source)

    def test_python_zlib_round_trip(self) -> None:
        source = "value = 'zlib works'\nprint(value)\n"
        wrapper = protect_code(source, "script.py", "python", "zlib")
        self.assertEqual(unwrap_code(wrapper.content, "script.py").content, source)

    def test_auto_rejects_compiled_source_with_clear_message(self) -> None:
        with self.assertRaisesRegex(ProcessingError, "compilación"):
            process("runnable_auto", b"int main() {}", "main.c")

    def test_available_runtimes_execute_wrappers(self) -> None:
        cases = [
            ("python", "run.py", sys.executable, 'print("PY_OK")\n', "PY_OK"),
            ("javascript_node", "run.js", "node", 'console.log("NODE_OK");\n', "NODE_OK"),
            ("bash", "run.sh", "bash", 'printf "%s\\n" "BASH_OK"\n', "BASH_OK"),
            ("perl", "run.pl", "perl", 'print "PERL_OK\\n";\n', "PERL_OK"),
            ("php", "run.php", "php", "<?php echo \"PHP_OK\\n\"; ?>\n", "PHP_OK"),
            ("ruby", "run.rb", "ruby", 'puts "RUBY_OK"\n', "RUBY_OK"),
            ("lua", "run.lua", "lua", 'print("LUA_OK")\n', "LUA_OK"),
            ("powershell", "run.ps1", "pwsh", 'Write-Output "PS_OK"\n', "PS_OK"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for language, filename, runtime, source, expected in cases:
                if shutil.which(runtime) is None:
                    continue
                with self.subTest(language=language):
                    wrapper = protect_code(source, filename, language)
                    path = root / filename
                    path.write_text(wrapper.content, encoding="utf-8")
                    result = subprocess.run(
                        [runtime, str(path)],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(expected, result.stdout)

    def test_python_marshal_executes_on_same_python(self) -> None:
        wrapper = protect_code(
            'print("MARSHAL_OK")\n', "marshal.py", "python", "marshal"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / wrapper.filename
            path.write_text(wrapper.content, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(path)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MARSHAL_OK", result.stdout)


class RegistryRoundTripTests(unittest.TestCase):
    def test_encodings(self) -> None:
        original = "Hola 👻".encode()
        for prefix in ("base64", "base32", "base85", "hex"):
            encoded = process(f"{prefix}_encode", original, "entrada.txt")
            decoded = process(f"{prefix}_decode", encoded.content, encoded.filename)
            self.assertEqual(decoded.content, original)

    def test_compression(self) -> None:
        original = (b"CodeCipherBot\n" * 5000) + b"\x00\xff"
        for prefix in ("gzip", "bzip2", "lzma"):
            compressed = process(f"{prefix}_compress", original, "data.bin")
            decompressed = process(
                f"{prefix}_decompress",
                compressed.content,
                compressed.filename,
            )
            self.assertEqual(decompressed.content, original)


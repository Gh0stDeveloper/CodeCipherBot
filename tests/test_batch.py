from __future__ import annotations

import io
import unittest
import zipfile

from codecipher.batch import BatchError, process_project_zip
from codecipher.runnable import MARKER_RE


def make_zip(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return output.getvalue()


def read_zip(payload: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        return {
            name: archive.read(name)
            for name in archive.namelist()
            if not name.endswith("/")
        }


class ProjectBatchTests(unittest.TestCase):
    def test_project_paths_and_assets_are_preserved(self) -> None:
        original = {
            "app/main.py": b'print("hello")\n',
            "app/tool.js": b'console.log("hello");\n',
            "public/logo.bin": b"\x00\x01\xff",
            "README.md": b"hello",
        }
        protected = process_project_zip(
            make_zip(original),
            "protect",
            max_files=20,
            max_uncompressed=1_000_000,
        )
        files = read_zip(protected.content)
        self.assertIn("app/main.py", files)
        self.assertTrue(MARKER_RE.search(files["app/main.py"].decode()))
        self.assertEqual(files["public/logo.bin"], original["public/logo.bin"])

        recovered = process_project_zip(
            protected.content,
            "unwrap",
            max_files=30,
            max_uncompressed=1_000_000,
        )
        result = read_zip(recovered.content)
        for name, content in original.items():
            self.assertEqual(result[name], content)

    def test_traversal_path_is_rejected(self) -> None:
        payload = make_zip({"../escape.py": b"print(1)"})
        with self.assertRaises(BatchError):
            process_project_zip(
                payload,
                "protect",
                max_files=10,
                max_uncompressed=1000,
            )


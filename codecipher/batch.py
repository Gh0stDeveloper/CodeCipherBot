"""Protección y recuperación segura de proyectos ZIP."""

from __future__ import annotations

import io
import json
import stat
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

from .runnable import LANGUAGE_EXTENSIONS, MARKER_RE, protect_code, unwrap_code


class BatchError(ValueError):
    pass


@dataclass(frozen=True)
class BatchResult:
    content: bytes
    protected: int
    recovered: int
    copied: int
    failed: int


def _safe_member(name: str) -> str:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or ".." in path.parts
        or "\x00" in normalized
    ):
        raise BatchError("El ZIP contiene una ruta no segura.")
    return str(path)


def process_project_zip(
    payload: bytes,
    action: str,
    *,
    max_files: int,
    max_uncompressed: int,
) -> BatchResult:
    """Procesa código compatible manteniendo las rutas y los nombres.

    Los archivos no compatibles (recursos, configuración, imágenes, etc.) se
    copian sin cambios para no romper el proyecto.
    """

    if action not in {"protect", "unwrap"}:
        raise BatchError("Acción de lote no compatible.")
    try:
        source = zipfile.ZipFile(io.BytesIO(payload), "r")
    except (zipfile.BadZipFile, OSError) as exc:
        raise BatchError("El documento no es un ZIP válido.") from exc

    infos = source.infolist()
    if len(infos) > max_files:
        raise BatchError(f"El ZIP supera el límite de {max_files} entradas.")
    total = sum(item.file_size for item in infos)
    if total > max_uncompressed:
        raise BatchError("El tamaño descomprimido supera el límite configurado.")

    output = io.BytesIO()
    protected = recovered = copied = failed = 0
    report: list[str] = [
        "CodeCipherBot · Informe de proyecto",
        f"Acción: {action}",
        "",
    ]
    esm_roots: set[PurePosixPath] = set()
    for info in infos:
        if PurePosixPath(info.filename.replace("\\", "/")).name != "package.json":
            continue
        try:
            package = json.loads(source.read(info).decode("utf-8"))
            if package.get("type") == "module":
                esm_roots.add(PurePosixPath(info.filename).parent)
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError):
            continue

    def belongs_to_esm_package(path: PurePosixPath) -> bool:
        parent = path.parent
        return any(
            parent == root or root in parent.parents
            for root in esm_roots
        )

    with source, zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as target:
        for info in infos:
            name = _safe_member(info.filename)
            if name == "CODECIPHER_REPORT.txt":
                continue
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(unix_mode):
                raise BatchError("El ZIP contiene enlaces simbólicos no permitidos.")
            if info.is_dir():
                target.writestr(info, b"")
                continue

            data = source.read(info)
            suffix = PurePosixPath(name).suffix.lower()
            result = data
            try:
                text = data.decode("utf-8-sig")
                if (
                    action == "protect"
                    and suffix == ".js"
                    and belongs_to_esm_package(PurePosixPath(name))
                ):
                    copied += 1
                    report.append(
                        f"OMITIDO     {name}: pertenece a un paquete ESM; requiere bundling"
                    )
                elif action == "protect" and suffix in LANGUAGE_EXTENSIONS:
                    result = protect_code(text, name).content.encode("utf-8")
                    protected += 1
                    report.append(f"PROTEGIDO  {name}")
                elif action == "unwrap" and MARKER_RE.search(text):
                    result = unwrap_code(text, name).content.encode("utf-8")
                    recovered += 1
                    report.append(f"RECUPERADO {name}")
                else:
                    copied += 1
            except (UnicodeDecodeError, ValueError) as exc:
                failed += 1
                report.append(f"OMITIDO     {name}: {exc}")
            target.writestr(info, result)

        report.extend(
            [
                "",
                f"Protegidos: {protected}",
                f"Recuperados: {recovered}",
                f"Copiados sin cambios: {copied}",
                f"Omitidos con aviso: {failed}",
                "",
                (
                    "Los wrappers ejecutables son ofuscación reversible. "
                    "No sustituyen el cifrado con contraseña."
                ),
            ]
        )
        target.writestr("CODECIPHER_REPORT.txt", "\n".join(report).encode("utf-8"))

    return BatchResult(output.getvalue(), protected, recovered, copied, failed)

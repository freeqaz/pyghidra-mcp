import logging
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from pyghidra_mcp.import_detection import is_ghidra_importable

logger = logging.getLogger(__name__)

ARCHIVE_SUFFIXES = (
    ".zip",
    ".jar",
    ".apk",
    ".ipa",
    ".tar",
    ".tgz",
    ".tar.gz",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
)


@dataclass(frozen=True)
class ImportCandidate:
    path: Path
    relative_path: Path | None = None


@dataclass(frozen=True)
class SkippedImport:
    path: Path
    reason: str


@dataclass(frozen=True)
class ImportPlan:
    candidates: list[ImportCandidate]
    skipped: list[SkippedImport]


def build_import_plan(binary_paths: Iterable[str | Path]) -> ImportPlan:
    candidates: list[ImportCandidate] = []
    skipped: list[SkippedImport] = []

    for raw_path in binary_paths:
        path = Path(raw_path)
        if path.is_dir():
            for candidate in path.rglob("*"):
                if not candidate.is_file():
                    continue
                rel = candidate.relative_to(path).parent
                resolved = _maybe_convert_dol(candidate)
                allowed, reason = _classify_import_path(resolved, allow_raw_binary=False)
                if allowed:
                    candidates.append(ImportCandidate(resolved, rel))
                else:
                    skipped.append(SkippedImport(candidate, reason))
            continue

        if path.is_file():
            resolved = _maybe_convert_dol(path)
            allowed, reason = _classify_import_path(resolved, allow_raw_binary=False)
            if allowed:
                candidates.append(ImportCandidate(resolved, None))
            else:
                skipped.append(SkippedImport(path, reason))

    return ImportPlan(candidates=candidates, skipped=skipped)


def _maybe_convert_dol(path: Path) -> Path:
    """Transparently transcode a GameCube/Wii DOL into a symbolized PPC ELF.

    Ghidra has no DOL loader, and a DOL has no symbols. Converting to an ELF
    (with CodeWarrior-map symbols, if a sibling .map is found) lets Ghidra's ELF
    loader map memory + auto-create functions, and the 0x8xxxxxxx entry point
    makes the context auto-select PowerPC:BE:32:Gekko_Broadway. Falls through to
    the original path on any error so non-DOL inputs are unaffected.
    """
    try:
        from pyghidra_mcp.gamecube_dol import ensure_elf_for_dol, is_dol_file

        # Structural sniff (cheap 256-byte read): a DOL has no magic, so we
        # validate the header rather than trust the extension.
        if not is_dol_file(path):
            return path
        elf = ensure_elf_for_dol(path)
        logger.info("GameCube/Wii DOL detected: %s -> %s", path, elf)
        return elf
    except Exception:
        logger.debug("DOL conversion skipped for %s", path, exc_info=True)
        return path


def _classify_import_path(path: Path, *, allow_raw_binary: bool) -> tuple[bool, str]:
    if _is_archive_like(path):
        return False, "archive/container imports are not supported"
    if not is_ghidra_importable(path, allow_binary_loader=allow_raw_binary):
        return False, "no supported Ghidra loader detected"
    return True, ""


def _is_archive_like(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)

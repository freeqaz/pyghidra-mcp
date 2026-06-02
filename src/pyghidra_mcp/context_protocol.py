from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from .cache_manager import CacheManager
    from .context import ProgramInfo
    from .models import ImportRequestResult, ProgramInfo as ProgramInfoModel


class MCPContext(Protocol):
    """Tool-facing context contract shared by headless and GUI modes."""

    programs: dict[str, "ProgramInfo"]

    # Underlying Ghidra project handle (GhidraProject for headless, GUI project
    # for GUI mode). Used by structure/signature tools to persist edits via
    # project.save(...). Typed Any to cover both backends.
    project: Any

    # Headless RE features (decompile cache + MSVC .map source). The GUI context
    # leaves these as None; tools read them defensively via getattr.
    cache_manager: "CacheManager | None"
    map_file: "Path | None"

    def get_program_info(self, binary_name: str) -> "ProgramInfo": ...

    def list_binaries(self) -> list[str]: ...

    def list_binary_domain_files(self) -> list[Any]: ...

    def list_program_infos(self) -> list["ProgramInfo"]: ...

    def list_project_binary_infos(self) -> list["ProgramInfoModel"]: ...

    def delete_program(self, program_name: str) -> bool: ...

    def import_binary_backgrounded(self, binary_path: str | Path) -> "ImportRequestResult": ...

    def close(self, save: bool = True) -> None: ...

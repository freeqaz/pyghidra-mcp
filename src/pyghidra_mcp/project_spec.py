from dataclasses import dataclass
from pathlib import Path

DEFAULT_PROJECT_NAME = "my_project"


@dataclass(frozen=True)
class ProjectSpec:
    """Normalized Ghidra project paths for headless and GUI launch modes."""

    project_directory: Path
    project_name: str
    gpr_path: Path
    pyghidra_mcp_dir: Path
    was_gpr_path: bool

    @classmethod
    def from_cli(
        cls,
        project_path: Path,
        project_name: str,
        *,
        default_project_name: str = DEFAULT_PROJECT_NAME,
    ) -> "ProjectSpec":
        """Normalize CLI project options without depending on click."""
        project_path = Path(project_path)

        if project_path.suffix.lower() == ".gpr":
            if project_name != default_project_name:
                raise ValueError("Cannot use --project-name when specifying a .gpr file")

            resolved_project_name = project_path.stem
            project_directory = project_path.parent
            return cls(
                project_directory=project_directory,
                project_name=resolved_project_name,
                gpr_path=project_path,
                pyghidra_mcp_dir=project_directory / f"{resolved_project_name}-pyghidra-mcp",
                was_gpr_path=True,
            )

        # Two CLI contracts share this branch, distinguished by whether
        # --project-name was given:
        #
        # * Fork style (no --project-name): the path itself encodes the project
        #   (--project-path .../DC3/DC3). Derive the name from the basename and
        #   keep MCP-side state (chromadb code index, symbol server) directly in
        #   the project home. Every existing service already has a populated
        #   {project_path}/chromadb and a {project_path}/{name}.gpr there, so
        #   this reopens them on restart instead of spawning a fresh
        #   "my_project" and re-analyzing + re-indexing from scratch.
        #
        # * Upstream style (explicit --project-name): treat --project-path as the
        #   directory and use a dedicated {name}-pyghidra-mcp state subdir.
        if project_name == default_project_name and project_path.name:
            resolved_name = project_path.name
            pyghidra_mcp_dir = project_path
        else:
            resolved_name = project_name
            pyghidra_mcp_dir = project_path / f"{resolved_name}-pyghidra-mcp"
        return cls(
            project_directory=project_path,
            project_name=resolved_name,
            gpr_path=project_path / f"{resolved_name}.gpr",
            pyghidra_mcp_dir=pyghidra_mcp_dir,
            was_gpr_path=False,
        )

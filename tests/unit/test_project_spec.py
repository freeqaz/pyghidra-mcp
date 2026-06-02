from pathlib import Path

import pytest

from pyghidra_mcp.project_spec import DEFAULT_PROJECT_NAME, ProjectSpec


def test_project_spec_from_gpr_path():
    spec = ProjectSpec.from_cli(Path("/tmp/projects/sample.gpr"), DEFAULT_PROJECT_NAME)

    assert spec.was_gpr_path is True
    assert spec.project_directory == Path("/tmp/projects")
    assert spec.project_name == "sample"
    assert spec.gpr_path == Path("/tmp/projects/sample.gpr")
    assert spec.pyghidra_mcp_dir == Path("/tmp/projects/sample-pyghidra-mcp")


def test_project_spec_rejects_project_name_with_gpr_path():
    with pytest.raises(ValueError, match="Cannot use --project-name"):
        ProjectSpec.from_cli(Path("/tmp/projects/sample.gpr"), "custom")


def test_project_spec_from_directory_path():
    spec = ProjectSpec.from_cli(Path("/tmp/projects"), "sample")

    assert spec.was_gpr_path is False
    assert spec.project_directory == Path("/tmp/projects")
    assert spec.project_name == "sample"
    assert spec.gpr_path == Path("/tmp/projects/sample.gpr")
    # Explicit --project-name keeps upstream's dedicated state subdir.
    assert spec.pyghidra_mcp_dir == Path("/tmp/projects/sample-pyghidra-mcp")


def test_project_spec_default_name_derives_from_path_basename():
    # Fork contract: .../DC3/DC3 with no explicit --project-name reopens the
    # existing project named by the path basename ("DC3"), not "my_project",
    # and keeps MCP state (chromadb, symbols) flat in the project home so the
    # existing index is reused on restart.
    spec = ProjectSpec.from_cli(Path("/x/ghidra_projects/DC3/DC3"), DEFAULT_PROJECT_NAME)

    assert spec.was_gpr_path is False
    assert spec.project_directory == Path("/x/ghidra_projects/DC3/DC3")
    assert spec.project_name == "DC3"
    assert spec.gpr_path == Path("/x/ghidra_projects/DC3/DC3/DC3.gpr")
    assert spec.pyghidra_mcp_dir == Path("/x/ghidra_projects/DC3/DC3")


def test_gui_stdio_rejected_before_ghidra_start():
    import click.testing

    from pyghidra_mcp.server import main

    runner = click.testing.CliRunner()
    result = runner.invoke(main, ["--gui", "--transport", "stdio"])

    assert result.exit_code != 0
    assert "--gui requires --transport streamable-http or --transport http" in result.output

# Server
# ---------------------------------------------------------------------------------
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

import re

import click
import pyghidra
from click_option_group import optgroup
from mcp.server import Server
from mcp.server.fastmcp import FastMCP

from pyghidra_mcp import __version__, mcp_tools
from pyghidra_mcp.cache_manager import CacheManager
from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.context_protocol import MCPContext
from pyghidra_mcp.gui_context import GuiPyGhidraContext
from pyghidra_mcp.gui_launcher import GuiPyGhidraMcpLauncher, ensure_macos_framework_python
from pyghidra_mcp.project_spec import DEFAULT_PROJECT_NAME, ProjectSpec

# Setup logging with both console and file output
def setup_logging(log_file: Optional[str] = None) -> logging.Logger:
    """Configure logging with console and optional file output."""
    _logger = logging.getLogger(__name__)
    _logger.setLevel(logging.DEBUG)

    # Console handler (stderr for stdio transport compatibility)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    console_handler.setFormatter(console_formatter)
    _logger.addHandler(console_handler)

    # File handler with rotation (if log file specified)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=10,  # Keep 10 files
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        _logger.addHandler(file_handler)

    return _logger


# Initialize logger (will be reconfigured with log file in main())
logger = setup_logging()


# Init Pyghidra
# ---------------------------------------------------------------------------------
@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[MCPContext]:
    """Manage server startup and shutdown lifecycle."""
    try:
        yield server._pyghidra_context  # type: ignore
    finally:
        # pyghidra_context.close()
        pass


mcp = FastMCP("pyghidra-mcp", lifespan=server_lifespan)  # type: ignore


# Port Management and Diagnostics
# ---------------------------------------------------------------------------------
def cleanup_stale_port(port: int = 8000, timeout_seconds: int = 5) -> bool:
    """Kill stale processes using the port and wait for it to become available.

    Args:
        port: Port number to clean up
        timeout_seconds: How long to wait for port to become free

    Returns:
        True if port is available, False if timeout
    """
    try:
        result = subprocess.run(
            ["lsof", "-i", f":{port}", "-t"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.stdout.strip():
            pids = result.stdout.strip().split("\n")
            for pid in pids:
                try:
                    pid_int = int(pid.strip())
                    os.kill(pid_int, signal.SIGKILL)
                    logger.info(f"Killed stale process {pid_int} on port {port}")
                    time.sleep(0.1)
                except (ValueError, ProcessLookupError, PermissionError) as e:
                    logger.debug(f"Could not kill PID {pid}: {e}")
    except FileNotFoundError:
        logger.debug("lsof not available, skipping port cleanup")
    except Exception as e:
        logger.debug(f"Port cleanup error: {e}")

    # Wait for port to be free
    start_time = time.time()
    while time.time() - start_time < timeout_seconds:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=1)
            sock.close()
            time.sleep(0.2)
        except (ConnectionRefusedError, socket.timeout):
            logger.info(f"Port {port} is now available")
            return True

    logger.warning(f"Port {port} still in use after {timeout_seconds}s (may proceed anyway)")
    return False


def diagnose() -> None:
    """Run diagnostics for the Ghidra service and print results."""
    print("=" * 70)
    print("Ghidra Service Diagnostics")
    print("=" * 70)

    # Check Ghidra install
    ghidra_home = os.environ.get("GHIDRA_INSTALL_DIR")
    print(f"\nGhidra Installation:")
    print(f"  GHIDRA_INSTALL_DIR: {ghidra_home}")
    if ghidra_home:
        print(f"  Exists: {os.path.exists(ghidra_home)}")
        if os.path.exists(ghidra_home):
            print(f"  Writable: {os.access(ghidra_home, os.W_OK)}")

    ghidra_user = os.environ.get("GHIDRA_USER_HOME")
    print(f"  GHIDRA_USER_HOME: {ghidra_user}")
    if ghidra_user:
        print(f"  Exists: {os.path.exists(ghidra_user)}")
        if os.path.exists(ghidra_user):
            print(f"  Writable: {os.access(ghidra_user, os.W_OK)}")

    # Check Java
    java_home = os.environ.get("JAVA_HOME")
    print(f"\nJava Configuration:")
    print(f"  JAVA_HOME: {java_home}")
    if java_home and os.path.exists(os.path.join(java_home, "bin", "java")):
        print(f"  Java executable found")

    # Check port
    port = 8000
    print(f"\nPort Status (Port {port}):")
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=1)
        sock.close()
        print(f"  Status: IN USE (likely by existing service)")
    except (ConnectionRefusedError, socket.timeout):
        print(f"  Status: AVAILABLE")
    except Exception as e:
        print(f"  Status: ERROR - {e}")

    # Check temp directories
    print(f"\nTemporary Directories:")
    for tmpdir in ["/tmp/claude", "/tmp"]:
        exists = os.path.exists(tmpdir)
        writable = os.access(tmpdir, os.W_OK) if exists else False
        print(f"  {tmpdir}: exists={exists}, writable={writable}")

    # Check logs
    print(f"\nService Logs:")
    log_file = "/tmp/claude/pyghidra-service.log"
    if os.path.exists(log_file):
        size = os.path.getsize(log_file)
        print(f"  {log_file}: {size} bytes")
        try:
            with open(log_file, "r") as f:
                lines = f.readlines()
                print(f"  Last 5 log entries:")
                for line in lines[-5:]:
                    print(f"    {line.rstrip()}")
        except Exception as e:
            print(f"  Error reading logs: {e}")
    else:
        print(f"  {log_file}: not found")

    print("\n" + "=" * 70)


# Module-level alias so main() can invoke diagnostics even though its --diagnose
# CLI flag parameter shadows the diagnose() function name inside that scope.
_run_diagnostics = diagnose


def register_common_tools(server: FastMCP) -> None:
    server.tool()(mcp_tools.decompile_function)
    server.tool()(mcp_tools.search_symbols_by_name)
    server.tool()(mcp_tools.search_code)
    server.tool()(mcp_tools.list_project_binaries)
    server.tool()(mcp_tools.list_project_binary_metadata)
    server.tool()(mcp_tools.rename_function)
    server.tool()(mcp_tools.rename_variable)
    server.tool()(mcp_tools.set_variable_type)
    server.tool()(mcp_tools.set_function_prototype)
    server.tool()(mcp_tools.set_comment)
    server.tool()(mcp_tools.delete_project_binary)
    server.tool()(mcp_tools.list_exports)
    server.tool()(mcp_tools.list_imports)
    server.tool()(mcp_tools.list_xrefs)
    server.tool()(mcp_tools.search_strings)
    server.tool()(mcp_tools.read_bytes)
    server.tool()(mcp_tools.gen_callgraph)
    server.tool()(mcp_tools.import_binary)
    # Fork-only tools (freeqaz/pyghidra-mcp)
    server.tool()(mcp_tools.get_service_health)
    server.tool()(mcp_tools.get_cache_stats)
    server.tool()(mcp_tools.search_functions_by_name)
    server.tool()(mcp_tools.list_structures)
    server.tool()(mcp_tools.extract_structures)
    server.tool()(mcp_tools.create_structures)
    server.tool()(mcp_tools.apply_this_types)
    server.tool()(mcp_tools.bulk_create_functions)
    server.tool()(mcp_tools.apply_demangled_signatures)


def register_gui_tools(server: FastMCP) -> None:
    server.tool()(mcp_tools.list_open_programs)
    server.tool()(mcp_tools.open_program_in_gui)
    server.tool()(mcp_tools.set_current_program)
    server.tool()(mcp_tools.goto)


register_common_tools(mcp)


def _detect_binary_language(binary_path: Path) -> tuple[str | None, str | None]:
    """Detect binary format and return language/compiler IDs if needed.

    When XEXLoaderWV is installed via _install_xex_loader(), XEX files are
    handled natively and don't need a language hint. Falls back to explicit
    language specification if the loader isn't available.
    """
    try:
        with binary_path.open("rb") as f:
            header = f.read(4)
            if header.startswith(b"XEX2"):
                # Check if XEXLoaderWV is installed
                ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR", "")
                ext_dir = Path(ghidra_dir) / "Extensions" / "XEXLoaderWV" if ghidra_dir else None
                if ext_dir and ext_dir.exists():
                    # XEX loader handles format parsing, but we must specify
                    # the Xenon language variant for VMX128 instruction support
                    logger.info("XEX binary detected, using XEXLoaderWV with Xenon language")
                    return "PowerPC:BE:64:Xenon", None
                else:
                    # Fallback: import as raw binary with PowerPC language
                    logger.info("XEX binary detected, no XEXLoaderWV - using raw import")
                    return "PowerPC:BE:64:Xenon", None
    except Exception as e:
        logger.debug(f"Could not detect language for {binary_path}: {e}")
    return None, None


def _install_xex_loader(launcher: "pyghidra.HeadlessPyGhidraLauncher"):
    """Install XEXLoaderWV extension if available, so Ghidra can import XEX files natively."""
    # Look for the built dist zip first (preferred by install_plugin)
    xex_loader_home = Path.home() / "code" / "milohax" / "XEXLoaderWV" / "XEXLoaderWV"
    dist_dir = xex_loader_home / "dist"
    if dist_dir.exists():
        zips = sorted(dist_dir.glob("*.zip"))
        if zips:
            zip_path = zips[-1]  # Latest zip
            try:
                details = pyghidra.ExtensionDetails.from_file(xex_loader_home)
                launcher.install_plugin(zip_path, details)
                logger.info(f"Installed XEXLoaderWV from {zip_path}")
                return
            except Exception as e:
                logger.warning(f"install_plugin failed with zip: {e}")

    # Fallback: add jar to classpath directly
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR", "")
    if not ghidra_dir:
        return
    jar = Path(ghidra_dir) / "Extensions" / "XEXLoaderWV" / "lib" / "XEXLoaderWV.jar"
    if jar.exists():
        try:
            launcher.add_class_files(jar)
            logger.info(f"Added XEXLoaderWV jar to classpath: {jar}")
        except Exception as e:
            logger.warning(f"Failed to add XEXLoaderWV jar: {e}")
    else:
        logger.debug("XEXLoaderWV not found")


def _apply_map_symbols(
    pyghidra_context: PyGhidraContext,
    map_file: Path,
) -> None:
    """Apply symbols from an MSVC linker .map file to all programs in the project.

    Parses the "Publics by Value" section of the map file and creates named
    symbols at the corresponding addresses in Ghidra, replacing auto-generated
    names like FUN_828853d8 with the real mangled names from the linker.

    Only applies symbols once per program — skips if IMPORTED symbols already exist.

    Args:
        pyghidra_context: The active Ghidra project context.
        map_file: Path to the MSVC linker .map file.
    """
    from ghidra.program.model.symbol import SourceType, SymbolUtilities

    if not map_file.exists():
        logger.warning(f"Map file not found: {map_file}")
        return

    for prog_path, program_info in pyghidra_context.programs.items():
        program = program_info.program

        # Check if map symbols were already applied via a program property marker
        MAP_SYMBOLS_OPTION = "Map Symbols Applied v4"
        prog_options = program.getOptions("pyghidra-mcp")
        if prog_options.getBoolean(MAP_SYMBOLS_OPTION, False):
            logger.info(f"Map symbols already applied to {prog_path}, skipping")
            continue

        logger.info(f"Applying map symbols to {prog_path} from {map_file}")

        # Parse "Publics by Value" section
        # Format: 0005:000186e0   ?PoseMeshes@CharBonesMeshes@@QAAXXZ 823486e0 f   char:CharBonesMeshes.obj
        symbol_pattern = re.compile(
            r"^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{8})"
        )

        symbols_to_apply: list[tuple[str, int]] = []
        in_publics = False
        with open(map_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "Publics by Value" in line:
                    in_publics = True
                    continue
                if not in_publics:
                    continue
                match = symbol_pattern.match(line)
                if match:
                    symbol_name = match.group(1)
                    address = int(match.group(2), 16)
                    symbols_to_apply.append((symbol_name, address))

        if not symbols_to_apply:
            logger.warning("No symbols found in map file")
            continue

        logger.info(f"Parsed {len(symbols_to_apply)} symbols from map file")

        addr_factory = program.getAddressFactory()
        memory = program.getMemory()

        fm = program.getFunctionManager()

        txn = program.startTransaction("Import map symbols")
        try:
            count = 0
            renamed = 0
            rename_failed = 0
            skipped = 0
            for symbol_name, addr_int in symbols_to_apply:
                try:
                    addr = addr_factory.getDefaultAddressSpace().getAddress(addr_int)
                    if addr and memory.contains(addr):
                        # Check if a function exists at this address with an auto name
                        func = fm.getFunctionAt(addr)
                        if func:
                            func_name = func.getName()
                            is_auto = (
                                func_name.startswith("FUN_")
                                or func_name.startswith("Function_")
                                or func_name.startswith("thunk_FUN_")
                            )
                            if is_auto:
                                # Remove any existing label with the same name at this address
                                # (from prior createPreferredLabelOrFunctionSymbol calls)
                                st = program.getSymbolTable()
                                for existing_sym in list(st.getSymbols(addr)):
                                    if (existing_sym.getName() == symbol_name
                                            and existing_sym != func.getSymbol()):
                                        existing_sym.delete()
                                # Rename the function directly instead of creating a label
                                try:
                                    func.setName(symbol_name, SourceType.IMPORTED)
                                    renamed += 1
                                except Exception as rename_err:
                                    rename_failed += 1
                                    if rename_failed <= 5:
                                        logger.debug(
                                            f"Failed to rename {func_name} at "
                                            f"0x{addr_int:08x} to {symbol_name}: {rename_err}"
                                        )
                            else:
                                # Function already has a real name, add as label
                                SymbolUtilities.createPreferredLabelOrFunctionSymbol(
                                    program, addr, None, symbol_name, SourceType.IMPORTED
                                )
                        else:
                            # No function — create a label or function symbol
                            SymbolUtilities.createPreferredLabelOrFunctionSymbol(
                                program, addr, None, symbol_name, SourceType.IMPORTED
                            )
                        count += 1
                    else:
                        skipped += 1
                except Exception:
                    skipped += 1

            program.endTransaction(txn, True)
            logger.info(
                f"Applied {count} symbols, renamed {renamed} functions, "
                f"{rename_failed} rename failures ({skipped} skipped)"
            )

            # Mark that map symbols have been applied so we don't re-apply on next startup
            txn2 = program.startTransaction("Mark map symbols applied")
            try:
                prog_options.setBoolean(MAP_SYMBOLS_OPTION, True)
                program.endTransaction(txn2, True)
            except Exception:
                program.endTransaction(txn2, False)
        except Exception:
            program.endTransaction(txn, False)
            logger.error("Failed to apply map symbols, transaction rolled back", exc_info=True)

        # Save the program with new symbols
        pyghidra_context.project.save(program)


def init_pyghidra_context(  # noqa: C901
    mcp: FastMCP,
    *,
    transport: str,
    input_paths: list[Path],
    project_name: str,
    project_directory: str,
    pyghidra_mcp_dir: Path,
    force_analysis: bool,
    verbose_analysis: bool,
    no_symbols: bool,
    gdts: list[str],
    program_options_path: str | None,
    gzfs_path: str | None,
    threaded: bool,
    max_workers: int,
    wait_for_analysis: bool,
    skip_code_collection: bool,
    decompiler_timeout: int,
    list_project_binaries: bool,
    delete_project_binary: str | None,
    symbols_path: str | None,
    sym_file_path: str | None,
    cache_manager: CacheManager | None = None,
    map_file: str | None = None,
) -> FastMCP:
    bin_paths: list[str | Path] = [Path(p) for p in input_paths]
    logger.info(f"Project: {project_name}")
    logger.info(f"Project: Location {project_directory}")

    program_options: dict | None = None
    if program_options_path:
        with open(program_options_path) as f:
            program_options = json.load(f)

    # init pyghidra with XEX loader extension (if available)
    launcher = pyghidra.HeadlessPyGhidraLauncher(verbose=False)
    _install_xex_loader(launcher)
    launcher.start()

    # init PyGhidraContext / import + analyze binaries
    logger.info("Server initializing...")
    pyghidra_context = PyGhidraContext(
        project_name=project_name,
        project_path=project_directory,
        pyghidra_mcp_dir=pyghidra_mcp_dir,
        force_analysis=force_analysis,
        verbose_analysis=verbose_analysis,
        no_symbols=no_symbols,
        gdts=gdts,
        program_options=program_options,
        gzfs_path=gzfs_path,
        threaded=threaded,
        max_workers=max_workers,
        wait_for_analysis=wait_for_analysis,
        skip_code_collection=skip_code_collection,
        decompiler_timeout=decompiler_timeout,
        symbols_path=symbols_path,
        sym_file_path=sym_file_path,
        cache_manager=cache_manager,
        map_file=map_file,
    )

    if list_project_binaries:
        binaries = pyghidra_context.list_binaries()
        if binaries:
            click.echo("Ghidra Project Binaries:")
            for binary_name in binaries:
                click.echo(f"- {binary_name}")
        else:
            click.echo("No binaries found in the project.")
        sys.exit(0)

    if delete_project_binary:
        try:
            if pyghidra_context.delete_program(delete_project_binary):
                click.echo(f"Successfully deleted binary: {delete_project_binary}")
            else:
                click.echo(f"Failed to delete binary: {delete_project_binary}", err=True)
        except ValueError as e:
            click.echo(f"Error: {e}", err=True)
        sys.exit(0)

    imported_programs: list[str] = []
    if len(bin_paths) > 0:
        logger.info(f"Adding new bins: {', '.join(map(str, bin_paths))}")
        logger.info(f"Importing binaries to {project_directory}")
        imported_programs = pyghidra_context.import_binaries(bin_paths)

    if imported_programs or force_analysis or wait_for_analysis:
        logger.info(f"Analyzing project: {pyghidra_context.project}")
        pyghidra_context.analyze_project()
        if wait_for_analysis:
            if transport != "stdio":
                pyghidra_context.schedule_startup_indexing(
                    max_binaries=max(len(pyghidra_context.programs), 1)
                )
        else:
            for binary_name in imported_programs:
                pyghidra_context.schedule_indexing(binary_name)
    else:
        logger.info("Skipping full-project analysis on startup; using existing project state.")
        pyghidra_context.schedule_startup_indexing()

    # Apply map file symbols after analysis (if provided)
    if map_file:
        map_path = Path(map_file)
        _apply_map_symbols(pyghidra_context, map_path)

    if len(pyghidra_context.list_binaries()) == 0:
        logger.warning("No binaries were imported and none exist in the project.")

    mcp._pyghidra_context = pyghidra_context  # type: ignore
    logger.info("Server intialized")

    return mcp


def init_gui_context(
    mcp: FastMCP,
    *,
    project_spec: ProjectSpec,
    input_paths: list[Path],
) -> FastMCP:
    logger.info("Waiting for Ghidra GUI project...")
    gui_context = GuiPyGhidraContext(project_spec=project_spec)
    if input_paths:
        logger.info("Importing/opening GUI binaries: %s", ", ".join(map(str, input_paths)))
        gui_context.import_binaries(input_paths)
    gui_context.schedule_startup_indexing()
    mcp._pyghidra_context = gui_context  # type: ignore
    logger.info("GUI-backed server initialized")
    return mcp


def run_mcp_server(mcp: FastMCP, transport: str) -> None:
    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport in ["streamable-http", "http"]:
        mcp.run(transport="streamable-http")
    elif transport == "sse":
        import warnings

        warnings.warn(
            "SSE transport is deprecated per the MCP spec (June 2025). "
            "Use --transport streamable-http instead.",
            DeprecationWarning,
            stacklevel=1,
        )
        mcp.run(transport="sse")
    else:
        raise ValueError(f"Invalid transport: {transport}")


# MCP Server Entry Point
# ---------------------------------------------------------------------------------


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(
    __version__,
    "-v",
    "--version",
    help="Show version and exit.",
)
# --- Server Options ---
@optgroup.group("Server Options")
@optgroup.option(
    "-t",
    "--transport",
    type=click.Choice(["stdio", "streamable-http", "sse", "http"], case_sensitive=False),
    default="stdio",
    envvar="MCP_TRANSPORT",
    show_default=True,
    help="Transport protocol to use. Note: SSE is deprecated, use streamable-http instead.",
)
@optgroup.option(
    "-p",
    "--port",
    type=int,
    default=8000,
    envvar="MCP_PORT",
    show_default=True,
    help="Port to listen on for HTTP-based transports.",
)
@optgroup.option(
    "-o",
    "--host",
    type=str,
    default="127.0.0.1",
    envvar="MCP_HOST",
    show_default=True,
    help="Host to listen on for HTTP-based transports.",
)
@optgroup.option(
    "--project-path",
    type=click.Path(path_type=Path),
    default=Path("pyghidra_mcp_projects"),
    show_default=True,
    help="Directory path to create new pyghidra-mcp project or an existing Ghidra .gpr file.",
)
@optgroup.option(
    "--project-name",
    type=str,
    default="my_project",
    show_default=True,
    help="Name for the project (used for Ghidra project files). Ignored when using .gpr files.",
)
@optgroup.option(
    "--threaded/--no-threaded",
    default=True,
    show_default=True,
    help="Allow threaded analysis. Disable for debug.",
)
@optgroup.option(
    "--max-workers",
    type=int,
    default=0,  # 0 means multiprocessing.cpu_count()
    show_default=True,
    help="Number of workers for threaded analysis. Defaults to CPU count.",
)
@optgroup.option(
    "--wait-for-analysis/--no-wait-for-analysis",
    default=False,
    show_default=True,
    help="Wait for initial project analysis to complete before starting the server.",
)
@optgroup.option(
    "--gui/--no-gui",
    default=False,
    show_default=True,
    help=(
        "Launch Ghidra GUI in-process, then open the requested project after startup and "
        "serve MCP over HTTP against GUI-open programs. Cannot attach to an already-running "
        "external Ghidra process."
    ),
)
@optgroup.option(
    "--log-file",
    type=click.Path(),
    help="Path to log file for rotating file logging (max 10MB, 10 backups).",
)
@optgroup.option(
    "--diagnose",
    is_flag=True,
    help="Run service diagnostics and exit.",
)
# --- Cache Options ---
@optgroup.group("Cache Options")
@optgroup.option(
    "--cache-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory to store decompilation cache (cache.db). Defaults to current directory.",
)
@optgroup.option(
    "--cache-disabled",
    is_flag=True,
    default=False,
    help="Disable decompilation caching for this run.",
)
@optgroup.option(
    "--cache-clear",
    is_flag=True,
    default=False,
    help="Clear entire decompilation cache and exit.",
)
@optgroup.option(
    "--cache-stats",
    is_flag=True,
    default=False,
    help="Print cache statistics and exit.",
)
# --- Project Options ---
@optgroup.group("Project Management")
@optgroup.option(
    "--list-project-binaries",
    is_flag=True,
    help="List all ingested binaries in the project.",
)
@optgroup.option(
    "--delete-project-binary",
    type=str,
    help="Delete a specific binary (program) from the project by name.",
)
# --- Analysis Options ---
@optgroup.group("Analysis Options")
@optgroup.option(
    "--force-analysis/--no-force-analysis",
    default=False,
    show_default=True,
    help="Force a new binary analysis each run.",
)
@optgroup.option(
    "--verbose-analysis/--no-verbose-analysis",
    default=False,
    show_default=True,
    help="Verbose logging for analysis step.",
)
@optgroup.option(
    "--no-symbols/--with-symbols",
    default=False,
    show_default=True,
    help="Turn off symbols for analysis.",
)
@optgroup.option(
    "--sym-file-path",
    type=click.Path(exists=True),
    default=None,
    help="Specify single pdb symbol file for bin (default: None)",
)
@optgroup.option(
    "-s",
    "--symbols-path",
    type=click.Path(),
    default=None,
    help="Path for local symbols directory (default: symbols)",
)
@optgroup.option(
    "--gdt",
    type=click.Path(exists=True),
    multiple=True,
    help="Path to GDT files (can be specified multiple times).",
)
@optgroup.option(
    "--program-options",
    type=click.Path(exists=True),
    help="Path to a JSON file containing program options.",
)
@optgroup.option(
    "--gzfs-path",
    type=click.Path(),
    help="Location to store GZFs of analyzed binaries.",
)
@optgroup.option(
    "--map-file",
    type=click.Path(exists=True),
    help="Path to an MSVC linker .map file. Symbols from 'Publics by Value' "
         "will be applied to the Ghidra project after analysis.",
)
@optgroup.option(
    "--skip-code-collection/--with-code-collection",
    default=False,
    show_default=True,
    help="Skip the ChromaDB code-collection build (the per-function decompile "
         "pass). Avoids wedging on very large/monolithic binaries; search_code "
         "becomes unavailable but the strings collection still builds.",
)
@optgroup.option(
    "--decompiler-timeout",
    type=int,
    default=0,
    show_default=True,
    help="Per-function decompiler timeout in seconds (0 = no timeout). Bounds "
         "both interactive and collection-build decompiles so a pathological "
         "function fails fast instead of hanging.",
)
@click.argument("input_paths", type=click.Path(exists=True), nargs=-1)
def main(
    transport: str,
    input_paths: list[Path],
    project_path: Path,
    project_name: str,
    port: int,
    host: str,
    threaded: bool,
    force_analysis: bool,
    verbose_analysis: bool,
    no_symbols: bool,
    gdt: tuple[str, ...],
    program_options: str | None,
    gzfs_path: str | None,
    map_file: str | None,
    max_workers: int,
    wait_for_analysis: bool,
    gui: bool,
    skip_code_collection: bool,
    decompiler_timeout: int,
    list_project_binaries: bool,
    delete_project_binary: str | None,
    sym_file_path: str | None,
    symbols_path: str | None,
    log_file: str | None,
    diagnose: bool,
    cache_dir: Path | None,
    cache_disabled: bool,
    cache_clear: bool,
    cache_stats: bool,
) -> None:
    """PyGhidra Command-Line MCP server

    - input_paths: Path to one or more binaries to import, analyze, and expose with pyghidra-mcp\n
    - transport: Supports stdio, streamable-http, and sse transports.\n
    For stdio, it will read from stdin and write to stdout.
    For streamable-http and sse, it will start an HTTP server on the specified port (default 8000).

    """
    global logger

    # Handle --diagnose flag early (before any initialization). The CLI flag
    # shadows the module-level diagnose() function in this scope, so call it
    # through its module-level alias.
    if diagnose:
        _run_diagnostics()
        sys.exit(0)

    # Reconfigure logging with file output if specified
    if log_file:
        logger = setup_logging(log_file)
        logger.info(f"Logging to file: {log_file}")

    # Initialize cache manager
    cache_dir_path = cache_dir if cache_dir else Path.cwd()
    cache_manager = CacheManager(cache_dir=cache_dir_path, enabled=not cache_disabled)
    mcp._cache_manager = cache_manager  # type: ignore

    # Handle cache management commands
    if cache_clear:
        cleared = cache_manager.clear()
        logger.info(f"Cache cleared: {cleared} entries removed")
        click.echo(f"Cache cleared: {cleared} entries removed")
        sys.exit(0)

    if cache_stats:
        stats = cache_manager.get_stats()
        logger.info(f"Cache stats: {json.dumps(stats)}")
        click.echo(json.dumps(stats, indent=2))
        sys.exit(0)

    try:
        project_spec = ProjectSpec.from_cli(
            project_path,
            project_name,
            default_project_name=DEFAULT_PROJECT_NAME,
        )
    except ValueError as e:
        raise click.BadParameter(str(e)) from e

    project_directory = str(project_spec.project_directory)
    project_name = project_spec.project_name
    pyghidra_mcp_dir = project_spec.pyghidra_mcp_dir
    mcp.settings.port = port
    mcp.settings.host = host

    if gui:
        if transport == "stdio":
            raise click.UsageError("--gui requires --transport streamable-http or --transport http")
        if transport == "sse":
            raise click.UsageError("--gui requires --transport streamable-http or --transport http")
        if list_project_binaries or delete_project_binary:
            raise click.UsageError("GUI mode does not support project-management CLI actions yet")

        register_gui_tools(mcp)
        ensure_macos_framework_python()
        launcher = GuiPyGhidraMcpLauncher(project_spec.gpr_path)
        launcher.start()
        gui_server_error: list[BaseException] = []

        def gui_server_thread() -> None:
            try:
                init_gui_context(mcp=mcp, project_spec=project_spec, input_paths=input_paths)
                run_mcp_server(mcp, transport)
            except BaseException as exc:
                gui_server_error.append(exc)
                logger.exception("GUI MCP server failed during startup or runtime.")
                launcher.request_shutdown()

        server_thread = threading.Thread(
            target=gui_server_thread,
            name="pyghidra-mcp-gui-server",
            daemon=True,
        )
        server_thread.start()
        try:
            launcher.run_gui_event_loop()
        finally:
            launcher.request_shutdown()
            launcher.wait_for_shutdown()
            context = getattr(mcp, "_pyghidra_context", None)
            if context is not None:
                context.close()
        if gui_server_error:
            raise RuntimeError("GUI MCP server failed to start.") from gui_server_error[0]
        return

    init_pyghidra_context(
        mcp=mcp,
        input_paths=input_paths,
        transport=transport,
        project_name=project_name,
        project_directory=project_directory,
        force_analysis=force_analysis,
        verbose_analysis=verbose_analysis,
        no_symbols=no_symbols,
        gdts=list(gdt),
        program_options_path=program_options,
        gzfs_path=gzfs_path,
        threaded=threaded,
        max_workers=max_workers,
        wait_for_analysis=wait_for_analysis,
        skip_code_collection=skip_code_collection,
        decompiler_timeout=decompiler_timeout,
        list_project_binaries=list_project_binaries,
        delete_project_binary=delete_project_binary,
        pyghidra_mcp_dir=pyghidra_mcp_dir,
        sym_file_path=sym_file_path,
        symbols_path=symbols_path,
        cache_manager=cache_manager,
        map_file=map_file,
    )

    try:
        run_mcp_server(mcp, transport)
    finally:
        mcp._pyghidra_context.close()  # type: ignore


if __name__ == "__main__":
    main()

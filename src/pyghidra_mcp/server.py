# Server
# ---------------------------------------------------------------------------------
import json
import logging
import os
import signal
import socket
import subprocess
import sys
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
from mcp.server.fastmcp import Context, FastMCP
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

from pyghidra_mcp.__init__ import __version__
from pyghidra_mcp.cache_manager import CacheManager
from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import (
    BinaryMetadata,
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CodeSearchResults,
    CrossReferenceInfos,
    DecompiledFunction,
    ExportInfos,
    FunctionSearchResults,
    ImportInfos,
    ProgramInfo,
    ProgramInfos,
    StringSearchResults,
    StructureInfo,
    StructureListResult,
    SymbolSearchResults,
)
from pyghidra_mcp.tools import GhidraTools

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

# Service start time for uptime tracking
SERVICE_START_TIME = time.time()


# Init Pyghidra
# ---------------------------------------------------------------------------------
@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[PyGhidraContext]:
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


# MCP Tools
# ---------------------------------------------------------------------------------
@mcp.tool()
def get_service_health(ctx: Context) -> dict:
    """Returns health status of the Ghidra service.

    This endpoint can be called to verify the service is running and responsive.
    Returns uptime, version, and Ghidra readiness status.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        uptime_seconds = int(time.time() - SERVICE_START_TIME)
        ghidra_ready = (
            len(pyghidra_context.programs) > 0
            if pyghidra_context else False
        )

        return {
            "status": "healthy",
            "version": __version__,
            "uptime_seconds": uptime_seconds,
            "ghidra_ready": ghidra_ready,
            "programs_loaded": len(pyghidra_context.programs) if pyghidra_context else 0,
        }
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {
            "status": "error",
            "version": __version__,
            "error": str(e),
        }


@mcp.tool()
def search_functions_by_name(
    binary_name: str, query: str, ctx: Context, offset: int = 0, limit: int = 100
) -> FunctionSearchResults:
    """Searches for functions within a binary by name.

    This is a dedicated function search that finds functions with names containing
    the query string. For broader symbol searches (including labels, variables, etc.),
    use search_symbols_by_name instead.

    Args:
        binary_name: The name of the binary to search within.
        query: The substring to search for in function names (case-insensitive).
        offset: The number of results to skip.
        limit: The maximum number of results to return.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        functions = tools.search_functions_by_name(query, offset, limit)
        return FunctionSearchResults(functions=functions)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error searching for functions: {e!s}")
        ) from e


@mcp.tool()
async def decompile_function(
    binary_name: str, name_or_address: str, ctx: Context
) -> DecompiledFunction:
    """Decompiles a function in a specified binary and returns its pseudo-C code.

    Args:
        binary_name: The name of the binary containing the function.
        name_or_address: The name or address of the function to decompile.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        cache_manager = getattr(mcp, '_cache_manager', None)
        tools = GhidraTools(program_info, cache_manager=cache_manager)
        return tools.decompile_function_by_name_or_addr(name_or_address)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error decompiling function: {e!s}")
        ) from e


@mcp.tool()
def get_cache_stats(ctx: Context) -> dict:
    """Returns decompilation cache statistics.

    Returns cache hit count, entry count, hit rate, and cache size.
    Useful for diagnostics and understanding cache performance.
    """
    try:
        cache_manager = getattr(mcp, '_cache_manager', None)
        if not cache_manager:
            return {
                "enabled": False,
                "message": "Cache not initialized",
            }
        return cache_manager.get_stats()
    except Exception as e:
        logger.error(f"Error getting cache stats: {e}")
        return {
            "error": str(e),
        }


@mcp.tool()
def search_symbols_by_name(
    binary_name: str, query: str, ctx: Context, offset: int = 0, limit: int = 25
) -> SymbolSearchResults:
    """Searches for symbols, including functions, within a binary by name.

    This tool searches for symbols by a case-insensitive substring. Symbols include
    Functions, Labels, Classes, Namespaces, Externals, Dynamics, Libraries,
    Global Variables, Parameters, and Local Variables.

    Args:
        binary_name: The name of the binary to search within.
        query: The substring to search for in symbol names (case-insensitive).
        offset: The number of results to skip.
        limit: The maximum number of results to return.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        symbols = tools.search_symbols_by_name(query, offset, limit)
        return SymbolSearchResults(symbols=symbols)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error searching for symbols: {e!s}")
        ) from e


@mcp.tool()
def search_code(binary_name: str, query: str, ctx: Context, limit: int = 5) -> CodeSearchResults:
    """
    Perform a semantic code search over a binarys decompiled pseudo C output
    powered by a vector database for similarity matching.

    This returns the most relevant functions or code blocks whose semantics
    match the provided query even if the exact text differs. Results are
    Ghidra generated pseudo C enabling natural language like exploration of
    binary code structure.

    For best results provide a short distinctive query such as a function
    signature or key logic snippet to minimize irrelevant matches.

    Args:
        binary_name: Name of the binary to search within.
        query: Code snippet signature or description to match via semantic search.
        limit: Maximum number of top scoring results to return (default: 5).
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        results = tools.search_code(query, limit)
        return CodeSearchResults(results=results)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error searching for code: {e!s}")
        ) from e


@mcp.tool()
def list_project_binaries(ctx: Context) -> ProgramInfos:
    """
    Retrieve binary name, path, and analysis status for every program (binary) currently
    loaded in the active project.

    Returns a structured list of program entries, each containing:
    - name: The display name of the program
    - file_path: Absolute path to the binary file on disk (if available)
    - load_time: Timestamp when the program was loaded into the project
    - analysis_complete: Boolean indicating if automated analysis has finished

    Use this to inspect the full set of binaries in the project, monitor analysis
    progress, or drive follow up actions such as listing imports/exports or running
    code searches on specific programs.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_infos = []
        for name, pi in pyghidra_context.programs.items():
            program_infos.append(
                ProgramInfo(
                    name=name,
                    file_path=str(pi.file_path) if pi.file_path else None,
                    load_time=pi.load_time,
                    analysis_complete=pi.analysis_complete,
                    metadata={},
                    code_collection=pi.code_collection is not None,
                    strings_collection=pi.strings_collection is not None,
                )
            )
        return ProgramInfos(programs=program_infos)
    except Exception as e:
        raise McpError(
            ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error listing project program info: {e!s}",
            )
        ) from e


@mcp.tool()
def list_project_binary_metadata(binary_name: str, ctx: Context) -> BinaryMetadata:
    """
    Retrieve detailed metadata for a specific program (binary) in the active project.

    This tool provides extensive information about a binary, including its architecture,
    compiler, executable format, and various analysis metrics like the number of
    functions and symbols. It is useful for gaining a deep understanding of a
    binary's composition and properties. For example, you can use it to determine
    the processor (`Processor`), endianness (`Endian`), or check if it's a
    relocatable file (`Relocatable`). The results also include hashes like MD5/SHA256
    and details from the executable format (e.g., ELF or PE).

    Args:
        binary_name: The name of the binary to retrieve metadata for.

    Returns:
        An object containing detailed metadata for the specified binary.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        metadata_dict = program_info.metadata
        return BinaryMetadata.model_validate(metadata_dict)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error retrieving binary metadata: {e!s}",
            )
        ) from e


@mcp.tool()
async def delete_project_binary(binary_name: str, ctx: Context) -> str:
    """Deletes a binary (program) from the project.

    Args:
        binary_name: The name of the binary to delete.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        if pyghidra_context.delete_program(binary_name):
            return f"Successfully deleted binary: {binary_name}"
        else:
            raise McpError(
                ErrorData(
                    code=INVALID_PARAMS,
                    message=f"Binary '{binary_name}' not found or could not be deleted.",
                )
            )
    except Exception as e:
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error deleting binary: {e!s}")
        ) from e


@mcp.tool()
def list_exports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ExportInfos:
    """
    Retrieve exported functions and symbols from a given binary,
    with optional regex filtering to focus on only the most relevant items.

    For large binaries, using the `query` parameter is strongly recommended
    to reduce noise and improve downstream reasoning. Specify a substring
    or regex to match export names. For example: `query="init"`
    to list only initialization-related exports.

    Args:
        binary_name: Name of the binary to inspect.
        query: Strongly recommended. Regex pattern to match specific
               export names. Use to limit irrelevant results and narrow
               context for analysis.
        offset: Number of matching results to skip (for pagination).
        limit: Maximum number of results to return.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        exports = tools.list_exports(query=query, offset=offset, limit=limit)
        return ExportInfos(exports=exports)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error listing exports: {e!s}")
        ) from e


@mcp.tool()
def list_imports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ImportInfos:
    """
    Retrieve imported functions and symbols from a given binary,
    with optional filtering to return only the most relevant matches.

    This tool is most effective when you use the `query` parameter to
    focus results — especially for large binaries — by specifying a
    substring or regex that matches the desired import names.
    For example: `query="socket"` to only see socket-related imports.

    Args:
        binary_name: Name of the binary to inspect.
        query: Strongly recommended. Regex pattern to match specific
               import names. Use to reduce irrelevant results and narrow
               context for downstream reasoning.
        offset: Number of matching results to skip (for pagination).
        limit: Maximum number of results to return.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        imports = tools.list_imports(query=query, offset=offset, limit=limit)
        return ImportInfos(imports=imports)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error listing imports: {e!s}")
        ) from e


@mcp.tool()
def list_cross_references(
    binary_name: str, name_or_address: str, ctx: Context
) -> CrossReferenceInfos:
    """Finds and lists all cross-references (x-refs) to a given function, symbol, or address within
    a binary. This is crucial for understanding how code and data are used and related.
    If an exact match for a function or symbol is not found,
    the error message will suggest other symbols that are close matches.

    Args:
        binary_name: The name of the binary to search for cross-references in.
        name_or_address: The name of the function, symbol, or a specific address (e.g., '0x1004010')
        to find cross-references to.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        cross_references = tools.list_cross_references(name_or_address)
        return CrossReferenceInfos(cross_references=cross_references)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error listing cross-references: {e!s}")
        ) from e


@mcp.tool()
def search_strings(
    binary_name: str,
    ctx: Context,
    query: str,
    limit: int = 100,
) -> StringSearchResults:
    """Searches for strings within a binary by name.
    This can be very useful to gain general understanding of behaviors.

    Args:
        binary_name: The name of the binary to search within.
        query: A query to filter strings by.
        limit: The maximum number of results to return.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        strings = tools.search_strings(query=query, limit=limit)
        return StringSearchResults(strings=strings)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error searching for strings: {e!s}")
        ) from e


@mcp.tool()
def read_bytes(binary_name: str, ctx: Context, address: str, size: int = 32) -> BytesReadResult:
    """Reads raw bytes from memory at a specified address.

    Args:
        binary_name: The name of the binary to read bytes from.
        address: The memory address to read from (supports hex format with or without 0x prefix).
        size: The number of bytes to read (default: 32, max: 8192).
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        return tools.read_bytes(address=address, size=size)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
    except Exception as e:
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Error reading bytes: {e!s}")) from e


@mcp.tool()
def list_structures(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 100,
) -> StructureListResult:
    """List structure/class data types from Ghidra's Data Type Manager.

    Returns structure layouts including member names, types, offsets, and sizes.
    Use query to filter by name (regex). Paginate with offset/limit.

    Args:
        binary_name: The name of the binary to inspect.
        query: Regex pattern to filter structure names (case-insensitive).
        offset: Number of results to skip (for pagination).
        limit: Maximum number of results to return.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        structures, total = tools.get_structures(query, offset, limit)
        return StructureListResult(
            structures=[StructureInfo(**s) for s in structures],
            total_count=total,
        )
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error listing structures: {e!s}")
        ) from e


@mcp.tool()
def extract_structures(
    binary_name: str,
    ctx: Context,
    max_functions: int = 0,
    timeout_per_func: int = 30,
) -> dict:
    """Extract structure types by batch-decompiling functions.

    Ghidra's DTM is empty after headless analysis. This tool decompiles functions
    to trigger the decompiler's type inference, then collects any Structure types
    it discovers from local/global variables and parameters.

    This is a long-running operation (minutes to hours for large binaries).
    Use max_functions to limit scope for testing.

    Args:
        binary_name: The name of the binary to analyze.
        max_functions: Max functions to decompile (0 = all).
        timeout_per_func: Decompiler timeout per function in seconds.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        structures, stats = tools.extract_structures(max_functions, timeout_per_func)
        return {
            "structures": structures,
            "total_count": len(structures),
            "stats": stats,
        }
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error extracting structures: {e!s}")
        ) from e


@mcp.tool()
def create_structures(
    binary_name: str,
    class_defs: list[dict],
    ctx: Context,
) -> dict:
    """Create structure data types in Ghidra's Data Type Manager.

    Seeds the DTM with structure definitions from DC3 headers, enabling the
    decompiler to use these types for type propagation and member inference.

    Args:
        binary_name: The name of the binary to operate on.
        class_defs: List of class definitions. Each dict should have:
            - name: str (class name)
            - members: list of {"name": str, "type_str": str, "offset": int, "size": int?}
            - total_size: int? (optional total size)
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        result = tools.create_structures(class_defs)
        # Persist to disk so structs survive restarts
        pyghidra_context.project.save(program_info.program)
        return result
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error creating structures: {e!s}")
        ) from e


@mcp.tool()
def apply_this_types(
    binary_name: str,
    class_methods: dict,
    ctx: Context,
) -> dict:
    """Apply this pointer types to member functions.

    Sets the first parameter (this) of member functions to the appropriate
    class pointer type, enabling better type propagation in the decompiler.

    Args:
        binary_name: The name of the binary to operate on.
        class_methods: Dict mapping class names to lists of function addresses.
            Format: {"ClassName": ["823486e0", "82348700", ...]}
            Addresses should be hex strings without 0x prefix.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        return tools.apply_this_types(class_methods)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error applying this types: {e!s}")
        ) from e


@mcp.tool()
def bulk_create_functions(
    binary_name: str,
    addresses: list[str],
    ctx: Context,
) -> dict:
    """Create Function objects at addresses where Ghidra auto-analysis missed them.

    Many map file addresses have code but no Ghidra function object. This bulk-creates
    functions so they can be decompiled and have signatures applied.

    Args:
        binary_name: The name of the binary to operate on.
        addresses: List of hex address strings without 0x prefix (e.g., ["823486e0", "82348700"]).
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        result = tools.bulk_create_functions(addresses)
        pyghidra_context.project.save(program_info.program)
        return result
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error creating functions: {e!s}")
        ) from e


@mcp.tool()
def apply_demangled_signatures(
    binary_name: str,
    symbols: list[dict],
    ctx: Context,
) -> dict:
    """Apply full function signatures by demangling MSVC mangled names.

    Uses Ghidra's MicrosoftDemangler to parse mangled names into complete function
    signatures (calling convention, return type, all parameter types) and applies them.
    This is far more powerful than apply_this_types as it sets ALL parameters, not just this*.

    Args:
        binary_name: The name of the binary to operate on.
        symbols: List of dicts, each with:
            - "mangled": MSVC mangled name (e.g., "?Load@CharBonesSamples@@QAAXAAVBinStream@@@Z")
            - "address": hex address without 0x prefix (e.g., "823486e0")
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        result = tools.apply_demangled_signatures(symbols)
        pyghidra_context.project.save(program_info.program)
        return result
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error applying demangled signatures: {e!s}")
        ) from e


@mcp.tool()
def gen_callgraph(
    binary_name: str,
    function_name: str,
    ctx: Context,
    direction: CallGraphDirection = CallGraphDirection.CALLING,
    display_type: CallGraphDisplayType = CallGraphDisplayType.FLOW,
    condense_threshold: int = 50,
    top_layers: int = 3,
    bottom_layers: int = 3,
) -> CallGraphResult:
    """Generates a mermaidjs function call graph for a specified function.

    Typically the 'calling' callgraph is most useful.
    The resulting graph string is mermaidjs format. This output is critical for correct rendering.
    The graph details function calls originating from (calling) or terminating at (called)
    the target function.

    Args:
        binary_name: The name of the binary containing the function.
        function_name: The name of the function to generate the call graph for.
        direction: Direction of the call graph (calling or called).
        display_type: Format of the graph (flow, flow_ends).
        condense_threshold: Maximum number of edges before graph condensation is triggered.
        top_layers: Number of top layers to show in a condensed graph.
        bottom_layers: Number of bottom layers to show in a condensed graph.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        return tools.gen_callgraph(
            function_name_or_address=function_name,
            cg_direction=direction,
            cg_display_type=display_type,
            include_refs=True,
            max_depth=None,
            max_run_time=60,
            condense_threshold=condense_threshold,
            top_layers=top_layers,
            bottom_layers=bottom_layers,
        )
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error generating call graph: {e!s}")
        ) from e


@mcp.tool()
def import_binary(binary_path: str, ctx: Context) -> str:
    """Imports a binary from a designated path into the current Ghidra project.

    Args:
        binary_path: The path to the binary file to import.
    """
    try:
        # We would like to do context progress updates, but until that is more
        # widely supported by clients, we will resort to this
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        pyghidra_context.import_binary_backgrounded(binary_path)
        return (
            f"Importing {binary_path} in the background."
            "When ready, it will appear analyzed in binary list."
        )
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error importing binary: {e!s}")
        ) from e


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


def init_pyghidra_context(
    mcp: FastMCP,
    input_paths: list[Path],
    project_name: str,
    project_directory: str,
    force_analysis: bool,
    verbose_analysis: bool,
    no_symbols: bool,
    gdts: list[str],
    program_options_path: str | None,
    gzfs_path: str | None,
    threaded: bool,
    max_workers: int,
    wait_for_analysis: bool,
    list_project_binaries: bool,
    delete_project_binary: str | None,
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
        force_analysis=force_analysis,
        verbose_analysis=verbose_analysis,
        no_symbols=no_symbols,
        gdts=gdts,
        program_options=program_options,
        gzfs_path=gzfs_path,
        threaded=threaded,
        max_workers=max_workers,
        wait_for_analysis=wait_for_analysis,
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

    if len(bin_paths) > 0:
        logger.info(f"Adding new bins: {', '.join(map(str, bin_paths))}")
        logger.info(f"Importing binaries to {project_directory}")
        pyghidra_context.import_binaries(bin_paths)

    logger.info(f"Analyzing project: {pyghidra_context.project}")
    pyghidra_context.analyze_project()

    # Apply map file symbols after analysis (if provided)
    if map_file:
        map_path = Path(map_file)
        _apply_map_symbols(pyghidra_context, map_path)

    if len(pyghidra_context.list_binaries()) == 0:
        logger.warning("No binaries were imported and none exist in the project.")

    mcp._pyghidra_context = pyghidra_context  # type: ignore
    logger.info("Server intialized")

    return mcp


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
    help="Transport protocol to use.",
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
    default=Path("pyghidra_mcp_projects/pyghidra_mcp"),
    show_default=True,
    help="Path to the Ghidra project.",
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
@click.argument("input_paths", type=click.Path(exists=True), nargs=-1)
def main(
    transport: str,
    input_paths: list[Path],
    project_path: Path,
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
    list_project_binaries: bool,
    delete_project_binary: str | None,
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

    # Handle --diagnose flag early (before any initialization)
    if diagnose:
        diagnose()
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

    project_name = project_path.stem
    project_directory = str(project_path.parent)
    mcp.settings.port = port
    mcp.settings.host = host

    init_pyghidra_context(
        mcp=mcp,
        input_paths=input_paths,
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
        list_project_binaries=list_project_binaries,
        delete_project_binary=delete_project_binary,
        map_file=map_file,
    )

    try:
        if transport == "stdio":
            mcp.run(transport="stdio")
        elif transport in ["streamable-http", "http"]:
            mcp.run(transport="streamable-http")
        elif transport == "sse":
            mcp.run(transport="sse")
        else:
            raise ValueError(f"Invalid transport: {transport}")
    finally:
        mcp._pyghidra_context.close()  # type: ignore


if __name__ == "__main__":
    main()

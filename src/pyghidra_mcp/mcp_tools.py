"""
MCP Tool handlers for pyghidra-mcp.

This module contains all MCP tool implementations with centralized error handling.
"""

import asyncio
import functools
import logging
import time
from typing import Literal, cast

from mcp.server.fastmcp import Context
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

from pyghidra_mcp._locking import GHIDRA_GLOBAL_LOCK
from pyghidra_mcp.context_protocol import MCPContext
from pyghidra_mcp.models import (
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CodeSearchResults,
    CommentResponse,
    CrossReferenceInfos,
    DecompiledFunction,
    ExportInfos,
    FunctionPrototypeResponse,
    FunctionSearchResults,
    GotoResponse,
    ImportInfos,
    ImportRequestResult,
    OpenProgramInfo,
    OpenProgramInfos,
    ProgramInfos,
    RenameResponse,
    SearchMode,
    StringSearchResults,
    StructureInfo,
    StructureListResult,
    SymbolSearchResults,
    VariableRenameResponse,
    VariableTypeResponse,
)
from pyghidra_mcp.tools import GhidraTools

logger = logging.getLogger(__name__)

# Service start time for uptime tracking (used by get_service_health). Defined
# here rather than in server.py so mcp_tools never needs to import server.
SERVICE_START_TIME = time.time()


def _make_tools(pyghidra_context, program_info) -> GhidraTools:
    """Build GhidraTools wired with the context's decompile cache + .map source.

    Reads cache_manager/map_file defensively (the GUI context does not set them)
    so decompile caching, SQLite-backed strings search, and .map lookups all work
    for the headless context while staying safe for the GUI context.
    """
    return GhidraTools(
        program_info,
        cache_manager=getattr(pyghidra_context, "cache_manager", None),
        map_file=getattr(pyghidra_context, "map_file", None),
    )


def _require_gui_context(ctx: Context):
    from pyghidra_mcp.gui_context import GuiPyGhidraContext

    pyghidra_context = ctx.request_context.lifespan_context
    if not isinstance(pyghidra_context, GuiPyGhidraContext):
        raise ValueError("This tool requires pyghidra-mcp to be running with --gui")
    return pyghidra_context


def _run_for_context(pyghidra_context: MCPContext, fn):
    from pyghidra_mcp.gui_context import GuiPyGhidraContext

    if isinstance(pyghidra_context, GuiPyGhidraContext):
        return pyghidra_context.run_on_swing(fn)
    return fn()


def _get_action_name(func_name: str) -> str:
    """Derives a gerund action name from a function name."""
    action = func_name.replace("_", " ")
    words = action.split()
    if words and not words[0].endswith("ing"):
        first = words[0]
        if first.endswith("e"):
            words[0] = first[:-1] + "ing"
        else:
            words[0] = first + "ing"
    return " ".join(words)


def mcp_error_handler(func):
    """
    Decorator that provides centralized error handling for MCP tools.
    """
    action = _get_action_name(func.__name__)

    def handle_error(e):
        if isinstance(e, ValueError):
            return McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))
        if isinstance(e, McpError):
            return e
        return McpError(ErrorData(code=INTERNAL_ERROR, message=f"Error {action}: {e!s}"))

    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            raise handle_error(e) from e

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise handle_error(e) from e

    return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper


# MCP Tool Implementations
# ---------------------------------------------------------------------------------


@mcp_error_handler
async def decompile_function(
    binary_name: str,
    name_or_address: str | list[str],
    ctx: Context,
    include_callees: bool = False,
    include_strings: bool = False,
    include_xrefs: bool = False,
    timeout_sec: int = 30,
) -> list[DecompiledFunction]:
    """Decompile function(s) to pseudo-C by name or address.

    Accepts a single target or a list for batch decompilation.
    Rich response flags attach callees, strings, and/or xrefs to each result.
    `timeout_sec` applies per target.
    """
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    targets = [name_or_address] if isinstance(name_or_address, str) else name_or_address
    results: list[DecompiledFunction] = []

    def _decompile_target(target: str) -> DecompiledFunction:
        result = tools.decompile_function_by_name_or_addr(target, timeout=timeout_sec)
        if include_callees:
            result.callees = tools.get_callees(target)
        if include_strings:
            result.referenced_strings = tools.get_referenced_strings(target)
        if include_xrefs:
            result.xrefs = tools.list_xrefs(target)
        return result

    for target in targets:
        try:
            result = await asyncio.to_thread(_decompile_target, target)
            results.append(result)
        except Exception as e:
            results.append(DecompiledFunction(name=target, code="", error=str(e)))
    return results


@mcp_error_handler
def search_symbols_by_name(
    binary_name: str,
    query: str,
    ctx: Context,
    functions_only: bool = False,
    offset: int = 0,
    limit: int = 25,
) -> SymbolSearchResults:
    """Search symbols by regex pattern (case-insensitive).

    Supports full regex (e.g. ``^main$``, ``func.*init``). Plain substrings
    still work since they are valid regex.

    Set ``functions_only=True`` to search only function symbols
    (excludes labels, variables, classes, namespaces).
    """
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    symbols = tools.search_symbols_by_name(
        query, functions_only=functions_only, offset=offset, limit=limit
    )
    return SymbolSearchResults(symbols=symbols)


@mcp_error_handler
def search_code(
    binary_name: str,
    query: str,
    ctx: Context,
    limit: int = 5,
    offset: int = 0,
    search_mode: Literal["semantic", "literal"] = "semantic",
    include_full_code: bool = True,
    preview_length: int = 500,
    similarity_threshold: float = 0.0,
) -> CodeSearchResults:
    """Search decompiled pseudo-C code.

    Modes: semantic (vector similarity, default) or literal (exact match).
    Results include both mode counts.
    """
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    # Distinguish "code index was SKIPPED for this server" from "index still
    # building". Under --skip-code-collection the code_collection is None and
    # will NEVER be built, so the generic "try again later" message is
    # misleading. Give an accurate, actionable error instead. (When code
    # collection is enabled, tools.search_code still raises the truthful
    # "indexing is not complete ... try again later" message.)
    if getattr(program_info, "code_collection", None) is None and getattr(
        pyghidra_context, "skip_code_collection", False
    ):
        raise ValueError(
            "Code search is unavailable: this server was started with "
            "--skip-code-collection, so the semantic/literal code index was "
            "never built for this binary and never will be during this "
            "session. Use search_strings for text/data references and "
            "list_xrefs (plus decompile_function) to trace code, or restart "
            "the server without --skip-code-collection to enable code search."
        )
    tools = _make_tools(pyghidra_context, program_info)
    return tools.search_code(
        query=query,
        limit=limit,
        offset=offset,
        search_mode=SearchMode(search_mode),
        include_full_code=include_full_code,
        preview_length=preview_length,
        similarity_threshold=similarity_threshold,
    )


@mcp_error_handler
def list_project_binaries(ctx: Context) -> ProgramInfos:
    """List all binaries in the project with their status."""
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    return ProgramInfos(programs=pyghidra_context.list_project_binary_infos())


@mcp_error_handler
def list_project_binary_metadata(binary_name: str, ctx: Context) -> dict:
    """Get binary metadata: architecture, compiler, endianness, hashes, analysis counts."""
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    return program_info.metadata


@mcp_error_handler
def list_open_programs(ctx: Context) -> OpenProgramInfos:
    """List programs currently open in the Ghidra GUI."""
    gui_context = _require_gui_context(ctx)
    programs = [OpenProgramInfo(**info) for info in gui_context.list_open_programs()]
    return OpenProgramInfos(programs=programs)


@mcp_error_handler
def open_program_in_gui(
    binary_name: str,
    new_window: bool = True,
    *,
    ctx: Context,
) -> OpenProgramInfo:
    """Open a project binary in the Ghidra GUI CodeBrowser.

    Defaults to a new CodeBrowser unless the binary is already open.
    """
    gui_context = _require_gui_context(ctx)
    return OpenProgramInfo(**gui_context.open_program_in_gui(binary_name, new_window=new_window))


@mcp_error_handler
def set_current_program(binary_name: str, ctx: Context) -> OpenProgramInfo:
    """Set the active/current program in the Ghidra GUI CodeBrowser."""
    gui_context = _require_gui_context(ctx)
    return OpenProgramInfo(**gui_context.set_current_program(binary_name))


@mcp_error_handler
def goto(
    binary_name: str,
    target: str,
    target_type: Literal["address", "function"],
    ctx: Context,
) -> GotoResponse:
    """Navigate the Ghidra GUI CodeBrowser to an address or function."""
    gui_context = _require_gui_context(ctx)
    return GotoResponse(**gui_context.goto(binary_name, target, target_type))


@mcp_error_handler
def rename_function(
    binary_name: str,
    name_or_address: str,
    new_name: str,
    ctx: Context,
) -> RenameResponse:
    """Rename a function."""
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.rename_function(name_or_address, new_name),
    )
    result = cast(dict, result)
    return RenameResponse(binary_name=binary_name, **result)


@mcp_error_handler
def rename_variable(
    binary_name: str,
    function_name_or_address: str,
    variable_name: str,
    new_name: str,
    ctx: Context,
) -> VariableRenameResponse:
    """Rename a parameter or local by exact name."""
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.rename_variable(function_name_or_address, variable_name, new_name),
    )
    result = cast(dict, result)
    return VariableRenameResponse(binary_name=binary_name, **result)


@mcp_error_handler
def set_variable_type(
    binary_name: str,
    function_name_or_address: str,
    variable_name: str,
    type_name: str,
    ctx: Context,
) -> VariableTypeResponse:
    """Set a parameter or local type by exact name."""
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.set_variable_type(function_name_or_address, variable_name, type_name),
    )
    result = cast(dict, result)
    return VariableTypeResponse(binary_name=binary_name, **result)


@mcp_error_handler
def set_function_prototype(
    binary_name: str,
    function_name_or_address: str,
    prototype: str,
    ctx: Context,
) -> FunctionPrototypeResponse:
    """Set a function prototype. Invalid input returns Ghidra's error."""
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.set_function_prototype(function_name_or_address, prototype),
    )
    result = cast(dict, result)
    return FunctionPrototypeResponse(binary_name=binary_name, **result)


@mcp_error_handler
def set_comment(
    binary_name: str,
    target: str,
    comment: str,
    comment_type: Literal["decompiler", "plate", "pre", "eol", "post", "repeatable"],
    ctx: Context,
) -> CommentResponse:
    """Set a decompiler or listing comment."""
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.set_comment(target, comment, comment_type),
    )
    result = cast(dict, result)
    return CommentResponse(binary_name=binary_name, **result)


@mcp_error_handler
async def delete_project_binary(binary_name: str, ctx: Context) -> str:
    """Delete a binary from the project."""
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    if pyghidra_context.delete_program(binary_name):
        return f"Successfully deleted binary: {binary_name}"
    else:
        raise McpError(
            ErrorData(
                code=INVALID_PARAMS,
                message=f"Binary '{binary_name}' not found or could not be deleted.",
            )
        )


@mcp_error_handler
def list_exports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ExportInfos:
    """List exported symbols, optionally filtered by regex query."""
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    exports = tools.list_exports(query=query, offset=offset, limit=limit)
    return ExportInfos(exports=exports)


@mcp_error_handler
def list_imports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ImportInfos:
    """List imported symbols, optionally filtered by regex query."""
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    imports = tools.list_imports(query=query, offset=offset, limit=limit)
    return ImportInfos(imports=imports)


@mcp_error_handler
def list_xrefs(
    binary_name: str, name_or_address: str | list[str], ctx: Context
) -> list[CrossReferenceInfos]:
    """List cross-references to function(s), symbol(s), or address(es).

    Accepts a single target or a list for batch lookup.
    Suggests close matches on no exact hit.
    """
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    targets = [name_or_address] if isinstance(name_or_address, str) else name_or_address
    results: list[CrossReferenceInfos] = []
    for target in targets:
        try:
            cross_references = tools.list_xrefs(target)
            results.append(CrossReferenceInfos(target=target, cross_references=cross_references))
        except Exception as e:
            results.append(CrossReferenceInfos(target=target, cross_references=[], error=str(e)))
    return results


@mcp_error_handler
def search_strings(
    binary_name: str,
    ctx: Context,
    query: str,
    limit: int = 100,
) -> StringSearchResults:
    """Search for strings within a binary."""
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    strings = tools.search_strings(query=query, limit=limit)
    return StringSearchResults(strings=strings)


@mcp_error_handler
def read_bytes(binary_name: str, ctx: Context, address: str, size: int = 32) -> BytesReadResult:
    """Read raw bytes at an address. Hex format supported (0x prefix optional)."""
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    return tools.read_bytes(address=address, size=size)


@mcp_error_handler
def gen_callgraph(
    binary_name: str,
    function_name: str,
    ctx: Context,
    direction: Literal["calling", "called"] = "calling",
    display_type: Literal["flow", "flow_ends"] = "flow",
    condense_threshold: int = 50,
    top_layers: int = 3,
    bottom_layers: int = 3,
    max_run_time: int = 120,
) -> CallGraphResult:
    """Generate a MermaidJS call graph for a function."""
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    return tools.gen_callgraph(
        function_name_or_address=function_name,
        cg_direction=CallGraphDirection(direction),
        cg_display_type=CallGraphDisplayType(display_type),
        include_refs=True,
        max_depth=None,
        max_run_time=max_run_time,
        condense_threshold=condense_threshold,
        top_layers=top_layers,
        bottom_layers=bottom_layers,
    )


@mcp_error_handler
def import_binary(binary_path: str, ctx: Context) -> ImportRequestResult:
    """Import a binary into the project from a file path."""
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    return pyghidra_context.import_binary_backgrounded(binary_path)


# Fork-only tools (freeqaz/pyghidra-mcp)
# ---------------------------------------------------------------------------------


@mcp_error_handler
def get_service_health(ctx: Context) -> dict:
    """Returns health status of the Ghidra service.

    This endpoint can be called to verify the service is running and responsive.
    Returns uptime, version, and Ghidra readiness status.
    """
    from pyghidra_mcp import __version__

    try:
        pyghidra_context: MCPContext = ctx.request_context.lifespan_context
        uptime_seconds = int(time.time() - SERVICE_START_TIME)
        programs = getattr(pyghidra_context, "programs", {}) or {}
        ghidra_ready = len(programs) > 0
        return {
            "status": "healthy",
            "version": __version__,
            "uptime_seconds": uptime_seconds,
            "ghidra_ready": ghidra_ready,
            "programs_loaded": len(programs),
        }
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {
            "status": "error",
            "version": __version__,
            "error": str(e),
        }


@mcp_error_handler
def get_cache_stats(ctx: Context) -> dict:
    """Returns decompilation cache statistics.

    Returns cache hit count, entry count, hit rate, and cache size.
    Useful for diagnostics and understanding cache performance.
    """
    try:
        pyghidra_context: MCPContext = ctx.request_context.lifespan_context
        cache = getattr(pyghidra_context, "cache_manager", None)
        if not cache:
            return {
                "enabled": False,
                "message": "Cache not initialized",
            }
        return cache.get_stats()
    except Exception as e:
        logger.error(f"Error getting cache stats: {e}")
        return {
            "error": str(e),
        }


@mcp_error_handler
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
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    functions = tools.search_functions_by_name(query, offset, limit)
    return FunctionSearchResults(functions=functions)


@mcp_error_handler
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
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    structures, total = tools.get_structures(query, offset, limit)
    return StructureListResult(
        structures=[StructureInfo(**s) for s in structures],
        total_count=total,
    )


@mcp_error_handler
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
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    structures, stats = tools.extract_structures(max_functions, timeout_per_func)
    return {
        "structures": structures,
        "total_count": len(structures),
        "stats": stats,
    }


@mcp_error_handler
def create_structures(
    binary_name: str,
    class_defs: list[dict],
    ctx: Context,
) -> dict:
    """Create structure data types in Ghidra's Data Type Manager.

    Seeds the DTM with the provided struct definitions (e.g. transcribed from
    headers or a symbol source), enabling the decompiler to use these types for
    type propagation and member inference.

    Args:
        binary_name: The name of the binary to operate on.
        class_defs: List of class definitions. Each dict should have:
            - name: str (class name)
            - members: list of {"name": str, "type_str": str, "offset": int, "size": int?}
            - total_size: int? (optional total size)
    """
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    result = tools.create_structures(class_defs)
    # Persist to disk so structs survive restarts. project.save touches the
    # shared Ghidra program DB, so serialize it through the same global lock
    # the GhidraTools methods use (create_structures already ran under it).
    with GHIDRA_GLOBAL_LOCK:
        pyghidra_context.project.save(program_info.program)
    return result


@mcp_error_handler
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
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    return tools.apply_this_types(class_methods)


@mcp_error_handler
def bulk_create_functions(
    binary_name: str,
    addresses: list[str],
    ctx: Context,
) -> dict:
    """Create Function objects at addresses where Ghidra auto-analysis missed them.

    Given addresses (e.g. from a symbol/map source, an .exidx table, or manual
    triage) that hold code but have no Ghidra function object, this bulk-creates
    functions so they can be decompiled and have signatures applied.

    Args:
        binary_name: The name of the binary to operate on.
        addresses: List of hex address strings without 0x prefix (e.g., ["823486e0", "82348700"]).
    """
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    result = tools.bulk_create_functions(addresses)
    # Serialize the shared-program-DB save through the global Ghidra lock.
    with GHIDRA_GLOBAL_LOCK:
        pyghidra_context.project.save(program_info.program)
    return result


@mcp_error_handler
def apply_demangled_signatures(
    binary_name: str,
    symbols: list[dict],
    ctx: Context,
) -> dict:
    """Apply full function signatures by demangling MSVC-mangled names.

    MSVC-ONLY: uses Ghidra's MicrosoftDemangler to parse Microsoft Visual C++
    mangled names ("?name@Class@@...") into complete function signatures (calling
    convention, return type, all parameter types) and applies them. More powerful
    than apply_this_types as it sets ALL parameters, not just this*.

    Not applicable to targets without MSVC mangling (e.g. a stripped GCC/ARM ELF,
    which has no mangled symbols at all, or Itanium/GCC-mangled C++). For those,
    use set_function_prototype to set signatures explicitly.

    Args:
        binary_name: The name of the binary to operate on.
        symbols: List of dicts, each with:
            - "mangled": MSVC mangled name (e.g., "?Load@Class@@QAAXAAVStream@@@Z")
            - "address": hex address without 0x prefix (e.g., "00401a20")
    """
    pyghidra_context: MCPContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = _make_tools(pyghidra_context, program_info)
    result = tools.apply_demangled_signatures(symbols)
    # Serialize the shared-program-DB save through the global Ghidra lock.
    with GHIDRA_GLOBAL_LOCK:
        pyghidra_context.project.save(program_info.program)
    return result

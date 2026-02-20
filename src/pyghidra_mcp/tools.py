"""
Comprehensive tool implementations for pyghidra-mcp.
"""

import functools
import logging
import re
import typing
from pathlib import Path
from typing import Optional

from ghidrecomp.callgraph import gen_callgraph
from jpype import JByte

from pyghidra_mcp.models import (
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CodeSearchResult,
    CrossReferenceInfo,
    DecompiledFunction,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    StringInfo,
    StringSearchResult,
    SwitchDetectionResult,
    SwitchInfo,
    SymbolInfo,
)
from pyghidra_mcp.symbol_lookup import (
    SymbolMatcher,
    MapFileParser,
    demangle_msvc,
    extract_method_name,
    extract_class_name,
    DEFAULT_MAP_FILE,
)

if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.app.decompiler import DecompileResults
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import Symbol

    from .context import ProgramInfo
    from pyghidra_mcp.cache_manager import CacheManager

logger = logging.getLogger(__name__)


def annotate_ppc_decompilation(code: str) -> str:
    """Annotate common PPC decompilation patterns with explanatory comments.

    Adds comments to LZCOUNT patterns (from PowerPC cntlzw instruction):
    - LZCOUNT(x) >> 5              ->  LZCOUNT(x) >> 5 /* == !x */
    - (ulonglong)(LZCOUNT(x) << 0x20) >> 0x25  ->  ... /* == !x */
    - (uint)LZCOUNT(x) >> 5        ->  ... /* == !x */

    The cntlzw instruction returns 32 if input is 0, 0-31 otherwise.
    Shifting right by 5 (dividing by 32) gives 1 for zero, 0 for non-zero.

    Preserves original Ghidra output while adding context for readability.
    """
    patterns = [
        # 64-bit variant: (ulonglong)(LZCOUNT(x) << 0x20) >> 0x25
        # Must come first (more specific)
        (r"(\(ulonglong\)\(LZCOUNT\([^)]+\)\s*<<\s*0x20\)\s*>>\s*0x25)",
         r"\1 /* == !x */"),

        # With cast: (uint)LZCOUNT(x) >> 5
        (r"(\(uint\)LZCOUNT\([^)]+\)\s*>>\s*5)",
         r"\1 /* == !x */"),

        # Simple: LZCOUNT(x) >> 5 (but not when preceded by a cast)
        # Negative lookbehind excludes (uint) and (ulonglong)( prefixes
        (r"(?<!\(uint\))(?<!\(ulonglong\)\()(LZCOUNT\([^)]+\)\s*>>\s*5)",
         r"\1 /* == !x */"),
    ]

    result = code
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result)

    return result


# Merged symbol pattern: merged_<8 hex digits>
_MERGED_PATTERN = re.compile(r'\bmerged_([0-9a-fA-F]{8})\b')

# Module-level cache for map parser (lazy init)
_map_parser_cache: Optional[MapFileParser] = None


def _get_map_parser() -> Optional[MapFileParser]:
    """Get cached map parser, initializing on first use."""
    global _map_parser_cache
    if _map_parser_cache is None and DEFAULT_MAP_FILE is not None and DEFAULT_MAP_FILE.exists():
        _map_parser_cache = MapFileParser(DEFAULT_MAP_FILE)
    return _map_parser_cache


def annotate_switch_statements(code: str, switches: list) -> str:
    """Add header comment about detected switch statements.

    When a function contains switch statements (detected via bctr instructions),
    adds a comment at the top of the decompiled code to help with matching.

    Args:
        code: Decompiled C code
        switches: List of SwitchInfo objects from detect_switch_statements

    Returns:
        Code with switch hint comment prepended if switches detected
    """
    if not switches:
        return code

    # Build hint comment
    lines = ["/* SWITCH STATEMENTS DETECTED:"]

    for i, sw in enumerate(switches, 1):
        parts = [f"   {i}. Address {sw.address}"]
        if sw.case_count is not None:
            parts.append(f"~{sw.case_count} cases")
        lines.append(" - ".join(parts))

    lines.append("   Ghidra if-else chains at these locations are likely switch statements.")
    lines.append("*/")
    lines.append("")

    return "\n".join(lines) + code


def annotate_merged_calls(code: str, map_parser: Optional[MapFileParser] = None) -> str:
    """Annotate merged_<addr> symbols with their actual symbol names.

    When the linker uses Identical COMDAT Folding (ICF), functions with identical
    machine code get merged to a single address. Ghidra shows these as
    'merged_82331360' which isn't helpful. This annotates them with the actual
    symbol names.

    Example:
        merged_82331360(this, 1)
    becomes:
        merged_82331360(this, 1) /* ObjRef scalar/vector dtor */

    Args:
        code: Ghidra decompilation output
        map_parser: Optional MapFileParser instance. If not provided,
                   uses the default map file.

    Returns:
        Annotated code with comments explaining merged symbols
    """
    if map_parser is None:
        map_parser = _get_map_parser()

    if map_parser is None:
        return code  # No map file available

    def replace_merged(match: re.Match) -> str:
        addr_hex = match.group(1).upper()
        full_match = match.group(0)

        try:
            address = int(addr_hex, 16)
        except ValueError:
            return full_match

        symbols = map_parser.lookup_all_symbols_by_address(address)
        if not symbols:
            return full_match

        if len(symbols) == 1:
            # Single symbol - just show its name
            sym = symbols[0]
            short_name = sym.method_name if sym.class_name else sym.demangled
            return f"{full_match} /* {short_name} */"

        # Multiple merged symbols - show abbreviated names
        # Common pattern: scalar and vector deleting destructors
        names = []
        for sym in symbols:
            if sym.method_name == "`scalar deleting destructor'":
                names.append("scalar dtor")
            elif sym.method_name == "`vector deleting destructor'":
                names.append("vector dtor")
            elif sym.class_name:
                names.append(f"{sym.class_name}::{sym.method_name}")
            else:
                names.append(sym.demangled[:30])  # Truncate long names

        # Deduplicate and join
        unique_names = list(dict.fromkeys(names))  # Preserve order, remove dupes
        if len(unique_names) <= 3:
            comment = ", ".join(unique_names)
        else:
            comment = f"{unique_names[0]}, {unique_names[1]}, +{len(unique_names) - 2} more"

        return f"{full_match} /* {comment} */"

    return _MERGED_PATTERN.sub(replace_merged, code)


def handle_exceptions(func):
    """Decorator to handle exceptions in tool methods"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e!s}")
            raise

    return wrapper


class GhidraTools:
    """Comprehensive tool handler for Ghidra MCP tools"""

    def __init__(
        self,
        program_info: "ProgramInfo",
        cache_manager: "CacheManager | None" = None,
        map_file: Optional[Path] = None,
    ):
        """Initialize with a Ghidra ProgramInfo object

        Args:
            program_info: Ghidra program information
            cache_manager: Optional cache manager for decompilation caching
            map_file: Optional path to linker map file for address lookups
        """
        self.program_info = program_info
        self.program = program_info.program
        self.decompiler = program_info.decompiler
        self.cache_manager = cache_manager

        # Initialize symbol matcher for multi-strategy lookups
        map_path = map_file or DEFAULT_MAP_FILE
        self.symbol_matcher = SymbolMatcher(map_path)

        # Compute binary hash for cache lookups
        self.binary_hash = None
        if cache_manager and program_info.file_path:
            try:
                from pyghidra_mcp.cache_manager import compute_binary_hash
                self.binary_hash = compute_binary_hash(program_info.file_path)
            except Exception as e:
                logger.debug(f"Could not compute binary hash: {e}")

    def _get_filename(self, func: "Function"):
        max_path_len = 50
        return f"{func.getSymbol().getName(True)[:max_path_len]}-{func.entryPoint}"

    def find_function(self, name_or_address: str) -> Optional["Function"]:
        """
        Find a function using multi-strategy lookup.

        Tries in order:
        1. Direct hex address (e.g., "0x82E4E6B8" or "82E4E6B8")
        2. Address lookup (from map file) - O(1) hash lookup
        3. Exact name match - O(n) iteration
        4. Demangled name match (Class::Method format)
        5. Method name only match
        6. Partial/substring match

        Args:
            name_or_address: Function name (mangled, demangled, or partial) or hex address

        Returns:
            Ghidra Function object or None if not found
        """
        fm = self.program.getFunctionManager()

        # Strategy 0: Direct hex address (e.g., "0x82E4E6B8" or "82E4E6B8")
        raw_addr = None
        stripped = name_or_address.strip().lower().replace("0x", "")
        if stripped and all(c in "0123456789abcdef" for c in stripped):
            try:
                raw_addr = int(stripped, 16)
            except ValueError:
                pass
        if raw_addr is not None:
            addr_formats = [
                f"0x{raw_addr:08x}",
                f"ram:0x{raw_addr:08x}",
            ]
            for addr_str in addr_formats:
                try:
                    addr = self.program.getAddressFactory().getAddress(addr_str)
                    if addr:
                        func = fm.getFunctionAt(addr)
                        if func:
                            logger.debug(f"Found function by direct address: {name_or_address} -> {func.name}")
                            return func
                        func = fm.getFunctionContaining(addr)
                        if func:
                            logger.debug(f"Found function by direct address (containing): {name_or_address} -> {func.name}")
                            return func
                except Exception as e:
                    logger.debug(f"Direct address lookup failed for {addr_str}: {e}")

        # Strategy 1: Address lookup from map file (O(1) - try first!)
        address = self.symbol_matcher.get_address(name_or_address)
        if address:
            # Try multiple address formats - Ghidra can be picky
            addr_formats = [
                f"0x{address:08x}",  # 0x82674a08
                f"{address:08x}",   # 82674a08
                f"ram:0x{address:08x}",  # ram:0x82674a08
                f"ram:{address:08x}",  # ram:82674a08
            ]
            found_addr = None  # Track successful address parse
            for addr_str in addr_formats:
                logger.debug(f"Attempting address lookup: {name_or_address} -> {addr_str}")
                try:
                    addr = self.program.getAddressFactory().getAddress(addr_str)
                    if addr:
                        found_addr = addr  # Save for later function creation
                        # Try exact match first
                        func = fm.getFunctionAt(addr)
                        if func:
                            logger.debug(f"Found function by address lookup (exact): {name_or_address} -> {addr_str}")
                            return func
                        # Try containing function (in case address is slightly off)
                        func = fm.getFunctionContaining(addr)
                        if func:
                            logger.debug(f"Found function by address lookup (containing): {name_or_address} -> {addr_str} -> {func.name}")
                            return func
                        logger.debug(f"No function at/containing address {addr_str}")
                    else:
                        logger.debug(f"Address factory returned None for {addr_str}")
                except Exception as e:
                    logger.debug(f"Address lookup failed for {addr_str}: {e}")

            # Strategy 1b: Try creating function at address if not found
            # Some symbols exist in map file but Ghidra didn't create functions during analysis
            if found_addr:
                try:
                    from ghidra.app.cmd.function import CreateFunctionCmd
                    cmd = CreateFunctionCmd(found_addr)
                    success = cmd.applyTo(self.program)
                    if success:
                        func = fm.getFunctionAt(found_addr)
                        if func:
                            logger.info(f"Created function at 0x{address:08x} for: {name_or_address}")
                            return func
                    else:
                        # Check if address is inside another function (inlined/thunk)
                        containing_func = fm.getFunctionContaining(found_addr)
                        if containing_func:
                            logger.warning(f"Address 0x{address:08x} is inside {containing_func.name} - "
                                         "possibly inlined or a jump target")
                        else:
                            logger.debug(f"Failed to create function at 0x{address:08x}")
                except Exception as e:
                    logger.debug(f"Failed to create function at 0x{address:08x}: {e}")
        else:
            logger.debug(f"No address found in map file for: {name_or_address}")

        # Strategy 2: Exact name match (O(n) - only if map lookup fails)
        functions = fm.getFunctions(True)
        for func in functions:
            if name_or_address == func.name:
                logger.debug(f"Found function by exact match: {name_or_address}")
                return func

        # Strategy 3-5: Try search variants (demangled, method name, etc.)
        variants = self.symbol_matcher.get_search_variants(name_or_address)
        for variant, match_type in variants:
            if match_type == "exact":
                continue  # Already tried

            # Try exact match on variant
            functions = fm.getFunctions(True)
            for func in functions:
                func_name = func.name

                if match_type == "demangled" and variant == func_name:
                    logger.debug(f"Found function by demangled match: {name_or_address} -> {func_name}")
                    return func

                if match_type == "short_demangled" and variant == func_name:
                    logger.debug(f"Found function by short demangled match: {name_or_address} -> {func_name}")
                    return func

                if match_type == "method":
                    # Method name might match end of function name
                    # e.g., variant="PoseMeshes" matches func_name="CharBonesMeshes::PoseMeshes"
                    if func_name == variant or func_name.endswith(f"::{variant}"):
                        logger.debug(f"Found function by method name match: {name_or_address} -> {func_name}")
                        return func

        # Strategy 6: Partial/substring match (last resort)
        # Try to find function where method name is in the function name
        method_name = extract_method_name(name_or_address)
        class_name = extract_class_name(name_or_address)

        if method_name:
            functions = fm.getFunctions(True)
            candidates = []
            for func in functions:
                func_name = func.name
                # Check if method name appears in function name
                if method_name.lower() in func_name.lower():
                    # Prefer matches that also have class name
                    if class_name and class_name.lower() in func_name.lower():
                        candidates.insert(0, func)  # Higher priority
                    else:
                        candidates.append(func)

            if candidates:
                logger.debug(f"Found function by partial match: {name_or_address} -> {candidates[0].name}")
                return candidates[0]

        logger.warning(f"Function not found with any strategy: {name_or_address}")
        return None

    def find_function_address(self, name_or_address: str) -> Optional["ghidra.program.model.address.Address"]:
        """
        Find a function's address using multi-strategy lookup.

        Similar to find_function but returns the address directly,
        useful for cross-reference lookups.

        Args:
            name_or_address: Function name (mangled, demangled, or partial) or address

        Returns:
            Ghidra Address object or None if not found
        """
        # Try finding the function first
        func = self.find_function(name_or_address)
        if func:
            return func.getEntryPoint()

        # If function not found, try direct address lookup
        address = self.symbol_matcher.get_address(name_or_address)
        if address:
            addr_str = self.symbol_matcher.format_address_for_ghidra(address)
            try:
                return self.program.getAddressFactory().getAddress(addr_str)
            except Exception as e:
                logger.debug(f"Address conversion failed: {e}")

        return None

    def _lookup_symbols(
        self,
        name_or_address: str,
        *,
        exact: bool = True,
        partial: bool = False,
        dynamic: bool = False,
    ) -> list["Symbol"]:
        """
        Resolve symbols by name or address.
        Returns a single flat list of unique Symbol objects.
        Search modes (exact, partial, dynamic) are optional and only applied if enabled.
        """
        st = self.program.getSymbolTable()
        af = self.program.getAddressFactory()

        # Try interpreting as an address first
        try:
            addr = af.getAddress(name_or_address)
            if addr:
                addr_symbols = st.getSymbols(addr)
                if addr_symbols:
                    return list(addr_symbols)
        except Exception:
            pass  # Not an address, fall back to name search

        name_lc = name_or_address.lower()
        matches: set[Symbol] = set()

        # Base symbol set (externals only once)
        base_symbols = self.get_all_symbols(include_externals=True)

        # Exact match
        if exact:
            matches.update(s for s in base_symbols if name_lc == s.getName(True).lower())

        # Partial match
        if partial:
            matches.update(s for s in base_symbols if name_lc in s.getName(True).lower())

        # Dynamic match (requires second scan)
        if dynamic:
            dyn_symbols = self.get_all_symbols(include_externals=True, include_dynamic=True)
            matches.update(s for s in dyn_symbols if name_lc in s.getName(True).lower())

        return list(matches)

    @handle_exceptions
    def find_symbols(self, name_or_address: str) -> list["Symbol"]:
        """
        Return all symbols that match name_or_address (exact or partial).
        Never raises; returns empty list if none.
        """
        return self._lookup_symbols(name_or_address, exact=True, partial=True)

    @handle_exceptions
    def find_symbol(self, name_or_address: str) -> "Symbol":
        """
        Resolve a single symbol by name or address.
        Raises if ambiguous or not found.
        """
        matches = self._lookup_symbols(name_or_address, exact=True, partial=True)

        if len(matches) == 1:
            return matches[0]
        elif len(matches) > 1:
            suggestions = [f"{s.getName(True)} @ {s.getAddress()}" for s in matches]
            raise ValueError(
                f"Ambiguous match for '{name_or_address}'. Did you mean one of these: "
                + ", ".join(suggestions)
            )
        else:
            raise ValueError(f"Symbol '{name_or_address}' not found.")

    @handle_exceptions
    def decompile_function_by_name_or_addr(
        self, name_or_address: str, timeout: int = 0
    ) -> DecompiledFunction:
        """Finds and decompiles a function in a specified binary and returns its pseudo-C code.

        Uses multi-strategy lookup to find functions by:
        - Direct hex address
        - Address lookup from map file
        - Exact name match
        - Demangled name (Class::Method)
        - Method name only
        - Partial/substring match
        """
        func = self.find_function(name_or_address)
        if not func:
            raise ValueError(f"Function {name_or_address} not found")
        return self._decompile_function_impl(func, timeout)

    def decompile_function(self, func: "Function", timeout: int = 0) -> DecompiledFunction:
        """Decompiles a function in a specified binary and returns its pseudo-C code."""
        return self._decompile_function_impl(func, timeout)

    def _decompile_function_impl(self, func: "Function", timeout: int = 0) -> DecompiledFunction:
        """Internal implementation of function decompilation with caching support."""
        from ghidra.util.task import ConsoleTaskMonitor

        # Try cache first
        address = str(func.getEntryPoint())
        if self.cache_manager and self.binary_hash:
            cached = self.cache_manager.get(address, self.binary_hash)
            if cached:
                logger.info(f"Cache hit for {func.name} at {address}")
                return DecompiledFunction(
                    name=self._get_filename(func),
                    code=cached,
                    signature=None,  # Could be parsed from cached code if needed
                )

        # Cache miss - decompile
        logger.debug(f"Cache miss for {func.name}, decompiling...")
        monitor = ConsoleTaskMonitor()
        result: DecompileResults = self.decompiler.decompileFunction(func, timeout, monitor)
        if "" == result.getErrorMessage():
            code = result.decompiledFunction.getC()
            # Annotate PPC-specific patterns with explanatory comments
            code = annotate_ppc_decompilation(code)
            # Annotate merged symbols with their actual names
            code = annotate_merged_calls(code)
            # Detect and annotate switch statements
            try:
                switches = self._detect_switches_internal(func)
                code = annotate_switch_statements(code, switches)
            except Exception as e:
                logger.debug(f"Switch detection failed for {func.name}: {e}")
            sig = result.decompiledFunction.getSignature()
        else:
            code = result.getErrorMessage()
            sig = None

        # Store in cache (stores simplified output)
        if self.cache_manager and self.binary_hash and code:
            self.cache_manager.put(address, self.binary_hash, code)

        return DecompiledFunction(name=self._get_filename(func), code=code, signature=sig)

    @handle_exceptions
    def get_all_functions(self, include_externals=False) -> list["Function"]:
        """
        Gets all functions within a binary.
        Returns a python list that doesn't need to be re-intialized
        """

        funcs = set()
        fm = self.program.getFunctionManager()
        functions = fm.getFunctions(True)
        for func in functions:
            func: Function
            if not include_externals and func.isExternal():
                continue
            if not include_externals and func.thunk:
                continue
            funcs.add(func)
        return list(funcs)

    @handle_exceptions
    def get_all_symbols(
        self, include_externals: bool = False, include_dynamic=False
    ) -> list["Symbol"]:
        """
        Gets all symbols within a binary.
        Returns a python list that doesn't need to be re-initialized.
        """

        symbols = set()
        from ghidra.program.model.symbol import SymbolTable

        st: SymbolTable = self.program.getSymbolTable()
        all_symbols = st.getAllSymbols(include_dynamic)

        for sym in all_symbols:
            sym: Symbol
            if not include_externals and sym.isExternal():
                continue
            symbols.add(sym)

        return list(symbols)

    @handle_exceptions
    def get_all_strings(self) -> list[StringInfo]:
        """Gets all defined strings for a binary"""
        try:
            from ghidra.program.util import DefinedStringIterator  # type: ignore

            data_iterator = DefinedStringIterator.forProgram(self.program)
        except ImportError:
            # Support Ghidra 11.3.2
            from ghidra.program.util import DefinedDataIterator

            data_iterator = DefinedDataIterator.definedStrings(self.program)

        strings = []
        for data in data_iterator:
            try:
                string_value = data.getValue()
                strings.append(StringInfo(value=str(string_value), address=str(data.getAddress())))
            except Exception as e:
                logger.debug(f"Could not get string value from data at {data.getAddress()}: {e}")

        return strings

    @handle_exceptions
    def search_functions_by_name(
        self, query: str, offset: int = 0, limit: int = 100
    ) -> list[FunctionInfo]:
        """Searches for functions within a binary by name.

        Checks both function names and symbol labels at function addresses,
        so map-file-imported labels are searchable even if the function wasn't renamed.

        Args:
            query: The substring to search for in function names (case-insensitive).
            offset: The number of results to skip.
            limit: The maximum number of results to return.

        Returns:
            List of FunctionInfo objects matching the query.
        """
        if not query:
            raise ValueError("Query string is required")

        funcs = []
        seen_addrs = set()
        query_lc = query.lower()
        fm = self.program.getFunctionManager()
        st = self.program.getSymbolTable()

        # Pass 1: Search function names directly
        for func in fm.getFunctions(True):
            if query_lc in func.name.lower():
                addr_str = str(func.getEntryPoint())
                if addr_str not in seen_addrs:
                    seen_addrs.add(addr_str)
                    funcs.append(FunctionInfo(
                        name=func.name,
                        entry_point=addr_str
                    ))

        # Pass 2: Search symbol labels and find functions at those addresses
        for symbol in st.getAllSymbols(True):
            if query_lc in symbol.getName(True).lower():
                addr = symbol.getAddress()
                addr_str = str(addr)
                if addr_str not in seen_addrs:
                    func = fm.getFunctionAt(addr)
                    if func:
                        seen_addrs.add(addr_str)
                        # Use the label name since it's the real symbol
                        funcs.append(FunctionInfo(
                            name=symbol.getName(True),
                            entry_point=addr_str
                        ))

        return funcs[offset : limit + offset]

    @handle_exceptions
    def search_symbols_by_name(
        self, query: str, offset: int = 0, limit: int = 100
    ) -> list[SymbolInfo]:
        """Searches for symbols within a binary by name."""

        if not query:
            raise ValueError("Query string is required")

        symbols_info = []
        symbols = self.find_symbols(query)
        rm = self.program.getReferenceManager()

        # Search for symbols containing the query string
        for symbol in symbols:
            if query.lower() in symbol.getName(True).lower():
                ref_count = len(list(rm.getReferencesTo(symbol.getAddress())))
                symbols_info.append(
                    SymbolInfo(
                        name=symbol.name,
                        address=str(symbol.getAddress()),
                        type=str(symbol.getSymbolType()),
                        namespace=str(symbol.getParentNamespace()),
                        source=str(symbol.getSource()),
                        refcount=ref_count,
                        external=symbol.isExternal(),
                    )
                )
        return symbols_info[offset : limit + offset]

    @handle_exceptions
    def list_exports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ExportInfo]:
        """Lists all exported functions and symbols from a specified binary."""
        exports = []
        symbols = self.program.getSymbolTable().getAllSymbols(True)
        for symbol in symbols:
            if symbol.isExternalEntryPoint():
                if query and not re.search(query, symbol.getName(), re.IGNORECASE):
                    continue
                exports.append(ExportInfo(name=symbol.getName(), address=str(symbol.getAddress())))
        return exports[offset : limit + offset]

    @handle_exceptions
    def list_imports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ImportInfo]:
        """Lists all imported functions and symbols for a specified binary."""
        imports = []
        symbols = self.program.getSymbolTable().getExternalSymbols()
        for symbol in symbols:
            if query and not re.search(query, symbol.getName(), re.IGNORECASE):
                continue
            imports.append(
                ImportInfo(name=symbol.getName(), library=str(symbol.getParentNamespace()))
            )
        return imports[offset : limit + offset]

    @handle_exceptions
    def list_cross_references(self, name_or_address: str) -> list[CrossReferenceInfo]:
        """Finds and lists all cross-references (x-refs) to a given function, symbol,
        or address within a binary.

        Uses multi-strategy lookup to find functions by:
        - Direct address (hex string like "823486e0")
        - Exact name match
        - Address lookup from map file
        - Demangled name (Class::Method)
        - Method name only
        - Partial/substring match
        """
        # Try parsing as direct address first
        addr = None
        try:
            addr = self.program.getAddressFactory().getAddress(name_or_address)
        except Exception:
            pass

        # If not a valid address, use multi-strategy function lookup
        if addr is None:
            addr = self.find_function_address(name_or_address)

        # Fall back to symbol lookup if function address not found
        if addr is None:
            sym: Symbol = self.find_symbol(name_or_address)
            addr = sym.getAddress()

        if addr is None:
            raise ValueError(f"Could not find function or address: {name_or_address}")

        cross_references: list[CrossReferenceInfo] = []
        rm = self.program.getReferenceManager()
        references = rm.getReferencesTo(addr)

        for ref in references:
            from_func = self.program.getFunctionManager().getFunctionContaining(
                ref.getFromAddress()
            )
            cross_references.append(
                CrossReferenceInfo(
                    function_name=from_func.getName() if from_func else None,
                    from_address=str(ref.getFromAddress()),
                    to_address=str(ref.getToAddress()),
                    type=str(ref.getReferenceType()),
                )
            )
        return cross_references

    @handle_exceptions
    def search_code(self, query: str, limit: int = 10) -> list[CodeSearchResult]:
        """Searches the code in the binary for a given query."""
        if not self.program_info.code_collection:
            raise ValueError(
                "Code indexing is not complete for this binary. Please try again later."
            )

        results = self.program_info.code_collection.query(query_texts=[query], n_results=limit)
        search_results = []
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"][0]):
                metadata = results["metadatas"][0][i]  # type: ignore
                distance = results["distances"][0][i]  # type: ignore
                search_results.append(
                    CodeSearchResult(
                        function_name=str(metadata["function_name"]),
                        code=doc,
                        similarity=1 - distance,
                    )
                )
        return search_results

    @handle_exceptions
    def search_strings(self, query: str, limit: int = 100) -> list[StringSearchResult]:
        """Searches for strings within a binary."""

        if not self.program_info.strings_collection:
            raise ValueError(
                "String indexing is not complete for this binary. Please try again later."
            )

        search_results = []
        results = self.program_info.strings_collection.get(
            where_document={"$contains": query}, limit=limit
        )
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"]):
                metadata = results["metadatas"][i]  # type: ignore
                search_results.append(
                    StringSearchResult(
                        value=doc,
                        address=str(metadata["address"]),
                        similarity=1,
                    )
                )
            limit -= len(results["documents"])

        if limit <= 0:
            return search_results
        results = self.program_info.strings_collection.query(query_texts=[query], n_results=limit)
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"][0]):
                metadata = results["metadatas"][0][i]  # type: ignore
                distance = results["distances"][0][i]  # type: ignore
                search_results.append(
                    StringSearchResult(
                        value=doc,
                        address=str(metadata["address"]),
                        similarity=1 - distance,
                    )
                )

        return search_results

    @handle_exceptions
    def read_bytes(self, address: str, size: int = 32) -> BytesReadResult:
        """Reads raw bytes from memory at a specified address."""
        # Maximum size limit to prevent excessive memory reads
        max_read_size = 8192

        if size <= 0:
            raise ValueError("size must be > 0")

        if size > max_read_size:
            raise ValueError(f"Size {size} exceeds maximum {max_read_size}")

        # Get address factory and parse address
        af = self.program.getAddressFactory()

        try:
            # Handle common hex address formats
            addr_str = address
            if address.lower().startswith("0x"):
                addr_str = address[2:]

            addr = af.getAddress(addr_str)
            if addr is None:
                raise ValueError(f"Invalid address: {address}")
        except Exception as e:
            raise ValueError(f"Invalid address format '{address}': {e}") from e

        # Check if address is in valid memory
        mem = self.program.getMemory()
        if not mem.contains(addr):
            raise ValueError(f"Address {address} is not in mapped memory")

        # Use JPype to handle byte arrays properly for PyGhidra
        # Create Java byte array - JPype's runtime magic confuses static type checkers
        buf = JByte[size]  # type: ignore[reportInvalidTypeArguments]
        n = mem.getBytes(addr, buf)

        # Convert Java signed bytes (-128 to 127) to Python unsigned (0 to 255)
        if n > 0:
            data = bytes([b & 0xFF for b in buf[:n]])  # type: ignore[reportGeneralTypeIssues]
        else:
            data = b""

        return BytesReadResult(
            address=str(addr),
            size=len(data),
            data=data.hex(),
        )

    @handle_exceptions
    def gen_callgraph(
        self,
        function_name_or_address: str,
        cg_direction: CallGraphDirection = CallGraphDirection.CALLING,
        cg_display_type: CallGraphDisplayType = CallGraphDisplayType.FLOW,
        include_refs: bool = True,
        max_depth: int | None = None,
        max_run_time: int = 60,
        condense_threshold: int = 50,
        top_layers: int = 5,
        bottom_layers: int = 5,
    ) -> CallGraphResult:
        """Generates a call graph for a specified function."""

        cg_func = self.find_function(function_name_or_address)
        mermaid_url: str = ""

        # Call the ghidrecomp function
        name, direction, _, graphs_data = gen_callgraph(
            func=cg_func,
            max_display_depth=max_depth,
            direction=cg_direction.value,
            max_run_time=max_run_time,
            name=cg_func.getSymbol().getName(True),
            include_refs=include_refs,
            condense_threshold=condense_threshold,
            top_layers=top_layers,
            bottom_layers=bottom_layers,
            wrap_mermaid=False,
        )

        selected_graph_content = ""
        for graph_type, graph_content in graphs_data:
            if CallGraphDisplayType(graph_type) == cg_display_type:
                selected_graph_content = graph_content
                break

        if not selected_graph_content:
            raise ValueError(
                f"Cg display type {cg_display_type.value} not found for function {cg_func}."
            )

        for graph_type, graph_content in graphs_data:
            if graph_type == "mermaid_url":
                mermaid_url = graph_content.split("\n")[0]
                break

        return CallGraphResult(
            function_name=name,
            direction=CallGraphDirection(direction),
            display_type=cg_display_type,
            graph=selected_graph_content,
            mermaid_url=mermaid_url,
        )

    @handle_exceptions
    def get_structures(self, query: str = ".*", offset: int = 0, limit: int = 100) -> tuple[list[dict], int]:
        """Get structure data types from the Data Type Manager.

        Args:
            query: Regex pattern to filter structure names (case-insensitive).
            offset: Number of results to skip (pagination).
            limit: Maximum number of results to return.

        Returns:
            Tuple of (list of structure dicts, total count matching filter).
        """
        from ghidra.program.model.data import Structure

        dtm = self.program.getDataTypeManager()
        dt_iter = dtm.getAllDataTypes()

        pattern = re.compile(query, re.IGNORECASE)
        structures = []
        for dt in dt_iter:
            if not isinstance(dt, Structure):
                continue
            try:
                name = dt.getName()
            except Exception:
                continue
            if not pattern.search(name):
                continue

            members = []
            try:
                for comp in dt.getComponents():
                    members.append({
                        'name': comp.getFieldName(),
                        'type_name': str(comp.getDataType().getName()),
                        'offset': comp.getOffset(),
                        'size': comp.getLength(),
                    })
            except Exception as e:
                logger.debug(f"Error reading members of {name}: {e}")

            structures.append({
                'name': name,
                'category': str(dt.getCategoryPath()),
                'size': dt.getLength(),
                'num_members': len(members),
                'members': members,
            })

        total = len(structures)
        return structures[offset:offset + limit], total

    @handle_exceptions
    def extract_structures(
        self, max_functions: int = 0, timeout_per_func: int = 30
    ) -> tuple[list[dict], dict]:
        """Extract structure types by decompiling functions and reading the decompiler's inferred types.

        The Ghidra DTM is typically empty for headless analysis. Structures are
        only created when the decompiler runs. This method batch-decompiles
        functions, collects any Structure types from the decompiler's HighFunction
        IR (local variables, parameters, globals), and returns them.

        Args:
            max_functions: Max functions to decompile (0 = all).
            timeout_per_func: Decompiler timeout per function in seconds.

        Returns:
            Tuple of (list of structure dicts, stats dict).
        """
        from ghidra.program.model.data import Structure, Composite, Pointer, Array, TypeDef
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        fm = self.program.getFunctionManager()

        # Collect all non-external functions
        all_funcs = []
        for func in fm.getFunctions(True):
            if func.isExternal() or func.isThunk():
                continue
            all_funcs.append(func)

        if max_functions > 0:
            all_funcs = all_funcs[:max_functions]

        total = len(all_funcs)
        logger.info(f"extract_structures: decompiling {total} functions...")

        # Track unique structures by name
        found_structs: dict[str, dict] = {}
        decompiled = 0
        errors = 0
        # Debug: track all type classes seen
        all_type_classes: set[str] = set()
        total_symbols_seen = 0

        def _unwrap_type(dt):
            """Unwrap pointers, arrays, and typedefs to get the base type."""
            seen = set()
            while dt is not None:
                dt_id = id(dt)
                if dt_id in seen:
                    break
                seen.add(dt_id)

                if isinstance(dt, Pointer):
                    dt = dt.getDataType()
                elif isinstance(dt, Array):
                    dt = dt.getDataType()
                elif isinstance(dt, TypeDef):
                    dt = dt.getBaseDataType()
                else:
                    break
            return dt

        def _collect_type(dt):
            """Collect Structure type, unwrapping wrappers first."""
            if dt is None:
                return

            # Track type class for debugging
            try:
                all_type_classes.add(type(dt).__name__)
            except Exception:
                pass

            base = _unwrap_type(dt)
            if base is None:
                return

            try:
                all_type_classes.add(type(base).__name__)
            except Exception:
                pass

            if not isinstance(base, Structure):
                return

            name = base.getName()
            if not name or name in found_structs:
                return
            # Skip auto-generated "astruct" names (decompiler placeholders)
            # but keep ones with real names
            if name.startswith("astruct") and name[7:].isdigit():
                return

            members = []
            try:
                for comp in base.getComponents():
                    members.append({
                        'name': comp.getFieldName(),
                        'type_name': str(comp.getDataType().getName()),
                        'offset': comp.getOffset(),
                        'size': comp.getLength(),
                    })
            except Exception as e:
                logger.debug(f"Error reading members of {name}: {e}")
                return

            found_structs[name] = {
                'name': name,
                'category': str(base.getCategoryPath()),
                'size': base.getLength(),
                'num_members': len(members),
                'members': members,
            }

        for i, func in enumerate(all_funcs):
            try:
                result = self.decompiler.decompileFunction(func, timeout_per_func, monitor)
                if result.getErrorMessage() != "":
                    errors += 1
                    continue

                high_func = result.getHighFunction()
                if not high_func:
                    errors += 1
                    continue

                decompiled += 1

                # Extract types from local symbol map
                try:
                    local_map = high_func.getLocalSymbolMap()
                    if local_map:
                        for sym in local_map.getSymbols():
                            total_symbols_seen += 1
                            _collect_type(sym.getDataType())
                except Exception:
                    pass

                # Extract types from global symbol map
                try:
                    global_map = high_func.getGlobalSymbolMap()
                    if global_map:
                        for sym in global_map.getSymbols():
                            total_symbols_seen += 1
                            _collect_type(sym.getDataType())
                except Exception:
                    pass

                # Extract function parameter types
                try:
                    proto = high_func.getFunctionPrototype()
                    if proto:
                        _collect_type(proto.getReturnType())
                        total_symbols_seen += 1
                        num_params = proto.getNumParams()
                        for p in range(num_params):
                            _collect_type(proto.getParam(p).getDataType())
                            total_symbols_seen += 1
                except Exception:
                    pass

            except Exception as e:
                errors += 1
                if errors <= 5:
                    logger.warning(f"Decompile error for {func.getName()}: {e}")

            # Progress logging every 1000 functions
            if (i + 1) % 1000 == 0:
                logger.info(
                    f"  Progress: {i+1}/{total} functions, "
                    f"{len(found_structs)} structures found"
                )

        # Log first batch of type classes for debugging
        if decompiled > 0 and not found_structs:
            logger.info(
                f"DEBUG: {total_symbols_seen} symbols seen across {decompiled} funcs, "
                f"type classes: {all_type_classes}"
            )

        stats = {
            'total_functions': total,
            'decompiled': decompiled,
            'errors': errors,
            'structures_found': len(found_structs),
        }
        logger.info(
            f"extract_structures complete: {decompiled}/{total} decompiled, "
            f"{errors} errors, {len(found_structs)} structures"
        )

        return list(found_structs.values()), stats

    def _detect_switches_internal(self, func: "Function") -> list[SwitchInfo]:
        """Internal switch detection that returns list of SwitchInfo.

        Used by decompilation pipeline to add annotations.
        """
        listing = self.program.getListing()
        body = func.getBody()
        instructions = listing.getInstructions(body, True)

        switches = []

        # Collect all instructions for back-reference
        instr_list = []
        for instr in instructions:
            instr_list.append(instr)

        # Find bctr instructions (switch jump points)
        for i, instr in enumerate(instr_list):
            mnemonic = instr.getMnemonicString()
            if mnemonic == "bctr":
                switch_info = self._analyze_switch_pattern(instr_list, i)
                switches.append(switch_info)

        return switches

    @handle_exceptions
    def detect_switch_statements(self, name_or_address: str) -> SwitchDetectionResult:
        """Detect switch statements in a function by analyzing PowerPC instructions.

        Switch statements on PowerPC use jump tables with the pattern:
        - Compare index against bounds (optional cmplwi)
        - Load target from jump table (lwzx rN, rBase, rIndex)
        - Move to count register (mtctr rN)
        - Branch to count register (bctr)

        This helps identify when Ghidra's if-else chains are actually switches.

        Args:
            name_or_address: Function name or address to analyze

        Returns:
            SwitchDetectionResult with detected switch locations
        """
        func = self.find_function(name_or_address)
        if not func:
            raise ValueError(f"Function not found: {name_or_address}")

        switches = self._detect_switches_internal(func)

        return SwitchDetectionResult(
            function_name=func.getName(),
            function_address=str(func.getEntryPoint()),
            switches=switches,
        )

    def _analyze_switch_pattern(
        self, instr_list: list, bctr_index: int
    ) -> SwitchInfo:
        """Analyze instructions before bctr to extract switch details.

        Looks backwards from bctr for:
        - mtctr rN (move to count register)
        - lwzx rN, rBase, rIndex (load from jump table)
        - cmplwi rIndex, N (bounds check - gives case count)
        """
        bctr_instr = instr_list[bctr_index]
        addr = str(bctr_instr.getAddress())

        index_reg = None
        table_addr = None
        case_count = None

        # Look back up to 20 instructions for the pattern
        lookback = min(bctr_index, 20)

        for j in range(bctr_index - 1, bctr_index - lookback - 1, -1):
            if j < 0:
                break

            instr = instr_list[j]
            mnemonic = instr.getMnemonicString()

            # mtctr rN - the register being branched to
            if mnemonic == "mtctr":
                # Could extract which register, but not critical
                pass

            # lwzx - load word indexed (jump table access)
            if mnemonic == "lwzx":
                # Format: lwzx rD, rA, rB
                # rB is typically the index register
                num_ops = instr.getNumOperands()
                if num_ops >= 3:
                    try:
                        # Get the index register (usually the last operand)
                        index_reg = str(instr.getOpObjects(2)[0])
                    except Exception:
                        pass
                    try:
                        # Try to get table base from rA
                        base_objs = instr.getOpObjects(1)
                        if base_objs:
                            table_addr = str(base_objs[0])
                    except Exception:
                        pass

            # cmplwi - compare logical word immediate (bounds check)
            # Format: cmplwi crN, rA, N or cmplwi rA, N
            if mnemonic == "cmplwi":
                try:
                    # The immediate value is the case count
                    num_ops = instr.getNumOperands()
                    # Get the last operand (the immediate)
                    last_op = instr.getOpObjects(num_ops - 1)
                    if last_op:
                        val = last_op[0]
                        if hasattr(val, 'getValue'):
                            case_count = int(val.getValue())
                        elif isinstance(val, (int, float)):
                            case_count = int(val)
                except Exception:
                    pass

            # cmpwi - signed compare (also used for bounds check)
            if mnemonic == "cmpwi":
                try:
                    num_ops = instr.getNumOperands()
                    last_op = instr.getOpObjects(num_ops - 1)
                    if last_op:
                        val = last_op[0]
                        if hasattr(val, 'getValue'):
                            case_count = int(val.getValue())
                        elif isinstance(val, (int, float)):
                            case_count = int(val)
                except Exception:
                    pass

        return SwitchInfo(
            address=addr,
            case_count=case_count,
            index_register=index_reg,
            table_address=table_addr,
        )

    @handle_exceptions
    def create_structures(self, class_defs: list[dict]) -> dict:
        """Create Structure data types in the program's DTM.

        Seeds Ghidra's Data Type Manager with structure definitions from DC3 headers.
        This enables the decompiler to use these types for type propagation.

        Args:
            class_defs: List of class definitions. Each dict:
                {
                    "name": str,
                    "members": [{"name": str, "type_str": str, "offset": int, "size": int?}],
                    "total_size": int?
                }

        Returns:
            {"created": int, "errors": int}
        """
        from ghidra.program.model.data import (
            StructureDataType, CategoryPath,
            IntegerDataType, FloatDataType, BooleanDataType,
            ByteDataType, ShortDataType, PointerDataType,
            Undefined1DataType, Undefined4DataType, CharDataType,
        )

        dtm = self.program.getDataTypeManager()
        category = CategoryPath("/DC3")

        # Type mapping for common DC3 types
        type_map = {
            "int": IntegerDataType.dataType,
            "float": FloatDataType.dataType,
            "bool": BooleanDataType.dataType,
            "char": CharDataType.dataType,
            "short": ShortDataType.dataType,
            "unsigned char": ByteDataType.dataType,
            "unsigned int": IntegerDataType.dataType,
        }

        txn = self.program.startTransaction("Create DC3 structures")
        created = 0
        errors = 0

        try:
            for class_def in class_defs:
                try:
                    name = class_def["name"]
                    total_size = class_def.get("total_size", 0)

                    # Auto-calculate total_size if not provided
                    if not total_size and class_def.get("members"):
                        for m in class_def["members"]:
                            end = m.get("offset", 0) + m.get("size", 4)
                            if end > total_size:
                                total_size = end

                    struct = StructureDataType(category, name, total_size or 0)

                    for member in class_def.get("members", []):
                        offset = member["offset"]
                        field_name = member["name"]
                        type_str = member.get("type_str", "")
                        size = member.get("size", 4)

                        # Resolve data type from type string
                        dt = type_map.get(type_str, Undefined4DataType.dataType)

                        try:
                            struct.replaceAtOffset(offset, dt, size, field_name, None)
                        except Exception:
                            # Overlap or alignment issue - skip this member
                            pass

                    dtm.addDataType(struct, None)
                    created += 1
                except Exception as e:
                    errors += 1
                    if errors <= 5:
                        logger.warning(f"Failed to create structure {class_def.get('name', '?')}: {e}")

            self.program.endTransaction(txn, True)
            logger.info(f"Created {created} structures in DTM ({errors} errors)")
            return {"created": created, "errors": errors}
        except Exception as e:
            self.program.endTransaction(txn, False)
            logger.error(f"Structure creation transaction failed: {e}")
            raise

    @handle_exceptions
    def apply_this_types(self, class_methods: dict[str, list[str]]) -> dict:
        """Set this pointer types on member functions.

        Uses the map file to identify which functions are member functions, then sets
        the first parameter (this) to the appropriate class pointer type.

        Args:
            class_methods: {class_name: [address_hex, address_hex, ...]}
                Each address should be a hex string without 0x prefix (e.g., "823486e0")

        Returns:
            {"applied": int, "missing_type": int, "no_function": int}
        """
        from ghidra.program.model.data import PointerDataType
        from ghidra.program.model.symbol import SourceType

        dtm = self.program.getDataTypeManager()
        fm = self.program.getFunctionManager()
        memory = self.program.getMemory()

        # Build DTM type lookup dict upfront (O(1) instead of O(n×m))
        logger.info("Building DTM type lookup index...")
        dtm_lookup: dict[str, object] = {}
        for dt in dtm.getAllDataTypes():
            try:
                dtm_lookup[dt.getName()] = dt
            except Exception:
                pass
        logger.info(f"Indexed {len(dtm_lookup)} data types")

        txn = self.program.startTransaction("Apply this types")
        applied = 0
        missing_type = 0
        no_function = 0
        debug_sample_count = 0

        try:
            for class_name, addresses in class_methods.items():
                # Look up the Structure type we created in create_structures (O(1))
                struct_dt = dtm_lookup.get(class_name)

                if struct_dt is None:
                    missing_type += len(addresses)
                    continue

                ptr_type = PointerDataType(struct_dt)

                for addr_hex in addresses:
                    try:
                        # Parse address (expect hex string without 0x prefix)
                        addr_int = int(addr_hex, 16)

                        # Try multiple address formats
                        addr = None
                        for addr_fmt in [f"0x{addr_int:08x}", f"ram:0x{addr_int:08x}"]:
                            try:
                                candidate = self.program.getAddressFactory().getAddress(addr_fmt)
                                if candidate and memory.contains(candidate):
                                    addr = candidate
                                    break
                            except Exception:
                                pass

                        if addr is None:
                            no_function += 1
                            if debug_sample_count < 5:
                                logger.info(f"Address not in memory: 0x{addr_int:08x} ({class_name})")
                                debug_sample_count += 1
                            continue

                        # Try exact function at address
                        func = fm.getFunctionAt(addr)

                        # Fallback: try containing function (for thunks/wrappers)
                        if func is None:
                            func = fm.getFunctionContaining(addr)
                            if func and debug_sample_count < 5:
                                logger.info(
                                    f"Using containing function {func.getName()} for 0x{addr_int:08x} ({class_name})"
                                )
                                debug_sample_count += 1

                        if func:
                            # Get or create the this parameter
                            if func.getParameterCount() > 0:
                                # Function has parameters - update the first one (this)
                                param = func.getParameter(0)
                                param.setDataType(ptr_type, SourceType.USER_DEFINED)
                            else:
                                # Function has no parameters - create the this parameter
                                from ghidra.program.model.listing import ParameterImpl
                                param = ParameterImpl("this", ptr_type, self.program)
                                func.insertParameter(0, param, SourceType.USER_DEFINED)
                            applied += 1
                        else:
                            no_function += 1
                            # Debug first few failures
                            if debug_sample_count < 5:
                                logger.info(
                                    f"No function found at 0x{addr_int:08x} ({class_name})"
                                )
                                debug_sample_count += 1
                    except Exception as e:
                        no_function += 1
                        if debug_sample_count < 5:
                            logger.info(f"Exception applying type at {addr_hex}: {e}")
                            debug_sample_count += 1

            self.program.endTransaction(txn, True)
            logger.info(f"Applied this types: {applied} functions, {missing_type} missing types, {no_function} no function")
            return {"applied": applied, "missing_type": missing_type, "no_function": no_function}
        except Exception as e:
            self.program.endTransaction(txn, False)
            logger.error(f"Apply this types transaction failed: {e}")
            raise

    def bulk_create_functions(self, addresses: list[str]) -> dict:
        """Create Function objects at addresses where none exist.

        Many addresses in the map file have code but Ghidra's auto-analysis
        didn't create function objects for them. This creates functions at
        those addresses so they can be decompiled and have signatures applied.

        Args:
            addresses: List of hex address strings without 0x prefix (e.g., ["823486e0", "82348700"])

        Returns:
            {"created": int, "already_exist": int, "failed": int}
        """
        from ghidra.app.cmd.function import CreateFunctionCmd

        fm = self.program.getFunctionManager()
        memory = self.program.getMemory()
        addr_factory = self.program.getAddressFactory()

        txn = self.program.startTransaction("Bulk create functions")
        created = 0
        already_exist = 0
        failed = 0
        debug_sample_count = 0

        try:
            for addr_hex in addresses:
                try:
                    addr_int = int(addr_hex, 16)
                    addr = None
                    for addr_fmt in [f"0x{addr_int:08x}", f"ram:0x{addr_int:08x}"]:
                        try:
                            candidate = addr_factory.getAddress(addr_fmt)
                            if candidate and memory.contains(candidate):
                                addr = candidate
                                break
                        except Exception:
                            pass

                    if addr is None:
                        failed += 1
                        if debug_sample_count < 5:
                            logger.info(f"Address not in memory: 0x{addr_int:08x}")
                            debug_sample_count += 1
                        continue

                    # Check if function already exists
                    if fm.getFunctionAt(addr) is not None:
                        already_exist += 1
                        continue

                    # Create function at address
                    cmd = CreateFunctionCmd(addr)
                    if cmd.applyTo(self.program):
                        created += 1
                    else:
                        failed += 1
                        if debug_sample_count < 5:
                            logger.info(f"CreateFunctionCmd failed at 0x{addr_int:08x}")
                            debug_sample_count += 1
                except Exception as e:
                    failed += 1
                    if debug_sample_count < 5:
                        logger.info(f"Exception creating function at {addr_hex}: {e}")
                        debug_sample_count += 1

            self.program.endTransaction(txn, True)
            logger.info(f"Bulk create functions: {created} created, {already_exist} already exist, {failed} failed")
            return {"created": created, "already_exist": already_exist, "failed": failed}
        except Exception as e:
            self.program.endTransaction(txn, False)
            logger.error(f"Bulk create functions transaction failed: {e}")
            raise

    def apply_demangled_signatures(self, symbols: list[dict]) -> dict:
        """Apply full function signatures by demangling MSVC mangled names.

        Uses Ghidra's built-in MicrosoftDemangler to parse mangled names into
        full function signatures (calling convention, return type, all parameter
        types) and applies them via DemangledObject.applyTo().

        This replaces both create_structures() and apply_this_types() for
        functions whose mangled names encode complete type information.

        Args:
            symbols: List of dicts with:
                - "mangled": MSVC mangled name (e.g., "?Load@CharBonesSamples@@QAAXAAVBinStream@@@Z")
                - "address": hex address without 0x prefix (e.g., "823486e0")

        Returns:
            {"applied": int, "partial": int, "no_function": int, "demangle_failed": int, "skipped": int}
        """
        from ghidra.app.util.demangler import DemanglerOptions
        from ghidra.app.util.demangler.microsoft import MicrosoftDemangler
        from ghidra.util.task import TaskMonitor

        fm = self.program.getFunctionManager()
        memory = self.program.getMemory()
        addr_factory = self.program.getAddressFactory()
        monitor = TaskMonitor.DUMMY

        demangler = MicrosoftDemangler()
        options = DemanglerOptions()
        options.setApplySignature(True)
        options.setApplyCallingConvention(True)

        txn = self.program.startTransaction("Apply demangled signatures")
        applied = 0
        partial = 0
        no_function = 0
        demangle_failed = 0
        skipped = 0
        debug_sample_count = 0

        try:
            for symbol in symbols:
                mangled = symbol.get("mangled", "")
                addr_hex = symbol.get("address", "")

                # Pre-filter: skip non-function symbols
                if not mangled.startswith("?") or mangled.startswith("??_C@") or mangled.startswith("??_R"):
                    skipped += 1
                    continue

                try:
                    addr_int = int(addr_hex, 16)
                    addr = None
                    for addr_fmt in [f"0x{addr_int:08x}", f"ram:0x{addr_int:08x}"]:
                        try:
                            candidate = addr_factory.getAddress(addr_fmt)
                            if candidate and memory.contains(candidate):
                                addr = candidate
                                break
                        except Exception:
                            pass

                    if addr is None:
                        no_function += 1
                        continue

                    # Check function exists
                    func = fm.getFunctionAt(addr)
                    if func is None:
                        no_function += 1
                        if debug_sample_count < 5:
                            logger.info(f"No function at 0x{addr_int:08x} for {mangled[:60]}")
                            debug_sample_count += 1
                        continue

                    # Demangle the symbol
                    try:
                        demangled = demangler.demangle(mangled)
                    except Exception as e:
                        demangle_failed += 1
                        if debug_sample_count < 5:
                            logger.info(f"Demangle failed for {mangled[:60]}: {e}")
                            debug_sample_count += 1
                        continue

                    if demangled is None:
                        demangle_failed += 1
                        continue

                    # Apply full signature
                    try:
                        demangled.applyTo(self.program, addr, options, monitor)
                        applied += 1
                    except Exception as e:
                        # applyTo can fail on conflicts — try partial application
                        partial += 1
                        if debug_sample_count < 5:
                            logger.info(f"Partial apply for {mangled[:60]}: {e}")
                            debug_sample_count += 1

                except Exception as e:
                    demangle_failed += 1
                    if debug_sample_count < 5:
                        logger.info(f"Exception processing {mangled[:60]}: {e}")
                        debug_sample_count += 1

            self.program.endTransaction(txn, True)
            logger.info(
                f"Apply demangled signatures: {applied} applied, {partial} partial, "
                f"{no_function} no function, {demangle_failed} demangle failed, {skipped} skipped"
            )
            return {
                "applied": applied,
                "partial": partial,
                "no_function": no_function,
                "demangle_failed": demangle_failed,
                "skipped": skipped,
            }
        except Exception as e:
            self.program.endTransaction(txn, False)
            logger.error(f"Apply demangled signatures transaction failed: {e}")
            raise

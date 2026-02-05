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
    SymbolInfo,
)
from pyghidra_mcp.symbol_lookup import (
    SymbolMatcher,
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
            sig = result.decompiledFunction.getSignature()
        else:
            code = result.getErrorMessage()
            sig = None

        # Store in cache
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
        fm = self.program.getFunctionManager()
        functions = fm.getFunctions(True)

        # Search for functions containing the query string
        for func in functions:
            if query.lower() in func.name.lower():
                funcs.append(FunctionInfo(
                    name=func.name,
                    entry_point=str(func.getEntryPoint())
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

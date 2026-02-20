"""
Symbol lookup utilities for MSVC mangled names and map file parsing.

Provides multi-strategy function lookup:
1. Exact mangled name match
2. Demangled name match (Class::Method format)
3. Address-based lookup (from map file)
4. Partial/fuzzy matching
5. String literal decoding (??_C@... symbols)
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def decode_msvc_string_literal(mangled: str) -> Optional[str]:
    """Decode string literal from MSVC ??_C@... symbol.

    MSVC encodes string literals as symbols with the format:
        ??_C@_<flag><len>@<hash>@<literal>?$AA@

    Components:
    - ??_C@ - String literal prefix
    - _0 or _1 - Encoding flag (0=single byte, 1=wide char)
    - <len> - Base-32 encoded length
    - <hash> - 8-char uppercase hash
    - <literal> - The string with escape sequences
    - ?$AA@ - Null terminator marker

    Examples:
        ??_C@_0O@EPEJKEFM@nar_bam_trans?$AA@ -> "nar_bam_trans"
        ??_C@_07LEAMOHCB@App?4cpp?$AA@ -> "App.cpp"
        ??_C@_0BH@MPLIJIBA@?1vo_bank_rehearse?4milo?$AA@ -> "/vo_bank_rehearse.milo"
        ??_C@_0M@GKILHAJE@?$CK?$CKno?5file?$CK?$CK?$AA@ -> "**no file**"
        ??_C@_0BB@OEPBHON@Couldn?8t?5load?5?$CFs?$AA@ -> "Couldn't load %s"
        ??_C@_0L@JDNODHIG@mRefs?5?$DO?$DN?50?$AA@ -> "mRefs >= 0"

    Args:
        mangled: MSVC mangled string symbol name

    Returns:
        Decoded string literal, or None if not a string symbol
    """
    if not mangled.startswith("??_C@"):
        return None

    # MSVC string literal encoding has two formats:
    # 1. Single-digit length: ??_C@_<flag><digit><hash>@<literal>?$AA@
    #    Example: ??_C@_07LEAMOHCB@App?4cpp?$AA@
    # 2. Letter/multi-char length: ??_C@_<flag><len>@<hash>@<literal>?$AA@
    #    Example: ??_C@_0O@EPEJKEFM@nar_bam_trans?$AA@
    # Hash is typically 7-8 uppercase letters

    # Try single-digit length format first (no @ between length and hash)
    match = re.match(r"\?\?_C@_[01]([0-9])([A-Z]{7,8})@(.+)\?\$AA@$", mangled)
    if match:
        literal = match.group(3)
    else:
        # Try letter/multi-char length format (@ between length and hash)
        match = re.match(r"\?\?_C@_[01]([A-Z0-9]+)@([A-Z]{7,8})@(.+)\?\$AA@$", mangled)
        if not match:
            return None
        literal = match.group(3)

    # Decode MSVC escape sequences
    # Order matters - do multi-char escapes first
    multi_char_escapes = {
        "?$CK": "*",   # asterisk
        "?$CF": "%",   # percent
        "?$DO": ">",   # greater than
        "?$DM": "<",   # less than
        "?$DN": "=",   # equals
    }
    for esc, char in multi_char_escapes.items():
        literal = literal.replace(esc, char)

    # Single-char numeric escapes
    single_escapes = {
        "?1": "/",     # forward slash
        "?2": "\\",    # backslash
        "?3": ":",     # colon
        "?4": ".",     # period
        "?5": " ",     # space
        "?6": "\n",    # newline
        "?8": "'",     # apostrophe
    }
    for esc, char in single_escapes.items():
        literal = literal.replace(esc, char)

    return literal


@dataclass
class SymbolInfo:
    """Information about a symbol from map file or demangling."""
    mangled: str
    demangled: str
    class_name: Optional[str]
    method_name: str
    address: Optional[int]  # Absolute address (Rva+Base from map file)
    section: Optional[str]


def demangle_msvc(mangled: str) -> Optional[SymbolInfo]:
    """
    Demangle MSVC decorated name to extract class and method.

    MSVC mangling format:
    - ?MethodName@ClassName@@... for member functions
    - ??0ClassName@@... for constructors
    - ??1ClassName@@... for destructors
    - ??_GClassName@@... for scalar deleting destructor
    - ??_EClassName@@... for vector deleting destructor

    Args:
        mangled: MSVC mangled symbol name

    Returns:
        SymbolInfo with demangled components, or None if not MSVC format
    """
    if not mangled or not mangled.startswith("?"):
        return None

    # Handle special cases first
    # Constructor: ??0ClassName@@...
    if mangled.startswith("??0"):
        match = re.match(r"\?\?0(\w+)@@", mangled)
        if match:
            class_name = match.group(1)
            return SymbolInfo(
                mangled=mangled,
                demangled=f"{class_name}::{class_name}",
                class_name=class_name,
                method_name=class_name,
                address=None,
                section=None,
            )

    # Destructor: ??1ClassName@@...
    if mangled.startswith("??1"):
        match = re.match(r"\?\?1(\w+)@@", mangled)
        if match:
            class_name = match.group(1)
            return SymbolInfo(
                mangled=mangled,
                demangled=f"{class_name}::~{class_name}",
                class_name=class_name,
                method_name=f"~{class_name}",
                address=None,
                section=None,
            )

    # Scalar deleting destructor: ??_GClassName@@...
    if mangled.startswith("??_G"):
        match = re.match(r"\?\?_G(\w+)@@", mangled)
        if match:
            class_name = match.group(1)
            return SymbolInfo(
                mangled=mangled,
                demangled=f"{class_name}::`scalar deleting destructor'",
                class_name=class_name,
                method_name="`scalar deleting destructor'",
                address=None,
                section=None,
            )

    # Vector deleting destructor: ??_EClassName@@...
    if mangled.startswith("??_E"):
        match = re.match(r"\?\?_E(\w+)@@", mangled)
        if match:
            class_name = match.group(1)
            return SymbolInfo(
                mangled=mangled,
                demangled=f"{class_name}::`vector deleting destructor'",
                class_name=class_name,
                method_name="`vector deleting destructor'",
                address=None,
                section=None,
            )

    # Regular method: ?MethodName@ClassName@@... or ?MethodName@ClassName@Namespace@@...
    # Split by @ and parse
    parts = mangled[1:].split("@")
    if len(parts) >= 2:
        method_name = parts[0]
        class_name = parts[1]

        # Check for namespace (parts[2] would be namespace, parts[3] would be @@...)
        namespace = None
        if len(parts) >= 3 and parts[2] and not parts[2].startswith("@"):
            namespace = parts[2]

        if namespace:
            demangled = f"{namespace}::{class_name}::{method_name}"
        else:
            demangled = f"{class_name}::{method_name}"

        return SymbolInfo(
            mangled=mangled,
            demangled=demangled,
            class_name=class_name,
            method_name=method_name,
            address=None,
            section=None,
        )

    return None


def extract_method_name(mangled_or_demangled: str) -> str:
    """
    Extract just the method name from a mangled or demangled symbol.

    Examples:
        "?PoseMeshes@CharBonesMeshes@@QAAXXZ" -> "PoseMeshes"
        "CharBonesMeshes::PoseMeshes" -> "PoseMeshes"
        "PoseMeshes" -> "PoseMeshes"
    """
    # Try demangling first
    if mangled_or_demangled.startswith("?"):
        info = demangle_msvc(mangled_or_demangled)
        if info:
            return info.method_name

    # Check for C++ qualified name
    if "::" in mangled_or_demangled:
        return mangled_or_demangled.split("::")[-1]

    return mangled_or_demangled


def extract_class_name(mangled_or_demangled: str) -> Optional[str]:
    """
    Extract the class name from a mangled or demangled symbol.

    Examples:
        "?PoseMeshes@CharBonesMeshes@@QAAXXZ" -> "CharBonesMeshes"
        "CharBonesMeshes::PoseMeshes" -> "CharBonesMeshes"
    """
    if mangled_or_demangled.startswith("?"):
        info = demangle_msvc(mangled_or_demangled)
        if info:
            return info.class_name

    if "::" in mangled_or_demangled:
        parts = mangled_or_demangled.split("::")
        if len(parts) >= 2:
            return parts[-2]

    return None


class MapFileParser:
    """Parser for MSVC linker map files."""

    def __init__(self, map_path: Path):
        """
        Initialize map file parser.

        Args:
            map_path: Path to the .map file
        """
        self.map_path = Path(map_path)
        self._symbols: Dict[str, SymbolInfo] = {}
        self._address_to_symbol: Dict[int, str] = {}
        self._address_to_string: Dict[int, str] = {}
        self._address_to_symbols: Dict[int, List[str]] = {}
        self._parsed = False

    def parse(self) -> None:
        """Parse the map file and build symbol tables."""
        if self._parsed:
            return

        if not self.map_path.exists():
            logger.warning(f"Map file not found: {self.map_path}")
            return

        logger.info(f"Parsing map file: {self.map_path}")

        # Map file format (after "Publics by Value" header):
        # Address         Publics by Value              Rva+Base       Lib:Object
        # 0005:000186e0   ?PoseMeshes@CharBonesMeshes@@QAAXXZ 823486e0 f   char:CharBonesMeshes.obj

        in_publics = False
        symbol_pattern = re.compile(
            r"^\s*([0-9a-fA-F]{4}):([0-9a-fA-F]+)\s+(\S+)\s+([0-9a-fA-F]+)"
        )

        with open(self.map_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "Publics by Value" in line:
                    in_publics = True
                    continue

                if not in_publics:
                    continue

                match = symbol_pattern.match(line)
                if match:
                    section = match.group(1)
                    offset = match.group(2)
                    symbol = match.group(3)
                    rva_base = int(match.group(4), 16)

                    # Try to demangle
                    info = demangle_msvc(symbol)
                    if info:
                        info.address = rva_base
                        info.section = section
                    else:
                        # Non-MSVC symbol (C function, etc.)
                        info = SymbolInfo(
                            mangled=symbol,
                            demangled=symbol,
                            class_name=None,
                            method_name=symbol,
                            address=rva_base,
                            section=section,
                        )

                    self._symbols[symbol] = info
                    self._address_to_symbol[rva_base] = symbol

                    # Check if this is a string symbol
                    string_value = decode_msvc_string_literal(symbol)
                    if string_value is not None:
                        self._address_to_string[rva_base] = string_value

                    # Store in address->symbols list (for ICF-merged lookup)
                    if rva_base not in self._address_to_symbols:
                        self._address_to_symbols[rva_base] = []
                    self._address_to_symbols[rva_base].append(symbol)

        self._parsed = True
        logger.info(f"Parsed {len(self._symbols)} symbols from map file")

    def lookup_by_mangled(self, mangled: str) -> Optional[SymbolInfo]:
        """Look up symbol by mangled name."""
        self.parse()
        return self._symbols.get(mangled)

    def lookup_by_address(self, address: int) -> Optional[SymbolInfo]:
        """Look up symbol by address."""
        self.parse()
        mangled = self._address_to_symbol.get(address)
        if mangled:
            return self._symbols.get(mangled)
        return None

    def get_address(self, mangled: str) -> Optional[int]:
        """Get the address for a mangled symbol."""
        info = self.lookup_by_mangled(mangled)
        return info.address if info else None

    def search(self, query: str, limit: int = 10) -> List[SymbolInfo]:
        """
        Search for symbols matching a query.

        Searches both mangled and demangled names.
        """
        self.parse()
        results = []
        query_lower = query.lower()

        for mangled, info in self._symbols.items():
            if query_lower in mangled.lower() or query_lower in info.demangled.lower():
                results.append(info)
                if len(results) >= limit:
                    break

        return results

    def lookup_string_by_address(self, address: int) -> Optional[str]:
        """Look up decoded string literal by address.

        Args:
            address: Absolute address (Rva+Base from map file)

        Returns:
            Decoded string value, or None if not a string symbol
        """
        self.parse()
        return self._address_to_string.get(address)

    def lookup_all_symbols_by_address(self, address: int) -> List[SymbolInfo]:
        """Look up all symbols at an address (for ICF-merged functions).

        Multiple symbols can share the same address when the linker
        performs Identical COMDAT Folding (ICF).

        Args:
            address: Absolute address (Rva+Base from map file)

        Returns:
            List of SymbolInfo objects at this address
        """
        self.parse()
        mangled_names = self._address_to_symbols.get(address, [])
        return [self._symbols[m] for m in mangled_names if m in self._symbols]


class SymbolMatcher:
    """
    Multi-strategy symbol matcher for Ghidra function lookup.

    Supports:
    - Exact mangled name match
    - Demangled name match (Class::Method)
    - Method name only match
    - Address-based lookup
    """

    def __init__(self, map_file: Optional[Path] = None):
        """
        Initialize symbol matcher.

        Args:
            map_file: Optional path to map file for address lookups
        """
        self.map_parser: Optional[MapFileParser] = None
        if map_file and Path(map_file).exists():
            self.map_parser = MapFileParser(map_file)

    def get_search_variants(self, symbol: str) -> List[Tuple[str, str]]:
        """
        Generate search variants for a symbol.

        Returns list of (variant, match_type) tuples to try in order.
        """
        variants = []

        # 1. Exact match (as provided)
        variants.append((symbol, "exact"))

        # 2. Try demangling if MSVC format
        if symbol.startswith("?"):
            info = demangle_msvc(symbol)
            if info:
                # Full demangled name (Class::Method)
                variants.append((info.demangled, "demangled"))

                # Just method name
                variants.append((info.method_name, "method"))

                # Class::Method without namespace
                if info.class_name:
                    short_demangled = f"{info.class_name}::{info.method_name}"
                    if short_demangled != info.demangled:
                        variants.append((short_demangled, "short_demangled"))
        else:
            # Already demangled or plain name
            if "::" in symbol:
                # Extract method name
                method = symbol.split("::")[-1]
                variants.append((method, "method"))

        return variants

    def get_address(self, symbol: str) -> Optional[int]:
        """
        Get address for symbol from map file.

        Returns address in format Ghidra expects (e.g., 0x823486e0).
        """
        if not self.map_parser:
            return None

        info = self.map_parser.lookup_by_mangled(symbol)
        return info.address if info else None

    def format_address_for_ghidra(self, address: int) -> str:
        """Format address for Ghidra lookup (hex string with 0x prefix)."""
        return f"0x{address:08x}"


# Default map file location (None - must be configured per-project)
DEFAULT_MAP_FILE: Path | None = None


def get_default_matcher(map_file: Path | None = None) -> SymbolMatcher:
    """Get a SymbolMatcher, optionally with a map file for address lookups."""
    return SymbolMatcher(map_file or DEFAULT_MAP_FILE)

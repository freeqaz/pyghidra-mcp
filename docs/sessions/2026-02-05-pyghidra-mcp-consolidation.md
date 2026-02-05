# Session: PyGhidra-MCP Fork Consolidation

**Date:** 2026-02-05
**Branch:** `feature/decomp-features` (off `feature/xex-support`)
**Working Dir:** `/home/free/code/milohax/pyghidra-mcp`

## Objective

Consolidate features from the DC3 decomp fork (`/home/free/code/milohax/dc3-decomp/tools/pyghidra-mcp-fork/`) into the standalone pyghidra-mcp repository, preserving all upstream features while adding decomp-specific enhancements.

## Background

The DC3 decomp project maintains a fork of pyghidra-mcp with specialized features for decompilation work:
- Decompilation caching (SQLite-backed) to avoid repeated ~0.2s Ghidra queries
- Multi-strategy function lookup using linker map files for O(1) address resolution
- MSVC symbol demangling for C++ name matching
- XEX loader support for Xbox 360 binaries

These features need to be merged into the standalone repo without losing upstream functionality like call graph generation, code search, and string search.

## Changes Made

### New Files

| File | Description |
|------|-------------|
| `src/pyghidra_mcp/cache_manager.py` | SQLite-based decompilation cache with thread-safe operations, statistics, and management |
| `src/pyghidra_mcp/symbol_lookup.py` | Multi-strategy symbol lookup with MSVC demangling and map file parsing |

### Modified Files

#### `src/pyghidra_mcp/models.py` (+15 lines)
- Added `FunctionInfo` dataclass with `name` and `entry_point` fields
- Added `FunctionSearchResults` container for MCP tool responses

#### `src/pyghidra_mcp/server.py` (+388 lines)
- **Imports:** Added `CacheManager` import
- **MCP Tools:**
  - `get_cache_stats()` - Returns cache hit rate, entry count, and size
  - Updated `decompile_function()` to pass `cache_manager` to `GhidraTools`
- **Helper Functions:**
  - `_detect_binary_language()` - Detects XEX files and returns PowerPC:BE:64:Xenon language ID
  - `_install_xex_loader()` - Installs XEXLoaderWV extension from dist zip or jar
- **CLI Options:**
  - `--cache-dir` - Directory for cache.db storage
  - `--cache-disabled` - Disable caching for this run
  - `--cache-clear` - Clear cache and exit
  - `--cache-stats` - Print cache statistics and exit
- **Initialization:** Cache manager setup in `main()` before pyghidra context

#### `src/pyghidra_mcp/tools.py` (+375 lines)
- **Imports:** Added `SymbolMatcher`, `extract_method_name`, `extract_class_name`, `DEFAULT_MAP_FILE`
- **GhidraTools.__init__:**
  - New params: `cache_manager`, `map_file`
  - Initializes `SymbolMatcher` for multi-strategy lookups
  - Computes binary hash for cache key generation
- **find_function()** - Completely rewritten with 6-strategy lookup:
  1. Direct hex address parsing (e.g., "0x82E4E6B8")
  2. Map file address lookup (O(1) hash)
  3. Exact name match
  4. Demangled name match (Class::Method)
  5. Method name only match
  6. Partial/substring match
  - Creates functions at addresses if Ghidra didn't during analysis
- **find_function_address()** - New helper for cross-reference lookups
- **_decompile_function_impl()** - New internal method with caching:
  - Cache hit: Returns cached code immediately
  - Cache miss: Decompiles and stores result
- **list_cross_references()** - Updated to use multi-strategy lookup

## Key Design Decisions

### DEFAULT_MAP_FILE = None
The DC3 fork had a hardcoded path to the DC3 map file. Changed to `None` by default so the standalone repo doesn't have a broken reference. Projects can configure via `map_file` parameter.

### Preserved Upstream Features
The following upstream-only features were preserved:
- `search_code()` - Vector DB semantic code search
- `search_strings()` - String search with embeddings
- `gen_callgraph()` - Mermaid.js call graph generation
- `read_bytes()` - Raw memory reading
- `list_project_binary_metadata()` - Detailed binary metadata
- All existing CLI options (threaded analysis, GDT loading, etc.)

### Cache Integration
Cache is optional and disabled gracefully:
- If `cache_manager=None`, caching is skipped
- If binary has no `file_path`, hash computation is skipped
- Cache operations are thread-safe with `RLock`

## File Status

```
modified:   src/pyghidra_mcp/models.py
modified:   src/pyghidra_mcp/server.py
modified:   src/pyghidra_mcp/tools.py
untracked:  src/pyghidra_mcp/cache_manager.py
untracked:  src/pyghidra_mcp/symbol_lookup.py
```

## Validation

- All modified files pass Python syntax check (`py_compile`)
- All imports resolve correctly with local PYTHONPATH
- No breaking changes to existing MCP tool signatures

## Next Steps

1. **Commit changes** to `feature/decomp-features` branch
2. **Test with Ghidra** - Verify caching and multi-strategy lookup work
3. **Merge to main** - After validation, merge feature branches
4. **Update dc3-decomp** - Point to consolidated repo instead of fork

## References

- DC3 fork source: `/home/free/code/milohax/dc3-decomp/tools/pyghidra-mcp-fork/`
- Upstream repo: `/home/free/code/milohax/pyghidra-mcp/`
- XEXLoaderWV: `/home/free/code/milohax/XEXLoaderWV/`

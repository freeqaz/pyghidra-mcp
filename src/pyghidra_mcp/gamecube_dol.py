"""GameCube/Wii DOL support for pyghidra-mcp.

Ghidra ships **no loader** for the Nintendo GameCube/Wii ``.dol`` executable
format, and a DOL carries **no symbols** — just raw code/data segments and their
load addresses. So a DOL on its own decompiles as an anonymous blob.

This module bridges that gap by transcoding a DOL (plus an optional CodeWarrior
linker ``.map``) into a synthetic **big-endian PowerPC ELF** that Ghidra loads
natively:

* Each DOL segment becomes an ELF section at its real load address, so Ghidra's
  ELF loader maps memory correctly (no manual block creation).
* The ELF is ``EM_PPC`` / 32-bit / big-endian with the DOL entry point, which is
  exactly what ``PyGhidraContext.detect_language_for_binary`` keys on to select
  ``PowerPC:BE:32:Gekko_Broadway`` (paired-single capable) automatically.
* Every CodeWarrior map symbol becomes an ELF ``.symtab`` entry with its address
  **and size**, typed ``STT_FUNC`` when it lands in an executable segment, so
  Ghidra auto-creates functions with exact boundaries — the decompiler then
  scopes each function correctly instead of guessing extents.

The transcode is deterministic and self-contained (stdlib ``struct`` only), so it
runs without Ghidra and is unit-testable. The fork's import path calls
:func:`ensure_elf_for_dol` to convert transparently when a ``.dol`` is imported.

Why this matters for matching decomp work: the *target* binary (e.g. RB3's Bank 8
``main.dol``) usually has no DWARF build, while the only DWARF ELF available is a
*different-era* prototype. Decompiling the DWARF ELF describes the wrong function
body. Feeding Ghidra the real target DOL via this converter gives target-accurate
pseudo-C (names from the map, no types) that complements the DWARF view.
"""

from __future__ import annotations

import hashlib
import logging
import re
import struct
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

DOL_MAGIC_HINT = "the file begins with a GameCube/Wii DOL header"

# --- DOL header layout (all fields big-endian u32) ---------------------------
# 7 text segments, then 11 data segments, then bss addr/size, then entry point.
_DOL_TEXT_COUNT = 7
_DOL_DATA_COUNT = 11
_DOL_HEADER_SIZE = 0x100
_OFF_TEXT_FILEOFF = 0x00
_OFF_DATA_FILEOFF = 0x1C
_OFF_TEXT_ADDR = 0x48
_OFF_DATA_ADDR = 0x64
_OFF_TEXT_SIZE = 0x90
_OFF_DATA_SIZE = 0xAC
_OFF_BSS_ADDR = 0xD8
_OFF_BSS_SIZE = 0xDC
_OFF_ENTRY = 0xE0

# Wii/GameCube MEM1 + MEM2 address windows; a DOL loads here.
_MEM_LO = 0x80000000
_MEM_HI = 0x94000000


@dataclass
class DolSegment:
    name: str
    addr: int
    size: int
    file_off: int  # 0 for .bss-style (no file data)
    executable: bool

    @property
    def has_data(self) -> bool:
        return self.file_off != 0 and self.size != 0


@dataclass
class Symbol:
    name: str
    addr: int
    size: int
    is_func: bool


def is_dol_file(path: Path) -> bool:
    """Heuristic DOL sniff: a sane header with at least one segment in MEM1/2.

    DOLs have no magic number, so validate structurally: the entry point and the
    first present text segment must land in the console's RAM window, and the
    declared file extents must fit the file.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(_DOL_HEADER_SIZE)
        if len(head) < _DOL_HEADER_SIZE:
            return False
        entry = struct.unpack_from(">I", head, _OFF_ENTRY)[0]
        if not (_MEM_LO <= entry < _MEM_HI):
            return False
        size = path.stat().st_size
        seen = False
        for i in range(_DOL_TEXT_COUNT + _DOL_DATA_COUNT):
            base = _OFF_TEXT_FILEOFF + i * 4
            foff = struct.unpack_from(">I", head, base)[0]
            saddr = struct.unpack_from(">I", head, _OFF_TEXT_ADDR + i * 4)[0]
            ssize = struct.unpack_from(">I", head, _OFF_TEXT_SIZE + i * 4)[0]
            if ssize == 0:
                continue
            if foff + ssize > size:
                return False
            if not (_MEM_LO <= saddr < _MEM_HI):
                return False
            seen = True
        return seen
    except OSError:
        return False


def parse_dol(data: bytes) -> tuple[list[DolSegment], int]:
    """Return (segments, entry_point) from raw DOL bytes."""
    segments: list[DolSegment] = []
    tcount = 0
    for i in range(_DOL_TEXT_COUNT):
        foff = struct.unpack_from(">I", data, _OFF_TEXT_FILEOFF + i * 4)[0]
        addr = struct.unpack_from(">I", data, _OFF_TEXT_ADDR + i * 4)[0]
        size = struct.unpack_from(">I", data, _OFF_TEXT_SIZE + i * 4)[0]
        if size:
            segments.append(DolSegment(f".text{tcount}", addr, size, foff, True))
            tcount += 1
    dcount = 0
    for i in range(_DOL_DATA_COUNT):
        foff = struct.unpack_from(">I", data, _OFF_DATA_FILEOFF + i * 4)[0]
        addr = struct.unpack_from(">I", data, _OFF_DATA_ADDR + i * 4)[0]
        size = struct.unpack_from(">I", data, _OFF_DATA_SIZE + i * 4)[0]
        if size:
            segments.append(DolSegment(f".data{dcount}", addr, size, foff, False))
            dcount += 1
    bss_addr = struct.unpack_from(">I", data, _OFF_BSS_ADDR)[0]
    bss_size = struct.unpack_from(">I", data, _OFF_BSS_SIZE)[0]
    if bss_size:
        # The DOL .bss spans .sbss/.bss; declare it but mark file_off=0 (NOBITS).
        # It may overlap data segments' addresses in the union; Ghidra tolerates
        # a NOBITS block, and real data segments take precedence for symbol shndx.
        segments.append(DolSegment(".bss", bss_addr, bss_size, 0, False))
    entry = struct.unpack_from(">I", data, _OFF_ENTRY)[0]
    segments.sort(key=lambda s: s.addr)
    return segments, entry


# CodeWarrior map symbol line:
#   "  OFF SIZE ADDR FILEOFF ALIGN SYMBOL \t lib path"
_MAP_LINE = re.compile(
    r"^  ([0-9a-fA-F]{8}) ([0-9a-fA-F]{6}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})\s+(\d+) (\S.*?) \t"
)


def parse_cw_map(text: str, exec_ranges: list[tuple[int, int]]) -> list[Symbol]:
    """Parse a CodeWarrior linker map into address+size+kind symbols.

    ``exec_ranges`` is the list of (lo, hi) executable address windows; a symbol
    in one of them is typed as a function.
    """
    def in_exec(addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in exec_ranges)

    syms: list[Symbol] = []
    for line in text.splitlines():
        m = _MAP_LINE.match(line)
        if not m:
            continue
        size = int(m.group(2), 16)
        addr = int(m.group(3), 16)
        name = m.group(6)
        if name.startswith("."):  # section header pseudo-entry
            continue
        if not (_MEM_LO <= addr < _MEM_HI):
            continue
        syms.append(Symbol(name, addr, size, in_exec(addr)))
    return syms


# --- ELF emission (Elf32, big-endian) ----------------------------------------
_EI = bytes([0x7F, 0x45, 0x4C, 0x46, 1, 2, 1, 0]) + b"\x00" * 8  # ELFCLASS32, MSB
_ET_EXEC = 2
_EM_PPC = 20
_SHT_NULL, _SHT_PROGBITS, _SHT_SYMTAB, _SHT_STRTAB, _SHT_NOBITS = 0, 1, 2, 3, 8
_SHF_WRITE, _SHF_ALLOC, _SHF_EXEC = 1, 2, 4
_STB_GLOBAL = 1
_STT_FUNC, _STT_OBJECT = 2, 1
_SHN_ABS = 0xFFF1


def _align(n: int, a: int = 4) -> int:
    return (n + a - 1) & ~(a - 1)


class _StrTab:
    def __init__(self) -> None:
        self._buf = bytearray(b"\x00")
        self._idx: dict[str, int] = {"": 0}

    def add(self, s: str) -> int:
        if s in self._idx:
            return self._idx[s]
        off = len(self._buf)
        self._buf += s.encode("utf-8", "replace") + b"\x00"
        self._idx[s] = off
        return off

    def bytes(self) -> bytes:
        return bytes(self._buf)


def build_elf(segments: list[DolSegment], entry: int, symbols: list[Symbol], dol_data: bytes) -> bytes:
    """Assemble a big-endian PPC ELF (ET_EXEC) with sections + symtab."""
    # Section order: NULL, [each segment], .symtab, .strtab, .shstrtab
    shstr = _StrTab()
    sym_sections = [s for s in segments]

    # Resolve which section index contains an address (for st_shndx). Data
    # segments take precedence over the overlapping NOBITS .bss union.
    def shndx_for(addr: int) -> int:
        candidates = [
            i for i, seg in enumerate(sym_sections, start=1)
            if seg.addr <= addr < seg.addr + seg.size
        ]
        if not candidates:
            return _SHN_ABS
        # Prefer a real data section over the overlapping NOBITS .bss union.
        for i in candidates:
            if sym_sections[i - 1].has_data:
                return i
        return candidates[0]

    # Build .strtab + .symtab. Index 0 is the reserved null symbol.
    strtab = _StrTab()
    sym_bytes = bytearray(struct.pack(">IIIBBH", 0, 0, 0, 0, 0, 0))
    # Sort symbols by address for stable, readable output.
    for s in sorted(symbols, key=lambda x: x.addr):
        shndx = shndx_for(s.addr)
        if shndx == _SHN_ABS:
            continue  # unmapped — skip rather than litter Ghidra with stray labels
        st_name = strtab.add(s.name)
        st_info = (_STB_GLOBAL << 4) | (_STT_FUNC if s.is_func else _STT_OBJECT)
        sym_bytes += struct.pack(">IIIBBH", st_name, s.addr, s.size, st_info, 0, shndx)

    # --- Lay out the file: header, segment blobs, symtab, strtab, shstrtab,
    #     then the section header table. ---
    ehsize = 52
    shentsize = 40
    cursor = ehsize
    seg_file_off: list[int] = []
    blob = bytearray()
    for seg in sym_sections:
        if seg.has_data:
            cursor = _align(cursor)
            seg_file_off.append(cursor)
            chunk = dol_data[seg.file_off : seg.file_off + seg.size]
            blob += b"\x00" * (cursor - (ehsize + len(blob)))  # pad
            blob += chunk
            cursor = ehsize + len(blob)
        else:
            seg_file_off.append(0)  # NOBITS

    cursor = _align(ehsize + len(blob))
    blob += b"\x00" * (cursor - (ehsize + len(blob)))
    symtab_off = cursor
    blob += sym_bytes
    cursor = ehsize + len(blob)

    strtab_bytes = strtab.bytes()
    strtab_off = cursor
    blob += strtab_bytes
    cursor = ehsize + len(blob)

    # Section names go in shstrtab; reserve indices now.
    name_off = {".symtab": shstr.add(".symtab"), ".strtab": shstr.add(".strtab")}
    for seg in sym_sections:
        name_off[seg.name] = shstr.add(seg.name)
    name_off[".shstrtab"] = shstr.add(".shstrtab")
    shstr_bytes = shstr.bytes()
    shstr_off = cursor
    blob += shstr_bytes
    cursor = ehsize + len(blob)

    sh_off = _align(cursor)
    blob += b"\x00" * (sh_off - (ehsize + len(blob)))

    # --- Section headers ---
    shdrs = [struct.pack(">10I", 0, _SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)]
    for i, seg in enumerate(sym_sections):
        flags = _SHF_ALLOC | (_SHF_EXEC if seg.executable else _SHF_WRITE)
        if seg.has_data:
            sh = struct.pack(
                ">10I", name_off[seg.name], _SHT_PROGBITS, flags, seg.addr,
                seg_file_off[i], seg.size, 0, 0, 4, 0,
            )
        else:
            sh = struct.pack(
                ">10I", name_off[seg.name], _SHT_NOBITS, flags, seg.addr,
                0, seg.size, 0, 0, 4, 0,
            )
        shdrs.append(sh)
    nseg = len(sym_sections)
    symtab_idx = 1 + nseg
    strtab_idx = symtab_idx + 1
    shstrtab_idx = strtab_idx + 1
    nsym = len(sym_bytes) // 16
    # .symtab: sh_link -> .strtab, sh_info -> first global (1, only null is local)
    shdrs.append(struct.pack(
        ">10I", name_off[".symtab"], _SHT_SYMTAB, 0, 0,
        symtab_off, len(sym_bytes), strtab_idx, 1, 4, 16,
    ))
    shdrs.append(struct.pack(
        ">10I", name_off[".strtab"], _SHT_STRTAB, 0, 0,
        strtab_off, len(strtab_bytes), 0, 0, 1, 0,
    ))
    shdrs.append(struct.pack(
        ">10I", name_off[".shstrtab"], _SHT_STRTAB, 0, 0,
        shstr_off, len(shstr_bytes), 0, 0, 1, 0,
    ))
    shnum = len(shdrs)

    ehdr = struct.pack(
        ">16sHHIIIIIHHHHHH",
        _EI, _ET_EXEC, _EM_PPC, 1, entry,
        0,            # e_phoff (no program headers; section-based load)
        sh_off,       # e_shoff
        0,            # e_flags
        ehsize, 0, 0, # e_ehsize, e_phentsize, e_phnum
        shentsize, shnum, shstrtab_idx,
    )
    out = bytearray(ehdr)
    out += blob
    for sh in shdrs:
        out += sh
    logger.debug("built ELF: %d sections, %d symbols, %d bytes", shnum, nsym - 1, len(out))
    return bytes(out)


def convert(dol_path: Path, map_path: Path | None, out_path: Path) -> dict:
    """Convert ``dol_path`` (+ optional CW ``map_path``) to a symbolized ELF.

    Returns a small summary dict for logging/tests.
    """
    dol_data = Path(dol_path).read_bytes()
    segments, entry = parse_dol(dol_data)
    exec_ranges = [(s.addr, s.addr + s.size) for s in segments if s.executable]
    symbols: list[Symbol] = []
    if map_path and Path(map_path).exists():
        symbols = parse_cw_map(Path(map_path).read_text(errors="replace"), exec_ranges)
    elf = build_elf(segments, entry, symbols, dol_data)
    Path(out_path).write_bytes(elf)
    nfunc = sum(1 for s in symbols if s.is_func)
    return {
        "entry": entry,
        "segments": len(segments),
        "symbols": len(symbols),
        "functions": nfunc,
        "out": str(out_path),
        "bytes": len(elf),
    }


def ensure_elf_for_dol(dol_path: Path, map_path: Path | None = None, cache_dir: Path | None = None) -> Path:
    """Return a cached symbolized ELF for ``dol_path``, building it if stale.

    The cache key folds in the DOL + map mtimes/sizes, so editing the map (or
    swapping the DOL) rebuilds. Called from the import path so importing a
    ``.dol`` transparently yields a Ghidra-loadable ELF.
    """
    dol_path = Path(dol_path)
    if map_path is None:
        map_path = _discover_map(dol_path)
    if cache_dir:
        cache_dir = Path(cache_dir)
    else:
        # Default to a temp cache so we never write into a pristine orig/ tree.
        # Override with PYGHIDRA_DOL_CACHE or the cache_dir arg (the RB3 launcher
        # points this at build/SZBE69_B8/ghidra/, which is gitignored).
        import os
        import tempfile

        env = os.environ.get("PYGHIDRA_DOL_CACHE")
        cache_dir = Path(env) if env else Path(tempfile.gettempdir()) / "pyghidra_dol_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    sig = hashlib.sha1()
    for p in (dol_path, map_path):
        if p and Path(p).exists():
            st = Path(p).stat()
            sig.update(f"{p}:{st.st_mtime_ns}:{st.st_size}".encode())
    key = sig.hexdigest()[:16]
    # Key lives in the directory name so the ELF keeps a clean basename — the
    # Ghidra program is then named after the DOL (e.g. "main.elf"), not a hash.
    out = cache_dir / key / f"{dol_path.stem}.elf"
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        logger.info("reusing cached DOL->ELF: %s", out)
        return out
    info = convert(dol_path, map_path, out)
    logger.info(
        "converted DOL->ELF %s: entry=0x%08x, %d segments, %d symbols (%d funcs) from map=%s",
        out, info["entry"], info["segments"], info["symbols"], info["functions"], map_path,
    )
    return out


def _discover_map(dol_path: Path) -> Path | None:
    """Find a CodeWarrior .map for a DOL: env override, sibling, or files/ dir.

    RB3 layout is orig/SZBE69_B8/sys/main.dol + orig/SZBE69_B8/files/band_r_wii.map.
    """
    import os

    env = os.environ.get("PYGHIDRA_DOL_MAP")
    if env and Path(env).exists():
        return Path(env)
    parent = dol_path.parent
    candidates = [
        *parent.glob("*.map"),
        *(parent.parent / "files").glob("*.map"),
        *parent.parent.glob("*.map"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Convert a GameCube/Wii DOL (+ CodeWarrior map) to a symbolized PPC ELF for Ghidra.")
    ap.add_argument("dol", type=Path, help="input .dol")
    ap.add_argument("-m", "--map", type=Path, default=None, help="CodeWarrior .map (auto-discovered if omitted)")
    ap.add_argument("-o", "--out", type=Path, default=None, help="output .elf (default: <dol>.elf)")
    args = ap.parse_args(argv)
    map_path = args.map or _discover_map(args.dol)
    out = args.out or args.dol.with_suffix(".elf")
    info = convert(args.dol, map_path, out)
    print(
        f"wrote {info['out']}  entry=0x{info['entry']:08x}  "
        f"segments={info['segments']}  symbols={info['symbols']} (functions={info['functions']})  "
        f"map={map_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

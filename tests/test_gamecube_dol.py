"""Unit tests for the GameCube/Wii DOL -> symbolized ELF converter.

No Ghidra required: builds a tiny synthetic DOL + CodeWarrior map, converts, and
re-reads the ELF with an independent reader (pyelftools) to assert structure,
addresses, sizes, and function/object typing.
"""
import io
import struct

import pytest

from pyghidra_mcp.gamecube_dol import (
    build_elf,
    convert,
    is_dol_file,
    parse_cw_map,
    parse_dol,
)

elffile = pytest.importorskip("elftools.elf.elffile")

# Synthetic addresses in the Wii MEM1 window.
TEXT_ADDR = 0x80004000
DATA_ADDR = 0x80100000
BSS_ADDR = 0x80200000
ENTRY = 0x80004010


def _make_dol(text: bytes, data: bytes, bss_size: int) -> bytes:
    """Assemble a minimal valid DOL: one text seg, one data seg, a bss, an entry."""
    header = bytearray(0x100)
    text_off = 0x100
    data_off = text_off + len(text)
    # text section 0
    struct.pack_into(">I", header, 0x00, text_off)        # text[0] file off
    struct.pack_into(">I", header, 0x48, TEXT_ADDR)       # text[0] addr
    struct.pack_into(">I", header, 0x90, len(text))       # text[0] size
    # data section 0 (slot at +0x1C / +0x64 / +0xAC)
    struct.pack_into(">I", header, 0x1C, data_off)        # data[0] file off
    struct.pack_into(">I", header, 0x64, DATA_ADDR)       # data[0] addr
    struct.pack_into(">I", header, 0xAC, len(data))       # data[0] size
    struct.pack_into(">I", header, 0xD8, BSS_ADDR)        # bss addr
    struct.pack_into(">I", header, 0xDC, bss_size)        # bss size
    struct.pack_into(">I", header, 0xE0, ENTRY)           # entry
    return bytes(header) + text + data


def _make_map() -> str:
    # CodeWarrior map symbol lines: "  OFF SIZE ADDR FILEOFF ALIGN SYMBOL \t lib path"
    def line(addr, size, name):
        return f"  00000000 {size:06x} {addr:08x} 00000000  4 {name} \tlib.a x.o"

    return "\n".join([
        ".text section layout",
        line(TEXT_ADDR, 0x20, "Foo__3BarFv"),         # function (in text)
        line(TEXT_ADDR + 0x20, 0x10, "Baz__3BarFi"),   # function (in text)
        line(DATA_ADDR, 0x4, "gCounter"),              # object (in data)
        line(BSS_ADDR + 0x8, 0x4, "gState"),           # object (in bss)
        "  .text \tlib.a x.o",                          # section pseudo-entry (skip)
    ]) + "\n"


def test_is_dol_file(tmp_path):
    dol = _make_dol(b"\x00" * 0x40, b"\x11" * 0x10, 0x100)
    p = tmp_path / "main.dol"
    p.write_bytes(dol)
    assert is_dol_file(p)

    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not a dol" * 100)
    assert not is_dol_file(junk)


def test_parse_dol():
    text = b"\xde\xad\xbe\xef" * 0x10
    data = b"\x11\x22\x33\x44" * 0x4
    segs, entry = parse_dol(_make_dol(text, data, 0x100))
    assert entry == ENTRY
    by_addr = {s.addr: s for s in segs}
    assert by_addr[TEXT_ADDR].executable and by_addr[TEXT_ADDR].has_data
    assert not by_addr[DATA_ADDR].executable and by_addr[DATA_ADDR].has_data
    assert by_addr[BSS_ADDR].size == 0x100 and not by_addr[BSS_ADDR].has_data


def test_parse_cw_map_typing():
    exec_ranges = [(TEXT_ADDR, TEXT_ADDR + 0x100)]
    syms = parse_cw_map(_make_map(), exec_ranges)
    by_name = {s.name: s for s in syms}
    assert ".text" not in by_name  # section pseudo-entry skipped
    assert by_name["Foo__3BarFv"].is_func
    assert by_name["Baz__3BarFi"].is_func
    assert not by_name["gCounter"].is_func   # data
    assert not by_name["gState"].is_func     # bss
    assert by_name["Foo__3BarFv"].size == 0x20


def test_convert_roundtrip(tmp_path):
    text = b"\x94\x21\xff\xf0" + b"\x00" * 0x3C   # a plausible prologue + filler
    data = b"\xaa\xbb\xcc\xdd"
    dol = tmp_path / "main.dol"
    dol.write_bytes(_make_dol(text, data, 0x100))
    mp = tmp_path / "band.map"
    mp.write_text(_make_map())
    out = tmp_path / "out.elf"
    info = convert(dol, mp, out)

    assert info["functions"] == 2
    e = elffile.ELFFile(io.BytesIO(out.read_bytes()))
    assert e.elfclass == 32
    assert e["e_ident"]["EI_DATA"] == "ELFDATA2MSB"
    assert e["e_machine"] == "EM_PPC"
    assert e["e_entry"] == ENTRY

    st = e.get_section_by_name(".symtab")
    foo = st.get_symbol_by_name("Foo__3BarFv")[0]
    assert foo.entry.st_value == TEXT_ADDR
    assert foo.entry.st_size == 0x20
    assert foo.entry.st_info.type == "STT_FUNC"

    gc = st.get_symbol_by_name("gCounter")[0]
    assert gc.entry.st_value == DATA_ADDR
    assert gc.entry.st_info.type == "STT_OBJECT"

    # The text bytes must survive verbatim at the right virtual address.
    for s in e.iter_sections():
        h = s.header
        if h.sh_addr == TEXT_ADDR:
            assert s.data()[:4] == b"\x94\x21\xff\xf0"
            break
    else:
        pytest.fail("text section not found at TEXT_ADDR")


def test_convert_without_map(tmp_path):
    # No map -> still a valid ELF, just no symbols (Ghidra can still disassemble).
    dol = tmp_path / "main.dol"
    dol.write_bytes(_make_dol(b"\x00" * 0x20, b"\x00" * 0x10, 0x40))
    out = tmp_path / "out.elf"
    info = convert(dol, None, out)
    assert info["symbols"] == 0
    e = elffile.ELFFile(io.BytesIO(out.read_bytes()))
    assert e["e_machine"] == "EM_PPC"

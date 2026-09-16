"""Standalone header-sniffing tests for Xbox 360 PPC-PE language detection.

No live Ghidra required: ``PyGhidraContext.detect_language_for_binary`` and
``_xbox360_pe_image_base`` are pure static header sniffers (all ``ghidra.*``
imports in context.py are lazy, inside methods), so importing the module and
calling these staticmethods works without a JVM.

Regression guard for the bug where Xbox 360 basefile PEs — PE32 images with COFF
machine 0x01F2 (IMAGE_FILE_MACHINE_POWERPCBE) — were imported as MS-DOS x86
16-bit real-mode garbage (0 functions) because detection only knew XEX2 magic and
BE-PPC ELF. They must now resolve to PowerPC:BE:64:Xenon, while x86 inputs must NOT.
"""
import struct

import pytest

from pyghidra_mcp.context import PyGhidraContext

XENON = "PowerPC:BE:64:Xenon"

# The two real Xbox 360 basefile PEs (machine 0x01F2). Skipped if absent so the
# suite still runs on machines without the reference corpus.
BAND_CLEAN_TU5 = "/home/free/code/milohax/rb3-xenon/_tu5probe/clean/band_clean_tu5.exe"
RB3EL_PE = "/home/free/code/milohax/xex-patcher/reference/rb3el.pe"


def _make_ppc_pe(image_base: int, e_lfanew: int = 0x80) -> bytes:
    """Build a minimal PE32 with COFF machine 0x01F2 and a given ImageBase."""
    buf = bytearray(e_lfanew + 0x40)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)  # e_lfanew
    buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"  # PE signature
    struct.pack_into("<H", buf, e_lfanew + 4, 0x01F2)  # COFF machine = POWERPCBE
    # PE32 optional header at e_lfanew+0x18, magic 0x010b, ImageBase at +0x1c.
    struct.pack_into("<H", buf, e_lfanew + 0x18, 0x010B)
    struct.pack_into("<I", buf, e_lfanew + 0x18 + 0x1C, image_base)
    return bytes(buf)


def _make_ppc_pe_with_text(
    image_base: int, text_rva: int, text_ptr_raw: int, e_lfanew: int = 0x80
) -> bytes:
    """PE32 machine 0x01F2 with a real COFF section table containing a .text.

    Lays down one section header (40 bytes) named ".text" with the given RVA and
    PointerToRawData so _xbox360_pe_image_base parses a nonzero file/RVA delta.
    """
    size_opt_hdr = 0xE0  # PE32 optional header size (matches real basefiles)
    sect_start = e_lfanew + 0x18 + size_opt_hdr
    buf = bytearray(sect_start + 40)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into("<H", buf, e_lfanew + 4, 0x01F2)  # machine
    struct.pack_into("<H", buf, e_lfanew + 6, 1)  # NumberOfSections
    struct.pack_into("<H", buf, e_lfanew + 0x14, size_opt_hdr)  # SizeOfOptionalHeader
    struct.pack_into("<H", buf, e_lfanew + 0x18, 0x010B)  # opt magic PE32
    struct.pack_into("<I", buf, e_lfanew + 0x18 + 0x1C, image_base)  # ImageBase
    # Section header @ sect_start: Name[8], VirtualSize@8, RVA@12, RawSize@16, PtrRaw@20
    buf[sect_start : sect_start + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", buf, sect_start + 12, text_rva)
    struct.pack_into("<I", buf, sect_start + 20, text_ptr_raw)
    return bytes(buf)


def _make_x86_pe(machine: int = 0x8664) -> bytes:
    """Build a minimal PE with an x86 COFF machine (amd64 0x8664 by default)."""
    e_lfanew = 0x80
    buf = bytearray(e_lfanew + 0x40)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into("<H", buf, e_lfanew + 4, machine)
    return bytes(buf)


# --- synthetic-fixture tests (always run) ----------------------------------


def test_synthetic_ppc_pe_detects_xenon(tmp_path):
    p = tmp_path / "basefile.exe"
    p.write_bytes(_make_ppc_pe(0x82000000))
    assert PyGhidraContext.detect_language_for_binary(p) == XENON
    ppc_pe, base = PyGhidraContext._xbox360_pe_image_base(p)
    assert ppc_pe is True
    assert base == 0x82000000


def test_synthetic_x86_pe_not_xenon(tmp_path):
    for machine in (0x8664, 0x014C):  # amd64, i386
        p = tmp_path / f"x86_{machine}.exe"
        p.write_bytes(_make_x86_pe(machine))
        assert PyGhidraContext.detect_language_for_binary(p) != XENON
        assert PyGhidraContext._xbox360_pe_image_base(p) == (False, None)


def test_non_pe_inputs_not_xenon(tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"\x00\x01\x02\x03not a pe at all" * 8)
    assert PyGhidraContext.detect_language_for_binary(junk) != XENON


# --- real-file tests (skipped if the corpus is not present) -----------------


@pytest.mark.parametrize("path", [BAND_CLEAN_TU5, RB3EL_PE])
def test_real_xbox360_pe_detects_xenon(path):
    import os
    from pathlib import Path

    if not os.path.exists(path):
        pytest.skip(f"reference file not present: {path}")
    assert PyGhidraContext.detect_language_for_binary(Path(path)) == XENON


def test_real_band_clean_tu5_auto_base_is_text_aligned():
    """Auto-base must be .text-aligned, not raw ImageBase.

    band_clean_tu5.exe is NOT a flat image: .text (RVA 0x270000) sits at file
    offset 0x264e00 (delta 0xb200). The correct flat base for code is therefore
    ImageBase(0x82000000) + 0xb200 = 0x8200b200 — verified against real function
    prologues. Raw ImageBase would put every function 0xb200 off. Pure header
    math; no live Ghidra.
    """
    import os
    from pathlib import Path

    if not os.path.exists(BAND_CLEAN_TU5):
        pytest.skip(f"reference file not present: {BAND_CLEAN_TU5}")
    ppc_pe, base = PyGhidraContext._xbox360_pe_image_base(Path(BAND_CLEAN_TU5))
    assert ppc_pe is True
    assert base == 0x8200B200


def test_synthetic_text_delta_shifts_auto_base(tmp_path):
    """A .text section with a nonzero file/RVA delta shifts the auto-base."""
    p = tmp_path / "delta.exe"
    p.write_bytes(_make_ppc_pe_with_text(image_base=0x82000000, text_rva=0x270000,
                                          text_ptr_raw=0x264E00))
    ppc_pe, base = PyGhidraContext._xbox360_pe_image_base(p)
    assert ppc_pe is True
    assert base == 0x8200B200


def test_x86_system_binary_not_xenon():
    import os
    from pathlib import Path

    for cand in ("/bin/ls", "/usr/bin/ls", "/bin/cat"):
        if os.path.exists(cand):
            assert PyGhidraContext.detect_language_for_binary(Path(cand)) != XENON
            return
    pytest.skip("no known /bin ELF available")

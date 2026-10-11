"""ELF header policy, without a JVM. Real import checks live in the CMP receipt."""
import struct
import pytest
from pyghidra_mcp.context import PyGhidraContext


def elf(bits, order, kind=3, vaddr=0):
    header=bytearray(64)
    header[:6]=b'\x7fELF'+bytes([2 if bits==64 else 1,1 if order=='<' else 2])
    struct.pack_into(order+'H',header,16,kind)
    struct.pack_into(order+('Q' if bits==64 else 'I'),header,32 if bits==64 else 28,64)
    size=56 if bits==64 else 32
    struct.pack_into(order+'HH',header,54 if bits==64 else 42,size,1)
    ph=bytearray(size)
    struct.pack_into(order+'I',ph,0,1)
    struct.pack_into(order+('Q' if bits==64 else 'I'),ph,16 if bits==64 else 8,vaddr)
    return bytes(header+ph)


@pytest.mark.parametrize('bits',[32,64])
@pytest.mark.parametrize('order',['<','>'])
@pytest.mark.parametrize('kind',[2,3])
def test_zero_base_elf(tmp_path,bits,order,kind):
    p=tmp_path/'image';p.write_bytes(elf(bits,order,kind))
    assert PyGhidraContext._is_zero_based_elf(p)


@pytest.mark.parametrize('data',[
    elf(32,'<',vaddr=0x8000), elf(64,'>',vaddr=0x400000),
    elf(32,'<',kind=1), b'raw binary', b'MZ'+bytes(64),
    elf(32,'<')[:70], elf(64,'>')[:52],
])
def test_preserve_other_inputs(tmp_path,data):
    p=tmp_path/'image';p.write_bytes(data)
    assert not PyGhidraContext._is_zero_based_elf(p)


def test_missing_file(tmp_path):
    assert not PyGhidraContext._is_zero_based_elf(tmp_path/'missing')

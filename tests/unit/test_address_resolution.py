"""Address resolution policy for read queries (decompile, xrefs, read_bytes).

Falcon programs map two memory spaces (imem, dmem). Ghidra's AddressFactory
silently resolves a bare offset in the default space, so "00001558" used to mean
imem:00001558 even when the caller meant dmem. These fakes reproduce that
factory behavior so the policy is tested without a JVM:

- bare hex is refused in multi-space programs, naming the qualified forms;
- a space-qualified address inside a function resolves to the containing function;
- single-space programs keep resolving bare hex as before;
- no lookup ever runs CreateFunctionCmd.
"""

# The fakes keep Ghidra's camelCase method names (getAddress, getReferencesTo).
# ruff: noqa: N802

import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pyghidra_mcp.tools import AmbiguousAddressError, GhidraTools


class FakeSpace:
    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name

    def getPhysicalSpace(self):
        return self

    def getAddress(self, offset):
        return FakeAddr(self, offset)


class FakeAddr:
    def __init__(self, space, offset):
        self.space = space
        self.offset = offset

    def getAddressSpace(self):
        return self.space

    def __eq__(self, other):
        return (
            isinstance(other, FakeAddr)
            and self.space.name == other.space.name
            and self.offset == other.offset
        )

    def __hash__(self):
        return hash((self.space.name, self.offset))

    def __str__(self):
        return f"{self.space.name}:{self.offset:08x}"


class FakeAddressFactory:
    """Mimics DefaultAddressFactory.getAddress: bare text -> default space."""

    def __init__(self, spaces):
        self.spaces = {s.name: s for s in spaces}
        self.default = spaces[0]

    def getDefaultAddressSpace(self):
        return self.default

    def getAddress(self, text):
        if ":" in text:
            name, _, off = text.partition(":")
            space = self.spaces.get(name)
            if space is None:
                return None
            try:
                return space.getAddress(int(off, 16))
            except ValueError:
                return None
        try:
            return self.default.getAddress(int(text, 16))
        except ValueError:
            return None


class FakeBlock:
    def __init__(self, space, loaded=True):
        self.space = space
        self.loaded = loaded

    def isLoaded(self):
        return self.loaded

    def getStart(self):
        return FakeAddr(self.space, 0)


class FakeFunction:
    def __init__(self, name, space, start, end):
        self.name = name
        self.entry = FakeAddr(space, start)
        self.space = space
        self.start = start
        self.end = end
        self.thunk = False

    def getName(self):
        return self.name

    def getEntryPoint(self):
        return self.entry

    def getSymbol(self):
        return SimpleNamespace(getName=lambda _full=False: self.name)

    def getSignature(self):
        return f"void {self.name}(void)"

    def isExternal(self):
        return False

    def contains(self, addr):
        return addr.space.name == self.space.name and self.start <= addr.offset <= self.end


class FakeFunctionManager:
    def __init__(self, functions):
        self.functions = functions

    def getFunctionAt(self, addr):
        return next((f for f in self.functions if f.entry == addr), None)

    def getFunctionContaining(self, addr):
        return next((f for f in self.functions if f.contains(addr)), None)

    def getFunctions(self, _forward):
        return iter(self.functions)


class FakeRef:
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst

    def getFromAddress(self):
        return self.src

    def getToAddress(self):
        return self.dst

    def getReferenceType(self):
        return "READ"


class FakeReferenceManager:
    def __init__(self, refs):
        self.refs = refs

    def getReferencesTo(self, addr):
        return [r for r in self.refs if r.dst == addr]


@pytest.fixture(autouse=True)
def forbid_function_creation(monkeypatch):
    """Any CreateFunctionCmd construction during a lookup fails the test.

    Recorded rather than raised: the old resolver swallowed exceptions from
    its creation attempt, so a raising stub would go unnoticed.
    """
    attempts = []

    def _create(*args, **_kwargs):
        attempts.append(args)
        return Mock(applyTo=Mock(return_value=False))

    module = SimpleNamespace(CreateFunctionCmd=_create)
    monkeypatch.setitem(sys.modules, "ghidra.app.cmd.function", module)
    yield
    assert attempts == [], f"read query constructed CreateFunctionCmd at {attempts}"


IMEM = FakeSpace("imem")
DMEM = FakeSpace("dmem")
RAM = FakeSpace("ram")
OTHER = FakeSpace("OTHER")


def _make_tools(spaces, blocks, functions, refs=()):
    program = Mock()
    program.getAddressFactory.return_value = FakeAddressFactory(spaces)
    program.getMemory.return_value.getBlocks.return_value = blocks
    program.getMemory.return_value.contains.return_value = True
    program.getFunctionManager.return_value = FakeFunctionManager(list(functions))
    program.getReferenceManager.return_value = FakeReferenceManager(list(refs))
    program.getSymbolTable.return_value.getSymbols.return_value = []

    tools = GhidraTools.__new__(GhidraTools)
    tools.program = program
    tools.symbol_matcher = Mock()
    tools.symbol_matcher.get_address.return_value = None
    tools.symbol_matcher.get_search_variants.return_value = []
    tools.get_all_symbols = lambda include_externals=False, include_dynamic=False: []
    return tools


def _falcon_tools():
    """imem function 0x9d2..0xa60 and 0x1524..0x1600; dmem:1558 read by imem:0a10."""
    functions = [
        FakeFunction("FUN_imem_000009d2", IMEM, 0x9D2, 0xA60),
        FakeFunction("FUN_imem_00001524", IMEM, 0x1524, 0x1600),
        FakeFunction("add", IMEM, 0x2000, 0x2010),  # hex-looking name
    ]
    refs = [FakeRef(FakeAddr(IMEM, 0xA10), FakeAddr(DMEM, 0x1558))]
    return _make_tools([IMEM, DMEM], [FakeBlock(IMEM), FakeBlock(DMEM)], functions, refs)


def _ram_tools():
    functions = [FakeFunction("main", RAM, 0x401000, 0x401100)]
    refs = [FakeRef(FakeAddr(RAM, 0x402000), FakeAddr(RAM, 0x401000))]
    blocks = [FakeBlock(RAM), FakeBlock(OTHER, loaded=False)]  # .comment-style block
    return _make_tools([RAM, OTHER], blocks, functions, refs)


# --- multi-space (Falcon) ---------------------------------------------------


@pytest.mark.parametrize("text", ["00001558", "0x1558", "1558"])
def test_bare_hex_refused_for_decompile_in_multi_space_program(text):
    tools = _falcon_tools()
    with pytest.raises(AmbiguousAddressError) as exc:
        tools.find_function(text)
    msg = str(exc.value)
    assert "imem:00001558" in msg and "dmem:00001558" in msg


def test_bare_hex_refused_for_xrefs_in_multi_space_program():
    tools = _falcon_tools()
    with pytest.raises(AmbiguousAddressError, match="dmem:00001558"):
        tools.list_xrefs("00001558")


def test_bare_hex_refused_for_read_bytes_in_multi_space_program():
    tools = _falcon_tools()
    with pytest.raises(AmbiguousAddressError, match="imem:00000a3b"):
        tools.read_bytes("0xa3b", size=4)


def test_bare_hex_is_not_partial_matched_against_function_names():
    """'1524' must not fall through to the substring strategy (FUN_imem_00001524)."""
    tools = _falcon_tools()
    with pytest.raises(AmbiguousAddressError):
        tools.find_function("1524")


def test_qualified_dmem_xrefs_resolve():
    tools = _falcon_tools()
    xrefs = tools.list_xrefs("dmem:00001558")
    assert [(x.from_address, x.to_address) for x in xrefs] == [("imem:00000a10", "dmem:00001558")]
    assert xrefs[0].function_name == "FUN_imem_000009d2"


def test_qualified_mid_function_pc_resolves_to_containing_function():
    tools = _falcon_tools()
    assert tools.find_function("imem:00000a3b").name == "FUN_imem_000009d2"
    assert tools.find_function("imem:0xa3b").name == "FUN_imem_000009d2"
    assert tools.find_function("imem:000009d2").name == "FUN_imem_000009d2"


def test_qualified_data_address_is_not_a_function():
    tools = _falcon_tools()
    with pytest.raises(ValueError, match="No function at or containing dmem:00001558"):
        tools.find_function("dmem:00001558")


def test_unknown_space_is_reported():
    tools = _falcon_tools()
    with pytest.raises(ValueError, match="memory spaces: imem, dmem"):
        tools.list_xrefs("xmem:00001558")


def test_hex_looking_exact_name_still_resolves():
    tools = _falcon_tools()
    assert tools.find_function("add").name == "add"


def test_names_still_resolve():
    tools = _falcon_tools()
    assert tools.find_function("FUN_imem_00001524").name == "FUN_imem_00001524"


def test_qualified_miss_outside_any_function_never_creates():
    tools = _falcon_tools()
    with pytest.raises(ValueError, match="No function at or containing imem:00003000"):
        tools.find_function("imem:00003000")


# --- single-space (ELF/PE and the other hosted binaries) --------------------


@pytest.mark.parametrize("text", ["00401000", "0x401000", "401000", "ram:00401000"])
def test_single_space_bare_hex_resolves_as_before(text):
    tools = _ram_tools()
    assert tools.find_function(text).name == "main"


def test_single_space_mid_function_bare_hex_resolves_to_containing():
    tools = _ram_tools()
    assert tools.find_function("0x401080").name == "main"


def test_single_space_xrefs_on_bare_hex():
    tools = _ram_tools()
    xrefs = tools.list_xrefs("00401000")
    assert [x.from_address for x in xrefs] == ["ram:00402000"]


def test_single_space_miss_returns_not_found_without_creating():
    tools = _ram_tools()
    with pytest.raises(ValueError, match="not found"):
        tools.find_function("0x500000")

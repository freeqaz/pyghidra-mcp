"""Tests for PPC decompilation annotation patterns."""

from unittest.mock import MagicMock
from pyghidra_mcp.tools import (
    annotate_ppc_decompilation,
    annotate_merged_calls,
    annotate_switch_statements,
)
from pyghidra_mcp.symbol_lookup import SymbolInfo
from pyghidra_mcp.models import SwitchInfo


class TestAnnotatePpcDecompilation:
    """Test LZCOUNT pattern annotation with comments."""

    def test_simple_lzcount_shift(self):
        """LZCOUNT(x) >> 5 gets annotated with comment."""
        code = "y = LZCOUNT(x) >> 5;"
        expected = "y = LZCOUNT(x) >> 5 /* == !x */;"
        assert annotate_ppc_decompilation(code) == expected

    def test_ulonglong_variant(self):
        """64-bit variant from actual Ghidra output."""
        code = "(ulonglong)(LZCOUNT(this->mState - 1) << 0x20) >> 0x25"
        expected = "(ulonglong)(LZCOUNT(this->mState - 1) << 0x20) >> 0x25 /* == !x */"
        assert annotate_ppc_decompilation(code) == expected

    def test_uint_cast(self):
        """(uint)LZCOUNT(x) >> 5 pattern."""
        code = "(uint)LZCOUNT(val) >> 5"
        expected = "(uint)LZCOUNT(val) >> 5 /* == !x */"
        assert annotate_ppc_decompilation(code) == expected

    def test_struct_member(self):
        """LZCOUNT with struct member access."""
        code = "arr[LZCOUNT(this->unk64) >> 5]"
        expected = "arr[LZCOUNT(this->unk64) >> 5 /* == !x */]"
        assert annotate_ppc_decompilation(code) == expected

    def test_multiple_occurrences(self):
        """Multiple LZCOUNT in one line."""
        code = "x = LZCOUNT(a) >> 5; y = LZCOUNT(b) >> 5;"
        expected = "x = LZCOUNT(a) >> 5 /* == !x */; y = LZCOUNT(b) >> 5 /* == !x */;"
        assert annotate_ppc_decompilation(code) == expected

    def test_no_lzcount(self):
        """Non-LZCOUNT code unchanged."""
        code = "x = y + 1;"
        assert annotate_ppc_decompilation(code) == code

    def test_lzcount_without_shift_unchanged(self):
        """LZCOUNT without >> 5 should not be annotated."""
        code = "x = LZCOUNT(y);"
        assert annotate_ppc_decompilation(code) == code

    def test_lzcount_with_different_shift_unchanged(self):
        """LZCOUNT with different shift amount should not be annotated."""
        code = "x = LZCOUNT(y) >> 4;"
        assert annotate_ppc_decompilation(code) == code

    def test_multiline_code(self):
        """LZCOUNT patterns across multiple lines."""
        code = """if (LZCOUNT(flag) >> 5) {
    arr[LZCOUNT(this->state) >> 5] = value;
}"""
        expected = """if (LZCOUNT(flag) >> 5 /* == !x */) {
    arr[LZCOUNT(this->state) >> 5 /* == !x */] = value;
}"""
        assert annotate_ppc_decompilation(code) == expected

    def test_nested_expression(self):
        """LZCOUNT with nested expression."""
        code = "result = LZCOUNT(ptr->field1 + ptr->field2) >> 5;"
        expected = "result = LZCOUNT(ptr->field1 + ptr->field2) >> 5 /* == !x */;"
        assert annotate_ppc_decompilation(code) == expected

    def test_empty_string(self):
        """Empty string returns empty string."""
        assert annotate_ppc_decompilation("") == ""

    def test_real_world_array_index(self):
        """Real-world pattern: using LZCOUNT result as array index."""
        code = "this->unk9a4[LZCOUNT(this->unk64) >> 5]"
        expected = "this->unk9a4[LZCOUNT(this->unk64) >> 5 /* == !x */]"
        assert annotate_ppc_decompilation(code) == expected

    def test_preserves_original_pattern(self):
        """Verify original LZCOUNT pattern is preserved, not replaced."""
        code = "LZCOUNT(x) >> 5"
        result = annotate_ppc_decompilation(code)
        # Original pattern must still be present
        assert "LZCOUNT(x) >> 5" in result
        # Comment is appended
        assert "/* == !x */" in result


class TestAnnotateMergedCalls:
    """Test merged symbol annotation."""

    def _make_mock_parser(self, address_to_symbols: dict):
        """Create a mock MapFileParser with the given symbol mappings."""
        parser = MagicMock()

        def lookup_all_symbols_by_address(address: int):
            return address_to_symbols.get(address, [])

        parser.lookup_all_symbols_by_address = lookup_all_symbols_by_address
        return parser

    def test_no_merged_symbols(self):
        """Code without merged symbols unchanged."""
        code = "foo(bar);"
        parser = self._make_mock_parser({})
        assert annotate_merged_calls(code, parser) == code

    def test_single_symbol_at_address(self):
        """Single symbol gets annotated with method name."""
        code = "merged_82331360(this);"
        parser = self._make_mock_parser({
            0x82331360: [
                SymbolInfo(
                    mangled="?Foo@Bar@@QAAXXZ",
                    demangled="Bar::Foo",
                    class_name="Bar",
                    method_name="Foo",
                    address=0x82331360,
                    section="0005",
                )
            ]
        })
        result = annotate_merged_calls(code, parser)
        assert "merged_82331360" in result
        assert "/* Foo */" in result

    def test_scalar_vector_destructor_merge(self):
        """Common case: scalar and vector deleting destructors merged."""
        code = "(*merged_82331360)(this, 1);"
        parser = self._make_mock_parser({
            0x82331360: [
                SymbolInfo(
                    mangled="??_GObjRef@@UAAPAXI@Z",
                    demangled="ObjRef::`scalar deleting destructor'",
                    class_name="ObjRef",
                    method_name="`scalar deleting destructor'",
                    address=0x82331360,
                    section="0005",
                ),
                SymbolInfo(
                    mangled="??_EObjRef@@UAAPAXI@Z",
                    demangled="ObjRef::`vector deleting destructor'",
                    class_name="ObjRef",
                    method_name="`vector deleting destructor'",
                    address=0x82331360,
                    section="0005",
                ),
            ]
        })
        result = annotate_merged_calls(code, parser)
        assert "merged_82331360" in result
        assert "scalar dtor" in result
        assert "vector dtor" in result

    def test_multiple_merged_in_code(self):
        """Multiple merged symbols in same code get annotated."""
        code = "merged_82331360(a); merged_82340000(b);"
        parser = self._make_mock_parser({
            0x82331360: [
                SymbolInfo(
                    mangled="?Foo@A@@QAAXXZ",
                    demangled="A::Foo",
                    class_name="A",
                    method_name="Foo",
                    address=0x82331360,
                    section="0005",
                )
            ],
            0x82340000: [
                SymbolInfo(
                    mangled="?Bar@B@@QAAXXZ",
                    demangled="B::Bar",
                    class_name="B",
                    method_name="Bar",
                    address=0x82340000,
                    section="0005",
                )
            ],
        })
        result = annotate_merged_calls(code, parser)
        assert "/* Foo */" in result
        assert "/* Bar */" in result

    def test_unknown_address(self):
        """Unknown address left unchanged."""
        code = "merged_99999999(this);"
        parser = self._make_mock_parser({})
        assert annotate_merged_calls(code, parser) == code

    def test_no_parser_returns_unchanged(self):
        """Without a parser, code is returned unchanged."""
        code = "merged_82331360(this);"
        result = annotate_merged_calls(code, None)
        assert result == code

    def test_preserves_original_symbol(self):
        """Verify merged symbol is preserved, not replaced."""
        code = "merged_82331360(this);"
        parser = self._make_mock_parser({
            0x82331360: [
                SymbolInfo(
                    mangled="?X@Y@@QAAXXZ",
                    demangled="Y::X",
                    class_name="Y",
                    method_name="X",
                    address=0x82331360,
                    section="0005",
                )
            ]
        })
        result = annotate_merged_calls(code, parser)
        # Original merged symbol must be preserved
        assert "merged_82331360" in result
        # Comment is appended, not replaced
        assert result.startswith("merged_82331360")

    def test_case_insensitive_hex(self):
        """Both upper and lowercase hex addresses are handled."""
        code = "merged_82abCDef(this);"
        parser = self._make_mock_parser({
            0x82ABCDEF: [
                SymbolInfo(
                    mangled="?X@Y@@QAAXXZ",
                    demangled="Y::X",
                    class_name="Y",
                    method_name="X",
                    address=0x82ABCDEF,
                    section="0005",
                )
            ]
        })
        result = annotate_merged_calls(code, parser)
        assert "/* X */" in result


class TestAnnotateSwitchStatements:
    """Test switch statement annotation."""

    def test_no_switches_unchanged(self):
        """Code without switches is unchanged."""
        code = "void foo() { return; }"
        result = annotate_switch_statements(code, [])
        assert result == code

    def test_single_switch(self):
        """Single switch adds header comment."""
        code = "void foo() {\n  if (x == 0) { }\n  else if (x == 1) { }\n}"
        switches = [
            SwitchInfo(
                address="0x82345678",
                case_count=None,
                index_register=None,
                table_address=None,
            )
        ]
        result = annotate_switch_statements(code, switches)
        assert "SWITCH STATEMENTS DETECTED" in result
        assert "0x82345678" in result
        assert code in result  # Original code preserved

    def test_switch_with_case_count(self):
        """Switch with detected case count shows it."""
        code = "void bar() { }"
        switches = [
            SwitchInfo(
                address="0x82340000",
                case_count=5,
                index_register="r3",
                table_address="0x82AABBCC",
            )
        ]
        result = annotate_switch_statements(code, switches)
        assert "~5 cases" in result
        assert "0x82340000" in result

    def test_multiple_switches(self):
        """Multiple switches all listed."""
        code = "void baz() { }"
        switches = [
            SwitchInfo(address="0x82340001", case_count=3, index_register=None, table_address=None),
            SwitchInfo(address="0x82340002", case_count=7, index_register=None, table_address=None),
        ]
        result = annotate_switch_statements(code, switches)
        assert "1. Address 0x82340001" in result
        assert "2. Address 0x82340002" in result
        assert "~3 cases" in result
        assert "~7 cases" in result

    def test_header_at_top(self):
        """Switch comment is prepended, not appended."""
        code = "int main() { return 0; }"
        switches = [
            SwitchInfo(address="0x82000000", case_count=None, index_register=None, table_address=None)
        ]
        result = annotate_switch_statements(code, switches)
        # Comment comes before code
        assert result.index("SWITCH") < result.index("int main")

    def test_guidance_note_included(self):
        """Includes guidance about Ghidra if-else chains."""
        code = "void x() {}"
        switches = [
            SwitchInfo(address="0x82111111", case_count=None, index_register=None, table_address=None)
        ]
        result = annotate_switch_statements(code, switches)
        assert "if-else chains" in result.lower() or "if-else" in result

"""Unit tests for symbol_lookup module."""

import pytest
from pyghidra_mcp.symbol_lookup import (
    decode_msvc_string_literal,
    demangle_msvc,
    extract_class_name,
    extract_method_name,
)


class TestDecodeMsvcStringLiteral:
    """Tests for decode_msvc_string_literal function."""

    def test_simple_string(self):
        """Test decoding a simple string with no escapes."""
        mangled = "??_C@_0O@EPEJKEFM@nar_bam_trans?$AA@"
        assert decode_msvc_string_literal(mangled) == "nar_bam_trans"

    def test_period_escape(self):
        """Test ?4 -> period escape."""
        mangled = "??_C@_07LEAMOHCB@App?4cpp?$AA@"
        assert decode_msvc_string_literal(mangled) == "App.cpp"

    def test_forward_slash_escape(self):
        """Test ?1 -> forward slash escape."""
        mangled = "??_C@_0BH@MPLIJIBA@?1vo_bank_rehearse?4milo?$AA@"
        assert decode_msvc_string_literal(mangled) == "/vo_bank_rehearse.milo"

    def test_asterisk_escape(self):
        """Test ?$CK -> asterisk escape."""
        mangled = "??_C@_0M@GKILHAJE@?$CK?$CKno?5file?$CK?$CK?$AA@"
        assert decode_msvc_string_literal(mangled) == "**no file**"

    def test_apostrophe_and_percent_escape(self):
        """Test ?8 -> apostrophe and ?$CF -> percent escapes."""
        mangled = "??_C@_0BB@OEPBHON@Couldn?8t?5load?5?$CFs?$AA@"
        assert decode_msvc_string_literal(mangled) == "Couldn't load %s"

    def test_greater_equals_escape(self):
        """Test ?$DO -> greater than and ?$DN -> equals escapes."""
        mangled = "??_C@_0L@JDNODHIG@mRefs?5?$DO?$DN?50?$AA@"
        assert decode_msvc_string_literal(mangled) == "mRefs >= 0"

    def test_backslash_and_colon_escape(self):
        """Test ?2 -> backslash and ?3 -> colon escapes."""
        mangled = "??_C@_0BI@DLCFLHPH@e?3?2lazer_build?$AA@"
        assert decode_msvc_string_literal(mangled) == "e:\\lazer_build"

    def test_less_than_escape(self):
        """Test ?$DM -> less than escape."""
        mangled = "??_C@_0L@ABCDEFGH@foo?5?$DM?5bar?$AA@"
        assert decode_msvc_string_literal(mangled) == "foo < bar"

    def test_space_escape(self):
        """Test ?5 -> space escape."""
        mangled = "??_C@_0M@ABCDEFGH@hello?5world?$AA@"
        assert decode_msvc_string_literal(mangled) == "hello world"

    def test_not_string_symbol(self):
        """Test that non-string symbols return None."""
        # Regular function symbol
        assert decode_msvc_string_literal("?PoseMeshes@CharBonesMeshes@@QAAXXZ") is None

        # Constructor
        assert decode_msvc_string_literal("??0CharBonesMeshes@@QAA@XZ") is None

        # Plain C symbol
        assert decode_msvc_string_literal("main") is None

        # Empty string
        assert decode_msvc_string_literal("") is None

    def test_malformed_string_symbol(self):
        """Test that malformed string symbols return None."""
        # Missing ?$AA@ terminator
        assert decode_msvc_string_literal("??_C@_0O@EPEJKEFM@nar_bam_trans") is None

        # Missing literal section
        assert decode_msvc_string_literal("??_C@_0O@EPEJKEFM@?$AA@") is None


class TestDemangleMsvc:
    """Tests for demangle_msvc function."""

    def test_regular_method(self):
        """Test demangling regular class method."""
        info = demangle_msvc("?PoseMeshes@CharBonesMeshes@@QAAXXZ")
        assert info is not None
        assert info.class_name == "CharBonesMeshes"
        assert info.method_name == "PoseMeshes"
        assert info.demangled == "CharBonesMeshes::PoseMeshes"

    def test_constructor(self):
        """Test demangling constructor."""
        info = demangle_msvc("??0CharBonesMeshes@@QAA@XZ")
        assert info is not None
        assert info.class_name == "CharBonesMeshes"
        assert info.method_name == "CharBonesMeshes"
        assert info.demangled == "CharBonesMeshes::CharBonesMeshes"

    def test_destructor(self):
        """Test demangling destructor."""
        info = demangle_msvc("??1CharBonesMeshes@@QAA@XZ")
        assert info is not None
        assert info.class_name == "CharBonesMeshes"
        assert info.method_name == "~CharBonesMeshes"
        assert info.demangled == "CharBonesMeshes::~CharBonesMeshes"

    def test_scalar_deleting_destructor(self):
        """Test demangling scalar deleting destructor."""
        info = demangle_msvc("??_GCharBonesMeshes@@QAAPAXI@Z")
        assert info is not None
        assert info.class_name == "CharBonesMeshes"
        assert info.method_name == "`scalar deleting destructor'"

    def test_non_msvc_symbol(self):
        """Test that non-MSVC symbols return None."""
        assert demangle_msvc("main") is None
        assert demangle_msvc("") is None
        assert demangle_msvc("_start") is None


class TestExtractMethodName:
    """Tests for extract_method_name function."""

    def test_from_mangled(self):
        """Test extracting method name from mangled symbol."""
        assert extract_method_name("?PoseMeshes@CharBonesMeshes@@QAAXXZ") == "PoseMeshes"

    def test_from_demangled(self):
        """Test extracting method name from demangled symbol."""
        assert extract_method_name("CharBonesMeshes::PoseMeshes") == "PoseMeshes"

    def test_plain_name(self):
        """Test with plain function name."""
        assert extract_method_name("PoseMeshes") == "PoseMeshes"


class TestExtractClassName:
    """Tests for extract_class_name function."""

    def test_from_mangled(self):
        """Test extracting class name from mangled symbol."""
        assert extract_class_name("?PoseMeshes@CharBonesMeshes@@QAAXXZ") == "CharBonesMeshes"

    def test_from_demangled(self):
        """Test extracting class name from demangled symbol."""
        assert extract_class_name("CharBonesMeshes::PoseMeshes") == "CharBonesMeshes"

    def test_plain_name(self):
        """Test with plain function name (no class)."""
        assert extract_class_name("PoseMeshes") is None

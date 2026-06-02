from enum import Enum

from pydantic import BaseModel, Field


class DecompiledFunction(BaseModel):
    name: str
    code: str
    signature: str | None = None
    error: str | None = None
    # Rich response fields (populated when include_* flags are set)
    callees: list[str] | None = None
    referenced_strings: list[str] | None = None
    xrefs: list["CrossReferenceInfo"] | None = None


class FunctionInfo(BaseModel):
    """Provides basic information about a function within a binary."""

    name: str = Field(..., description="The name of the function.")
    entry_point: str = Field(..., description="The entry point address of the function.")


class FunctionSearchResults(BaseModel):
    """A container for a list of functions found during a search."""

    functions: list[FunctionInfo] = Field(
        ..., description="A list of functions that match the search criteria."
    )


class ProgramBasicInfo(BaseModel):
    name: str
    analysis_complete: bool


class ProgramBasicInfos(BaseModel):
    programs: list[ProgramBasicInfo]


class ProgramInfo(BaseModel):
    name: str
    file_path: str | None = None
    load_time: float | None = None
    analysis_complete: bool
    metadata: dict
    code_indexed: bool
    strings_indexed: bool


class ProgramInfos(BaseModel):
    programs: list[ProgramInfo]


class OpenProgramInfo(BaseModel):
    name: str
    path: str
    current: bool
    analysis_complete: bool


class OpenProgramInfos(BaseModel):
    programs: list[OpenProgramInfo]


class SkippedImport(BaseModel):
    path: str
    reason: str


class ImportRequestResult(BaseModel):
    requested_path: str
    queued_count: int
    queued_paths: list[str]
    skipped_count: int
    skipped: list[SkippedImport]
    message: str


class GotoResponse(BaseModel):
    binary_name: str
    address: str
    success: bool


class RenameResponse(BaseModel):
    binary_name: str
    address: str
    old_name: str
    new_name: str


class VariableRenameResponse(BaseModel):
    binary_name: str
    function_name: str
    function_address: str
    variable_kind: str
    old_name: str
    new_name: str


class VariableTypeResponse(BaseModel):
    binary_name: str
    function_name: str
    function_address: str
    variable_kind: str
    variable_name: str
    old_type: str
    new_type: str


class FunctionPrototypeResponse(BaseModel):
    binary_name: str
    function_name: str
    function_address: str
    old_prototype: str
    new_prototype: str


class CommentResponse(BaseModel):
    binary_name: str
    address: str
    comment: str
    comment_type: str


class ExportInfo(BaseModel):
    name: str
    address: str


class ExportInfos(BaseModel):
    exports: list[ExportInfo]


class ImportInfo(BaseModel):
    name: str
    library: str


class ImportInfos(BaseModel):
    imports: list[ImportInfo]


class CrossReferenceInfo(BaseModel):
    function_name: str | None = None
    from_address: str
    to_address: str
    type: str


class CrossReferenceInfos(BaseModel):
    target: str | None = None
    cross_references: list[CrossReferenceInfo]
    error: str | None = None


# Resolve forward reference for DecompiledFunction.xrefs
DecompiledFunction.model_rebuild()


class SymbolInfo(BaseModel):
    name: str
    address: str
    type: str
    namespace: str
    source: str
    refcount: int
    external: bool
    is_thunk: bool = False
    thunk_target: str | None = None


class SymbolSearchResults(BaseModel):
    symbols: list[SymbolInfo]


class SearchMode(str, Enum):
    """Search mode for code search."""

    SEMANTIC = "semantic"  # Vector similarity search
    LITERAL = "literal"  # Exact string match ($contains)


class CodeSearchResult(BaseModel):
    function_name: str
    code: str
    similarity: float
    search_mode: SearchMode
    preview: str | None = None


class CodeSearchResults(BaseModel):
    results: list[CodeSearchResult]
    query: str
    search_mode: SearchMode
    returned_count: int
    offset: int
    limit: int
    literal_total: int = Field(..., description="total literal matches")
    semantic_total: int = Field(..., description="estimated semantic matches")
    total_functions: int


class StringInfo(BaseModel):
    value: str
    address: str


class StringSearchResult(StringInfo):
    similarity: float


class StringSearchResults(BaseModel):
    strings: list[StringSearchResult]


class BytesReadResult(BaseModel):
    address: str
    size: int
    data: str = Field(..., description="hex string")


class CallGraphDirection(str, Enum):
    """Represents the direction of the call graph."""

    CALLING = "calling"
    CALLED = "called"


class CallGraphDisplayType(str, Enum):
    """Represents the display type of the call graph."""

    FLOW = "flow"
    FLOW_ENDS = "flow_ends"
    MIND = "mind"


class CallGraphResult(BaseModel):
    function_name: str
    direction: CallGraphDirection
    display_type: CallGraphDisplayType
    graph: str = Field(..., description="MermaidJS graph string")
    mermaid_url: str


class StructureMemberInfo(BaseModel):
    """A member/field within a structure."""

    name: str | None = Field(None, description="Field name (may be None for undefined)")
    type_name: str = Field(..., description="Data type name")
    offset: int = Field(..., description="Byte offset within the structure")
    size: int = Field(..., description="Size in bytes")


class StructureInfo(BaseModel):
    """A structure/class data type from Ghidra's Data Type Manager."""

    name: str = Field(..., description="Structure name")
    category: str = Field(..., description="Category path (e.g. '/DC3/classes')")
    size: int = Field(..., description="Total size in bytes")
    num_members: int = Field(..., description="Number of defined members")
    members: list[StructureMemberInfo] = Field(..., description="Structure members")


class StructureListResult(BaseModel):
    """Result of listing structures from the Data Type Manager."""

    structures: list[StructureInfo] = Field(..., description="Matched structures")
    total_count: int = Field(..., description="Total structures matching filter")


class SwitchInfo(BaseModel):
    """Information about a detected switch statement in a function."""

    address: str = Field(..., description="Address of the bctr instruction (switch jump)")
    case_count: int | None = Field(
        None, description="Estimated number of cases if detectable from bounds check"
    )
    index_register: str | None = Field(
        None, description="Register used for switch index if detected"
    )
    table_address: str | None = Field(
        None, description="Address of jump table if detected"
    )


class SwitchDetectionResult(BaseModel):
    """Result of switch statement detection for a function."""

    function_name: str = Field(..., description="Name of the analyzed function")
    function_address: str = Field(..., description="Entry point address of the function")
    switches: list[SwitchInfo] = Field(
        default_factory=list, description="Detected switch statements"
    )
    note: str = Field(
        default="If Ghidra shows if-else chains, they are likely switch statements",
        description="Interpretation guidance"
    )

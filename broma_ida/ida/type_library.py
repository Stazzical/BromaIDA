from collections.abc import Iterable, Sequence
from enum import Enum, auto
from functools import cache
from re import compile
from typing import TYPE_CHECKING

from ida_typeinf import (
    tinfo_t as ida_tinfo_t,
    udt_type_data_t as ida_udt_type_data_t,
    get_idati,
    parse_decl as ida_parse_decl,
    get_ordinal_limit, get_numbered_type_name,
    del_named_type,
    PT_SIL, BADSIZE,
    BT_VOID, BT_INT,
    TERR_OK, BTF_STRUCT, TCMP_DECL,
    NTF_TYPE,
)

from broma_ida.ida import dirtree
from broma_ida.utils import STLNode, STLUtils

if TYPE_CHECKING:
    from broma_ida.models.argtype import ArgType


_CLASS_NAME_RE = compile(r"^[A-Za-z_]\w*(::[A-Za-z_]\w*)*$")


class TypeState(Enum):
    """Enum for the state of a type in the IDA type library."""
    MISSING = auto()
    FORWARD = auto()
    BROKEN = auto()
    OK = auto()


def native_int_type() -> ida_tinfo_t:
    t = ida_tinfo_t()
    t.create_simple_type(BT_INT)
    return t


def native_void_type() -> ida_tinfo_t:
    t = ida_tinfo_t()
    t.create_simple_type(BT_VOID)
    return t


def declare_forward_decl(name: str, folder: str | None = dirtree.FORWARD_FOLDER) -> ida_tinfo_t | None:
    """Registers `name` in the til as a forward-declaration."""
    if not _CLASS_NAME_RE.match(name):
        return None

    fwd = ida_tinfo_t()
    if fwd.create_forward_decl(get_idati(), BTF_STRUCT, name) != TERR_OK:
        return None

    # keep it with the other BromaIDA types
    if folder is not None:
        dirtree.move(f"/{name}", folder)
    return fwd


def til_type_names() -> list[str]:
    """
    Get the names of all types in the local types.

    Returns:
        list[str]
    """
    til = get_idati()
    names = (
        get_numbered_type_name(til, o)
        for o in range(1, get_ordinal_limit(til))
    )

    return [n for n in names if n]


def delete_types(names: Iterable[str]) -> int:
    """
    Deletes the named types from the local type library.

    Args:
        names (Iterable[str])

    Returns:
        int: Count of how many were successfully deleted.
    """
    til = get_idati()
    deleted = sum(
        bool(del_named_type(til, n, NTF_TYPE)) for n in names
    )
    resolve_type_tinfo.cache_clear()
    return deleted


def get_type_info(
    name: str,
    allow_forward_decl: bool = False
) -> ida_tinfo_t | None:
    """
    Gets the info about a type from IDA's type library.
    Returns None if the type is considered incorrect
    by IDA with `ida_tinfo.tinfo_t.is_correct()`.
    If `allow_forward_decl` is `True`, the type is
    returned regardless if it's forward-declared.

    Args:
        name (str): The name of the type/struct.
        allow_forward_decl (bool, optional)

    Returns:
        ida_typeinf.tinfo_t | None
    """
    tif = ida_tinfo_t()
    if not tif.get_named_type(get_idati(), name):
        return None

    if tif.is_forward_decl():
        # IDAClang imports forward-only structs as forward declarations.
        # is_correct() is False for those, but they're valid behind a pointer
        return tif if allow_forward_decl else None

    return tif if tif.is_correct() else None


def resolve_bare_type(name: str, allow_forward_decl: bool = False) -> ida_tinfo_t | None:
    """
    Resolves a bare type name (no const/ptr/ref decoration) to a
    tinfo_t. Tries the IDA type library first, then falls back
    to parsing it as a built-in/primitive declaration.

    Args:
        name (str)
        allow_forward_decl (bool, optional)

    Returns:
        ida_typeinf.tinfo_t | None
    """
    if name == "":
        return None

    # we can't get this with parse_decl
    if name == "void":
        return native_void_type()

    tif = get_type_info(name, allow_forward_decl)
    if tif is not None:
        return tif

    probe = ida_tinfo_t()
    if ida_parse_decl(
        probe, get_idati(), f"{name} __probe_dummy;", PT_SIL
    ) is None or not probe.is_correct():
        return None

    return probe


@cache
def resolve_type_tinfo(arg: "ArgType") -> ida_tinfo_t | None:
    """
    Resolves an ArgType/RetType's fully decorated type
    (const/ptr/ref included) against IDA's type library.

    Args:
        arg (ArgType)

    Returns:
        ida_typeinf.tinfo_t | None
    """
    bare_name = (
        arg.stripped_expanded_type if arg.is_stl
        else arg.stripped_type
    )
    by_ref = arg.is_ptr_or_ref
    base = resolve_bare_type(bare_name, allow_forward_decl=by_ref)

    if base is None and by_ref:
        base = declare_forward_decl(bare_name)

    if base is None:
        return None

    # create_func accepts these but the result is is_correct() == False
    if base.is_forward_decl() and not by_ref:
        print(
            "[!] BromaIDA: Can't use forward-declared type "
            f"'{bare_name}' by value!")
        return None

    if arg.is_const:
        base.set_const()

    if arg.is_ptr_or_ref:
        # wrap it for as many pointers/references needed
        for _ in arg.stl_node.ptr:
            wrapped = ida_tinfo_t()
            wrapped.create_ptr(base)
            base = wrapped

    return base


def get_type_state(name: str | ida_tinfo_t) -> "TypeState":
    if isinstance(name, str):
        tif = ida_tinfo_t()

        if not tif.get_named_type(get_idati(), name):
            return TypeState.MISSING
    else:
        tif = name

    if tif.is_forward_decl():
        return TypeState.FORWARD

    if not tif.is_correct() or tif.get_size() == BADSIZE:
        return TypeState.BROKEN

    return TypeState.OK


def types_equivalent(name_a: str, name_b: str) -> bool:
    """
    True if two bare type names refer to the same underlying IDA type,
    resolving through typedef aliases (e.g. cocos2d::ccColor3B and
    cocos2d::_ccColor3B naming the same anonymous struct under the hood).
    Falls back to False if either name isn't a registered type yet.

    Args:
        name_a (str)
        name_b (str)

    Returns:
        bool
    """
    if name_a == "" or name_b == "":
        return False

    tif_a = resolve_bare_type(name_a)
    tif_b = resolve_bare_type(name_b)

    if tif_a is None or tif_b is None:
        return False

    return tif_a.equals_to(tif_b)


def same_declared_type(a: ida_tinfo_t, b: ida_tinfo_t) -> bool:
    return a.compare_with(b, TCMP_DECL)


def stl_nodes_equivalent(a: STLNode, b: STLNode) -> bool:
    """
    Check if two STLNode instances are the same
    by checking against the IDA type library.

    Args:
        node_a (STLNode)
        node_b (STLNode)

    Returns:
        bool
    """
    if a == b:
        return True
    if a.const != b.const or a.ptr != b.ptr:
        return False
    if a.is_stl or b.is_stl:
        return (
            a.name == b.name and len(a.args) == len(b.args)
            and all(stl_nodes_equivalent(x, y) for x, y in zip(a.args, b.args))
        )

    return types_equivalent(a.name, b.name)


def struct_matches(name: str, member_types: Sequence[str], must_exist: bool = False) -> bool:
    tif = get_type_info(name)
    if tif is None:
        return not must_exist

    udt = ida_udt_type_data_t()
    if not tif.get_udt_details(udt) or udt.size() != len(member_types):
        return False

    for member, expected in zip(udt, member_types):
        ida_node = STLUtils.collapse_stl_type(STLNode.parse(str(member.type)))
        expected_node = STLUtils.collapse_stl_type(STLNode.parse(expected))
        if not stl_nodes_equivalent(ida_node, expected_node):
            return False
    return True


def broken_types(names: Iterable[str]) -> list[str]:
    """Names that are missing, forward-declared or broken."""
    return [n for n in names if get_type_state(n) is not TypeState.OK]

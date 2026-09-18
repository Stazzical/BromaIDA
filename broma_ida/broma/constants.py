from typing import Literal
from enum import IntEnum

from ida_typeinf import (
    CM_CC_INVALID, CM_CC_UNKNOWN, CM_CC_VOIDARG,
    CM_CC_CDECL, CM_CC_ELLIPSIS, CM_CC_STDCALL,
    CM_CC_FASTCALL, CM_CC_THISCALL, CM_CC_SPECIAL
)


BROMA_PLATFORMS = Literal["win", "imac", "m1", "ios", "android32", "android64"]

BROMA_PLATFORM_GROUPS = {
    "android32": "android",
    "android64": "android",
    "imac": "mac",
    "m1": "mac"
}

BROMA_CALLING_CONVENTIONS = Literal[
    "default", "thiscall",
    "optcall",      # compiler-optimized fastcall, MSVC Win32 only, not a real call conv
    "membercall"    # compiler-optimized thiscall, MSVC Win32 only, not a real call conv
]

# not a Broma constant but a constant nonetheless
CALLING_CONVENTIONS = Literal[
    "__thiscall", "__fastcall",
    "__cdecl", "__stdcall"
]


# I don't know if these are actually ints in python from IDA
# but it wasn't happy when I used Enum instead
class IDACallingConvention(IntEnum):
    """Calling conventions enum for IDA's bitmask."""

    invalid = CM_CC_INVALID     # = 0x00
    """Invalid calling convention"""
    unknown = CM_CC_UNKNOWN     # = 0x10
    """Unknown calling convention."""
    voidarg = CM_CC_VOIDARG     # = 0x20
    """
    Represents an empty function prototype 'f()'
    with a valid calling convention and 0 arguments.
    """
    cdecl = CM_CC_CDECL         # = 0x30
    """__cdecl"""
    ellipsis = CM_CC_ELLIPSIS   # = 0x40
    """
    Calling convention for variadic functions.
    Handled internally between different architectures and bitnesses.
    """
    stdcall = CM_CC_STDCALL     # = 0x50
    """__stdcall, only relevant on 32-bit."""
    fastcall = CM_CC_FASTCALL   # = 0x70
    """__fastcall, only relevant on 32-bit."""
    thiscall = CM_CC_THISCALL   # = 0x80
    """__thiscall, only relevant on 32-bit."""
    special = CM_CC_SPECIAL     # = 0xF0
    """
    IDA's bitmask for user-defined calling conventions,
    AKA "__usercall".
    """


CPP_TYPE_SPECIFIERS = ("unsigned", "signed")
CPP_TYPE_QUALIFIERS = ("const", "volatile")
CPP_DATA_TYPES = ("bool", "char", "short", "int", "long")
CPP_PRIMITIVES = (
    "void", "int", "char", "float", "short",
    "double", "bool", "long"
)

DATA_TYPE_TO_SIZE = {
    "long": 8,
    "int": 4,
    "short": 2,
    "char": 1,
    "bool": 1
}

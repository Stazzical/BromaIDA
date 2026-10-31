from typing import Literal, Final


BROMA_PLATFORMS = Literal["win", "imac", "m1", "ios", "android32", "android64"]

BROMA_PLATFORM_GROUPS = {
    "android32": "android",
    "android64": "android",
    "imac": "mac",
    "m1": "mac"
}

BROMA_CALLING_CONVENTIONS = Literal[
    "default", "thiscall",
    # these should just be manually defined in broma files with attributes to map memory
    # compiler optimizations aren't universal and these are specific to geometry dash
    "optcall",      # compiler-optimized fastcall, MSVC Win32 only, not a real call conv
    "membercall"    # compiler-optimized thiscall, MSVC Win32 only, not a real call conv
]

CALLING_CONVENTIONS : Final = (
    "__cdecl", "__stdcall", "__pascal", "__fastcall", "__thiscall",
    "__golang", "__usercall", "__userpurge"
)
"""Calling convention names as IDA prints them in declarations."""

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

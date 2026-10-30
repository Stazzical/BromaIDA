from dataclasses import dataclass
from functools import cache
from hashlib import sha256
from pathlib import Path
from struct import unpack
from typing import NoReturn

from ida_bytes import get_dword, get_bytes
from ida_diskio import idadir
from ida_funcs import get_func, get_func_name
from ida_ida import inf_get_filetype, f_PE, f_MACHO, f_ELF
from ida_kernwin import take_database_snapshot
from ida_loader import (
    get_path, PATH_TYPE_IDB,
    snapshot_t
)
from ida_nalt import (
    get_imagebase, get_root_filename,
    retrieve_input_file_md5
)
from ida_pro import IDA_SDK_VERSION
from ida_segment import (
    get_first_seg, get_segm_by_name,
    getseg, get_segm_name,
    SEG_CODE, SEGPERM_EXEC
)

from broma_ida.broma.constants import BROMA_PLATFORMS


class UnsupportedBinaryError(RuntimeError):
    pass


# i don't like importing ida_pro just for this in some modules
ENV_IDA_VERSION = IDA_SDK_VERSION

# Mach-O Load commands
_MINIMUM_OS_VERSION_LOAD_COMMAND = 0x32

# Mach-O CPU types
_CPU_TYPE_ARM64 = 0x0100000c
_CPU_TYPE_X86_64 = 0x01000007

# Mach-O Platform types
_PLATFORM_TYPE_MACOS = 0x1
_PLATFORM_TYPE_IOS = 0x2


@dataclass(frozen=True, slots=True)
class PlatformProfile:
    """Profile container for facts about a certain binary platform."""

    printable: str
    thunk_sizes: tuple[int, ...]
    clang_args: str
    stl_dir: str
    itanium_abi: bool
    instruction_alignment: int = 1
    reg_return_sizes: frozenset[int] = frozenset(range(1, 17))


PLATFORM_PROFILES: dict[BROMA_PLATFORMS, PlatformProfile] = {
    "win":          PlatformProfile("Windows", (6, 12), "-target x86_64-pc-win32", "windows", itanium_abi=False, reg_return_sizes=frozenset({1, 2, 4, 8})),
    "imac":         PlatformProfile("Intel MacOS", (12,), "-target x86_64-apple-darwin", "macho", itanium_abi=True),
    "m1":           PlatformProfile("M1 MacOS", (12,), "-target arm64-apple-darwin", "macho", itanium_abi=True, instruction_alignment=4),
    "ios":          PlatformProfile("iOS", (12,), "-target arm64-apple-darwin", "macho", itanium_abi=True, instruction_alignment=4),
    "android32":    PlatformProfile("Android (32-bit)", (12,), "-target armv7-none-linux-androideabi", "android", itanium_abi=True, instruction_alignment=2, reg_return_sizes=frozenset(range(1, 5))),
    "android64":    PlatformProfile("Android (64-bit)", (16,), "-target aarch64-none-linux-android", "android", itanium_abi=True, instruction_alignment=4)
}


def stop(reason: str | None = None) -> NoReturn:
    """Kills the plugin process."""
    raise SystemExit if reason is None else Exception(reason)


def _macho_min_os_platform() -> int:
    """
    Gets the minimum OS version struct from the Mach-O header.

    Returns:
        int: -1 if it couldn't find MOSV load command
    """
    start = get_imagebase()
    magic = get_dword(start)

    if magic == 0xFEEDFACF:
        header_size = 32  # 64-bit Mach-O header size
    else:
        header_size = 28  # 32-bit Mach-O header size

    mach_header = get_bytes(start, header_size)
    magic_number, cpu_type, cpu_subtype, file_type, \
        ncmds, cmds_size, flags, reserved = \
        unpack("<IIIIIIII", mach_header)

    offset = start + header_size

    for _ in range(ncmds):
        cmd_header = get_bytes(offset, 8)
        if not cmd_header or len(cmd_header) < 8:
            break

        cmd, cmdsize = unpack("<II", cmd_header)

        if cmd == _MINIMUM_OS_VERSION_LOAD_COMMAND:
            minimum_os_version_struct = get_bytes(offset, 24)
            commandtype, cmd_size, platform_type, min_os_ver, sdk_ver, \
                num_tools = unpack("<IIIIII", minimum_os_version_struct)

            return platform_type

        offset += cmdsize

    return -1

@cache
def _detect_platform() -> BROMA_PLATFORMS:
    """
    Gets the currently open binary's target platform.
    Raises a `UnsupportedBinaryError` if detection fails.

    Returns:
        BROMA_PLATFORMS
    """
    file_type = inf_get_filetype()

    if file_type == f_PE:
        return "win"
    elif file_type == f_MACHO:
        cpu_type = get_dword(
            get_segm_by_name("HEADER").start_ea + 4
        )

        if cpu_type == _CPU_TYPE_ARM64:
            platform_type = _macho_min_os_platform()

            if platform_type == _PLATFORM_TYPE_IOS:
                return "ios"
            elif platform_type == _PLATFORM_TYPE_MACOS:
                return "m1"
        elif cpu_type == _CPU_TYPE_X86_64:
            return "imac"
    elif file_type == f_ELF:
        bitness = get_first_seg().bitness

        if bitness == 0x1:
            return "android32"
        elif bitness == 0x2:
            return "android64"

    raise UnsupportedBinaryError(
        "no supported target platform was found for the currently open binary"
    )


def get_ida_path(path: str) -> Path:
    """
    Gets a path relative to the IDA root folder.

    Returns:
        Path: The path as a pathlib.Path
    """
    return Path(idadir(path))


@cache
def get_idb_sha256() -> str:
    """
    Gets a unique SHA-256 of the IDB.
    The hash's input is "[full path of the IDB]-[binary's md5]".

    Returns:
        str
    """
    idb_path: str = get_path(PATH_TYPE_IDB).replace("\\", "/")
    idb_binary_md5: str = retrieve_input_file_md5().hex()

    hash_str = f"{idb_path}-{idb_binary_md5}".encode()

    return sha256(hash_str).hexdigest()


def take_snapshot(description: str) -> tuple[bool, str]:
    """
    Takes an IDA database snapshot.

    Args:
        description (str): Truncated to 128 characters.

    Returns:
        tuple[bool, str]: (success, error message)
    """
    ss = snapshot_t()
    # snapshot_t.desc is a char[128]
    ss.desc = description[:127]
    return take_database_snapshot(ss)


def address_problem(ea: int) -> str | None:
    """Why a function can't start at `ea`, or None if one plausibly can."""
    func = get_func(ea)
    if func is not None:
        if func.start_ea == ea:
            # IDA already has a function exactly here
            return None

        # function is in the middle of another one
        return f"inside {get_func_name(func.start_ea)} (which starts at {hex(func.start_ea)})"

    seg = getseg(ea)
    if seg is None:
        # covers out-of-binary and gaps between segments
        # TODO: test
        return "outside every segment"

    # loaders don't always set permissions, so either signal saying "code" is enough
    if seg.type != SEG_CODE and not seg.perm & SEGPERM_EXEC:
        return f"in the non-code segment '{get_segm_name(seg)}'"

    alignment = get_binary_info().profile.instruction_alignment
    if ea % alignment:
        return f"not aligned to {alignment} bytes"

    return None


@dataclass(frozen=True, slots=True)
class BinaryInfo:
    """Facts about the binary currently open in IDA."""

    platform: BROMA_PLATFORMS
    filename: str

    @property
    def stem(self) -> str:
        return Path(self.filename).stem

    @property
    def profile(self) -> PlatformProfile:
        return PLATFORM_PROFILES[self.platform]


# the idb_path parameter is to key the cache
@cache
def _binary_info_for(idb_path: str) -> BinaryInfo:
    return BinaryInfo(_detect_platform(), get_root_filename())


def get_binary_info() -> BinaryInfo:
    return _binary_info_for(get_path(PATH_TYPE_IDB))


def to_ea(rva: int) -> int:
    """EA (effective address) from RVA (relative virtual address)."""
    return get_imagebase() + rva


def to_rva(ea: int) -> int:
    """RVA (relative virtual address) from EA (effective address)."""
    return ea - get_imagebase()

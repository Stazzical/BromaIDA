from typing import Callable, NoReturn
from functools import cache

from ida_idaapi import BADADDR
from ida_kernwin import ASKBTN_BTN1
from ida_name import (
    get_name_ea,
    SN_NOWARN, set_name
)
from ida_diskio import idadir
from ida_ida import inf_get_filetype, f_PE, f_MACHO, f_ELF
from ida_segment import (
    get_first_seg, get_segm_by_name
)
from ida_bytes import get_dword, get_bytes
from ida_loader import get_path, PATH_TYPE_IDB
from ida_funcs import (
    func_t as ida_func_t, FUNC_LIB
)
from ida_typeinf import (
    func_type_data_t as ida_func_type_data_t,
    tinfo_t as ida_tinfo_t,
    get_idati
)
from ida_nalt import (
    get_tinfo, retrieve_input_file_md5,
    get_imagebase
)
from ida_dirtree import (
    get_std_dirtree,
    dirtree_visitor_t as ida_dirtree_visitor_t,
    dirtree_cursor_t as ida_dirtree_cursor_t,
    direntry_t as ida_direntry_t,
    dirtree_t as ida_dirtree_t
)
from ida_pro import IDA_SDK_VERSION

from struct import unpack
from pathlib import Path
from hashlib import sha256

from broma_ida.broma.constants import BROMA_PLATFORMS
from broma_ida.ui.ask_popup import AskPopup

HAS_IDACLANG = False
try:
    import ida_srclang
    del ida_srclang
    HAS_IDACLANG = True
except ModuleNotFoundError:
    pass


TreeType = int | ida_dirtree_t
DirtreeEntry = tuple[ida_direntry_t, str]


def stop(reason: str | None = None) -> NoReturn:
    """Kills the plugin process."""
    raise SystemExit if reason is None else Exception(reason)


def path_exists(path: str, ext: str = "") -> bool:
    """
    Checks if a path exists.

    Args:
        path (str)
        ext (str, optional): Extension of file. Defaults to "".

    Returns:
        bool
    """
    if path == "" or path is None:
        return False

    if ext == "":
        return Path(path).exists()
    else:
        p_path = Path(path)

        return p_path.suffix == ext and p_path.exists()


class IDAUtils:
    """Collection of utilities to work with IDA indirectly."""

    # Mach-O Load commands
    _MINIMUM_OS_VERSION_LOAD_COMMAND = 0x32

    # Mach-O CPU types
    _CPU_TYPE_ARM64 = 0x0100000c
    _CPU_TYPE_X86_64 = 0x01000007

    # Mach-O Platform types
    _PLATFORM_TYPE_MACOS = 0x1
    _PLATFORM_TYPE_IOS = 0x2

    _plat_to_printable = {
        "win": "Windows",
        "imac": "Intel MacOS",  # MacchewOS my beloved
        "m1": "M1 MacOS",
        "ios": "iOS",
        "android32": "Android (32-bit)",
        "android64": "Android (64-bit)"
    }

    class DirtreeCollector(ida_dirtree_visitor_t):
        def __init__(self, tree: TreeType, path: str, top: bool = True):
            ida_dirtree_visitor_t.__init__(self)

            self.tree = get_std_dirtree(tree) \
                if isinstance(tree, int) else tree
            self.path = Path(path)
            self.entries: list[DirtreeEntry] = []
            self.top = top

            self.tree.traverse(self)

        def descendant_check(self, entry_path: str) -> bool:
            return bool(Path(entry_path).relative_to(self.path)) \
                if not self.top else Path(entry_path).parent == self.path

        def visit(self, c: ida_dirtree_cursor_t, de: ida_direntry_t) -> int:
            try:
                entry_path = IDAUtils.get_entry_abspath(self.tree, de)

                if de.valid() and entry_path != self.path.as_posix() and \
                        self.descendant_check(entry_path):
                    self.entries.append((de, entry_path))
            except ValueError:
                pass

            return 0

    class DirtreeExecutor(ida_dirtree_visitor_t):
        def __init__(
                self,
                tree: TreeType,
                predicate: Callable[[ida_direntry_t, str], bool],
                func: Callable[[ida_direntry_t, str], bool],
                path: str,
                top: bool = True
        ) -> None:
            ida_dirtree_visitor_t.__init__(self)

            self.tree: ida_dirtree_t = get_std_dirtree(tree) \
                if isinstance(tree, int) else tree
            self.failed_entries: list[DirtreeEntry] = []
            self.predicate = predicate
            self.callback = func
            self.path = Path(path)
            self.top = top

            self.tree.traverse(self)

        def descendant_check(self, entry_path: str) -> bool:
            return bool(Path(entry_path).relative_to(self.path)) \
                if not self.top else Path(entry_path).parent == self.path

        def visit(self, c: ida_dirtree_cursor_t, de: ida_direntry_t) -> int:
            try:
                entry_path = IDAUtils.get_entry_abspath(self.tree, de)

                if de.valid() and entry_path != self.path.as_posix() and \
                        self.descendant_check(entry_path) and \
                        self.predicate(de, entry_path) and \
                        not self.callback(de, entry_path):
                    self.failed_entries.append((de, entry_path))
            except ValueError:
                pass

            return 0

    @staticmethod
    def __get_minimum_mach_o_os_version() -> int:
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

            if cmd == IDAUtils._MINIMUM_OS_VERSION_LOAD_COMMAND:
                minimum_os_version_struct = get_bytes(offset, 24)
                commandtype, cmd_size, platform_type, min_os_ver, sdk_ver, \
                    num_tools = unpack("<IIIIII", minimum_os_version_struct)

                return platform_type

            offset += cmdsize

        return -1

    @staticmethod
    @cache
    def get_platform() -> BROMA_PLATFORMS:
        """
        Gets the currently open binary's target platform.
        Raises a `RuntimeError` if detection fails.

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

            if cpu_type == IDAUtils._CPU_TYPE_ARM64:
                platform_type = IDAUtils.__get_minimum_mach_o_os_version()

                if platform_type == IDAUtils._PLATFORM_TYPE_IOS:
                    return "ios"
                elif platform_type == IDAUtils._PLATFORM_TYPE_MACOS:
                    return "m1"
            elif cpu_type == IDAUtils._CPU_TYPE_X86_64:
                return "imac"
        elif file_type == f_ELF:
            bitness = get_first_seg().bitness

            if bitness == 0x1:
                return "android32"
            elif bitness == 0x2:
                return "android64"

        raise RuntimeError("no supported target platform was found for the currently open binary")

    @staticmethod
    @cache
    def get_platform_printable() -> str:
        """
        Printable platform name.

        Returns:
            str
        """
        return IDAUtils._plat_to_printable[IDAUtils.get_platform()]

    @staticmethod
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

    @staticmethod
    @cache
    def get_srclang_parser() -> str:
        """
        Gets the current source language parser name.

        Returns:
            str
        """
        if not HAS_IDACLANG:
            return "none"

        # TODO: support new clang parser in IDA 9.2+
        return "clang" if IDA_SDK_VERSION < 920 else "old_clang"

    @staticmethod
    @cache
    def get_thunk_size() -> tuple[int] | tuple[int, int]:
        """
        Gets the size of a jump thunk in the current binary.

        Returns:
            int
        """
        platform = IDAUtils.get_platform()

        # either a jmp or a lea + jmp
        if platform in ("win"):
            return 6, 12
        elif platform in ("imac", "m1", "android32", "ios"):
            return 12,
        elif platform == "android64":
            return 16,

        return -1,

    @staticmethod
    def rename_func(addr: int, name: str, max: int = 10) -> bool:
        """
        Renames the function at the given address with `name`.
        Accounts for overloads by appending _X
        where X is a number between 1 and max (exclusive).

        Args:
            addr (int): The address to rename
            name (str): The name to give it
            max (int, optional): Maximum number of retires.
                Defaults to 10.

        Returns:
            bool: True if the address has been renamed successfully
                after maximum tries.
        """
        renamed = False

        for i in range(max):
            if set_name(addr, name if i == 0 else f"{name}_{i}", SN_NOWARN):
                renamed = True
                break

        if not renamed:
            ida_prev_addr = get_name_ea(BADADDR, name)
            if ida_prev_addr != BADADDR and addr != ida_prev_addr:
                if AskPopup(
                    f"{name} is already taken at "
                    f"{hex(ida_prev_addr - get_imagebase())} while trying to "
                    f"rename {hex(addr)}\n"
                    "Overwrite or keep current name?\n"
                    "(Old location will be renamed to "
                    f"sub_{hex(ida_prev_addr)[2:].upper()})",
                    "Overwrite", "Keep",
                    icon="WARNING"
                ).show() == ASKBTN_BTN1:
                    set_name(
                        ida_prev_addr,
                        f"sub_{hex(ida_prev_addr)[2:]}",
                        SN_NOWARN
                    )

        return renamed

    @staticmethod
    def get_ida_path(path: str) -> Path:
        """
        Gets a path relative to the IDA root folder.

        Returns:
            Path: The path as a pathlib.Path
        """
        return Path(idadir(path))

    @staticmethod
    def get_function_info(
        ida_ea: int,
        force: bool = False
    ) -> ida_func_type_data_t | None:
        """
        Gets the info of the function at the given address.

        Args:
            ida_ea (int): The function's address.
            force (bool, optional): If the data should be forcefully
                obtained using recovery methods like decompilation.
                Defaults to False.

        Returns:
            ida_typeinf.func_type_data_t | None: The `ida_typeinf.func_type_data_t` of
                the function or `None` if unable to get function info.
        """
        tif = ida_tinfo_t()
        if get_tinfo(tif, ida_ea) and tif.is_func():
            fi = ida_func_type_data_t()
            if tif.get_func_details(fi):
                return fi

        if not force:
            return None

        try:
            from ida_hexrays import decompile
            cfunc = decompile(ida_ea)
            if cfunc is not None:
                return IDAUtils.get_function_info(ida_ea)
        except ImportError:
            pass

        return None

    @staticmethod
    def is_library_function(func: ida_func_t) -> bool:
        """
        Checks if a function is a library function.
        Has some heuristics to detect false library functions.

        Args:
            func (ida_funcs.func_t): The function to check.

        Returns:
            bool
        """
        if func is None:
            return False

        ida_is_lib = bool(func.flags & FUNC_LIB)

        if ida_is_lib and func.size() in IDAUtils.get_thunk_size():
            return True

        # skimmed thru 2.2082 and 450 seemed to be the size where
        # library and random garbage funcs became actual functions
        if IDAUtils.get_platform() == "win":
            if ida_is_lib and func.size() >= 450:
                func.flags &= ~FUNC_LIB
                set_name(func.start_ea, "", SN_NOWARN)

        return False

    @staticmethod
    def get_type_info(name: str) -> ida_tinfo_t | None:
        """
        Gets the info about a type/struct.

        Args:
            name (str): The name of the type/struct.

        Returns:
            ida_typeinf.tinfo_t | None
        """
        tif = ida_tinfo_t()
        return tif if tif.get_named_type(get_idati(), name) else None

    @staticmethod
    def is_corrupted_type(t: ida_tinfo_t | None) -> bool:
        """
        True only if `t` exists but is structurally broken
        (BADADDR size or an unresolved forward-declaration).

        Args:
            t (ida_typeinf.tinfo_t | None)

        Returns:
            bool
        """
        return t is not None and (t.get_size() == BADADDR or t.is_forward_decl())

    @staticmethod
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

        tif_a = IDAUtils.get_type_info(name_a)
        tif_b = IDAUtils.get_type_info(name_b)

        if tif_a is None or tif_b is None:
            return False

        return tif_a.equals_to(tif_b)

    @staticmethod
    def get_dirtree_entries(
        tree: TreeType,
        path: str = "/"
    ) -> list[DirtreeEntry]:
        """
        Gets the entries of a dirtree (`dirtree_id_t`)

        Args:
            tree (int | ida_dirtree_t): The dirtree to get entries from
            path (str, defaults to "/"): The path inside the tree
                to get entries from

        Returns:
            list[tuple[ida_dirtree_cursor_t, ida_direntry_t]]:
                List of tuples containing the cursor and direntry
        """
        tree = get_std_dirtree(tree) if isinstance(tree, int) else tree

        collector = IDAUtils.DirtreeCollector(tree, path)
        return collector.entries

    @staticmethod
    def visit_dirtree(
        tree: TreeType,
        predicate: Callable[[ida_direntry_t, str], bool],
        visit: Callable[[ida_direntry_t, str], bool],
        path: str = "/"
    ) -> list[DirtreeEntry]:
        """
        Visits dirtree entries and executes a function on them
        if they satisfy a predicate.

        Args:
            tree (int | ida_dirtree_t): The dirtree to get entries from.
            predicate (Callable[[ida_direntry_t, str], bool]):
                The predicate to test entries with.
            visit (Callable[[ida_direntry_t, str], bool]):
                The function to execute on entries that satisfy the predicate.

        Returns:
            list[tuple[ida_direntry_t, str]]:
                List of tuples containing the direntry and path of failed entries.
        """  # noqa: E501
        tree = get_std_dirtree(tree) if isinstance(tree, int) else tree

        executor = IDAUtils.DirtreeExecutor(tree, predicate, visit, path)
        return executor.failed_entries

    @staticmethod
    def get_entry_abspath(tree: TreeType, entry: ida_direntry_t) -> str:
        """
        Gets the absolute path of the current IDA dirtree entry.

        Args:
            tree (int | ida_dirtree_t): The dirtree of the entry.
            entry (ida_direntry_t): The entry to get the path of.

        Returns:
            str
        """
        tree = get_std_dirtree(tree) if isinstance(tree, int) else tree
        return tree.get_abspath(tree.find_entry(entry))

    @staticmethod
    def chdir_dirtree_entries(
        tree: TreeType, path: str, entries: list[DirtreeEntry]
    ) -> None:
        """
        Changes the directory of dirtree entries to a new path.

        Args:
            tree (int): The dirtree of the entries.
            path (str): The new path inside the tree.
            entries (list[tuple[ida_dirtree_cursor_t, ida_direntry_t]]):
                The entries to change directory.
        """
        tree = get_std_dirtree(tree) if isinstance(tree, int) else tree

        for _, entry_path in entries:
            tree.rename(f"{entry_path}", f"{path}{entry_path}")

from copy import deepcopy
from collections import deque
from functools import cache

from idc import SetType
from ida_funcs import (
    get_func, add_func,
    get_func_cmt, set_func_cmt
)
from ida_kernwin import (
    warning as ida_warning,
    ASKBTN_BTN1, ASKBTN_BTN2, ASKBTN_BTN3
)
from ida_typeinf import (
    get_idati, set_c_header_path,
    func_type_data_t as ida_func_type_data_t,
    tinfo_t as ida_tinfo_t, udt_type_data_t as ida_udt_type_data_t,
    apply_tinfo, TINFO_DEFINITE, BTF_TYPEDEF
)
from ida_name import get_ea_name, GN_SHORT, GN_DEMANGLED
from idautils import Names
from ida_dirtree import (
    get_std_dirtree,
    direntry_t as ida_direntry_t,
    DIRTREE_LOCAL_TYPES
)
from ida_nalt import (
    get_imagebase, get_root_filename
)

from re import sub
from pathlib import Path
from hashlib import file_digest

from pybroma import Root, Class

from broma_ida.broma.argtype import STLNode, STLUtils, ArgType, RetType
from broma_ida.broma.constants import BROMA_PLATFORMS, BROMA_PLATFORM_GROUPS
from broma_ida.broma.binding import Binding
from broma_ida.broma.codegen import BromaCodegen
from broma_ida.broma.class_graph import STLStubDefinition, STLTypeDefinitions, ClassGraph
from broma_ida.utils import (
    path_exists, stop,
    IDAUtils, DirtreeEntry,
    HAS_IDACLANG
)

from broma_ida.data.data_manager import DataManager

from broma_ida.ui.simple_popup import SimplePopup
from broma_ida.ui.directory_input_form import DirectoryInputForm
from broma_ida.ui.ask_popup import AskPopup
from broma_ida.ui.wait_box import WaitBox
from broma_ida.ui.temp_jump_to_address import TempJumpToAddress

if HAS_IDACLANG:
    from ida_srclang import (
        set_parser_argv, parse_decls_with_parser,
        select_parser_by_name as select_srclang_parser_by_name
    )


class VerifyUtils:
    """Used to verify structs and types for BromaImporter."""

    @staticmethod
    def stl_nodes_equivalent(node_a: "STLNode", node_b: "STLNode") -> bool:
        """
        Check if two STLNode instances are the same.

        Args:
            node_a (STLNode)
            node_b (STLNode)

        Returns:
            bool
        """
        a_ptr = "*" if node_a.ptr in ("*", "&") else ""
        b_ptr = "*" if node_b.ptr in ("*", "&") else ""

        # staz be damned the IDA type library can work a const
        if node_a.const != node_b.const or a_ptr != b_ptr:
            return False

        if node_a.is_stl or node_b.is_stl:
            if node_a.name != node_b.name or len(node_a.args) != len(node_b.args):
                return False

            return all(
                VerifyUtils.stl_nodes_equivalent(x, y)
                for x, y in zip(node_a.args, node_b.args)
            )

        return IDAUtils.types_equivalent(node_a.name, node_b.name)

    @staticmethod
    def _stub_matches(stub: STLStubDefinition) -> bool:
        t = IDAUtils.get_type_info(stub.class_name)
        if t is None:
            return True

        if IDAUtils.is_corrupted_type(t):
            return False

        udt = ida_udt_type_data_t()
        if not t.get_udt_details(udt) or udt.size() != len(stub.members):
            return False

        for member, stlmember in zip(udt, stub.members):
            ida_str = STLUtils.to_ida_equivalent(
                STLUtils.normalize_type(str(member.type))
            )
            expected_str = STLUtils.to_ida_equivalent(
                STLUtils.normalize_type(stlmember.type)
            )

            ida_node = STLUtils.collapse_stl_type(
                STLUtils.split_stl_type(ida_str)
            )
            expected_node = STLUtils.collapse_stl_type(
                STLUtils.split_stl_type(expected_str)
            )

            if not VerifyUtils.stl_nodes_equivalent(ida_node, expected_node):
                return False

        return True

    @staticmethod
    def verify_stl_structs(defs: STLTypeDefinitions) -> bool:
        """
        Verifies if there is a mismatch between the ClassGraph's
        STL structs and the imported structs.

        Args:
            defs (STLTypeDefinitions)

        Returns:
            bool: True on success
        """
        if not (VerifyUtils._stub_matches(defs.ptr) \
                and VerifyUtils._stub_matches(defs.value)):
            return False

        return True

    @staticmethod
    def verify_types_preimport(defs: STLTypeDefinitions) -> bool:
        """
        Verify if there are any mismatches between current
        STL structs from ClassGraph and any previously
        imported ones.
        Used before types are imported.

        Args:
            defs (STLTypeDefinitions)

        Returns:
            bool: True on success
        """
        if DataManager().get("ignore_mismatched_structs"):
            return True

        if not VerifyUtils.verify_stl_structs(defs):
            if AskPopup(
                "Mismatch from previously imported STL types!\n\n"
                "It is recommended to cancel the current type import, "
                "go to the 'Local Types' subview, delete the\n"
                "'BromaIDA' dirtree (you might have to right-click -> Show folders), "
                "and then save the IDB.\n\n"
                "Continue to overwrite previous types anyway?",
                "Overwrite", "Cancel",
                icon="WARNING"
            ).show() != ASKBTN_BTN1:
                return False

        return True

    @staticmethod
    def verify_types_postimport(defs: STLTypeDefinitions) -> bool:
        """
        Verifies the existence of the imported STL structs
        and some sample Cocos2d-x types.
        Used to check if importation succeeded
        without silent faults.

        Args:
            defs (STLTypeDefinitions)

        Returns:
            bool: True on success
        """
        if not VerifyUtils.verify_stl_structs(defs):
            ida_warning(
                "Faulty STL struct found when checking imported types!\n\n"
                "It is recommended to go to the 'Local Types' subview, "
                "delete the 'BromaIDA' dirtree\n"
                "(you might have to right-click -> Show folders), "
                "and then save the IDB before importing types again.\n\n"
            )
            return False

        if any((
            IDAUtils.is_corrupted_type(IDAUtils.get_type_info(t))
            for t in (
                "cocos2d::CCObject", "cocos2d::CCNode", "cocos2d::CCImage",
                "cocos2d::CCApplication", "cocos2d::CCDirector"
            )
        )):
            ida_warning(
                "Faulty struct found when checking imported types!\n\n"
                "It is recommended to go to the 'Local Types' subview, "
                "delete the 'BromaIDA' dirtree\n"
                "(you might have to right-click -> Show folders), "
                "and then save the IDB before importing types again.\n\n"
            )
            return False

        return True


class BIUtils:
    """BromaImporter utilities"""

    _common_clang_argv = "-x c++ -nostdlib -nostdinc -nostdinc++"

    _plat_to_parser_argv: dict[BROMA_PLATFORMS, str] = {
        "win": "-target x86_64-pc-win32",
        "imac": "-target x86_64-apple-darwin",
        "m1":  "-target arm64-apple-darwin",
        "ios": "-target arm64-apple-darwin",
        "android32":  "-target armv7-none-linux-androideabi",
        "android64": "-target aarch64-none-linux-android"
    }

    _plat_to_stl_name: dict[BROMA_PLATFORMS, str] = {
        "win": "windows",
        "android32": "android",
        "android64": "android",
        "imac": "macho",
        "m1": "macho",
        "ios": "macho"
    }

    @staticmethod
    def get_parser_argv(platform: BROMA_PLATFORMS) -> str:
        """
        Gets the parser arguments for a certain platform.

        Args:
            platform (BROMA_PLATFORMS)

        Returns:
            str
        """
        return f"""{
            BIUtils._common_clang_argv
        } {BIUtils._plat_to_parser_argv[platform]}"""

    @staticmethod
    def get_stl_headers_path(platform: BROMA_PLATFORMS, headers_root: Path) -> str:
        """
        Gets the STL headers path for a given platform.

        Args:
            platform (BROMA_PLATFORMS)
            headers_root (pathlib.Path): pathlib.Path to the root folder
                of where the headers are located.

        Returns:
            str
        """
        return str(headers_root / "c++stl" / BIUtils._plat_to_stl_name[platform])

    @staticmethod
    def prompt_invalid_dir(input_str: str, dm_key: str):
        """
        Shows a warning and prompts the user to input a valid directory.
        Saves the directory to the DataManager.

        Args:
            input_str (str)
            dm_key (str)
        """
        ida_warning(
            f"Importing types with an invalid {input_str}!\n"
            "Please set one!"
        )
        dir_form = DirectoryInputForm(input_str)
        dir_form.show()

        dir_str = dir_form.saved_controls.iDir

        if not path_exists(dir_str):
            BIUtils.prompt_invalid_dir(input_str, dm_key)

        DataManager().set(dm_key, dir_str)

    @staticmethod
    def move_type_entries_to_bromaida() -> None:
        """Moves imported type entries to '/BromaIDA' in the Local Types tree."""
        dirtree = get_std_dirtree(DIRTREE_LOCAL_TYPES)
        entries = IDAUtils.get_dirtree_entries(
            DIRTREE_LOCAL_TYPES, "/"
        )
        found_first = False

        for _, path in entries:
            if path in \
                    ["/SearchType", "/cocos2d::CCNode", "/cocos2d::CCLayer"]:
                found_first = True

            if path.count("/") > 1 or not found_first:
                continue

            dirtree.rename(f"{path}", f"/BromaIDA{path}")

            # this will add other entries added after imported types
            # nothing much i can do abt that :/

    @staticmethod
    def dirtree_is_bromaida_entry(de: ida_direntry_t, ep: str) -> bool:
        """
        Predicate to check if a dirtree entry is in '/BromaIDA'.

        Args:
            de (ida_direntry_t)
            ep (str)

        Returns:
            bool
        """
        return ep.startswith("/BromaIDA/")

    @staticmethod
    def delete_dirtree_entry(de: ida_direntry_t, ep: str) -> bool:
        """
        Deletes a dirtree entry.

        Args:
            de (ida_direntry_t)
            ep (str)
        """
        return get_std_dirtree(DIRTREE_LOCAL_TYPES).unlink(ep) == 0x0

    # Signature stuff

    @staticmethod
    def has_mismatch(
        function: ida_func_type_data_t | None,
        binding: Binding
    ) -> bool:
        """
        Checks if there is a mismatch between the IDB and a binding.

        Args:
            function (func_type_data_t | None):
                The function signature returned by IDA.
            binding (Binding): The binding.

        Returns:
            bool
        """
        if function is None:
            return True

        # constructors and destructors have no return types
        # just let IDA do what it has to with them
        if binding.ret.type != "" \
                and STLUtils.normalize_type(str(function.rettype)) != binding.ret.type:
            return True

        # IDA might've guessed extra arguments,
        # then we'll have an out-of-range index
        # when checking the binding
        if len(function) != len(binding.parameters) + (0 if binding.is_static else 1):
            return True

        for i, arg in enumerate(function):
            ida_arg = STLUtils.normalize_type(
                str(arg.type)
            )

            if i == 0 and not binding.is_static:
                if ida_arg != f"{binding.class_name}*":
                    return True
            elif ida_arg != STLUtils.to_ida_equivalent(
                binding.parameters[
                    i - (0 if binding.is_static else 1)
                ].type
            ):
                return True

        return False

    @staticmethod
    def set_function_signature(ea: int, binding: Binding):
        """
        Sets the function at `ea`'s signature. Has custom logic for
        functions that use STL types since those break when using SetType
        due to the use of commas in the function argument types.

        Args:
            ea (int)
            binding (Binding)
        """
        if not binding.needs_stl_fixup:
            SetType(ea, binding.signature)
            return

        binding_fix = deepcopy(binding)
        arg_stl_idx: list[int] = []

        if binding.has_stl_args:
            for i in range(len(binding_fix.parameters)):
                if binding_fix.parameters[i].stripped_type != "std::string" \
                        and "std::" in binding_fix.parameters[i].type:
                    arg_stl_idx.append(i)
                    binding_fix.parameters[i] = ArgType("void*", binding_fix.parameters[i].name)

        if binding.has_stl_ret:
            binding_fix.ret = RetType("void*", binding_fix.ret.name)

        # first set correct amount of arguments
        SetType(ea, binding_fix.signature)

        function_data = IDAUtils.get_function_info(ea, True)

        if function_data is None:
            print(
                "[!] BromaImporter: Couldn't fix "
                "STL parameters for "
                f"function {binding.qualified_name}! "
                "(function is null)"
            )
            return

        # then fix the arguments
        for idx in arg_stl_idx:
            stl_type = ida_tinfo_t()
            stl_type.get_named_type(
                get_idati(),
                binding.parameters[idx].stripped_expanded_type,
                BTF_TYPEDEF,
                False
            )

            if stl_type.get_ordinal() == 0:
                print(
                    f"[!] BromaImporter: STL Type "
                    f"'{stl_type.get_type_name()}' "
                    "isn't present in the type library! "
                    "Please open a GitHub issue."
                )
                return

            if "const" in binding.parameters[idx].type:
                stl_type.set_const()

            if binding.parameters[idx].type.endswith("&") or \
                    binding.parameters[idx].type.endswith("*"):
                stl_type_ptr = ida_tinfo_t()
                stl_type_ptr.create_ptr(stl_type)

                stl_type = stl_type_ptr

            try:
                function_data[
                    idx + (0 if binding.is_static else 1)
                ].type = stl_type
            except IndexError:
                print(
                    "[!] BromaImporter: Couldn't fix "
                    "STL parameters for "
                    f"function {binding.qualified_name}! "
                    "(parameter index out of range)"
                )
                return

        if binding.has_stl_ret:
            stl_type = ida_tinfo_t()
            stl_type.get_named_type(
                get_idati(),
                binding.ret.stripped_expanded_type,
                BTF_TYPEDEF,
                False
            )

            if binding.ret.type.endswith("&") or \
                    binding.ret.type.endswith("*"):
                stl_type_ptr = ida_tinfo_t()
                stl_type_ptr.create_ptr(stl_type)

                stl_type = stl_type_ptr

            function_data.rettype = stl_type

        func_tinfo = ida_tinfo_t()
        func_tinfo.create_func(function_data)

        # and finally apply the actual correct type
        apply_tinfo(ea, func_tinfo, TINFO_DEFINITE)


class BromaImporter:
    """Broma importer of all time using PyBroma now!"""

    _target_platform: BROMA_PLATFORMS
    _bromas_path: Path
    _headers_path: Path
    _imported_types: list[DirtreeEntry] = []
    _broma_files: dict[str, Root] = {}
    _graph: ClassGraph
    _codegen: BromaCodegen

    has_types: bool = False
    bindings: deque[Binding] = deque()
    classes: dict[str, Class] = {}
    duplicates: dict[int, list[Binding]] = {}

    def _is_class_present(self, class_name: str) -> bool:
        """
        Check if the current binary has certain
        classes present on it.

        Args:
            class_name: str

        Returns:
            bool
        """
        binary_name = get_root_filename().lower()

        if self._target_platform == "win":
            # what the heck
            is_cocos = (
                class_name.startswith("cocos2d")
                or class_name.startswith("pugi")
                or class_name == "DS_Dictionary"
                or class_name == "ObjectDecoder"
                or class_name == "ObjectDecoderDelegate"
                or class_name == "CCContentManager"
            )
            is_cocos_ext = class_name.startswith("cocos2d::extension")
            # custom RobTop class, compiled into GeometryDash.exe
            is_exception = (class_name == "cocos2d::CCLightning")

            if binary_name.startswith("libcocos2d"):    # libcocos2d.dll
                return is_cocos and not is_cocos_ext and not is_exception

            if binary_name.startswith("libextensions"): # libExtensions.dll
                return is_cocos_ext

            return (not is_cocos) or is_exception       # GeometryDash.exe

        return True

    @cache
    def _get_input_file_hashes(self) -> str:
        """
        Gets the hashes key of the input files.

        Returns:
            str: Hash of each Broma input file joined by ','.
        """
        hash: str = ""

        for bfile in self._broma_files.keys():
            with open(self._bromas_path / bfile, "rb", buffering = 0) as f:
                hash += file_digest(f, "sha256").hexdigest() + ","

        return hash[:-1]

    def _preload_broma_files(self):
        """
        Pre-loads all the Broma files needed for importing
        Geometry Dash's classes and bindings, relative to
        the current binary's target platform.
        """
        bfiles = [
            "Cocos2d.bro",
            # this only references GeometryDash types by-pointer,
            # but it's not vice-versa for GeometryDash.bro
            "Extras.bro",
            "FMOD.bro",
            "GeometryDash.bro",
            "Kazmath.bro"
        ]

        for bfile in bfiles:
            bro_path = self._bromas_path / bfile
            if not bro_path.exists():
                # TODO: think if we could make use of prompt_invalid_dir from BIUtils
                # to receive a new directory if import fails.
                ida_warning(
                    f"Broma file '{bfile}' not found during pre-load!\n"
                    "No bindings (or types) were imported."
                )
                stop()

            # TODO: error check for this
            self._broma_files[bfile] = Root(str(bro_path))

    def _load_broma_classes(self):
        for bfile, root in self._broma_files.items():
            for cls in root.classes:
                if self._target_platform in cls.attrs.missing:
                    continue

                if cls.name in self.classes:
                    print(
                        "[!] BromaImporter: Duplicate class definition! "
                        f"({cls.name} from {bfile}) "
                        "Overwriting..."
                    )

                if len(cls.fields) == 0:
                    print(
                        "[!] BromaImporter: Found empty class definition "
                        f"({cls.name} from {bfile}). "
                    )
                    
                self.classes[cls.name] = cls

    def _load_broma_bindings(self):
        """Gather all the needed bindings from the Broma files."""
        # finding duplicate binds on Android is mostly impossible
        # due to the compiler not inlining almost any functions
        if self._target_platform.startswith("android"):
            for class_name, broma_class in self.classes.items():
                for field in broma_class.fields:
                    function_field = field.getAsFunctionBindField()

                    if function_field is None:
                        continue

                    self.bindings.append(
                        Binding.from_field(class_name, function_field)
                    )

            for bfile in self._broma_files.values():
                for func in bfile.functions:
                    if self._target_platform in func.proto.attrs.missing:
                        continue

                    raw_addr = getattr(func.binds, self._target_platform, -1)
                    if raw_addr in (-1, -2):
                        continue

                    self.bindings.append(
                        Binding.from_freefunc(func)
                    )

            return

        for class_name, broma_class in self.classes.items():
            if not self._is_class_present(class_name):
                continue

            for field in broma_class.fields:
                function_field = field.getAsFunctionBindField()

                if function_field is None:
                    continue

                func_addr = getattr(
                    function_field.binds,
                    self._target_platform,
                    -1
                )

                # -2 is explicitly inlined, -1 is missing
                if func_addr == -1 or func_addr == -2:
                    continue

                function = function_field.prototype

                # Runs only for the first time an address has a duplicate
                if func_addr in self.bindings:
                    dup_binding = self.bindings[
                        self.bindings.index(func_addr) # type: ignore
                    ]
                    error_location = \
                        f"{class_name}::{function.name} " \
                        f"and {dup_binding.short_info}"

                    if f"{class_name}::{function.name}" == \
                            dup_binding.qualified_name:
                        print(
                            "[!] BromaImporter: Duplicate binding with "
                            f"same qualified name! ({error_location})"
                        )
                        continue
                    elif class_name == dup_binding.class_name:
                        print(
                            "[!] BromaImporter: Duplicate binding within "
                            f"same class! ({error_location})"
                        )
                        continue

                    print(
                        "[!] BromaImporter: Duplicate binding! "
                        f"({class_name}::{function.name} "
                        f"and {dup_binding.short_info})"
                    )
                    self.bindings.remove(dup_binding)
                    self.duplicates[func_addr] = []
                    self.duplicates[func_addr].append(dup_binding)

                if func_addr in self.duplicates:
                    self.duplicates[func_addr].append(
                        Binding.from_field(class_name, function_field)
                    )
                    continue

                self.bindings.append(
                    Binding.from_field(class_name, function_field)
                )

        for bfile in self._broma_files.values():
            for func in bfile.functions:
                if self._target_platform in func.proto.attrs.missing:
                    continue

                raw_addr = getattr(func.binds, self._target_platform, -1)
                if raw_addr in (-1, -2):
                    continue

                self.bindings.append(
                    Binding.from_freefunc(func)
                )

    def _pre_import_types(self):
        """Pre-import types hook"""
        dirtree = get_std_dirtree(DIRTREE_LOCAL_TYPES)
        self._imported_types = IDAUtils.get_dirtree_entries(dirtree, "/")

        mkdir_ret = dirtree.mkdir("/BromaIDA")

        for _, path in self._imported_types:
            if path in \
                    ["/SearchType", "/cocos2d::CCNode", "/cocos2d::CCLayer"]:
                print("[+] BromaImporter: Moving existing types to /BromaIDA")
                BIUtils.move_type_entries_to_bromaida()
                break

        if mkdir_ret != 0:
            IDAUtils.visit_dirtree(
                dirtree,
                BIUtils.dirtree_is_bromaida_entry,
                BIUtils.delete_dirtree_entry
            )

    def _post_import_types(self):
        """Post-import types hook"""
        new_types = IDAUtils.get_dirtree_entries(
            DIRTREE_LOCAL_TYPES, "/"
        )
        old_types_paths = [path for _, path in self._imported_types]
        self._imported_types = []

        # direntry_t is unhashable so we manually deduplicate
        for _, path in new_types:
            if path not in old_types_paths:
                self._imported_types.append((_, path))

        IDAUtils.chdir_dirtree_entries(
            DIRTREE_LOCAL_TYPES, "/BromaIDA", self._imported_types
        )

    def __init__(self, platform: BROMA_PLATFORMS, hdrpath: Path, bpath: Path):
        """
        Initializes a BromaImporter instance.

        Args:
            platform (BROMA_PLATFORMS): The target platform.
            hdrpath (pathlib.Path): The folder that points to
                where the headers are stored.
            bpath (pathlib.Path): The folder path with the relevant
                Broma binding files.
        """
        self._reset()
        self._target_platform = platform
        self._headers_path = hdrpath
        self._bromas_path = bpath

        self._preload_broma_files()
        self._load_broma_classes()
        self._graph = ClassGraph(self.classes)
        self._codegen = BromaCodegen(
            self._target_platform,
            self.classes,
            self._graph,
            self._headers_path,
            self._bromas_path
        )

    def parse_bromas(self):
        """
        Parses the Broma files as classes and bindings,
        then also imports the methods and members through
        Codegen if importing types is enabled in settings.
        """
        import_types: bool = DataManager().get("import_types")

        if not HAS_IDACLANG and import_types:
            ida_warning(
                "Trying to import types without IDAClang!\n"
                "Disabling importing of types..."
            )
            DataManager().set("import_types", False)
            import_types = False

        if import_types:
            # Hash check for bindings
            if not DataManager().get("disable_input_hash_check"):
                input_hashes = self._get_input_file_hashes()
                # replaced last_broma_info for better target platform support
                last_import_hashes: dict[str, str] = DataManager().get("last_import_file_hashes", {})

                if last_import_hashes.get(self._target_platform) == input_hashes:
                    SimplePopup(
                        "Detected same Broma input file hashes.\n"
                        "Type import will be skipped.\n\n"
                        "You can disable this check in 'Settings'.",
                        "OK"
                    ).show()
                    import_types = False
            else:
                print(
                    "[!] BromaImporter: Broma input files hash check disabled. "
                    "Skipping..."
                )

        if import_types:
            if VerifyUtils.verify_types_preimport(self._graph.stl_type_definitions):
                type_prompt = AskPopup(
                    "Importing Types...\n"
                    "This can possibly freeze IDA for up to minutes.\n"
                    "Click on 'OK' to confirm.",
                    "OK", "Skip This Time", "Always Skip"
                ).show()

                if type_prompt == ASKBTN_BTN2:
                    print("[!] BromaImporter: Types import cancelled by user for this time.")
                elif type_prompt == ASKBTN_BTN3:
                    DataManager().set("import_types", False)
                    print("[!] BromaImporter: Types import cancelled and disabled by user.")
                else:
                    self.has_types = self.import_types()

                if self.has_types:
                    dm = DataManager()
                    saved_hashes = dm.get("last_import_file_hashes", {})
                    saved_hashes[self._target_platform] = self._get_input_file_hashes()
                    dm.set("last_import_file_hashes", saved_hashes)

                    print(
                        f"\n\n[+] BromaImporter: Successfully "
                        f"imported types from {len(self.classes)} "
                        "Broma classes."
                    )
                else:
                    self.has_types = len(IDAUtils.get_dirtree_entries(
                        DIRTREE_LOCAL_TYPES, "/BromaIDA"
                    )) != 0
            else:
                self.has_types = len(IDAUtils.get_dirtree_entries(
                    DIRTREE_LOCAL_TYPES, "/BromaIDA"
                )) != 0

            if self.has_types:
                self._post_import_types()

        self._load_broma_bindings()

        print(
            f"\n\n[+] BromaImporter: Read {len(self.bindings)} "
            f"{IDAUtils.get_platform_printable()} bindings, "
            f"{len(self.duplicates)} duplicates "
            f"and {len(self._broma_files)} Broma files "
            f"from {str(self._bromas_path)}"
        )

    def import_types(self):
        """
        Import types into IDA using
        BromaCodegen and the Clang parser.
        """
        types_file = self._codegen.write()
        srclang_parser = IDAUtils.get_srclang_parser()
        select_srclang_parser_by_name(srclang_parser)

        if DataManager().get("set_default_parser_args"):
            set_parser_argv(
                srclang_parser,
                BIUtils.get_parser_argv(self._target_platform)
            )

        set_c_header_path(
            BIUtils.get_stl_headers_path(self._target_platform, self._headers_path)
        )

        with WaitBox("Importing types..."):
            self._pre_import_types()

            parse_decls_with_parser(
                srclang_parser,
                None,
                types_file.as_posix(),
                True
            )

        return VerifyUtils.verify_types_postimport(self._graph.stl_type_definitions)

    def import_into_idb(self):
        """
        Imports the parsed bindings from the Broma files
        into the current IDB.
        """
        total_bindings = len(self.bindings)
        resolved_count = 0

        if self._target_platform.startswith("android"):
            if not self.has_types:
                return

            ida_addresses: dict[str, int] = {}

            for addr, _ in Names():
                demangled_name = sub(
                    r"(\S+)::(\S+)\(.*\)",
                    r"\1::\2",
                    get_ea_name(addr, GN_SHORT | GN_DEMANGLED)
                )
                ida_addresses[demangled_name] = addr

            while self.bindings:
                binding = self.bindings.pop()

                ida_ea = ida_addresses.get(binding.qualified_name, -0x1)

                if ida_ea == -0x1:
                    continue

                resolved_count += 1

                if BIUtils.has_mismatch(
                    IDAUtils.get_function_info(ida_ea),
                    binding
                ):
                    if not DataManager().get("debug_info"):
                        print(
                            "[+] BromaImporter: Function signature mismatch between "
                            f"Broma and IDB ({binding.short_info})! "
                            "Attempting to correct..."
                        )
                    BIUtils.set_function_signature(ida_ea, binding)

            print(
                f"[+] BromaImporter: Resolved {resolved_count}/"
                f"{total_bindings} bindings from the Broma files."
            )
            return

        # first, handle non-duplicates
        while self.bindings:
            binding = self.bindings.pop()

            ida_ea = get_imagebase() + binding.address
            ida_name = get_ea_name(ida_ea)
            ida_func = get_func(ida_ea)

            if ida_name.startswith("loc_"):
                add_func(ida_ea)

            if IDAUtils.is_library_function(get_func(ida_ea)):
                print(
                    f"[!] BromaImporter: Tried to rename a library function! "
                    f"({binding.short_info})"
                )
                continue

            # is_library_function can change func name
            # if it was a false positive
            ida_name = get_ea_name(ida_ea)
            ida_func = get_func(ida_ea)

            if ida_func is None \
                    and not DataManager().get("ignore_unmarked_functions"):
                with TempJumpToAddress(ida_ea):
                    if AskPopup(
                        f"{hex(ida_ea)} is not marked as a function by "
                        "IDA.\nWould you like to mark it as a "
                        "function now?",
                        "Yes", "No",
                        icon="INFO"
                    ).show() == ASKBTN_BTN1:
                        add_func(ida_ea)
                        IDAUtils.get_function_info(ida_ea, True)
                        ida_func = get_func(ida_ea)
                    else:
                        continue

            if ida_func is None:
                print(
                    f"[!] BromaImporter: Couldn't retrieve function at "
                    f"{hex(ida_ea)}! ({binding.short_info})"
                )
                continue

            if ida_func.start_ea != ida_ea:
                print(
                    f"[!] BromaImporter: Function is in the middle of "
                    f"another one! ({binding.short_info})"
                )
                continue

            resolved_count += 1

            # types are needed because we can't
            # just apply one to any variable
            # without having it in the first place
            if self.has_types and BIUtils.has_mismatch(
                IDAUtils.get_function_info(ida_ea),
                binding
            ):
                if not DataManager().get("debug_info"):
                    print(
                        "[+] BromaImporter: Function signature mismatch between "
                        f"Broma and IDB ({binding.short_info})! "
                        "Attempting to correct..."
                    )
                BIUtils.set_function_signature(ida_ea, binding)

            if ida_name.startswith("sub_"):
                IDAUtils.rename_func(
                    ida_ea,
                    binding.ida_qualified_name
                )
            elif sub("_[0-9]+", "", ida_name) != binding.ida_qualified_name:
                if DataManager().get("always_overwrite_idb") or \
                    AskPopup(
                        f"""Mismatch in Broma ({binding.qualified_name}) """
                        f"and idb ({ida_name})!\n"
                        "Overwrite from Broma or keep current name?",
                        "Overwrite", "Keep",
                        icon="WARNING"
                ).show() == ASKBTN_BTN1:
                    IDAUtils.rename_func(
                        ida_ea,
                        binding.ida_qualified_name
                    )

        # and now handle duplicates
        total_duplicate_bindings = sum(len(b) for b in self.duplicates.values())
        resolved_duplicate_bindings = 0

        for addr, bindings in self.duplicates.items():
            ida_ea = get_imagebase() + addr
            ea_func = get_func(ida_ea)

            if ea_func is None:
                print(
                    "[!] BromaImporter: Couldn't retrieve function for merged "
                    f"duplicates at {hex(ida_ea)}! Skipping. (Would've merged: "
                    f"{', '.join(b.qualified_name for b in bindings)})"
                )
                continue

            resolved_duplicate_bindings += len(bindings)

            func_cmt: str = get_func_cmt(ea_func, True) or ""
            func_names = ", ".join(
                [binding.qualified_name for binding in bindings]
            )

            if func_cmt == "":
                # use the first occurrence as the name (very good imo)
                IDAUtils.rename_func(
                    ida_ea,
                    bindings[0].ida_qualified_name
                )

                set_func_cmt(ea_func, f"Merged with: {func_names}", True)
            elif func_cmt.startswith("Merged with: "):
                cmt_func_names = func_cmt.removeprefix("Merged with: ")

                # suppress the warning if IDA had truncated
                # the string cause of character limits
                if func_names[:len(cmt_func_names)] == cmt_func_names:
                    continue

                if set(func_names.split(", ")) != \
                        set(cmt_func_names.split(", ")):
                    print(
                        "[!] BromaImporter: Mismatch in merged function list "
                        f"(Current: {cmt_func_names} | "
                        f"Correct: {func_names})! Correcting..."
                    )
                    set_func_cmt(
                        ea_func, f"Merged with: {func_names}", True
                    )
            else:
                if DataManager().get(
                        "always_overwrite_merge_information"
                    ) or AskPopup(
                        f"{hex(addr)} already has a comment! "
                        "Would you like to overwrite it with "
                        "merge information or keep the current comment?\n"
                        "(You will be prompted with this again if you "
                        "keep the current comment and rerun the "
                        "script and there are merged functions!)\n"
                        "(You can enable 'Always overwrite function "
                        "comments with merge information' in settings "
                        "to get rid of this popup)",
                        "Overwrite", "Keep"
                ).show() == ASKBTN_BTN1:
                    set_func_cmt(
                        ea_func, f"Merged with: {func_names}", True
                    )

        total_resolved = resolved_count + resolved_duplicate_bindings
        total_all = total_bindings + total_duplicate_bindings

        print(
            f"[+] BromaImporter: Resolved and mapped {total_resolved}/{total_all} "
            f"bindings onto their respective addresses "
            f"({resolved_duplicate_bindings}/{total_duplicate_bindings} "
            "from merged duplicates)."
        )

    def _reset(self):
        """
        Resets the current BromaImporter instance.
        Not doing so would result in a re-run of
        the script populating the same parsed content.
        """
        self._target_platform = ""  # type: ignore
        self._headers_path = Path()
        self._bromas_path = Path()
        self._broma_files.clear()

        self.has_types = False
        self.bindings.clear()
        self.classes.clear()
        self.duplicates.clear()

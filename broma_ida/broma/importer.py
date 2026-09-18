from collections import deque, defaultdict
from functools import cache
from re import sub, match
from pathlib import Path
from hashlib import file_digest

from ida_funcs import (
    get_func, add_func,
    get_func_cmt, set_func_cmt
)
from ida_kernwin import (
    warning as ida_warning,
    ASKBTN_BTN1, ASKBTN_BTN2, ASKBTN_BTN3
)
from ida_typeinf import (
    set_c_header_path,
    func_type_data_t as ida_func_type_data_t,
    udt_type_data_t as ida_udt_type_data_t,
    tinfo_t as ida_tinfo_t
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

from pybroma import Root, Class, FunctionBindField

from broma_ida.broma.argtype import STLNode, STLUtils, ArgType
from broma_ida.broma.constants import BROMA_PLATFORMS, IDACallingConvention
from broma_ida.broma.binding import Binding
from broma_ida.broma.codegen import BromaCodegen
from broma_ida.broma.class_graph import STLStubDefinition, STLTypeDefinitions, ClassGraph
from broma_ida.utils import path_exists, CppUtils
from broma_ida.ida_utils import (
    IDAUtils, DirtreeEntry,
    stop, HAS_IDACLANG
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
        This does some IDA-specific normalization,
        but might be moved elsewhere later.

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
            ida_str = CppUtils.to_ida_equivalent(
                CppUtils.normalize_type(str(member.type))
            )
            expected_str = CppUtils.to_ida_equivalent(
                CppUtils.normalize_type(stlmember.type)
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
        STL structs and the imported type library structs.

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
        imported ones in the IDA type library.
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
        Used to check if importation succeeded without
        silent faults.

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
        Saves the directory to the DataManager key given.

        Args:
            input_str (str)
            dm_key (str): The key name to store
                the resulting input to in DataManager.
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

    @staticmethod
    def build_symbol_index() -> dict[str, list[int]]:
        """
        Indexes every named address in the current binary by its
        demangled qualified name (ClassName::method, argument list
        stripped), so overloads sharing a name collect under one key.
        Covers both natively-defined functions and imported symbols,
        since idautils.Names() enumerates both.

        Returns:
            dict[str, list[int]]: demangled qualified name -> addresses.
        """
        index: dict[str, list[int]] = defaultdict(list)

        for addr, _ in Names():
            demangled_name = sub(
                r"(\S+)::(\S+)\(.*\)",
                r"\1::\2",
                get_ea_name(addr, GN_SHORT | GN_DEMANGLED)
            )
            index[demangled_name].append(addr)

        return index

    @staticmethod
    def _params_match(arg_types: list["ida_tinfo_t | None"], binding: Binding) -> bool:
        if len(arg_types) != len(binding.parameters):
            return False

        for candidate, param in zip(arg_types, binding.parameters):
            # implicit skip for args that weren't demangled correctly from IDA
            if candidate is None:
                continue

            expected = IDAUtils.resolve_type_tinfo(param)
            if expected is not None and not candidate.equals_to(expected):
                return False

        return True

    @staticmethod
    def has_mismatch(
        function: "ida_func_type_data_t | None",
        binding: Binding
    ) -> bool:
        """
        Checks if there is a mismatch between the IDB and a binding.

        Args:
            function (ida_typeinf.func_type_data_t | None):
                The function type info container from IDA.
            binding (Binding): The binding.

        Returns:
            bool: True if mismatch exists between either the
                return type or the parameters.
        """
        needs_retptr = False
        if function is None:
            return True

        is_ellipsis_cc = function.get_cc() == IDACallingConvention.ellipsis
        if is_ellipsis_cc != binding.is_variadic:
            return True

        # do not check against TodoReturn placeholders
        expected_rettype = function.rettype
        if not binding.ida_rettype.type == "TodoReturn":
            resolved_ret = IDAUtils.resolve_type_tinfo(binding.ida_rettype)
            needs_retptr = resolved_ret is not None and resolved_ret.is_udt()

            expected_rettype = resolved_ret
            if needs_retptr:
                expected_rettype = ida_tinfo_t()
                expected_rettype.create_ptr(resolved_ret)

            if expected_rettype is not None and not function.rettype.equals_to(expected_rettype):
                return True

        funcargs = list(function)
        itanium_abi = IDAUtils.get_platform() != "win"

        if needs_retptr and itanium_abi:
            if not funcargs or not funcargs[0].type.equals_to(expected_rettype):
                return True
            funcargs = funcargs[1:]

        # check if there's a 'ClassName* this' argument would be passed to the function
        if binding.class_name != "" and not binding.is_static:
            if not funcargs:
                return True

            this_tinfo = IDAUtils.resolve_type_tinfo(ArgType(f"{binding.class_name}*"))
            if this_tinfo is not None and not funcargs[0].type.equals_to(this_tinfo):
                return True

            funcargs = funcargs[1:]

        if needs_retptr and not itanium_abi:
            if not funcargs or not funcargs[0].type.equals_to(expected_rettype):
                return True
            funcargs = funcargs[1:]

        arg_types = [arg.type for arg in funcargs]
        if not BIUtils._params_match(arg_types, binding):
            return True

        for ida_arg, param in zip(funcargs, binding.parameters):
            # pX is Broma auto-generated name, aX is IDA auto-generated name
            if match(r"(p|a)([0-9]+)", param.name) is None \
                    and ida_arg.name != param.name:
                return True

        return False

    # this is for functions that have a named symbol on the binary
    @staticmethod
    def resolve_overload(binding: Binding, candidates: list[int]) -> list[int]:
        """
        Resolve which overload of a function from available
        candidates fits best based on the Binding instance.

        Args:
            binding (Binding): The binding.
            candidates (list[int]): List of all candidates
                by their address in the binary.

        Returns:
            int | None: The selected candidate's address,
                or None if no candidate was fit.
        """
        if len(candidates) == 1:
            return candidates

        exact: list[int] = []
        plausible: list[int] = []

        for addr in candidates:
            info = IDAUtils.get_demangled_info(addr)
            if info is None:
                continue

            _, arg_strs, is_variadic = info
            if is_variadic != binding.is_variadic or len(arg_strs) != len(binding.parameters):
                continue

            # IDA might sometimes demangle arguments incorrectly
            # so implicitly give those back as None instead
            arg_tifs = [
                IDAUtils.resolve_bare_type(arg)
                if not CppUtils.looks_malformed(arg)
                else None
                for arg in arg_strs
            ]
            if not BIUtils._params_match(arg_tifs, binding):
                continue

            plausible.append(addr)
            if all(t is not None for t in arg_tifs):
                exact.append(addr)

        return exact or plausible

    @staticmethod
    def fix_function_signature(ea: int, binding: Binding) -> bool:
        """
        Rebuilds and applies the full function signature at `ea`
        from a Broma binding.

        Args:
            ea (int)
            binding (Binding)

        Returns:
            bool: True on success.
        """
        success = IDAUtils.apply_function_signature(
            ea,
            binding.ida_rettype,
            binding.parameters,
            binding.is_static,
            binding.is_variadic,
            class_name=binding.class_name
        )

        return success


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
    linked_bindings: list[Binding]
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
            # taken from Geode's bindings codegen as of GD 2.2082
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

        if self._target_platform == "android32" or self._target_platform == "android64":
            is_fmod = class_name.startswith("FMOD")

            if binary_name.startswith("libfmod"):       # libfmod.so
                return is_fmod

            return True

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

    def _preload_broma_files(self) -> None:
        """
        Pre-loads all the Broma files needed for importing
        Geometry Dash's classes and bindings, relative to
        the current binary's target platform.
        """
        # TODO: revert back to single-file import,
        # that's more manageable in the long term
        # than hand-writing these names that wouldn't
        # work for anything other than what they're
        # targetting anyway, i.e. GD 2.2081 here.
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

    def _load_broma_classes(self) -> None:
        """
        Iterates through all parsed class definitions
        and lists all of them in the classes property.
        Ignores classes with the missing attribute
        for the current target platform.
        """
        for _, root in self._broma_files.items():
            for cls in root.classes:
                if self._target_platform in cls.attrs.missing:
                    continue

                if cls.name in self.classes:
                    print(
                        "[!] BromaImporter: Duplicate class definition! "
                        f"({cls.name} from {cls.source})"
                    )

                if len(cls.fields) == 0:
                    print(
                        "[-] BromaImporter: Found empty class definition: "
                        f"({cls.name} from {cls.source})"
                    )

                self.classes[cls.name] = cls

    def _load_broma_bindings(self) -> None:
        """Gather all the needed bindings from the Broma files."""
        for class_name, broma_class in self.classes.items():
            class_present = self._is_class_present(class_name)

            for field in broma_class.fields:
                function_field = field.getAsFunctionBindField()
                if function_field is None:
                    continue

                proto = function_field.prototype

                if class_present:
                    func_addr = getattr(
                        function_field.binds, self._target_platform, -1
                    )

                    # -2 is explicitly inlined, -1 is missing/unbound
                    if func_addr not in (-1, -2):
                        self._add_binding(
                            class_name, function_field, func_addr
                        )

                if self._target_platform in proto.attrs.links and \
                        self._target_platform not in proto.attrs.missing:
                    self.linked_bindings.append(
                        Binding.from_field(class_name, function_field)
                    )

        for bfile in self._broma_files.values():
            for func in bfile.functions:
                # check for missing attribute was moved to
                # import_into_idb for logging purposes
                proto = func.prototype

                raw_addr = getattr(func.binds, self._target_platform, -1)
                if raw_addr not in (-1, -2):
                    self.bindings.append(Binding.from_freefunc(func))

                if self._target_platform in proto.attrs.links and \
                        self._target_platform not in proto.attrs.missing:
                    self.linked_bindings.append(Binding.from_freefunc(func))

    def _add_binding(
        self,
        class_name: str,
        function_field: FunctionBindField,
        func_addr: int
    ) -> None:
        """
        Checks the binding against currently resolved
        bindings and adds it to the appropriate collection
        between duplicates and non-duplicate bindings.
        """
        function = function_field.prototype

        # Runs only for the first time an address has a duplicate
        if func_addr in self.bindings:
            dup_binding = self.bindings[
                self.bindings.index(func_addr)  # type: ignore
            ]
            error_location = \
                f"{class_name}::{function.name} " \
                f"and {dup_binding.short_info}"

            if f"{class_name}::{function.name}" == dup_binding.qualified_name:
                print(
                    "[!] BromaImporter: Duplicate binding with "
                    f"same qualified name! ({error_location})"
                )
                return
            elif class_name == dup_binding.class_name:
                print(
                    "[!] BromaImporter: Duplicate binding within "
                    f"same class! ({error_location})"
                )
                return

            print(
                "[!] BromaImporter: Duplicate binding! "
                f"({class_name}::{function.name} "
                f"and {dup_binding.short_info})"
            )
            self.bindings.remove(dup_binding)
            self.duplicates[func_addr] = [dup_binding]

        if func_addr in self.duplicates:
            self.duplicates[func_addr].append(
                Binding.from_field(class_name, function_field)
            )
            return

        self.bindings.append(Binding.from_field(class_name, function_field))

    def _pre_import_types(self) -> None:
        """Pre-import types hook"""
        dirtree = get_std_dirtree(DIRTREE_LOCAL_TYPES)
        self._imported_types = IDAUtils.get_dirtree_entries(dirtree, "/")

        mkdir_ret = dirtree.mkdir("/BromaIDA")

        for _, path in self._imported_types:
            if path in \
                    ["/SearchType", "/cocos2d::CCNode", "/cocos2d::CCLayer"]:
                print("[+] BromaImporter: Moving existing types to '/BromaIDA'...")
                BIUtils.move_type_entries_to_bromaida()
                break

        if mkdir_ret != 0:
            IDAUtils.visit_dirtree(
                dirtree,
                BIUtils.dirtree_is_bromaida_entry,
                BIUtils.delete_dirtree_entry
            )

    def _post_import_types(self) -> None:
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

    def parse_bromas(self) -> None:
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
                    "[-] BromaImporter: Broma input files hash check disabled. "
                    "Proceeding with type import."
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
                    print("[-] BromaImporter: Types import cancelled by user for this time.")
                elif type_prompt == ASKBTN_BTN3:
                    DataManager().set("import_types", False)
                    print("[-] BromaImporter: Types import cancelled and disabled by user.")
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

    @staticmethod
    def safe_rename_function(ea: int, ida_name: str, name: str):
        """
        Ensures user consent and current function name
        is generic before renaming a function.
        """
        if ida_name.startswith("sub_"):
            IDAUtils.rename_func(
                ea,
                name
            )
        elif sub("_[0-9]+", "", ida_name) != name:
            if DataManager().get("always_overwrite_idb") or \
                AskPopup(
                    f"Mismatch between Broma ({name}) "
                    f"and IDB ({ida_name})!\n"
                    "Overwrite from Broma or keep current name?",
                    "Overwrite", "Keep",
                    icon="WARNING"
            ).show() == ASKBTN_BTN1:
                IDAUtils.rename_func(
                    ea,
                    name
                )

    def import_types(self) -> bool:
        """
        Import types into IDA using
        BromaCodegen and the Clang parser.

        Returns:
            bool: Value that VerifyUtils.verify_types_postimport
                returns to check if type import succeeded.
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

    def import_into_idb(self) -> None:
        """
        Imports the parsed bindings from the Broma files
        into the current IDB.
        """
        total_bindings = len(self.bindings)
        resolved_count = 0

        # first do a pass for non-duplicate bindings
        while self.bindings:
            binding = self.bindings.pop()
            if binding.is_missing:
                print(
                    "[!] BromaImporter: Binding has an address but "
                    f"has missing attribute ({binding.short_info})! "
                    "Skipping."
                )
                continue

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
                        if not add_func(ida_ea):
                            print(
                                f"[!] BromaImporter: Failed to mark the address "
                                f"at {ida_ea} as a function! ({binding.short_info})"
                            )
                            continue

                        IDAUtils.get_function_info(ida_ea, True)
                        ida_func = get_func(ida_ea)
                    else:
                        continue

            if ida_func is None:
                print(
                    f"[!] BromaImporter: Couldn't retrieve function at "
                    f"{hex(ida_ea)}! ({binding.qualified_name})"
                )
                continue

            if ida_func.start_ea != ida_ea:
                print(
                    f"[!] BromaImporter: Function is in the middle of "
                    f"another one! ({binding.short_info})"
                )
                continue

            resolved_count += 1

            # types are needed because we can't just apply one to any variable
            # without having it in the first place
            if self.has_types and BIUtils.has_mismatch(
                IDAUtils.get_function_info(ida_ea),
                binding
            ):
                sig_fix = BIUtils.fix_function_signature(ida_ea, binding)

                if not sig_fix:
                    print(
                        "[!] BromaImporter: Failed to fix function signature "
                        f"for '{binding.qualified_name}'!"
                    )

            self.safe_rename_function(ida_ea, ida_name, binding.ida_qualified_name)

        # now pass over all duplicates
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

            if self.has_types and BIUtils.has_mismatch(
                IDAUtils.get_function_info(ida_ea),
                bindings[0]
            ):
                sig_fix = BIUtils.fix_function_signature(ida_ea, bindings[0])

                if not sig_fix:
                    print(
                        "[!] BromaImporter: Failed to fix function signature "
                        f"for '{bindings[0].qualified_name}' (merged duplicate)!"
                    )

            # use the first occurrence as the name
            self.safe_rename_function(
                ida_ea,
                get_ea_name(ida_ea),
                bindings[0].ida_qualified_name
            )

            func_cmt: str = get_func_cmt(ea_func, True) or ""
            func_names = ", ".join(
                [binding.qualified_name for binding in bindings]
            )

            if func_cmt == "":
                set_func_cmt(ea_func, f"Merged with: {func_names}", True)
            elif func_cmt.startswith("Merged with: "):
                cmt_func_names = func_cmt.removeprefix("Merged with: ")

                if func_names == cmt_func_names:
                    continue

                # we're gonna be setting it anyway
                # so let's do it now to see if IDA's
                # truncated it
                set_func_cmt(ea_func, f"Merged with: {func_names}", True)

                new_cmt = (get_func_cmt(ea_func, True) or "").removeprefix("Merged with: ")

                # check if it was truncated
                if cmt_func_names == new_cmt:
                    continue

                # joke's on you i've already finished the correcting
                print(
                    "[!] BromaImporter: Mismatch or new data "
                    "in merged function list "
                    f"(Current: {cmt_func_names} | "
                    f"Correct/Truncated: {new_cmt})! Correcting..."
                )
            else:
                if DataManager().get(
                        "always_overwrite_merge_information"
                    ) or AskPopup(
                        f"{hex(addr)} already has a comment! "
                        "Would you like to overwrite it with "
                        "merge information or keep the current comment?\n"
                        "This prompt may show up again in future imports"
                        "if the comment is kept.\n\n"
                        "You can enable 'Always Overwrite Function "
                        "Comments With Merge Information' in settings "
                        "to automatically overwrite comments on future imports.",
                        "Overwrite", "Keep"
                ).show() == ASKBTN_BTN1:
                    set_func_cmt(
                        ea_func, f"Merged with: {func_names}", True
                    )

        total_resolved = resolved_count + resolved_duplicate_bindings
        total_all = total_bindings + total_duplicate_bindings

        if total_all != 0:
            print(
                f"[+] BromaImporter: Resolved and mapped {total_resolved}/{total_all} "
                f"bindings onto their respective addresses "
                f"({resolved_duplicate_bindings}/{total_duplicate_bindings} "
                "from merged duplicates)."
            )

        # now do a pass on all linked bindings
        total_linked = len(self.linked_bindings)
        resolved_linked = 0

        if not self.has_types:
            if total_linked:
                print(
                    f"[-] BromaImporter: Skipping {total_linked} linked "
                    "binding(s) - no types were imported to check/apply against."
                )
            return

        if total_linked:
            symbol_index = BIUtils.build_symbol_index()

            while self.linked_bindings:
                binding = self.linked_bindings.pop()

                candidates = symbol_index.get(binding.qualified_name)
                if not candidates:
                    continue

                matched = BIUtils.resolve_overload(binding, candidates)
                if not matched:
                    print(
                        "[!] BromaImporter: Couldn't disambiguate an "
                        f"overload for '{binding.qualified_name}'! Skipping."
                    )
                    continue

                resolved_linked += 1

                for ida_ea in matched:
                    candidates.remove(ida_ea)

                    if BIUtils.has_mismatch(
                        IDAUtils.get_function_info(ida_ea),
                        binding
                    ):
                        sig_fix = BIUtils.fix_function_signature(ida_ea, binding)

                        if not sig_fix:
                            print(
                                "[!] BromaImporter: Failed to fix function "
                                f"signature for '{binding.qualified_name}' "
                                "(linked)!"
                            )

        print(
            f"[+] BromaImporter: Resolved {resolved_linked}/{total_linked} "
            "linked bindings by symbol."
        )

    def _reset(self) -> None:
        """
        Resets the current BromaImporter instance.
        Not doing so would result in a re-run of
        the script populating the same parsed content.
        """
        self._target_platform = ""  # type: ignore
        self._headers_path = Path()
        self._bromas_path = Path()
        self._imported_types = []
        self._broma_files = {}

        self.has_types = False
        self.bindings = deque()
        self.linked_bindings = []
        self.classes = {}
        self.duplicates = {}

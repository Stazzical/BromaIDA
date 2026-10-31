from os import path
from re import (
    sub,
    search, findall,
    match, fullmatch,
    Match
)
from shutil import move
from typing import cast, Generator, Any

from ida_kernwin import ASKBTN_BTN1

from broma_ida.constants import BROMA_PLATFORMS
from broma_ida.broma.binding import Binding
from broma_ida.broma.argtype import ArgType, RetType
from broma_ida.ida.env import to_rva
from broma_ida.ida.parser import resolve_parser
from broma_ida.ida.functions import read_function_signature

from broma_ida.data.data_manager import DataManager

from broma_ida.ui.ask_popup import AskPopup


# TODO: Use pybroma.BromaWriter when it becomes good
class BromaExporter:
    """
    Broma exporter of all time using regex!
    """

    RX_CLASS = r"""class (\S+)"""
    """
    group 1: class name
    """

    RX_METHOD = \
        r"""^[ \t]*(virtual|callback|static|)(?: *)?(?:((?:const )?\S+) )?(\S+)\((.*)\)(?: const|)(?: = ((?=inline).* \{|(?!inline)(?:(?:win|imac|m1|ios) (?:0[xX][0-9a-fA-F]+|inline)(?:, )?)+))?"""  # noqa: E501
    """
    group 1: "virtual", "callback", "static", or empty
    group 2: return type, empty if ctor/dtor
    group 3: function name
    group 4: comma-separated parameters or empty
    group 5: comma-separated platform address(es)
    """

    RX_METHOD_PLAT_ADDR_BASE = r"""{platform} (0[xX][0-9a-fA-F]+|inline)"""
    """
    group 1: binding address or "inline"
    """

    _filepath: str = ""
    _target_platform: BROMA_PLATFORMS

    bindings: dict[str, Binding] = {}
    """{ "qualified_name": Binding }"""
    overloads: dict[str, list[Binding]] = {}
    """{ "qualified_name": [Binding, Binding, ...] }"""
    num_exports: int = 0
    """Number of exported bindings"""
    num_ret_exports: int = 0
    """Number of exported return types"""
    num_args_names_exports: int = 0
    """Number of exported renamed function arguments' names"""

    def _make_plat_method_addr_regex(self, platform: BROMA_PLATFORMS) -> str:
        """
        Makes a platform method address regex

        Args:
            platform (BROMA_PLATFORMS): The platform

        Returns:
            str: RX_METHOD_PLAT_ADDR_BASE with the platform
        """
        return self.RX_METHOD_PLAT_ADDR_BASE.replace("{platform}", platform)

    def _parse_method_platforms(
        self,
        platforms: str | None
    ) -> dict[BROMA_PLATFORMS, int]:
        """
        Parses "win 0x13be40, imac 0x586990, m1 inline" to
        { "win": 0x13be40, "imac": 0x586990, "m1": 0 }

        Args:
            platforms (str | None): Platforms string of format "plat 0xaddr"

        Returns:
            dict[BROMA_PLATFORMS, int]: Platform-to-Address dict
        """
        if platforms is None:
            return {}

        return {
            cast(BROMA_PLATFORMS, plat): 0 if addr == "inline" else int(addr, 16)
            for plat, addr in findall(r"(win|imac|m1|ios) (0[xX][0-9a-fA-F]+|inline)", platforms)
        }

    @staticmethod
    def _parse_broma_params(
        func: Match[str], class_name: str
    ) -> tuple[list[ArgType], bool]:
        """
        Read a Broma function signature and recreate standardized
        information for use against IDA.
        Adds the implicit `this` parameter to the parameters list.

        Returns:
            tuple[list[ArgType], bool]: (parameters, is_variadic)
        """
        is_static = func.group(1) == "static"

        params, is_variadic = ArgType.parse_params(
            func.group(4), first_index=0 if is_static else 1
        )
        if not is_static:
            params.insert(0, ArgType.for_this(class_name))

        return params, is_variadic

    @staticmethod
    def _find_overload(
        group: list[Binding],
        params: list[ArgType],
        is_variadic: bool
    ) -> int | None:
        """
        Index of the binding in `group` that belongs to a Broma line.
        Overloads that differ only by '...' are told apart
        by the flag first. If none agrees, any binding with
        the same parameters will do, since an IDB that doesn't
        mark a function variadic says nothing against Broma's '...'.

        Args:
            group (list[Binding]): List of Binding instances
                of a function's overloads grouped together.
            params (list[ArgType]): List of arguments to match
                against and specify the overload.
            is_variadic (bool): If the function overload is
                variadic.

        Returns:
            int | None: Index of the specific function overload
                inside `group` if found, or None.
        """
        same_params = [i for i, o in enumerate(group) if o.parameters == params]

        return next(
            (i for i in same_params if group[i].is_variadic == is_variadic),
            same_params[0] if same_params else None
        )

    def _get_broma_string(
        self,
        parsed_broma_line: Match[str],
        binding: Binding
    ) -> str:
        """
        Gets the Broma line to export after adding the binding's address

        Args:
            parsed_broma_line (Match[str]): Parsed Broma line in export()
            binding (Binding): The binding to add the address of

        Returns:
            str: The Broma line with the address
            (return type and function args names if applicable) added
        """
        # some very freaky code below (it uses nonlocal), you have been warned
        # TODO: literally do anything else bruh please
        sub_repl: str
        prefix = parsed_broma_line.string[:parsed_broma_line.start(1)]

        def sub_ret_type_f(m: Match[str]):
            nonlocal sub_repl

            groups = m.groups()

            if groups[0] == "":
                return prefix + "{} {}({}){addr}".replace(
                    "{addr}", f" = {groups[4]}" if groups[4] else ""
                ).format(
                    *(sub_repl, *groups[2:])
                )

            return prefix + "{} {} {}({}){addr}".replace(
                "{addr}", f" = {groups[4]}" if groups[4] else ""
            ).format(
                *(groups[0], sub_repl, *groups[2:])
            )

        def sub_args_names_f(m: Match[str]):
            nonlocal sub_repl

            groups = m.groups()

            if groups[0] == "":
                return prefix + "{ret}{}({}){addr}".replace(
                    "{ret}", f"{groups[1]} " if groups[1] else ""
                ).replace(
                    "{addr}", f" = {groups[4]}" if groups[4] else ""
                ).format(
                    groups[2], sub_repl
                )

            return prefix + "{} {ret}{}({}){addr}".replace(
                "{ret}", f"{groups[1]} " if groups[1] else ""
            ).replace(
                "{addr}", f" = {groups[4]}" if groups[4] else ""
            ).format(
                # step intentional; skip return type group
                *(*groups[:3:2], sub_repl)
            )

        self.num_exports += 1

        # trust the Broma line over the IDB-derived guess
        binding.is_static = parsed_broma_line.group(1) == "static"

        broma_ret = parsed_broma_line.group(2)

        if DataManager().get("export_return_types") and (
                # not ctor or dtor
                broma_ret is not None
                and not binding.ret.is_unknown
                and binding.ret != RetType(broma_ret)
        ):
            self.num_ret_exports += 1

            sub_repl = binding.ret.type

            new_line = sub(
                self.RX_METHOD,
                sub_ret_type_f,
                parsed_broma_line.string
            )
            parsed_broma_line = search(
                self.RX_METHOD,
                new_line
            )  # type: ignore

        if DataManager().get("export_args_names"):
            broma_args, broma_variadic = self._parse_broma_params(
                parsed_broma_line, binding.class_name
            )

            # pX is Broma auto-generated name, aX is IDA auto-generated name
            names_differ = any((
                fullmatch(r"(p|a)([0-9]+)", p.name) is None and
                p.name != broma_args[i].name
                for i, p in enumerate(binding.parameters)
                if i > 0 or binding.is_static
            ))
            # be conservative about ellipsis, keep broma's ellipsis if it has one
            adds_ellipsis = binding.is_variadic and not broma_variadic

            if names_differ or adds_ellipsis:
                self.num_args_names_exports += 1

                binding.is_variadic |= broma_variadic

                sub_repl = binding.get_args_str()

                new_line = sub(
                    self.RX_METHOD,
                    sub_args_names_f,
                    parsed_broma_line.string
                )
                parsed_broma_line = search(
                    self.RX_METHOD,
                    new_line
                )  # type: ignore

        # freaky code ends

        broma_line_no_address = search(r"\);(.*)", parsed_broma_line.string)
        # binding has no address associated to it
        if broma_line_no_address:
            return f"""{
                broma_line_no_address.string[
                    :broma_line_no_address.span(0)[0]
                ]
            }) = {self._target_platform} {hex(binding.address)};{
                broma_line_no_address.string[
                    broma_line_no_address.span(0)[0]:
                ][2:]
            }"""

        broma_binding_platforms = self._parse_method_platforms(
            parsed_broma_line.group(5)
        )

        # binding has another platform's address associated to it
        if self._target_platform not in broma_binding_platforms:
            # add this platform's address behind the `= inline;`
            bare_inline = sub(
                r"(=\s*)inline(\s*;)",
                rf"\1{self._target_platform} {hex(binding.address)}, inline\2",
                parsed_broma_line.string,
                count=1
            )
            if bare_inline != parsed_broma_line.string:
                return bare_inline

            return sub(
                r"((?:(?:win|imac|m1|ios) (?:0[xX][0-9a-fA-F]+|inline)(?:, )?)+)",  # noqa: E501
                rf"""{self._target_platform} {hex(binding.address)}, \1""",
                parsed_broma_line.string
            )

        # binding has this platform's address associated to it
        if broma_binding_platforms[self._target_platform] != \
                binding.address:
            if AskPopup(
                "Mismatch in Broma for method "
                f"""{binding.qualified_name} """
                f"""(Broma: {
                    "inlined" if broma_binding_platforms[
                        self._target_platform
                    ] == 0 else hex(
                        broma_binding_platforms[self._target_platform]
                    )
                }. """
                f"""idb: {hex(binding.address)})\n"""
                "Overwrite Broma or Keep?",
                "Overwrite", "Keep",
                icon="WARNING"
            ).show() == ASKBTN_BTN1:
                return sub(
                    self._make_plat_method_addr_regex(self._target_platform),
                    f"{self._target_platform} "
                    f"""{hex(binding.address)}""",
                    parsed_broma_line.string
                )

        self.num_exports -= 1

        return parsed_broma_line.string

    def __init__(self, platform: BROMA_PLATFORMS, file: str):
        self._reset()

        self._target_platform = platform
        self._filepath = file

    def push_binding(self, binding: Binding):
        """
        Adds a binding to be exported

        Args:
            binding (Binding): The binding to be exported
        """
        group = self.overloads.get(binding.qualified_name)
        if group is not None:
            # names arrive in address order, so foo_1 can come before foo
            group.append(binding)
        else:
            self.bindings[binding.qualified_name] = binding

    def push_bindings(self, bindings: list[Binding]):
        """
        Adds a list of bindings at once

        Args:
            bindings (list[Binding]): The list of bindings
        """
        self.bindings.update([
            (binding.qualified_name, binding)
            for binding in bindings
        ])

    def import_from_idb(self, names: Generator[tuple[int, str], Any, None]):
        """
        Imports bindings from an idautils.Names generator

        Args:
            names (Generator[tuple[int, str], Any, None]):
                The idautils.Names generator
        """
        for ea, name in names:
            if "::" not in name:
                continue

            split_name = name.split("::")

            # avoid exporting symbols more than 1 namespace/class deep
            # (is the case for cocos methods)
            if len(split_name) > 2:
                continue

            class_name, method = split_name

            overload = search(r"^(.+)_(\d+)$", method)
            base_name = overload[1] if overload else method

            # ["GJUINode", "dGJUINode"] -> "~GJUINode"
            if base_name[:1] in ("d", "~") and base_name[1:] == class_name:
                base_name = f"~{class_name}"

            signature = read_function_signature(ea)
            if signature is None:
                continue

            ret, args, is_variadic = signature

            # i dont feel like it rn tbh
            # TODO: properly handle stl types with gd:: namespace considerations
            if ret.is_stl or any(p.is_stl for p in args):
                continue

            binding = Binding(
                base_name,
                class_name,
                ret,
                args,
                is_variadic=is_variadic,
                # check if first argument is ClassName*
                # because func_type_data_t.is_static is always False :D
                is_static=not (args and args[0] == f"{class_name}*"),
                address=to_rva(ea)
            )

            if overload is None:
                self.push_binding(binding)
                continue

            group = self.overloads.setdefault(binding.qualified_name, [])
            if not group:
                original = self.bindings.pop(binding.qualified_name, None)
                if original is not None:
                    group.append(original)

            group.append(binding)

    def export(self):
        """Exports the bindings to the file"""
        if not path.exists(self._filepath):
            with open(self._filepath, "w", encoding="utf-8"):
                pass

        with open(self._filepath, "r", encoding="utf-8-sig", newline="") as fr, \
                open(f"{self._filepath}.tmp", "w", encoding="utf-8", newline="") as fw:
            current_class_name: str = ""
            member_indent: str | None = None

            for line in fr.readlines():
                if current_class_name == "":
                    current_class = match(self.RX_CLASS, line)

                    if current_class:
                        current_class_name = current_class.group(1)
                        member_indent = None

                    fw.write(line)
                    continue

                if line.startswith("}"):
                    current_class_name = ""
                    fw.write(line)
                    continue

                # members sit at the class body's own indentation, taken from
                # its first indented line, anything deeper is left alone
                if member_indent is None and (m := match(r"[ \t]+(?=\S)", line)):
                    member_indent = m.group(0)

                if member_indent is None \
                        or not line.startswith(member_indent) \
                        or not line[len(member_indent):][:1].strip() \
                        or line.lstrip().startswith(("//", "[[")):
                    fw.write(line)
                    continue

                func = search(self.RX_METHOD, line)
                if func is None:
                    fw.write(line)
                    continue

                qualified_name = f"{current_class_name}::{func.group(3)}"

                if qualified_name not in self.overloads \
                        and qualified_name not in self.bindings:
                    fw.write(line)
                    continue

                params, is_variadic = self._parse_broma_params(
                    func, current_class_name
                )

                if qualified_name in self.overloads:
                    if resolve_parser(DataManager().get("use_new_clang", False)) is None:
                        fw.write(line)
                        continue

                    group = self.overloads[qualified_name]
                    idx = self._find_overload(group, params, is_variadic)
                    fw.write(
                        line if idx is None
                        else self._get_broma_string(func, group.pop(idx))
                    )
                    continue

                binding = self.bindings[qualified_name]
                fw.write(
                    self._get_broma_string(func, binding)
                    if binding.parameters == params else line
                )

        move(f"{self._filepath}.tmp", self._filepath)

    def _reset(self):
        """Resets a BromaExporter instance"""
        self._filepath = ""
        self._target_platform = ""  # type: ignore
        self.bindings = {}
        self.overloads = {}
        self.num_exports = 0

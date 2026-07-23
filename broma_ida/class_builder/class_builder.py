from pybroma import Class

from broma_ida.broma.class_graph import ClassGraph
from broma_ida.broma.constants import BROMA_PLATFORMS, BROMA_PLATFORM_GROUPS
from broma_ida.broma.argtype import STLUtils


class ClassBuilder:
    """Builds a C++ class string from a Broma Class."""
    _target_platform: BROMA_PLATFORMS
    _broma_class: Class
    _graph: ClassGraph

    _class_str: str

    def _import_class(self):
        """
        Converts a Broma class to a C++ class
        declaration string for the IDA parser.
        """
        body = ""
        has_left_functions = False

        for sig in self._graph.get_own_virtuals(self._broma_class.name):
            # supress any missing functions on the target platform.
            if sig.is_missing:
                continue

            # this is a hack. a very bad hack.
            # it makes MSVC vtables work, somehow.
            # it'll stay for now until a missing piece
            # is in place, refer to IDA docs:
            # https://docs.hex-rays.com/core/types/concepts/cpp-type-details
            # it's not needed for Itanium ABI binaries.
            # TODO: two-pass codegen to auto-generate secondary vtables in the type library
            if self._target_platform == "win" and self._graph.is_secondary_override(
                self._broma_class, sig
            ):
                continue

            body += f"\t{str(sig)}\n"
            has_left_functions = True

        for field in self._broma_class.fields:
            member_field = field.getAsMemberField()
            pad_field = field.getAsPadField()

            if member_field is not None:
                present = (
                    len(member_field.platform) == 0
                    or (
                        str(self._target_platform) in member_field.platform
                        or BROMA_PLATFORM_GROUPS.get(str(self._target_platform)) in member_field.platform
                    )
                )

                if not present:
                    continue

                if has_left_functions:
                    body += "\n"
                    has_left_functions = False

                body += f"""\t{
                    STLUtils.normalize_type(
                        member_field.type.name
                    ).replace("geode::", "")
                } {member_field.name};\n"""

            elif pad_field is not None:
                # skip other members because no padding for current platform (why)
                if self._target_platform not in \
                        pad_field.amount.platforms_as_dict():
                    break

                pad_amount = pad_field.amount.platforms_as_dict()[
                    self._target_platform
                ]

                # thank you andy pads
                if pad_amount == 0:
                    continue

                if has_left_functions:
                    body += "\n"
                    has_left_functions = False

                body += f"\tPAD({pad_amount});\n"

        # TODO: superclasses contains 'depends'
        # attribute's classes too as of now,
        # we don't wanna add those to the bases
        # if they're not actually a base.
        bases = ", ".join(
            f"public {cls}" for cls in self._broma_class.superclasses
        )
        inherit = f" : {bases}" if bases else ""

        if "::" in self._broma_class.name:
            parts = self._broma_class.name.split("::")
            bare_name = parts[-1]
            open_ns = " ".join(
                f"namespace {ns} {{" for ns in parts[:-1]
            )
            close_ns = (" }" * (len(parts) - 1))[1:]

            self._class_str = (
                f"{open_ns}\n"
                f"class {bare_name}{inherit} {{"
                f"{'\npublic:\n' + body if body is not '' else ''}"
                "};\n"
                f"{close_ns}\n\n"
            )
        else:
            self._class_str = (
                f"class {self._broma_class.name}{inherit} {{"
                f"{'\npublic:\n' + body if body is not '' else ''}"
                "};\n\n"
            )

    def __init__(
        self,
        platform: BROMA_PLATFORMS,
        broma_class: Class,
        graph: ClassGraph
    ):
        self._target_platform = platform
        self._broma_class = broma_class
        self._graph = graph

        self._class_str = ""

        self._import_class()

    def get_str(self) -> str:
        return self._class_str

class STLClassBuilder:
    stl_types: tuple[list[str], list[str]]

    def __init__(
        self,
        stl_types: tuple[list[str], list[str]]
    ) -> None:
        self.stl_types = stl_types

    def emit_ptr_types(self) -> str:
        if len(self.stl_types[0]) == 0:
            return ""

        body = "class __BromaSTLTypesPtr {\npublic:\n"

        for member in self.stl_types[0]:
            body += f"\t{member};\n"

        body += "};\n"

        return body

    def emit_value_types(self) -> str:
        if len(self.stl_types[1]) == 0:
            return ""

        body = "class __BromaSTLTypesValue {\npublic:\n"

        for member in self.stl_types[1]:
            body += f"\t{member};\n"

        body += "};\n"

        return body

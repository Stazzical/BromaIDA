from pybroma import Class

from broma_ida.broma.class_graph import ClassGraph
from broma_ida.broma.constants import BROMA_PLATFORMS
from broma_ida.utils import CppUtils


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
            if field.for_platform(self._target_platform) is None:
                continue

            if (member := field.getAsMemberField()) is not None:
                line = self._member_line(member)
            elif (pad := field.getAsPadField()) is not None:
                amount = pad.amount.for_platform(self._target_platform)
                if not amount:
                    continue

                line = f"PAD(0x{amount:x});"
            else:
                continue

            if has_left_functions:
                body += "\n"
                has_left_functions = False
            body += f"\t{line}\n"

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
                f"{'\npublic:\n' + body if body != '' else ''}"
                "};\n"
                f"{close_ns}\n\n"
            )
        else:
            self._class_str = (
                f"class {self._broma_class.name}{inherit} {{"
                f"{'\npublic:\n' + body if body != '' else ''}"
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

    @staticmethod
    def _member_line(m) -> str:
        t = CppUtils.normalize_type(m.type.name).replace("geode::", "")
        return f"{t} {m.name}{f'[{m.count}]' if m.count else ''};"

from pybroma import Class, FunctionType

from broma_ida.broma.binding import FunctionSignature
from broma_ida.broma.class_graph import ClassGraph
from broma_ida.broma.constants import BROMA_PLATFORMS


class ClassBuilder:
    """Builds a C++ class string from a Broma Class."""
    _target_platform: BROMA_PLATFORMS
    _broma_class: Class
    _class_str: str
    _graph: ClassGraph

    # TODO: just make this do the parsing, make lists of members
    # and methods to be used in get_str for making the class instead
    def _import_class(self):
        """
        Converts a Broma class to a C++ class
        declaration string for the IDA parser.
        """
        bases = ", ".join(
            f"public {cls}" for cls in self._broma_class.superclasses
        )
        inherit = f" : {bases}" if bases else ""
        # we declare the class inside namespace blocks to
        # avoid C++ parsing errors, this is done
        # after the body has finished constructing
        bare_name = self._broma_class.name.rsplit("::", 1)[-1]

        body = f"class {bare_name}{inherit}\n{{\npublic:\n"

        has_left_functions = False

        for sig in self._graph.get_own_virtuals(self._broma_class.name):
            # TODO: wait until pybroma exposes FunctionType for detecting
            # and skipping constructors and destructors

            # skip any inlined functions on the target platform
            # they will simply clutter the generated vtables
            # after parsing and cause shifts in the vtable sizes.

            # if Broma files had reliably defined inline functions
            # in the class definitions, the field could've been
            # gotten as an InlineField, which has a C++ string
            # defining the function fully (InlineField.inner).
            # regardless, this isn't very useful for type defining.
            if sig.is_inline:
                continue

            # skip overriden functions introduced by the secondary superclasses
            # primary overrides (if not inlined) are still needed for the change
            # in "this" argument's type for the function call
            if self._graph.is_secondary_override(
                self._broma_class, sig
            ):
                continue

            body += str(sig)
            has_left_functions = True

        for field in self._broma_class.fields:
            member_field = field.getAsMemberField()
            pad_field = field.getAsPadField()

            if member_field is not None:
                if has_left_functions:
                    body += "\n"
                    has_left_functions = False

                body += f"\t{
                    member_field.type.name
                        .replace('gd::', 'std::')
                        .replace('geode::', '')
                } {member_field.name};\n"

            elif pad_field is not None:
                # skip other members because no padding for current platform
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

        body += "};\n"

        if "::" in self._broma_class.name:
            parts = self._broma_class.name.split("::")
            open_ns = " ".join(
                f"namespace {ns} {{" for ns in parts[:-1]
            )
            close_ns = " }" * (len(parts) - 1)
            self._class_str = f"{open_ns}\n{body}{close_ns}\n\n"
        else:
            self._class_str = body + "\n"

    def __init__(
        self,
        platform: BROMA_PLATFORMS,
        broma_class: Class,
        graph: ClassGraph
    ):
        self._target_platform = platform
        self._broma_class = broma_class
        self._class_str = ""
        self._graph = graph
        
        self._import_class()

    def get_str(self) -> str:
        return self._class_str

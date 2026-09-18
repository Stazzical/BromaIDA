from dataclasses import dataclass, field

from broma_ida.utils import CppUtils, STLNode, STLUtils


@dataclass
class ArgType:
    """A function argument type."""

    type: str
    name: str = ""
    reg: str = ""

    expanded_type: str = field(init=False)
    _node: "STLNode" = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        self.type = CppUtils.normalize_type(self.type)
        # canonical parsed representation of this type's decoration
        self._node = STLUtils.split_stl_type(self.type)

        if "std::" in self.type:
            self.expanded_type = CppUtils.format_ptr(
                STLUtils.expand_stl_type(self.type)
            )
        else:
            self.expanded_type = self.type

    @property
    def stripped_type(self) -> str:
        """
        Type stripped from const, reference and pointer.

        Returns:
            str
        """
        return self._node.name

    @property
    def stripped_expanded_type(self) -> str:
        return CppUtils.strip_crp(self.expanded_type)

    @property
    def stl_node(self) -> "STLNode":
        """The parsed STLNode tree for this type."""
        return self._node

    @property
    def is_stl(self) -> bool:
        return self._node.is_stl

    @property
    def is_const(self) -> bool:
        return self._node.const == "const"

    @property
    def is_ptr(self) -> bool:
        return self._node.ptr.endswith("*")

    @property
    def is_ref(self) -> bool:
        return self._node.ptr.endswith("&")

    @property
    def is_ptr_or_ref(self) -> bool:
        return bool(self._node.ptr)

    def __str__(self) -> str:
        if not self.name:
            return self.type

        result = f"{self.type} {self.name}"

        if self.reg:
            result += f"@<{self.reg}>"

        return result

    def __eq__(self, other):
        if isinstance(other, str):
            return self.type == CppUtils.normalize_type(other)
        elif isinstance(other, (ArgType, RetType)):
            return self.type == other.type

        return NotImplemented

    def __hash__(self):
        return hash(self.type)


class RetType(ArgType):
    """A function return type."""

    @classmethod
    def void_type(cls) -> "RetType":
        """A plain `void` return type."""
        # might be more useful later when i could
        # probably move IDA type info into these classes
        return cls("void")

    @classmethod
    def for_ctor(cls, class_name: str) -> "RetType":
        """
        The return type relevant to IDA for constructors,
        which is the owning class. Broma has no return type for
        constructors, so this should always be used
        explicitly instead of relying on a guess from IDA.

        Args:
            class_name (str)

        Returns:
            RetType
        """
        return cls(f"{class_name}*")

    @classmethod
    def for_dtor(cls) -> "RetType":
        """
        The return type relevant to IDA for destructors,
        which is `void`. Broma has no return type for
        destructors, so this should always be used
        explicitly instead of relying on a guess from IDA.

        Returns:
            RetType
        """
        return cls.void_type()

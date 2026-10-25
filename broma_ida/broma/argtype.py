from dataclasses import dataclass, field
import re

from broma_ida.broma.constants import CPP_TYPE_QUALIFIERS, CPP_TYPE_SPECIFIERS, CPP_PRIMITIVES

from broma_ida.utils import CppUtils, STLNode, STLUtils


_NOT_A_NAME = frozenset((*CPP_TYPE_SPECIFIERS, *CPP_TYPE_QUALIFIERS, *CPP_PRIMITIVES))
"""Keywords that are not part of the name."""
_NAME_TAIL_RE = re.compile(r"(?<=[\s*&])[A-Za-z_]\w*$")
"""Find the last word at the tail end of the parameter declaration."""
_ONLY_DECOR_RE = re.compile(r"\b(?:const|volatile)\b|[*&\s]")
"""Strip everything from before the last word."""


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

    @classmethod
    def for_this(cls, class_name: str) -> "ArgType":
        """
        The implicit `this` parameter IDA shows
        for a method of `class_name`.
        """
        return cls(f"{class_name}*", "this")

    @classmethod
    def parse_params(
        cls,
        params: str,
        first_index: int = 0,
        auto_names: bool = False
    ) -> tuple[list["ArgType"], bool]:
        """
        Converts a string of function parameters into a
        list of ArgTypes and detect if there is a variadic
        ellipsis present.

        Args:
            params (str): The function parameters string.
            first_index (int, optional): The parameter to
                start from. Defaults to `0`.
            auto_names (bool, optional): Generate Broma names
                for parameters that don't have one.
                Defaults to `False`.

        Returns:
            tuple[list["ArgType"], bool]: 'const char* a, int, ...' ->
                ([ArgType, ArgType], True)
        """
        result: list[ArgType] = []
        tokens, is_variadic = CppUtils.split_params(params)

        for i, token in enumerate(tokens, start=first_index):
            m = _NAME_TAIL_RE.search(token)
            if m and m.group() not in _NOT_A_NAME:
                type_part = token[:m.start()]

                if _ONLY_DECOR_RE.sub("", type_part):
                    result.append(cls(type_part.rstrip(), m.group()))
                    continue

            result.append(cls(token, (f"p{i}" if auto_names else "")))

        return result, is_variadic

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

    _UNKNOWN = frozenset({"", "auto", "TodoReturn"})

    @property
    def is_unknown(self) -> bool:
        """Broma placeholders meaning 'return type not known'."""
        return self.stripped_type in RetType._UNKNOWN

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

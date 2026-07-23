from typing import Final

from dataclasses import dataclass, field

from re import sub


@dataclass(slots=True)
class STLNode:
    const: str
    name: str
    """The actual type."""
    args: list["STLNode"] = field(default_factory=list)
    ptr: str = ""

    @property
    def is_stl(self) -> bool:
        return "std::" in self.name


class STLUtils:
    """STL utilities."""

    STL_EXPANSION_MAP: Final = {
        "std::map": "std::map<{0}, {1}, std::less<{0}>, std::allocator<std::pair<const {0}, {1}>>>",  # noqa: E501
        "std::unordered_map":
            "std::unordered_map<{0}, {1}, std::hash<{0}>, std::equal_to<{0}>, std::allocator<std::pair<const {0}, {1}>>>",  # noqa: E501
        "std::vector": "std::vector<{0}, std::allocator<{0}>>",
        "std::set": "std::set<{0}, std::less<{0}>, std::allocator<{0}>>",
        "std::unordered_set": "std::unordered_set<{0}, std::hash<{0}>, std::equal_to<{0}>, std::allocator<{0}>>",  # noqa: E501
        "std::list": "std::list<{0}, std::allocator<{0}>>",
        "std::deque": "std::deque<{0}, std::allocator<{0}>>",

        # ditto
        "std::pair": "std::pair<{0}, {1}>",

        # not really a templated type, but whatever
        "std::string": "std::basic_string<char, std::char_traits<char>, std::allocator<char>>"  # noqa: E501
    }
    """Dictionary of STL types to their expanded forms."""

    STL_CORE_ARITY: Final = {
        "std::map": 2, "std::unordered_map": 2,
        "std::vector": 1, "std::set": 1, "std::unordered_set": 1,
        "std::list": 1, "std::deque": 1,
        "std::pair": 2, "std::string": 0,
    }
    """
    Dictionary of the amount of arguments each
    STL type has in its 'sugar' type,
    used to collapse them in `STLUtils.collapse_stl_type`.
    """

    @staticmethod
    def format_ptr(pt: str) -> str:
        """IDA is east pointer (ew)"""
        return sub(r"([^ ])\*", r"\1 *", pt)

    @staticmethod
    def to_ida_equivalent(t: str) -> str:
        """
        IDA always resolves references into raw pointers internally,
        so a canonical type's '&' needs to become '*' before comparing
        against anything sourced from IDA.
        """
        # as of now the 'geode::' namespace
        # is only for SeedValue classes
        # they're put in 'helpers.hpp';
        # this won't be needed when we finish
        # the sdk parser.
        return t.replace("geode::", "").replace("&", "*")

    @staticmethod
    def strip_crp(tt: str) -> str:
        """Strips const, reference and pointer from the type."""
        return (
            tt.removesuffix("&").removesuffix("*")
            .removeprefix("const ").removesuffix(" const")
            .strip()
        )

    @staticmethod
    def normalize_type(t: str) -> str:
        """
        Normalize the type string to the following standards:
        - gd:: -> std::
        - east `const` moved to west position
        - pointer/reference attached to type with no spaces

        Args:
            t (str)

        Returns:
            str
        """
        t = t.strip().replace("gd::", "std::")

        # you darn whitespaces get off my property!!
        t = sub(r"\s+", " ", t)
        t = sub(r"\s*,\s*", ", ", t)
        t = sub(r"<\s+", "<", t)
        t = sub(r"\s+>", ">", t)

        # normalize east const to west const
        t = sub(
            r"^((?:(?!const\s*[*&]).)+?)\s+const\s*([*&])$",
            r"const \1\2",
            t
        )

        # normalize east pointer/reference to west pointer/reference
        t = sub(r"\s+([*&])", r"\1", t)

        return t

    @staticmethod
    def split_stl_type(stl_t: str) -> "STLNode":
        """
        Splits an STL type string into a list of STL type name
        and contained types.

        Args:
            stl_t (str): STL type string. Assumed to be
                normalized first using `STLUtils.normalize_type`.

        Returns:
            STLNode
        """  # noqa: E501
        stl_t = stl_t.strip()

        ptr = stl_t[-1] if stl_t[-1] in ("*", "&") else ""
        if ptr:
            stl_t = stl_t[:-1].rstrip()

        const = "const" if stl_t.startswith("const ") else ""
        if const:
            stl_t = stl_t[len("const "):].lstrip()

        stripped = STLUtils.strip_crp(stl_t)
        if "std::" not in stl_t or stripped == "std::string":
            return STLNode(const, stripped, ptr=ptr)

        # find the outermost template bracket
        template_start = stl_t.index("<")
        type_name = stl_t[:template_start].strip()
        # everything between outermost < and >
        inner = stl_t[template_start + 1:stl_t.rindex(">")]

        args: list[STLNode] = []
        depth = 0
        token_start = 0

        for i, c in enumerate(inner + ","):
            if c == "<":
                depth += 1
            elif c == ">":
                depth -= 1
            elif c == "," and depth == 0:
                args.append(
                    STLUtils.split_stl_type(inner[token_start:i].strip())
                )
                token_start = i + 1

        return STLNode(const, type_name, args, ptr)

    @staticmethod
    def expand_stl_type(stl_t: str) -> str:
        """Expands an STL type.
        Example:
        "std::map<int, int>"
        into
        "std::map<int, int, std::less<int>, std::allocator<std::pair<const int, int>>>"

        Args:
            stl_t (str): Unexpanded STL type. Assumed to be
                normalized first using `STLUtils.normalize_type`.

        Returns:
            str
        """
        def expand_node(node: STLNode) -> str:
            if not node.is_stl:
                return f"{node.const} {node.name}{node.ptr}".lstrip()

            if node.name == "std::string":
                return f"{node.const} {STLUtils.STL_EXPANSION_MAP['std::string']}{node.ptr}".lstrip()

            template = STLUtils.STL_EXPANSION_MAP[node.name]
            expanded_args = [expand_node(arg) for arg in node.args]

            return f"{node.const} {template.format(*expanded_args)}{node.ptr}".lstrip()

        return expand_node(STLUtils.split_stl_type(stl_t))

    @staticmethod
    def collapse_stl_type(node: "STLNode") -> "STLNode":
        """
        Collapse an STL type back to its 'sugar'
        format.

        Args:
            node (STLNode)

        Returns:
            STLNode
        """
        if not node.is_stl or node.name not in STLUtils.STL_CORE_ARITY:
            return STLNode(node.const, node.name, [], node.ptr)

        arity = STLUtils.STL_CORE_ARITY[node.name]
        core_args = [STLUtils.collapse_stl_type(a) for a in node.args[:arity]]

        return STLNode(node.const, node.name, core_args, node.ptr)

    @staticmethod
    def stl_value_types(
        raw: str
    ) -> list[tuple[str, bool]]:
        """
        Walk split_stl_type tree, yielding (bare_type, is_by_value)
        tuples in a list for every leaf type.

        Args:
            raw (str): Raw string of the type. Assumed to be
                normalized first using `STLUtils.normalize_type`.

        Returns:
            list[tuple[str, bool]]: [(stripped_leaf_type, is_by_value), ...]
        """
        results: list[tuple[str, bool]] = []

        def walk(node: "STLNode"):
            if node.args:
                for arg in node.args:
                    walk(arg)
                return

            if node.is_stl or not node.name:
                return

            bare = STLUtils.strip_crp(node.name)
            if not bare:
                return

            by_value = "*" not in node.ptr and "&" not in node.ptr
            results.append((bare, by_value))

        walk(STLUtils.split_stl_type(raw))
        return results


@dataclass
class ArgType:
    """A function argument type."""
    type: str
    name: str = ""
    reg: str = ""

    expanded_type: str = field(init=False)

    def __post_init__(self):
        self.type = STLUtils.normalize_type(self.type)

        if "std::" in self.type:
            self.expanded_type = STLUtils.format_ptr(
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
        return STLUtils.strip_crp(self.type)

    @property
    def stripped_expanded_type(self) -> str:
        return STLUtils.strip_crp(self.expanded_type)

    def __str__(self) -> str:
        if not self.name:
            return self.type

        result = f"{self.type} {self.name}"

        if self.reg:
            result += f"@<{self.reg}>"

        return result

    def __eq__(self, other):
        if isinstance(other, str):
            return self.type == STLUtils.normalize_type(other)
        elif isinstance(other, (ArgType, RetType)):
            return self.type == other.type

        return NotImplemented

    def __hash__(self):
        return hash(self.type)


class RetType(ArgType):
    """A function return type."""

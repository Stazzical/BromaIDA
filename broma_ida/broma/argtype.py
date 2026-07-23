from typing import cast, Final, Union

from dataclasses import dataclass, field

from re import sub

STL_TREE = list[str | list[Union[str, "STL_TREE"]]]


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
    def split_stl_type(stl_t: str) -> STL_TREE:
        """
        Splits an STL type string into a list of STL type name
        and contained types. This function assumes `stl_t` types are
        normalized first using `normalize_type`.

        Args:
            stl_t (str): STL type string.

        Returns:
            list[str | list[str]]: if stl_t is "std::type<const T1, T2*>&" then
                ["", "std::type", ["const", "T1", ""], ["", "T2, "*"], "&"] will
                be returned.
        """  # noqa: E501
        stl_t = stl_t.strip()
        ptr = ""
        const = ""

        # extract trailing pointer/reference
        if stl_t[-1] in ("*", "&"):
            ptr = stl_t[-1]
            stl_t = stl_t[:-1].rstrip()

        # extract leading const
        if stl_t.startswith("const "):
            const = "const"
            stl_t = stl_t[6:].lstrip()  # len("const ") == 6

        stripped = STLUtils.strip_crp(stl_t)
        if "std::" not in stl_t or stripped == "std::string":
            return [const, stripped, ptr]

        # find the outermost template bracket
        template_start = stl_t.index("<")
        type_name = stl_t[:template_start].strip()
        # everything between outermost < and >
        inner = stl_t[template_start + 1:stl_t.rindex(">")]

        result: STL_TREE = [const, type_name]

        # split inner by commas at nest depth 0
        nest_count = 0
        current_token = ""

        for i, c in enumerate(inner):
            if c == "<":
                nest_count += 1
            elif c == ">":
                nest_count -= 1

            if nest_count == 0 and (c == "," or i == len(inner) - 1):
                if i == len(inner) - 1 and c != ",":
                    current_token += c

                result.append(
                    STLUtils.split_stl_type(current_token.strip())
                )
                current_token = ""
            else:
                current_token += c

        result.append(ptr)
        return result

    @staticmethod
    def expand_stl_type(stl_t: str) -> str:
        """Expands an STL type.
        Example:
        "std::map<int, int>"
        into
        "std::map<int, int, std::less<int>, std::allocator<std::pair<const int, int>>>"

        Args:
            stl_t (str): The unexpanded STL type

        Returns:
            str
        """  # noqa: E501
        def flatten_and_expand(s: STL_TREE) -> str:
            r: list[str] = []

            for i, t in enumerate(s):
                if isinstance(t, str):
                    if "std::" not in t:
                        r.append(t)
                        continue

                    if t == "std::string":
                        return "{} {}{}".format(
                            cast(str, s[0]),
                            STLUtils.STL_EXPANSION_MAP["std::string"],
                            cast(str, s.pop(-1))
                        ).lstrip()

                    expanded_stl_t = STLUtils.STL_EXPANSION_MAP[t]

                    r.append(expanded_stl_t)

                    if "std::" in s[i + 1][1]:
                        r.append(flatten_and_expand(cast(list, s.pop(i + 1))))
                    else:
                        contained = cast(list[str], s.pop(i + 1))
                        r.append("{} {}{}".format(*contained).lstrip())

                    if STLUtils.has_two_templates(expanded_stl_t):
                        if "std::" in s[i + 1][1]:
                            r.append(
                                flatten_and_expand(cast(list, s.pop(i + 1)))
                            )
                        else:
                            contained = cast(list[str], s.pop(i + 1))
                            r.append("{} {}{}".format(*contained).lstrip())

                    # 0 is const or empty
                    # 1 is stl format string
                    # whatever after are its arguments
                    # -1 is ptr or reference
                    r = [
                        "{} {}{}".format(
                            r[0],
                            r[1].format(*r[2:]),
                            s.pop(-1)
                        ).lstrip()
                    ]

                    continue

            return r[0]

        return flatten_and_expand(STLUtils.split_stl_type(stl_t))

    @staticmethod
    def stl_value_types(
        raw: str
    ) -> list[tuple[str, bool]]:
        """
        Walk split_stl_type tree, yielding (bare_type, is_by_value)
        for every leaf type.
        """
        tree = STLUtils.split_stl_type(raw)
        results: list[tuple[str, bool]] = []

        def walk(node, parent_by_value: bool = True):
            # STL_Tree list
            if isinstance(node, list):
                ptr_slot = node[-1] if isinstance(node[-1], str) else ""
                by_value = "*" not in ptr_slot and "&" not in ptr_slot

                for item in node:
                    if isinstance(item, list):
                        walk(item, by_value)
                    elif isinstance(item, str):
                        if item in ("const", "*", "&", ""):
                            continue
                        if item.startswith("std::"):
                            continue

                        bare = STLUtils.strip_crp(item)
                        if bare:
                            results.append((bare, by_value))
            elif isinstance(node, str):
                if node in ("const", "*", "&", ""):
                    return
                if node.startswith("std::"):
                    return

                bare = STLUtils.strip_crp(node)
                if bare:
                    results.append((bare, parent_by_value))

        walk(tree)
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

from functools import cached_property
from dataclasses import dataclass, field

from pybroma import Class

from broma_ida.data.data_manager import DataManager
from broma_ida.broma.binding import FunctionSignature
from broma_ida.broma.argtype import STLUtils


@dataclass(frozen=True, slots=True)
class STLMember:
    type: str
    name: str

    @property
    def expanded_type(self) -> str:
        if "std::" not in self.type:
            return self.type
        return STLUtils.expand_stl_type(self.type)

    def __str__(self) -> str:
        return f"{self.type} {self.name}"


@dataclass(slots=True)
class STLStubDefinition:
    class_name: str
    members: list[STLMember] = field(default_factory=list)

    def emit(self) -> str:
        if not self.members:
            return ""
        body = f"class {self.class_name} {{\npublic:\n"
        for m in self.members:
            body += f"\t{m};\n"
        body += "};\n"
        return body


@dataclass(slots=True)
class STLTypeDefinitions:
    ptr: STLStubDefinition
    value: STLStubDefinition


class ClassGraph:
    """Encodes the full inheritance topology of all Broma classes."""

    _classes: dict[str, Class]
    _info: dict[str, "ClassGraph._ClassInfo"]
    _namespace_prefixes: set[str]

    class_order: list[str]

    @dataclass
    class _ClassInfo:
        """All relevant info of a Broma class for ClassGraph."""
        name: str

        # list instead of set to keep the order for imports
        own_virtuals: list[FunctionSignature] = field(default_factory=list)

        inherited_virtuals: set[FunctionSignature] = field(default_factory=set)
        inherited_virtuals_by_name: dict[str, set[FunctionSignature]] = field(default_factory=dict)

        # normalized_type -> [(stripped_leaf_type, is_by_value), ...]
        type_refs: dict[str, list[tuple[str, bool]]] = field(default_factory=dict)

    def __init__(self, classes: dict[str, Class]):
        self._classes = classes
        self._info = {}
        self._namespace_prefixes = set()
        self.class_order = []

        for name, cls in classes.items():
            self._info[name] = self._build_class_info(name, cls)
            if "::" in name:
                self._namespace_prefixes.add("::".join(name.split("::")[:-1]))

        # inherited_virtuals needs all _ClassInfo to already exist
        # (it recurses across classes), so it can't be folded into
        # the loop above
        for name in classes:
            self._resolve_inherited_virtuals(name)

        self._emit_order()

        if DataManager().get("debug_info") == True:
            self.diagnose_broken_overrides()

    @staticmethod
    def _build_class_info(
        name: str,
        cls: Class
    ) -> "ClassGraph._ClassInfo":
        """
        Single pass over a class's fields, populating both
        own_virtuals and type_refs at once.
        Must run `_resolve_inherited_virtuals` after all
        class info instances are built to populate them.
        """
        info = ClassGraph._ClassInfo(name=name)

        def process_type(raw: str):
            normalized = STLUtils.normalize_type(raw)
            if normalized in info.type_refs:
                return

            if "std::" in normalized:
                info.type_refs[normalized] = STLUtils.stl_value_types(normalized)
            else:
                bare = STLUtils.strip_crp(normalized)
                if bare:
                    by_value = "*" not in normalized and "&" not in normalized
                    info.type_refs[normalized] = [(bare, by_value)]

        for f in cls.fields:
            ff = f.getAsFunctionBindField()
            mf = f.getAsMemberField()

            if ff is not None:
                process_type(ff.prototype.ret.name)
                for _, arg_t in ff.prototype.args:
                    process_type(arg_t.name)

                if ff.prototype.is_virtual:
                    info.own_virtuals.append(
                        FunctionSignature.from_field(name, ff)
                    )
            elif mf is not None:
                process_type(mf.type.name)

        return info

    def _resolve_inherited_virtuals(self, name: str) -> set[FunctionSignature]:
        info = self._info.get(name)
        if info is None:
            return set()

        if info.inherited_virtuals:
            return info.inherited_virtuals

        cls = self._classes.get(name)
        if cls is None:
            return set()

        # getting all virtual functions that the bases
        # (and also their bases) declare themselves
        sigs: set[FunctionSignature] = set()
        for base_name in cls.superclasses:
            base_info = self._info.get(base_name)
            if base_info:
                sigs |= set(base_info.own_virtuals)
            sigs |= self._resolve_inherited_virtuals(base_name)

        for sig in sigs:
            info.inherited_virtuals_by_name.setdefault(sig.name, set()).add(sig)

        return sigs

    @staticmethod
    def primary_base(i_cls: Class) -> str:
        """First superclass."""
        if i_cls is None or not i_cls.superclasses:
            return ""
        return i_cls.superclasses[0]

    @staticmethod
    def secondary_bases(i_cls: Class) -> list[str]:
        """All superclasses beyond the first."""
        if i_cls is None or len(i_cls.superclasses) < 2:
            return []
        return i_cls.superclasses[1:]

    def is_override(
        self,
        class_name: str,
        sig: FunctionSignature
    ) -> bool:
        """
        True if the given function is an override
        from any of the bases in the inheritance chain.

        Args:
            class_name (str):
                Name of the class the function to check comes from.
            sig (FunctionSignature):
                The signature of the function to check for.

        Returns:
            bool
        """
        info = self._info.get(class_name)
        return info is not None and sig in info.inherited_virtuals

    def is_secondary_override(
        self,
        cls: Class,
        sig: FunctionSignature
    ) -> bool:
        """
        True if the given function is an override
        from a secondary base in the inheritance chain.

        Args:
            cls (Class):
                The `Class` instance the function to check comes from.
            sig (FunctionSignature):
                The signature of the function to check for.

        Returns:
            bool
        """
        if cls is None:
            return False

        for base_name in self.secondary_bases(cls):
            base_info = self._info.get(base_name)
            if base_info is None:
                continue

            # if signature exists in either the secondary base itself
            # or in the base's own inherited functions
            if sig in base_info.own_virtuals or sig in base_info.inherited_virtuals:
                return True

        return False

    def get_own_virtuals(self, name: str) -> list[FunctionSignature]:
        info = self._info.get(name)
        return info.own_virtuals if info else []

    @cached_property
    def forward_declarations(self) -> list[str]:
        """
        A `list` of classes needed to be declared
        as an empty class beforehand - "forward-declared" -
        for by-reference types in other members/functions to work.

        Returns:
            list[str]
        """
        position = {name: i for i, name in enumerate(self.class_order)}
        fwd_needed: list[str] = list(self.stl_forward_declarations)
        seen: set[str] = set(self.stl_forward_declarations)

        for class_name, info in self._info.items():
            class_pos = position.get(class_name, -1)
            for entries in info.type_refs.values():
                for bare, by_value in entries:
                    if (
                        by_value
                        or bare not in self._classes
                        or bare in self._namespace_prefixes
                    ):
                        continue

                    bare_pos = position.get(bare)
                    needs_fwd = (
                        bare_pos is not None
                        and bare_pos > class_pos
                        and bare not in seen
                    )
                    if needs_fwd:
                        seen.add(bare)
                        fwd_needed.append(bare)

        return fwd_needed

    @cached_property
    def _stl_derived(self) -> tuple[set[str], "STLTypeDefinitions"]:
        """
        Single pass over all STL type references, computing both:
        - the forward-declaration set for by-pointer STL-referenced classes
        - the stub struct definitions (ptr/value)
        """
        stl_fwd_needed: set[str] = set()
        ptr = STLStubDefinition("__BromaSTLTypesPtr")
        value = STLStubDefinition("__BromaSTLTypesValue")
        seen_members: set[str] = set()
        idx = 0

        for info in self._info.values():
            for type_str, entries in info.type_refs.items():
                if "std::" not in type_str:
                    continue

                for bare, by_value in entries:
                    if by_value or bare in self._namespace_prefixes:
                        continue
                    if bare in self._classes:
                        stl_fwd_needed.add(bare)

                stripped = STLUtils.strip_crp(type_str)
                if stripped in seen_members:
                    continue
                seen_members.add(stripped)

                member = STLMember(stripped, f"m_{idx}")
                idx += 1

                target = value if any(bv for _, bv in entries) else ptr
                target.members.append(member)

        return stl_fwd_needed, STLTypeDefinitions(ptr, value)

    @property
    def stl_forward_declarations(self) -> set[str]:
        """
        All by-pointer referenced types extracted
        from within STL types. Primarily used for
        emitting forward-declarations.

        Returns:
            set[str]
        """
        return self._stl_derived[0]

    @property
    def stl_type_definitions(self) -> "STLTypeDefinitions":
        """
        Retrieve the unexpanded STL types needed to be
        defined in two stub dummy classes under a 
        `STLTypeDefinitions` instance:
        - Member/function types used by reference
        - Member/function types used by value

        Returns:
            STLTypeDefinitions: Contains two `STLStubDefinition`
                instances with names "__BromaSTLTypesPtr"
                and "__BromaSTLTypesValue".
        """
        return self._stl_derived[1]

    def get_broken_overrides(
        self, class_name: str
    ) -> list[tuple[FunctionSignature, set[FunctionSignature]]]:
        """
        Finds own virtuals in `class_name` that share a name with a base
        class's virtual but don't match its full signature, which
        would most likely be an error than intended.

        Returns:
            list of (own_sig, conflicting_base_sigs) pairs.
        """
        info = self._info.get(class_name)
        if info is None:
            return []

        broken: list[tuple[FunctionSignature, set[FunctionSignature]]] = []

        for own_sig in info.own_virtuals:
            same_name = info.inherited_virtuals_by_name.get(own_sig.name)
            if not same_name or own_sig in same_name:
                continue

            broken.append((own_sig, same_name))

        return broken

    def diagnose_broken_overrides(self) -> None:
        """
        Scans every class for virtuals that look like
        intended overrides (same name as a base virtual) but don't
        signature-match, and prints them.
        """
        found_any = False

        for class_name in self._classes:
            for own_sig, conflicts in self.get_broken_overrides(class_name):
                found_any = True
                conflict_list = ", ".join(str(c) for c in conflicts)
                print(
                    f"[!] ClassGraph: Possible broken override in {class_name}: "
                    f"{own_sig} does not match base signature(s) [{conflict_list}]"
                )

        if not found_any:
            print("[+] ClassGraph: No broken overrides detected.")

    def _get_hard_deps(self, class_name: str) -> list[str]:
        """
        Types that must be fully defined before class_name.
        Includes:
        - superclasses (inheritance)
        - by-value member types (bare structs and STL value params)

        Args:
            class_name (str)

        Returns:
            list[str]
        """
        cls = self._classes.get(class_name)
        info = self._info.get(class_name)
        if cls is None or info is None:
            return []

        deps: list[str] = list(cls.superclasses)
        seen: set[str] = set(deps)

        for entries in info.type_refs.values():
            for bare, by_value in entries:
                if by_value and bare in self._classes and bare not in seen:
                    seen.add(bare)
                    deps.append(bare)

        return deps

    def _emit_order(self):
        """
        Topologically sorts the class names per inheritence
        and member types for correct order of definition.
        """
        visited: set[str] = set()

        def visit(name: str):
            if name in visited:
                return
            visited.add(name)

            # skip bare namespace names entirely
            if name in self._namespace_prefixes:
                return

            for dep in self._get_hard_deps(name):
                visit(dep)
            self.class_order.append(name)

        for name in self._classes:
            visit(name)

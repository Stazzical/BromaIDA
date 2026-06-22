from pybroma import Class

from broma_ida.broma.binding import FunctionSignature
from broma_ida.broma.argtype import STLUtils


class ClassGraph:
    """Encodes the full inheritance topology of all Broma classes."""
    _classes: dict[str, Class]
    _inherited_virtuals_cache: dict[str, set[FunctionSignature]]
    # list instead of set to keep the order for imports
    _own_virtuals_cache: dict[str, list[FunctionSignature]]
    # this is horrible
    _type_refs: dict[str, dict[str, list[tuple[str, bool]]]]
    _namespace_prefixes: set[str]

    class_order: list[str]

    def __init__(self, classes: dict[str, Class]):
        self._classes = classes
        self._inherited_virtuals_cache: dict[str, set[FunctionSignature]] = {}
        self._own_virtuals_cache: dict[str, list[FunctionSignature]] = {}
        self._type_refs: dict[str, dict[str, list[tuple[str, bool]]]] = {}
        self._namespace_prefixes: set[str] = set()
        self.class_order = []

        for name in classes:
            self._get_inherited_virtuals(name)
            self.get_own_virtuals(name)

            if "::" in name:
                self._namespace_prefixes.add("::".join(name.split("::")[:-1]))

        self._build_type_refs()
        self._emit_order()

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
        """
        return sig in self._inherited_virtuals_cache.get(class_name, set())

    def is_secondary_override(
        self,
        cls: Class,
        sig: FunctionSignature
    ) -> bool:
        """
        True if the given virtual function was an override
        from a secondary base in the inheritance chain.
        """
        if cls is None:
            return False

        for base_name in self.secondary_bases(cls):
            # if signature exists in either the secondary base itself
            # or in the base's own inherited functions
            if sig in self.get_own_virtuals(base_name) or \
                sig in self._get_inherited_virtuals(base_name):
                return True

        return False

    @property
    def forward_declarations(self) -> list[str]:
        """
        A `list` of classes needed to be declared
        as an empty class beforehand - "forward-declared" -
        for by-reference types in other members/functions to work.

        Returns:
            list[str]
        """
        position = {name: i for i, name in enumerate(self.class_order)}
        fwd_needed: list[str] = []
        seen: set[str] = set()

        # TODO: consider using a new class type for
        # type references indexing, this really sucks
        for class_name in self._classes:
            class_pos = position.get(class_name, -1)
            for entries in self._type_refs[class_name].values():
                for bare, by_value in entries:
                    bare_pos = position.get(bare)

                    if by_value:
                        continue  # hard dep, emit_order handles it
                    if bare not in self._classes:
                        continue  # only classes we can actually define
                    if bare in self._namespace_prefixes:
                        continue

                    needs_fwd = (
                        bare in self.stl_forward_declarations or
                        (
                            bare_pos is not None
                            and bare_pos > class_pos
                            and bare not in seen
                        )
                    )

                    if needs_fwd:
                        seen.add(bare)
                        fwd_needed.append(bare)

        return fwd_needed

    @property
    def stl_forward_declarations(self):
        stl_fwd_needed = set()

        for fields in self._type_refs.values():
            for type, entries in fields.items():
                if "std::" not in type:
                    continue

                for bare, by_value in entries:
                    if by_value:
                        continue
                    if bare in self._namespace_prefixes:
                        continue

                    if bare in self._classes:
                        stl_fwd_needed.add(bare)

        return stl_fwd_needed

    @property
    def stl_type_definitions(self) -> tuple[list[str], list[str]]:
        """
        Retrieve the unexpanded STL types needed to be
        defined in a dummy class in two `list` parts
        inside a `tuple`:
        - Member/function types used by reference
        - Member/function types used by value

        Returns:
            tuple[list[str], list[str]]
        """
        ptr_members: list[str] = []
        value_members: list[str] = []
        seen: set[str] = set()
        idx = 0

        for fields in self._type_refs.values():
            for type, entries in fields.items():
                if "std::" not in type:
                    continue

                stripped = STLUtils.strip_crp(type)

                if stripped in seen:
                    continue
                seen.add(stripped)

                member = f"{stripped} m_{idx}"
                idx += 1

                # if any entry for this raw type is by_value, it goes
                # in the value section, those need full definitions
                if any(by_value for _, by_value in entries):
                    value_members.append(member)
                else:
                    ptr_members.append(member)

        return ptr_members, value_members

    def _get_hard_deps(self, class_name: str) -> list[str]:
        """
        Types that must be fully defined before class_name.
        - superclasses (inheritance)
        - by-value member types (bare structs and STL value params)

        Returns:
            list[str]
        """
        cls = self._classes.get(class_name)
        if cls is None:
            return []

        # superclasses
        deps: list[str] = list(cls.superclasses)
        seen: set[str] = set(deps)

        type_refs = self._type_refs[cls.name]

        for types in type_refs.values():
            for type, by_value in types:
                if by_value and type in self._classes and \
                        type not in seen:
                    seen.add(type)
                    deps.append(type)

        return deps

    def _build_type_refs(self):
        """
        Builds a collection of type references based on
        properties such as class name, normalized type
        and `tuple`s of bare stripped leaf types and if they are
        referenced by value.
        """
        def process(cls_name: str, raw: str):
            self._type_refs.setdefault(cls_name, {})

            normalized = STLUtils.normalize_type(raw)
            if normalized in self._type_refs[cls_name]:
                return

            if "std::" in normalized:
                self._type_refs[cls_name][normalized] = STLUtils.stl_value_types(normalized)
            else:
                bare = STLUtils.strip_crp(normalized)
                if bare:
                    by_value = "*" not in normalized and "&" not in normalized
                    self._type_refs[cls_name][normalized] = [(bare, by_value)]

        for cls_name, cls in self._classes.items():
            for f in cls.fields:
                ff = f.getAsFunctionBindField()
                mf = f.getAsMemberField()

                if ff is not None:
                    process(cls_name, ff.prototype.ret.name)

                    for arg_t in ff.prototype.args.values():
                        process(cls_name, arg_t.name)
                elif mf is not None:
                    process(cls_name, mf.type.name)

    def _emit_order(self):
        """
        Topologically sorts the class names per inheritence
        and member types for correct order of import.
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

    def _get_inherited_virtuals(self, name: str) -> set[FunctionSignature]:
        if name in self._inherited_virtuals_cache:
            return self._inherited_virtuals_cache[name]

        cls = self._classes.get(name)
        if cls is None:
            self._inherited_virtuals_cache[name] = set()
            return set()

        # getting all virtual functions that the bases
        # (and also their bases) declare themselves
        sigs: set[FunctionSignature] = set()

        # as of writing, the official Broma parser currently
        # also appends any classes inside the "depends" attribute
        # of Broma class definitions, so we don't worry about it.
        for base_name in cls.superclasses:
            base_cls = self._classes.get(base_name)

            if base_cls:
                for field in base_cls.fields:
                    ff = field.getAsFunctionBindField()

                    if ff and ff.prototype.is_virtual:
                        sigs.add(
                            FunctionSignature.from_field(base_name, ff)
                        )

            sigs |= self._get_inherited_virtuals(base_name)

        self._inherited_virtuals_cache[name] = sigs

        return sigs

    def get_own_virtuals(self, name: str) -> list[FunctionSignature]:
        if name in self._own_virtuals_cache:
            return self._own_virtuals_cache[name]

        cls = self._classes.get(name)
        if cls is None:
            self._own_virtuals_cache[name] = []
            return []

        sigs: list[FunctionSignature] = []
        for field in cls.fields:
            ff = field.getAsFunctionBindField()

            if ff and ff.prototype.is_virtual:
                sigs.append(
                    FunctionSignature.from_field(cls.name, ff)
                )

        self._own_virtuals_cache[name] = sigs

        return sigs

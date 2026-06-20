from pybroma import Class

from broma_ida.broma.binding import FunctionSignature
from broma_ida.broma.argtype import STLUtils


class ClassGraph:
    """Encodes the full inheritance topology of all Broma classes."""
    _classes: dict[str, Class]
    _inherited_virtuals_cache: dict[str, set[FunctionSignature]]
    _own_virtuals_cache: dict[str, set[FunctionSignature]]
    _namespace_prefixes: set[str]

    class_order: list[str]

    def __init__(self, classes: dict[str, Class]):
        self._classes = classes
        self._inherited_virtuals_cache: dict[str, set[FunctionSignature]] = {}
        self._own_virtuals_cache: dict[str, set[FunctionSignature]] = {}
        self._namespace_prefixes: set[str] = set()

        for name in classes:
            self._get_inherited_virtuals(name)
            self.get_own_virtuals(name)

            if "::" in name:
                self._namespace_prefixes.add("::".join(name.split("::")[:-1]))

        self._emit_order()

    def primary_base(self, cls: Class) -> str | None:
        """First superclass, the one whose vtable is the primary."""
        if cls is None or not cls.superclasses:
            return None

        return cls.superclasses[0]

    def secondary_bases(self, cls: Class) -> list[str]:
        """All superclasses beyond the first."""
        if cls is None or len(cls.superclasses) < 2:
            return []

        return cls.superclasses[1:]
    
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
    def forward_declarations(self) -> set[str]:
        position = {name: i for i, name in enumerate(self.class_order)}
        fwd_needed: set[str] = set()

        for class_name, cls in self._classes.items():
            class_pos = position.get(class_name, -1)

            for f in cls.fields:
                ff = f.getAsFunctionBindField()
                mf = f.getAsMemberField()

                raw_types: list[str] = []

                if ff:
                    proto = ff.prototype
                    raw_types.append(
                        proto.ret.name
                    )
                    for arg_t in proto.args.values():
                        raw_types.append(
                            arg_t.name
                        )
                elif mf:
                    raw = mf.type.name
                    # by-value members are hard deps
                    # emit_order handles them, skip here
                    if "*" in raw or "&" in raw:
                        raw_types.append(raw)

                for raw_type in raw_types:
                    for bare in STLUtils.extract_bare_types(raw_type):
                        # only the classes we can define from self._classes
                        if bare not in self._classes:
                            continue
                        if bare in self._namespace_prefixes:
                            continue

                        ref_pos = position.get(bare, -1)
                        if ref_pos > class_pos or ref_pos == -1:
                            fwd_needed.add(bare)

        return fwd_needed

    def _get_hard_deps(self, class_name: str) -> list[str]:
        """
        Types that must be fully defined before class_name.
        - superclasses (inheritance)
        - by-value member types (bare structs and STL value params)
        """
        cls = self._classes.get(class_name)
        if cls is None:
            return []

        deps: list[str] = list(cls.superclasses)

        def check_type(type):
            # bare member: by-value if no pointer or reference
            if "*" not in type and "&" not in type:
                bare = STLUtils.strip_crp(type)
                if bare in self._classes:
                    deps.append(bare)

        for field in cls.fields:
            ff = field.getAsFunctionBindField()
            mf = field.getAsMemberField()

            if ff is not None:
                check_type(ff.prototype.ret.name)

                for type in ff.prototype.args.values():
                    check_type(type.name)
            elif mf is not None:
                raw = mf.type.name

                if "std::" in raw:
                    for bare, by_value in STLUtils.stl_value_types(raw):
                        if by_value and bare in self._classes:
                            deps.append(bare)
                else:
                    check_type(raw)

        return deps

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

    def get_own_virtuals(self, name: str) -> set[FunctionSignature]:
        if name in self._own_virtuals_cache:
            return self._own_virtuals_cache[name]

        cls = self._classes.get(name)
        if cls is None:
            self._own_virtuals_cache[name] = set()
            return set()

        sigs: set[FunctionSignature] = set()
        for field in cls.fields:
            ff = field.getAsFunctionBindField()

            if ff and ff.prototype.is_virtual:
                sigs.add(
                    FunctionSignature.from_field(cls.name, ff)
                )

        self._own_virtuals_cache[name] = sigs

        return sigs

from dataclasses import dataclass, field
from functools import cached_property

from ida_name import is_visible_cp

from pybroma import (
    FunctionProto, MemberFunctionProto,
    FunctionBindField, Function
)

from broma_ida.broma.argtype import ArgType, RetType
from broma_ida.ida_utils import IDAUtils


@dataclass
class FunctionSignature:
    """
    A container for the signature of a C++ function.
    Includes the return type as a `RetType`, and arguments
    as a list of `ArgType` constructed classes.
    """

    name: str
    "Name of the function without namespaces. Use `qualified_name` for the full name."
    class_name: str
    """
    Class(es) and/or namespace(s) this function is part of.
    Empty for free functions.
    """
    ret: RetType = field(default_factory=lambda: RetType(""))
    parameters: list[ArgType] = field(default_factory=list)
    is_virtual: bool = False
    is_static: bool = False
    is_const: bool = False
    is_inline: bool = False
    is_missing: bool = False
    is_ctor: bool = False
    is_dtor: bool = False
    is_variadic: bool = False

    @staticmethod
    def _check_if_variadic(proto: FunctionProto | MemberFunctionProto) -> bool:
        """
        Whether `proto` (a Broma FunctionProto/MemberFunctionProto) is
        variadic. Prefers the explicit `is_variadic` AST field on newer
        PyBroma or falls back to detecting a literal `...` type
        for older versions.

        Args:
            proto (FunctionProto | MemberFunctionProto)

        Returns:
            bool
        """
        if getattr(proto, "is_variadic", False):
            return True

        # fallback compatibility
        return any(arg_t.name == "..." for _, arg_t in proto.args)

    @staticmethod
    def _extract_common(f: FunctionBindField | Function) -> dict:
        """
        Shared field extraction for from_field/from_freefunc classmethods.

        Args:
            f (FunctionBindField | Function)

        Returns:
            dict
        """
        proto = f.prototype
        platform = IDAUtils.get_platform()
        # get address as an int at base of 16 (hexadecimal int)
        # here we only use it to know if the function was inlined
        # or missing on the target platform

        # -2 is explicitly inlined, -1 is not found
        raw_addr = getattr(f.binds, platform, -1)

        return {
            "name": proto.name,
            "ret": RetType(proto.ret.name),
            "parameters": [
                ArgType(arg_t.name, param_name)
                for param_name, arg_t in proto.args
                if arg_t.name != "..."  # variadic ellipsis gets removed here
            ],
            "is_variadic": FunctionSignature._check_if_variadic(proto),
            "is_virtual": getattr(proto, "is_virtual", False),
            "is_static": getattr(proto, "is_static", False),
            "is_const": getattr(proto, "is_const", False),
            "is_inline": raw_addr == -2,
            "is_missing": platform in proto.attrs.missing,
            "_raw_addr": raw_addr,
        }

    @staticmethod
    def _check_ctor_dtor_ret(data: dict, class_name: str) -> dict:
        """
        Sets the is_ctor and is_dtor properties based
        on the name of the function and whether it comes
        from a class.

        Args:
            data (dict): The dict returned by `_extract_common`.
            class_name (str)

        Returns:
            dict: The same dict, with `is_ctor` or `is_dtor`
                property set if relevant.
        """
        if class_name != "":
            last_class = class_name.split("::")[-1]
            if data["name"] == last_class:
                data["is_ctor"] = True
            elif data["name"] == f"~{last_class}":
                data["is_dtor"] = True

        return data

    @classmethod
    def from_field(
        cls,
        class_name: str,
        f: FunctionBindField
    ) -> "FunctionSignature":
        """
        Get a FunctionSignature class instance from the
        class name and FunctionBindField instance.

        Args:
            class_name (str)
            f (FunctionBindField)

        Returns
            FunctionSignature
        """
        data = cls._extract_common(f)
        # FunctionSignature doesn't keep address, remove
        data.pop("_raw_addr")
        data = cls._check_ctor_dtor_ret(data, class_name)
        return cls(class_name=class_name, **data)

    @cached_property
    def is_ctor_dtor(self) -> bool:
        return self.is_ctor or self.is_dtor

    @cached_property
    def ida_rettype(self) -> "RetType":
        """
        Returns a RetType instance of the function's
        return type relevant to IDA. This changes
        constructors' return type to their class type
        and destructors' to `void`.

        Returns:
            RetType
        """
        # ret is shared with codegen, so
        # let's not make a mess there and do
        # our IDA-specific stuff right here...
        bind_rettype = self.ret

        if self.is_ctor:
            bind_rettype = RetType.for_ctor(self.class_name)
        elif self.is_dtor:
            bind_rettype = RetType.for_dtor()

        return bind_rettype

    @cached_property
    def qualified_name(self) -> str:
        """
        The qualified name of the function.

        Returns:
            str: ClassName::MethodName or simply
                MethodName if it's a free function.
        """
        return f"{self.class_name + '::' if self.class_name != '' else ''}{self.name}"

    @cached_property
    def ida_qualified_name(self) -> str:
        """
        The IDA qualified name of the function.
        '~' replaced with 'd' if not a visible codepoint.

        Returns:
            str
        """
        return self.qualified_name.replace(
            "~", "~" if is_visible_cp(ord("~")) else "d"
        )

    def get_args_str(
        self,
        include_this_arg: bool = True,
        expand_stl: bool = False
    ) -> str:
        """
        Gets a function's arguments signature string.

        Args:
            include_this_arg (bool, optional): Include the `this` argument.
                Defaults to True.
            expand_stl (bool, optional): Uses STL-expanded types instead
                of normal ones. Defaults to False.

        Returns:
            str
        """
        args = list(self.parameters)

        has_this_arg = (
            len(args) > 0
            and args[0].type == f"{self.class_name}*"
        )

        if include_this_arg and not self.is_static:
            if not has_this_arg:
                args.insert(0, ArgType(f"{self.class_name}*", "this"))
        elif has_this_arg:
            args = args[1:]

        parts = [
            arg.expanded_type if expand_stl
            else str(arg)
            for arg in args
        ]

        if self.is_variadic:
            parts.append("...")

        return ", ".join(parts)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FunctionSignature):
            return (
                self.name == other.name
                and self.parameters == other.parameters
            )

        return NotImplemented

    def __hash__(self) -> int:
        return hash((
            self.name,
            tuple(p.type for p in self.parameters)
        ))

    def __str__(self) -> str:
        # this does NOT use qualified_name,
        # it represents the function independently
        return (
            f"{'static ' if self.is_static else ''}"
            f"{'virtual ' if self.is_virtual else ''}"
            f"{self.ret.type + ' ' if self.ret.type and not self.is_ctor_dtor else ''}"
            f"{self.name}({self.get_args_str(include_this_arg=False)})"
            f"{' const;' if self.is_const else ';'}"
        )


@dataclass
class Binding(FunctionSignature):
    """FunctionSignature extended with an address for IDA-specific use."""
    address: int = -1

    @classmethod
    def from_field(
        cls,
        class_name: str,
        f: FunctionBindField
    ) -> "Binding":
        """
        Get a Binding class instance from the
        class name and FunctionBindField instance.

        Args:
            class_name (str)
            f (FunctionBindField)

        Returns
            Binding
        """
        data = cls._extract_common(f)
        address = data.pop("_raw_addr")
        data = cls._check_ctor_dtor_ret(data, class_name)
        return cls(class_name=class_name, address=address, **data)

    @classmethod
    def from_freefunc(cls, f: Function) -> "Binding":
        """
        Get a Binding class instance of a free
        function from its Function instance.

        Args:
            f (Function)

        Returns
            Binding
        """
        data = cls._extract_common(f)
        address = data.pop("_raw_addr")
        return cls(class_name="", address=address, **data)

    @cached_property
    def has_address(self) -> bool:
        """True if the binding is not missing or inlined."""
        return self.address not in (-1, -2)

    @cached_property
    def short_info(self) -> str:
        """
        Short info about the binding.

        Returns:
            str: "[binding qualified name] @ [binding address]"
        """
        return f"{self.qualified_name} @ {hex(self.address)}"

    @property
    def signature(self) -> str:
        """C++ function signature string."""
        # IDA drops const declaration for methods
        return (
            f"{'static ' if self.is_static else ''}"
            f"{'virtual ' if self.is_virtual else ''}"
            f"{self.ret.type} "
            f"{self.ida_qualified_name}({self.get_args_str()});"
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, int):
            return self.address == other
        elif isinstance(other, str):
            return self.qualified_name == other
        elif isinstance(other, Binding):
            return (
                self.signature == other.signature
                and self.address == other.address
            )

        return NotImplemented

    def __hash__(self) -> int:
        return hash((
            self.qualified_name,
            self.address,
            tuple(str(arg) for arg in self.parameters)
        ))

    def __str__(self) -> str:
        return (
            f"{'virtual ' if self.is_virtual else ''}"
            f"{'static ' if self.is_static else ''}"
            f"{self.ret.type} "
            f"{self.qualified_name}"
            f"({', '.join(arg.type for arg in self.parameters)})"
            f" @ {hex(self.address)}; "
            f"({self.ida_qualified_name})"
        )

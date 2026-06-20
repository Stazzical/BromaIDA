from dataclasses import dataclass, field, is_dataclass
from functools import cache, cached_property

from ida_name import is_visible_cp

from pybroma import FunctionBindField

from broma_ida.broma.argtype import ArgType, RetType
from broma_ida.utils import IDAUtils


@dataclass
class FunctionSignature:
    """
    A container for the signature of a C++ function.
    Includes the return type, and arguments as a list of
    ArgType constructed classes.
    """
    name: str
    class_name: str
    ret: RetType = field(default_factory=lambda: RetType(""))
    parameters: list[ArgType] = field(default_factory=list)
    is_virtual: bool = False
    is_static: bool = False
    is_const: bool = False
    is_inline: bool = False
    
    @classmethod
    def from_field(
        cls,
        class_name: str,
        f: FunctionBindField
    ) -> FunctionSignature:
        proto = f.prototype
        # get address as an int at base of 16 (hexadecimal int)
        # here we only use it to know if the function was inlined
        # on the target platform
        raw_addr = int(
            getattr(f.binds, IDAUtils.get_platform(), -1), # type: ignore
            16
        )

        return cls(
            name=proto.name,
            class_name=class_name,
            ret=RetType(proto.ret.name),
            parameters=[
                ArgType(arg_t.name, param_name)
                for param_name, arg_t in proto.args.items()
            ],
            is_virtual=proto.is_virtual,
            is_static=proto.is_static,
            is_const=proto.is_const,
            is_inline=(raw_addr == 0)
        )

    @property
    def qualified_name(self) -> str:
        """
        The qualified name of a binding.

        Returns:
            str: ClassName::MethodName
        """
        return f"{self.class_name}::{self.name}"

    @cached_property
    def ida_qualified_name(self) -> str:
        """
        The IDA qualified name of a binding.
        '~' replaced with 'd' if not a visible codepoint.

        Returns:
            str
        """
        return f"{self.class_name}::{self.name}".replace(
            "~", "~" if is_visible_cp(ord("~")) else "d"
        )

    @cached_property
    def signature(self) -> str:
        """C++ function signature string."""
        # IDA drops const declaration for methods
        return (
            f"{'static ' if self.is_static else ''}"
            f"{'virtual ' if self.is_virtual else ''}"
            f"{self.ret.type} {self.ida_qualified_name}({self.get_args_str()});"
        )

    @property
    def has_stl_args(self) -> bool:
        """
        True if any parameter contains a non-string STL type.
        Used to determine whether special STL fixup is needed
        when applying the signature to IDA.
        """
        # we don't have an issue with std::string, only with generic stl types
        return any(
            "std::" in p.type and p.stripped_type != "std::string"
            for p in self.parameters
        )

    @property
    def has_stl_ret(self) -> bool:
        """
        True if the return type is a non-string STL type.
        Used to determine whether special STL fixup is needed
        when applying the signature to IDA.
        """
        return (
            "std::" in self.ret.type
            and self.ret.stripped_type != "std::string"
        )

    @property
    def needs_stl_fixup(self) -> bool:
        """
        True if this signature requires the STL parameter
        fixup path in IDA rather than a plain SetType call.
        """
        return self.has_stl_args or self.has_stl_ret

    @cache
    def get_args_str(
        self,
        include_this_arg: bool = True
    ) -> str:
        """
        Gets a function's argument string.

        Args:
            include_this_arg (bool, optional): Include the `this` argument.
                Defaults to True.

        Returns:
            str
        """
        args = self.parameters

        has_this_arg = (
            len(args) > 0
            and args[0].type == f"{self.class_name}*"
        )

        if include_this_arg and not self.is_static:
            if not has_this_arg:
                args.insert(0, ArgType(f"{self.class_name}*", "this"))
        elif has_this_arg:
            args = args[1:]

        return ", ".join([str(arg) for arg in args])

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
        # this does NOT use qualified_name
        return (
            f"{'static ' if self.is_static else ''}"
            f"{'virtual ' if self.is_virtual else ''}"
            f"{self.ret.type} {self.name}({self.get_args_str(include_this_arg=False)})"
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
    ) -> Binding:
        proto = f.prototype
        raw_addr = int(
            getattr(f.binds, IDAUtils.get_platform(), -1), # type: ignore
            16
        )

        return cls(
            name=proto.name,
            class_name=class_name,
            ret=RetType(proto.ret.name),
            parameters=[
                ArgType(arg_t.name, param_name)
                for param_name, arg_t in proto.args.items()
            ],
            is_virtual=proto.is_virtual,
            is_static=proto.is_static,
            is_const=proto.is_const,
            is_inline=(raw_addr == 0),
            address=raw_addr
        )

    @property
    def short_info(self) -> str:
        """
        Short info about the binding.

        Returns:
            str: "[binding qualified name] @ [binding address]"
        """
        return f"{self.qualified_name} @ {hex(self.address)}"

    def __eq__(self, value: object) -> bool:
        if isinstance(value, int):
            return self.address == value
        elif isinstance(value, str):
            return self.qualified_name == value
        elif is_dataclass(value):
            return self.__dataclass_fields__ == value.__dataclass_fields__

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
            f"{self.class_name}::{self.name}"
            f"({', '.join(str(arg) for arg in self.parameters)})"
            f" @ {hex(self.address)}; "
            f"({self.ida_qualified_name})"
        )

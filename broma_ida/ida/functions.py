from collections import defaultdict
from enum import IntEnum
from re import compile, fullmatch
from typing import Iterable, Final

from ida_idaapi import BADADDR
from ida_name import (
    get_name_ea, get_ea_name, set_name,
    SN_NOWARN, GN_SHORT, GN_DEMANGLED
)
from ida_funcs import (
    func_t as ida_func_t,
    FUNC_LIB, FUNC_THUNK
)
from ida_typeinf import (
    func_type_data_t as ida_func_type_data_t,
    udt_type_data_t as ida_udt_type_data_t,
    funcarg_t as ida_funcarg_t,
    tinfo_t as ida_tinfo_t,
    argloc_t as ida_argloc_t,
    apply_tinfo, print_tinfo,
    PRTYPE_1LINE,
    TINFO_DEFINITE, CM_CC_MASK,
    FAI_RETPTR, FAI_STRUCT,
    CM_CC_INVALID, CM_CC_UNKNOWN, CM_CC_VOIDARG,
    CM_CC_CDECL, CM_CC_ELLIPSIS, CM_CC_STDCALL,
    CM_CC_FASTCALL, CM_CC_THISCALL, CM_CC_SPECIAL,
    CM_CC_SPECIALE
)
from ida_nalt import (
    get_tinfo
)
from ida_ida import inf_get_cc_cm
from idautils import Names

from broma_ida.utils import CppUtils
from broma_ida.broma.argtype import ArgType, RetType
from broma_ida.ida.env import get_binary_info
from broma_ida.ida.type_library import (
    resolve_type_tinfo, resolve_bare_type,
    same_declared_type,
    native_int_type
)


AUTO_NAME_RE = compile(r"[pa]\d+")

VARARG_CCS = (CM_CC_ELLIPSIS, CM_CC_SPECIALE)

TO_VARARG = {
    CM_CC_UNKNOWN: CM_CC_ELLIPSIS, CM_CC_VOIDARG: CM_CC_ELLIPSIS,
    CM_CC_CDECL: CM_CC_ELLIPSIS, CM_CC_ELLIPSIS: CM_CC_ELLIPSIS,
    CM_CC_SPECIAL: CM_CC_SPECIALE, CM_CC_SPECIALE: CM_CC_SPECIALE,
}
FROM_VARARG = {CM_CC_ELLIPSIS: CM_CC_CDECL, CM_CC_SPECIALE: CM_CC_SPECIAL}


class CallingConvention(IntEnum):
    # NOT A BITMASK !!
    """Calling conventions enum for IDA's `cm_t` type."""

    invalid = CM_CC_INVALID     # = 0x00
    """Invalid calling convention"""
    unknown = CM_CC_UNKNOWN     # = 0x10
    """Unknown calling convention."""
    voidarg = CM_CC_VOIDARG     # = 0x20
    """
    Represents an empty function prototype 'func()'
    with a valid calling convention and 0 real arguments.
    """
    cdecl = CM_CC_CDECL         # = 0x30
    """__cdecl"""
    ellipsis = CM_CC_ELLIPSIS   # = 0x40
    """
    Calling convention for variadic functions.
    Handled internally by IDA between different architectures and bitnesses.
    """
    stdcall = CM_CC_STDCALL     # = 0x50
    """__stdcall, only relevant on 32-bit."""
    fastcall = CM_CC_FASTCALL   # = 0x70
    """__fastcall, only relevant on 32-bit."""
    thiscall = CM_CC_THISCALL   # = 0x80
    """__thiscall, only relevant on 32-bit."""
    special = CM_CC_SPECIAL     # = 0xF0
    """
    IDA's bitmask for user-defined calling conventions,
    AKA "__usercall".
    """


def _params_match(
    arg_types: list["ida_tinfo_t | None"],
    binding,
    strict: bool = False
) -> bool:
    if len(arg_types) != len(binding.parameters):
        return False

    for candidate, param in zip(arg_types, binding.parameters):
        # implicit skip for args that weren't demangled correctly from IDA
        if candidate is None:
            continue

        expected = resolve_type_tinfo(param)
        if expected is None:
            continue

        matches = (
            same_declared_type(candidate, expected) if strict
            else candidate.equals_to(expected)
        )
        if not matches:
            return False

    return True


def can_return_in_registers(tif: ida_tinfo_t) -> bool:
    """
    Checks if the given tinfo_t would return in
    registers, or the stack instead.
    """
    try:
        from ida_typeinf import calc_retloc
    except ImportError:
        calc_retloc = None

    if calc_retloc is not None:
        retloc = ida_argloc_t()
        if calc_retloc(retloc, tif, inf_get_cc_cm() & CM_CC_MASK):
            return retloc.is_reg1() or retloc.is_reg2()
    return tif.get_size() in get_binary_info().profile.reg_return_sizes


def resolve_calling_convention(existing_cc: int, is_variadic: bool) -> int:
    if not is_variadic:
        # keep IDA's cc, but never carry an ellipsis cc onto a non-variadic prototype
        return FROM_VARARG.get(existing_cc, existing_cc)

    cc = TO_VARARG.get(existing_cc)
    if cc is None:
        # fastcall/thiscall/stdcall can't be combined with an ellipsis in cm_t\
        return existing_cc

    return cc


class SignatureApplier:
    """
    Used for checking functions against IDA
    and applying correct signatures.
    """

    def __init__(self, known_nontrivials: Iterable[str] = ()) -> None:
        self._known_nontrivials = frozenset(known_nontrivials)
        self.checked = self.applied = self.failed = 0

    def ensure(self, ea: int, binding, context: str = "") -> bool:
        """
        Applies the binding's signature only if the IDB disagrees
        against the given `binding`.

        Args:
            ea (int)
            binding
            context (str, optional)

        Returns:
            bool
        """
        self.checked += 1
        if not self.has_mismatch(get_function_info(ea), binding):
            return True

        if self.apply(ea, binding):
            self.applied += 1
            return True

        self.failed += 1
        print(f"[!] SignatureApplier: Failed to fix signature for '{binding.qualified_name}' ({context})!")
        return False

    def print_summary(self) -> None:
        matched = self.checked - self.applied - self.failed
        print(
            f"[+] SignatureApplier: {self.applied} applied, {matched} already matched, "
            f"{self.failed} failed ({self.checked} checked)."
        )

    def has_mismatch(self, function, binding) -> bool:
        """
        Checks if there is a mismatch between the IDB and a binding.

        Args:
            function (ida_typeinf.func_type_data_t | None):
                The function type info container from IDA.
            binding (Binding): The binding.

        Returns:
            bool: True if mismatch exists between either the
                return type or the parameters.
        """
        needs_retptr: bool = False

        if function is None:
            return True

        if (function.get_cc() in VARARG_CCS) != binding.is_variadic:
            return True

        expected_rettype = function.rettype
        funcargs = list(function)
        if binding.ida_rettype.is_unknown:
            # keep IDA's own return type, and ignore a retptr it already has
            funcargs = [a for a in funcargs if not (a.flags & FAI_RETPTR)]
        else:
            resolved_ret = resolve_type_tinfo(binding.ida_rettype)
            needs_retptr = self._needs_retptr(binding.ida_rettype, resolved_ret)

            expected_rettype = resolved_ret
            if needs_retptr:
                expected_rettype = ida_tinfo_t()
                expected_rettype.create_ptr(resolved_ret)

            if expected_rettype is not None and \
                    not same_declared_type(function.rettype, expected_rettype):
                return True

        itanium_abi = get_binary_info().profile.itanium_abi

        if needs_retptr and itanium_abi:
            if not funcargs or not funcargs[0].type.equals_to(expected_rettype) \
                    or not (funcargs[0].flags & FAI_RETPTR):
                return True
            funcargs = funcargs[1:]

        # check if a 'ClassName* this' argument would be passed to the function
        if binding.class_name != "" and not binding.is_static:
            if not funcargs:
                return True

            this_arg = funcargs[0]
            this_tinfo = resolve_type_tinfo(
                ArgType.for_this(binding.class_name)
            )

            # trigger mismatch if the name is auto-generated by IDA
            type_matches = this_arg.type.equals_to(this_tinfo)
            name_is_auto = AUTO_NAME_RE.fullmatch(this_arg.name) is not None
            if not type_matches or name_is_auto:
                return True

            funcargs = funcargs[1:]

        if needs_retptr and not itanium_abi:
            if not funcargs or not funcargs[0].type.equals_to(expected_rettype) \
                    or not (funcargs[0].flags & FAI_RETPTR):
                return True
            funcargs = funcargs[1:]

        arg_types = [arg.type for arg in funcargs]
        if not _params_match(arg_types, binding, strict=True):
            return True

        for ida_arg, param in zip(funcargs, binding.parameters):
            # pX is Broma auto-generated name, aX is IDA auto-generated name
            if AUTO_NAME_RE.fullmatch(param.name) is None \
                    and ida_arg.name != param.name:
                return True

        return False

    def apply(self, ea: int, binding) -> bool:
        """
        Builds and applies a complete function signature at `ea` by
        resolving the return type and every parameter against IDA's
        type library (using `resolve_type_tinfo`),
        then constructing and applying a `func_type_data_t` directly.

        Args:
            ea (int): The function's address.
            binding: The binding instance to
                apply its info to the function.

        Returns:
            bool: True on success.
        """
        resolved_ret: ida_tinfo_t | None = None
        retptr_entry: tuple[str, ida_tinfo_t, int] | None = None
        existing_info = None

        existing_info = get_function_info(ea)
        existing_cc = existing_info.get_cc() if existing_info is not None else CM_CC_UNKNOWN

        # process the return type, decide if we need a __return_ptr argument applied
        if binding.ret.is_unknown:
            # keep whatever IDA currently guessed
            final_rettype = (
                existing_info.rettype if existing_info is not None
                else native_int_type()
            )

            for existing_arg in (list(existing_info) if existing_info is not None else []):
                # keep a __return_ptr arg if it existed from before
                if existing_arg.flags & FAI_RETPTR:
                    retptr_entry = (existing_arg.name, existing_arg.type, existing_arg.flags)
                    break

            needs_retptr = retptr_entry is not None
        else:
            resolved_ret = resolve_type_tinfo(binding.ret)
            if resolved_ret is None:
                print(
                    "[!] IDAUtils: Couldn't resolve return type "
                    f"'{binding.ret.type}' for function at {hex(ea)}!"
                )
                return False

            final_rettype = resolved_ret
            needs_retptr = self._needs_retptr(binding.ret, resolved_ret)

            if needs_retptr:
                retptr_tinfo = ida_tinfo_t()
                retptr_tinfo.create_ptr(resolved_ret)
                retptr_entry = ("retstr", retptr_tinfo, FAI_RETPTR | FAI_STRUCT)
                final_rettype = retptr_tinfo

        this_entry: tuple[str, ida_tinfo_t, int] | None = None
        if not binding.is_static and binding.class_name != "":
            this_tinfo = resolve_type_tinfo(
                ArgType.for_this(binding.class_name)
            )

            if this_tinfo is None:
                print(
                    "[!] IDAUtils: Couldn't resolve implicit 'this' "
                    f"argument ('{binding.class_name}*') for function at {hex(ea)}!"
                )
                return False

            this_entry = ("this", this_tinfo, 0)

        resolved_args: list[tuple[str, ida_tinfo_t, int]] = []
        for arg in binding.parameters:
            tinfo = resolve_type_tinfo(arg)

            if tinfo is None:
                print(
                    "[!] IDAUtils: Couldn't resolve parameter "
                    f"'{arg.name or arg.type}' ('{arg.type}') for "
                    f"function at {hex(ea)}!"
                )
                return False

            resolved_args.append((arg.name, tinfo, 0))

        itanium_abi = get_binary_info().profile.itanium_abi

        ordered: list[tuple[str, ida_tinfo_t, int]] = []
        if needs_retptr and itanium_abi and retptr_entry is not None:
            ordered.append(retptr_entry)
        if this_entry is not None:
            ordered.append(this_entry)
        if needs_retptr and not itanium_abi and retptr_entry is not None:
            ordered.append(retptr_entry)
        ordered.extend(resolved_args)

        function_data = ida_func_type_data_t()
        function_data.set_cc(resolve_calling_convention(existing_cc, binding.is_variadic))
        function_data.rettype = final_rettype
        if binding.is_variadic:
            function_data.set_cc(CallingConvention.ellipsis)

        for name, tinfo, flags in ordered:
            funcarg = ida_funcarg_t()
            funcarg.type = tinfo
            funcarg.name = name
            if flags != 0:
                funcarg.flags = flags
            function_data.push_back(funcarg)

        func_tinfo = ida_tinfo_t()
        if not func_tinfo.create_func(function_data):
            print(
                "[!] IDAUtils: Couldn't construct type information "
                f"for function at {hex(ea)}!"
            )
            return False

        return apply_tinfo(ea, func_tinfo, TINFO_DEFINITE)

    def _is_nontrivial(self, tif) -> bool:
        """Aggregates that always travel through memory, regardless of size."""
        if tif is None or not tif.is_udt() or tif.is_forward_decl():
            return False

        names = {n for n in (tif.get_type_name(), tif.get_final_type_name()) if isinstance(n, str)}

        # STL types are non-trivial
        if any(n.startswith("std::") or n in self._known_nontrivials for n in names):
            return True

        udt = ida_udt_type_data_t()
        if not tif.get_udt_details(udt):
            return False

        for member in udt:
            if member.is_vftable():
                return True

            mt = member.type

            while mt.is_array():
                mt = mt.get_array_element()

            if mt.is_udt() and self._is_nontrivial(mt):
                return True

        return False

    # this is stupid but i don't wanna resolve the type twice so i'll pass it to it
    def _needs_retptr(self, ret, resolved) -> bool:
        if resolved is None or ret.is_ptr_or_ref or not resolved.is_udt():
            return False

        if ret.is_stl or self._is_nontrivial(resolved):
            return True

        return not can_return_in_registers(resolved)


class SymbolIndex:
    """
    Every named address in the binary, grouped by demangled qualified
    name (arguments stripped) so overloads share one key.
    """

    _KEY_RE: Final = compile(r"(\S+)::(\S+)\(.*\)")

    def __init__(self) -> None:
        self._by_name: dict[str, list[int]] = defaultdict(list)
        for ea, _ in Names():
            name = get_ea_name(ea, GN_SHORT | GN_DEMANGLED)
            self._by_name[self._KEY_RE.sub(r"\1::\2", name)].append(ea)

    def candidates(self, name: str) -> list[int]:
        """Addresses still unclaimed under `name` (a copy)."""
        return list(self._by_name.get(name, ()))

    def claim(self, name: str, ea: int) -> None:
        """Takes `ea` out of the pool so a later overload can't match it again."""
        bucket = self._by_name.get(name)
        if bucket and ea in bucket:
            bucket.remove(ea)

    def __contains__(self, name: str) -> bool:
        return bool(self._by_name.get(name))

    def __iter__(self):
        return iter(self._by_name)

    def __len__(self) -> int:
        return len(self._by_name)


def get_function_info(
    ida_ea: int,
    force: bool = False
) -> ida_func_type_data_t | None:
    """
    Gets the info of the function at the given address.

    Args:
        ida_ea (int): The function's address.
        force (bool, optional): If the data should be forcefully
            obtained using recovery methods like decompilation.
            Defaults to False.

    Returns:
        ida_typeinf.func_type_data_t | None: The `ida_typeinf.func_type_data_t` of
            the function or `None` if unable to get function info.
    """
    tif = ida_tinfo_t()
    if get_tinfo(tif, ida_ea) and tif.is_func():
        fi = ida_func_type_data_t()
        if tif.get_func_details(fi):
            return fi

    if not force:
        return None

    try:
        from ida_hexrays import decompile
        cfunc = decompile(ida_ea)
        if cfunc is not None:
            return get_function_info(ida_ea)
    except ImportError:
        pass

    return None


def get_function_declaration(ea: int) -> str | None:
    """
    The type declaration of the function stored at `ea`,
    without a name: 'int __fastcall(Foo *this)'.

    Args:
        ea (int)

    Returns:
        str | None
    """
    tif = ida_tinfo_t()
    if not get_tinfo(tif, ea):
        return None
    return print_tinfo("", 0, 0, PRTYPE_1LINE, tif, "", "") or None


def read_function_signature(ea: int) -> tuple[RetType, list[ArgType], bool] | None:
    """
    Read a function's signature and turn it into
    standardized information.
    Removes the `__return_ptr` parameter but
    keeps the `this` parameter.

    Args:
        ea (int): Effective address of the function in IDA.

    Returns:
        tuple[RetType, list[ArgType], bool] | None:
            (return_type, list[arg_type, ...], is_variadic)
            or None if look-up failed
    """
    info = get_function_info(ea, True)

    if info is None:
        decl = get_function_declaration(ea)
        if decl is None or "(" not in decl:
            return None

        ret, _, params = CppUtils.split_signature(decl)
        args, is_variadic = ArgType.parse_params(params)
        return RetType(ret), args, is_variadic

    ret = info.rettype
    if any(a.flags & FAI_RETPTR for a in info) and ret.is_ptr():
        ret = ret.get_pointed_object()

    return (
        RetType(str(ret)),
        [ArgType(str(a.type), a.name) for a in info if not (a.flags & FAI_RETPTR)],
        info.get_cc() in VARARG_CCS,
    )


def get_demangled_info(ea: int) -> tuple[str, list[str], bool] | None:
    """
    Fetch demangled function information of
    an address from IDA.

    Args:
        ea (int): The address to look-up.

    Returns:
        tuple[str, list[str], bool] | None:
            (function_name, list[param_type], is_variadic)
            or None if look-up failed.
    """
    # the demangler doesn't give us "foo::bar(void)" here to us for
    # functions that don't take any arguments, unlike the functions list
    demangled = get_ea_name(ea, GN_SHORT | GN_DEMANGLED)

    # i DON'T care that msvc has calling conventions too, they're too problematic
    m = fullmatch(r"(\S+)\((.*)\)", demangled)
    if m is None:
        return None

    real_args, is_variadic = CppUtils.split_params(m.group(2))

    args = [
        CppUtils.clean_demangled_type(a)
        for a in real_args
    ]
    return m.group(1), args, is_variadic


# this is for functions that have a named symbol on the binary
def resolve_overload(binding, candidates: list[int]) -> list[int]:
    """
    Resolve which overloads of a function from available
    candidates fit best based on the given Binding instance.

    Args:
        binding (Binding): The binding instance.
        candidates (list[int]): List of all candidates
            by their effective address in the binary.

    Returns:
        list[int]: List of exact matches,
            or plausible ones if no exact matches.
    """
    if len(candidates) == 1:
        return candidates

    exact: list[int] = []
    plausible: list[int] = []

    for addr in candidates:
        info = get_demangled_info(addr)
        if info is None:
            continue

        _, arg_strs, is_variadic = info
        if is_variadic != binding.is_variadic or len(arg_strs) != len(binding.parameters):
            continue

        # IDA might sometimes demangle arguments incorrectly
        # so implicitly give those back as None instead
        arg_tifs = [
            resolve_bare_type(arg)
            if not CppUtils.looks_malformed(arg)
            else None
            for arg in arg_strs
        ]
        if not _params_match(arg_tifs, binding):
            continue

        plausible.append(addr)
        if all(t is not None for t in arg_tifs):
            exact.append(addr)

    return exact or plausible


def rename_function(ea: int, name: str, max_tries: int = 10) -> bool:
    """
    Renames the function at the given address with `name`.
    Accounts for overloads by falling back to
    `name_1 .. name_{max_tries-1}` on collisions.

    Args:
        addr (int): The address to rename the function at.
        name (str): The new name of the function to rename.
        max_tries (int, optional): Maximum number of retries.
            Defaults to `10`.

    Returns:
        bool: True if the address has been renamed successfully
            after maximum tries.
    """
    return any(
        set_name(ea, name if i == 0 else f"{name}_{i}", SN_NOWARN)
        for i in range(max_tries)
    )


def name_owner(name: str, ea: int) -> int:
    """Address holding `name`, or BADADDR if it's free or already `ea`."""
    owner = get_name_ea(BADADDR, name)
    return BADADDR if owner == ea else owner


def is_library_function(func: ida_func_t | None) -> bool:
    """
    Checks if a function is a library function.

    Args:
        func (func_t | None): The function to check.

    Returns:
        bool
    """
    return func is not None and bool(func.flags & FUNC_LIB)


def is_thunk_function(func: ida_func_t | None) -> str | None:
    """
    Checks if a function is a thunk and return
    the reason as a `str`.

    Args:
        func (func_t | None): The function to check.

    Returns:
        str | None
    """
    if func is None:
        return None

    if func.flags & FUNC_THUNK:
        return "has thunk attribute"
    if func.size() in get_binary_info().profile.thunk_sizes:
        return "is the size of a thunk"

    return None

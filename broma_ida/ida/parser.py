from functools import cache
from pathlib import Path

from ida_pro import IDA_SDK_VERSION
from ida_srclang import (
    select_parser_by_name, get_selected_parser_name
)


def is_new_clang(name: str) -> bool:
    return name == "clang" and IDA_SDK_VERSION >= 920


def new_clang_is_optional() -> bool:
    """Both IDAClang and the new clang parser exist (IDA 9.2-9.4)."""
    return 920 <= IDA_SDK_VERSION < 950


def wanted_parser(use_new_clang: bool = False) -> str:
    """
    Returns the correct source parser name for
    use according to IDA version and `use_new_clang`.

    - <9.2: "clang" is IDAClang.
    - 9.2-9.4: IDAClang is "old_clang", "clang" is the new LibTooling-based one.
    - 9.5+: "clang" is the only parser. IDAClang is removed.

    Args:
        use_new_clang (bool, optional):
            Prefer the new LibTooling-based source parser
            on IDA 9.2-9.4. Defaults to `False`.

    Returns:
        str: The parser's name as recognized by
            IDA's modules.
    """
    if new_clang_is_optional() and not use_new_clang:
        return "old_clang"
    return "clang"


# i don't know anymore,
# i just hope parse_decls_with_parser will keep working
# since i restore the user's own parser on every probe now
@cache
def _is_selectable(name: str) -> bool:
    previous = get_selected_parser_name()
    found = select_parser_by_name(name)
    select_parser_by_name(previous)
    return found


def resolve_parser(use_new_clang: bool = False) -> str | None:
    """
    Chooses and probes the source parser to be
    used in IDA to determine availability.

    Args:
        use_new_clang (bool, optional):
            Prefer the new LibTooling-based source parser
            on IDA 9.2-9.4. Defaults to `False`.

    Returns:
        str | None: The parser's name as recognized by IDA's modules,
            or None if IDA did not accept the parser.
    """
    name = wanted_parser(use_new_clang)
    return name if _is_selectable(name) else None


def parser_argv(parser_name: str, extra_args: str = "") -> str:
    """
    Arguments to pass to the source parser,
    plus any platform-specific `extra_args`.

    Args:
        extra_args (str)

    Returns:
        str
    """
    nostd = "-nostdlib -nostdinc" if is_new_clang(parser_name) else "-nostdlib -nostdinc -nostdinc++"
    return f"-x c++ {nostd} {extra_args}".strip()


def stl_headers_dir(stl_dir: str, headers_root: Path) -> Path:
    """
    Gets the STL headers path for a given platform.

    Args:
        stl_dir (str)
        headers_root (pathlib.Path): pathlib.Path to the root folder
            of where the headers are located.

    Returns:
        Path
    """
    return headers_root / "c++stl" / stl_dir

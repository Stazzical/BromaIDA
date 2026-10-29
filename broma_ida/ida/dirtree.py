from collections.abc import Iterable
from dataclasses import dataclass
# using this thing instead of Path cause of slashes!!
from pathlib import PurePosixPath

from ida_dirtree import (
    get_std_dirtree,
    dirtree_t as ida_dirtree_t,
    dirtree_visitor_t as ida_dirtree_visitor_t,
    DIRTREE_LOCAL_TYPES
)


ROOT_FOLDER = "/BromaIDA"
"""Root dirtree folder for type definitions."""
OTHER_FOLDER = f"{ROOT_FOLDER}/_other"
"""Types the import created that Broma doesn't explicitly define."""
FORWARD_FOLDER = f"{ROOT_FOLDER}/_forward"
"""Forward declarations made while applying signatures."""


def local_types_tree() -> ida_dirtree_t:
    return get_std_dirtree(DIRTREE_LOCAL_TYPES)


def _warn(message: str) -> None:
    print(f"[!] BromaIDA dirtree: {message}")


@dataclass(frozen=True)
class Entry:
    """A dirtree entry."""
    path: str
    is_dir: bool

    @property
    def name(self) -> str:
        return PurePosixPath(self.path).name


class _Collector(ida_dirtree_visitor_t):
    def __init__(self, tree: ida_dirtree_t) -> None:
        ida_dirtree_visitor_t.__init__(self)
        self.tree = tree
        self.entries: list[Entry] = []

    def visit(self, c, de) -> int:
        path = self.tree.get_abspath(c)

        if de.valid() and path not in ("", "/"):
            self.entries.append(Entry(path, de.isdir))

        return 0


def walk(tree: ida_dirtree_t | None = None) -> list[Entry]:
    """
    Walk every entry in `tree` at any depth and return a list
    of all of them as `Entry` dataclass instances.

    Args:
        tree (ida_dirtree_t | None, optional):
            Defaults to the Local Types subview.

    Returns:
        list[Entry]
    """
    tree = local_types_tree() if tree is None else tree

    collector = _Collector(tree)
    tree.traverse(collector)

    return collector.entries


def linked_type_paths(tree: ida_dirtree_t | None = None) -> dict[str, str]:
    """
    Every type inside `tree` returned as
    type name -> its current path.

    Args:
        tree (ida_dirtree_t | None, optional):
            Defaults to the Local Types subview.

    Returns:
        dict[str, str]
    """
    return {e.name: e.path for e in walk(tree) if not e.is_dir}


def linked_type_names(tree: ida_dirtree_t | None = None) -> set[str]:
    """
    Set of names of every linked (non-orphan) entry inside `tree`.

    Args:
        tree (ida_dirtree_t | None, optional):
            Defaults to the Local Types subview.

    Returns:
        set[str]
    """
    return set(linked_type_paths(tree))


def ensure_folder(folder: str, tree: ida_dirtree_t | None = None) -> bool:
    """Creates `folder` and any missing parents."""
    tree = local_types_tree() if tree is None else tree
    path = ""

    # parts[0] is "/"
    for part in PurePosixPath(folder).parts[1:]:
        path += f"/{part}"
        if tree.isdir(path):
            continue

        err = tree.mkdir(path)
        if err != 0:
            _warn(f"couldn't create '{path}': {ida_dirtree_t.errstr(err)}")
            return False

    return True


def move(src: str, folder: str, tree: ida_dirtree_t | None = None) -> bool:
    """Moves the entry at `src` into `folder`, creating it if needed."""
    tree = local_types_tree() if tree is None else tree

    dst = f"{folder}/{PurePosixPath(src).name}"
    if src == dst:
        return True

    if folder == src or folder.startswith(f"{src}/"):
        # IDA reports success for this and then the whole subtree is unreachable
        _warn(f"refusing to move '{src}' into itself")
        return False

    if not ensure_folder(folder, tree):
        return False

    err = tree.rename(src, dst)
    if err != 0:
        _warn(f"couldn't move '{src}' to '{folder}': {ida_dirtree_t.errstr(err)}")
        return False

    return True


def place_types(placements: dict[str, str], tree: ida_dirtree_t | None = None) -> list[str]:
    """
    Moves each type in `placements` to its targeted folder.

    Args:
        placements (dict[str, str]):
            {type_name: targeted_folder}
        tree (ida_dirtree_t | None, optional):
            Defaults to the Local Types subview.

    Returns:
        list[str]: Names that were missing or couldn't be moved.
    """
    tree = local_types_tree() if tree is None else tree
    paths = linked_type_paths(tree)

    unplaced = []
    for name, folder in placements.items():
        src = paths.get(name)
        if src is None or not move(src, folder, tree):
            unplaced.append(name)

    return unplaced


# snapshot all dirtree entries, before importing any new ones, as `before`
# so you don't move IDA's own or the user's own types into `folder`
def sweep_new_types(before: set[str], folder: str = OTHER_FOLDER, tree: ida_dirtree_t | None = None) -> int:
    """
    Moves all entries in `tree` that didn't exist in the `before`
    name snapshot, and aren't in `ROOT_FOLDER` yet, into `folder`.

    Args:
        before (set[str])
        folder (str): Defaults to `OTHER_FOLDER`.
        tree (ida_dirtree_t | None, optional):
            Defaults to the Local Types subview.

    Returns:
        int: Count of types that were moved successfully.
    """
    tree = local_types_tree() if tree is None else tree
    moved = 0

    for e in walk(tree):
        if e.is_dir or e.name in before or e.path.startswith(f"{ROOT_FOLDER}/"):
            continue
        moved += move(e.path, folder, tree)

    return moved


def adopt_orphaned_types(til_names: Iterable[str], folder: str = OTHER_FOLDER) -> int:
    """
    Links orphaned types that exist but have no dirtree entry
    in local types dirtree into `folder`.

    Args:
        folder (str):
            Defaults to `OTHER_FOLDER`.

    Returns:
        int: Count of successful links of orphaned types.
    """
    tree = local_types_tree()

    linked = linked_type_names(tree)
    orphans = [n for n in til_names if n not in linked]
    if not orphans or not ensure_folder(folder, tree):
        return 0

    return sum(tree.link(f"{folder}/{n}") == 0 for n in orphans)


def root_types(tree: ida_dirtree_t | None = None) -> list[str]:
    """
    Names of every type inside `ROOT_FOLDER`,
    i.e. everything the plugin imported, filed or created.

    Args:
        tree (ida_dirtree_t | None, optional):
            Defaults to the Local Types subview.

    Returns:
        list[str]
    """
    return [
        e.name for e in walk(tree)
        if not e.is_dir and e.path.startswith(f"{ROOT_FOLDER}/")
    ]

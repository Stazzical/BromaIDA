from typing import Self, Any
from pathlib import Path
from pickle import UnpicklingError
import shelve

from broma_ida.data.settings import ALL_SETTINGS


class DataManager:
    """Manages saved data. This class is a singleton."""

    __default_argument = object()

    __instance: Self = None  # type: ignore[assignment]
    __shelf: shelve.Shelf[Any] = None  # type: ignore[assignment]
    __shelf_path: Path = None  # type: ignore[assignment]

    def __new__(cls, *args, **kwargs) -> Self:
        if not cls._DataManager__instance:  # type: ignore[has-type]
            cls._DataManager__instance = super(DataManager, cls).__new__(
                cls, *args, **kwargs
            )

        return cls._DataManager__instance  # type: ignore[misc]

    def _init_values(self):
        """Initializes DataManager's values."""
        try:
            for s in ALL_SETTINGS:
                self.get(s.key, s.default)
        except (UnpicklingError, EOFError, OSError) as e:
            print(
                "[!] BromaDataManager: Failed to initialize "
                f"values ({e})! Saved settings are not loaded!"
            )
            self._delete_shelf()
            self.__shelf = shelve.Shelf({})

    def init(self, filepath: Path):
        """
        Initializes a DataManager instance.

        Args:
            filepath (Path): Path to the shelf file.
        """
        if self.__shelf is not None:
            return

        self.__shelf_path = filepath

        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            self.__shelf = shelve.open(filepath)
        except PermissionError:
            print(
                f"[!] BromaDataManager: No write access to {filepath.parent}! "
                "Settings will not persist between sessions!"
            )
            self.__shelf = shelve.Shelf({})
        except (UnpicklingError, EOFError, OSError) as e:
            print(
                f"[!] BromaDataManager: Shelf is corrupted ({e})! "
                "Resetting to default values."
            )
            self._delete_shelf()
            self.__shelf = shelve.open(filepath)

        self._init_values()

    def sync(self):
        """Manually syncs changes to the shelf."""
        self.__shelf.sync()

    def has(self, key: str) -> bool:
        """
        Checks if the shelf has the given key.

        Args:
            key (str)

        Returns:
            bool
        """
        return key in self.__shelf

    def get(self, key: str, default: Any = __default_argument) -> Any:
        """
        Gets the data of a key from the current shelf instance.
        Populates the key with the default if the key doesn't exist.

        Args:
            key (str): The key name.
            default (Any): The default value.
        """
        if self.has(key):
            return self.__shelf[key]
        else:
            if default is self.__default_argument:
                raise KeyError(
                    f"shelf has no '{key}' key and no default value was provided"
                )
            self.__shelf[key] = default
            return default

    def set(self, key: str, value: Any):
        """
        Sets a key to a value in the shelf.

        Args:
            key (str)
            value (Any)
        """
        self.__shelf[key] = value

    # def register_idb(self, idb_hash: str, ) -> None:
    #     """_summary_

    #     Args:
    #         idb_hash (str): _description_
    #     """

    def close(self):
        """Closes the DataManager. Saves everything to the shelf."""
        if self.__shelf is not None:
            self.__shelf.close()
            self.__shelf = None  # type: ignore[assignment]

    def _delete_shelf(self):
        """Deletes the shelf."""
        for f in self.__shelf_path.parent.glob(f"{self.__shelf_path.stem}*"):
            f.unlink(missing_ok=True)

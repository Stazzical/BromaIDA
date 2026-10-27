from pathlib import Path
from platformdirs import PlatformDirs
import traceback

from ida_idaapi import (
    plugin_t as ida_plugin_t,
    PLUGIN_PROC as IDA_PLUGIN_PROC,
    PLUGIN_KEEP as IDA_PLUGIN_KEEP
)
from ida_kernwin import (
    ask_file,
    msg as ida_msg,
    warning as ida_warning,
    ASKBTN_BTN1, ASKBTN_BTN2, ASKBTN_BTN3,
    ASKBTN_CANCEL
)
from idautils import Names
from ida_auto import auto_is_ok

from broma_ida.metadata import (
    __version__,
    PLUGIN_NAME, PLUGIN_DESCRIPTION, PLUGIN_HOTKEY
)
from broma_ida.utils import path_exists
from broma_ida.ida.env import (
    stop, get_binary_info, take_snapshot,
    UnsupportedBinaryError
)
from broma_ida.broma.importer import BromaImporter
from broma_ida.broma.exporter import BromaExporter

from broma_ida.data.data_manager import DataManager
from broma_ida.data.idb_state import IDBState

from broma_ida.ui.simple_popup import SimplePopup
from broma_ida.ui.main_form import MainForm
from broma_ida.ui.wait_box import WaitBox
from broma_ida.ui.ask_popup import AskPopup

from pybroma import __version__ as pybroma_version


SHELF_DIR = PlatformDirs(appname=PLUGIN_NAME, appauthor=False)


def check_auto_analysis() -> bool:
    """
    Checks if IDA is done with analysis.
    Emits a warning for the user to close the plugin,
    since IDA runs plugins on main thread and stops
    the auto-analysis from working.

    Returns:
        bool: True if safe, False if not.
    """
    if not auto_is_ok():
        ida_warning(
            "Warning: IDA analysis is still running!\n\n"
            "Modifying database bindings mid-analysis can cause severe race conditions,\n"
            "missing types and symbols, and potentially IDB database corruption!\n\n"
            f"Please close {PLUGIN_NAME} and wait for the 'AU: idle' indicator\n"
            "at the bottom-left corner of IDA to appear before running the plugin again."
        )
        return False

    return True


def _take_snapshot_ui(binfo, entry_name: str) -> bool:
    """False only if the snapshot failed and the user chose to cancel."""
    with WaitBox("Taking database snapshot..."):
        ok, err = take_snapshot(f"BromaIDA: before import ({binfo.profile.printable}, {entry_name})")

    if ok:
        return True

    return AskPopup(
        f"Taking the snapshot failed: {err}\nContinue the import without one?",
        "Continue", "Cancel", icon="WARNING"
    ).show() == ASKBTN_BTN1


def ensure_snapshot(binfo, entry_name: str) -> bool:
    """
    Snapshot policy. Encourages users to take a
    snapshot for the first time they use the importer.

    Args:
        binfo: The shared BinaryInfo of current IDB.
        entry_name (str): Name of the Broma input entry file.

    Returns:
        bool: False if the user cancelled the import.
    """
    dm, state = DataManager(), IDBState()
    imports = state.get("import.count", 0)

    if dm.get("snapshot_before_import", False):
        if imports == 0:
            return _take_snapshot_ui(binfo, entry_name)

        choice = AskPopup(
            f"BromaIDA has already imported into this database {imports} time(s).\n"
            "Take another snapshot before this import?",
            "Take Snapshot", "Skip"
        ).show()
        if choice == ASKBTN_BTN1:
            return _take_snapshot_ui(binfo, entry_name)

        # closing the dialog cancels
        return choice == ASKBTN_BTN2

    # first-time-only prompt to encourage use of snapshots
    if imports == 0 and not dm.get("snapshot_prompt_seen", False):
        choice = AskPopup(
            "BromaIDA is about to change this database:\n"
            "types, function names and signatures may drastically alter.\n"
            "A snapshot lets you roll back from IDA's Database Snapshot Manager.\n\n"
            "(Snapshots take disk space. You can change this later in Settings.)",
            "Take Snapshot", "Continue Without", "Always Snapshot"
        ).show()

        if choice == ASKBTN_CANCEL:
            return False

        dm.set("snapshot_prompt_seen", True)
        if choice == ASKBTN_BTN3:
            dm.set("snapshot_before_import", True)

        if choice in (ASKBTN_BTN1, ASKBTN_BTN3):
            return _take_snapshot_ui(binfo, entry_name)

    return True


def on_import(form: MainForm, code: int = 0):
    if not check_auto_analysis():
        return

    form.Close(1)

    try:
        binfo = get_binary_info()

        entry = ask_file(False, "*.bro", "Select the Broma entry file")
        if not path_exists(entry, ".bro"):
            SimplePopup("Please select a valid .bro file!", "OK").show()
            stop()

        headers_path = Path(__file__).resolve().parent / "broma_ida" / "types"
        entry_path = Path(entry)

        broma_importer = BromaImporter(binfo, headers_path, entry_path)

        if not ensure_snapshot(binfo, entry_path.name):
            print("[-] BromaIDA: Import cancelled.")
            return

        # mark before mutating, so an interrupted import still counts
        state = IDBState()
        state.set("import.count", state.get("import.count", 0) + 1)

        broma_importer.parse_bromas()
        broma_importer.import_into_idb()

        # TODO: make this more verbose with proper post-action reports
        SimplePopup(
            "Finished importing "
            f"{binfo.profile.printable} "
            f"bindings {'and types ' if broma_importer.has_types else ''}"
            "from Broma files.",
            "OK"
        ).show()
    finally:
        DataManager().close()


def on_export(form: MainForm, code: int = 0):
    if not check_auto_analysis():
        return

    form.Close(1)

    try:
        platform = get_binary_info().platform

        if platform.startswith("android"):
            SimplePopup(
                "Cannot export bindings from Android binary!", "OK"
            ).show()
            stop()

        # for_saving is not True because we need to read the file first
        # which may not even exist if the saving prompt is used
        # (since you can select files that don't exist within said prompt)
        file_path: str = ask_file(False, "GeometryDash.bro", "bro")

        if not path_exists(file_path, ".bro"):
            SimplePopup("Please select a valid file!", "OK").show()
            stop()

        broma_exporter = BromaExporter(platform, file_path)

        broma_exporter.import_from_idb(Names())
        broma_exporter.export()

        print(
            "[+] BromaIDA: Finished exporting "
            f"{broma_exporter.num_exports} bindings, "
            f"{broma_exporter.num_ret_exports} return types and "
            f"{broma_exporter.num_args_names_exports} argument names."
        )
        SimplePopup("Finished exporting bindings to Broma file.", "OK").show()
    finally:
        DataManager().close()


def bida_main():
    """Plugin main entrypoint."""

    try:
        bingo = get_binary_info()
    except UnsupportedBinaryError:
        ida_warning(
            f"{PLUGIN_NAME} was unable to detect this binary's platform.\n"
            "Cannot execute this plugin on this binary."
        )
        stop()

    DataManager().init(
        SHELF_DIR.user_config_path / "shelf"
    )

    form_code = MainForm(
        bingo.profile.printable,
        on_import,
        on_export
    ).show()

    # cancel
    if form_code == 0:
        DataManager().close()


class BromaIDAPlugin(ida_plugin_t):
    """IDA plugin instance."""

    flags = IDA_PLUGIN_PROC
    comment = PLUGIN_DESCRIPTION
    help = f"Press {PLUGIN_HOTKEY} to begin importing/exporting bindings."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        """Ran on plugin load."""
        ida_msg(f"{PLUGIN_NAME} v{__version__} initialized. Using PyBroma version v{pybroma_version}.\n    {self.help}\n")

        return IDA_PLUGIN_KEEP

    def term(self):
        """Ran on plugin unload."""
        ida_msg(f"{PLUGIN_NAME} v{__version__} unloaded.\n")

    def run(self, arg):
        """Ran on "File -> Script File"
        (does not work because this plugin has multiple py files)"""
        try:
            bida_main()
        except SystemExit:
            pass
        except BaseException:
            ida_msg(f"[!] BromaIDA: Fatal error:\n{traceback.format_exc()}\n")


# IDA plugin entry
def PLUGIN_ENTRY():
    return BromaIDAPlugin()

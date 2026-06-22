from pathlib import Path

from idaapi import (
    msg as ida_msg,
    plugin_t as ida_plugin_t, action_desc_t as ida_action_desc_t,
    PLUGIN_PROC, PLUGIN_KEEP
)
from ida_kernwin import ask_file
from idautils import Names

from broma_ida.metadata import (
    SCRIPT_VERSION,
    PLUGIN_NAME,
    PLUGIN_HOTKEY
)
from broma_ida.utils import stop, path_exists, IDAUtils
from broma_ida.broma.importer import BromaImporter
from broma_ida.broma.exporter import BromaExporter

from broma_ida.data.data_manager import DataManager

from broma_ida.ui.simple_popup import SimplePopup
from broma_ida.ui.main_form import MainForm
from broma_ida.ui.directory_input_form import DirectoryInputForm


def on_import(form: MainForm, code: int = 0):
    form.Close(1)

    platform = IDAUtils.get_platform()

    dir_form = DirectoryInputForm("Select folder containing .bro files")
    ok = dir_form.show()

    if ok != 1:
        stop()

    bromas_dir = str(dir_form.saved_controls.iDir)

    broma_importer = BromaImporter(platform, Path(bromas_dir))
    broma_importer.parse_bromas()
    broma_importer.import_into_idb()

    print("[+] BromaIDA: Finished importing bindings from Broma files.")
    SimplePopup(
        "Finished importing "
        f"{IDAUtils.get_platform_printable()} "
        "bindings from Broma files.",
        "OK"
    ).show()

    DataManager().close()

def on_export(form: MainForm, code: int = 0):
    form.Close(1)

    platform = IDAUtils.get_platform()

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

    DataManager().close()


def bida_main():
    """BromaIDA main entrypoint."""
    DataManager().init(
        Path.home() / "broma_ida" / "shelf"
    )

    form_code = MainForm(
        IDAUtils.get_platform_printable(),
        on_import,
        on_export
    ).show()

    # cancel
    if form_code == 0:
        DataManager().close()


class BromaIDAPlugin(ida_plugin_t):
    """BromaIDA plugin."""
    flags = PLUGIN_PROC
    comment = "Broma support for IDA."
    help = f"{PLUGIN_HOTKEY} to begin importing/exporting bindings."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        """Ran on plugin load."""
        ida_msg(f"{PLUGIN_NAME} v{SCRIPT_VERSION} initialized\n")

        return PLUGIN_KEEP

    def term(self):
        """Ran on plugin unload."""
        ida_msg(f"{PLUGIN_NAME} v{SCRIPT_VERSION} unloaded\n")

    def run(self, arg):
        """Ran on "File -> Script File"
        (does not work because this plugin has multiple py files)"""
        try:
            bida_main()
        except SystemExit:
            pass
        except BaseException as e:
            ida_msg(f"[!] BromaIDA: Fatal error: {e}\n")


def PLUGIN_ENTRY():
    return BromaIDAPlugin()

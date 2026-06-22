from typing import Callable, Self

from ida_kernwin import Form

from broma_ida.metadata import SCRIPT_VERSION, PLUGIN_NAME

from broma_ida.ui.types.dynamic_form import DynamicForm
from broma_ida.ui.settings_form import SettingsForm


class MainForm(DynamicForm):
    """Main form"""

    version: str
    on_import_button: Callable[[Self, int], None]
    on_export_button: Callable[[Self, int], None]

    def __init__(
        self,
        platform: str,
        on_import_button: Callable[[Self, int], None],
        on_export_button: Callable[[Self, int], None]
    ):
        self.on_import_button = on_import_button
        self.on_export_button = on_export_button

        super().__init__(f"""STARTITEM 0
BUTTON CANCEL Cancel
{PLUGIN_NAME}

{{cMainLabel}}
{{cPlatformLabel}}

Select Mode:<##Import:{{iImportButton}}><##Export:{{iExportButton}}>

<Settings:{{iSettingsButton}}>
""", {
            "cMainLabel": Form.StringLabel(
                f"{PLUGIN_NAME} v{SCRIPT_VERSION}.\nBroma support for IDA."
            ),
            "cPlatformLabel": Form.StringLabel(
                f"Current Platform: {platform}"
            ),
            "iImportButton": Form.ButtonInput(self.onImportButton),
            "iExportButton": Form.ButtonInput(self.onExportButton),
            "iSettingsButton": Form.ButtonInput(
                self.onSettingsButton, swidth="27"
            )
        })

    def onImportButton(self, code: int = 0):
        try:
            self.on_import_button(self, code)
        except SystemExit:
            pass

    def onExportButton(self, code: int = 0):
        try:
            self.on_export_button(self, code)
        except SystemExit:
            pass

    def onSettingsButton(self, code: int = 0):
        SettingsForm().show()

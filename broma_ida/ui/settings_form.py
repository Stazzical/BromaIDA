import webbrowser

from ida_kernwin import Form

from broma_ida.metadata import (
    __version__, __author__, __maintainer__,
    PLUGIN_NAME, PLUGIN_GITHUB
)
from broma_ida.utils import HAS_IDACLANG

from broma_ida.ui.types.dynamic_form import DynamicForm
from broma_ida.data.data_manager import DataManager
from broma_ida.data.settings import (
    SETTINGS_GROUPS, ALL_SETTINGS, SETTINGS_BY_KEY
)


class SettingsForm(DynamicForm):
    """The settings form."""
    _pending: dict[str, bool]

    @staticmethod
    def _build_group_rows(group) -> str:
        """
        Dynamically generates a settings group's
        string to be used in the final form.

        Args:
            group

        Returns:
            str:
                Full generated string of all settings within the group.
        """
        rows = []
        last_idx = len(group.settings) - 1

        for i, s in enumerate(group.settings):
            prefix = (
                f"##{group.title}#{s.tooltip}"
                if i == 0
                else f"#{s.tooltip}"
            )
            row = f"<{prefix}#{s.label}:{{{s.control_name}}}>"
    
            if i == last_idx:
                row += f"{{{group.control_name}}}>"

            rows.append(row)

        return "\n".join(rows)

    def __init__(self):
        self._pending = {}

        controls: dict = {
            "FormChangeCb": Form.FormChangeCb(self.onFormChange),
        }

        group_blocks = []
        for group in SETTINGS_GROUPS:
            group_blocks.append(self._build_group_rows(group))
            controls[group.control_name] = Form.ChkGroupControl(
                tuple(s.control_name for s in group.settings)
            )

        controls.update({
            "cFooterLabel1": Form.StringLabel(f"{PLUGIN_NAME} v{__version__}."),
            "cFooterLabel2": Form.StringLabel(f"Original author: {__author__}"),
            "cFooterLabel3": Form.StringLabel(f"Maintained by {__maintainer__}"),
            "cFooterLabel4": Form.StringLabel("(+ contributors)"),
            "iGitHubButton": Form.ButtonInput(self.onGitHubButton, swidth="25"),
        })

        layout = f"""STARTITEM 0
BUTTON YES OK
BUTTON CANCEL Cancel
{PLUGIN_NAME}
{{FormChangeCb}}
{"\n\n".join(group_blocks)}

            {{cFooterLabel1}}
          {{cFooterLabel2}}
           {{cFooterLabel3}}
            {{cFooterLabel4}}

            <Open GitHub:{{iGitHubButton}}>
"""

        super().__init__(layout, controls)

    def setup(self):
        dm = DataManager()
        for s in ALL_SETTINGS:
            getattr(self, s.control_name).checked = dm.get(s.key, s.default)

    def onFormChange(self, fid: int) -> int:
        super().onFormChange(fid)

        for s in ALL_SETTINGS:
            ctrl = getattr(self, s.control_name)
            if fid == getattr(ctrl, "id", None):
                self._pending[s.key] = bool(self.GetControlValue(ctrl))
                break

        import_ctrl = getattr(self, SETTINGS_BY_KEY["import_types"].control_name)
        if fid in [-1, import_ctrl.id]:
            if not HAS_IDACLANG:
                self.EnableField(import_ctrl, False)
                self._pending["import_types"] = False
                DataManager().set("import_types", False)

        # only sync from self._pending upon pressing the 'OK' button
        # lets the user abort their changes if they want to
        if fid == -2:
            dm = DataManager()
            for key, value in self._pending.items():
                dm.set(key, value)
            dm.sync()

        return 1

    def onGitHubButton(self, code: int = 0):
        webbrowser.open(PLUGIN_GITHUB)

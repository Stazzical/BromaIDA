from ida_kernwin import warning as ida_warning, Form

from broma_ida.metadata import PLUGIN_NAME

from broma_ida.ui.types.dynamic_form import DynamicForm

from broma_ida.utils import path_exists

__all__ = ["DirectoryInputForm"]


class DirectoryInputForm(DynamicForm):
    """
    Simple form that asks for a directory since ida_kernwin
    and its infinite wisdom doesnt have an ask_directory method :D
    Directory string is saved in DirectoryInputForm.saved_controls.iDir
    """

    def __init__(self, prompt: str):
        super().__init__(f"""STARTITEM 0
BUTTON YES Done
BUTTON CANCEL Cancel
{PLUGIN_NAME}
{{FormChangeCb}}<{prompt}:{{iDir}}>""", {
            "FormChangeCb": Form.FormChangeCb(self.onFormChange),
            "iDir": Form.DirInput(swidth=35)
        })

    def onFormChange(self, fid: int) -> int:
        super().onFormChange(fid)

        if fid == -2:
            if not path_exists(self.GetControlValue(self.iDir)): # type: ignore
                ida_warning("Please select a valid folder!")
                return 0

        return 1

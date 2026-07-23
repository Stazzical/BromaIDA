from typing import Literal
from dataclasses import dataclass

from ida_kernwin import ask_buttons

from broma_ida.metadata import PLUGIN_NAME

__all__ = ["AskPopup"]


@dataclass
class AskPopup:
    """A Yes/No popup. Not a Form."""

    text: str
    """The text to put."""
    button1: str = "Yes"
    """Button 1 text. Defaults to "Yes"."""
    button2: str = "No"
    """Button 2 text. Defaults to "No"."""
    button3: str | None = None
    """Button 3 text. Defaults to None."""
    title: str = PLUGIN_NAME
    """Title text. Defaults to `broma_ida.metadata.PLUGIN_NAME`."""
    icon: Literal["WARNING", "QUESTION", "INFO"] = "QUESTION"
    """The icon. Defaults to "QUESTION"."""
    autohide: Literal["NONE", "DATABASE", "REGISTRY", "SESSION"] = "NONE"
    """The autohide type. Defaults to "NONE"."""
    default: Literal[-1, 0, 1] = 1
    """The default option. Defaults to 1 (button1)."""

    def show(self) -> int:
        """
        Shows the popup.

        Returns:
            int: The selected button.
        """
        return ask_buttons(
            self.button1, self.button2, self.button3, self.default,
            f"TITLE {self.title}\nICON {self.icon}\nAUTOHIDE {self.autohide}\n"
            f"{'HIDECANCEL\n' if self.button3 is None else ''}{self.text}"
        )

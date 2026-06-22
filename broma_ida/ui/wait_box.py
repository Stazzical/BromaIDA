from types import TracebackType

from ida_kernwin import show_wait_box, hide_wait_box, user_cancelled

__all__ = ["WaitBox"]


class WaitBox:
    def __init__(self, message: str, hide_cancel: bool = True):
        """
        Creates a wait box context manager.

        Args:
            message (str): The wait box message
            hide_cancel (bool, optional): Whether to hide the cancel button.
                Defaults to True.
        """
        self.message = message
        self.hide_cancel = hide_cancel

    def __enter__(self) -> None:
        """Shows a wait box.

        Args:
            message (str): The wait box message
            hide_cancel (bool, optional): Whether to hide the cancel button.
                Defaults to True.
        """
        show_wait_box(
            # chr 10 is \n, backwards compat with python < 3.12
            f"{f'HIDECANCEL{chr(10)}' if self.hide_cancel else ''}"
            f"{self.message}"
        )

    def __exit__(
            self, exc_type: BaseException | None,
            exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        """Hides the wait box."""
        hide_wait_box()

    def was_cancelled(self) -> int:
        """
        Checks if the user cancelled the wait box.

        Returns:
            int: 0 if not cancelled, 1 if cancelled and message is displayed,
                2 if cancelled and no message is displayed
        """
        return user_cancelled()

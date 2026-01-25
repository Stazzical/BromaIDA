from types import TracebackType

from ida_kernwin import jumpto as ida_jumpto, get_screen_ea

__all__ = ["TempJumpToAddress"]


class TempJumpToAddress:
    def __init__(self, ea: int) -> None:
        """Temporary jump to address in IDA View.

        Args:
            ea (int): The address to jump to
        """
        self.ea = ea
        self.cur_ea = get_screen_ea()

    def __enter__(self) -> None:
        """Jumps to the address."""
        ida_jumpto(self.ea)

    def __exit__(
            self, exc_type: BaseException | None,
            exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        """Jumps back to initial address."""
        ida_jumpto(self.cur_ea)

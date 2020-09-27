"""Positive int argument parser type."""
from argparse import ArgumentTypeError

class PositiveInt(object):
    """Positive int argument class."""

    @staticmethod
    def parse(arg):
        """Positive int parse function.

        Args:
            arg (str): String representing a positive int.

        Raises:
            ArgumentTypeError: Failed to parse int from input.
            ArgumentTypeError: Int is not positive.

        Returns:
            int: Positive int.

        """
        try:
            num = int(arg)
        except ValueError as v_err:
            raise ArgumentTypeError(v_err)

        if num < 1:
            raise ArgumentTypeError("Number must be positive.")

        return num

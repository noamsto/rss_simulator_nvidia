"""Argument parser type decorator module."""
from argparse import ArgumentTypeError


def arg_parse_type_decorator(parse_func):
    """Decorate function for making parse functions to work with argparse package.

    Args:
        parse_func (function): Parsing function.

    Returns:
        function: Decorated function to use with ArgumentParser.

    """
    def _parse(arg):
        try:
            return parse_func(arg)
        except Exception as ex:
            raise ArgumentTypeError(ex)
    return _parse

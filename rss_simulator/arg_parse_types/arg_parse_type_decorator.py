from argparse import ArgumentTypeError


def arg_parse_type_decorator(parse_func):
    def _parse(arg):
        try:
            return parse_func(arg)
        except Exception as ex:
            raise ArgumentTypeError(ex)
    return _parse

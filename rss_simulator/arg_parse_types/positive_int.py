
from argparse import ArgumentTypeError

class PositiveInt(object):

    @staticmethod
    def parse(arg):
        try:
            num = int(arg)
        except ValueError as v_err:
            raise ArgumentTypeError(v_err)

        if num < 1:
            raise ArgumentTypeError("Number must be positive.")

        return num

from cognis_mil import make_cli

from . import __version__
from .core import scan


def main():
    make_cli("stigsentry", scan, version=__version__)

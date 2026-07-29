from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("white-hat-agent")
except PackageNotFoundError:  # Direct source-tree imports before installation.
    __version__ = "0+unknown"

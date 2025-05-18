from .scanner import Scanner
from .extractor import Extractor
from .operator import Operator

import shutil


def _check_pypi_depends():
    if shutil.which("semgrep") is None:
        raise RuntimeError("semgrep has not been installed correctly")
    if shutil.which("r2") is None:
        raise RuntimeError("radare2 has not been installed correctly")


_check_pypi_depends()

from __future__ import annotations

import argparse
import sys

from .base import IsolationError
from .windows_native import WindowsNativeAppContainer


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["create", "delete"])
    parser.add_argument("name")
    arguments = parser.parse_args()
    try:
        native = WindowsNativeAppContainer()
        if arguments.operation == "create":
            sid = native.create_profile(arguments.name)
            native.free_sid(sid)
        else:
            native.delete_profile(arguments.name)
        return 0
    except IsolationError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3

import re
import sys


FREE_SOFTWARE_RE = re.compile(
    r"^\s*\*\s*This is free software; see the Copyright file in the source distribution",
    re.IGNORECASE,
)


def should_skip(line: str) -> bool:
    return FREE_SOFTWARE_RE.match(line) is not None


def should_skip_comment(lines) -> bool:
    return any(should_skip(line) for line in lines)


def filter_lines(lines):
    in_top_comment = False
    top_comment_done = False
    top_comment_lines = []

    for line in lines:
        stripped = line.lstrip()

        if not top_comment_done:
            if not in_top_comment:
                if stripped.strip() == "" or stripped.startswith("//"):
                    yield line
                    continue

                if stripped.startswith("/*"):
                    in_top_comment = True
                    top_comment_lines = [line]

                    if "*/" in line:
                        in_top_comment = False
                        top_comment_done = True

                        if not should_skip_comment(top_comment_lines):
                            yield from top_comment_lines

                    continue

                top_comment_done = True
                yield line
                continue

            top_comment_lines.append(line)

            if "*/" in line:
                in_top_comment = False
                top_comment_done = True

                if not should_skip_comment(top_comment_lines):
                    yield from top_comment_lines

            continue

        yield line


def main() -> int:
    if len(sys.argv) > 1:
        for path in sys.argv[1:]:
            with open(path, "r", encoding="utf-8", errors="ignore") as stream:
                sys.stdout.writelines(filter_lines(stream))
        return 0

    sys.stdout.writelines(filter_lines(sys.stdin))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
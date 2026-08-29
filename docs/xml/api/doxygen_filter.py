#!/usr/bin/env python3
"""Doxygen input filter for xmlsec source files.

Strips the leading copyright header comment block (the one containing the
free-software notice) before Doxygen parses the file, so the license text
does not end up in the generated documentation.  All other content is passed
through unchanged.

Usage:
    doxygen_filter.py [FILE ...]     # filter the given files to stdout
    doxygen_filter.py                # filter stdin to stdout
"""

import re
import sys


# The free-software notice, matched anywhere within a line of the top comment
# block (it may appear on the '/*' line itself or on a ' * ' continuation).
FREE_SOFTWARE_RE = re.compile(
    r"This is free software; see the Copyright file in the source distribution",
    re.IGNORECASE,
)


def should_skip(line: str) -> bool:
    return FREE_SOFTWARE_RE.search(line) is not None


def should_skip_comment(lines: list[str]) -> bool:
    return any(should_skip(line) for line in lines)


class UnterminatedCommentError(ValueError):
    """Raised when the top comment block is never terminated with '*/'."""


def filter_lines(lines) -> list[str]:
    """Return *lines* with the leading copyright header comment removed.

    Raises UnterminatedCommentError if a top comment block is opened but
    never closed, so the caller can fail loudly instead of silently
    dropping the rest of the file.
    """
    result: list[str] = []
    in_top_comment = False
    top_comment_done = False
    top_comment_lines: list[str] = []

    for line in lines:
        stripped = line.lstrip()

        if not top_comment_done:
            if not in_top_comment:
                if stripped.strip() == "" or stripped.startswith("//"):
                    result.append(line)
                    continue

                if stripped.startswith("/*"):
                    in_top_comment = True
                    top_comment_lines = [line]

                    # The comment ends at the first '*/' after the opening
                    # '/*'; check only the remainder so that openers such as
                    # '/*/' are not mistaken for a closed comment.
                    open_idx = len(line) - len(stripped)
                    if "*/" in line[open_idx + 2:]:
                        in_top_comment = False
                        top_comment_done = True

                        if not should_skip_comment(top_comment_lines):
                            result.extend(top_comment_lines)

                    continue

                top_comment_done = True
                result.append(line)
                continue

            top_comment_lines.append(line)

            if "*/" in line:
                in_top_comment = False
                top_comment_done = True

                if not should_skip_comment(top_comment_lines):
                    result.extend(top_comment_lines)

            continue

        result.append(line)

    if in_top_comment:
        raise UnterminatedCommentError("top comment block is never terminated with '*/'")

    return result


def main() -> int:
    try:
        if len(sys.argv) > 1:
            for path in sys.argv[1:]:
                try:
                    with open(path, "r", encoding="utf-8") as stream:
                        lines = stream.readlines()
                except OSError as exc:
                    print(f"ERROR: cannot read {path}: {exc}", file=sys.stderr)
                    return 1
                except UnicodeDecodeError as exc:
                    print(f"ERROR: {path} is not valid UTF-8: {exc}", file=sys.stderr)
                    return 1
                sys.stdout.writelines(filter_lines(lines))
            return 0

        # Pin stdin/stdout to UTF-8 so the filter does not depend on the locale.
        if hasattr(sys.stdin, "reconfigure"):
            sys.stdin.reconfigure(encoding="utf-8")
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        sys.stdout.writelines(filter_lines(sys.stdin))
        return 0
    except UnterminatedCommentError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

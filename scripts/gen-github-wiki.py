#!/usr/bin/env python3
"""
gen-github-wiki.py - Generate GitHub Wiki pages from xmlsec documentation.

Usage: gen-github-wiki.py <destination_folder>
"""

import os
import re
import sys
import shlex
import shutil
import tempfile
import subprocess


# Special-case word replacements applied after initial capitalize()
WORD_MAP = {
    "Api":       "API",
    "Certkeys":  "CertKeys",
    "Gcrypt":    "GCrypt",
    "Gnutls":    "GnuTLS",
    "Keysmngr":  "KeysMngr",
    "Keysstore": "KeysStore",
    "Mscng":     "MSCng",
    "Mscrypto":  "MSCrypto",
    "Nss":       "NSS",
    "Openssl":   "OpenSSL",
    "Xmlsec":    "XMLSec",
    "Xmldsig":   "XMLDSig",
    "Xmlenc":    "XMLEnc",
}


def capitalize_parts(s):
    """Split on hyphens and underscores, capitalize each word, apply WORD_MAP."""
    parts = [WORD_MAP.get(p.capitalize(), p.capitalize())
             for p in re.split(r"[-_]", s) if p]
    return "-".join(parts)


def camel_case_name(folder, filename):
    """
    Convert a folder/filename pair to a camel-cased wiki page name.
    e.g. ("api", "index.md") -> "API-Index.md"
    e.g. ("tutorial", "compiling-and-linking.md") -> "Tutorial-Compiling-And-Linking.md"
    e.g. ("tutorial", "some_file_name.md") -> "Tutorial-Some-File-Name.md"
    """
    base, ext = os.path.splitext(filename)
    folder_part = capitalize_parts(folder)
    file_part = capitalize_parts(base)
    return f"{folder_part}-{file_part}{ext}"


def camel_case_top_level_name(filename):
    """
    Convert a top-level filename (no folder prefix) to a wiki page name.
    e.g. "index.md" -> "Home.md"
    e.g. "getting-started.md" -> "Getting-Started.md"
    """
    if filename.lower() == "index.md":
        return "Home.md"
    base, ext = os.path.splitext(filename)
    return capitalize_parts(base) + ext


def resolve_link_target(source_folder, link_target):
    """
    Given the source folder (e.g. 'tutorial') and a relative link target
    (e.g. '../api/index.md'), resolve it to a repo-relative path like 'api/index.md'.
    Returns (folder, filename) where folder is '' for top-level files,
    or (None, None) if it cannot be resolved to a docs/md file.
    """
    # Join the source folder with the link to get a normalized relative path
    joined = os.path.normpath(os.path.join(source_folder, link_target))
    # joined should now look like 'api/index.md', 'faq.md', or similar
    parts = joined.replace("\\", "/").split("/")
    # Top-level file (e.g. faq.md)
    if len(parts) == 1:
        return "", parts[0]
    # Subfolder file (e.g. api/index.md)
    if len(parts) == 2:
        return parts[0], parts[1]
    return None, None


def fix_md_links(content, source_folder, image_dest_prefix="images/"):
    """
    Fix markdown links and image references in content.

    - Local .md links (e.g. [text](../api/index.md)) -> [text](API-Index.md)
    - Image links are rewritten to images/<basename>, since all images from
      all subfolders are flattened into a single images/ directory in the wiki.

    Links inside fenced code blocks and inline code spans are left as-is,
    and an optional link title (e.g. [t](img.png "title")) is preserved.
    """
    def replace_link(m):
        prefix = m.group(1)   # '![' or '['
        text = m.group(2)
        target = m.group(3)

        # Preserve an optional "title" after the target path
        title = ""
        title_match = re.search(r'\s+"[^"]*"\s*$', target)
        if title_match:
            title = target[title_match.start():]
            target = target[:title_match.start()]

        # Skip external links and anchors-only
        if target.startswith("http://") or target.startswith("https://") or target.startswith("#"):
            return m.group(0)

        # Separate anchor from path
        anchor = ""
        path = target
        if "#" in target:
            idx = target.index("#")
            path = target[:idx]
            anchor = target[idx:]

        if not path:
            return m.group(0)

        # Is it an image reference?
        if prefix == "![":
            # Images are referenced relative to the md file's folder.
            # After flattening, all md files are in dest root, images go to images/
            # Resolve the image path relative to source_folder
            resolved = os.path.normpath(os.path.join(source_folder, path))
            # resolved will be something like 'tutorial/images/foo.png'
            # or 'examples/images/foo.png'
            # In the wiki, all images are in images/
            img_filename = os.path.basename(resolved)
            return f"{prefix}{text}]({image_dest_prefix}{img_filename}{anchor}{title})"

        # Is it a .md link?
        _, ext = os.path.splitext(path)
        if ext.lower() == ".md":
            folder, filename = resolve_link_target(source_folder, path)
            if filename is not None:
                if folder:
                    wiki_name = os.path.splitext(camel_case_name(folder, filename))[0]
                else:
                    wiki_name = os.path.splitext(camel_case_top_level_name(filename))[0]
                return f"{prefix}{text}]({wiki_name}{anchor}{title})"

        return m.group(0)

    # Match both image links ![alt](url) and regular links [text](url)
    pattern = re.compile(r"(!\[|\[)([^\]]*)\]\(([^)]*)\)")

    def fix_outside_inline_code(text):
        # Skip inline code spans (odd parts of the split are code)
        parts = re.split(r"(`+[^`]*`+)", text)
        for i in range(0, len(parts), 2):
            parts[i] = pattern.sub(replace_link, parts[i])
        return "".join(parts)

    # Skip fenced code blocks (odd parts of the split are fences)
    segments = re.split(r"(^```.*?^```)", content, flags=re.DOTALL | re.MULTILINE)
    for i in range(0, len(segments), 2):
        segments[i] = fix_outside_inline_code(segments[i])
    return "".join(segments)


def collect_images(md_folder):
    """
    List image files stored in the images/ subfolders of md_folder.
    Returns a list of absolute image paths.
    """
    images = []
    for subfolder in os.listdir(md_folder):
        subfolder_path = os.path.join(md_folder, subfolder)
        if not os.path.isdir(subfolder_path):
            continue
        images_path = os.path.join(subfolder_path, "images")
        if os.path.isdir(images_path):
            for img in os.listdir(images_path):
                img_path = os.path.join(images_path, img)
                if os.path.isfile(img_path):
                    images.append(img_path)
    return images


def run_command(cmd, cwd=None, description=None):
    """Run a shell command, abort with detailed error on failure."""
    desc = description or (" ".join(cmd) if isinstance(cmd, list) else cmd)
    print(f"  Running: {desc}")
    result = subprocess.run(
        cmd,
        cwd=cwd,
        shell=isinstance(cmd, str),
        capture_output=False,
    )
    if result.returncode != 0:
        print(f"\nERROR: Command failed (exit code {result.returncode}): {desc}", file=sys.stderr)
        if cwd:
            print(f"  Working directory: {cwd}", file=sys.stderr)
        sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <destination_folder>", file=sys.stderr)
        sys.exit(1)

    dest_folder = os.path.abspath(sys.argv[1])

    # Determine srcdir: one level up from the script's dirname
    script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    src_dir = os.path.dirname(script_dir)

    print(f"Source directory: {src_dir}")
    print(f"Destination folder: {dest_folder}")

    # Verify autogen.sh exists
    autogen_sh = os.path.join(src_dir, "autogen.sh")
    if not os.path.isfile(autogen_sh):
        print(f"ERROR: autogen.sh not found at {autogen_sh}", file=sys.stderr)
        sys.exit(1)

    # Create temporary build folder (in the platform default temp directory)
    tmp_dir = tempfile.mkdtemp(prefix="xmlsec-wiki-build-")
    print(f"Temporary build directory: {tmp_dir}")

    try:
        # Run autogen.sh from srcdir inside tmp_dir
        print("\n--- Running autogen.sh ---")
        jobs = os.cpu_count() or 2
        build_cmd = f"{shlex.quote(autogen_sh)} && make -j{jobs} && make -C docs docs"
        run_command(
            build_cmd,
            cwd=tmp_dir,
            description=f"cd {tmp_dir} && {build_cmd}",
        )

        # Locate the generated docs/md folder in the build dir
        build_md_folder = os.path.join(tmp_dir, "docs", "md")
        if not os.path.isdir(build_md_folder):
            print(f"ERROR: Expected build output at {build_md_folder} not found.", file=sys.stderr)
            sys.exit(1)

        # Create destination folder if needed
        if not os.path.exists(dest_folder):
            print(f"\nCreating destination folder: {dest_folder}")
            try:
                os.makedirs(dest_folder)
            except OSError as e:
                print(f"ERROR: Failed to create destination folder {dest_folder}: {e}", file=sys.stderr)
                sys.exit(1)

        # Create images subfolder
        dest_images_folder = os.path.join(dest_folder, "images")
        if not os.path.exists(dest_images_folder):
            try:
                os.makedirs(dest_images_folder)
            except OSError as e:
                print(f"ERROR: Failed to create images folder {dest_images_folder}: {e}", file=sys.stderr)
                sys.exit(1)

        # --- Collect and process markdown files ---
        print("\n--- Processing markdown files ---")

        # Build a mapping: wiki_name -> (source_folder_name, source_abs_path)
        wiki_files = {}
        for subfolder in sorted(os.listdir(build_md_folder)):
            subfolder_path = os.path.join(build_md_folder, subfolder)
            if not os.path.isdir(subfolder_path):
                continue
            for filename in sorted(os.listdir(subfolder_path)):
                if not filename.endswith(".md"):
                    continue
                src_path = os.path.join(subfolder_path, filename)
                if not os.path.isfile(src_path):
                    continue
                wiki_name = camel_case_name(subfolder, filename)
                wiki_files[wiki_name] = (subfolder, src_path)

        # Process top-level .md files directly in build_md_folder
        for filename in sorted(os.listdir(build_md_folder)):
            if not filename.endswith(".md"):
                continue
            src_path = os.path.join(build_md_folder, filename)
            if not os.path.isfile(src_path):
                continue
            wiki_name = camel_case_top_level_name(filename)
            wiki_files[wiki_name] = (".", src_path)

        if not wiki_files:
            print(f"ERROR: No markdown files found under {build_md_folder}", file=sys.stderr)
            sys.exit(1)

        # Existing .md files in dest (to detect obsolete ones)
        existing_md = set()
        for f in os.listdir(dest_folder):
            if f.endswith(".md") and os.path.isfile(os.path.join(dest_folder, f)):
                existing_md.add(f)

        copied_files = []
        deleted_files = []

        # Process and copy markdown files
        for wiki_name, (subfolder, src_path) in wiki_files.items():
            try:
                with open(src_path, "r", encoding="utf-8") as fh:
                    content = fh.read()
            except OSError as e:
                print(f"ERROR: Failed to read {src_path}: {e}", file=sys.stderr)
                sys.exit(1)

            # Fix links
            fixed_content = fix_md_links(content, subfolder)

            dest_path = os.path.join(dest_folder, wiki_name)
            try:
                with open(dest_path, "w", encoding="utf-8") as fh:
                    fh.write(fixed_content)
            except OSError as e:
                print(f"ERROR: Failed to write {dest_path}: {e}", file=sys.stderr)
                sys.exit(1)

            copied_files.append(dest_path)
            src_label = os.path.basename(src_path) if subfolder == "." else os.path.join(subfolder, os.path.basename(src_path))
            print(f"  Copied: {src_label} -> {wiki_name}")

        # Delete obsolete .md files in dest (but never delete Home.md or files starting with "_")
        new_md_names = set(wiki_files.keys())
        for old_name in sorted(existing_md - new_md_names):
            if old_name == "Home.md" or old_name.startswith("_"):
                continue
            old_path = os.path.join(dest_folder, old_name)
            try:
                os.remove(old_path)
                deleted_files.append(old_path)
                print(f"  Deleted obsolete: {old_name}")
            except OSError as e:
                print(f"ERROR: Failed to delete {old_path}: {e}", file=sys.stderr)
                sys.exit(1)

        # --- Collect and copy images ---
        print("\n--- Processing images ---")

        # Existing images in dest/images/
        existing_images = set()
        for f in os.listdir(dest_images_folder):
            if os.path.isfile(os.path.join(dest_images_folder, f)):
                existing_images.add(f)

        new_image_names = set()
        src_images = collect_images(build_md_folder)

        # All images are flattened into a single images/ directory by basename,
        # so two source folders containing an image with the same name would
        # silently overwrite each other; fail loudly instead.
        images_by_name = {}
        for img_src in src_images:
            images_by_name.setdefault(os.path.basename(img_src), []).append(img_src)
        collisions = {name: paths for name, paths in images_by_name.items() if len(paths) > 1}
        if collisions:
            for name in sorted(collisions):
                print(f"ERROR: multiple source images share the name '{name}':", file=sys.stderr)
                for path in collisions[name]:
                    print(f"  {path}", file=sys.stderr)
            sys.exit(1)

        for img_src in sorted(src_images):
            img_filename = os.path.basename(img_src)
            img_dest = os.path.join(dest_images_folder, img_filename)
            try:
                shutil.copy2(img_src, img_dest)
                new_image_names.add(img_filename)
                copied_files.append(img_dest)
                print(f"  Copied image: {img_filename}")
            except OSError as e:
                print(f"ERROR: Failed to copy image {img_src} to {img_dest}: {e}", file=sys.stderr)
                sys.exit(1)

        # Delete obsolete images
        for old_img in sorted(existing_images - new_image_names):
            old_img_path = os.path.join(dest_images_folder, old_img)
            try:
                os.remove(old_img_path)
                deleted_files.append(old_img_path)
                print(f"  Deleted obsolete image: {old_img}")
            except OSError as e:
                print(f"ERROR: Failed to delete {old_img_path}: {e}", file=sys.stderr)
                sys.exit(1)

    finally:
        # Clean up temporary directory
        print(f"\n--- Cleaning up temporary directory {tmp_dir} ---")
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Summary
    print("\n=== Summary ===")
    print(f"\nCopied files ({len(copied_files)}):")
    for f in copied_files:
        print(f"  {f}")

    if deleted_files:
        print(f"\nDeleted files ({len(deleted_files)}):")
        for f in deleted_files:
            print(f"  {f}")
    else:
        print("\nNo files deleted.")

    print("\nDone.")


if __name__ == "__main__":
    main()

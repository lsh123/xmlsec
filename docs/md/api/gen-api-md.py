#!/usr/bin/env python3
#
# gen-api-md.py — Generate Markdown API documentation from Doxygen XML group files.
#
# Usage:
#   python3 gen-api-md.py <xmlsec_version> <xml_input_dir> <md_output_dir>
#
# Reads group__*.xml files from <xml_input_dir> (Doxygen XML output) and writes
# one Markdown file per group into <md_output_dir>.
#
# Validates the structure of each XML file and reports errors for missing or
# unexpected elements.
#

import dataclasses
import os
import re
import sys
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_errors: list[str] = []
_warnings: list[str] = []
_version: str = ""


def _error(msg: str) -> None:
    _errors.append(msg)
    print(f"ERROR: {msg}", file=sys.stderr)


def _warn(msg: str) -> None:
    _warnings.append(msg)
    print(f"WARNING: {msg}", file=sys.stderr)


def _require(node: ET.Element | None, path: str, context: str) -> ET.Element | None:
    """Assert that *node* is not None; record an error if it is."""
    if node is None:
        _error(f"{context}: missing required element <{path}>")
    return node


def _require_attr(node: ET.Element, attr: str, context: str) -> str | None:
    """Assert that *node* has *attr*; record an error and return None if missing."""
    val = node.get(attr)
    if val is None:
        _error(f"{context}: element <{node.tag}> is missing required attribute '{attr}'")
    return val


def _require_text(node: ET.Element | None, tag: str, context: str) -> str:
    """Return text of child *tag* or '' with error if missing / empty."""
    if node is None:
        _error(f"{context}: parent element is None when looking for <{tag}>")
        return ""
    child = node.find(tag)
    if child is None:
        _error(f"{context}: missing required child element <{tag}>")
        return ""
    text = (child.text or "").strip()
    return text


# ---------------------------------------------------------------------------
# Description markup → Markdown
# ---------------------------------------------------------------------------

def _inline_markup(node: ET.Element) -> str:
    """Convert a mixed-content node to plain/markdown inline text."""
    parts: list[str] = []
    if node.text:
        parts.append(node.text)
    for child in node:
        tag = child.tag
        if tag == "ref":
            parts.append(f"`{(child.text or '').strip()}`")
        elif tag == "computeroutput":
            parts.append(f"`{(child.text or '').strip()}`")
        elif tag == "bold":
            parts.append(f"**{(child.text or '').strip()}**")
        elif tag == "emphasis":
            parts.append(f"*{(child.text or '').strip()}*")
        elif tag == "ulink":
            url = child.get("url", "")
            text = (child.text or url).strip()
            parts.append(f"[{text}]({url})")
        elif tag == "linebreak":
            parts.append("\n")
        elif tag == "ndash":
            parts.append("–")
        elif tag == "mdash":
            parts.append("—")
        elif tag == "sp":
            parts.append(" ")
        else:
            # Recurse for unknown inline tags so we don't lose text
            parts.append(_inline_markup(child))
        if child.tail:
            parts.append(child.tail)
    return "".join(parts).strip()


def _para_to_md(para: ET.Element) -> str:
    """Convert a single <para> element (which may contain mixed content) to
    Markdown text.  Block-level children (parameterlist, simplesect) are
    rendered inline with appropriate prefixes."""
    parts: list[str] = []
    if para.text:
        parts.append(para.text)

    for child in para:
        tag = child.tag
        if tag == "parameterlist":
            kind = child.get("kind", "param")
            if kind == "param":
                items = _render_parameterlist(child)
                if items:
                    parts.append("\n\n**Parameters:**\n\n" + items)
        elif tag == "simplesect":
            kind = child.get("kind", "")
            label_map = {
                "return": "**Returns:**",
                "note": "**Note:**",
                "warning": "**Warning:**",
                "see": "**See also:**",
                "since": "**Since:**",
                "pre": "**Precondition:**",
                "post": "**Postcondition:**",
                "attention": "**Attention:**",
                "remark": "**Remark:**",
                "author": "**Author:**",
                "version": "**Version:**",
                "date": "**Date:**",
                "bug": "**Bug:**",
                "deprecated": "**Deprecated:**",
                "invariant": "**Invariant:**",
            }
            label = label_map.get(kind, f"**{kind.capitalize()}:**")
            inner = " ".join(_para_to_md(p) for p in child.findall("para"))
            parts.append(f"\n\n{label} {inner}")
        elif tag == "ref":
            parts.append(f"`{(child.text or '').strip()}`")
        elif tag == "computeroutput":
            parts.append(f"`{(child.text or '').strip()}`")
        elif tag == "bold":
            parts.append(f"**{(child.text or '').strip()}**")
        elif tag == "emphasis":
            parts.append(f"*{(child.text or '').strip()}*")
        elif tag == "ulink":
            url = child.get("url", "")
            text = (child.text or url).strip()
            parts.append(f"[{text}]({url})")
        elif tag == "linebreak":
            parts.append("\n")
        elif tag in ("ndash",):
            parts.append("–")
        elif tag in ("mdash",):
            parts.append("—")
        elif tag == "sp":
            parts.append(" ")
        elif tag == "itemizedlist":
            items_md = "\n".join(
                "- " + _para_to_md(li.find("para") if li.find("para") is not None else ET.Element("para"))
                for li in child.findall("listitem")
            )
            parts.append("\n\n" + items_md)
        elif tag == "orderedlist":
            items_md = "\n".join(
                f"{i+1}. " + _para_to_md(li.find("para") if li.find("para") is not None else ET.Element("para"))
                for i, li in enumerate(child.findall("listitem"))
            )
            parts.append("\n\n" + items_md)
        elif tag == "programlisting":
            code = "".join(ET.tostring(l, encoding="unicode", method="text") for l in child)
            parts.append(f"\n\n```c\n{code.rstrip()}\n```")
        elif tag in ("title", "heading"):
            pass  # skip internal headings
        else:
            parts.append(_inline_markup(child))

        if child.tail:
            parts.append(child.tail)

    return "".join(parts).strip()


def _render_parameterlist(node: ET.Element) -> str:
    """Render a <parameterlist kind='param'> as a Markdown list."""
    lines: list[str] = []
    for item in node.findall("parameteritem"):
        names = [
            (pn.text or "").strip()
            for pnl in item.findall("parameternamelist")
            for pn in pnl.findall("parametername")
            if (pn.text or "").strip()
        ]
        desc_paras = [
            _para_to_md(p)
            for pd in item.findall("parameterdescription")
            for p in pd.findall("para")
        ]
        desc = " ".join(desc_paras).strip()
        for name in names:
            lines.append(f"- `{name}` — {desc}")
    return "\n".join(lines)


def _description_to_md(parent: ET.Element | None) -> str:
    """Convert a <briefdescription> or <detaileddescription> element to Markdown."""
    if parent is None:
        return ""
    paragraphs: list[str] = []
    for child in parent:
        if child.tag == "para":
            text = _para_to_md(child)
            if text:
                paragraphs.append(text)
        elif child.tag == "sect1":
            title_elem = child.find("title")
            title = (title_elem.text or "") if title_elem is not None else ""
            if title:
                paragraphs.append(f"#### {title}")
            for p in child.findall("para"):
                text = _para_to_md(p)
                if text:
                    paragraphs.append(text)
        elif child.tag == "verbatim":
            code = (child.text or "").strip()
            if code:
                paragraphs.append(f"```\n{code}\n```")
        elif child.tag == "programlisting":
            code = "".join(ET.tostring(l, encoding="unicode", method="text") for l in child)
            if code.strip():
                paragraphs.append(f"```c\n{code.rstrip()}\n```")
        # other tags (itemizedlist at top level, etc.) — ignored for brevity
    return "\n\n".join(paragraphs)


# ---------------------------------------------------------------------------
# GitHub source link helper
# ---------------------------------------------------------------------------

_GITHUB_BASE = "https://github.com/lsh123/xmlsec/blob"


def _github_source_link(src_file: str, src_line: str) -> str:
    """Return a Markdown source-location string, linking to GitHub when a version is set."""
    if not src_file:
        return ""
    if _version:
        url = f"{_GITHUB_BASE}/{_version}/{src_file}"
        if src_line:
            url += f"#L{src_line}"
        return f"[{src_file}]({url})"
    loc_str = f"`{src_file}`"
    if src_line:
        loc_str += f" (line {src_line})"
    return loc_str


# ---------------------------------------------------------------------------
# Type/signature helpers
# ---------------------------------------------------------------------------

def _elem_to_text(node: ET.Element | None) -> str:
    """Extract plain text from an element that may contain <ref> children."""
    if node is None:
        return ""
    return "".join(node.itertext()).strip()


def _build_function_signature(member: ET.Element) -> str:
    """Build a C-style function signature string from a memberdef element."""
    ret_type = _elem_to_text(member.find("type"))
    name = (member.findtext("name") or "").strip()
    argsstring = (member.findtext("argsstring") or "").strip()

    # If argsstring already looks complete, use it directly
    if argsstring.startswith("("):
        return f"{ret_type} {name}{argsstring};"

    # Otherwise build from individual params
    params_parts: list[str] = []
    for param in member.findall("param"):
        ptype = _elem_to_text(param.find("type"))
        pdecl = (param.findtext("declname") or "").strip()
        # handle function-pointer params: type="void(*" argsstring=")(...)
        parray = (param.findtext("array") or "").strip()
        if pdecl:
            params_parts.append(f"{ptype} {pdecl}{parray}".strip())
        else:
            params_parts.append(ptype)
    params_str = ", ".join(params_parts) if params_parts else "void"
    return f"{ret_type} {name}({params_str});"


def _build_typedef_signature(member: ET.Element) -> str:
    """Reconstruct a typedef signature."""
    defn = (member.findtext("definition") or "").strip()
    argsstring = (member.findtext("argsstring") or "").strip()
    if defn:
        return f"{defn}{argsstring};"
    t = _elem_to_text(member.find("type"))
    name = (member.findtext("name") or "").strip()
    return f"typedef {t} {name}{argsstring};"


# ---------------------------------------------------------------------------
# Validation: check for unexpected / unknown attributes
# ---------------------------------------------------------------------------

_KNOWN_SECTION_KINDS = {"define", "typedef", "enum", "func"}


def _validate_compounddef(compound: ET.Element, source_file: str) -> None:
    ctx = os.path.basename(source_file)
    if compound.get("kind") != "group":
        _error(f"{ctx}: <compounddef> has unexpected kind='{compound.get('kind')}' (expected 'group')")
    if not compound.findtext("compoundname"):
        _error(f"{ctx}: <compounddef> is missing <compoundname>")
    if not compound.findtext("title"):
        _warn(f"{ctx}: <compounddef> is missing <title> — group will have no heading")
    for section in compound.findall("sectiondef"):
        kind = section.get("kind")
        if kind not in _KNOWN_SECTION_KINDS:
            _warn(f"{ctx}: unknown <sectiondef kind='{kind}'> — section will be skipped")
        for member in section.findall("memberdef"):
            m_kind = member.get("kind")
            # validate that name is present for every member
            name = (member.findtext("name") or "").strip()
            if not name:
                _error(f"{ctx}: <memberdef kind='{m_kind}'> is missing <name>")
            if m_kind == "function":
                if member.find("type") is None:
                    _error(f"{ctx}: function '{name}' is missing <type>")
            elif m_kind == "typedef":
                if not member.findtext("definition") and member.find("type") is None:
                    _error(f"{ctx}: typedef '{name}' is missing <type> and <definition>")


# ---------------------------------------------------------------------------
# Markdown renderers per section kind
# ---------------------------------------------------------------------------

def _render_defines(section: ET.Element) -> str:
    lines: list[str] = ["## Macros\n"]
    for member in section.findall("memberdef"):
        name = (member.findtext("name") or "").strip()
        initializer = _elem_to_text(member.find("initializer"))
        brief = _description_to_md(member.find("briefdescription"))
        detail = _description_to_md(member.find("detaileddescription"))
        loc = member.find("location")
        src_file = loc.get("file", "") if loc is not None else ""
        src_line = loc.get("declline") or (loc.get("line", "") if loc is not None else "")

        lines.append(f"### `{name}`\n")
        if initializer:
            lines.append(f"*Defined as:* `{initializer}`\n")
        if src_file:
            lines.append(f"*Source:* {_github_source_link(src_file, src_line)}\n")
        if brief:
            lines.append(f"{brief}\n")
        if detail and detail != brief:
            lines.append(f"{detail}\n")
        lines.append("---\n")
    return "\n".join(lines)


def _render_typedefs(section: ET.Element) -> str:
    lines: list[str] = ["## Typedefs\n"]
    for member in section.findall("memberdef"):
        name = (member.findtext("name") or "").strip()
        sig = _build_typedef_signature(member)
        brief = _description_to_md(member.find("briefdescription"))
        detail = _description_to_md(member.find("detaileddescription"))
        loc = member.find("location")
        src_file = loc.get("file", "") if loc is not None else ""
        src_line = loc.get("declline") or (loc.get("line", "") if loc is not None else "")

        lines.append(f"### `{name}`\n")
        lines.append(f"```c\n{sig}\n```\n")
        if src_file:
            lines.append(f"*Source:* {_github_source_link(src_file, src_line)}\n")
        if brief:
            lines.append(f"{brief}\n")
        if detail and detail != brief:
            lines.append(f"{detail}\n")
        lines.append("---\n")
    return "\n".join(lines)


def _render_enums(section: ET.Element) -> str:
    lines: list[str] = ["## Enumerations\n"]
    for member in section.findall("memberdef"):
        name = (member.findtext("name") or "").strip()
        brief = _description_to_md(member.find("briefdescription"))
        detail = _description_to_md(member.find("detaileddescription"))
        loc = member.find("location")
        src_file = loc.get("file", "") if loc is not None else ""
        src_line = loc.get("declline") or (loc.get("line", "") if loc is not None else "")

        lines.append(f"### `{name}`\n")
        if src_file:
            lines.append(f"*Source:* {_github_source_link(src_file, src_line)}\n")
        if brief:
            lines.append(f"{brief}\n")
        if detail and detail != brief:
            lines.append(f"{detail}\n")

        # Render enum values as a table
        values = [
            ev for ev in member.findall("enumvalue")
            if (ev.findtext("name") or "").strip()
        ]
        if values:
            lines.append("| Value | Initializer | Description |")
            lines.append("|-------|-------------|-------------|")
            for ev in values:
                ev_name = (ev.findtext("name") or "").strip()
                ev_init = (ev.findtext("initializer") or "").strip()
                ev_brief = _description_to_md(ev.find("briefdescription")).replace("\n", " ")
                lines.append(f"| `{ev_name}` | `{ev_init}` | {ev_brief} |")
            lines.append("")
        lines.append("---\n")
    return "\n".join(lines)


def _render_functions(section: ET.Element) -> str:
    lines: list[str] = ["## Functions\n"]
    for member in section.findall("memberdef"):
        name = (member.findtext("name") or "").strip()
        sig = _build_function_signature(member)
        brief = _description_to_md(member.find("briefdescription"))
        detail = _description_to_md(member.find("detaileddescription"))
        loc = member.find("location")
        src_file = loc.get("file", "") if loc is not None else ""
        src_line = loc.get("declline") or (loc.get("line", "") if loc is not None else "")

        lines.append(f"### `{name}`\n")
        lines.append(f"```c\n{sig}\n```\n")
        if src_file:
            lines.append(f"*Source:* {_github_source_link(src_file, src_line)}\n")
        if brief:
            lines.append(f"{brief}\n")
        if detail and detail != brief:
            lines.append(f"{detail}\n")
        lines.append("---\n")
    return "\n".join(lines)


_SECTION_RENDERERS = {
    "define": _render_defines,
    "typedef": _render_typedefs,
    "enum": _render_enums,
    "func": _render_functions,
}

# Order in which sections appear in the output
_SECTION_ORDER = ["define", "typedef", "enum", "func"]


# ---------------------------------------------------------------------------
# Group metadata (collected while parsing, used to build the index)
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class GroupInfo:
    group_id: str        # Doxygen compound id, e.g. 'group__xmlsec__core'
    group_name: str      # compoundname, e.g. 'xmlsec_core'
    title: str           # human-readable title
    brief: str           # one-liner description
    filename: str        # output .md filename
    children: list[str]  # list of child group_ids (from <innergroup>)


# ---------------------------------------------------------------------------
# Per-group Markdown generation
# ---------------------------------------------------------------------------

def _group_id_to_filename(group_id: str) -> str:
    """Convert a Doxygen group id (e.g. 'group__xmlsec__core__base64') to a
    Markdown filename (e.g. 'xmlsec_core_base64.md')."""
    # strip leading 'group__' then collapse double underscores to single
    name = re.sub(r"^group__", "", group_id)
    name = re.sub(r"__+", "_", name)
    return f"{name}.md"


def _parse_group_xml(xml_path: str) -> tuple[list[str], GroupInfo] | None:
    """Parse *xml_path* and build the Markdown content for a group.
    Returns a (md_parts, GroupInfo) tuple on success, None on fatal parse error.
    The caller is responsible for writing the file."""
    ctx = os.path.basename(xml_path)

    # --- Parse ---
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        _error(f"{ctx}: XML parse error: {exc}")
        return None

    root = tree.getroot()
    if root.tag != "doxygen":
        _error(f"{ctx}: root element is <{root.tag}> (expected <doxygen>)")
        return None

    compound = root.find("compounddef")
    if compound is None:
        _error(f"{ctx}: missing <compounddef>")
        return None

    # --- Validate ---
    _validate_compounddef(compound, xml_path)

    group_id = compound.get("id", "")
    if not group_id:
        _error(f"{ctx}: <compounddef> missing 'id' attribute")
    title = (compound.findtext("title") or group_id).strip()
    group_name = (compound.findtext("compoundname") or group_id).strip()

    # --- Build output ---
    md_parts: list[str] = []

    # Heading placeholder — caller may replace with a versioned heading
    md_parts.append(f"# {title}\n")
    md_parts.append(f"**API Group:** `{group_name}`\n")

    brief = _description_to_md(compound.find("briefdescription"))
    if brief:
        md_parts.append(brief + "\n")

    # sub-groups
    inner_groups = compound.findall("innergroup")
    if inner_groups:
        md_parts.append("## Sub-groups\n")
        for ig in inner_groups:
            ref_id = ig.get("refid", "")
            ig_title = (ig.text or ref_id).strip()
            # link to the generated .md file for the sub-group
            ig_filename = _group_id_to_filename(ref_id)
            md_parts.append(f"- [{ig_title}]({ig_filename})\n")

    detail = _description_to_md(compound.find("detaileddescription"))
    if detail and detail != brief:
        md_parts.append(detail + "\n")

    # sections (macros, typedefs, enums, functions)
    sections_by_kind: dict[str, ET.Element] = {}
    for section in compound.findall("sectiondef"):
        kind = section.get("kind", "")
        if kind in _KNOWN_SECTION_KINDS:
            sections_by_kind[kind] = section

    for kind in _SECTION_ORDER:
        if kind in sections_by_kind:
            renderer = _SECTION_RENDERERS[kind]
            rendered = renderer(sections_by_kind[kind])
            if rendered.strip():
                md_parts.append(rendered)

    info = GroupInfo(
        group_id=group_id,
        group_name=group_name,
        title=title,
        brief=_description_to_md(compound.find("briefdescription")),
        filename=_group_id_to_filename(group_id),
        children=[ig.get("refid", "") for ig in compound.findall("innergroup")],
    )
    return md_parts, info


# ---------------------------------------------------------------------------
# Index generation
# ---------------------------------------------------------------------------

def generate_index_md(groups: dict[str, GroupInfo], out_dir: str, version: str = "") -> str:
    """Build index.md with a hierarchical table of contents.

    Top-level groups (those not referenced as a child by any other group) are
    listed as H2 sections, sorted by title.  Their children and grand-children
    follow as nested lists, each level sorted alphabetically by title.
    Any group not reachable from a root is appended at the end under
    "Other Groups" so nothing is silently lost.
    """
    # Determine root groups: those not listed as a child of any other group
    all_children: set[str] = {c for info in groups.values() for c in info.children}
    roots = sorted(
        [gid for gid in groups if gid not in all_children],
        # deprecated groups sort last; within each tier, sort alphabetically
        key=lambda gid: (1 if "(DEPRECATED)" in groups[gid].title else 0, groups[gid].title.lower()),
    )

    # Warn about any child references that have no corresponding parsed file
    for cid in sorted(all_children - groups.keys()):
        _warn(f"index: child group '{cid}' has no parsed GroupInfo — omitted from index")

    # Track which groups have been rendered to catch orphans
    rendered: set[str] = set()

    lines: list[str] = []
    heading = "# XML Security Library – API Reference"
    if version:
        heading += f" ({version})"
    lines.append(heading + "\n")
    lines.append(
        "This index lists all API groups. "
        "Each group links to a page describing its macros, types, "
        "enumerations, and functions.\n"
    )

    def _toc_entry(gid: str, depth: int) -> None:
        """Recursively emit a TOC entry for *gid* and all its children."""
        if gid not in groups:
            return
        info = groups[gid]
        rendered.add(gid)
        indent = "  " * depth
        brief_line = info.brief.split("\n")[0] if info.brief else ""
        suffix = f" — {brief_line}" if brief_line else ""
        lines.append(f"{indent}- [{info.title}]({info.filename}){suffix}")
        for child_id in sorted(
            info.children,
            key=lambda c: groups.get(c, GroupInfo(c, c, c, "", "", [])).title.lower(),
        ):
            _toc_entry(child_id, depth + 1)

    for root_id in roots:
        info = groups[root_id]
        lines.append(f"## {info.title}\n")
        if info.brief:
            lines.append(info.brief.split("\n")[0] + "\n")
        for child_id in sorted(
            info.children,
            key=lambda c: groups.get(c, GroupInfo(c, c, c, "", "", [])).title.lower(),
        ):
            _toc_entry(child_id, 0)
        lines.append(f"\n[Full {info.title} reference →]({info.filename})\n")

    # Emit any groups not reachable from a root (e.g. orphaned groups)
    orphans = sorted(
        [gid for gid in groups if gid not in rendered and gid not in roots],
        key=lambda gid: groups[gid].title.lower(),
    )
    if orphans:
        lines.append("## Other Groups\n")
        for gid in orphans:
            info = groups[gid]
            brief_suffix = f" — {info.brief.split(chr(10))[0]}" if info.brief else ""
            lines.append(f"- [{info.title}]({info.filename}){brief_suffix}")
        lines.append("")

    out_path = os.path.join(out_dir, "index.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return out_path


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    if len(sys.argv) != 4:
        print(
            f"Usage: {sys.argv[0]} <xmlsec_version> <xml_input_dir> <md_output_dir>",
            file=sys.stderr,
        )
        return 2

    version = sys.argv[1]
    xml_dir = sys.argv[2]
    out_dir = sys.argv[3]

    global _version
    _version = version

    # Validate input directory
    if not os.path.isdir(xml_dir):
        print(f"ERROR: input directory not found: {xml_dir}", file=sys.stderr)
        return 1

    # Collect group XML files
    group_files = sorted(
        os.path.join(xml_dir, f)
        for f in os.listdir(xml_dir)
        if f.startswith("group__") and f.endswith(".xml")
    )

    if not group_files:
        print(f"ERROR: no group__*.xml files found in {xml_dir}", file=sys.stderr)
        return 1

    print(f"-- Found {len(group_files)} group XML file(s) in {xml_dir}")

    # Phase 1: parse all XML files to collect md_parts and GroupInfo
    parsed: dict[str, tuple[list[str], GroupInfo]] = {}
    for xml_path in group_files:
        result = _parse_group_xml(xml_path)
        if result:
            md_parts, info = result
            parsed[info.group_id] = (md_parts, info)
        else:
            _error(f"Failed to parse {xml_path}")

    # Determine root groups: those not referenced as a child by any other group
    all_children: set[str] = {c for _, info in parsed.values() for c in info.children}
    root_ids: set[str] = {gid for gid in parsed if gid not in all_children}

    # Phase 2: write files, adding version to the heading for root groups
    os.makedirs(out_dir, exist_ok=True)

    generated: list[str] = []
    groups: dict[str, GroupInfo] = {}
    for group_id, (md_parts, info) in parsed.items():
        if version and group_id in root_ids:
            md_parts_out = [f"# {info.title} ({version})\n"] + md_parts[1:]
        else:
            md_parts_out = md_parts
        out_path = os.path.join(out_dir, info.filename)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md_parts_out))
        print(f"Generated {out_path}")
        generated.append(out_path)
        groups[group_id] = info

    print(f"-- Generated {len(generated)} Markdown file(s) in {out_dir}")

    # Generate index.md
    if groups:
        index_path = generate_index_md(groups, out_dir, version)
        print(f"Generated {index_path}")

    if _errors:
        print(
            f"\n-- {len(_errors)} error(s) encountered; see messages above.",
            file=sys.stderr,
        )
        return 1
    if _warnings:
        print(f"-- {len(_warnings)} warning(s) encountered.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

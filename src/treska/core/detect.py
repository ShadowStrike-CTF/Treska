# Treska core — extraction type detection (iOS FFS / Android logical) by name only.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import os
from pathlib import Path

IOS_FFS = "IOS_FFS"
ANDROID_LOGICAL = "ANDROID_LOGICAL"
UNKNOWN = "UNKNOWN"

# Markers are stored casefolded: extraction tools capitalise names inconsistently.
IOS_DIRS = frozenset({"homedomain"})
IOS_DIR_PREFIXES = ("appdomain-",)
IOS_FILES = frozenset({"sms.db", "knowledgec.db", "addressbook.sqlitedb"})

ANDROID_DIRS: frozenset[str] = frozenset()
ANDROID_DIR_PREFIXES = ("com.android.",)
ANDROID_FILES = frozenset({"mmssms.db", "contacts2.db", "calllog.db"})


def _has_marker(
    root: Path,
    dir_names: frozenset[str],
    dir_prefixes: tuple[str, ...],
    file_names: frozenset[str],
) -> bool:
    """True if any directory or file name anywhere under root is a marker.

    Walks names only (os.walk, symlinks not followed) — never opens a file.
    """
    for _, dirnames, filenames in os.walk(root):
        for name in dirnames:
            folded = name.casefold()
            if folded in dir_names or folded.startswith(dir_prefixes):
                return True
        for name in filenames:
            if name.casefold() in file_names:
                return True
    return False


def detect_extraction_type(tree_root: Path) -> str:
    """IOS_FFS, ANDROID_LOGICAL or UNKNOWN for an unzipped extraction tree.

    The iOS check runs over the whole tree first, so a tree carrying both
    iOS and Android markers is IOS_FFS. A missing root is UNKNOWN.
    """
    root = Path(tree_root)
    if not root.is_dir():
        return UNKNOWN
    if _has_marker(root, IOS_DIRS, IOS_DIR_PREFIXES, IOS_FILES):
        return IOS_FFS
    if _has_marker(root, ANDROID_DIRS, ANDROID_DIR_PREFIXES, ANDROID_FILES):
        return ANDROID_LOGICAL
    return UNKNOWN

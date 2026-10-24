# Treska Phase 7 tests — extraction type detection (iOS FFS / Android logical).
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import zipfile
from dataclasses import asdict

from treska.core.detect import ANDROID_LOGICAL, IOS_FFS, UNKNOWN, detect_extraction_type
from treska.core.pipeline import parse_zip


def _tree(root, *paths: str):
    """Build a synthetic tree: "a/b/" makes a directory, anything else an empty file."""
    for rel in paths:
        target = root / rel
        if rel.endswith("/"):
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"")
    return root


def test_detect_ios_ffs_by_homedomain(tmp_path):
    _tree(tmp_path, "private/var/mobile/HomeDomain/")
    assert detect_extraction_type(tmp_path) == IOS_FFS


def test_detect_ios_ffs_by_appdomain(tmp_path):
    _tree(tmp_path, "backup/AppDomain-com.apple.foo/Documents/notes.txt")
    assert detect_extraction_type(tmp_path) == IOS_FFS


def test_detect_ios_ffs_by_sms_db(tmp_path):
    _tree(tmp_path, "private/var/mobile/Library/SMS/sms.db")
    assert detect_extraction_type(tmp_path) == IOS_FFS


def test_detect_ios_ffs_by_knowledgec(tmp_path):
    _tree(tmp_path, "private/var/mobile/Library/CoreDuet/Knowledge/KnowledgeC.db")
    assert detect_extraction_type(tmp_path) == IOS_FFS


def test_detect_ios_ffs_by_addressbook(tmp_path):
    _tree(tmp_path, "private/var/mobile/Library/AddressBook/AddressBook.sqlitedb")
    assert detect_extraction_type(tmp_path) == IOS_FFS


def test_detect_android_logical(tmp_path):
    _tree(
        tmp_path,
        "data/data/com.android.providers.telephony/databases/mmssms.db",
        "data/data/com.android.providers.contacts/databases/contacts2.db",
    )
    assert detect_extraction_type(tmp_path) == ANDROID_LOGICAL


def test_detect_unknown(tmp_path):
    # Near-misses: marker names on the wrong kind of entry, or not quite the name.
    _tree(tmp_path, "docs/readme.txt", "HomeDomain", "sms.db/", "AppDomain/", "mmssms.db.bak")
    assert detect_extraction_type(tmp_path) == UNKNOWN
    assert detect_extraction_type(tmp_path / "missing") == UNKNOWN


def test_detect_ios_priority_over_android(tmp_path):
    # Android marker is shallower than the iOS one: iOS still wins.
    _tree(tmp_path, "a/calllog.db", "z/deep/er/still/HomeDomain/")
    assert detect_extraction_type(tmp_path) == IOS_FFS


def test_detect_case_insensitive(tmp_path):
    ios = _tree(tmp_path / "ios", "x/HOMEDOMAIN/")
    assert detect_extraction_type(ios) == IOS_FFS
    sms = _tree(tmp_path / "sms", "Library/SMS/SMS.DB")
    assert detect_extraction_type(sms) == IOS_FFS
    appdomain = _tree(tmp_path / "app", "appdomain-com.example/")
    assert detect_extraction_type(appdomain) == IOS_FFS
    android = _tree(tmp_path / "android", "data/Com.Android.Providers.Telephony/")
    assert detect_extraction_type(android) == ANDROID_LOGICAL


def test_parse_zip_reports_extraction_type(tmp_path):
    zip_path = tmp_path / "ios.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("HomeDomain/Library/SMS/sms.db", b"")
        zf.writestr("readme.txt", b"hello")
    result = parse_zip(zip_path)
    assert result.extraction_type == IOS_FFS
    assert asdict(result)["extraction_type"] == IOS_FFS

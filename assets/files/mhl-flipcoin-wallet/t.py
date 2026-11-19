#!/usr/bin/env python3
# Flipcoin Wallet SQLi harness: rebuilds the app's query and runs it through
# sqlite3_prepare, exactly like DatabaseHelper.getWallets.
# usage: python3 t.py '<raw amount value>'
import ctypes, ctypes.util, sys, urllib.parse

lib = ctypes.CDLL(ctypes.util.find_library("sqlite3"))
P = ctypes.c_void_p
lib.sqlite3_open.argtypes = [ctypes.c_char_p, ctypes.POINTER(P)]
lib.sqlite3_prepare.argtypes = [P, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(P), ctypes.POINTER(ctypes.c_char_p)]
lib.sqlite3_step.argtypes = [P]
lib.sqlite3_errmsg.argtypes = [P];               lib.sqlite3_errmsg.restype = ctypes.c_char_p
lib.sqlite3_column_int.argtypes = [P, ctypes.c_int]
lib.sqlite3_column_double.argtypes = [P, ctypes.c_int]; lib.sqlite3_column_double.restype = ctypes.c_double
lib.sqlite3_column_text.argtypes = [P, ctypes.c_int];   lib.sqlite3_column_text.restype = ctypes.c_char_p

raw = sys.argv[1]
enc = urllib.parse.quote(raw, safe="")
dec = urllib.parse.unquote(enc)

# same string the app builds (final char at 0x100022d46)
sql = ("SELECT * FROM wallet " + f"WHERE amount >{dec} AND currency='flipcoin' LIMIT 1" + ";").encode()
print("[sql]  ", sql.decode())
print("[url]   amount=" + enc)

db, stmt, tail = P(), P(), ctypes.c_char_p()
lib.sqlite3_open(b"/tmp/fc.db", ctypes.byref(db))
if lib.sqlite3_prepare(db, sql, -1, ctypes.byref(stmt), ctypes.byref(tail)) != 0:
    print("[app]   error preparing query:", lib.sqlite3_errmsg(db).decode())
    print("[sent]  nothing (NoBalance screen)")
    sys.exit()
if tail.value and tail.value.strip(b" ;"):
    print("[ignored by prepare]", tail.value.decode())

rows = []
while lib.sqlite3_step(stmt) == 100:          # SQLITE_ROW
    r = [lib.sqlite3_column_int(stmt, 0)]
    for i in (1, 2, 3, 4):
        if i == 3:
            r.append(lib.sqlite3_column_double(stmt, 3))
        else:
            v = lib.sqlite3_column_text(stmt, i)
            if v is None:
                print(f"[app]   CRASH: column {i} is NULL (force unwrap)")
                sys.exit()
            r.append(v.decode())
    rows.append(r); print("[row]  ", r)

print("[sent] ", rows[-1][1] if rows else "nothing (NoBalance screen)")

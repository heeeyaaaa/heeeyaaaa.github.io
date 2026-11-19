-- Schema and seed rows from the Flipcoin Wallet binary (__cstring), recovery keys redacted.
CREATE TABLE IF NOT EXISTS wallet (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT,
    currency FLOAT,
    amount FLOAT,
    recovery_key TEXT
);
INSERT OR IGNORE INTO wallet (id, address, currency, amount, recovery_key) VALUES
(1, '0x252B2Fff0d264d946n1004E581bb0a46175DC009', 'flipcoin', 0.3654, 'FLAG{REDACTED}'),
(2, '1W5vKAAKmBAjjtpCkGZREjgEGjrbwERND', 'bitcoin', 15.26, 'REDACTED');

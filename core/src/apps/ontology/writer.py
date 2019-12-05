from apps.wallet.sign_tx.writers import write_varint


def write_byte(w: bytearray, n: int) -> None:
    """
    Writes one byte (8bit)
    """
    w.append(n & 0xFF)


def write_uint16(w: bytearray, n: int) -> None:
    """
    Writes short (16bit)
    """
    w.append(n & 0xFF)
    w.append((n >> 8) & 0xFF)


def write_uint32(w: bytearray, n: int) -> None:
    """
    Writes int (32bit)
    """
    w.append(n & 0xFF)
    w.append((n >> 8) & 0xFF)
    w.append((n >> 16) & 0xFF)
    w.append((n >> 24) & 0xFF)


def write_uint64(w: bytearray, n: int) -> None:
    """
    Writes long (64bit)
    """
    w.append(n & 0xFF)
    w.append((n >> 8) & 0xFF)
    w.append((n >> 16) & 0xFF)
    w.append((n >> 24) & 0xFF)
    w.append((n >> 32) & 0xFF)
    w.append((n >> 40) & 0xFF)
    w.append((n >> 48) & 0xFF)
    w.append((n >> 56) & 0xFF)


def write_bool(w: bytearray, n: bool) -> None:
    """
    Writes boolean
    """
    if n:
        write_byte(w, 1)
    else:
        write_byte(w, 0)


def write_bytes(w: bytearray, buf: bytes) -> None:
    """
    Writes arbitrary byte sequence
    """
    w.extend(buf)


def write_bytes_with_length(w: bytearray, buf: bytes) -> None:
    """
    Writes arbitrary byte sequence prepended with the length using variable length integer
    """
    write_varint(w, len(buf))
    write_bytes(w, buf)

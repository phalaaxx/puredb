# puredb.py

import mmap
import os
import struct
import tempfile

__all__ = ['CdbReader', 'CdbWriter', 'PasswdWriter']


def cdb_hash(buf):
    """CDB hash function"""
    h = 5381  # cdb hash start
    for c in buf:
        h = (h + (h << 5)) & 0xFFFFFFFF
        h ^= c
    return h


def uint32_unpack(buf):
    """Unpack 32 bit integer from a stream"""
    return struct.unpack('<L', buf)[0]


def uint32_pack(n):
    """Pack 32 bit integer to a stream"""
    return struct.pack('<L', n)


class CdbReader(object):
    """CDB reader object"""

    def __init__(self, name):
        """Class constructor, initialize class variables"""
        self.loop = 0
        self.key_hash = 0
        self.hash_pos = 0
        self.hash_slots = 0
        fp = open(name, 'rb')
        fd = fp.fileno()
        self.mmap = mmap.mmap(fd, os.stat(fd).st_size, access=mmap.ACCESS_READ)
        self.key = None
        self.key_pos = None

    def __enter__(self):
        """Return object instance"""
        return self

    def __exit__(self, exit_type, exit_value, traceback):
        """Close CDB file"""
        self.mmap.close()
        self.mmap = None

    # read data
    def read(self, n, pos):
        return self.mmap[pos:pos + n]

    def prepare_find(self, key):
        """Prepare a new search"""
        if isinstance(key, int):
            key = str(key)
        if isinstance(key, str):
            key = key.encode()
        self.key = key
        self.loop = 0

    def find_next(self):
        """Find the specified key"""
        if not self.loop:
            u = cdb_hash(self.key)
            buf = self.read(8, u << 3 & 2047)
            self.hash_slots = uint32_unpack(buf[4:])
            if not self.hash_slots:
                raise KeyError
            self.hash_pos = uint32_unpack(buf[:4])
            self.key_hash = u
            u >>= 8
            u %= self.hash_slots
            u <<= 3
            self.key_pos = self.hash_pos + u

        while self.loop < self.hash_slots:
            buf = self.read(8, self.key_pos)
            pos = uint32_unpack(buf[4:])
            if not pos:
                raise KeyError
            self.loop += 1
            self.key_pos += 8
            if self.key_pos == self.hash_pos + (self.hash_slots << 3):
                self.key_pos = self.hash_pos
            u = uint32_unpack(buf[:4])
            if u == self.key_hash:
                buf = self.read(8, pos)
                u = uint32_unpack(buf[:4])
                if u == len(self.key):
                    if self.key == self.read(len(self.key), pos + 8):
                        data_len = uint32_unpack(buf[4:])
                        data_pos = pos + 8 + len(self.key)
                        return self.read(data_len, data_pos).decode()
        raise KeyError

    def get(self, key, n=-1):
        """Look up a cdb key"""
        if self.key != key or n != -1:
            self.prepare_find(key)
        try:
            if n == -1:
                return self.find_next()
            else:
                _key = None
                for i in range(0, n + 1):
                    _key = self.find_next()
                return _key
        except KeyError:
            return None

    def get_all(self, key):
        """Get all items for a key specified"""
        self.prepare_find(key)
        keys = []
        while True:
            try:
                keys.append(self.find_next())
            except KeyError:
                return keys


class CdbWriter(object):
    """CDB writer object"""

    def __init__(self, name):
        """Class constructor, open temp file in target directory"""
        fd, self.temp_name = tempfile.mkstemp(dir=os.path.dirname(name))
        self.fp = os.fdopen(fd, 'wb')
        self.target_name = name
        self.pos = 2048
        self.tables = {}
        self.fp.seek(self.pos)

    def __enter__(self):
        """Return object instance"""
        return self

    def __exit__(self, exit_type, exit_value, traceback):
        """Flush and close temp CDB file and rename it to target name"""
        final = b''
        for i in range(0, 256):
            entries = self.tables.get(i, [])
            num_slots = 2 * len(entries)
            final += uint32_pack(self.pos) + uint32_pack(num_slots)
            null = (0, 0)
            table = [null] * num_slots
            for h, p in entries:
                n = (h >> 8) % num_slots
                while table[n] is not null:
                    n = (n + 1) % num_slots
                table[n] = (h, p)
            for h, p in table:
                self.fp.write(uint32_pack(h) + uint32_pack(p))
                self.pos += 8
        self.fp.flush()
        self.fp.seek(0)
        self.fp.write(final)
        self.fp.close()
        os.rename(self.temp_name, self.target_name)

    def add(self, key, value):
        """Add new key/value pair"""
        if isinstance(key, int):
            key = str(key)
        if isinstance(key, str):
            key = key.encode()
        if isinstance(value, int):
            value = str(value)
        if isinstance(value, str):
            value = value.encode()
        self.fp.write(uint32_pack(len(key)) + uint32_pack(len(value)))
        h = cdb_hash(key)
        self.fp.write(key)
        self.fp.write(value)
        self.tables.setdefault(h & 255, []).append((h, self.pos))
        self.pos += 8 + len(key) + len(value)


class PasswdWriter(object):
    """A passwd file writer object"""

    def __init__(self, name):
        self.target = name

    def __enter__(self):
        """Open temporary database file"""
        fd, self.temp = tempfile.mkstemp(dir=os.path.dirname(self.target))
        self.fp = os.fdopen(fd, 'w+')
        return self

    def __exit__(self, exit_type, exit_value, traceback):
        """Flush database file and rename it to target"""
        self.fp.close()
        os.rename(self.temp, self.target)

    def add(self, name: str, passwd: str = '', uid: int = 0, gid: int = 0, home: str = '', extra: str = ''):
        """Append passwd entry in database file"""
        self.fp.write(
            '{0}:{1}:{2}:{3}::{4}::{5}\n'.format(
                name,
                passwd,
                uid,
                gid,
                home,
                extra,
            ),
        )

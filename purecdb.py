# purecdb.py

import mmap
import os
import struct


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


class CDBRead(object):
    """CDB read object"""

    def __init__(self, name):
        """Class constructor, initialize class variables"""
        self.__loop = 0
        self.__key_hash = 0
        self.__hash_pos = 0
        self.__hash_slots = 0
        fp = open(name, 'rb')
        fd = fp.fileno()
        self.__mmap = mmap.mmap(fd, os.stat(fd).st_size, access=mmap.ACCESS_READ)
        self.__key = None
        self.key_pos = None

    def __enter__(self):
        """Return object instance"""
        return self

    def __exit__(self, exit_type, exit_value, traceback):
        """Close CDB file"""
        self.__mmap.close()
        self.__mmap = None

    # read data
    def read(self, n, pos):
        return self.__mmap[pos:pos + n]

    def prepare_find(self, key):
        """Prepare a new search"""
        if isinstance(key, int):
            key = str(key)
        if isinstance(key, str):
            key = key.encode()
        self.__key = key
        self.__loop = 0

    def find_next(self):
        """Find the specified key"""
        if not self.__loop:
            u = cdb_hash(self.__key)
            buf = self.read(8, u << 3 & 2047)
            self.__hash_slots = uint32_unpack(buf[4:])
            if not self.__hash_slots:
                raise KeyError
            self.__hash_pos = uint32_unpack(buf[:4])
            self.__key_hash = u
            u >>= 8
            u %= self.__hash_slots
            u <<= 3
            self.key_pos = self.__hash_pos + u

        while self.__loop < self.__hash_slots:
            buf = self.read(8, self.key_pos)
            pos = uint32_unpack(buf[4:])
            if not pos:
                raise KeyError
            self.__loop += 1
            self.key_pos += 8
            if self.key_pos == self.__hash_pos + (self.__hash_slots << 3):
                self.key_pos = self.__hash_pos
            u = uint32_unpack(buf[:4])
            if u == self.__key_hash:
                buf = self.read(8, pos)
                u = uint32_unpack(buf[:4])
                if u == len(self.__key):
                    if self.__key == self.read(len(self.__key), pos + 8):
                        data_len = uint32_unpack(buf[4:])
                        data_pos = pos + 8 + len(self.__key)
                        return self.read(data_len, data_pos).decode()
        raise KeyError

    def get(self, key, n=-1):
        """Look up a cdb key"""
        if self.__key != key or n != -1:
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


class CDBWrite(object):
    """CDB write object"""

    def __init__(self, name):
        """Class constructor"""
        self.__fp = open(name, 'wb')
        self.cdb_file = name
        self.__pos = 2048
        self.__tables = {}
        self.__fp.seek(self.__pos)

    def __enter__(self):
        """Return object instance"""
        return self

    def __exit__(self, exit_type, exit_value, traceback):
        """Flush and close CDB file"""
        final = b''
        for i in range(0, 256):
            entries = self.__tables.get(i, [])
            num_slots = 2 * len(entries)
            final += uint32_pack(self.__pos) + uint32_pack(num_slots)
            null = (0, 0)
            table = [null] * num_slots
            for h, p in entries:
                n = (h >> 8) % num_slots
                while table[n] is not null:
                    n = (n + 1) % num_slots
                table[n] = (h, p)
            for h, p in table:
                self.__fp.write(uint32_pack(h) + uint32_pack(p))
                self.__pos += 8

        self.__fp.flush()
        self.__fp.seek(0)
        self.__fp.write(final)

        self.__fp.close()
        self.__fp = None

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
        self.__fp.write(uint32_pack(len(key)) + uint32_pack(len(value)))
        h = cdb_hash(key)
        self.__fp.write(key)
        self.__fp.write(value)
        self.__tables.setdefault(h & 255, []).append((h, self.__pos))
        self.__pos += 8 + len(key) + len(value)

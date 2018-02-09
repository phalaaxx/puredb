puredb
--

PureDB is a pure Python3 library for reading and writing CDB and passwd database files. Its purpose is to make it easy to generate
and read these simple database file formats from Python programs.  

Example usage:

    import puredb
    with purecdb.CdbWriter('test.cdb') as cdb:
        cdb.add('key', 'value')
    ...
    with puredb.CdbReader('test.cdb') as cdb:
        print(cdb.get('key'))
    ...
    with puredb.PasswdWriter('passwd') as pw:
        pw.add(name='test', home='/home/test', uid=1100, gid=1100)
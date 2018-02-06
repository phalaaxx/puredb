purecdb
--

PureCDB is a pure Python3 library for reading and writing CDB database files. Its purpose is to make it easy to generate
and read CDB files from Python programs.  

Example usage:

    import purecdb
    with purecdb.CDBWriter('test.cdb') as cdb:
        cdb.add('key', 'value')
    ...
    with purecdb.CDBReader('test.cdb') as cdb:
        print(cdb.get('key'))
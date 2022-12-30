import pathlib
import zlib
from struct import unpack, pack
from sys import argv


def uncompress(src, dst):
    with src.open('rb') as f:
        header = f.read(4)
        compressed_data = f.read()
        f.close()
    expected_size = unpack('>I', header)[0]
    decompressed_data = zlib.decompress(compressed_data)
    if expected_size != len(decompressed_data):
        print("WARN: size mismatch")
    with dst.open('wb') as f:
        f.write(decompressed_data)
        f.close()


def compress(src, dst):
    with src.open('rb') as f:
        decompressed_data = f.read()
        f.close()
    header = pack('>I', len(decompressed_data))
    compressed_data = zlib.compress(decompressed_data)
    with dst.open('wb') as f:
        f.write(header)
        f.write(compressed_data)
        f.close()


def main():
    if len(argv) > 1:
        outfile = pathlib.Path(argv[2]) if len(argv) > 2 else None
        infile = pathlib.Path(argv[1])
        ext = infile.suffix.lower()
        if ext == '.slc':
            uncompress(infile, outfile or infile.with_suffix('.xml'))
        elif ext == '.xml':
            compress(infile, outfile or infile.with_suffix('.slc'))
        else:
            print('Поддерживаются только файлы .slc и .xml')
    else:
        print(f'Программа для распаковки/упаковки файлов конфигурации Starline')
        print(f'Использование: {pathlib.Path(argv[0]).name} slc|xml [outfile]')


if __name__ == "__main__":
    main()

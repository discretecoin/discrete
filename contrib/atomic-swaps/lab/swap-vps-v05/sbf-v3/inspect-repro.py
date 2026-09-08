"""Read-only ELF comparison for the retained local rebuild artifacts."""
import hashlib
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parent


def describe(path):
    data = path.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01', 'expected ELF64 little-endian'
    offset = struct.unpack_from('<Q', data, 40)[0]
    stride, count, strings_index = struct.unpack_from('<HHH', data, 58)
    raw = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * stride) for i in range(count)]
    string_header = raw[strings_index]
    strings = data[string_header[4]:string_header[4] + string_header[5]]
    sections = {}
    for h in raw:
        name = strings[h[0]:].split(b'\0', 1)[0].decode('ascii')
        if name:
            sections[name] = dict(flags=h[2], address=h[3], offset=h[4], size=h[5],
                                  data=data[h[4]:h[4] + h[5]] if h[1] != 8 else b'')
    return dict(path=str(path.relative_to(ROOT)), bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                elf_flags=struct.unpack_from('<I', data, 48)[0], entrypoint=struct.unpack_from('<Q', data, 24)[0]), sections


def compare(first, second):
    a, sa = describe(first)
    b, sb = describe(second)
    assert sa.keys() == sb.keys(), 'section sets differ'
    result = []
    for name, left in sa.items():
        right = sb[name]
        diffs = [i for i, (x, y) in enumerate(zip(left['data'], right['data'])) if x != y]
        item = dict(name=name, allocatable=bool(left['flags'] & 2), size_a=left['size'], size_b=right['size'],
                    sha256_a=hashlib.sha256(left['data']).hexdigest(), sha256_b=hashlib.sha256(right['data']).hexdigest(),
                    different_bytes=len(diffs) + abs(len(left['data']) - len(right['data'])))
        if name == '.text':
            starts = sorted({i // 8 * 8 for i in diffs})
            item['different_instructions'] = [dict(offset=i, virtual_address=left['address'] + i,
                original=left['data'][i:i+8].hex(), rebuilt=right['data'][i:i+8].hex()) for i in starts]
        result.append(item)
    return dict(original=a, rebuilt=b, whole_elf_identical=a['sha256'] == b['sha256'], sections=result)


if __name__ == '__main__':
    print(json.dumps({name: compare(ROOT / 'solana_escrow.so', ROOT / name /
        'sbpfv3-solana-solana/release/xds_swap_sbpfv3.so') for name in ('target-repro-01', 'target-repro-02')}, indent=2))

import argparse
import hashlib
import io
import json
import os
import struct
import sys
import zipfile
import zlib
import re

## Needs pycryptodome
# pip install pycryptodome

# helper consts
EOCD = b'PK\x05\x06' # End of Central Directory
LFH = b'PK\x03\x04' # Local File Header
CFH_SIG = b'PK\x01\x02' # Central File Header Signature
DEX_MAGIC_BYTES = b'dex\n'

# helper methods (always default to little endian)
def u16(b, o): return int.from_bytes(b[o:o+2], 'little')
def u32(b, o): return int.from_bytes(b[o:o+4], 'little')
def i32(b, o): return int.from_bytes(b[o:o+4], 'little', signed=True)

def error_out_misaligned(dex_idx, rec_idx, method_count, pos, detail):
    raise Exception(f"Parser misaligned at dex[{dex_idx}] record {rec_idx}/{method_count}: pos={pos}, {detail}")

# classes.dex -> 0, classes2.dex -> 1, classesN.dex -> N-1, anything else -> -1
def dex_index(name):
    base = name.rsplit('/', 1)[-1]
    m = re.match(r'classes(\d*)\.dex$', base, re.IGNORECASE)
    if not m:
        return -1
    num = m.group(1)
    return 0 if num == '' else int(num) - 1

# dpt-shell's real dex files live in a zip appended to the (stub) classes.dex,
# with a 4-byte big-endian length trailer at the very end.
def extract_inner_zip(outer_dex):
    n = len(outer_dex)
    if n < 4:
        raise ValueError(f"classes.dex too small to hold an inner zip ({n} bytes)")
    zip_len = int.from_bytes(outer_dex[n - 4:n], 'big')
    if not (0 < zip_len + 4 <= n):
        raise ValueError(f"invalid inner zip length: {zip_len} (classes.dex size {n})")
    start = n - zip_len - 4
    return outer_dex[start:start + zip_len]

def human_size(val):
    if val >= (1024 ** 2): return f"{(val / (1024 ** 2)):.1f} MB"
    elif val >= 1024: return f"{(val / 1024 ):.1f} KB"
    else: return f"{val:.1f} B"


# --- reusable logic adapted from unknown_dump.py (min_vm-independent) --------

def resolve_base_apk(data):
    """If `data` is a .apks/.zip bundle (not common) containing several .apk files (a
    multisplit install set), return the BASE apk's bytes (the one carrying
    classes.dex -- the packer lives there). Plain apks pass through unchanged.
    """
    if not zipfile.is_zipfile(io.BytesIO(data)):
        return data                                    # not a clean zip (or our malformed apk) -> as-is
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        apks = [(n, z.read(n)) for n in z.namelist() if n.lower().endswith('.apk')]
    except Exception:
        return data
    if not apks:
        return data                                    # a zip, but it IS the app
    is_split = lambda n: any(t in os.path.basename(n).lower()
                             for t in ('config.', '.config.', 'split'))
    dexed = [(n, a) for n, a in apks if b'classes.dex' in a]   # cheap check; base carries classes.dex
    pool = dexed or apks
    non_split = [x for x in pool if not is_split(x[0])]
    return max(non_split or pool, key=lambda x: len(x[1]))[1]


def validate_dex(data):
    """Validate a recovered DEX: header, file_size, SHA-1 signature, adler32.
    Returns a dict or None. SHA-1 (bytes 0x0c..0x20 over data[0x20:]) is the
    authoritative check; a zeroed adler is a benign packer artifact (ART recomputes)."""
    if data[:4] != b'dex\n' or len(data) < 0x70:
        return None
    file_size  = struct.unpack_from('<I', data, 0x20)[0]
    class_defs = struct.unpack_from('<I', data, 0x60)[0]
    methods    = struct.unpack_from('<I', data, 0x58)[0]
    adler      = struct.unpack_from('<I', data, 0x08)[0]
    sha_ok = hashlib.sha1(data[0x20:]).digest() == data[0x0c:0x20]
    adler_calc = zlib.adler32(data[12:]) & 0xffffffff
    adler_state = 'ok' if adler == adler_calc else ('packer-nulled' if adler == 0 else 'MISMATCH')
    return dict(size=len(data), file_size_ok=(file_size == len(data)), class_defs=class_defs,
                methods=methods, sha_ok=sha_ok, adler_state=adler_state)


# Is it dex content for dpt_shell? (Is a simplified version, may break, will need TLC later)
def is_dex_content(b):
    if len(b) < 8:
        return False

    version = struct.unpack_from('<H', b, 0)[0]
    n = struct.unpack_from('<H', b, 2)[0]  # dexCount
    return version in (1, 2) \
        and 0 < n <= 256 \
        and len(b) >= 8 + (4 * n) \
        and struct.unpack_from('<I', b, 4)[0] == 4 + (4 * n)


class Log:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def info(self, msg):  print('[*] ' + msg)
    def ok(self, msg):    print('[+] ' + msg)
    def warn(self, msg):  print('[!] ' + msg)
    def err(self, msg):   print('[x] ' + msg)
    def debug(self, msg):
        if self.verbose:
            print('    ' + msg)


class InstructionRecord:
    def __init__(self, method_index, offset_dex_idx, insns_size, insns_data):
        self.method_index = method_index
        self.offset_dex_idx = offset_dex_idx # only used for v1; v2 is always 0
        self.insns_size = insns_size
        self.insns_data = insns_data

    def __eq__(self, other):
        if self is other:
            return True
        if not isinstance(other, InstructionRecord):
            return False
        return self.method_index == other.method_index \
            and self.offset_dex_idx == other.offset_dex_idx \
            and self.insns_size == other.insns_size \
            and self.insns_data == other.insns_data

    def __hash__(self):
        r = self.method_index
        r = 31 * r + self.insns_size
        r = 31 * r + hash(bytes(self.insns_data))
        return r

    def __str__(self):
        return ('io.isaacgc.dpt_extractor.InstructionRecord('
                f'methodIndex={self.method_index}, insnsSize={self.insns_size}, '
                f'offsetDexIdx={self.offset_dex_idx})')


class PatchResult:
    def __init__(self, dex_filename, total_records, patched_count, skipped_count):
        self.dex_filename = dex_filename
        self.total_records = total_records
        self.patched_count = patched_count
        self.skipped_count = skipped_count


class DexCodeBlock:
    def __init__(self, dex_index, records):
        self.dex_index = dex_index
        self.records = records


class SimplifiedZipParser:
    """
    Simplified Zip Parser to bypass common malformed zip file methods

    Reference: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
    """

    def __init__(self, zip_file, logger: Log):
        self.zip_file = zip_file # Most likely an apk, but JIC
        self.data = None
        self.records = []
        self.logger = logger

        try:
            with open(self.zip_file, 'rb') as f:
                self.data = f.read()
        except FileNotFoundError:
            print(f"file {zip_file} not found")

        # If handed a .xapk/.apks/.zip bundle, drop to the base apk (the packer
        # lives there). Plain/malformed apks pass through untouched.
        if self.data:
            base = resolve_base_apk(self.data)
            if base is not self.data:
                self.logger.ok(f"Bundle detected -> using base apk ({human_size(len(base))})")
                self.data = base

        for record in self.__central_dir():
            blob = self.__read_entry_raw_bytes(record)
            if record['method'] == 0: # no DEFLATE
                self.logger.debug("{record['name']} {len(blob)}")
                if record['name'] not in self.records:
                    self.records.append({
                        'name': record['name'],
                        'blob': blob,
                        'record': record,
                    })

            if record['method'] == 8:
                try:
                    self.logger.debug(f"{record['name']} --> Deflated")
                    zblob = zlib.decompress(blob, -15)
                    self.records.append({
                        'name': record['name'],
                        'blob': zblob,
                        'record': record,
                    })
                    # return zlib.decompress(blob, -15)
                except zlib.error as e:
                    # return blob
                    print(e)


    def __central_dir(self):
        eocd = self.data.rfind(EOCD)
        if eocd < 0:
            raise ValueError('no EOCD found -- is this a zip file?')

        cd_off = u32(self.data, eocd + 16) # Central Directory offset
        i = cd_off
        while i + 4 <= eocd and self.data[i:i+4] == CFH_SIG:
            flag = u16(self.data, i + 8)
            nlen = u16(self.data, i + 28)
            elen = u16(self.data, i + 30)
            clen = u16(self.data, i + 32)

            yield {
                'flag': flag & ~0x1, # encrypted?! if so its a liar!
                'method': u16(self.data, i + 10),
                'crc': u32(self.data, i + 16),
                'csize': u32(self.data, i + 20),
                'usize': u32(self.data, i + 24),
                'lho': u32(self.data, i + 42),  # local-header offset
                'name': self.data[i + 46: i + 46 + nlen].decode('latin1'),
            }
            i += 46 + nlen + elen + clen


    def __read_entry_raw_bytes(self, record):
        lho = record['lho']
        if self.data[lho:lho + 4] != LFH:
            print(f"bad local header for {record['name']}")

        l_nlen = u16(self.data, lho + 26)
        l_elen = u16(self.data, lho + 28)
        start = lho + 30 + l_nlen + l_elen
        return self.data[start:(start + record['csize'])]


class DptExtractor:

    def __init__(self, zip_parser: SimplifiedZipParser, logger: Log):
        self.zip_parser = zip_parser
        self.logger = logger
        self.working_data = {
            'dex_classes': []
        }

    ## There should only be one classes.dex
    def __get_classes_dex(self):
        for record in self.zip_parser.records:
            if matched := re.match(r'classes\d{0,2}.dex', record['name'], re.IGNORECASE):
                self.working_data['dex_classes'].append(matched.group(0))
        self.working_data['dex_classes'].sort() # Sort as the zip file may not return in order (or as you would expect)

    def can_walk_v2_block(self, data, block_offset, block_end, layout):
        if block_offset + 2 > len(data):
            return False
        method_count = u16(data, block_offset)
        pos = block_offset + 2  # try to align properly
        for _ in range(method_count):
            if pos + 8 > block_end:
                return False
            if layout == 'METHOD_FIRST':
                size = i32(data, pos + 4)
            else:
                size = i32(data, pos)
            if size < 0:
                return False
            pos += 8 + size
            if pos > block_end:
                return False
        return pos == block_end

    def detect_xor_key(self, blocks):
        freq = [0] * 256  # frequency of every byte value
        total = 0
        for block in blocks:
            for rec in block.records.values():
                for b in rec.insns_data:
                    freq[b] += 1  # bytes iterate as 0..255 already
                    total += 1
        if total < 64:
            return 0
        dominant = max(range(256), key=lambda i: freq[i])
        if dominant != 0 and freq[dominant] * 10 >= total:
            return dominant
        return 0

    def read_block(self, data, block_offset, block_end, dex_idx, version, v2_layout):
        method_count = u16(data, block_offset)
        records = {}
        pos = block_offset + 2

        for it in range(method_count):
            if version == 1:
                if pos + 12 > block_end:
                    error_out_misaligned(dex_idx, it, method_count, pos, 'Header runs past block end')
                method_idx     = i32(data, pos)
                offset_dex_idx = i32(data, pos + 4)
                insns_bytes    = i32(data, pos + 8)
                insns_start    = i32(data, pos + 12)
            else:                                       # V2
                if pos + 8 > block_end:
                    error_out_misaligned(dex_idx, it, method_count, pos, 'Header runs past block end')
                offset_dex_idx = 0
                if v2_layout == 'METHOD_FIRST':
                    method_idx  = i32(data, pos)
                    insns_bytes = i32(data, pos + 4)
                else:                                   # SIZE_FIRST
                    insns_bytes = i32(data, pos)
                    method_idx  = i32(data, pos + 4)
                insns_start = pos + 8

            insns_end = insns_start + insns_bytes
            if insns_bytes < 0 or insns_end > block_end:
                error_out_misaligned(
                    dex_idx, it, method_count, pos,
                    'methodIdx=%d insnsBytes=%d insnsEnd=%d (0x%x) reads past block end '
                    '(insnsEnd=%d, blockEnd=%d)'
                    % (method_idx, insns_bytes, insns_end, insns_bytes, insns_end, block_end))

            records[method_idx] = InstructionRecord(
                method_idx, offset_dex_idx, insns_bytes,
                bytearray(data[insns_start:insns_end]))     # mutable copy
            pos = insns_end

        return records

    def parse(self, data):
        # dex code table is little-endian
        version = u16(data, 0)
        dex_count = u16(data, 2)

        if version != 1 and version != 2:
            self.logger.warn('Unexpected dex file version %d... continuing' % version)  # or print to stderr

        offsets = [i32(data, 4 + i * 4) for i in range(dex_count)]

        # block end = next block's offset, or EOF for the last one
        block_ends = [offsets[i + 1] if i + 1 < dex_count else len(data)
                      for i in range(dex_count)]

        v2_layout = None
        if version == 2:
            first_block = offsets[0]
            first_end = block_ends[0]
            v2_layout = next(
                (lay for lay in ('METHOD_FIRST', 'SIZE_FIRST')
                 if self.can_walk_v2_block(data, first_block, first_end, lay)),
                None)
            if v2_layout is None:
                raise ValueError('Could not detect v2 record layout (blockOffset=%d)' % first_block)

        blocks = []
        for dex_idx in range(dex_count):
            records = self.read_block(data, offsets[dex_idx], block_ends[dex_idx], dex_idx, version, v2_layout)
            blocks.append(DexCodeBlock(dex_idx, records))

        xor_key = self.detect_xor_key(blocks)
        if xor_key != 0:
            self.logger.info('Detected XOR encrypted instructions (key=0x%02x) -> decrypting...' % xor_key)
            for block in blocks:
                for r in block.records.values():
                    d = r.insns_data
                    for i in range(len(d)):
                        d[i] ^= xor_key  # in-place, needs bytearray
        return blocks


class Patcher:
    def __init__(self, original_bytes):
        self.buffer = bytearray(original_bytes)     # mutable copy (== originalBytes.copyOf())
        self._method_map = None                     # lazy cache

    def get_bytes(self):
        return self.buffer

    @property
    def method_to_code_offset(self):
        if self._method_map is None:                # `by lazy { buildMethodMap() }`
            self._method_map = self._build_method_map()
        return self._method_map

    # ====================================================

    def _is_dex(self, data):
        return len(data) >= 4 and data[:4] == DEX_MAGIC_BYTES

    def _read_uleb128(self, pos):
        result = 0
        shift = 0
        cur_pos = pos
        while True:
            b = self.buffer[cur_pos]
            cur_pos += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return result, cur_pos                      # (value, new_pos)

    def _build_method_map(self):
        m = {}
        buf = self.buffer

        # dex header items: https://source.android.com/docs/core/runtime/dex-format#header-item
        class_def_size   = u32(buf, 96)
        class_def_offset = u32(buf, 100)

        for clazz in range(class_def_size):
            base = class_def_offset + clazz * 32
            class_data_off = u32(buf, base + 24)
            if class_data_off == 0:
                continue

            pos = class_data_off
            static_fields_size,   pos = self._read_uleb128(pos)
            instance_fields_size, pos = self._read_uleb128(pos)
            direct_methods_size,  pos = self._read_uleb128(pos)
            virtual_methods_size, pos = self._read_uleb128(pos)

            for _ in range(static_fields_size + instance_fields_size):
                _, pos = self._read_uleb128(pos)    # field_idx_diff
                _, pos = self._read_uleb128(pos)    # access flags

            method_idx = 0
            for _ in range(direct_methods_size):
                delta,       pos = self._read_uleb128(pos); method_idx += delta
                _,           pos = self._read_uleb128(pos)  # access flags
                code_offset, pos = self._read_uleb128(pos)
                if code_offset != 0:                # 0 => method has no code
                    m[method_idx] = code_offset

            method_idx = 0
            for _ in range(virtual_methods_size):
                delta,       pos = self._read_uleb128(pos); method_idx += delta
                _,           pos = self._read_uleb128(pos)  # access flags
                code_offset, pos = self._read_uleb128(pos)
                if code_offset != 0:
                    m[method_idx] = code_offset

        return m

    def apply_block(self, block, dex_file_name):
        num_patched = 0
        num_skipped = 0

        for method_idx, record in block.records.items():
            if record.insns_size == 0:
                num_skipped += 1
                continue

            if record.offset_dex_idx != 0:
                insns_offset = record.offset_dex_idx            # v1
            else:
                code_offset = self.method_to_code_offset.get(method_idx)   # v2
                if code_offset is None:
                    print('[X] Warning -- %s: method %d not found in DEX content'
                          % (dex_file_name, method_idx), file=sys.stderr)
                    num_skipped += 1
                    continue
                insns_offset = code_offset + 16

            insns_end = insns_offset + record.insns_size
            if insns_end > len(self.buffer):
                print('[X] Warning -- %s: method %d insns is out of bounds'
                      % (dex_file_name, method_idx), file=sys.stderr)
                num_skipped += 1
                continue

            self.buffer[insns_offset:insns_end] = record.insns_data   # == copyInto
            num_patched += 1

        return PatchResult(dex_file_name, len(block.records), num_patched, num_skipped)

    def fix_header(self):
        buf = self.buffer
        if len(buf) < 36:
            return

        sha1 = hashlib.sha1(bytes(buf[32:])).digest()   # 20 bytes
        buf[12:32] = sha1                               # signature

        adler = zlib.adler32(buf[12:]) & 0xFFFFFFFF
        buf[8:12] = adler.to_bytes(4, 'little')         # checksum


# ============================================================================
# Fallback path for hardened dpt-shell forks
# ----------------------------------------------------------------------------
# Some forks don't leave a plaintext code table on disk. Instead they:
#   - ship the RC4/AES key as an exported ELF symbol (DPT_*_DATA) in the shell .so
#   - AES-128-CBC encrypt a JSON config asset (key = DPT_*_DATA, IV = generateIV)
#   - store the method bodies in a version-3 code table, XOR-obfuscated
# The config names every renamed asset, the code table, the insns XOR key and the
# runtime output jar.
# ============================================================================

def rc4(key, data):
    """RC4 (used for the .bitcode section; handy for callers)."""
    s = list(range(256)); j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i + 1) & 0xFF; j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


# --- minimal AES-128 (decrypt path, CBC only), pure stdlib -----------------
def _aes_sbox():
    p = q = 1; sbox = [0] * 256
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= (q << 1) & 0xFF; q ^= (q << 2) & 0xFF; q ^= (q << 4) & 0xFF
        q ^= 0x09 if q & 0x80 else 0; q &= 0xFF
        x = q ^ ((q << 1 | q >> 7) & 0xFF) ^ ((q << 2 | q >> 6) & 0xFF) \
              ^ ((q << 3 | q >> 5) & 0xFF) ^ ((q << 4 | q >> 4) & 0xFF)
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox

_SBOX = _aes_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80; a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p

def _aes128_round_keys(key):
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [_SBOX[b] for b in (t[1:] + t[:1])]     # RotWord + SubWord
            t[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    # state is column-major: byte index = row + 4*col
    return [bytes(w[4 * r + c][row] for c in range(4) for row in range(4)) for r in range(11)]

def _inv_shift_rows(s):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c - r) % 4)]
    return out

def _inv_mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        out[4 * c + 0] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
        out[4 * c + 1] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
        out[4 * c + 2] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
        out[4 * c + 3] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)
    return out

def aes128_cbc_decrypt(key, iv, data, strip_pkcs7=True):
    """Decrypt AES-128-CBC. Ignores a trailing partial block."""
    rk = _aes128_round_keys(key)
    out = bytearray(); prev = list(iv)
    for off in range(0, len(data) - (len(data) % 16), 16):
        c = list(data[off:off + 16])
        st = [c[i] ^ rk[10][i] for i in range(16)]
        for r in range(9, 0, -1):
            st = _inv_shift_rows(st)
            st = [_INV_SBOX[b] for b in st]
            st = [st[i] ^ rk[r][i] for i in range(16)]
            st = _inv_mix_columns(st)
        st = _inv_shift_rows(st)
        st = [_INV_SBOX[b] for b in st]
        out += bytes(st[i] ^ rk[0][i] ^ prev[i] for i in range(16))
        prev = c
    if strip_pkcs7 and out:
        pad = out[-1]
        if 1 <= pad <= 16 and all(b == pad for b in out[-pad:]):
            out = out[:-pad]
    return bytes(out)


# --- AES-128 CTR (encrypt path; used for the dex_store container) -----------
def _shift_rows(s):                      # forward: row r rotated LEFT by r
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return out

def _mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        out[4 * c + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
        out[4 * c + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
        out[4 * c + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
        out[4 * c + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
    return out

def _aes128_encrypt_block(block, rk):
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for r in range(1, 10):
        s = _shift_rows([_SBOX[b] for b in s])
        s = _mix_columns(s)
        s = [s[i] ^ rk[r][i] for i in range(16)]
    s = _shift_rows([_SBOX[b] for b in s])
    return bytes(s[i] ^ rk[10][i] for i in range(16))

def aes128_ctr(key, iv12, data, counter=2):
    try:                                                      # 1. pycryptodome
        from Crypto.Cipher import AES as _CAES
        return _CAES.new(key, _CAES.MODE_CTR, nonce=iv12, initial_value=counter).decrypt(data)
    except Exception:
        pass
    try:                                                      # 2. openssl CLI
        import shutil, subprocess
        if shutil.which('openssl'):
            iv = (iv12 + counter.to_bytes(4, 'big')).hex()
            p = subprocess.run(['openssl', 'enc', '-aes-128-ctr', '-K', key.hex(), '-iv', iv],
                               input=data, capture_output=True)
            if p.returncode == 0 and len(p.stdout) == len(data):
                return p.stdout
    except Exception:
        pass
    return _aes128_ctr_py(key, iv12, data, counter)           # 3. pure-Python fallback


def decrypt_dex_store(stub_dex, key):
    """Decrypt the dex_store jar appended (unaligned) to the stub classes.dex.

    Layout at data_off+data_size (DEX header @0x68/0x6c): [12-byte IV][AES-128-CTR
    ciphertext][GCM tag + some random 4 byte trailer]. Counter starts at 2 (GCM J0=IV||1 is the
    tag); key = DPT_KEY_DATA. We only need CTR confidentiality; the tag is integrity.
    """
    start = u32(stub_dex, 0x68) + u32(stub_dex, 0x6c)          # data_size + data_off
    blob = bytes(stub_dex[start:])
    dec = aes128_ctr(key, blob[:12], blob[12:], counter=2)
    eocd = dec.rfind(b'PK\x05\x06')                            # bound the jar; drop tag+(random 4 byte trailer)
    if eocd >= 0:
        clen = struct.unpack_from('<H', dec, eocd + 20)[0]
        dec = dec[:eocd + 22 + clen]
    return dec


def generate_iv(key):
    """dpt-shell KeyUtils.generateIV: copy the key, set byte 3=0x2f, byte 9=0x76."""
    iv = bytearray(key[:16]); iv[3] = 0x2F; iv[9] = 0x76
    return bytes(iv)


def read_shell_key(elf):
    """Return the 16-byte RC4/AES key from an exported DPT_*_DATA object symbol
    in the shell .so, or None.
    """
    if elf[:4] != b'\x7fELF' or elf[4] != 2:            # 64-bit little-endian ELF
        return None
    du16 = lambda o: int.from_bytes(elf[o:o + 2], 'little')
    du32 = lambda o: int.from_bytes(elf[o:o + 4], 'little')
    du64 = lambda o: int.from_bytes(elf[o:o + 8], 'little')
    e_shoff, e_shent, e_shnum, e_shstr = du64(0x28), du16(0x3A), du16(0x3C), du16(0x3E)
    secs = []
    for i in range(e_shnum):
        b = e_shoff + i * e_shent
        secs.append(dict(name=du32(b), type=du32(b + 4), addr=du64(b + 0x10),
                         off=du64(b + 0x18), size=du64(b + 0x20)))
    if e_shstr >= len(secs):
        return None
    shstr = secs[e_shstr]['off']
    sname = lambda n: elf[shstr + n:elf.index(b'\0', shstr + n)].decode('latin1')
    dynsym = next((s for s in secs if sname(s['name']) == '.dynsym'), None)
    dynstr = next((s for s in secs if sname(s['name']) == '.dynstr'), None)
    if not dynsym or not dynstr:
        return None
    def va2off(va):
        for s in secs:
            if s['addr'] and s['addr'] <= va < s['addr'] + s['size'] and s['type'] != 8:  # not NOBITS
                return s['off'] + (va - s['addr'])
        return None
    for i in range(dynsym['size'] // 24):
        b = dynsym['off'] + i * 24
        nameoff, value, size = du32(b), du64(b + 8), du64(b + 16)
        if value == 0 or size < 16:
            continue
        nm = elf[dynstr['off'] + nameoff:elf.index(b'\0', dynstr['off'] + nameoff)].decode('latin1')
        if re.fullmatch(r'DPT_[A-Z0-9_]*DATA', nm):
            off = va2off(value)
            if off is not None:
                return elf[off:off + 16]
    return None


class ConfigVariantExtractor:
    def __init__(self, zip_parser: SimplifiedZipParser, logger: Log):
        self.zip = zip_parser
        self.logger = logger

    def _asset(self, name):
        return next((r['blob'] for r in self.zip.records if r['name'] == name), None)

    def find_key(self):
        for r in self.zip.records:
            blob = r['blob']
            if blob[:4] != b'\x7fELF':
                continue
            key = read_shell_key(blob)
            if key:
                self.logger.ok(f"Recovered shell key from {r['name']}: {key.hex()}")
                return key
        return None

    def decrypt_config(self, key):
        iv = generate_iv(key)
        for r in self.zip.records:
            blob = r['blob']
            if not r['name'].startswith('assets/') or len(blob) < 16 or len(blob) % 16 or len(blob) > 0x10000:
                continue
            try:
                dec = aes128_cbc_decrypt(key, iv, blob)
                if dec[:1] == b'{':
                    cfg = json.loads(dec)
                    self.logger.ok(f"Decrypted shell config: {r['name']}")
                    return cfg
            except Exception:
                continue
        return None

    def parse_v3_table(self, data, xor_key):
        helper = DptExtractor(self.zip, self.logger)     # reuse can_walk / read_block
        version = u16(data, 0); dex_count = u16(data, 2)
        offsets = [u32(data, 4 + 4 * i) for i in range(dex_count)]
        ends = [offsets[i + 1] if i + 1 < dex_count else len(data) for i in range(dex_count)]
        layout = next((l for l in ('METHOD_FIRST', 'SIZE_FIRST')
                       if helper.can_walk_v2_block(data, offsets[0], ends[0], l)), 'METHOD_FIRST')
        blocks = []
        for di in range(dex_count):
            try:
                recs = helper.read_block(data, offsets[di], ends[di], di, 2, layout)  # v2 record layout == v3
            except Exception as e:
                self.logger.warn(f"code block {di} failed to walk fully: {e}")
                continue
            for rec in recs.values():
                d = rec.insns_data
                for i in range(len(d)):
                    d[i] ^= xor_key[i & 3]
            blocks.append(DexCodeBlock(di, recs))
        return blocks, layout, version

    def run(self, output_dir):
        key = self.find_key()
        if not key:
            self.logger.err("No shell key symbol (DPT_*_DATA) found in any asset ELF")
            return False
        cfg = self.decrypt_config(key)
        if not cfg:
            self.logger.err("No AES-CBC config asset could be decrypted with that key")
            return False

        names = cfg.get('runtime_names', {})
        code_asset = names.get('code_item_asset')
        xv = cfg.get('insns_xor_key', 0)
        xor_key = struct.pack('<i', xv) if isinstance(xv, int) else b'\x00\x00\x00\x00'
        self.logger.ok(f"target_package : {cfg.get('target_package')}")
        self.logger.ok(f"runtime jar    : {names.get('dex_store')}  (dropped at runtime)")
        self.logger.ok(f"code_item_asset: {code_asset}")
        self.logger.ok(f"insns_xor_key  : 0x{int.from_bytes(xor_key, 'little'):08x}")
        self.logger.ok(f"container_magic: {names.get('container_magic') or cfg.get('container_magic')}")

        os.makedirs(output_dir, exist_ok=True)
        with open(os.path.join(output_dir, 'shell_config.json'), 'w') as f:
            json.dump(cfg, f, indent=2)
        self.logger.info(f"\tSaved: {os.path.join(output_dir, 'shell_config.json')}")

        table = self._asset(f"assets/{code_asset}") if code_asset else None
        if table is None:                                 # heuristic fallback: scan for a v3 table
            table = next((r['blob'] for r in self.zip.records
                          if len(r['blob']) > 8 and u16(r['blob'], 0) in (2, 3)
                          and 0 < u16(r['blob'], 2) <= 256), None)
        if table is None:
            self.logger.err("code-item table asset not found")
            return False

        blocks, layout, version = self.parse_v3_table(table, xor_key)
        self.logger.ok(f"Parsed v{version} code table ({layout}): {len(blocks)} dex block(s)")
        for b in blocks:
            nbytes = sum(r.insns_size for r in b.records.values())
            self.logger.info(f"\tdex[{b.dex_index}]: {len(b.records)} method bodies, {human_size(nbytes)} insns")
        block_map = {b.dex_index: b for b in blocks}

        shells = self._get_hollow_dexes(key)
        if shells:
            self.logger.ok(f"Recovered dex_store jar -> {len(shells)} hollow dex(es): "
                           f"{', '.join(e['name'] for e in shells)}")
            self._reconstruct(shells, block_map, output_dir)
        else:
            self._dump_bodies(blocks, output_dir)
            self.logger.warn("Could not recover the hollow dex shells (dex_store decrypt failed).")
            self.logger.warn(f"Method bodies were recovered above; pull '{names.get('dex_store')}'")
            self.logger.warn("from the app's private dir at runtime for the complete dex.")
        self.logger.ok(f"Output: {os.path.abspath(output_dir)}")
        return True

    def _get_hollow_dexes(self, key):
        stub = self._asset('classes.dex')
        if stub is None:
            return None
        for source in ('dex_store', 'inner_zip'):
            try:
                if source == 'dex_store':
                    blob = decrypt_dex_store(stub, key)
                else:
                    blob = extract_inner_zip(stub)
                entries = []
                with zipfile.ZipFile(io.BytesIO(blob)) as z:
                    for info in z.infolist():
                        if dex_index(info.filename) >= 0:
                            entries.append({'name': info.filename, 'blob': z.read(info.filename)})
                if entries:
                    return sorted(entries, key=lambda e: dex_index(e['name']))
            except Exception as e:
                self.logger.debug(f"{source} sourcing failed: {e}")
        return None

    def _reconstruct(self, shells, block_map, output_dir):
        for entry in shells:
            idx = dex_index(entry['name'])
            patcher = Patcher(entry['blob'])
            block = block_map.get(idx)
            if block is not None:
                res = patcher.apply_block(block, entry['name'])
                self.logger.ok(f"{entry['name']} (idx={idx}) -> {res.patched_count}/{res.total_records} patched")
            patcher.fix_header()
            out = os.path.join(output_dir, entry['name'].rsplit('/', 1)[-1])
            out_bytes = patcher.get_bytes()
            with open(out, 'wb') as f:
                f.write(out_bytes)
            info = validate_dex(bytes(out_bytes))
            vnote = f" [{'sha1 OK' if info['sha_ok'] else 'sha1 FAIL'}]" if info else ""
            self.logger.info(f"\tSaved: {out}{vnote}")

    def _dump_bodies(self, blocks, output_dir):
        for b in blocks:
            path = os.path.join(output_dir, f"dex{b.dex_index}_method_bodies.bin")
            with open(path, 'wb') as f:
                for midx in sorted(b.records):
                    rec = b.records[midx]
                    f.write(struct.pack('<II', rec.method_index, rec.insns_size))
                    f.write(rec.insns_data)
            self.logger.info(f"\tSaved de-obfuscated bodies: {path} ({len(b.records)} methods)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='file to decrypt (apk)')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose output')
    parser.add_argument('-o', '--output', default='out', help='output directory (default: out)')

    args = parser.parse_args()
    logger = Log(verbose=args.verbose)

    logger.info(f"Opening {args.file}")
    zip_parser = SimplifiedZipParser(args.file, logger=logger)
    if not zip_parser.data:
        logger.err(f"could not read {args.file}")
        sys.exit(1)

    extractor = DptExtractor(zip_parser, logger)

    # 1. Locate + parse the packed code table (the dpt-shell "OoooooOooo"
    #    equivalent). Its name can be randomized and the method is_dex_content
    #    is only a heuristic, so we try every candidate and keep the first that
    #    actually parses cleanly.
    packed, blocks = None, None
    for r in zip_parser.records:
        if not is_dex_content(r['blob']):
            continue
        try:
            blocks = extractor.parse(r['blob'])
            packed = r
            break
        except Exception as e:
            logger.debug(f"{r['name']} matched the table heuristic but failed to parse: {e}")

    if blocks is None:
        logger.warn("No plaintext dpt-shell table found -- trying hardened-fork fallback (config-based)")
        if ConfigVariantExtractor(zip_parser, logger).run(args.output):
            return
        logger.err("Fallback failed too. See docs/dpt-shell-runtime-variant.md")
        sys.exit(1)
    logger.ok(f"Found packed dex code table: {packed['name']} ({human_size(len(packed['blob']))})")

    # 2. Index the parsed blocks by dex slot.
    block_map = {b.dex_index: b for b in blocks}
    logger.info(f"Packed table covers {len(blocks)} dex slot(s):")
    for b in blocks:
        name = 'classes.dex' if b.dex_index == 0 else f'classes{b.dex_index + 1}.dex'
        nbytes = sum(r.insns_size for r in b.records.values())
        logger.info(f"\tdex[{b.dex_index}] ({name}): {len(b.records)} methods, {human_size(nbytes)} insns")

    # 3. The APK's classes.dex is only a loader stub -- the real dex files are in
    #    a (clean) zip appended to it. Pull them out and order by dex index.
    outer = next((r['blob'] for r in zip_parser.records if r['name'] == 'classes.dex'), None)
    if outer is None:
        logger.err("classes.dex not found in the APK")
        sys.exit(1)
    inner_zip = extract_inner_zip(outer)

    dex_entries = []
    with zipfile.ZipFile(io.BytesIO(inner_zip)) as z:
        for info in z.infolist():
            if dex_index(info.filename) >= 0:
                dex_entries.append({'name': info.filename, 'blob': z.read(info.filename)})
    dex_entries.sort(key=lambda e: dex_index(e['name']))
    if not dex_entries:
        logger.err("No classes*.dex entries found in the inner zip")
        sys.exit(1)
    logger.ok(f"Found {len(dex_entries)} dex file(s) to restore")

    # 4. Patch each dex with its block, fix the header, and write it out.
    os.makedirs(args.output, exist_ok=True)
    results = []
    for entry in dex_entries:
        idx = dex_index(entry['name'])
        block = block_map.get(idx)
        patcher = Patcher(entry['blob'])

        if block is not None:
            result = patcher.apply_block(block, entry['name'])
            extra = f" ({result.skipped_count} skipped)" if result.skipped_count else ""
            logger.ok(f"{entry['name']} (idx={idx}) {human_size(len(entry['blob']))} -> "
                      f"{result.patched_count}/{result.total_records} patched{extra}")
        else:
            result = PatchResult(entry['name'], 0, 0, 0)
            logger.warn(f"{entry['name']} (idx={idx}) -> no matching block, writing unmodified")

        patcher.fix_header()
        out_name = entry['name'].rsplit('/', 1)[-1]
        out_path = os.path.join(args.output, out_name)
        out_bytes = patcher.get_bytes()
        with open(out_path, 'wb') as f:
            f.write(out_bytes)
        info = validate_dex(bytes(out_bytes))
        vnote = ""
        if info:
            vnote = f" [{'sha1 OK' if info['sha_ok'] else 'sha1 FAIL'}" + \
                    (f", adler {info['adler_state']}" if info['adler_state'] != 'ok' else "") + "]"
        logger.info(f"\tSaved: {out_path} ({human_size(len(out_bytes))}){vnote}")
        results.append(result)

    # 5. Summary.
    total = sum(r.patched_count for r in results)
    logger.info("=== Summary ===")
    for r in results:
        if r.total_records > 0:
            pct = (r.patched_count * 100) // r.total_records
            logger.info(f"\t{r.dex_filename}: {r.patched_count}/{r.total_records} methods restored ({pct}%)")
        else:
            logger.info(f"\t{r.dex_filename}: no patches needed or applied")
    logger.ok(f"{total} total patches applied")
    logger.ok(f"Output: {os.path.abspath(args.output)}")


if __name__ == '__main__':
    main()
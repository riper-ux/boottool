#!/usr/bin/env python3
"""
boottool.py — утилита для работы с Zynq-7000 BOOT.bin

Режимы:
  --read   <BOOT.bin>
      Парсит BOOT.bin и выводит все метаданные.

  --switch <index> <new_file> <BOOT.bin>
      Заменяет раздел с указанным индексом.
      Тип файла определяется по расширению:
        .elf  — парсится, извлекаются PT_LOAD-сегменты, обновляются
                destination_load_address = min(p_paddr),
                destination_exec_address = e_entry
        .bit  — отрезается заголовок, остаётся чистый bitstream,
                устанавливается attribute_bits с dev=PL
        .raw  — принимается как есть, метаданные не трогаются
      Иные расширения — ошибка.

  --unpack <out_dir> <BOOT.bin>
      Распаковывает BOOT.bin в out_dir (partN.raw + manifest.json).

  --pack   <manifest.json> <out_BOOT.bin>
      Собирает BOOT.bin по манифесту.
"""

import sys
import os
import json
import struct


# =====================================================================
# Низкоуровневые утилиты
# =====================================================================

def bytes_to_words(data):
    if len(data) % 4:
        data += b'\x00' * (4 - len(data) % 4)
    words = []
    for i in range(0, len(data), 4):
        words.append(data[i] | (data[i+1] << 8) |
                     (data[i+2] << 16) | (data[i+3] << 24))
    return words


def words_to_bytes(words):
    out = bytearray()
    for w in words:
        out += (w & 0xFFFFFFFF).to_bytes(4, 'little')
    return bytes(out)


def align_up(n, a):
    return ((n + a - 1) // a) * a


def attr_decode(attr):
    owner = (attr >> 16) & 0x3
    rsa   = (attr >> 15) & 0x1
    cksum = (attr >> 12) & 0x7
    dev   = (attr >> 4)  & 0xF
    last  = (attr >> 0)  & 0x1
    return {
        'partition_owner':    {0: 'FSBL', 1: 'U-Boot'}.get(owner, f'Res({owner})'),
        'rsa_signature':      'Yes' if rsa else 'No',
        'checksum_type':      {0: 'None', 1: 'MD5'}.get(cksum, f'Res({cksum})'),
        'destination_device': {0: 'None', 1: 'PS', 2: 'PL'}.get(dev, f'Res({dev})'),
        'last_partition':     'Yes' if last else 'No',
    }


def attr_set_device(attr, dev):
    """Устанавливает биты device (7:4) и сбрасывает owner/rsa/checksum/last."""
    return (attr & ~0xFF) | ((dev & 0xF) << 4)


def partition_checksum(fields15):
    s = 0
    for v in fields15:
        s = (s + v) & 0xFFFFFFFF
    return s ^ 0xFFFFFFFF


def boot_header_checksum(words_0x20_to_0x44):
    s = 0
    for v in words_0x20_to_0x44:
        s = (s + v) & 0xFFFFFFFF
    return s ^ 0xFFFFFFFF


# =====================================================================
# Парсеры ELF и BIT
# =====================================================================

def parse_elf(raw):
    """
    Парсит 32-битный LE ELF. Возвращает {'entry', 'segments': [...]} или None.
    """
    if len(raw) < 52 or raw[:4] != b'\x7fELF':
        return None
    if raw[4] != 1 or raw[5] != 1:  # 32-bit, little-endian
        return None
    try:
        (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
         e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
            struct.unpack_from('<HHIIIIIHHHHHH', raw, 16)
    except struct.error:
        return None

    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(raw) or e_phentsize < 32:
            break
        try:
            (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz,
             p_flags, p_align) = struct.unpack_from('<IIIIIIII', raw, off)
        except struct.error:
            break
        if p_type == 1:  # PT_LOAD
            segments.append({
                'offset': p_offset,
                'vaddr':  p_vaddr,
                'paddr':  p_paddr,
                'filesz': p_filesz,
                'memsz':  p_memsz,
            })
    return {'entry': e_entry, 'machine': e_machine, 'segments': segments}


def elf_to_raw(raw):
    """
    Извлекает PT_LOAD-сегменты и склеивает их с учётом p_paddr.
    Возвращает (raw_data, load_addr, exec_addr) или None.
    """
    info = parse_elf(raw)
    if info is None or not info['segments']:
        return None
    segs = info['segments']
    base = min(s['paddr'] for s in segs)

    # Сортируем по p_paddr и укладываем с заполнением дырок нулями
    segs_sorted = sorted(segs, key=lambda s: s['paddr'])
    out = bytearray()
    cursor = 0
    for s in segs_sorted:
        delta = s['paddr'] - base
        if delta > cursor:
            out += b'\x00' * (delta - cursor)
            cursor = delta
        elif delta < cursor:
            # Перекрытие — пропускаем этот сегмент, чтобы не портить раскладку
            continue
        chunk = raw[s['offset']:s['offset'] + s['filesz']]
        out += chunk
        cursor += len(chunk)
        if s['memsz'] > s['filesz']:
            out += b'\x00' * (s['memsz'] - s['filesz'])
            cursor += (s['memsz'] - s['filesz'])
    return bytes(out), base, info['entry']


def strip_bit_header(raw):
    """
    Извлекает чистый bitstream из .bit файла.
    Формат: 13 байт служебного заголовка, затем поля a/b/c/d (1-байтовый
    ключ + 2-байтовая BE-длина + данные), затем 'e' (1 байт + 4-байтовая
    BE-длина) + сырые данные bitstream.
    Возвращает bytes или None.
    """
    if len(raw) < 13:
        return None
    if raw[0:2] != b'\x00\x09':
        return None
    pos = 13
    while pos < len(raw):
        key = raw[pos]
        if key == ord('e'):
            if pos + 5 > len(raw):
                return None
            data_len = struct.unpack_from('>I', raw, pos + 1)[0]
            pos += 5
            if pos + data_len > len(raw):
                return None
            return raw[pos:pos + data_len]
        elif key in (ord('a'), ord('b'), ord('c'), ord('d')):
            if pos + 3 > len(raw):
                return None
            field_len = struct.unpack_from('>H', raw, pos + 1)[0]
            pos += 3 + field_len
        else:
            return None
    return None


# =====================================================================
# Парсер BOOT.bin
# =====================================================================

class BootImage:
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.raw = f.read()
        self.words = bytes_to_words(self.raw)
        self.total_bytes = len(self.raw)
        self.boot_header = {}
        self.image_headers = []
        self.partition_headers = []
        self.error = None

    def w(self, idx):
        return self.words[idx] if 0 <= idx < len(self.words) else 0

    def parse(self):
        bh = {
            'width_detection':               self.w(0x20 // 4),
            'image_identification':          self.w(0x24 // 4),
            'encryption_status':             self.w(0x28 // 4),
            'user_field_0':                  self.w(0x2C // 4),
            'user_field_1':                  self.w(0x30 // 4),
            'user_field_2':                  self.w(0x34 // 4),
            'user_field_3':                  self.w(0x38 // 4),
            'user_field_4':                  self.w(0x3C // 4),
            'user_field_5':                  self.w(0x40 // 4),
            'user_field_6':                  self.w(0x44 // 4),
            'user_field_7':                  self.w(0x48 // 4),
            'image_header_table_offset':     self.w(0x98 // 4),
            'partition_header_table_offset': self.w(0x9C // 4),
            'field_0xA0':                    self.w(0xA0 // 4),
            'field_0xA4':                    self.w(0xA4 // 4),
            'field_0xA8':                    self.w(0xA8 // 4),
            'field_0xAC':                    self.w(0xAC // 4),
        }
        self.boot_header = bh

        if bh['image_identification'] != 0x584C4E58:
            self.error = f'Сигнатура не XLNX: 0x{bh["image_identification"]:08X}'
            return False

        iht_byte = bh['image_header_table_offset']
        pht_byte = bh['partition_header_table_offset']
        if iht_byte == 0 or pht_byte == 0 or iht_byte >= self.total_bytes:
            self.error = 'Некорректные смещения таблиц'
            return False

        iht_w = iht_byte // 4
        self.image_headers.append({
            'iht_version':      self.w(iht_w + 0),
            'partition_count':  self.w(iht_w + 1),
            'pht_offset_words': self.w(iht_w + 2),
            'extra_offset':     self.w(iht_w + 3),
        })

        count = self.image_headers[0]['partition_count']
        if count == 0 or count > 32:
            self.error = f'Некорректный partition_count={count}'
            return False

        pht_w = pht_byte // 4
        for i in range(count):
            wbase = pht_w + i * 16
            f = [self.w(wbase + j) for j in range(16)]
            self.partition_headers.append({
                'encrypted_partition_length':   f[0],
                'unencrypted_partition_length': f[1],
                'total_partition_word_length':  f[2],
                'destination_load_address':     f[3],
                'destination_exec_address':     f[4],
                'data_word_offset_in_image':    f[5],
                'attribute_bits':               f[6],
                'section_count':                f[7],
                'checksum_word_offset':         f[8],
                'image_header_word_offset':     f[9],
                'auth_cert_word_offset':        f[10],
                'reserved_0':                   f[11],
                'reserved_1':                   f[12],
                'reserved_2':                   f[13],
                'reserved_3':                   f[14],
                'header_checksum':              f[15],
            })
        return True

    def extract_partition_raw(self, index):
        hdr = self.partition_headers[index]
        start_w = hdr['data_word_offset_in_image']
        n_words = hdr['unencrypted_partition_length']
        out = bytearray()
        for i in range(n_words):
            out += self.w(start_w + i).to_bytes(4, 'little')
        return bytes(out)

    def verify_partition_checksum(self, index):
        hdr = self.partition_headers[index]
        fields = [
            hdr['encrypted_partition_length'],
            hdr['unencrypted_partition_length'],
            hdr['total_partition_word_length'],
            hdr['destination_load_address'],
            hdr['destination_exec_address'],
            hdr['data_word_offset_in_image'],
            hdr['attribute_bits'],
            hdr['section_count'],
            hdr['checksum_word_offset'],
            hdr['image_header_word_offset'],
            hdr['auth_cert_word_offset'],
            hdr['reserved_0'],
            hdr['reserved_1'],
            hdr['reserved_2'],
            hdr['reserved_3'],
        ]
        expected = partition_checksum(fields)
        return expected == hdr['header_checksum'], expected


# =====================================================================
# --read
# =====================================================================

def cmd_read(bin_path):
    if not os.path.isfile(bin_path):
        print(f'[!] Файл не найден: {bin_path}')
        return 1

    img = BootImage(bin_path)
    if not img.parse():
        print(f'[!] Ошибка парсинга: {img.error}')
        return 2

    print('=' * 64)
    print(f'BOOT.bin: {bin_path}')
    print(f'Размер:   {img.total_bytes} байт')
    print('=' * 64)

    print('\n--- BOOT HEADER ---')
    for k, v in img.boot_header.items():
        print(f'  {k:32s} = 0x{v:08X}')

    uf = [img.boot_header[k] for k in
          ('width_detection', 'image_identification', 'encryption_status',
           'user_field_0', 'user_field_1', 'user_field_2', 'user_field_3',
           'user_field_4', 'user_field_5', 'user_field_6')]
    expected_bh = boot_header_checksum(uf)
    ok_bh = expected_bh == img.boot_header['user_field_7']
    print(f'  Boot Header checksum: computed=0x{expected_bh:08X}, '
          f'stored=0x{img.boot_header["user_field_7"]:08X}  '
          f'[{"OK" if ok_bh else "MISMATCH"}]')

    print('\n--- IMAGE HEADER TABLE ---')
    for h in img.image_headers:
        for k, v in h.items():
            print(f'  {k:20s} = 0x{v:08X}')

    print('\n--- PARTITION HEADERS ---')
    for i, h in enumerate(img.partition_headers):
        print(f'\nPartition #{i}:')
        words_n = h['unencrypted_partition_length']
        print(f'  unencrypted_partition_length  = 0x{words_n:08X} '
              f'({words_n} слов = {words_n * 4} байт)')
        print(f'  total_partition_word_length   = 0x{h["total_partition_word_length"]:08X}')
        print(f'  destination_load_address      = 0x{h["destination_load_address"]:08X}')
        print(f'  destination_exec_address      = 0x{h["destination_exec_address"]:08X}')
        print(f'  data_word_offset_in_image     = 0x{h["data_word_offset_in_image"]:08X}')
        print(f'  attribute_bits                = 0x{h["attribute_bits"]:08X}')
        for ak, av in attr_decode(h['attribute_bits']).items():
            print(f'    -> {ak:26s} = {av}')
        print(f'  section_count                 = {h["section_count"]}')
        ok, computed = img.verify_partition_checksum(i)
        status = 'OK' if ok else f'MISMATCH (computed=0x{computed:08X})'
        print(f'  header_checksum               = 0x{h["header_checksum"]:08X}  [{status}]')
    return 0


# =====================================================================
# Общие куски
# =====================================================================

def _pad_raw(raw):
    pad = (4 - len(raw) % 4) % 4
    if pad:
        raw += b'\x00' * pad
    return raw


def _extract_paddings(img):
    paddings = []
    n = len(img.partition_headers)
    for i, hdr in enumerate(img.partition_headers):
        start = hdr['data_word_offset_in_image'] * 4
        raw_size = hdr['unencrypted_partition_length'] * 4
        end = start + raw_size
        if i < n - 1:
            next_start = img.partition_headers[i + 1]['data_word_offset_in_image'] * 4
        else:
            next_start = img.total_bytes
        if next_start < end:
            next_start = end
        paddings.append(img.raw[end:next_start])
    return paddings


def _update_boot_header_fsbl_size(boot_hdr_bytes, new_fsbl_size):
    words = bytes_to_words(boot_hdr_bytes)
    orig = words[0x34 // 4]
    if orig == new_fsbl_size:
        return boot_hdr_bytes, False
    words[0x34 // 4] = new_fsbl_size
    words[0x40 // 4] = new_fsbl_size
    uf = [words[0x20 // 4 + j] for j in range(10)]
    words[0x48 // 4] = boot_header_checksum(uf)
    return words_to_bytes(words), True


def _build_pht(raws, metas, orig_sizes, paddings, first_part_byte):
    n = len(raws)
    offsets_w = []
    current_w = first_part_byte // 4
    for i, raw in enumerate(raws):
        offsets_w.append(current_w)
        current_w += len(raw) // 4
        if i < n - 1:
            if len(raw) == orig_sizes[i] and i < len(paddings):
                current_w += len(paddings[i]) // 4
            else:
                current_w = align_up(current_w * 4, 64) // 4

    pht_words = []
    for i, raw in enumerate(raws):
        m = metas[i]
        raw_w = len(raw) // 4
        fields15 = [
            m.get('encrypted_partition_length', 0),
            raw_w,
            raw_w,
            m['destination_load_address'],
            m['destination_exec_address'],
            offsets_w[i],
            m['attribute_bits'],
            m.get('section_count', 1),
            m.get('checksum_word_offset', 0),
            m.get('image_header_word_offset', 0),
            m.get('auth_cert_word_offset', 0),
            m.get('reserved_0', 0),
            m.get('reserved_1', 0),
            m.get('reserved_2', 0),
            m.get('reserved_3', 0),
        ]
        pht_words.extend(fields15)
        pht_words.append(partition_checksum(fields15))

    return pht_words, offsets_w


def _assemble(boot_hdr, iht_region, pht_bytes, post_pht,
              raws, orig_sizes, paddings):
    out = bytearray()
    out += boot_hdr
    out += iht_region
    out += pht_bytes
    out += post_pht
    n = len(raws)
    for i, raw in enumerate(raws):
        out += raw
        if i < n - 1:
            if len(raw) == orig_sizes[i] and i < len(paddings):
                out += paddings[i]
            else:
                while len(out) % 64:
                    out += b'\x00'
        else:
            if len(raw) == orig_sizes[i] and i < len(paddings):
                out += paddings[i]
    return bytes(out)


# =====================================================================
# --switch
# =====================================================================

def _prepare_switch_payload(new_file):
    """
    Возвращает (raw_data, meta_overrides) или (None, error_message).
    meta_overrides: словарь с переопределениями полей PHT.
    """
    ext = os.path.splitext(new_file)[1].lower()

    with open(new_file, 'rb') as f:
        file_content = f.read()

    if ext == '.elf':
        result = elf_to_raw(file_content)
        if result is None:
            return None, 'не удалось распарсить ELF (ожидался 32-bit LE ELF)'
        new_raw, load_addr, exec_addr = result
        meta = {
            'destination_load_address': load_addr,
            'destination_exec_address': exec_addr,
        }
        print(f'[i] ELF разобран:')
        print(f'    entry (exec_addr)   = 0x{exec_addr:08X}')
        print(f'    load_addr (min paddr) = 0x{load_addr:08X}')
        print(f'    размер raw данных    = {len(new_raw)} байт')
        return new_raw, meta

    if ext == '.bit':
        new_raw = strip_bit_header(file_content)
        if new_raw is None:
            return None, 'не удалось распарсить .bit (нет сигнатуры 0x0009 или поля "e")'
        print(f'[i] BIT разобран:')
        print(f'    исходный размер      = {len(file_content)} байт')
        print(f'    размер bitstream     = {len(new_raw)} байт')
        print(f'    отрезано заголовка   = {len(file_content) - len(new_raw)} байт')
        return new_raw, {'_set_device_pl': True}

    if ext == '.raw':
        print(f'[i] RAW принят как есть: {len(file_content)} байт, '
              f'метаданные не изменяются')
        return file_content, {}

    return None, f'неизвестное расширение "{ext}" (поддерживаются .elf, .bit, .raw)'


def cmd_switch(index_str, new_file, bin_path):
    try:
        index = int(index_str)
    except ValueError:
        print(f'[!] Номер раздела должен быть числом: {index_str}')
        return 1

    if not os.path.isfile(bin_path):
        print(f'[!] BOOT.bin не найден: {bin_path}')
        return 2
    if not os.path.isfile(new_file):
        print(f'[!] Новый файл не найден: {new_file}')
        return 3

    img = BootImage(bin_path)
    if not img.parse():
        print(f'[!] Ошибка парсинга: {img.error}')
        return 4

    n = len(img.partition_headers)
    if index < 0 or index >= n:
        print(f'[!] Индекс {index} вне диапазона [0, {n-1}]')
        return 5

    print(f'[i] Замена раздела #{index} файлом {new_file}')

    # Готовим данные и метаданные с учётом типа файла
    payload, meta = _prepare_switch_payload(new_file)
    if payload is None:
        print(f'[!] {meta}')
        return 6

    new_raw = _pad_raw(payload)

    # Собираем обновлённые метаданные для этого раздела
    old_hdr = img.partition_headers[index]
    new_meta = dict(old_hdr)
    new_meta['destination_load_address'] = meta.get(
        'destination_load_address', old_hdr['destination_load_address'])
    new_meta['destination_exec_address'] = meta.get(
        'destination_exec_address', old_hdr['destination_exec_address'])

    if meta.get('_set_device_pl'):
        new_meta['attribute_bits'] = attr_set_device(old_hdr['attribute_bits'], 2)

    # Пересобираем список raws и metas
    raws = [_pad_raw(img.extract_partition_raw(i)) for i in range(n)]
    orig_sizes = [h['unencrypted_partition_length'] * 4 for h in img.partition_headers]
    paddings = _extract_paddings(img)

    print(f'    старый размер: {len(raws[index])} байт')
    print(f'    новый размер:  {len(new_raw)} байт '
          f'({len(new_raw) - len(raws[index]):+d})')
    print(f'    load_addr:     0x{old_hdr["destination_load_address"]:08X} → '
          f'0x{new_meta["destination_load_address"]:08X}')
    print(f'    exec_addr:     0x{old_hdr["destination_exec_address"]:08X} → '
          f'0x{new_meta["destination_exec_address"]:08X}')
    print(f'    attr_bits:     0x{old_hdr["attribute_bits"]:08X} → '
          f'0x{new_meta["attribute_bits"]:08X}')

    raws[index] = new_raw
    metas = [dict(h) for h in img.partition_headers]
    metas[index] = new_meta

    iht_off = img.boot_header['image_header_table_offset']
    pht_off = img.boot_header['partition_header_table_offset']
    pht_end = pht_off + n * 64
    first_part_byte = min(h['data_word_offset_in_image']
                          for h in img.partition_headers) * 4

    if first_part_byte < pht_end:
        print(f'[!] first_part_offset < pht_end')
        return 7

    boot_hdr = bytearray(img.raw[:iht_off])
    iht_region = img.raw[iht_off:pht_off]
    post_pht = img.raw[pht_end:first_part_byte]

    if index == 0:
        bh_bytes, changed = _update_boot_header_fsbl_size(
            bytes(boot_hdr), len(raws[0]))
        boot_hdr = bytearray(bh_bytes)
        if changed:
            print(f'[i] Обновлён boot_header (user_field_2/_5/_7)')

    pht_words, offsets = _build_pht(raws, metas, orig_sizes,
                                     paddings, first_part_byte)
    pht_bytes = words_to_bytes(pht_words)

    out = _assemble(bytes(boot_hdr), iht_region, pht_bytes, post_pht,
                    raws, orig_sizes, paddings)

    with open(bin_path, 'wb') as f:
        f.write(out)
    print(f'[+] Записано: {bin_path}  ({len(out)} байт)')
    for i, off in enumerate(offsets):
        print(f'    part{i}: offset=0x{off*4:X}  size={len(raws[i])}')
    return 0


# =====================================================================
# --unpack
# =====================================================================

def cmd_unpack(out_dir, bin_path):
    if not os.path.isfile(bin_path):
        print(f'[!] BOOT.bin не найден: {bin_path}')
        return 1

    img = BootImage(bin_path)
    if not img.parse():
        print(f'[!] Ошибка парсинга: {img.error}')
        return 2

    os.makedirs(out_dir, exist_ok=True)
    n = len(img.partition_headers)

    iht_off = img.boot_header['image_header_table_offset']
    pht_off = img.boot_header['partition_header_table_offset']
    pht_end = pht_off + n * 64
    first_part_byte = min(h['data_word_offset_in_image']
                          for h in img.partition_headers) * 4

    if first_part_byte < pht_end:
        print(f'[!] first_part_offset < pht_end')
        return 3

    boot_hdr = img.raw[:iht_off]
    iht_region = img.raw[iht_off:pht_off]
    post_pht = img.raw[pht_end:first_part_byte]
    paddings = _extract_paddings(img)

    print(f'[i] IHT offset:  0x{iht_off:X}')
    print(f'[i] PHT offset:  0x{pht_off:X}')
    print(f'[i] PHT end:     0x{pht_end:X}')
    print(f'[i] First part:  0x{first_part_byte:X}')

    partitions_meta = []
    for i, hdr in enumerate(img.partition_headers):
        raw = img.extract_partition_raw(i)
        fname = f'part{i}.raw'
        with open(os.path.join(out_dir, fname), 'wb') as f:
            f.write(raw)
        print(f'[+] {fname}: {len(raw)} байт  '
              f'(attr=0x{hdr["attribute_bits"]:08X}, '
              f'load=0x{hdr["destination_load_address"]:08X}, '
              f'exec=0x{hdr["destination_exec_address"]:08X}, '
              f'pad_after={len(paddings[i])})')

        partitions_meta.append({
            'index':                       i,
            'filename':                    fname,
            'size_bytes':                  len(raw),
            'attribute_bits':              hdr['attribute_bits'],
            'destination_load_address':    hdr['destination_load_address'],
            'destination_exec_address':    hdr['destination_exec_address'],
            'section_count':               hdr['section_count'],
            'checksum_word_offset':        hdr['checksum_word_offset'],
            'image_header_word_offset':    hdr['image_header_word_offset'],
            'auth_cert_word_offset':       hdr['auth_cert_word_offset'],
            'encrypted_partition_length':  hdr['encrypted_partition_length'],
            'reserved_0':                  hdr['reserved_0'],
            'reserved_1':                  hdr['reserved_1'],
            'reserved_2':                  hdr['reserved_2'],
            'reserved_3':                  hdr['reserved_3'],
            'padding_after_hex':           paddings[i].hex(),
        })

    manifest = {
        'format':                  'zynq7-bootbin-v1',
        'source':                  os.path.basename(bin_path),
        'source_size':             img.total_bytes,
        'iht_offset_bytes':        iht_off,
        'pht_offset_bytes':        pht_off,
        'first_part_offset_bytes': first_part_byte,
        'partition_count':         n,
        'boot_header_hex':         boot_hdr.hex(),
        'iht_region_hex':          iht_region.hex(),
        'post_pht_hex':            post_pht.hex(),
        'partitions':              partitions_meta,
    }

    with open(os.path.join(out_dir, 'manifest.json'), 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f'\n[+] Манифест: {out_dir}/manifest.json')
    return 0


# =====================================================================
# --pack
# =====================================================================

def cmd_pack(manifest_path, out_path):
    if not os.path.isfile(manifest_path):
        print(f'[!] Манифест не найден: {manifest_path}')
        return 1

    manifest_path = os.path.abspath(manifest_path)
    work_dir = os.path.dirname(manifest_path)

    with open(manifest_path) as f:
        m = json.load(f)

    required = ['format', 'boot_header_hex', 'iht_region_hex', 'post_pht_hex',
                'iht_offset_bytes', 'pht_offset_bytes', 'first_part_offset_bytes',
                'partition_count', 'partitions']
    for k in required:
        if k not in m:
            print(f'[!] В манифесте отсутствует поле: {k}')
            return 2

    if m['format'] != 'zynq7-bootbin-v1':
        print(f'[!] Неизвестный формат манифеста: {m["format"]}')
        return 3

    n = m['partition_count']
    iht_off = m['iht_offset_bytes']
    pht_off = m['pht_offset_bytes']
    first_off = m['first_part_offset_bytes']

    boot_hdr = bytes.fromhex(m['boot_header_hex'])
    iht_region = bytes.fromhex(m['iht_region_hex'])
    post_pht = bytes.fromhex(m['post_pht_hex'])

    if len(boot_hdr) != iht_off:
        print(f'[!] boot_header_hex: {len(boot_hdr)} != {iht_off}')
        return 4
    if iht_off + len(iht_region) != pht_off:
        print(f'[!] iht_region_hex не сходится по длине')
        return 5
    pht_end = pht_off + n * 64
    if pht_end + len(post_pht) != first_off:
        print(f'[!] post_pht_hex не сходится: {pht_end} + {len(post_pht)} != {first_off}')
        return 6
    if first_off % 64:
        print(f'[!] first_part_offset не кратен 64: 0x{first_off:X}')
        return 7
    if len(m['partitions']) != n:
        print(f'[!] partitions: {len(m["partitions"])} != {n}')
        return 8

    raws = []
    metas = []
    orig_sizes = []
    paddings = []
    for i, p in enumerate(m['partitions']):
        fname = p.get('filename', f'part{i}.raw')
        fpath = os.path.join(work_dir, fname)
        if not os.path.isfile(fpath):
            print(f'[!] Не найден файл раздела: {fpath}')
            return 9
        with open(fpath, 'rb') as f:
            raw_orig = f.read()
        raw_padded = _pad_raw(raw_orig)
        raws.append(raw_padded)
        metas.append(p)
        orig_sizes.append(p.get('size_bytes', len(raw_orig)))
        paddings.append(bytes.fromhex(p.get('padding_after_hex', '')))
        print(f'[i] {fname}: {len(raw_orig)} байт  (attr=0x{p["attribute_bits"]:08X})')

    boot_hdr, changed = _update_boot_header_fsbl_size(boot_hdr, len(raws[0]))
    if changed:
        print(f'[i] Размер FSBL изменился — boot_header обновлён')

    pht_words, offsets = _build_pht(raws, metas, orig_sizes,
                                     paddings, first_off)
    pht_bytes = words_to_bytes(pht_words)

    out = _assemble(boot_hdr, iht_region, pht_bytes, post_pht,
                    raws, orig_sizes, paddings)

    with open(out_path, 'wb') as f:
        f.write(out)

    print(f'\n[+] Записано: {out_path}  ({len(out)} байт)')
    for i, off in enumerate(offsets):
        print(f'    part{i}: offset=0x{off*4:X}  size={len(raws[i])}')

    print()
    print('[i] Валидация результата:')
    test = BootImage(out_path)
    if not test.parse():
        print(f'    [!] Ошибка: {test.error}')
        return 10
    for i in range(n):
        ok, computed = test.verify_partition_checksum(i)
        status = 'OK' if ok else f'MISMATCH (0x{computed:08X})'
        print(f'    part{i}: checksum={status}')
    return 0


# =====================================================================
# CLI
# =====================================================================

def print_usage():
    print(__doc__)


def main():
    if len(sys.argv) < 2:
        print_usage()
        return 1

    mode = sys.argv[1]

    if mode == '--read':
        if len(sys.argv) != 3:
            print('Использование: --read <BOOT.bin>')
            return 1
        return cmd_read(sys.argv[2])

    if mode == '--switch':
        if len(sys.argv) != 5:
            print('Использование: --switch <index> <new_file> <BOOT.bin>')
            print('  <new_file> — .elf, .bit или .raw')
            return 1
        return cmd_switch(sys.argv[2], sys.argv[3], sys.argv[4])

    if mode == '--unpack':
        if len(sys.argv) != 4:
            print('Использование: --unpack <out_dir> <BOOT.bin>')
            return 1
        return cmd_unpack(sys.argv[2], sys.argv[3])

    if mode == '--pack':
        if len(sys.argv) != 4:
            print('Использование: --pack <manifest.json> <out_BOOT.bin>')
            return 1
        return cmd_pack(sys.argv[2], sys.argv[3])

    print(f'Неизвестный режим: {mode}')
    print_usage()
    return 1


if __name__ == '__main__':
    sys.exit(main())
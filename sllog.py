import argparse
import pathlib
import sys
import zipfile
import time
import re
import struct
import base64
from itertools import zip_longest
from types import SimpleNamespace

import log_rules

# crc8, poly = 0x07, init = 0xFF, ref_in = False, ref_out = False, xor_out = 0x00
crc_table = [
    0x00, 0x07, 0x0e, 0x09, 0x1c, 0x1b, 0x12, 0x15, 0x38, 0x3f, 0x36, 0x31, 0x24, 0x23, 0x2a, 0x2d,
    0x70, 0x77, 0x7e, 0x79, 0x6c, 0x6b, 0x62, 0x65, 0x48, 0x4f, 0x46, 0x41, 0x54, 0x53, 0x5a, 0x5d,
    0xe0, 0xe7, 0xee, 0xe9, 0xfc, 0xfb, 0xf2, 0xf5, 0xd8, 0xdf, 0xd6, 0xd1, 0xc4, 0xc3, 0xca, 0xcd,
    0x90, 0x97, 0x9e, 0x99, 0x8c, 0x8b, 0x82, 0x85, 0xa8, 0xaf, 0xa6, 0xa1, 0xb4, 0xb3, 0xba, 0xbd,
    0xc7, 0xc0, 0xc9, 0xce, 0xdb, 0xdc, 0xd5, 0xd2, 0xff, 0xf8, 0xf1, 0xf6, 0xe3, 0xe4, 0xed, 0xea,
    0xb7, 0xb0, 0xb9, 0xbe, 0xab, 0xac, 0xa5, 0xa2, 0x8f, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9d, 0x9a,
    0x27, 0x20, 0x29, 0x2e, 0x3b, 0x3c, 0x35, 0x32, 0x1f, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0d, 0x0a,
    0x57, 0x50, 0x59, 0x5e, 0x4b, 0x4c, 0x45, 0x42, 0x6f, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7d, 0x7a,
    0x89, 0x8e, 0x87, 0x80, 0x95, 0x92, 0x9b, 0x9c, 0xb1, 0xb6, 0xbf, 0xb8, 0xad, 0xaa, 0xa3, 0xa4,
    0xf9, 0xfe, 0xf7, 0xf0, 0xe5, 0xe2, 0xeb, 0xec, 0xc1, 0xc6, 0xcf, 0xc8, 0xdd, 0xda, 0xd3, 0xd4,
    0x69, 0x6e, 0x67, 0x60, 0x75, 0x72, 0x7b, 0x7c, 0x51, 0x56, 0x5f, 0x58, 0x4d, 0x4a, 0x43, 0x44,
    0x19, 0x1e, 0x17, 0x10, 0x05, 0x02, 0x0b, 0x0c, 0x21, 0x26, 0x2f, 0x28, 0x3d, 0x3a, 0x33, 0x34,
    0x4e, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5c, 0x5b, 0x76, 0x71, 0x78, 0x7f, 0x6a, 0x6d, 0x64, 0x63,
    0x3e, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2c, 0x2b, 0x06, 0x01, 0x08, 0x0f, 0x1a, 0x1d, 0x14, 0x13,
    0xae, 0xa9, 0xa0, 0xa7, 0xb2, 0xb5, 0xbc, 0xbb, 0x96, 0x91, 0x98, 0x9f, 0x8a, 0x8d, 0x84, 0x83,
    0xde, 0xd9, 0xd0, 0xd7, 0xc2, 0xc5, 0xcc, 0xcb, 0xe6, 0xe1, 0xe8, 0xef, 0xfa, 0xfd, 0xf4, 0xf3
]


def crc8(data):
    crc = 0xFF
    for byte in data:
        crc = crc_table[crc ^ byte]
    return crc


def is1251(c):
    return 0x20 <= c <= 0x7e or 0xC0 <= c <= 0xFF or c == 0xA8 or c == 0xB8 or c == 0xB9


def dump(b, width=64, split=None, show_ascii=True):
    hex_part = []
    asc_part = []
    for i in range(len(b)):
        if split and i in split:
            hex_part.append(' ')
            asc_part.append(' ')
        # if split:
        #     c = split.count(i)
        #     if c:
        #         hex_part.append(' '*c)
        #         asc_part.append(' '*c)
        v = b[i]
        hex_part.append(f'{v:02x}')
        if is1251(b[i]):
            asc_part.append(bytes([v]).decode('cp1251', errors='ignore'))
        else:
            asc_part.append('.')
    hex_part = ''.join(hex_part)
    asc_part = ''.join(asc_part)

    if show_ascii:
        return f'{hex_part:{width}} {asc_part}'
    else:
        return f'{hex_part}'


def uid2str(uid):
    return uid if uid is not None else '<unknown>'


class Sprintf:
    _cache = {}
    _fmt = re.compile(r'%[-+0 #]*(?:\d+|\*)?(?:\.(\d+|\*))?(?:h|l|ll|w|I|I32|I64)?([cdiouxXeEfFgGps])|%%')
    _conversion = {
        # 'c': (1, 'B'),
        'd': (4, '<i'), 'i': (4, '<i'),
        'u': (4, '<I'), 'x': (4, '<I'), 'X': (4, '<I'),
    }

    def __init__(self, string):
        self._string = string
        self.tail_pos = 0
        self.args = []

        if string in Sprintf._cache:
            self.format_str, self._specs = Sprintf._cache[string]
        else:
            self._specs = []  # list like ('%.5d', 'd', 5)
            self.format_str = self._fmt.sub(self.__repl, string)
            Sprintf._cache[string] = self.format_str, self._specs

    def __repl(self, var):
        specifier = var.group(2)
        if specifier:
            prec = var.group(1)
            prec = 0 if prec is None else int(prec) if prec != '*' else None
            self._specs.append((var.group(0), specifier, prec))
            return '{}'
        else:
            return '%'

    @staticmethod
    def chain(items):
        for v in items:
            if isinstance(v, tuple):
                yield from v
            else:
                yield v

    def tostring_fast(self):
        return self._string % tuple(self.chain(self.args))

    def tostring_cb(self, cb=None, line=None):
        d = SimpleNamespace(
            string=self.format_str,
            args=tuple(SimpleNamespace(
                print=a[0] % v if v is not None else f'{{{a[0]}}}',
                value=v) for a, v in zip_longest(self._specs, self.args)),
            line=line)
        if callable(cb):
            cb(d)
        return d.string.format(*[a.print for a in d.args])

    @property
    def string(self):
        return self._string

    def unpack_buf(self, buf):
        offset = 0
        self.args = []
        for arg in self._specs:
            spec = arg[1]
            prec = arg[2]
            if prec is None:
                # * -> read prec as int
                length, fmt = self._conversion['d']
                chunk = buf[offset: offset + length]
                if len(chunk) != length:
                    err = KeyError(f'В буфере недостаточно данных для строки "{self.string}"')
                    return err
                prec_value = struct.unpack(fmt, chunk)[0]
                offset += length
            else:
                prec_value = prec

            if spec == 's':
                if prec_value != 0:
                    pos = buf.find(b'\0', offset, offset+prec_value)
                    if pos < 0:
                        pos = offset + prec_value
                    chunk = buf[offset:pos]
                    offset = pos
                else:
                    pos = buf.find(b'\0', offset)
                    if pos < 0:
                        # попытаемся отобразить даже повреждённые строки
                        chunk = buf[offset:] + b'\x19'  # ASCII == end of medium
                        offset = len(buf)
                    else:
                        chunk = buf[offset:pos]
                        offset = pos + 1

                value = chunk.decode('cp1251', errors='backslashreplace')
                value = value.replace('\n', '\\n')
                value = value.replace('\r', '\\r')

            elif spec == 'c':
                chunk = buf[offset:offset + 1]
                value = chunk.decode('cp1251', errors='backslashreplace')
                offset += 1

            elif spec in self._conversion:
                length, fmt = self._conversion[spec]
                chunk = buf[offset: offset + length]
                if len(chunk) != length:
                    err = KeyError(f'В буфере недостаточно данных для строки "{self.string}"')
                    return err

                value = struct.unpack(fmt, chunk)[0]
                offset += length

            else:
                err = AttributeError(f'Необработанный аргумент "{spec}" в строке "{self.string}"')
                return err

            if prec is None:
                self.args.append((prec_value, value))
            else:
                self.args.append(value)

        self.tail_pos = offset
        return None


class DB:
    # Общие правила для всех версий
    RID_CHANGEUID = 0xfe00
    RID_TIMESTAMP = 0xfe01

    db_common = {
        RID_CHANGEUID: ('previous uid: %.32s', '?', ''),
        RID_TIMESTAMP: ('Временная метка %d сек', 'TIME', 'TIME_UTC'),
    }

    # какие rid игнорировать при выводе с разделением по времени
    services_rid = (
        RID_CHANGEUID,
        RID_TIMESTAMP
    )

    db = {}

    @staticmethod
    def check_db_ver():
        return hasattr(log_rules, 'db_ver') and log_rules.db_ver == 3

    @staticmethod
    def _get_rul_indexes(uid):
        if uid not in DB.db:
            if uid in log_rules.db:
                ver, *ss = log_rules.db[uid]
                if ss:
                    packed = base64.b64decode(ss[0])
                    DB.db[uid] = struct.unpack(f'<{len(packed)//2}H', packed)
                else:
                    DB.db[uid] = ()

            else:
                return None
        return DB.db[uid]

    def get_rule(self, uid, rid):
        if uid is not None:
            rul_indexes = self._get_rul_indexes(uid)
            if rul_indexes:
                if rid < len(rul_indexes):
                    idx = rul_indexes[rid]
                    return log_rules.rul[idx]

        # Берём из common
        return DB.db_common.get(rid, None)

    @staticmethod
    def ver_all():
        """
        Список всех версий в базе
        """
        versions = list()
        for r in log_rules.db.values():
            if len(r) > 1:
                versions.extend([v[0] for v in r[0] if v[0] not in versions])
        return versions

    @staticmethod
    def ver_list(uid):
        """
        Список всех версий, подходящих по uid или [], если не найдено
        """
        return log_rules.db[uid][0] if uid in log_rules.db else []

    @staticmethod
    def uid_list(ver):
        """
        Список всех uid, подходящих по версии или [], если не найдено
        """
        return [uid for uid, r in log_rules.db.items() if ver in r[0]]

    def required(self, uid_list):
        """
        Проверить базу на наличие необходимых uid.
        Вернёт список отсутствующих, а те, что есть, будут подгружены
        """
        return [uid for uid in uid_list if not self._get_rul_indexes(uid)]


class Parser:

    class LineCommon:
        def __init__(self, parser, hdr, pos, data):
            self.parser = parser
            self.hdr = hdr
            self.pos = pos
            self.data = data[:]

    class Line30(LineCommon):
        # UID логов. Встречается в начале и с некоторой периодичностью. Похоже, всегда одинаковый,
        # даже если в логе записи нескольких версий
        def __init__(self, parser, hdr, pos, data):
            super().__init__(parser, hdr, pos, data)
            self.uid = self.data.decode('cp1251', errors='backslashreplace')
            if self.uid == '':
                self.uid = None
            else:
                if parser.uid is None:
                    parser.uid = self.uid
                else:
                    if parser.uid != self.uid:
                        self.parser.error(f'! uid {self.uid} different from what has been seen before {parser.uid}')

        def __str__(self):
            comment = f'! uid: 0x{self.pos:06x} 0x{self.hdr:02x}'
            text = f'\'{self.uid}\''
            return f'{comment:42}{text}'

    class Line32(LineCommon):
        # Меняется после перезагрузки сигналки. Не знаю, что это. Встречается только 1 раз в начале
        def __init__(self, parser, hdr, pos, data):
            super().__init__(parser, hdr, pos, data)
            if not parser.line32:
                parser.line32 = self
            else:
                self.parser.error('! повторно встречен пакет 0x32')

        def __str__(self):
            comment = f'! ?not yet known: 0x{self.pos:06x} 0x{self.hdr:02x}'
            text = dump(self.data, 34)
            return f'{comment:42}{text}'

    class Line31(LineCommon):
        BASE_TIME = 1325376000000   # 2012-01-01 00:00:00.000
        INIT_FIELDS = "PAVUtRLsmDc"  # Исходное состояние
        # такой вариант чуть быстрее, чем set()
        _field_a = _field_v = _field_u = _field_r = _field_l = False
        _field_d = _field_p = False
        _field_t = _field_s = _field_m = True
        _field_c = True

        def __init__(self, parser, hdr, pos, data):
            super().__init__(parser, hdr, pos, data)
            # записи лога считаются в миллисекундах от временных меток
            # временные метки в логах хранятся в секундах от 2012-01-01 00:00:00.000
            self.abs_ts = 0
            self.offset_timestamp = 0
            self.uid = None
            self.ver = None
            self.det = False
            self.rid, self.ts = struct.unpack('<HI', data[:6])
            self.payload = data[6:]
            self.set_offset_timestamp(0)

        @classmethod
        def set_fields(cls, fields=None):
            if fields is None:
                fields = cls.INIT_FIELDS
            for f in fields:
                setattr(cls, f'_field_{f.lower()}', f.islower())

        def set_offset_timestamp(self, offset_timestamp):
            self.offset_timestamp = offset_timestamp
            self.abs_ts = self.ts + self.offset_timestamp + self.BASE_TIME

        @property
        def timestamp(self):
            sec = self.abs_ts // 1000
            ms = self.abs_ts % 1000
            ts = time.strftime('%d.%m.%Y %H-%M-%S', time.gmtime(sec)) + f'-{ms:03}:'
            return ts

        def __str__(self):
            try:
                rule = self.parser.db.get_rule(self.uid, self.rid)
                if rule is None:
                    msg = f'unknown rid: 0x{self.rid:04x}'
                    level = ''
                    src = ''
                else:
                    string, src = rule[:2]
                    level = rule[2] if len(rule) > 2 else ''

                    s = Sprintf(string)
                    if self._field_c:
                        s.unpack_buf(self.payload)
                        cb = getattr(log_rules, rule[3], None) if len(rule) > 3 else None
                        msg = s.tostring_cb(cb, self)
                    else:
                        err = s.unpack_buf(self.payload)
                        if err:
                            raise err
                        msg = s.tostring_fast()

            # except (AttributeError, KeyError, IndexError) as e:
            except Exception as e:
                msg = f'!!! ERROR PARSING !!! ({e.__class__.__name__}: {e}, rid: 0x{self.rid:04x})'
                level = ''
                src = ''

            fields = []
            if self._field_p:
                f_pos = f'0x{self.pos:06x}'
                fields.append(f_pos)
            if self._field_a:
                f_det = '!' if self.det else ' '
                fields.append(f_det)
            if self._field_v:
                f_ver = f'{self.ver[0] if self.ver is not None else "?.?":>7}'
                fields.append(f_ver)
            if self._field_u:
                f_uid = f'{uid2str(self.uid):32}'
                fields.append(f_uid)
            if self._field_t:
                f_abs_ts = self.timestamp
                fields.append(f_abs_ts)
            if self._field_r:
                f_rid = f'0x{self.rid:04x}'
                fields.append(f_rid)
            if self._field_l:
                f_level = f'{level:>12}:' if level else ' ' * 13
                fields.append(f_level)
            if self._field_s:
                f_src = f'{src:>20}:' if src else ' ' * 21
                fields.append(f_src)
            if self._field_m:
                f_msg = f'{msg:100}' if self._field_d else msg
                fields.append(f_msg)
            if self._field_d:
                f_dump = dump(self.data, 112, [2, 2, 6])
                fields.append(f_dump)

            return ' '.join(fields)

    def __init__(self, content, custom_uid_list=None):
        self.Line31.set_fields()        # Исходное состояние
        self.db = DB()
        self.errors = []
        self.invalid = False
        self._parse_errors = 0
        self.log = []
        self.seen_ver = []              # какие версии встретились
        self.line32 = None
        self.uid = None                 # uid прошивки, или последних записей, если в логе несколько версий
        self.__packet_pos = 0
        self.__last_chunk = bytearray()
        self.parse_log_file(content)
        self.preprocess(custom_uid_list)

    def error(self, message):
        self.errors.append(message)

    def set_fields(self, fields):
        self.Line31.set_fields(fields)

    def __store_chunk(self):
        if self.__last_chunk:
            self.log.append(self.Line31(self, 0x31, self.__packet_pos, self.__last_chunk))
            self.__last_chunk.clear()

    def __add_packet(self, packet_pos, packet_hdr, packet):
        if packet_hdr == 0x32:
            self.__packet_pos = packet_pos
            self.Line32(self, packet_hdr, self.__packet_pos, packet)
        elif packet_hdr == 0x30:
            self.__packet_pos = packet_pos
            self.Line30(self, packet_hdr, self.__packet_pos, packet)
        elif packet_hdr == 0x31:
            # формат пакета
            # если первый байт 0xEE, то данные - продолжение данных предыдущего пакета
            # {тип:1byte} {данные} {0xFF:1byte} {CRC8:1byte}
            # в остальных случаях
            # {rid:2bytes} {время в ms:4bytes} {данные} {0xFF:1byte} {CRC8:1byte}
            # todo: скорее всего это не верно. т.к. теряются все записи с rid 0x..EE
            #  если бы кодировалось в big-endian, то было бы норм
            data = packet[:-2]
            crc = crc8(data)
            if 0xff != packet[-2]:
                self.error(f'! expected 0xFF but found 0x{packet[-2]:02x} @ 0x{packet_pos:06x}')
            if crc != packet[-1]:
                self.error(f'! BAD CRC. expected 0x{packet[-1]:02x} but computed 0x{crc:02x} @ 0x{packet_pos:06x}')
            packet_type = data[0]
            if packet_type == 0xEE:
                # Продолжение предыдущего
                if self.__last_chunk:
                    self.__last_chunk.extend(data[1:])
                else:
                    # Иногда попадается на первом пакете в файле
                    self.error(f'! not a complete packet @ 0x{packet_pos:06x}, skip')
            else:
                self.__store_chunk()
                self.__packet_pos = packet_pos
                self.__last_chunk.extend(data)
        else:
            comment = f'! unknown type: 0x{packet_pos:06x} 0x{packet_hdr:02x}'
            text = dump(packet)
            self.error(comment)
            self.error(text)

    def __complete(self):
        self.__store_chunk()

    def parse_log_file(self, content):
        packet_hdr = None
        position = 0
        packet_pos = 0
        was_1a = False
        is_data = False
        packet_start = 0
        packet = bytearray()
        while position < len(content):
            byte = content[position]
            if not was_1a and not is_data:
                packet_pos = position
                if byte == 0x1A:
                    was_1a = True
                elif byte == 0x00:
                    # Последовательность \x00 - добивка до 1kb блока
                    pass
                else:
                    self.error(f'! unexpected byte 0x{byte:02x} @ 0x{position:06x}')
                    self._parse_errors += 1
                    self.invalid = self._parse_errors > 35
                    if self.invalid:
                        self.error(f'! Слишком много ошибок. Вероятно это не лог')
                        break

            elif not was_1a and is_data:
                if byte == 0x1A:
                    was_1a = True
                else:
                    # byte добавляется в пакет
                    pass

            elif was_1a and not is_data:
                if byte in [0x30, 0x31, 0x32]:
                    packet_hdr = byte
                    packet_start = position + 1
                    was_1a, is_data = False, True
                else:
                    was_1a = False
                    self.error(f'! unknown header 0x{byte:02x} @ 0x{position:06x}')

            else:  # was_1a and is_data
                if byte == 0x2E:
                    was_1a, is_data = False, False
                    # complete packet
                    packet.extend(content[packet_start:position-1])
                    self.__add_packet(packet_pos, packet_hdr, packet)
                    packet.clear()
                elif byte == 0x5A:
                    # Ещё не конец
                    packet.extend(content[packet_start:position])
                    packet_start = position + 1
                    was_1a = False
                else:
                    self.error(f'! unexpected 0x1a, 0x{byte:02x} @ 0x{position-1:06x}')
            position += 1
        self.__complete()

    # Посчитать абсолютное время события и определиться с версией
    def preprocess(self, custom_uid_list):
        _custom_uid_list = custom_uid_list.copy() if custom_uid_list is not None else None
        pattern_ver = re.compile(br'(\d+)\.(\d+)\.(\d+)\.(\d+)\((\w+)\)')
        pre_uid_lines = []
        seen_ver = set()
        blocks = []
        last_offset_timestamp = 0

        def add_block(_uid):
            # Отсортировать встреченные версии по убыванию. Самая старшая вероятно и будет версией прошивки
            if pre_uid_lines:
                versions = tuple(sorted(seen_ver, reverse=True))
                blocks.append({'uid': _uid, 'versions': versions, 'lines': pre_uid_lines})

        def tup2ver(_ver):
            return f'{_ver[0]}.{_ver[1]}.{_ver[2]}', f'{_ver[3]}' if _ver[-1] == 'public' else f'{_ver[3]}({_ver[4]})'

        for line in self.log:
            pre_uid_lines.append(line)

            if line.rid == self.db.RID_TIMESTAMP:
                rule = self.db.get_rule(None, line.rid)
                if rule is not None:
                    # s = Sprintf(rule[0])
                    # s.unpack_buf(line.payload)
                    # i1 = s.args[0]
                    i1 = struct.unpack('<I', line.payload[:4])[0]
                    last_offset_timestamp = 1000 * (i1 - line.ts // 1000)

            elif line.rid == self.db.RID_CHANGEUID:
                rule = self.db.get_rule(None, line.rid)
                if rule is not None:
                    s = Sprintf(rule[0])
                    s.unpack_buf(line.payload)
                    uid = s.args[0]
                    # Попадались пакеты, когда UID заканчивался не /0. Поэтому может быть это и не %s, а %.32s
                    # если был /0, то оставляем неопределённый uid
                    add_block(None if uid == '' else s.args[0])
                    pre_uid_lines = []
                    seen_ver = set()

            elif line.payload[:10] == b'\xc2\xe5\xf0\xf1\xe8\xff\x20\xcf\xce\x00':  # "Версия ПО\0"
                # могут попадаться версии и основной прошивки и загрузчика и вообще чего угодно
                res = pattern_ver.match(line.payload[10:])
                if res:
                    seen_ver.add(tuple(v.decode('cp1251', errors='ignore') for v in res.groups()))

            # скорректировать время по последней метке
            line.set_offset_timestamp(last_offset_timestamp)

        add_block(self.uid)

        # Попытаемся подобрать uid, для неопределённых блоков
        for b in blocks:
            uid = b['uid']
            det = uid is None
            ver = None
            uid_list = []
            ver_list = []
            # приведём в читаемый вид, исключая "0.0.0.0" и удаляя "(public)"
            for v in b['versions']:
                if not all(map(lambda n: n == '0', v[:4])):
                    ver_list.append(tup2ver(v))

            if det:
                # uid не определён, пытаемся подобрать из версии
                if b['versions']:
                    # Определяем по встреченным аналогичным блокам
                    uu1 = [g['uid'] for g in blocks if g['uid'] is not None and g['versions'] == b['versions']]

                    # Определяем по встреченной версии
                    v2 = tup2ver(b['versions'][0])
                    uu2 = self.db.uid_list(v2)

                    uu = set(uu1) & set(uu2)
                    if len(uu) == 1:
                        uid = uu.pop()
                        ver = v2
                    elif len(uu1) > 0:
                        uid = uu1[0]
                    elif len(uu2) > 0:
                        uid = uu2[0]
                        ver = v2

                    uid_list.extend(uu1)
                    uid_list.extend([uid for uid in uu2 if uid not in uid_list])

                else:
                    # uid нет, версия не определена
                    pass

            else:
                # uid точно определён
                # только один, без вариантов
                uid_list.append(uid)
                # но версий может быть несколько, найдём соответствие из базы и той, что засекли в дампе
                db_ver_list = self.db.ver_list(uid)
                if len(db_ver_list) == 1:
                    ver = db_ver_list[0]
                else:
                    v = set(db_ver_list) & set(ver_list)
                    if len(v) == 1:
                        ver = v.pop()
                # приоритет: точно определённая версия, данные из базы, обнаруженные версии
                vv = []
                if ver:
                    vv.append(ver)
                vv.extend(v for v in db_ver_list if v not in vv)
                vv.extend(v for v in ver_list if v not in vv)
                ver_list = vv

            # определены пользовательские uid, их и используем
            if _custom_uid_list:
                u = _custom_uid_list.pop(0)
                if u not in ('', '-') and uid != u:
                    uid = u
                    det = True
                    vv = self.db.ver_list(uid)
                    if vv:
                        ver = vv[0]
                    # ver_list.extend([v for v in vv if v not in ver_list])

            self.seen_ver.append({
                'det': det,             # возможно, uid определён неточно
                'uid': uid,             # какой uid будет использован
                'ver': ver,             # точная версия прошивки
                'uid_list': uid_list,   # возможные uid, если определитель сработал неверно
                'ver_list': ver_list    # возможные версии прошивки
            })

            for line in b['lines']:
                line.uid = uid
                line.ver = ver
                line.det = det


def get_args():
    default = Parser.Line31.INIT_FIELDS
    desc = {
        'a': ('Показать метку автоопределения. Автоматически, если не указан ключ -A ', 'Скрыть метку'),
        'v': ('Показать версию', 'Скрыть версию'),
        'u': ('Показать uid', 'Скрыть uid'),
        't': ('Показать timestamp', 'Скрыть timestamp'),
        'r': ('Показать rid', 'Скрыть rid'),
        'l': ('Показать log_level', 'Скрыть log_level'),
        's': ('Показать src', 'Скрыть src'),
        'm': ('Показать msg', 'Скрыть msg'),
        'd': ('Показать dump', 'Скрыть dump'),
        'p': ('Показать pos', 'Скрыть pos'),
        'c': ('Добавлять комментарии', 'Не добавлять комментарии'),
    }
    # Подготовить список полей, сохранив последовательность desc
    d = list(default.lower())
    fields = [f for f in desc if f in d and (d.remove(f) or True)]
    fields.extend(d)

    parser = argparse.ArgumentParser(usage=f'%(prog)s [-{"".join(fields)}] [--split SPLIT] [--uid UID [UID ...]] '
                                           'log [output]')
    parser.add_argument('log', type=str, help='StarLine log или zip файл')
    parser.add_argument('output', type=str, nargs='?',
                        help='Результат. Если не указан, будет сгенерирован автоматически')
    for lo in fields:
        up = lo.upper()
        g = parser.add_mutually_exclusive_group()
        h = '* ' if lo in default and lo in desc else ''
        g.add_argument(f'-{lo}', dest='fields', action='append_const', const=lo,
                       help=h+desc[lo][0] if lo in desc else None)
        h = '* ' if up in default and lo in desc else ''
        g.add_argument(f'-{up}', dest='fields', action='append_const', const=up,
                       help=h+desc[lo][1] if lo in desc else None)
    parser.add_argument('--split', default=None, type=int,
                        help='Разбивать вывод, если время между записями превысит заданное значение, ms')
    parser.add_argument('--uid', default=None, type=str, dest='uid', nargs='+',
                        help='Использовать эти uid. Для пропуска используйте "" или -')
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    if args.fields is None:
        args.fields = []
    return args


def get_log_content(filename):
    p = pathlib.Path(filename)
    if not p.is_file():
        print('Файл не найден')
        return None
    if p.suffix.lower() == '.zip':
        try:
            z = zipfile.ZipFile(filename)
        except zipfile.BadZipFile:
            print('Архив повреждён')
            return None
        log_filename = next(iter((fn for fn in z.namelist() if pathlib.Path(fn).suffix.lower() == '.log')), None)
        if log_filename:
            content = z.read(log_filename)
            z.close()
            return content
        else:
            print('Архив не содержит файлов .log')
            return None
    else:
        return p.open('rb').read()


def main():
    if not DB.check_db_ver():
        print('Версия базы не соответствует')
        sys.exit(-1)

    args = get_args()

    if args.output:
        # Выходной файл указан, перенаправляем в него stdout
        sys.stdout = open(args.output, 'w')
    else:
        if not sys.stdout.seekable():
            # Файл не указан и похоже вывод в консоль
            # генерим имя файла
            p = pathlib.Path(args.log)
            output = p.with_suffix(time.strftime('.%d%m%y%H%M%S.txt', time.localtime()))
            print(f'Пишем в {output}')
            sys.stdout = output.open('w')

    content = get_log_content(args.log)
    if content:
        parser = Parser(content, args.uid)

        det = any(v['det'] for v in parser.seen_ver)
        if det:
            parser.set_fields('a')
        if args.fields:
            parser.set_fields(args.fields)

        if parser.errors:
            print(*parser.errors, sep='\n')

        if parser.log:
            missing = parser.db.required([u['uid'] for u in parser.seen_ver])

            # Если есть детектируемые версии, то выведем подробный список версий
            if det:
                if 'A' not in args.fields:
                    print(f'Строки, помеченные "!", возможно, раскодированы неверно')
                for v in parser.seen_ver:
                    mark = '!' if v['det'] else ' '
                    ver = f"{v['ver'][0]}.{v['ver'][1]}" if v['ver'] is not None else '?.?.?'
                    uid = uid2str(v['uid'])
                    m = ' - нет в базе!' if v['uid'] in missing else ' '*14 if missing else ''
                    ver_list = [f'{v[0]}.{v[1]}' for v in v['ver_list']]
                    print(f"{mark} будет использован uid: {uid:>32}{m}  Версия: {ver:13}  "
                          f"Возможные uid, ver: {v['uid_list']}, {ver_list}")
            else:
                for u in missing:
                    vv = parser.db.ver_list(u)
                    ver = ', '.join([f'{v[0]}.{v[1]}' for v in vv]) if vv else '?.?.?'
                    if vv:
                        add_info = ''
                    else:
                        ver_list = [s['ver_list'] for s in parser.seen_ver if s['uid'] == u][0]
                        ver_list = [f'{v[0]}.{v[1]}' for v in ver_list]
                        add_info = f'  Возможные ver: {ver_list}'
                    print(f'Отсутствует база для версии {uid2str(u)} [{ver}]{add_info}')

        last_ts = None
        for line in parser.log:
            if args.split is not None:
                if line.rid not in parser.db.services_rid:
                    if last_ts is not None:
                        dm = line.abs_ts - last_ts
                        sign = '+' if dm >= 0 else '-'
                        dm = abs(dm)
                        if dm > args.split:
                            ms = dm % 1000
                            ds = dm // 1000
                            print(f'{sign}{ds if ds else ""}.{ms}')
                    last_ts = line.abs_ts
            print(line)


if __name__ == "__main__":
    main()

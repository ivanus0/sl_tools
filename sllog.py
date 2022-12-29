import argparse
import pathlib
import sys
import zipfile
import time
import re
import struct

import log_rules


def crc8(data):
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
    crc = 0xFF
    for byte in data:
        crc = crc_table[crc ^ byte]
    return crc

# def crc8(data):
#     # crc8, poly = 0x07, init = 0xFF, ref_in = False, ref_out = False, xor_out = 0x00
#     poly = 0x07
#     crc = 0xFF
#     for i in range(len(data)):
#         crc ^= data[i]
#         for j in range(0, 8):
#             if (crc & 0x80) > 0:
#                 crc = (crc << 1) ^ poly
#             else:
#                 crc = crc << 1
#     return crc & 0xFF


def iter_to_pat(iter_of_bytes):
    return b''.join([fr'\x{v:02x}'.encode('cp1251') for v in iter_of_bytes])


def ts_to_pat(ts):
    return iter_to_pat(struct.pack('<I', ts))


def uid_to_pat(uid):
    return iter_to_pat(struct.pack('<H', uid))


def iswin1251(c):
    return 0x20 <= c <= 0x7e or 0xC0 <= c <= 0xFF or c == 0xA8 or c == 0xB8


def dump(b, width=64, split=None, show_ascii=True):
    if type(b) is int:
        b = [b]
    hex_part = []
    asc_part = []
    for v in list(b):
        hex_part.append(f'{v:02x}')
        if iswin1251(v):
            asc_part.append(bytes([v]).decode('windows-1251'))
        else:
            asc_part.append('.')
    hex_part = ''.join(hex_part)
    asc_part = ''.join(asc_part)
    if type(split) is list:
        left = 0
        hl = []
        al = []
        for s in split:
            hl.append(hex_part[left*2:s*2])
            al.append(asc_part[left:s])
            left = s
        hl.append(hex_part[left*2:])
        al.append(asc_part[left:])
        hex_part = ' '.join(hl)
        asc_part = ' '.join(al)
    if show_ascii:
        return f'{hex_part:{width}} {asc_part}'
    else:
        return f'{hex_part:{width}}'


def to_str(data, length=0):
    if length == 0:
        length = len(data)
    s = []
    for c in data[0: length]:
        if iswin1251(c):
            s.append(bytes([c]).decode('windows-1251'))
        elif c == 0x0a:
            s.append('\\n')
        elif c == 0x0d:
            s.append('\\r')
        else:
            s.append('?')
    return ''.join(s)


def pchar(data):
    s = []
    for c in data:
        if c == 0x00:
            break
        if iswin1251(c):
            s.append(bytes([c]).decode('windows-1251'))
        elif c == 0x0a:
            s.append('\\n')
        elif c == 0x0d:
            s.append('\\r')
        else:
            s.append('?')
    return ''.join(s), len(s)+1


# Вычитываем из content данные в формате pattern
# pattern - текстовая строка, в формате {СИМВОЛ}[ЧИСЛО], где
# СИМВОЛ определяет тип переменной, возможные значения:
#   P - Null-terminated строка или строка заданной длины, если указано ЧИСЛО
#   I - беззнаковый DWORD (4bytes) Little-endian
#   i - знаковый DWORD (4bytes) Little-endian
#   H - беззнаковый WORD (2bytes) Little-endian
#   B - беззнаковый DWORD (4bytes) Big-endian
# ЧИСЛО необязательное число повторений типа
# callback - внешний обработчик pattern
# возвращаем то, что осталось от content и вычитанные данные
def read_content(content, pattern, callback=None) -> tuple:
    result = []
    for f in re.finditer(r'(\w)(\d*)', pattern):
        c, n = f.groups()
        d = int(n) if n != '' else 1

        # callback
        if callback:
            r = callback(content, c, d)
            if r:
                result.append(r[0])
                content = r[1]
                continue

        if c == 'P':
            if n == '':
                s, slen = pchar(content)
            else:
                s = to_str(content, d)
                slen = d
            result.append(s)
            content = content[slen:]
        elif c == 'I':
            for _ in range(d):
                # Little-endian
                result.append(struct.unpack('<I', bytes(content[0:4]))[0])
                content = content[4:]
        elif c == 'i':
            for _ in range(d):
                # Little-endian
                result.append(struct.unpack('<i', bytes(content[0:4]))[0])
                content = content[4:]
        elif c == 'H':
            for _ in range(d):
                # Little-endian
                result.append(struct.unpack('<H', bytes(content[0:2]))[0])
                content = content[2:]

        elif c == 'B':
            for _ in range(d):
                # Big-endian
                result.append(struct.unpack('>I', bytes(content[0:4]))[0])
                content = content[4:]

        elif c == 'd':
            result.append(dump(content, width=1))
            content = []

        # вроде такие типы не встречаются
        elif c == 'b':
            for _ in range(d):
                result.append(struct.unpack(c, bytes(content[0:1]))[0])
                content = content[1:]

    return content, *result


class Parser:

    class LineCommon:
        def __init__(self, parser, hdr, pos, data):
            self.parser = parser
            self.hdr = hdr
            self.pos = pos
            self.data = data[:]

        def __repr__(self):
            return self.__str__()

    class Line30(LineCommon):
        # Hash (md5?) версии прошивки
        def __init__(self, parser, hdr, pos, data):
            super().__init__(parser, hdr, pos, data)
            fw_ver_hash = to_str(self.data)
            if not parser.fw_ver_hash:
                parser.fw_ver_hash = fw_ver_hash
            else:
                if parser.fw_ver_hash != fw_ver_hash:
                    print(f'! fw_ver_hash {fw_ver_hash} different from what has been seen before {parser.fw_ver_hash}')

        def __str__(self):
            comment = f'! fw version hash: 0x{self.pos:06x} 0x{self.hdr:02x}'
            text = f'\'{to_str(self.data)}\''
            return f'{comment:60}{text}'

    class Line32(LineCommon):
        # Меняется после перезагрузки сигналки
        def __str__(self):
            comment = f'! ?not yet known: 0x{self.pos:06x} 0x{self.hdr:02x}'
            text = dump(self.data, 34)
            return f'{comment:60}{text}'

    class Line31(LineCommon):
        # Размеры пакетов могут быть
        # Число пакетов    Размер пакета    Данных в пакете
        #   1                 18              12
        #   2                 35              29
        #   3                 52              46
        #   4                 69              63
        #   5                 86              80
        #   6                103              97
        #   больше не встречал
        # payload может содержать только 0-terminated строки и unsigned DWORD или реже signed DWORD. Других типов не
        # встречал
        # Конец payload может содержать мусор от предыдущих данных. По этому признаку можно визуально ориентироваться
        # для определения размера и типа payload

        BASE_TIME = 1325376000000   # за 0 миллисекунд у старлайн принята датавремя 2012-01-01 00:00:00.000
        PACK1 = 18
        PACK2 = 35
        PACK3 = 52
        PACK4 = 69
        PACK5 = 86
        PACK6 = 103

        def __init__(self, parser, hdr, pos, data):
            super().__init__(parser, hdr, pos, data)
            # записи лога считаются в миллисекундах от 2012-01-01 00:00:00.000 или от временных меток
            # временные метки в логах хранятся в секундах
            self.offset_timestamp = 0
            self.len = len(data)
            self.payload, self.uid, self.ts = read_content(data, 'HI')

        def timestamp(self):
            d = self.ts + self.offset_timestamp + self.BASE_TIME
            sec = d // 1000
            ms = d % 1000
            ts = time.strftime('%d.%m.%Y %H-%M-%S', time.gmtime(sec)) + f'-{ms:03}:'
            return ts

        def arg_callback(self, content, c, d):
            if c == 'u':
                return f'(0x{self.uid:04x})', content
            else:
                return None

        def arg(self, mask):
            return read_content(self.payload, mask, self.arg_callback)

        def __str__(self):
            uid = self.uid

            try:
                rule = self.parser.get_rule(uid)
                if rule is None:
                    msg = f'unknown: (uid: 0x{uid:04x})'
                    prefix_dump = 'UNK:'
                    src = ''
                    content = self.payload
                else:
                    content, *args = self.arg(rule[1])
                    msg = rule[0].format(*args)
                    prefix_dump = 'TAIL:'
                    src = f'{rule[2]:>12}:{rule[3]:>21}:'
                    # 4-й параметр - имя дополнительного обработчика
                    # возможно пригодится для кастомизации обработки записей, кроме коррекции ts

            # except (AttributeError, KeyError) as e:
            except Exception as e:
                msg = f'!!! ERROR PARSING !!! ({e.__class__.__name__}: {e}, uid: 0x{uid:04x})'
                prefix_dump = 'RAW:'
                src = ''
                content = self.data

            str_timestamp = self.timestamp()
            str_uid = f' 0x{uid:04x} '
            str_tail = f'{prefix_dump:>5}{dump(content, 48)}'
            str_fulldump = dump(self.data, 112, [2, 2, 6, self.PACK1, self.PACK2, self.PACK3, self.PACK4, self.PACK5])
            if self.parser.output_level == 0:
                return f'{str_timestamp:28}{src:36}{msg}'
            elif self.parser.output_level == 1:
                return f'{str_timestamp:28}{src:36}{msg:100}{str_uid}{str_tail}'
            else:
                return f'{str_timestamp:28}{src:36}{msg:100}{str_uid}{str_tail:84}{str_fulldump}'

    def __init__(self, content):
        self.log = []
        self.ts_uid = set()
        self.fw_ver_hash = ''
        self.rules = {}
        self.last_timestamp = 0  # в миллисекундах
        self.output_level = 0
        self.__packet_pos = 0
        self.__last_chunk = []
        self.parse_log_file(content)
        # выбираем базу
        if self.fw_ver_hash in log_rules.db:
            self.rules = log_rules.db[self.fw_ver_hash]
        else:
            print('Для этой версии прошивки отсутствуют log rules!')

    def __store_chunk(self):
        if len(self.__last_chunk) > 0:
            self.log.append(self.Line31(self, 0x31, self.__packet_pos, self.__last_chunk))
            self.__last_chunk.clear()

    def __add_packet(self, packet_pos, packet_hdr, packet):
        if packet_hdr == 0x32:
            self.__packet_pos = packet_pos
            self.log.append(self.Line32(self, packet_hdr, self.__packet_pos, packet))
        elif packet_hdr == 0x30:
            self.__packet_pos = packet_pos
            self.log.append(self.Line30(self, packet_hdr, self.__packet_pos, packet))
        elif packet_hdr == 0x31:
            # формат пакета
            # {?тип:2bytes} {время в ms:4bytes} {данные} {0xFF:1byte} {CRC8:1byte}
            # но для типа 0xEE подтипа и времени нет
            # {тип:1byte} {данные} {0xFF:1byte} {CRC8:1byte}
            data = packet[:-2]
            crc = crc8(data)
            if 0xff != packet[-2]:
                print(f'! expected 0xFF but found 0x{packet[-2]:02x} @ 0x{packet_pos:06x}')
            if crc != packet[-1]:
                print(f'! BAD CRC. expected 0x{packet[-1]:02x} but computed 0x{crc:02x} @ 0x{packet_pos:06x}')
            packet_type = data[0]
            if packet_type == 0xEE:
                # Продолжение предыдущего
                self.__last_chunk.extend(data[1:])
            else:
                self.__packet_pos = packet_pos
                self.__store_chunk()
                self.__last_chunk.extend(data)
        else:
            comment = f'! ?unknown type: 0x{packet_pos:06x} 0x{packet_hdr:02x}'
            text = dump(packet)
            print(comment)
            print(text)

    def __complete(self):
        self.__store_chunk()

    def parse_log_file(self, content):
        packet_hdr = None
        position = 0
        packet_pos = 0
        was_1a = False
        is_data = False
        packet = []
        while position < len(content):
            byte = content[position]
            if not was_1a and not is_data:
                packet_pos = position
                if byte == 0x1A:
                    was_1a = True
                elif byte == 0x00:
                    # последовательность \x00. Допустимо
                    pass
                else:
                    print(f'! unexpected byte 0x{byte:02x} @ 0x{position:06x}')

            elif not was_1a and is_data:
                if byte == 0x1A:
                    was_1a = True
                else:
                    packet.append(byte)

            elif was_1a and not is_data:
                if byte in [0x30, 0x31, 0x32]:
                    packet_hdr = byte
                    was_1a, is_data = False, True
                else:
                    was_1a = False
                    print(f'! unknown header 0x{byte:02x} @ 0x{position:06x}')

            else:  # was_1a and is_data
                if byte == 0x2E:
                    was_1a, is_data = False, False
                    # complete packet
                    self.__add_packet(packet_pos, packet_hdr, packet)
                    packet.clear()
                elif byte == 0x5A:
                    # Ещё не конец
                    packet.append(0x1A)
                    was_1a = False
                else:
                    print(f'! unexpected 0x1a, 0x{byte:02x} @ 0x{position-1:06x}')
            position += 1
        self.__complete()
        # print('PARSER DONE')

    def match(self, log_line, pattern):
        if isinstance(pattern, str):
            pattern = pattern.encode('cp1251')
        if isinstance(log_line, self.Line31):
            return re.match(pattern, bytes(log_line.data), re.DOTALL)

    # Генератор индексов с фильтрами
    def filter(self, pattern=None, start=0, forward=True, limit=0, skip_ts=True):
        if isinstance(pattern, str):
            pattern = pattern.encode('cp1251')
        for idx in range(start, len(self.log), 1) if forward else range(start, -1, -1):
            if not isinstance(self.log[idx], self.Line31):
                continue
            if skip_ts and self.log[idx].uid in self.ts_uid:
                continue
            if pattern and not re.match(pattern, bytes(self.log[idx].data), re.DOTALL):
                continue
            yield idx
            if limit:
                limit -= 1
                if limit == 0:
                    break

    # Анализируем все типы пакетов подходящие по pattern
    # Если указан length, то все обнаруженные однотипные пакеты должны быть указанного размера
    # Если указан callback_check2, то все строки попарно сравниваются друг с другом, 1 и 2, 2 и 3 итд,
    # если будет возвращено True, то только тогда создаём правило rule
    def analyze_all_by_mask(self, pattern, rule, length=0, callback_check2=None):
        skip_uid = set()
        for i0 in self.filter(pattern=pattern, skip_ts=True):
            uid = self.log[i0].uid
            if uid in skip_uid:
                # Уже анализировали такой пакет, пропускаем
                continue
            if uid not in self.rules:
                # Такого правила ещё нет, дополнительно проверяем
                flag = True
                # убедится, что такие пакеты только такого размера
                if length and self.log[i0].len == length:
                    for i1 in self.filter(b'^' + uid_to_pat(uid), skip_ts=True):
                        if self.log[i1].len != length:
                            flag = False
                            break
                # Проверяем через callback
                if flag:
                    if callback_check2:
                        flag = False
                        pre_idx = None
                        for cur_idx in self.filter(b'^' + uid_to_pat(uid), skip_ts=True):
                            if pre_idx is not None:
                                flag = callback_check2(self.log[pre_idx], self.log[cur_idx])
                                if flag:
                                    break
                            pre_idx = cur_idx

                    if flag:
                        self.analyze_add_rule(uid, rule)
            skip_uid.add(uid)

    # Добавляем автоопределённое правило
    def analyze_add_rule(self, uid, rule):
        if uid not in self.rules:
            self.rules[uid] = rule
            print('AUTO: ', f'0x{uid:04x}: {rule},')

    # Ищем пакет по mask
    # и добавляем правило, если ещё неопределён
    def analyze_by_mask(self, pattern, rule):
        i0 = next(self.filter(pattern), None)
        if i0:
            uid = self.log[i0].uid
            self.analyze_add_rule(uid, rule)
        return i0

    def get_rule(self, uid):
        rule = self.rules.get(uid, None)
        # if isinstance(rule, int):
        #     # подмена
        #     rule = self.rules.get(rule, None)
        return rule

    def set_timestamp(self, line, *args):
        self.ts_uid.add(line.uid)
        i1 = args[0]
        self.last_timestamp = 1000 * (i1 - line.ts // 1000)

    def is_timestamp(self, line, *args):
        self.ts_uid.add(line.uid)

    # Скорректировать метки времени у всех записей по Временным меткам из лога
    def adjust_timestamp(self):
        for line in self.log:
            if isinstance(line, self.Line31):
                rule = self.get_rule(line.uid)
                if rule is not None and len(rule) > 4:
                    # 4-й параметр - имя дополнительного обработчика
                    cb = getattr(self, rule[4], None)
                    if cb is not None:
                        _, *args = line.arg(rule[1])
                        cb(line, *args)
                line.offset_timestamp = self.last_timestamp

    # Перебираем последовательности
    # в последовательности должна быть запись, соответствующая pattern
    # pattern_idx индекс искомой записи в последовательности
    # в callback_check передаём список обнаруженных строк, если вернёт True, то это счётная последовательность
    # rules список правил, которая описывает последовательность
    # min_hits - минимум попаданий для фиксирования правил
    # возвращаем список определённых uid (хотя может и нет смысла)
    # todo: можно ускорить работу ф-ии, если прерваться сразу при наборе min_hits последовательностей,
    #       но статистика для max будет неверная.
    def analyze_seq(self, pattern, pattern_idx, callback_check, rules, min_hits=5):
        count = len(rules)
        if 0 <= pattern_idx < count:
            d = [dict() for _ in range(count)]
            for i0 in self.filter(pattern):
                seq = []
                # записи до pattern
                if pattern_idx > 0:
                    seq_up = list(self.filter(start=i0-1, forward=False, limit=pattern_idx))
                    seq_up.reverse()
                    seq.extend(seq_up)
                # записи с pattern и после
                seq_down = list(self.filter(start=i0, forward=True, limit=count - pattern_idx))
                seq.extend(seq_down)
                if len(seq) == count and callback_check([self.log[i] for i in seq]):
                    for k, j in enumerate(seq):
                        uid = self.log[j].uid
                        d[k][uid] = d[k].get(uid, 0) + 1

            # выбираем подходящие
            uids = [None] * count
            for k, d in enumerate(d):
                if d:
                    uid = max(d, key=d.get)
                    if d[uid] >= min_hits:
                        uids[k] = uid
            # все должны набрать не менее min_hits
            if all(uids):
                for k, uid in enumerate(uids):
                    self.analyze_add_rule(uid, rules[k])
                return uids
        return None

    def analyze(self, deep_analyze):
        # временные метки
        # Похоже, на всех прошивках имеют код 0xfe01
        def check_ts(l0, l1):
            ts0 = l0.ts
            ts1 = l1.ts
            a0 = l0.arg('I')[1]
            a1 = l1.arg('I')[1]
            # разница между метками > 10сек
            # разница между 2мя метками(msec) по времени записи в логе соответствует значениям меток(sec)
            # с точностью до секунды
            return ts1 - ts0 > 10000 and 0 <= (a1 - a0) - (ts1 - ts0) // 1000 <= 1

        if not deep_analyze:
            i0 = None
            for index in self.filter(r'^\x01\xfe', skip_ts=False):
                i1 = index
                if i0 is not None:
                    if check_ts(self.log[i0], self.log[i1]):
                        uid = self.log[i0].uid
                        self.ts_uid.add(uid)
                        self.analyze_add_rule(uid, ('Временная метка {} сек', 'I', 'TIME_UTC', 'TIME', 'set_timestamp'))

                        # Встречаются доп. временные метки рядом с теми-же значениями сек и тем же timestamp
                        pat = iter_to_pat(self.log[i0].data[2:10])  # берём timestamp м arg0
                        for i2 in self.filter(b'..'+pat, start=i0+1, limit=i1-i0-2, skip_ts=False):
                            uid = self.log[i2].uid
                            self.ts_uid.add(uid)
                            self.analyze_add_rule(uid, ('Временная метка (2?) {} сек', 'I', '? TIME_UTC', '? TIME', 'is_timestamp'))
                            break

                        break
                i0 = i1
        else:
            # Вариант более глубокого поиска. Тут будут найдены и основные и доп. метки
            # При использовании маски
            # r'^\x01\xfe.{16}$',               # Ищем пакеты 0xfe01
            # получим примерно тоже что и код выше
            # r'^.........[\x0d-x20].{8}$',     # Более детальный поиск. Фильтруем по значению в диапазоне примерно c nov.2018 по jan.2029гг.
            self.analyze_all_by_mask(
                r'^.........[\x0d-x20].{8}$',
                ('Временная метка {} сек', 'I', 'TIME_UTC', 'TIME', 'set_timestamp'),
                self.Line31.PACK1,
                check_ts
            )

        # Для 2.30.0 это 0x0070, 0x0d31
        self.analyze_seq(
            r'^......SHOCK LOW\0active\0',
            1,
            lambda lines: lines[1].ts == lines[0].ts,
            [
                ('Сработал датчик удара по нижне...???', '', 'LOG_DEBUG', 'TASK_SENSOR'),
                ('ZONE: {} = {}', 'PP', 'LOG_DEBUG', 'SYSDATA')
            ]
        )

        # Для 2.30.0 это 0x0087, 0x0de5, 0x0d31
        self.analyze_seq(
            r'^......SHOCK LOW\0passive\0',
            2,
            lambda lines: (0 <= lines[1].ts - lines[0].ts <= 1) and (1 <= lines[2].ts - lines[1].ts <= 3),
            [
                ('Срабатывание датчика удара по ...???', '', 'LOG_DEBUG', 'TASK_SENSOR'),
                ('Датчик удара LOW: конец сработки', '', 'LOG_INFO', 'USER_EVENT'),
                ('ZONE: {} = {}', 'PP', 'LOG_DEBUG', 'SYSDATA')
            ]
        )

        # Для 2.30.0 это 0x0086, 0x0d31
        # SHOCK HIGH = active обычно идёт сразу после SHOCK HIGH = passive, игнорим такие
        self.analyze_seq(
            r'^......SHOCK HIGH\0active\0',
            1,
            lambda lines: lines[1].uid != lines[0].uid and (1 <= lines[1].ts - lines[0].ts <= 3),
            [
                ('Сработал датчик удара по верхн...???', '', 'LOG_DEBUG', 'TASK_SENSOR'),
                ('ZONE: {} = {}', 'PP', 'LOG_DEBUG', 'SYSDATA')
            ]
        )

        # Для 2.30.0 это 0x0088, 0x0de6, 0x0d31
        self.analyze_seq(
            r'^......SHOCK HIGH\0passive\0',
            2,
            lambda lines: (0 <= lines[1].ts - lines[0].ts <= 1) and (1 <= lines[2].ts - lines[1].ts <= 3),
            [
                ('Срабатывание датчика удара по ...???', '', 'LOG_DEBUG', 'TASK_SENSOR'),
                ('Датчик удара HIGH: конец сработки', '', 'LOG_INFO', 'USER_EVENT'),
                ('ZONE: {} = {}', 'PP', 'LOG_DEBUG', 'SYSDATA')
            ]
        )

        # Для 2.30.0 это 0x0089, 0x0d31
        self.analyze_seq(
            r'^......ДАТЧИК НАКЛОНА\0active\0',
            1,
            lambda lines: 1 <= lines[1].ts - lines[0].ts <= 3,
            [
                ('Сработал датчик наклона', '', 'LOG_DEBUG', 'TASK_SENSOR'),
                ('ZONE: {} = {}', 'PP', 'LOG_DEBUG', 'SYSDATA')
            ]
        )

        # Для 2.30.0 это 0x008a, 0x0de4, 0x0d31
        self.analyze_seq(
            r'^......ДАТЧИК НАКЛОНА\0passive\0',
            2,
            lambda lines: (lines[1].ts == lines[0].ts) and (lines[2].ts - lines[1].ts == 3),
            [
                ('Срабатывание датчика наклона с...???', '', 'LOG_DEBUG', 'TASK_SENSOR'),
                ('Датчик наклона: конец сработки', '', 'LOG_INFO', 'USER_EVENT'),
                ('ZONE: {} = {}', 'PP', 'LOG_DEBUG', 'SYSDATA')
            ]
        )

        # Для 2.30.0 это 0x008b, 0x033e, 0x0d31
        self.analyze_seq(
            r'^......ДАТЧИК ДВИЖЕНИЯ\0active\0',
            2,
            lambda lines: (1 <= lines[1].ts - lines[0].ts <= 3) and (0 <= lines[2].ts - lines[1].ts <= 1),
            [
                ('Сработал датчик движения', '', 'LOG_DEBUG', 'TASK_SENSOR'),
                ('Активен паркинг игнорируем дат...???', '', 'LOG_INFO', 'GUARD_STATE_DISARM'),
                ('ZONE: {} = {}', 'PP', 'LOG_DEBUG', 'SYSDATA')
            ]
        )

        # Для 2.30.0 это 0x008d, 0x0de3, 0x0d31
        self.analyze_seq(
            r'^......ДАТЧИК ДВИЖЕНИЯ\0passive\0',
            2,
            lambda lines: (lines[1].ts == lines[0].ts) and (2 <= lines[2].ts - lines[1].ts <= 3),
            [
                ('Срабатывание датчика движения', '', 'LOG_DEBUG', 'TASK_SENSOR'),
                ('Датчик движения: конец сработки', '', 'LOG_INFO', 'USER_EVENT'),
                ('ZONE: {} = {}', 'PP', 'LOG_DEBUG', 'SYSDATA')
            ]
        )

        # Todo
        # АКСЕССУАРЫ = active
        # АКСЕССУАРЫ = passive
        # БАГАЖНИК = active|passive
        # ГЕРКОН = unk
        # ДВЕРИ = active|passive
        # ДВЕРЬ ВОДИТЕЛЯ = active|passive
        # ДВЕРЬ ПАССАЖИРА = active|passive
        # ДОП. ДАТЧИК 1 = active|passive
        # РУЧНОЙ ТОРМОЗ = active|passive|unk
        # СЕНСОР РУЧКИ = active|passive

        # все uid для версии 2.30.0
        # 0x0dd9 -> 4ms -> 0x0d31 r'^......КАПОТ\0active\0'
        # 0x0dda -> 4ms -> 0x0d31 r'^......КАПОТ\0passive\0'

        # 0x026e(25, 1) -> 0ms -> 0x027f(1) -> 0ms -> 0x0d31 r'^......ПАРКИНГ\0active\0'
        # 0x026e(25, 2) -> 0ms -> 0x027f(0) -> 0ms -> 0x0d31 r'^......ПАРКИНГ\0passive\0'

        # 0x026e(7, 1) -> 0ms -> 0x0273(1) -> 0ms -> 0x0ddd -> 0ms -> 0x0d31 r'^......ПЕДАЛЬ ТОРМОЗА\0active\0'
        # 0x026e(7, 2) -> 0ms -> 0x0273(0) -> 0ms -> 0x0dde -> 0ms -> 0x0d31 r'^......ПЕДАЛЬ ТОРМОЗА\0passive\0'

        # 0x026e(67, 1) -> 0ms -> 0x026e(5, 1) -> 0ms -> 0x0271(1) -> 0-1ms -> 0x0d46 -> 0-1ms -> 0x0d31 r'^......ЗАЖИГАНИЕ\0active\0'
        # 0x026e(67, 0) -> 0ms -> 0x026e(5, 2) -> 0ms -> 0x0271(0) -> (0ms -> 0x0dd6 ->)? 1ms -> 0x0d31 r'^......ЗАЖИГАНИЕ\0passive\0'

        # 0x026e(23, 1) -> 0ms -> 0x0288(1) -> 0ms -> 0x0d48 r'^......IN_SEATBELT\0active\0'
        # 0x026e(23, 2) -> 0ms -> 0x0288(0) -> 0ms -> 0x0d48 r'^......IN_SEATBELT\0passive\0'

        # 0x026e(17, 1) -> 0ms -> 0x028a(1) -> 0ms -> 0x0d48 r'^......UNK: 0x1C19\0active\0'
        # 0x026e(17, 2) -> 0ms -> 0x028a(0) -> 0ms -> 0x0d48 r'^......UNK: 0x1C19\0passive\0'

        # 0x026e(24, 1) -> 0ms -> 0x0280(1) -> 0ms -> 0x0d48 r'^......UNK: 0x1C1A\0active\0'
        # 0x026e(24, 2) -> 0ms -> 0x0280(0) -> 0ms -> 0x0d48 r'^......UNK: 0x1C1A\0passive\0'

        # 0x026e(3, 1) -> 0ms -> 0x026f(1) -> 0ms -> 0x0ddb -> 1ms -> 0x0d31 r'^......БАГАЖНИК\0active\0'
        # 0x026e(3, 2) -> 0ms -> 0x026f(0) -> 0ms -> 0x0ddc -> 1ms -> 0x0d31 r'^......БАГАЖНИК\0passive\0'

        # 0x026e(2, 1) -> 0ms -> 0x0e4f -> 0-1ms -> 0x0d31 r'^......ДВЕРЬ ПАССАЖИРА\0active\0'
        # 0x026e(2, 2) -> 0ms -> 0x0e50 -> 0-1ms -> 0x0d31 r'^......ДВЕРЬ ПАССАЖИРА\0passive\0'

        # 0x026e(
        # 1 - ДВЕРЬ ВОДИТЕЛЯ
        # 2 - ДВЕРЬ ПАССАЖИРА
        # 3 - БАГАЖНИК
        # 4
        # 5 - ЗАЖИГАНИЕ
        # 7 - ПЕДАЛЬ ТОРМОЗА
        # 8 - РУЧНОЙ ТОРМОЗ
        # 10 - ДАТЧИК НАКЛОНА
        # 12
        # 13
        # 14
        # 17 - UNK: 0x1C19 ("ID_IN_ACC": 7193)
        # 20
        # 21
        # 22
        # 23 - IN_SEATBELT
        # 24 - UNK: 0x1C1A ("ID_IN_GEARBOX_R": 7194)
        # 25 - ПАРКИНГ
        # 33
        # 34
        # 35
        # 67 - ЗАЖИГАНИЕ
        # 68

        def check_dlg_status(lines):
            nonlocal pre_arg0
            result = lines[0].len == self.Line31.PACK4 and lines[2].len == self.Line31.PACK1 and lines[0].ts == lines[1].ts == lines[2].ts
            arg0 = lines[0].arg('I')[1]
            if pre_arg0 is not None:
                result = result and pre_arg0 == arg0-1
            pre_arg0 = arg0
            return result

        # Для 2.30.0 это 0x0ca1, 0x0ca2, 0x0cec
        pre_arg0 = None
        self.analyze_seq(
            r'^......Диалог\0статус\0.{15}$',
            1,
            check_dlg_status,
            [
                ('Счетчик: {}: мелодия: {}: данные {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}', 'III11', 'LOG_INFO', 'REM_DLG'),
                ('{}: {}', 'PP', 'LOG_INFO', 'REM_DLG'),
                ('Диалог закончен. Есть запрос на отправку статуса', '', 'LOG_DEBUG', 'REM_IRX_SPI')
            ]
        )

        # Для 2.30.0 это 0x0d46
        self.analyze_by_mask(
            r'^......ОТПИРАНИЕ ЦЗ АКТИВНО\0OFF\0',
            ('FLAG: {} = {}', 'PP', 'LOG_DEBUG', 'SYSDATA')
        )

        # Для 2.30.0 это 0x02b6
        self.analyze_by_mask(
            r'^......s=0,[\w=,]{42,}',
            ('{}', 'P', '?', '?')
        )

        # Для 2.30.0 это 0x0dc1
        self.analyze_by_mask(
            r'^.......\0\0\0КНОПКА НА БРЕЛКЕ\0.\0\0\0.\0\0\0.{17}$',
            ('{} {} {} {}', 'IPII', '?', '?')
        )
        # Для 2.30.0 это 0x0dce
        self.analyze_by_mask(
            r'^.......\0\0\0КНОПКА НА БРЕЛКЕ\0.\0\0\0.{4}$',
            ('{} {} {}', 'IPI', '?', '?')
        )

        # Для 2.30.0 это 0x038a
        # 'Версия CAN-lib'\0
        # на версии 2.30 встречались похожие записи 'Версия SLP' с кодом 0x0132
        self.analyze_by_mask(
            r'^......Версия CAN-lib\0',
            ('{}: {}', 'PP', 'LOG_BLOCK', 'VERSION')
        )

        # Для 2.30.0 это 0x0d61, 0x0d58
        # заголовок таблицы.
        # 0x0Dxx I I I I I I 'Idle'\0
        # Записи в таблице каждые 30ms. Заголовок за 30ms до первой записи
        self.analyze_seq(
            r'^.\x0d....(..\x00\x00){6}Idle\0',
            1,
            lambda lines: (29 <= lines[1].ts - lines[0].ts <= 31) and (lines[1].uid & 0xFF00 == lines[0].uid & 0xFF00),
            [
                ('_ID:Стек:Не исп.:Макс.:Загруз. ...???', '', 'LOG_BLOCK', 'TNPROFILER'),
                ('{:3}: {:3}: {:3}: {:5}: {:2}.{:02} : {}', 'IIIIIIP', 'LOG_BLOCK', 'TNPROFILER')
            ],
            min_hits=2
        )

        # Для 2.30.0 это 0x0d26, 0x0d27
        # заголовок таблицы
        # 0x08xxxxxx : I :  I : I : I : TASK_ROUTER
        self.analyze_seq(
            r'^.........\x08......\0\0..\0\0..\0\0TASK_ROUTER\0',
            1,
            lambda lines: (lines[1].ts == lines[0].ts) and (lines[1].uid & 0xFF00 == lines[0].uid & 0xFF00),
            [
                ('___pFunc___:____cnt____:_max_:_?_:_?_:_???_', '', 'LOG_BLOCK', 'ROUTER'),
                ('0x{:08x} : {:9} : {:3} : {} : {} : {}', 'IIIIIP', 'LOG_BLOCK', 'ROUTER')
            ],
            min_hits=2
        )

        # Для 2.30.0 это 0x0005
        # Gyro ?
        # I какойто индекс, последующие события имеют I+5
        # дальше 3 группы по 5 знаковых int
        # События идут по 3 подряд каждые 100ms
        # Есть похожие записи, где по 1 каждые 50ms
        self.analyze_all_by_mask(
            r'^........\x00\x00(..(\x00\x00|\xff\xff)){15}.{16}$',
            ('{:4} : {:4}, {:4}, {:4}, {:4}, {:4} : {:4}, {:4}, {:4}, {:4}, {:4} : {:4}, {:4}, {:4}, {:4}, {:4}', 'Ii15', '?', '? gyro'),
            self.Line31.PACK5,
            lambda l0, l1: l1.arg('i')[1] - l0.arg('i')[1] == 5 and l1.ts == l0.ts
        )

        # очень долгий поиск
        # RPM
        if deep_analyze:
            skip_uid = set()
            for i0 in self.filter(r'^........\0\0.{8}$'):
                uid = self.log[i0].uid
                if uid in skip_uid:
                    continue
                if uid not in self.rules:
                    flag = True
                    rpm = []
                    for i1 in self.filter(b'^' + uid_to_pat(uid)):
                        if self.log[i1].len != self.Line31.PACK1:
                            flag = False
                            break
                        a = self.log[i1].arg('I')[1]
                        if a != 0 and (a < 400 or a > 6000):
                            flag = False
                            break
                        rpm.append(a)
                    if flag and len(set(rpm)) > 5:
                        self.analyze_add_rule(uid, ('RPM = {} check me', 'I', '? LOG_INFO', '? ENG'))
                skip_uid.add(uid)

        # Gyro ?
        # I какойто индекс, последующие события имеют I+5, может быть отрицательным
        # дальше 3 группы по 5 знаковых int
        # События идут по 1 каждые 50ms
        self.analyze_all_by_mask(
            r'^......(..(\x00\x00|\xff\xff)){16}.{16}$',
            ('{:4} : {:4}, {:4}, {:4}, {:4}, {:4} : {:4}, {:4}, {:4}, {:4}, {:4} : {:4}, {:4}, {:4}, {:4}, {:4}', 'ii15', '?', '? gyro(2)'),
            self.Line31.PACK5,
            lambda l0, l1: l1.arg('i')[1] - l0.arg('i')[1] == 5 and 49 <= l1.ts - l0.ts <= 51
        )

        # I16, 5 пакетов
        # положительные небольшие значения
        self.analyze_all_by_mask(
            r'^......(.\x00\x00\x00){16}.{16}$',
            ('{:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3}', 'I16', '?data_16-5?', 'check me'),
            self.Line31.PACK5
        )

        # Для 2.30.0 подходит 0x0ca1, но выше детектим точнее
        # I13, 4 пакета
        self.analyze_all_by_mask(
            r'^......(..\x00\x00){13}.{11}$',
            ('{:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3}', 'I13', '?data13-4?', 'check me'),
            self.Line31.PACK4
        )

        # I7, 2 пакета
        self.analyze_all_by_mask(
            r'^......(.\x00\x00\x00){7}.{1}$',
            ('{:3} : {:3} : {:3} : {:3} : {:3} : {:3} : {:3}', 'I7', '?data_7-2?', 'check me'),
            self.Line31.PACK2
        )

        # I7, 2 пакета
        self.analyze_all_by_mask(
            r'^......(.\x00\x00\x00){5}.{9}$',
            ('{:3} : {:3} : {:3} : {:3} : {:3}', 'I5', '?data_5-2?', 'check me'),
            self.Line31.PACK2
        )

        # self.analyze_add_rule(0x09eb, ('{}', 'P', '?QQQQ?', '?'))
        # self.analyze_add_rule(0x09ec, ('{:3} : {:3} {:3} {:3} {:3} : {:3} {:3} {:3} : {:3} : {:3}', 'IbbbbbbHiI', '?QQQQ?', '?'))

        # SMS текст
        self.analyze_by_mask(
            r'^......SMS-текст: \0.\0\0\0',
            ('{} {}', 'PI', '?', '?')
        )
        self.analyze_by_mask(
            r'^......SMS-текст: \0[ \w\xC0-\xFF]+',
            ('{} {}', 'PP', '?', '?')
        )

        # Для 2.30.0 это 0x01ff
        self.analyze_by_mask(
            r'^.......\0\0\0ENGINE_START_BLOCK\0KILL\0.\0\0\0',
            ('{}: {} : {} : {}', 'IPPI', '?', '?')
        )

        # Для 2.30.0 это 0x0d3f
        self.analyze_by_mask(
            r'^......\x0b\0\0\0ПЕДАЛЬ ТОРМОЗА\0\0\0\0\0',
            ('MASK:{} по {} = {}', 'IPI', 'LOG_DEBUG', 'SYSDATA')
        )

        # Для 2.30.0 это 0x0d46
        self.analyze_by_mask(
            r'^......ДВИГАТЕЛЬ ЗАПУЩЕН\0ON\0',
            ('FLAG: {} = {}', 'PP', 'LOG_DEBUG', 'SYSDATA')
        )

        # Для 2.30.0 это 0x0d48
        self.analyze_by_mask(
            r'^......UNK: 0x[0-9A-F]{4}\0(active|passive)\0',
            ('FLAG ?: {} = {}', 'PP', '? LOG_DEBUG', '? SYSDATA')
        )

        # Не знаю что, но для 2.30.0 это 0x0d39, похож на 0x0d3f
        # 3-й аргумент всегда 1. Но, судя по размеру пакетов, он точно есть
        # alt mask: r'^.......\0\0\0SHOCK LOW\0.\0\0\0'
        self.analyze_by_mask(
            r'^......\x0b\0\0\0ПЕДАЛЬ ТОРМОЗА\0\x01\0\0\0',
            ('MASK:{} по {} = {}', 'IPI', 'LOG_DEBUG', 'SYSDATA')
        )

        # Для 2.30.0 это 0x0353
        # Температура до целых 5 раз
        # -8 +9 +10 +11 +12
        self.analyze_by_mask(
            r'^......([\+\-]\d+\0){5}',
            ('{} : {} : {} : {} : {}', 'PPPPP', '?', '? temp двигатель')
        )

        # Для 2.30.0 это 0x0350
        # Температура до десятых 5 раз
        # -3.8 +10.2 +10.2 +10.2 +10.3
        self.analyze_by_mask(
            r'^......([\+\-]\d+\.\d\0){5}',
            ('{} : {} : {} : {} : {}', 'PPPPP', '?', '? temp салон')
        )

        # Для 2.30.0 это 0x031d (без фильтра), 0x031e (с фильтром?), 0x031f (сильный фильтр)
        # Напряжение в mV 5 раз
        # 1F00-3B00 (7936-15104)
        pat = r'^......(.[\x1F-\x3B]\0\0){5}'
        self.analyze_seq(
            pat,
            0,
            lambda lines: (0 <= lines[1].ts-lines[0].ts <= 3) and (0 <= lines[2].ts-lines[1].ts <= 3) and self.match(lines[1], pat) and self.match(lines[2], pat),
            # lambda lines: lines[0].ts == lines[1].ts == lines[2].ts and self.match(lines[1], pat) and self.match(lines[2], pat),
            [
                ('no filter voltage: {:5} : {:5} : {:5} : {:5} : {:5}', 'IIIII', '?', '? volt'),
                ('filter 1  voltage: {:5} : {:5} : {:5} : {:5} : {:5}', 'IIIII', '?', '? volt'),
                ('filter 2  voltage: {:5} : {:5} : {:5} : {:5} : {:5}', 'IIIII', '?', '? volt')
            ]
        )

        # Для 2.30.0 это 0x0521
        # Остаток топлива 5 раз
        # 20л 19л 18л 17л 16л
        self.analyze_by_mask(
            r'^......(.\0\0\0Л\0){5}',
            ('{} {} : {} {} : {} {} : {} {} : {} {}', 'IPIPIPIPIP', '?', '? литры')
        )

        # Для 2.30.0 это 0x096e
        # "В охране" -> "Снято с охраны"
        self.analyze_by_mask(
            r'^......"В охране"\0"Снято с охраны"\0',
            ('{} -> {}', 'PP', 'LOG_INFO', 'GUARD')
        )

        # Для 2.30.0 это 0x0ba9
        self.analyze_by_mask(
            r'^......TASK_GUARD\0[\w\xC0-\xFF]+\0...\0..\0\0..\0\0..\0\0',
            ('{}: {}: {} раз \'1\'={}ms \'0\'={}ms (vol={}%)', 'PPIiiI', 'LOG_DEBUG', 'OUTS')
        )

        # Для 2.30.0 это 0x0d35
        self.analyze_by_mask(
            r'^......STOPPED\0STOP_\S+\0\S+\0.\0\0\0.\0\0\0[ \w\xC0-\xFF]+\0',
            ('ENG_STATE:{}:{}:{}:flags=0x{:02x}:guard=0x{:02x}:src={}', 'PPPIIP', 'LOG_DEBUG', 'SYSDATA')
        )


        # def check_show(lines):
        #     cb = lambda lines: True
        #     # cb = lambda lines: lines[1].ts == lines[0].ts and self.match(lines[1], r'^......OK\0.{9}$')
        #     result = cb(seq)
        #
        #     print('++' if result else '--')
        #     print(*[self.log[_] for _ in seq], sep='\n')
        #     print()
        #     return False
        # __len = 4
        # self.analyze_seq(
        #     r'^......ДВЕРЬ ВОДИТЕЛЯ\0active\0',
        #     3,
        #     check_show,
        #     [tuple() for _ in range(__len)]
        # )


        # Для 2.30.0 это 0x0998, 0x0999
        # Какието статусы. 1 пакет
        # 'SHOCK LOW'
        # in the same ms
        # 'OK'
        self.analyze_seq(
            r'^......SHOCK LOW\0..$',
            0,
            lambda lines: lines[1].ts == lines[0].ts and self.match(lines[1], r'^......OK\0.{9}$'),
            [
                ('{}', 'P', '?', '?'),
                ('{}', 'P', '?', '?')
            ]
        )

        # Похоже так начинается загрузка
        # Первые записи в течении 1 ms. Чтото типа:
        # Дата, причина
        # Версия сигналки 900-..... модель s/n
        # тип сборки
        # Git hash сборки
        # Версии модулей
        # Загрузка модулей и куча записей по прошивке..
        # Для 2.30.0 это 0x0dab
        self.analyze_by_mask(
            r'^......\d\d-\d\d-\d\d \d\d:\d\d:\d\d\0..\0\0\w+\0',
            ('date...: {} : {} : {} : {}', 'PIPI', '? LOG_BLOCK', '?')
        )

        # Для 2.30.0 это 0x0d73
        if self.fw_ver_hash:
            self.analyze_by_mask(
                r'^......' + self.fw_ver_hash + r'\0',
                ('fw_ver_hash: {}', 'P', '? LOG_BLOCK', 'TNPROFILER')
            )

        # Для 2.30.0 это 0x0d74
        self.analyze_by_mask(
            r'^......900-00\d{3} ',
            ('Серийный номер {}', 'P', '? LOG_BLOCK', 'TNPROFILER')
        )

        # Для 2.30.0 это 0x0d76
        self.analyze_by_mask(
            r'^......\.(user|beta|regional|demo|developer)\0',
            ('Сборка: {}', 'P', 'LOG_BLOCK', 'TNPROFILER')
        )

        # Для 2.30.0 это 0x0d77
        self.analyze_by_mask(
            r'^......[0-9a-f]{10}\0',
            ('Git hash прошивки {}', 'P', 'LOG_BLOCK', 'TNPROFILER')
        )

        # Для 2.30.0 это 0x0d8a
        self.analyze_by_mask(
            r'^........[\x00-\x0f]\x08..[\x00-\x0f]\x08..\0\0..\0\0.{13}$',
            ('0x{:08x} : 0x{:08x} : {:9} : {:9}', 'IIII', '? LOG_BLOCK', 'TN_HEAP')
        )

        # modem
        self.analyze_by_mask(
            r'^......Отправка части данных по TCP/IP\0',
            ('{} {} {} {}', 'PIPP', '?', '? modem')
        )

        # Поиск строковых записей
        self.analyze_all_by_mask(
            r'......[ \.\,:\'\"\(\)\*\w\xC0-\xFF]{4,}\0[ \.\,:\'\"\(\)\*\w\xC0-\xFF]{4,}\0[ \.\,:\'\"\(\)\*\w\xC0-\xFF]{4,}\0',
            ('{} : {} : {}', 'PPP', '?PPP?', 'check me')
        )
        self.analyze_all_by_mask(
            r'......[ \.\,:\'\"\(\)\*\w\xC0-\xFF]{4,}\0[ \.\,:\'\"\(\)\*\w\xC0-\xFF]{4,}\0',
            ('{} : {}', 'PP', '?PP?', 'check me')
        )
        self.analyze_all_by_mask(
            r'......[ \.\,:\'\"\(\)\*\w\xC0-\xFF]{4,}\0',
            ('{}', 'P', '?P?', 'check me')
        )
        self.analyze_all_by_mask(
            r'........\0\0[ \.\,:\'\"\(\)\*\w\xC0-\xFF]{4,}\0[ \.\,:\'\"\(\)\*\w\xC0-\xFF]{4,}\0',
            ('{} : {} : {}', 'IPP', '?IPP?', 'check me')
        )
        self.analyze_all_by_mask(
            r'........\0\0[ \.\,:\'\"\(\)\*\w\xC0-\xFF]{4,}\0',
            ('{} : {}', 'IP', '?IP?', 'check me')
        )


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('log', type=str, help='Starline log или zip файл')
    parser.add_argument('output', type=str, help='результат', nargs='?')
    parser.add_argument('-a', '--analyze', default=False, action='store_true',  help='запустить автоанализ')
    parser.add_argument('-d', '--deep-analyze', default=False, action='store_true',  help='более глубокий и долгий автоанализ')
    parser.add_argument('-o', '--output-level', default=0, type=int, choices=[0, 1, 2], help='уровень детализации лога')
    parser.add_argument('-s', '--split', default=None, type=int, help='разбивать вывод, если время между записями превысит заданное значение')
    parser.add_argument('-g', '--group', default=False, action='store_true', help='группировать вывод по uid (только для анализа log rules)')
    args = parser.parse_args()
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
        log_filename = next(iter([fn for fn in z.namelist() if pathlib.Path(fn).suffix.lower() == '.log']), None)
        if log_filename:
            content = z.read(log_filename)
            z.close()
            return content
        else:
            print('Архив не содержит файлов .log')
            return None
    else:
        with p.open('rb') as f:
            content = f.read()
            f.close()
        return content


def main():
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
        parser = Parser(content)
        parser.output_level = args.output_level
        if args.analyze:
            parser.analyze(args.deep_analyze)
        parser.adjust_timestamp()

        if args.group:
            groups = dict()
            for i in parser.filter(skip_ts=False):
                line = parser.log[i]
                if line.uid not in groups:
                    groups[line.uid] = []
                groups[line.uid].append(line)
            for uid in groups:
                print()
                print(*groups[uid], sep='\n')
                
        else:
            last_ts = None
            for i in parser.filter(skip_ts=False):
                line = parser.log[i]
                if args.split is not None:
                    if line.uid not in parser.ts_uid:
                        if last_ts is not None:
                            dt = line.ts - last_ts
                            if dt > args.split:
                                dms = dt % 1000
                                ds = dt // 1000
                                if ds > 0:
                                    print(f'+{ds}.{dms}')
                                else:
                                    print(f'+{dms}')
                        last_ts = line.ts
                print(str(line))


if __name__ == "__main__":
    main()

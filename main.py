import random
import hashlib
import argparse
import sys
import platform
import aes
import re

from mnemonic import Mnemonic

"""
pycryptodome or pycrypto
1) Рандомизация образа флешки +
2) Посолить сиид +
3) Добавить выбор размера блока +
4) Пошифровать сиид статик ключем для полной рандомизации +
5) Вывод скорости работы и прогресса +
"""


BLOCK_SIZE = 256*256
AES_STATIC_KEY = ",dj8fneldnzorglc"


def printProgressBar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='█', printEnd=""):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=printEnd)
    # Print New Line on Complete
    # if iteration == total:
    #    print()


def bytes_to_int(local_bytes):
    result = 0
    for b in local_bytes:
        result = result * 256 + int(b)
    return result


def int_to_bytes(value, length):
    result = []
    for i in range(0, length):
        result.append(value >> (i * 8) & 0xff)
    result.reverse()
    return bytes(result)


def get_random_bytes(size):
    try:
        """
        random.randbytes only python 3.9+
        """
        return random.randbytes(size)
    except:
        try:
            import numpy
            return numpy.random.bytes(size)
        except ImportError:
            print("Please install numpy or use python 3.9")


def create_null_image(filename, size, progress=False):
    with open(filename, 'wb') as f:
        block_count = size // BLOCK_SIZE
        non_blocked_size = size % BLOCK_SIZE
        i = 0
        for _ in range(block_count):
            f.write(b"\x00" * BLOCK_SIZE)
            i += 1
            printProgressBar(i + 1, block_count, prefix='Progress:', suffix='Complete', length=50)

        f.write(b"\x00" * non_blocked_size)


def create_random_image(filename, size, progress=False):
    with open(filename, 'wb') as f:
        block_count = size // BLOCK_SIZE
        non_blocked_size = size % BLOCK_SIZE
        i = 0
        for _ in range(block_count):
            f.write(get_random_bytes(BLOCK_SIZE))
            i += 1
            printProgressBar(i + 1, block_count, prefix='Progress:', suffix='Complete', length=50)
        f.write(get_random_bytes(non_blocked_size))


def write_random_image(filename, size, progress=False):
    with open(filename, 'rb+') as f:
        block_count = size // BLOCK_SIZE
        non_blocked_size = size % BLOCK_SIZE
        i = 0
        for _ in range(block_count):
            f.write(get_random_bytes(BLOCK_SIZE))
            i += 1
            printProgressBar(i + 1, block_count, prefix='Progress:', suffix='Complete', length=50)
        f.write(get_random_bytes(non_blocked_size))


def gen_offset_from_seed(seed, size, local_block_size, output_size):
    if output_size < size:
        return False
    seed_hash = hashlib.sha512(seed).digest()
    block_count = size // local_block_size
    non_block_len = size % local_block_size
    # print("blocks: %d\nnon_block_len: %d" % (block_count, non_block_len))
    base = bytes_to_int(seed_hash)
    result = list()

    if non_block_len != 0:
        result.append({"offset": base % output_size, "len": non_block_len})
        block_count += 1

    while block_count != len(result):
        base = bytes_to_int(hashlib.sha512(int_to_bytes(base, 64)).digest())
        new_offset = base % output_size
        for r in result:
            if r["offset"] <= new_offset <= r["offset"] + r["len"]:
                break
            if r["offset"] <= new_offset + local_block_size <= r["offset"] + r["len"]:
                break
            if (new_offset > output_size) or (new_offset + r["len"]) > output_size:
                break
        else:
            result.append({"offset": new_offset, "len": local_block_size})

    result2 = list()
    for i in result:
        result2.append(i["offset"])
    """
    result2 = sorted(result2)
    for i in result2:
        print("start: %d\tend: %d" % (i, i + 1024 ** 3))
    """
    return result


def write_on_offset(filename, offset, data):
    f = open(filename, 'rb+')
    f.seek(offset, 0)
    f.write(data)
    f.close()


def read_on_offset(filename, offset, byte_count):
    with open(filename, 'rb') as f:
        f.seek(offset, 0)
        data = f.read(byte_count)
        f.close()
        return data


def get_file_size(filename):
    with open(filename, 'rb') as f:
        f.seek(0, 2)
        size = f.tell()
        return size


def bxor(ba1, ba2):
    """ XOR two byte strings """
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def save(image_name, input_file_name, local_block_size):
    mnemo = Mnemonic("english")
    image_size = get_file_size(image_name)
    input_file_size = get_file_size(input_file_name)

    # print(image_size)
    # print(input_file_size)
    random_seed = get_random_bytes(8)
    data = \
        random_seed + int_to_bytes(local_block_size, 8) + int_to_bytes(image_size, 8) + int_to_bytes(input_file_size, 8)

    my_aes = aes.AESCipher(AES_STATIC_KEY)
    data = my_aes.encrypt(data)

    seed = mnemo.to_mnemonic(data)
    print("SEED:", seed)

    # data = mnemo.to_entropy(seed)
    # data = bxor(data, XOR_KEY)\
    # image_size = bytes_to_int(data[0:8])
    # input_file_size = bytes_to_int(data[9:16])

    image_offsets = gen_offset_from_seed(seed.encode("ascii"), input_file_size, local_block_size,
                                         image_size)
    file_offset = 0
    i = 0
    for image_offset in image_offsets:
        write_on_offset(image_name, image_offset["offset"],
                        read_on_offset(input_file_name, file_offset, image_offset["len"])
                        )
        file_offset += image_offset["len"]
        i += 1
        printProgressBar(i, len(image_offsets), prefix='Progress:', suffix='Complete', length=50)


def extract(image_name, output_file_name, seed, local_block_size):
    with open(output_file_name, "w") as f:
        f.close()

    mnemo = Mnemonic("english")
    data = mnemo.to_entropy(seed)

    my_aes = aes.AESCipher(AES_STATIC_KEY)
    data = my_aes.decrypt(data)
    data = data[8:] # stip random_seed

    local_block_size = bytes_to_int(data[0:8])
    image_size = bytes_to_int(data[9:16])
    input_file_size = bytes_to_int(data[17:24])

    image_offsets = gen_offset_from_seed(seed.encode("ascii"), input_file_size, local_block_size,
                                         image_size)

    file_offset = 0
    i = 0
    for image_offset in image_offsets:
        write_on_offset(output_file_name, file_offset,
                        read_on_offset(image_name, image_offset["offset"], image_offset["len"])
                        )
        file_offset += image_offset["len"]
        i += 1
        printProgressBar(i, len(image_offsets), prefix='Progress:', suffix='Complete', length=50)


def mnemo_to_bytes(text):
    data = {"k": 1024,
            "m": 1024 ** 2,
            "g": 1024 ** 3,
            "t": 1024 ** 4}
    try:
        result = re.findall(r"(\d+)([kmgt])", text)[0]
        return int(result[0])*data[result[1]]
    except IndexError:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--device', type=str, help="", action='store', required=True)
    parser.add_argument('--input', type=str, help="", action='store')
    parser.add_argument('--output', type=str, help="", action='store')
    parser.add_argument('-s', help="", action='store_true', default=False)
    parser.add_argument('-e', help="", action='store_true', default=False)
    parser.add_argument('--seed', type=str, help="", action='store')
    parser.add_argument('--rndimage', help="", action='store_true', default=False)
    parser.add_argument('--block_size', help="", action='store', default="32m")

    args = parser.parse_args()

    input_file_name = args.input
    image_name = args.device
    output_file_name = args.output

    bytes_block_size = mnemo_to_bytes(args.block_size)
    if not bytes_block_size:
        print("Error parsed block_size")
        sys.exit(-1)

    if args.rndimage:
        write_random_image(image_name, get_file_size(image_name), progress=True)
        sys.exit(0)

    if args.s:
        save(image_name, input_file_name, bytes_block_size)
        sys.exit(0)

    if args.e:
        try:
            extract(image_name, output_file_name, args.seed, bytes_block_size)
            sys.exit(0)
        except AttributeError:
            print("Seed error")
            sys.exit(-1)


if __name__ == '__main__':
    main()

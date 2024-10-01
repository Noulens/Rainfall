import sys
import struct
import binascii


def generate_pattern(length):
    if length > 20280 or length < 0:
        return "invalid"

    pattern = ""
    maj = ord('A')
    low = ord('a')
    num = ord('0')
    i = 0
    idx = 0

    while i < length:
        idx = i % 3
        if idx == 0:
            if low == ord('z') and num > ord('9'):
                low = ord('a')
                num = ord('0')
                maj += 1
            pattern += chr(maj)
            i += 1
        elif idx == 1:
            if num > ord('9'):
                num = ord('0')
                low += 1
            pattern += chr(low)
            i += 1
        else:
            pattern += chr(num)
            i += 1
            num += 1

    return pattern


def find_offset(pattern_file, address):
    read_content = ""

    if address.startswith('0x'):
        hex_bytes = binascii.unhexlify(address[2:])
    else:
        hex_bytes = binascii.unhexlify(address)

    with open(pattern_file, "r") as file:
        read_content = file.read()

    is_big_endian = struct.pack('H', 1) == '\x00\x01'
    if not is_big_endian:
        hex_bytes = hex_bytes[::-1]

    ascii_char = ''.join(chr(ord(byte)) for byte in hex_bytes)
    index = read_content.find(ascii_char)
    if index != -1:
        print("offset found at: {}".format(index))
    else:
        print("Pattern not found.")


def main():
    pattern_string = ""
    pattern_len = 0
    if len(sys.argv) == 1:
        pattern_string = generate_pattern(100)
        print(pattern_string)
    elif len(sys.argv) == 2:
        try:
            pattern_len = int(sys.argv[1])
            pattern_string = generate_pattern(pattern_len)
            print(pattern_string)
        except:
            print("Error: Argument '{}' is not an integer.".format(sys.argv[1]))
            return
    else:
        find_offset(sys.argv[1], sys.argv[2])
        return


if __name__ == "__main__":
    main()

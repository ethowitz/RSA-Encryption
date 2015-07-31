import os.path
import hashlib
import sys
import math

################################################################################
#                                 ~Encryption~                                 #
################################################################################

# pads input file according to optimal asymmetric encryption padding scheme
# based on info from ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf
def oaep_encoding(n_len, message, label=""):
        if len(label) > 2**61 - 1:
                print("label too long")
                sys.exit(1)

        l_hash = hashlib.sha256(label.encode())
        h_len = l_hash.digest_size

        if len(message) > n_len - 2 * h_len - 2:
                print("message too long")
                sys.exit(1)

        data_block = bytearray.fromhex(l_hash.hexdigest())

        # append one byte for each octet
        for bit in range(n_len - len(message) - 2 * h_len - 2):
                data_block.append(0)
        data_block.append(1)

        message = bytearray(message.encode())
        data_block += message

        seed = bytearray(os.urandom(h_len))

        data_block_mask = mask_gen_function(seed, n_len - h_len - 1)
        masked_data_block = bitwise_xor(data_block, data_block_mask)

        seed_mask = mask_gen_function(masked_data_block, h_len)
        masked_seed = bitwise_xor(seed, seed_mask)

        encoded_message = bytearray()
        encoded_message.append(0)
        encoded_message = encoded_message + masked_seed + masked_data_block

        return encoded_message

# output must be pseudorandom
# MGF1
# TODO: fix length issue
def mask_gen_function(seed, m_len):
        seed = hashlib.sha256(seed)
        h_len = seed.digest_size

        if m_len > (2 ** 32) * h_len:
                print("mask too long")
                sys.exit(1)

        t = bytearray()
        t.append(0)
        for c in range(0, math.ceil(float(m_len) / float(h_len)) - 1):
                t += i2osp(c, 4)
        return t[0:m_len]


def oaep_decoding(n_len, message, label=""):
        l_hash = hashlib.sha256(label.encode())
        h_len = l_hash.digest_size
        message = bytearray(message)

        y = message[0]
        masked_seed = bytearray()
        masked_data_block = bytearray()

        for i in range(0, h_len):
                masked_seed.append(message[i + 1])
        for i in range(0, n_len - h_len - 1):
                masked_data_block.append(message[i + h_len + 1])

        # what should n_len be? number of octets of integer?
        seed_mask = mask_gen_function(masked_data_block, h_len)
        seed = bitwise_xor(masked_seed, seed_mask)
        data_block_mask = mask_gen_function(seed, n_len - h_len - 1)

        data_block = bitwise_xor(masked_data_block, data_block_mask)

        l_hash_prime = bytearray()
        for i in range(0, h_len):
                l_hash_prime.append(data_block[i])

        count = l_hash.digest_size
        while data_block[count] != 1:
                count -= 1
        count += 1

        message = bytearray()
        for i in range(count, len(data_block)):
                message.append(data_block[i])
        message = message.decode()

        return message

# function to compute bitwise  XOR operation for two bytearrays
# TODO: bytearray1 and bytearray2 will be the same length, so logic
#       should be changed
def bitwise_xor(bytearray1, bytearray2):
        result = bytearray()
        if len(bytearray1) > len(bytearray2):
                for c in range(0, len(bytearray1)):
                        if c < len(bytearray2):
                                result.append(bytearray1[c] ^ bytearray2[c])
                        else:
                                # A xor 0 = A
                                result.append(bytearray1[c])
        else:
                for c in range(0, len(bytearray2)):
                        if c < len(bytearray1):
                                result.append(bytearray1[c] ^ bytearray2[c])
                        else:
                                # A xor 0 = A
                                result.append(bytearray2[c])
        return result

# converts an octet string to an integer
# m must be bytearray
# OS2IP --> Octet String TO Integer Primative
def os2ip(m):
        result = 0
        m_len = len(m)
        for b in range(0, m_len):
                #ASSUMPTION: m[0] = ms-byte
                result += (m[b] * (256 ** (m_len - b - 1)))
        return result

def i2osp(x, x_len):
        if x >= 256 ** x_len:
                print("integer too large")
                sys.exit(1)
        result = dec_to_baseX(x, 256)

        # prepend list with zero octets until desired length is reached
        while len(result) < x_len:
                result.insert(0, 0)

        return result

# dec_to_baseX()
#        purpose: Converts a number of radix 10 to a number of a different radix
#        parameters: num = decimal number to convert; radix = desired radix
#        return value: number converted to the specified radix (as a string)
def dec_to_baseX(num, radix):
        result = bytearray()
        while num >= radix:
                rem = num % radix
                num //= radix
                result.insert(0, rem)
        result.insert(0, num % radix)
        return result

def encrypt_message(m):
        n = 0
        e = 0
        with open("public_key", "r") as f:
                n = int(f.readline())
                e = int(float(f.readline()))

        n_len = len(dec_to_baseX(n, 2)) // 8

        message = oaep_encoding(n_len, m)
        message = os2ip(message)
        message = encryption_primative(message, n, e)
        ciphertext = i2osp(message, len(str(n)))
        
        return ciphertext

def encryption_primative(m, n ,e):
        if m < 0 or m > n - 1:
                print("message representative out of range")
                sys.exit(1)

        return pow(m, e, n)

# m is byterray
def decrypt_message(m):
        n = 0
        d = 0
        with open("private_key", "r") as f:
                n = int(f.readline())
                d = int(f.readline())

        # check length
        c = os2ip(m)
        n_len = len(dec_to_baseX(n, 256))

        message = decryption_primative(c, n ,d)
        encoded_message = i2osp(message, len(str(n)))
        message = oaep_decoding(n_len, encoded_message)

        return message


def decryption_primative(c, n ,d):
        if c < 0 or c > n - 1:
                print("ciphertext out of range")
                sys.exit(1)

        return pow(c, d, n)

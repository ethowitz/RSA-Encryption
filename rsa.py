import prime
import random
import decimal
import os.path
import hashlib
import sys
import binascii

################################################################################
#			       ~Key Generation~                                #
################################################################################

# Euler's totient function implementation (where p1, p2 are prime integers)
def totient(p1, p2):
	return (p1 - 1) * (p2 - 1)	

def generate_filename(base):
	while os.path.isfile(base):
		base = base + ".copy"
	return base

def write_to_file(modulus, exp, filename):
	filename = generate_filename(filename)
	with open(filename, "w") as f:
		f.write(str(modulus))
		f.write("\n")
		f.write(str('{:f}'.format(exp)))

# Euclidian algorithm implementation
def gcd(n1, n2):
	if n2 == 0:
		return n1
	else:
		return gcd(n2, n1 % n2)

# extended Euclidian algorithm to find modular multiplicative inverse of 
#	e (mod phi(n))
# adopted from 
#    https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers
def modular_multi_inverse(a, n):
	decimal.getcontext().prec = 506

	t = 0
	r = n
	new_t = 1
	new_r = a

	while new_r != 0:
		quotient = decimal.Decimal(r) / decimal.Decimal(new_r)
		t = new_t
		new_t = t - quotient * new_t
		r = new_r
		new_r = r - quotient * new_r
	if t < 0:
		t = t + n
	return t

# size is in bits
# adopted from https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation
def generate_keys(size=2048):
	print("Generating keys...", end="")

	p = prime.generate_prime(size / 8)
	q = p

	while p == q:
		q = prime.generate_prime(size / 8)

	n = p * q
	phi_n = totient(p, q)

	# public key exponent
	e = 65537

	# if e and phi_n are not coprime (unlikely)
	while gcd(e, phi_n) != 1:
		e += 2

	# private key exponent
	d = modular_multi_inverse(e, phi_n)

	# write public key to file
	write_to_file(n, e, "public_key")
	#write private key to file
	write_to_file(n, d, "private_key")

	print("done")

################################################################################
#			         ~Encryption~                                  #
################################################################################

def random_octet(length):
	rand = random.SystemRandom().randint(pow(10, length - 1), pow(10, length))
	return binascii.hexlify(str(rand).encode())

# pads input file according to optimal asymmetric encryption padding scheme
# based on info from ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf
def oaep_padding(n_len, message, label=""):
	if len(label) > 2**61 - 1:
		print("label too long")
		sys.exit(1)

	l_hash = hashlib.sha256(label.encode())

	if len(message) > n_len - 2 * l_hash.digest_size - 2:
		print("message too long")
		sys.exit(1)

	data_block = bytearray.fromhex(l_hash.hexdigest())

	#append one byte for each octet
	for bit in range(n_len - len(message) - 2 * l_hash.digest_size - 2):
		data_block.append(0)
	data_block.append(1)

	message = bytearray(message.encode())
	data_block += message

	seed = binascii.hexlify(random_octet(l_hash.digest_size))
	seed = bytearray.fromhex(seed.decode())
	
	# length as second input?
	data_block_mask = bytearray.fromhex(hashlib.sha256(seed).hexdigest())
	masked_data_block = bitwise_xor(data_block, data_block_mask)
	
	# length as second input?
	seed_mask = hashlib.sha256(masked_data_block).hexdigest()
	seed_mask = bytearray.fromhex(seed_mask)

	masked_seed = bitwise_xor(seed, seed_mask)

	encoded_message = bytearray()
	encoded_message.append(0)
	encoded_message = encoded_message + masked_seed + masked_data_block
	print(encoded_message)

	return encoded_message

# function to compute bitwise XOR operation for two bytearrays
def bitwise_xor(bytearray1, bytearray2):
	result = bytearray()
	if len(bytearray1) > len(bytearray2):
		for c in bytearray1:
			if c < len(bytearray2):
				result.append(bytearray1[c] ^ bytearray2[c])
			else:
				# A xor 0 => A
				result.append(bytearray1[c])
	else:
		for c in bytearray2:
			if c < len(bytearray1):
				result.append(bytearray1[c] ^ bytearray2[c])
			else:
				# A xor 0 => A
				result.append(bytearray2[c])
	return result

def to_octet_string(m):
	octet_string = ''
	for c in m:
		octet_string += '{:08b}'.format(ord(c), 'b')
	return octet_string

def hex_to_bin(m):
	octet_string = ''
	for c in range(0, len(m), 2):
		octet_string += '{0:0>8}'.format(str(bin(int(m[c:c+2], 16)))[2:])
	return octet_string

# converts an octet string to an integer
def os2ip(m):
	result = 0
	count = 1
	print(len(m))
	for c in range(0, len(m), 8):
		#				 extra 4 bits on m...
		result += int(m[c:c+8], 2) * (256 ** ((len(m) // 8) - count))
		count += 1
	return result

def i2osp(m):
	if m >= 256 ** len(m):
		print("integer too large")
		sys.exit(1)

	return int(m, 256)

def encrypt_message(m):
	message = oaep_padding(2048, m)
	message = os2ip(message)
	
	n = 0
	e = 0
	with open("public_key", "r") as f:
		n = int(f.readline())
		e = int(f.readline())

	message = (message ** e) % n
	ciphertext = i2osp(message)

	return ciphertext

print(encrypt_message('ethan'))
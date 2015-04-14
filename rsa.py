import prime
import random
import decimal
import os.path
import hashlib
import sys
import binascii
import math

################################################################################
#			       ~Key Generation~                                #
################################################################################

# totient()
# 	purpose: This is an implementation for Euler's totient function.  This
#		particular version is only valid for when p1 and p2 are prime
#		integers
#	parameters: p1 and p2 are prime integers
#	return value: Gives phi(n), where n = p1 * p2, and phi(n) is the 
#		count of the totatives of n
#	references:
#		https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation
#		https://en.wikipedia.org/wiki/Euler%27s_totient_function
def totient(p1, p2):
	return (p1 - 1) * (p2 - 1)	

# generate_filename()
#	purpose: Generates a filename by appending ".copy" to the end of the
#		filename if the input filename already exists in the current
#		working directory
#	parameters: base = the desired filename
#	return value: final filename
def generate_filename(base):
	while os.path.isfile(base):
		base = base + ".copy"
	return base

# write_to_file()
#	purpose: Writes the input encryption key to a file, with the modulus
#		as the first line and the public/private exponent as the second
#		line
#	parameters: modulus = the modulus of the public and private keys;
#		exp = public or private exponent;
#		filename = file into which the key is being written
#	return value: none
def write_to_file(modulus, exp, filename):
	filename = generate_filename(filename)
	with open(filename, "w") as f:
		f.write(str(modulus))
		f.write("\n")
		f.write(str('{:f}'.format(exp)))

# gcd()
#	purpose: Uses the Euclidean algorithm to find the greatest common
#		divisor of the two input numbers
#	parameters: n1 and n2 are the numbers whose greatest common divisor is
#		is being found
#	return value: the greatest common divisor of the two input numbers
#	references:
#		https://en.wikipedia.org/wiki/Euclidean_algorithm
def gcd(n1, n2):
	if n2 == 0:
		return n1
	else:
		return gcd(n2, n1 % n2)

# modular_multi_inverse()
#	purpose: Finds the modular multiplicative inverse of a (mod n)
#	parameters: a = the number whose modular multiplicative inverse is being
#		calculated; n = the modulus of a
#	return value: The modular multiplicative inverse of a (mod n)
#	references: 
# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers
# TODO: sometimes function stalls during calculation 
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

# generate_keys()
#	purpose: Generates two associated public and private keys and writes
#		them to separate files
#	parameters: size = desired size of the keys in bits (default size is
#		2048 bits)
#	return value: none
#	references: 
#		https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation
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

# length is in bytes
def random_octet(length):
	rand = random.SystemRandom().randint(pow(10, length - 1), pow(10, length))
	return binascii.hexlify(str(rand).encode())

# pads input file according to optimal asymmetric encryption padding scheme
# based on info from ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf
def oaep_encoding(n_len, message, label=""):
	if len(label) > 2**61 - 1:
		print("label too long")
		sys.exit(1)

	l_hash = hashlib.sha256(label.encode())

	if len(message) > n_len - 2 * l_hash.digest_size - 2:
		print("message too long")
		sys.exit(1)

	data_block = bytearray.fromhex(l_hash.hexdigest())

	# append one byte for each octet
	for bit in range(n_len - len(message) - 2 * l_hash.digest_size - 2):
		data_block.append(0)
	data_block.append(1)

	message = bytearray(message.encode())
	data_block += message

	seed = binascii.hexlify(random_octet(l_hash.digest_size))
	seed = bytearray.fromhex(seed.decode())
	
	# length as second input? --> mask generation function
	data_block_mask = bytearray.fromhex(hashlib.sha256(seed).hexdigest())
	masked_data_block = bitwise_xor(data_block, data_block_mask)
	
	# length as second input? --> mask generation function
	seed_mask = hashlib.sha256(masked_data_block).hexdigest()
	seed_mask = bytearray.fromhex(seed_mask)

	masked_seed = bitwise_xor(seed, seed_mask)

	encoded_message = bytearray()
	encoded_message.append(0)
	encoded_message = encoded_message + masked_seed + masked_data_block

	return encoded_message

# output must be pseudorandom
# MGF1
def mask_gen_function(seed, m_len, h_len):
	if m_len > (2 ** 32) * h_len:
		print("mask too long")
		sys.exit(1)

	t = b'00000000'

	#for counter in range(0, math.ceil(m_len/h_len) - 1):


def oaep_decoding(n_len, message, label=""):
	l_hash = hashlib.sha256(label.encode())
	h_len = l_hash.digest_size
	message = bytearray(message)
	
	y = message[0]
	masked_seed = bytearray()
	masked_data_block = bytearray()

	for i in range(0, h_len):
		masked_seed.append(message[i + 1])
		masked_data_block.append(message[i + h_len])

	seed_mask = hashlib.sha256(masked_data_block)
	seed = bitwise_xor(masked_seed, seed_mask)
	data_block_mask = hashlib.sha256(seed)

	data_block = bitwise_xor(masked_data_block, data_block_mask)

	l_hash_prime = bytearray()
	for i in range(0, h_len):
		l_hash_prime.append(data_block[i])

	count = l_hash
	while data_block[count] != 1:
		count += 1
	count += 1

	message = bytearray()
	for i in range(count, len(data_block)):
		message.append(data_block[i])
	message = message.decode()

	return message

# function to compute bitwise XOR operation for two bytearrays
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
def os2ip(m):
	result = 0
	count = 1
	for b in range(0, len(m)):
		result += m[b] * (256 ** (len(m) - count))
		count += 1
	return result

def i2osp(x, x_len):
	if x >= 256 ** x_len:
		print("integer too large")
		sys.exit(1)
	return dec_to_baseX(m, 256)

# dec_to_baseX()
#	purpose: Converts a number of radix 10 to a number of a different radix
#	parameters: num = decimal number to convert; radix = desired radix
#	return value: number converted to the specified radix (as a string)
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

	# length of n has to be in octets
	message = oaep_encoding(len(str(n)), m)
	message = os2ip(message)
	message = encryption_primative(message, n, e)
	ciphertext = i2osp(message)

	return ciphertext

def encryption_primative(m, n ,e):
	if m < 0 or m > n - 1:
		print("message representative out of range")
		sys.exit(1)

	return pow(m, e, n)

def decrypt_message(m):
	n = 0
	d = 0
	with open("private_key", "r") as f:
		n = int(f.readline())
		e = int(f.readline())

	# check length
	m = bytearray(m.encode())
	c = os2ip(m)
	message = decryption_primative(c, n ,d)
	encoded_message = i2osp(message)
	message = oaep_decoding(len(str(n)), message)

	return message


def decryption_primative(m, n ,d):
	if m < 0 or m > n - 1:
		print("ciphertext out of range")
		sys.exit(1)

	return pow(m, d, n)
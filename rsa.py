import prime
import random
import decimal
import os.path
import hashlib
import sys
import binascii
import base64

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
	with open(filename, "w") as file:
		file.write(str(modulus))
		file.write("\n")
		file.write(str('{:f}'.format(exp)))
		file.write("\n")

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

	ps = ''
	for bit in range(n_len - len(message) - 2 * l_hash.digest_size - 2):
		ps = ps +'00000000'

	hex_one = '00000001'
	message = to_octet_string(message)
	
	data_block = hex_to_bin(str(l_hash.hexdigest())) + ps + hex_one + message

	seed = random_octet(l_hash.digest_size) # correct size?
	
	# length as second input?
	data_block_mask = hex_to_bin(hashlib.sha256(seed).hexdigest())
	masked_data_block = int(data_block, 2) ^ int(data_block_mask, 2)
	
	# length as second input?
	seed_mask = hex_to_bin(hashlib.sha256(str(masked_data_block).encode()).hexdigest())
	masked_seed = int(seed, 16) ^ int(seed_mask, 2)

	encoded_message = ('00000000' + bin(masked_seed)[2:]
		+ bin(masked_data_block)[2:])
	
	return encoded_message

def to_octet_string(m):
	octet_string = ''
	for c in m:
		octet_string += format(ord(c), 'b')
	return octet_string

def hex_to_bin(m):
	octet_string = ''
	for c in range(0, len(m), 2):
		octet_string += str(bin(int(m[c:c+2], 16)))[2:]
	return octet_string

print(oaep_padding(256, 'ethan'))











	


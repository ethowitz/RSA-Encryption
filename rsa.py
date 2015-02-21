import prime
import random
import decimal
import os.path
import hashlib
import sys
import binascii
import os

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

# pads input file according to optimal asymmetric encryption padding scheme
# based on info from ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf
def oaep_padding(n_len, message, label=""):
	if label.len() > (2**61 - 1) / 8:
		print("label too long")
		sys.exit(1)

	l_hash = hashlib.sha256(label.encode())

	if message.len() > n_len - 2 * l_hash.digest_size() - 2:
		print("message too long")
		sys.exit(1)

	ps = ""
	for bit in 256 - n_len - 2 * l_hash.digest_size() - 1:
		ps = ps +'0'
	
	ps = binascii.hexlify(ps.encode())
	hex_one = binascii.hexlify('01'.encode()) # wrong

	data_block = l_hash.digest() + ps + hex_one + message
	









	


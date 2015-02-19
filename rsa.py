import prime
import random
import decimal

def totient(p1, p2):
	return (p1 - 1) * (p2 - 1)

#def encrypt(message, pub_key):	
	
#def write_to_file(key, filename):

# Euclidian algorithm implementation
def gcd(n1, n2):
	if n2 == 0:
		return n1
	else:
		return gcd(n2, n1 % n2)

# extended Euclidian algorithm to find modular multiplicative inverse of 
#	e (mod phi(n))
def modular_multi_inverse(a, n):
	decimal.getcontext().prec = 512

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

#def generate_filename():

# size is in bits
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

	print("done")

	print("p: " + str(p))
	print("q: " + str(q))
	print("n: " + str(n))
	print("phi(n): " + str(phi_n))
	print("e: " + str(e))
	print("d: " + str(d))

generate_keys()




		


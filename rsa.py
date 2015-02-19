import prime

class RSA:
	def phi(p1, p2):
		return (p1 - 1) * (p2 - 1)

	def encrypt(message, pub_key):	
	
	# size is in bits
	def generate_key(size=2048):
		if size % 8 != 0:
			print("ERROR: key size must be divisible by 8")
			return
		return Prime.generate_prime(size / 8)
		
	def write_to_file(key):
		with open(rsa_key, w) as file:
			f.write(str(key))


	#def generate_filename():
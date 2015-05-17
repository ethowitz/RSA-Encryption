import binascii

def generate_key(length):
	return binascii.hexlify(os.urandom(length))

def encrypt_file(f, key):
	f.open("rb") #open file for reading bytes
	s = file.read() #reads in string of bytes composing file
	encrypted = ""
	for byte in range(os.stat(f).st_size): #for each byte in string
		encrypted = encrypted + ord(key[byte]) + ord(s) 
		
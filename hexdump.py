import binascii
import sys

def hexdump(file_in):
	with open(file_in, "rb") as file:
		byte = file.read(1)
		while byte:
			print(binascii.hexlify(byte).decode(), end="")
			print(" ", end="")
			byte = file.read(1)

hexdump(sys.argv[1])
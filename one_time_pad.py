import os, sys, vigenere

# file from command line argument
f = sys.argv[1]

file_size = os.stat(f).st_size
key = generate_key(file_size)
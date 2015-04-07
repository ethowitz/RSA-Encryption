#Cryptography

This repository contains an implementation of the RSA encryption standard
written in Python.  The implementation follows most of the guidelines and 
standards given in this document: 
ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf

##Files

###rsa.py
This file contains the module with the functions which are directly involved in 
encrypting a file.  It deals with key generation, encoding/decoding, 
encryption/decryption, and key file creation.

###prime.py
This file contains the module with the functions which are involved with 
prime number generation.

###hexdump.py
This file contains a function which produces a hexdump of the input file given
as a command-line argument.

##References
References for implementation specifics are given in the .py files.
import os
import decimal
import prime
import rsa
import math

# totient()
#         purpose: This is an implementation for Euler's totient function.  This
#                particular version is only valid for when p1 and p2 are prime
#                integers
#        parameters: p1 and p2 are prime integers
#        return value: Gives phi(n), where n = p1 * p2, and phi(n) is the
#                count of the totatives of n
#        references:
#                https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation
#                https://en.wikipedia.org/wiki/Euler%27s_totient_function
def totient(p1, p2):
        return (p1 - 1) * (p2 - 1)

# generate_filename()
#        purpose: Generates a filename by appending ".copy" to the end of the
#                filename if the input filename already exists in the current
#                working directory
#        parameters: base = the desired filename
#        return value: final filename
def generate_filename(base):
        while os.path.isfile(base):
                base = base + ".copy"
        return base

# write_to_file()
#        purpose: Writes the input encryption key to a file, with the modulus
#                as the first line and the public/private exponent as the second
#                line
#        parameters: modulus = the modulus of the public and private keys;
#                exp = public or private exponent;
#                filename = file into which the key is being written
#        return value: none
def write_to_file(modulus, exp, filename):
        filename = generate_filename(filename)
        with open(filename, "w") as f:
                f.write(str(modulus))
                f.write("\n")
                f.write(str('{:f}'.format(exp)))

# gcd()
#        purpose: Uses the Euclidean algorithm to find the greatest common
#                divisor of the two input numbers
#        parameters: n1 and n2 are the numbers whose greatest common divisor is
#                is being found
#        return value: the greatest common divisor of the two input numbers
#        references:
#                https://en.wikipedia.org/wiki/Euclidean_algorithm
def gcd(n1, n2):
        if n2 == 0:
                return n1
        else:
                return gcd(n2, n1 % n2)

# modular_multi_inverse()
#        purpose: Finds the modular multiplicative inverse of a (mod n)
#        parameters: a = the number whose modular multiplicative inverse is
#               being calculated; n = the modulus of a
#        return value: The modular multiplicative inverse of a (mod n)
#        references:
# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers
# TODO: sometimes function stalls during calculation
# TODO: when precision is greater than 506, function runs indefinitely...
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
#        purpose: Generates two associated public and private keys and writes
#                them to separate files
#        parameters: size = desired size of the keys in bits (default size is
#                2048 bits)
#        return value: none
#        references:
#                https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation
# TODO: WRONG!!!!
def generate_keys(size=2048):
        e = 65537

        p = prime.generate_prime(1024)
        q = prime.generate_prime(1024)

        n = str(p * q)[0:size]
        n = int(n)
        phi_n = totient(p, q)

        # if e and phi_n are not coprime (unlikely)
        while gcd(e, phi_n) != 1:
                e += 2

        # private key exponent
        d = modular_multi_inverse(e, phi_n)

        # write public key to file
        write_to_file(n, e, "public_key")
        #write private key to file
        write_to_file(n, d, "private_key")

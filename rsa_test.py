import rsa
import prime
import keygen

keygen.generate_keys()
message = "hello"
encrypted = rsa.encrypt_message(message)
decrypted = rsa.decrypt_message(encrypted)
print(encrypted)

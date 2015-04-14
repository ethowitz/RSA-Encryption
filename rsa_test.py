import rsa
import prime

#rsa.generate_keys()
message = "hello"
encrypted = rsa.encrypt_message(message)
decrypted = rsa.decrypt_message(encrypted)
print(decrypted)
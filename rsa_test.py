import rsa
import prime

rsa.generate_keys()
message = "ethan"
encrypted = rsa.encrypt_message(message)
decrypted = rsa.decrypt_message(encrypted)
print(decrypted)
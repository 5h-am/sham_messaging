from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

while True:
    password = input("Set your password:")
    if not password:
        print("You can't leave the password empty")
        continue
    else:
        confirm = input("Confirm your password:")
        if confirm == password:
            print("Password set")
            break
        else:
            print("Both passwords don't match")
            continue

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

with open("private_key.pem","wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    ))

with open("public_key.pem","wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

print("RSA pair generated")

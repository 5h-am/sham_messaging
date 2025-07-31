from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def send_message():
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    message = input("\nEnter your message:").encode()
    encrypted_message = public_key.encrypt(
        message,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=  hashes.SHA256(),
        label=None,
        ))
    with open("encrypted_message.bin", 'wb')as f:
        f.write(encrypted_message)

def passwordcheck():
    k = 5
    while True:
        password = input("\nEnter the password:").encode()
        try:
            with open ('private_key.pem', "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password)
                return private_key                
        except:
            print("\nThe password is wrong")
            k -= 1
            if k > 0:
                print(f"\nYou have {k} chances left")
                continue
            else:
                print("\nYou have no chances left. Access Denied")
                return False

def recieve_message():
    private_key = passwordcheck()
    if private_key:    
        with open("encrypted_message.bin", "rb")as f:
            encrypted = f.read()

        decrypted_message = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"\nMessage: {decrypted_message.decode()}\n")
    else:
        return False

print()
print("="*100)
print("Sham".center(100))
print("="*100)

while True:
    print("\n1.Send Message")
    print("2.Recieve Message")
    print("3.Exit the program")
    try:
        menu = int(input("\nWhat do you want to do(1/2/3)?:"))
        if menu not in range(1,4):
            raise ValueError
    except ValueError:
        print("\nError, Enter a valid command")
        continue
    if menu == 1:
        send_message()
        continue
    elif menu == 2:
        check = recieve_message()
        if check:
            continue
        else:
            break
    elif menu == 3:
        print("\nGoodbye, Have a nice day\n")
        break
        



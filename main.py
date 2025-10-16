import json 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding 
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import base64
import hashlib
import os
import secrets
import string
import random
import pwinput




masterPassword = None
passwordData = {} #stores password data in dict

PUBLIC_KEY_FILE = "public.pem"
PRIVATE_KEY_FILE = "private.pem"


#master password 
def setupMasterPassword():
    if os.path.exists("master.hash"):  #master password exists
        while True: 
            masterInput = pwinput.pwinput("Enter the Master Password: ", mask="*")
            hashInput = hashlib.sha256(masterInput.encode()).hexdigest()
            with open("master.hash", "r") as f:
                savedHash = f.read()
            if hashInput == savedHash:
                print("Welcome!")
                return masterInput  #return the password
            else: 
                print("Incorrect password, try again.")
    else:  #create a new master password
        while True:
            masterInput = pwinput.pwinput("Create a master Password: ", mask="*")
            confirmInput = pwinput.pwinput("Confirm master password: ",mask="*")
            if masterInput == confirmInput:
                hashedMaster = hashlib.sha256(masterInput.encode()).hexdigest()
                with open("master.hash", "w") as f:
                    f.write(hashedMaster)
                print("Master password successfully created!")
                return masterInput  #return the password
            else:
                print("Password did not match, try again.")


def generateRSAKeyRepair(masterPassword):
    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    publicKey = privateKey.public_key()

    # save public key
    pubPem = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(pubPem)

    # save private key encrypted with master password
    encPrivatePem = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(masterPassword.encode())
    )
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(encPrivatePem)

    return publicKey, privateKey

def loadPublicKey():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        pubPem = f.read()
    publicKey = serialization.load_pem_public_key(pubPem)
    return publicKey

def loadPrivateKey(masterPassword: str):
    if not masterPassword:
        raise ValueError("loadPrivateKey requires a valid masterPassword (not None).")
    with open(PRIVATE_KEY_FILE, "rb") as f:
        privPem = f.read()
    privateKey = serialization.load_pem_private_key(privPem, password=masterPassword.encode())
    return privateKey

def encryptWithPublic(plaintext: str) -> str:
    if not os.path.exists(PUBLIC_KEY_FILE):
        raise FileNotFoundError("Public key not found. Run ensureKeys(masterPassword) first.")

    publicKey = loadPublicKey()
    ciphertext = publicKey.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()



def decryptWithPrivate(ciphertextB64: str, masterPassword: str) -> str:
    if not masterPassword:
        raise ValueError("decryptWithPrivate requires masterPassword to be set.")
    privateKey = loadPrivateKey(masterPassword)
    ciphertext = base64.b64decode(ciphertextB64)
    plaintext = privateKey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()


def setupAESKey():
    if os.path.exists(AES_KEY_ENC_FILE):
        return #already exists
    aesKey = Fernet.generate_key()
    cipherKey = encryptWithPublic(aesKey.decode("utf-8"))#encrypts with RSA public
    with open (AES_KEY_ENC_FILE, "w") as f:
        f.write(cipherKey)
#Load AES key by decrypting with RSA private key
def loadAESKey(masterPassword):
    if not masterPassword:
        raise ValueError("loadAESKey requires masterPassword (not None).")
    if not os.path.exists(AES_KEY_ENC_FILE):
        raise FileNotFoundError(f"{AES_KEY_ENC_FILE} not found. Have you called ensureKeys()?")
    with open(AES_KEY_ENC_FILE, "r") as f:
        cipherKey = f.read()
    aesKey = decryptWithPrivate(cipherKey, masterPassword).encode()
    return Fernet(aesKey)


#GENERATING AES KEY AND ENCRYPTING IT WITH RSA PUBLIC KEY
AES_KEY_ENC_FILE = "aes.key.enc"
PASSWORDS_FILE = "passwords.json.enc"


#save encrypted Json
def saveData():
    if not masterPassword:
        raise ValueError("saveData requires masterPassword to be set (can't encrypt without it).")
    fernet = loadAESKey(masterPassword)
    plaintext = json.dumps(passwordData).encode()
    ciphertext = fernet.encrypt(plaintext)
    with open(PASSWORDS_FILE, "wb") as f:
        f.write(ciphertext)



#loads encrypted json
def loadData():
    global passwordData
    # If master password hasn't been set by GUI/login yet, don't attempt to load
    if not masterPassword:
        # nothing to load yet
        passwordData = {}
        return

    if not os.path.exists(PASSWORDS_FILE):
        passwordData = {}
        return

    fernet = loadAESKey(masterPassword)
    with open(PASSWORDS_FILE, "rb") as f:
        ciphertext = f.read()
    try:
        plaintext = fernet.decrypt(ciphertext)
        passwordData = json.loads(plaintext.decode())
    except Exception as e:
        print("Error decrypting JSON: ", e)
        passwordData = {}

#DO NOT RUN ON IMPORT
#masterPassword = setupMasterPassword()


def ensureKeys(masterPassword):
    #Ensure RSA and AES keys exist safely using the current master password.
    if not masterPassword:
        raise ValueError("Master password cannot be None when ensuring keys.")

    if not os.path.exists(PUBLIC_KEY_FILE) or not os.path.exists(PRIVATE_KEY_FILE):
        generateRSAKeyRepair(masterPassword)
    setupAESKey()



#adding websites
def addPassword():
    web = input("Enter website domain: ")
    user =input("Enter Username: ")
    password = pwinput.pwinput("Enter your password: ", mask="*")
    #encrypt the password
    cipherb64 = encryptWithPublic(password)
    # store encrypted passowrd in dict
    passwordData[web] = {"Username": user, "Password": cipherb64}
    saveData() #saves the website and passwords
    print("password added!")
    #ask user if they want to continue
    reset = input("\n is your operation finished? (y/n): ").strip().lower()
    if reset == "y":
        return False
    elif reset == "n":
        return True 
    else: 
        print("Invalid input")

#viewing all the passwords, created a seperate section where you choose the website and collect the information
def viewPassword():
    if not passwordData:
        print("No data yet!")
        return True
    
    print("\nWebsites:")
    webs = sorted(passwordData.keys())
    for i, web in enumerate(webs):
            print(f"{i+1}. {web}")        
    try: 
        choice = int(input("Enter the number of the website you'd like to view: "))-1
        if 0 <= choice < len(webs):
            selectedSite = webs[choice]
            details = passwordData[selectedSite]
            #decrypt password:
            decryptedPassword = decryptWithPrivate(details["Password"],masterPassword)
            print(f"\nWebsite: {selectedSite}")
            print(f"Username: {details['Username']}")
            print(f"Password: {decryptedPassword}")
        else: 
            print("Invalid choice")

    except (ValueError, IndexError):
            print("Invalid input.")
            return True
#ask user if they want to continue
    reset = input("\n is your operation finished? (y/n): ").strip().lower()
    if reset == "y":
        return False
    elif reset == "n":
        return True 
    else: 
        print("Invalid Input")

#removing passwords/websites
def removePassword():
    if not passwordData:
        print("No data yet!")
        return
    
    webs = sorted(passwordData.keys())
    print("\nWebsites:")
    for i, web in enumerate(webs):
        print(f"{i+1}. {web}")

    try:
        num = int(input("Enter the number of the website you'd like to remove: "))
        if 1 <= num <= len(webs):  # check that choice is valid
            selectedSite = webs[num-1]  # get the actual website name
            removed = passwordData.pop(selectedSite)  # remove it from dictionary
            saveData() # saves the deletion 
            print(f"Removed: {selectedSite}")
        else: 
            print("Invalid number.")
    except ValueError:
        print("Please enter a valid number.")
        #ask user if they want to continue
    reset = input("\n is your operation finished? (y/n): ").strip().lower()
    if reset == "y":
        return False
    elif reset == "n":
        return True 
    else: 
        print("Invalid input")
    


def updatePassword():
    if not passwordData:
        print("No data yet!")
        return True

    webs = sorted(passwordData.keys())
    print("\nWebsites:")
    for i, web in enumerate(webs):
        print(f"{i+1}. {web}")

    try:
        num = int(input("Enter the number of the website you'd like to update: "))
        if 1 <= num <= len(webs):
            selectedSite = webs[num-1]
            print(f"\nUpdating password for: {selectedSite}")

            choice = input("Do you want to (1) enter a new password or (2) generate one? ").strip()
            if choice == "1":
                newPassword = pwinput.pwinput("Enter your new password: ", mask="*")
            elif choice == "2":
                userLength = input("Enter password length (leave blank for random): ")
                if userLength.strip() == "":
                    newPassword = generatePassword()
                else:
                    try:
                        newPassword = generatePassword(int(userLength))
                    except ValueError:
                        print("Invalid input, using random length.")
                        newPassword = generatePassword()
                print(f"Generated new password: {newPassword}")
            else:
                print("Invalid choice, cancelling update.")
                return True

            # Encrypt and save
            encryptedPassword = encryptWithPublic(newPassword)
            passwordData[selectedSite]["Password"] = encryptedPassword
            saveData()
            print("Password successfully updated!")

            # confirmation of decryption right away
            decryptedPassword = decryptWithPrivate(passwordData[selectedSite]["Password"], masterPassword)
            print("\n✅ Password successfully updated!")
            print(f"Website: {selectedSite}")
            print(f"Username: {passwordData[selectedSite]['Username']}")
            print(f"New Password: {decryptedPassword}")
        else:
            print("Invalid number.")
    except ValueError:
        print("Please enter a valid number.")

    reset = input("\nIs your operation finished? (y/n): ").strip().lower()
    if reset == "y":
        return False
    elif reset == "n":
        return True
    else:
        print("Invalid input")
        return True

def searchPassword():
    if not passwordData:
        print("No data yet!")
        return True
    query = input("Enter the website name to search: ").strip().lower()
    matches = [web for web in passwordData if query in web.lower()]

    if not matches:
        print("No websites found matching your query")
        return True
    print ("\nMatching websites:")
    for i, web in enumerate(matches):
        print(f"{i+1}. {web}")
    try: 
        choice = int(input("Enter a number you'd like to view: "))-1
        if 0 <= choice < len(matches):
            selectedSite = matches[choice]
            details = passwordData[selectedSite]
            decryptedPassword = decryptWithPrivate(details["Password"], masterPassword)
            print(f"\nWebsite: {selectedSite}")
            print(f"Username: {details['Username']}")
            print(f"Password: {decryptedPassword}")
        else:
            print("Invalid choice.")
    except ValueError:
        print("Please enter a valid number.")

         #asks user if they want to continue
    reset = input("\nIs your operation finished? (y/n): ").strip().lower()
    if reset == "y":
        return False
    elif reset == "n":
        return True
    else:
        print("Invalid input")
        return True

def generatePassword(length=None):
    # if no length is provided, choose a random length between 5 and 25
    if length is None: 
        length = random.randint(5, 25)

    alphabet = string.ascii_letters + string.digits + string.punctuation
    
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in string.punctuation for c in password)):
            return password 
       
            
    







        
if __name__ == "__main__": 
    #muted the following so it doesnt run on import      
   # loadData()  # loads in all saved passwords
    while True:

        print(""" \n
Welcome to the terminal
Please choose from the options down below
--------------------------------------------------------------------------------------------------------------
1. Add a password
2. View a password
3. Remove a password
4. Generate a strong password 
5. Update a password
6. Search password
7. Quit  
        """)
        
        try:
            choice = int(input("Enter a number: "))
        except ValueError:
            print("Invalid Input, please enter a number ")
            continue
        if choice == 1:
            keepGoing = addPassword()  
            if not keepGoing:
                print("Goodbye!")
                break

        elif choice == 2:
            keepGoing = viewPassword()
            if not keepGoing:
                print("Goodbye!")
                break

        elif choice == 3:
            keepGoing = removePassword()
            if not keepGoing:
                print("Goodbye!")
                break
            
        elif choice == 4:
            userLength = input("Enter password length from 5 - 25 (leave blank for random): ").strip()
            if userLength == "":
                newpass = generatePassword()  #random length
            else:
                try:
                    newpass = generatePassword(int(userLength))
                except ValueError:
                    print("Invalid input, please enter a number or leave blank.")
                    continue  #go back tomenu

            print(f"\nGenerated new password: {newpass}")

        elif choice == 5:
            keepGoing = updatePassword()
            if not keepGoing:
                print("Goodbye")
                break
        elif choice == 6: 
            keepGoing = searchPassword()
            if not keepGoing:
                print("Goodbye")
                break
        elif choice == 7:
            print("Goodbye!")
            break
        

        



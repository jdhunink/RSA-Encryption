#!/usr/bin/python
# -*- coding: <UTF-8> -*-

#Jacob Hunink
#Cryptography Programming Project
#Implementing RSA 4096, OAEP (SHA1), SHA-512

#November 21, 2017
#Still a work in progress, user experience could be improved, and prompts could be streamlined.

#Imports
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import serialization

#---------------------------------------------------------------------
#---------------------------------------------------------------------
#OPENING PROMPT
#---------------------------------------------------------------------
#---------------------------------------------------------------------
print("\nThis program will encrypt, decrypt, and hash any file using the RSA 4096 bit encryption protocol with SHA1 padding, and the SHA-512 bit hashing protocol.")
print("\nPlease enter a filename to be encrypted, decrypted or hashed. Type 'help' for more instructions.")
name = input("Filename: ")

if(name == "help"):
    print("\nThis program can perform three functions:\n")
    print("Encryption - e \nThis will encrypt your specified file and write the new encrypted file to your disk.\n")
    print("Decrpytion - d \nThis will decrypt your specified file and write the new decrypted file to your disk.\n")
    print("Hashing - h \nThis will create a hash of your specified file and write a file conatining just the hash of your file to your disk.")
    print("\nAlso the Encryption and Hashing functions can be performed in the same step with the following functions:")
    print("'eh' - Will create a hash of your file and append it to the end of your specified file, the entire message including the hash will then be encrpyted.")
    print("'he' - Will create a hash and encrpyt your specified file, however the hash will be appended to the end of the encrypted file, still in its original form.")
    print("\nThe same can be done while decrypting with the following functions:")
    print("'dh' - Will decrypt the file and its encrypted hash, returning the decrypted file and its hash.")
    print("'hd' - Will decrypt the file and return the unencrpyted hash to be verfied.\n")
    name = input("Please enter a filename: ")

#OPEN FILE
OrigF = open(name,"rb")
message = OrigF.read()
OrigF.close()
#FILE READ

def CheckKeys():

    if function == "d":
        haveKey = "Yes"
    elif function == "hd":
        haveKey = "Yes"
    elif function == "dh":
        haveKey = "Yes"
    else:
        haveKey = input("\nDo you have a public and private key? (Yes/No) ")

    #IF NO GENERATE KEYS

    if haveKey == "No":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        pem.splitlines()[0]

        PrivateKeyFile = open("MyKeys", "wb")
        PrivateKeyFile.write(pem)
        PrivateKeyFile.close

        print("\nYour private and public keys have been written to a files titled 'MyKeys'.")
        print("Take Note your public key will be generated from the private key stored on disk for further operations.")
        return private_key

    #IF YES LOAD KEYS FUNCTION
    elif haveKey == "Yes":
        PrivateKeyFilePath = input("\nPlease type the path to the file holding your private key: ")
        print("\nLoading Keys.")

        with open(PrivateKeyFilePath, "rb") as Private_key_file:
            private_key = serialization.load_pem_private_key(
            Private_key_file.read(),
            password=None,
            backend=default_backend()
        )

        print("Keys Loaded.")
        return private_key



print("\nWhat would you like to do with this file?")
function = input("Function: ")

    #---------------------------------------------------------------------
    #---------------------------------------------------------------------
    #HASHING FUNCTION
    #---------------------------------------------------------------------
    #---------------------------------------------------------------------
if(function == "h"):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(message)
    DocHash = digest.finalize()
    f= open("MyHash",'wb')
    f.write(DocHash)
    f.close()

#---------------------------------------------------------------------
#---------------------------------------------------------------------
#ENCRYPTION FUNCTION
#---------------------------------------------------------------------
#---------------------------------------------------------------------
if(function == "e"):
    private_key = CheckKeys()
    Pub_Key = private_key.public_key()
    Outputname = input("\nWhat would you like your encrypted file to be called? ")
    ciphertext =  Pub_Key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    f= open(Outputname,'wb')
    f.write(ciphertext)
    f.close()
    print("\nEncryption Complete.")
#---------------------------------------------------------------------
#---------------------------------------------------------------------
#DECRYPT FUNCTION
#---------------------------------------------------------------------
#---------------------------------------------------------------------
if(function == "d"):
    private_key = CheckKeys()
    from cryptography.hazmat.primitives.asymmetric import padding
    f= open(name,'rb')
    ciphertext = f.read()
    f.close()

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    Outputname = input("What would you like your decrypted file to be called? ")
    f= open(Outputname,'wb')
    f.write(plaintext)
    f.close()
    print("\nYour decrypted file has been created.")


#---------------------------------------------------------------------
#---------------------------------------------------------------------
#APPENED HASH ENCRYPTION FUNCTION
#---------------------------------------------------------------------
#---------------------------------------------------------------------
if(function == "eh"):

    private_key = CheckKeys()
    Pub_Key = private_key.public_key()
    #Hash + Append Hash
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(message)
    DocHash = digest.finalize()
    message = message + "\nHash\n"
    message = message + DocHash
    f= open("MyHash",'wb')
    f.write(DocHash)
    f.close()
    print("Your hash has been written to a file called 'MyHash'.")

    #Encrypt all of it
    ciphertext =  Pub_Key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    #Write Output to disk
    Outputname = input("\nWhat would you like the encrypted file and hash to be called? ")
    f= open(Outputname,'w+')
    f.write(ciphertext)
    f.close()


if(function == "he"):
    private_key = CheckKeys()
    public_key = private_key.public_key()

    #Encrypt
    ciphertext =  public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    #Hash + Append Hash
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(message)
    DocHash = digest.finalize()

    ciphertext = ciphertext + "\nHash\n"
    ciphertext = ciphertext + DocHash

    f= open("MyHash",'w+')
    f.write(DocHash)
    f.close()
    print("Your hash has been written to a file called MyHash.")

    Outputname = input("What would you like the encrypted file and appended hash to be called? ")
    f= open(Outputname,'w+')
    f.write(ciphertext)
    f.close()

if(function == "dh"):
    private_key = CheckKeys()
    public_key = private_key.public_key()

    f= open(name,'r')
    ciphertext = f.read()
    f.close()

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    #Unencrypted File
    Outputname = input("\nWhat would you like your decrypted file to be called? ")
    f= open(Outputname,'w+')
    f.write(plaintext)
    f.close()

    #Hash Verification
    print("Hash Verification:")
    HashFileName = input("Please Enter the name of your Hash File: ")
    Hashfile = open(HashFileName, "r")
    ReadHash = Hashfile.read()
    Hashfile.close()

    UnencryptedFile = open(Outputname, 'r')

    line = ""
    nextline = "/"
    UnencryptedHash = ""
    for i in range(0,8):
        line = UnencryptedFile.readline()
        if(line == "Hash\n"):
            print("\nHash has been found.")
            while nextline != "":
                nextline = UnencryptedFile.readline()
                UnencryptedHash = UnencryptedHash + nextline
            break

    for j in range(0,63):
        if(UnencryptedHash[j] != ReadHash[j]):
            #Hashes Dont match
            print("The Hash from this file and the Hash you provided do not match.")
            print("Someone may have tampered with the file.")
            override = input("Would you like to override and write the file to disk? (Yes/No) ")
            if(override == "Yes"):
                print("\nDecryption Complete.")
                print("Your decrypted file has been created.\n")
            if(override == "No"):
                os.remove(Outputname)
                break
            else:
                break

        if(j==62):
            print("Hash Verified.")
            f= open(Outputname,'w+')
            f.write(plaintext)
            f.close()
            print("Your decrypted file has been created.\n")
            print("Decryption Complete.")



if(function == "hd"):
    private_key = CheckKeys()
    public_key = private_key.public_key()

    f= open(name,'r')
    ciphertext = ""
    line = ""
    Hash = ""

    while True:
        line = f.readline()
        if line == "Hash\n":
            print("\nHash has been found.")
            while line != "":
                line = f.readline()
                Hash = Hash + line
            break

        if line == "":
            break

        else:
            ciphertext = ciphertext + line

    NewCipherText = ciphertext.strip('\n')

    plaintext = private_key.decrypt(
        NewCipherText,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    #Hash Verification
    print("\nHash Verification:")
    HashFileName = input("Please Enter the name of your Hash File: ")
    Hashfile = open(HashFileName, "r")
    ReadHash = Hashfile.read()
    Hashfile.close()

    for j in range(0,63):
        if(Hash[j] != ReadHash[j]):
            #Hashes Dont match
            print("The Hash from this file and the Hash you provided do not match.")
            print("Someone could have tampered with the file.")
            override = input("Would you like to override and write the file to disk anyway? (Yes/No) ")
            if(override == "Yes"):
                print("\nDecryption Complete.")
                Outputname = input("What would you like your decrypted file to be called? ")
                f= open(Outputname,'w+')
                f.write(plaintext)
                f.close()
                print("Your decrypted file has been created.\n")
            if(override == "No"):
                print("Ending without writing to disk.")
                break
            else:
                break
            break
        if(j==62):
            print("Hash Verified.")
            Outputname = input("What would you like your decrypted file to be called? ")
            f= open(Outputname,'w+')
            f.write(plaintext)
            f.close()
            print("Decryption Complete.")

print("\nProgram Complete.\n")

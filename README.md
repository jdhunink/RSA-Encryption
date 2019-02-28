# RSA-Encryption

Status: Completed

An encryption script that has the ability to encrypt, decrypt and hash text files on 
disk and write the new file to disk. It also has the ability to do any combination 
of those functions as well such as taking the hash of the file, appending it to 
the end of the to be encrypted text and then encrypting the entire block. This project 
was written in python and implements the pycrypt library. It utilizes 4096-bit RSA 
Encrpytion and SHA1 256-bit Hashing protocol. As with standard RSA encryption the 
code has the ability to generate both public and private key files, store them to 
disk and take the file they're contained in as input. 

Note: Due to RSA technology both public and private keys are written to the same 
file as the public key is held within the private key.

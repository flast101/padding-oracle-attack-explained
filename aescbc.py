#!/usr/bin/env python3
import sys,os
from Crypto.Cipher import AES
from settings import *
mode = AES.MODE_CBC

# PKCS7 padding: adding b bytes each worth b 
def padding(text):
    b = BYTE_NB - (len(text) % BYTE_NB)
    return text + chr(b)*b # PKCS7 padding

def unpadding(data):
    return data[:-data[-1]]


# AES CBC Encryption
def encryption(text):
    encryptor = AES.new(key, mode, IV=IV)
    padded_text = padding(text)
    return encryptor.encrypt(padded_text)

# AES CBC decryption without padding
def decryption(encrypted):
    decryptor = AES.new(key, mode, IV=IV)
    return decryptor.decrypt(encrypted)


# Ckeck validity of PKCS7 padding
def pkcs7_padding(data):
    pkcs7 = True
    last_byte_padding = data[-1]
    if(last_byte_padding < 1 or last_byte_padding > 16):
      pkcs7 = False
    else:
      for i in range(0,last_byte_padding):
        if(last_byte_padding != data[-1-i]):
          pkcs7 = False
    return pkcs7


#### Script ####

usage = """
Usage:
  python3 paescbc.py <message>         encrypts and displays the message (output in hex format)
  python3 aescbc.py -d <hex code>      decrypts and displays the message

Cryptographic parameters can be changed in settings.py
"""
if __name__ == '__main__':
    if len(sys.argv) == 2 : 
        print(encryption(sys.argv[1]).hex())
    elif len(sys.argv) == 3 and sys.argv[1] == '-d' : 
        print(unpadding(decryption(bytes.fromhex(sys.argv[2]))))
    else:
        print(usage)
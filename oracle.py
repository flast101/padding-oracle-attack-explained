#!/usr/bin/env python3
import sys,os
from Crypto.Cipher import AES
from settings import *
mode = AES.MODE_CBC

# AES CBC decryption 
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

# Determine if the message is encrypted with valid PKCS7 padding
def oracle(encrypted):
    return pkcs7_padding(decryption(encrypted))


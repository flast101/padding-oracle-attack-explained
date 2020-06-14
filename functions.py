#!/usr/bin/env python3
import sys
import os
from Crypto.Cipher import AES
from params import *
mode = AES.MODE_CBC


"""
  PKCS7 padding: adding b bytes of value b
"""


def bourrage(texte):
    b = BYTE_NB - (len(texte) % BYTE_NB)
    return texte + chr(b)*b  # bourrage PKCS7


def debourrage(data):
    return data[:-data[-1]]


"""
AES 128 CBC Encryption
"""


def chiffre(texte):
    encryptor = AES.new(key, mode, IV=IV)
    texte_avec_bourrage = bourrage(texte)
#    oracle(texte_avec_bourrage)
    return encryptor.encrypt(texte_avec_bourrage)


"""
AES 128 CBC decryption without padding
"""


def dechiffre(chiffré):
    decryptor = AES.new(key, mode, IV=IV)
    return decryptor.decrypt(chiffré)


"""
Determining if the message is PKCS7 padding compliant
"""


def bourrage_ok(data):
    pkcs7 = True
    bourrage_last_byte = data[-1]
    if(bourrage_last_byte < 1 or bourrage_last_byte > 16):
        pkcs7 = False
#      print("out of range")
    else:
        for i in range(0, bourrage_last_byte):
            if(bourrage_last_byte != data[-1-i]):
                pkcs7 = False
#    if(pkcs7):
#      print("PKCS#7:", data, pkcs7)
    return pkcs7


"""
Determining if the encryption matches valid encrypted data from a PKCS7 padding perspective.
"""


def oracle(chiffré):
    return bourrage_ok(dechiffre(chiffré))


# Script
usage = """
Usage:
    decoder.py <message>
            displays the encrypted message (in hex format)
    decoder.py -d <hex>
        decrypts the message provided in hex format
Parameters should be set in config.py
"""
if __name__ == '__main__':
    if len(sys.argv) == 2:  # encryption
        print(chiffre(sys.argv[1]).hex())
    elif len(sys.argv) == 3 and sys.argv[1] == '-d':  # decryption
        print(debourrage(dechiffre(bytes.fromhex(sys.argv[2]))))
    elif len(sys.argv) == 3 and sys.argv[1] == '-o':  # oracle
        print(oracle(bytes.fromhex(sys.argv[2])))
    else:
        print(usage)

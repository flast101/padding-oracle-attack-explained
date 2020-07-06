# Padding Oracle Attack Explained
Padding Oracle attack fully explained and coded from scratch in Python3.


## 1- Summary

## 2- Usage

~~~
$ python3 poracle_exploit.py <message>         decrypts and displays the message
$ python3 poracle_exploit.py -o <hex code>     displays oracle answer

Cryptographic parameters can be changed in settings.py
~~~

## Example

~~~
root@kali:~# python3 poracle_exploit.py 5c448a498fb642915c20ba4df9decf5c2b13306b12f1102dfbace8c38b353ff8
Decryptded message:  I am not encrypted anymore.
~~~



* * * 
## 3- Overview

The padding oracle attack is a spectacular attack because it allows to decrypt a message that has been intercepted if the message was encrypted using CBC mode. 
For this, the size of the blocks used for encryption will require only being able to ensure that 

we are able to obtain a response from the server that will serve us from Oracle (we'll come back to these in more detail later in this report). We will be able to
then decrypt the entire message except the first block.   

However, we will focus on how to use this vulnerability and propose a
python script that decrypts a message encrypted in AES-CBC.

* * *
## 4- AES-CBC Ciphering
### 4.1- AES
Safeguarding information has become an indispensable measure in today’s cybersecurity world. Encryption is one such method to protect discreet information being transferred online.

The Advanced Encryption Standard (AES), also known by its original name Rijndael (Dutch pronunciation: [ˈrɛindaːl]),[3] is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST) in 2001.

The Encryption technique is employed in two ways, namely symmetric encryption and asymmetric encryption. For symmetric encryption, the same secret key is used for both encryption and decryption, while asymmetric encryption has one key for encryption and another one for decryption.

With regard to symmetric encryption, data can be encrypted in two ways. There are stream ciphers: any length of data can be encrypted, and the data does not need to be cut. The other way is block encryption. In this case, the data is cut into fixed size blocks before encryption.

There are several operating modes for block encryption, such as Cipher Block Chaining (CBC).

### 4.2- Cipher Block Chaining (CBC)
In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted. This way, each ciphertext block depends on all plaintext blocks processed up to that point. To make each message unique, an initialization vector must be used in the first block. 

![CBC Mode](https://github.com/flast101/padding-oracle-attack-explained/blob/master/images/cbc.png)

CBC has been the most commonly used mode of operation. Its main drawbacks are that encryption is sequential (i.e., it cannot be parallelized), and that the message must be **padded** to a multiple of the cipher block size.

Decrypting with the incorrect IV causes the first block of plaintext to be corrupt but subsequent plaintext blocks will be correct. This is because each block is XORed with the ciphertext of the previous block, not the plaintext, so one does not need to decrypt the previous block before using it as the IV for the decryption of the current one. This means that a plaintext block can be recovered from two adjacent blocks of ciphertext. 

### 4.3 - Applications


* * *
## 5- Exploiting CBC mode
### 5.1- PKCS7 padding validation function



### 5.2- Ask the Oracle



### 5.3- CBC mode vulnerability




Happy hacking !   :smiley:


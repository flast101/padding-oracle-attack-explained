# AES CBC encoding settings

BLOCK_SIZE = 128
BYTE_NB = BLOCK_SIZE//8

key = '0123456789abcdef'
IV = BYTE_NB * '\x00'

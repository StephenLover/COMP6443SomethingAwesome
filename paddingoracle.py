from Crypto.Cipher import DES
import random

# This is the code for COMP6443 padding oracle study for something awesome project
# The cryptography that you need to be familiar with: DES, XOR operation
# The encryption standard that we use is PKC#7 and DES,
# The length of block in this demo is fixed, which is 8 bytes.


# The DES_key that you may need when encrypting
DES_key = "StephenW"
# The random initialisation vector that you need.
def IV():
     nums = [str(x) for x in range(10)]
     random.shuffle(nums)
     IV = "".join(nums[:8])
     return IV

# Using PKCS#7 standard to pad plaintext

def PKCS7(plaintext):
     # First, calculate the padding value spaces according the plaintext's length
     pad_bytes = 8 - len(plaintext) % 8
     # Secord, according the padding spaces to produce the padding.
     pad_value = pad_bytes * chr(pad_bytes)
     # Thrid, add the padding to the tail.
     padded_block = plaintext + pad_value
     return padded_block

def PKCS7_Check(plaintext):
     pl_len = len(plaintext)
     pre_val = ord(plaintext[pl_len-1])
     # case 1: Return False if padding value is incorrect:
     if (pre_val < 1) or (pre_val > 8):
          return False
     # case 2: Return False if the number of pad_value is wrong:
     if plaintext[pl_len- pre_val:] != chr(pre_val) * pre_val:
          return False
     # case 3: Return True plaintext, correct match.
     #print(len(plaintext))
     return plaintext


# DES-CBC encryption function:

def DES_encrypt(plaintext):
     cipher = DES.new(DES_key, DES.MODE_CBC, IV())
     ciphertext = cipher.encrypt(PKCS7(plaintext))
     return ciphertext

# DES-CBC decryption function:
def DES_decrypt(ciphertext):
     cipher = DES.new(DES_key, DES.MODE_CBC, IV())
     return PKCS7_Check(cipher.decrypt(ciphertext))




def OracleAttack(pre_block, cur_block ):
    # initialise the cipher hex block sequence and block in this form:
    # \x00\x00\x00\x00\x00\x00\x00\x00 + block
    c_prime = chr(0)*8
    # create a list to store the intermediate value when we solve it
    inter_vals = []
    # create a cracked plaintext chars when we decrypt it.
    plain_list = []
    # For each byte in the two consecutive cipher hex block, we try to encrypt them
    # from the last to the front
    for index_cprime in range(7,-1,-1):
        # Create a PKCS#7 padding index [0x01, 0x08]
        index_padding = 8 - index_cprime
        # brute force to try to match the valid padding:
        for guess in range(256):
            # Create new ciphertext with the guess
            if index_cprime > 0:
                ciphertext = c_prime[:index_cprime]
                ciphertext += chr(guess)
            else:
                ciphertext = chr(guess)
            # Previous Intermediate Values insertion:
            for intmd in inter_vals:
                #adjusting P_IV for this padding index
                ciphertext += chr(intmd ^ index_padding) 
            # append the block which is cracking
            ciphertext += cur_block
            # If the oracle correctly decrypts the ciphertext
            if DES_decrypt( ciphertext ):
                # calculate the intermediate value
                intermediate_value = guess ^ index_padding
                # store it into intermediate value list:
                inter_vals.insert(0, intermediate_value)
                # add the plaintext that we decrypt into the list:
                plain_list.insert(0, intermediate_value ^ ord(pre_block[index_cprime]))
                # cracked! jump out the loop.
                break
    #pring Intermediate Value for each time of cracking.
    print "Intermediate Values :" , inter_vals
    plaintext_str = ""
    for char in plain_list:
         if char > 0x08:
              plaintext_str += chr(char)
         else:
              plaintext_str += chr(char).encode("hex")
    return plaintext_str


# spliting the plaintext to the fixed blocks
# return False to remind the block can not be divided into at least 2 blocks
def split_into_blocks(plaintext):
     if len(plaintext) < 8:
          return False
     ciphertext = DES_encrypt(plaintext)
#     print(type(ciphertext))
     blocks = []
     blocks_num = len(plaintext) // 8 + 1
     start_index = 0
     #print(ciphertext)
     for b in range(blocks_num):
          blocks.append(ciphertext[start_index:start_index+8])
     return blocks

# decrypting the ciphertext
# same logic as above function.
def Cracking(plaintext):
    if len(plaintext) < 8:
         return False
    ciphertext = DES_encrypt(plaintext)
    blk1 = ciphertext[:8]
    blk2 = ciphertext[8:16]
    blk3 = ciphertext[16:24]

    #Cracking information
    print "******************* Padding Oracle Demo *****************"
    #print "The input plaintext is:", plaintext
    print "******************* Encrypting text using DES and CBC Mode *****************"
    print plaintext+"::"+blk1.encode("hex")+" "+blk2.encode("hex")+"\n"
    print "Cracking cipher block ["+blk2.encode("hex")+"]"
    # Crack the second block using the first
    plain = OracleAttack(blk1, blk2)
    print "Cracked ", blk2.encode("hex"), " to",
    print "\""+plain+"\""
    print "*********************************"
    # Crack the third block using the second
    print plaintext+"::"+blk2.encode("hex")+" "+blk3.encode("hex")+"\n"
    print "Cracking cipher block ["+blk3.encode("hex")+"]"
    plain2 = OracleAttack(blk2, blk3)
    print "Cracked ", blk3.encode("hex"), " to",
    print "\""+plain2+"\""

    return plain+plain2

if __name__ == '__main__':
    plaintext = "Awesome COMP6443 Hello!"
    cracked_string = Cracking(plaintext)
    print "*********************************"
    print "The cracked ciphertext is:", cracked_string


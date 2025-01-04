import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes

#pip install pycryptodome

#CBC mode
k1 = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')
c11 =bytes.fromhex('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')
c12 = bytes.fromhex('5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253')

#Counter mode
k2 = bytes.fromhex('36f18357be4dbd77f050515c73fcf9f2')
c21 =bytes.fromhex('69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329')
c22 = bytes.fromhex('770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')

def hex_to_ascii(s):
   if len(s) % 2 != 0:
      s = s[:-1] + '0' + s[-1]
   b_arr = bytes.fromhex(s)
   ascii_str = b_arr.decode('ASCII','replace')
   return ascii_str

def blocks(s,n):
    return [s[i:i+n] for i in range(0,len(s),n)]

def padding(pt,n):
    pt = bytes(pt, 'utf-8')
    b = blocks(pt,n)
    if len(b[-1]) < n:
        d = n - len(b[-1])
        p = bytes(chr(d), 'ascii')
        while(len(b[-1])<n):
            b[-1] = b[-1] + p
    else:
        s = b''
        p = bytes(chr(16), 'ascii')
        for i in range(n):
            s = s + p
        b.append(s)
    return b

#print(padding('Basic CBC mode encryption needs padding.',16))
#print(padding('Our implementation uses rand. IV',16))


def CBC_encrypt(k,iv,pt):
    bls = padding(pt,16)
    cipher = AES.new(k, AES.MODE_ECB)
    IV = cipher.encrypt(iv)
    #IV = iv
    ct = IV
    for i in range(len(bls)):
        c = bytes(a ^ b for a, b in zip(bls[i], ct[-16:]))
        cc = cipher.encrypt(c)
        ct = ct + cc
    return ct.hex()

#print(CBC_encrypt(k1, c11[:16] ,'Basic CBC mode encryption needs padding.'))

def CBC_decrypt(k,ct):
    bls =
    cipher = 
    pt = 
    for i in range(1,len(bls)):
        #insert

    return pt

print(hex_to_ascii(CBC_decrypt(k1,c11)[:-16]))

#print(CBC_decrypt(k1,c12))
#print(CBC_decrypt(k1,c12)[:-32])
print(hex_to_ascii(CBC_decrypt(k1,c12)[:-32]))

def CTR_encrypt(k,iv,pt):
    cipher = AES.new(k,AES.MODE_ECB)
    pt = bytes(pt, 'utf-8')
    bls = blocks(pt,16)
    IV = cipher.encrypt(iv)
    ct = iv.hex() + hex(int(IV.hex(),16)^int(bls[0].hex(),16))[2:]
    for i in range(1,len(bls)):
        iv = bytes.fromhex(hex(int(iv.hex(),16) + 1)[2:])
        IV = cipher.encrypt(iv)
        mlen = min(len(IV), len(bls[i]))
        ct = ct + hex(int(IV[:mlen].hex(),16)^int(bls[i][:mlen].hex(),16))[2:]
    return ct

#print(CTR_encrypt(k2,c21[:16], 'CTR mode lets you build a stream cipher from a block cipher.'))
#print(CTR_encrypt(k2,c22[:16], 'Always avoid the two time pad!'))

def CTR_decrypt(k, ct):
    cipher = 
    bls = 
    ctr = 
    IV = 
    pt = 
    for i in range(1,len(bls)):
        #insert
    return hex_to_ascii(pt)

print(CTR_decrypt(k2,c21))
print(CTR_decrypt(k2,c22))
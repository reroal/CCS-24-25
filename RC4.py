#!/usr/bin/env python


MOD = 256

def KSA(key):
	key_length = len(key)
	S = list(range(MOD))
	j = 0
	for i in range(MOD):
   		j = (j + S[i] + key[i % key_length]) % MOD
   		S[i], S[j] = S[j], S[i]
	return S
        
def PRGA(S):
	i = 0
	j = 0
	while True:
		i = (i + 1) % MOD
		j = (j + S[i]) % MOD
		S[i], S[j] = S[j], S[i]
		K = S[(S[i] + S[j]) % MOD]
		yield K
        
def get_keystream(key):
    S = KSA(key)
    return PRGA(S)

def encrypt(key, plaintext):
	key = [ord(c) for c in key]
	plaintext = [ord(c) for c in plaintext]
	keystream = get_keystream(key)
	res = []
	for c in plaintext:
		val = ("%02X"%( c ^ next(keystream)))
		res.append(val)
	return res
	
def decrypt(key, ciphertext):
	ciphertext = [chr(int(c,16)) for c in ciphertext]
	res = encrypt(key, ciphertext)
	return res
    
k = 'CryptographyAndComputerSafety2425'
p = 'thesolutionsforthemidterm'

ciphertext = encrypt(k,p)
print("".join(ciphertext))

decr = decrypt(k,ciphertext)
print("".join([chr(int(c,16)) for c in decr]))


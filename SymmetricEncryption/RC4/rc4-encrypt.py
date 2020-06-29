#! /usr/bin/python
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA256
from Crypto import Random

def enc(key,p):
		return ARC4.new(key).encrypt(p)

def dec(key,msg):
		return ARC4.new(key).decrypt(msg)

def main():
		key = 'very long key'
		p = 'RC4 test hehehe'
		nonce=Random.new().read(16)
		key +=nonce
		key = SHA256.new(key).digest() #key is no more than 256bytes
		print "Key : %r" % key
		ciphertext = enc(key, p)
		print "Ciphertext : %r" % ciphertext
		print "Decrypted Text: %s" % dec(key,ciphertext)

if __name__=='__main__':
		main()
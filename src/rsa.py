from crypto import *
from math import gcd

class RSA(Crypto):
	def __init__(self, p, q):
		super().__init__()
		self.p = p
		self.q = q
		self.encryption_key = 0
		self.decryption_key = 0

		self.n = p * q
		self.t = (p - 1) * (q - 1)

	#e publikus kulcs kiválasztása
	def set_public_key(self):
		for i in range(2, self.t):
			if gcd(i, self.t) == 1:
				self.encryption_key = i
				break


	# d privát kulcs kiválasztása
	def set_private_key(self):
		j = 0
		while True:
			if (j * self.encryption_key) % self.t == 1:
				self.decryption_key = j
				break
			j += 1

	def encrypt(self, plaintext):
		cyphertext = (plaintext ** self.encryption_key) % self.n
		print(f'Kódolt üzenet: {cyphertext}')
		return cyphertext

	def decrypt(self, cyphertext):
		message = (cyphertext ** self.decryption_key) % self.n
		print(f'Dekódolt üzenet: {message}')

rsa = RSA(53, 59)
rsa.set_public_key()
rsa.set_private_key()
rsa.decrypt(rsa.encrypt(123))

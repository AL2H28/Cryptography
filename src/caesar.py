from crypto import Crypto

class Caesar(Crypto):

	def __init__(self, offset):
		super().__init__()
		self.offset = offset


	def encrypt(self, plaintext):
		cyphertext = ''
		for ch in plaintext:
			cyphertext += chr(ord(ch) + self.offset)

		return cyphertext

	def decrypt(self, cyphertext):
		plaintext = ''
		for ch in cyphertext:
			plaintext += chr(ord(ch) - self.offset)

		return plaintext
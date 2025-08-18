class Crypto:
	def __init__(self):
		pass

	def generate_key(self, l):
		raise NotImplementedError("Please Implement this method")

	def encrypt(self, plaintext):
		raise NotImplementedError("Please Implement this method")

	def decrypt(self, cyphertext):
		raise NotImplementedError("Please Implement this method")

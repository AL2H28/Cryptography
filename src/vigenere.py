import random
from string import ascii_lowercase, ascii_uppercase

from crypto import Crypto


class Vigenere(Crypto):
	def __init__(self, key):
		super().__init__()
		self.key = key

	def generate_key(self, l):
		self.key = ''.join(random.choices(ascii_lowercase, k=l))


	@staticmethod
	def _repeat_to_length(s, length):
		return (s * (length // len(s) + 1))[:length]


	def encrypt(self, plaintext):
		cyphertext = ''
		key = self._repeat_to_length(self.key, len(plaintext))

		for k, ch in zip(key, plaintext):
			k_i = ascii_lowercase.find(k)
			ch_i = ascii_lowercase.find(ch)
			cyphertext += ascii_uppercase[(k_i + ch_i) % 26]

		return cyphertext


	def decrypt(self, cyphertext):
		plaintext = ''
		key = self._repeat_to_length(self.key, len(cyphertext))

		for k, ch in zip(key, cyphertext):
			k_i = ascii_lowercase.find(k)
			ch_i = ascii_uppercase.find(ch)
			plaintext += ascii_lowercase[(ch_i - k_i) % 26]

		return plaintext

	def kasiski_cracker(self, plaintext):
		start = []
		matches = re.finditer



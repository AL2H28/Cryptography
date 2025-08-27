from caesar import Caesar
from vigenere import Vigenere
import string

if __name__ == '__main__':
	caesar = Caesar(3)
	pt = "hello"
	ct = caesar.encrypt(pt)
	print(ct)
	decrypted = caesar.decrypt(ct)
	print(decrypted)

	vigenere = Vigenere('asdf')
	vig_ct = vigenere.encrypt("megszentsegtelenithetetlensegeskedeseitekert")
	print(vig_ct)

	vig_dt = vigenere.decrypt(vig_ct)
	print(vig_dt)

# caesar
	for k in range(26):
		print(k, ''.join([chr((ord(char) - k - 97) % 26 + 97) for char in ct]))
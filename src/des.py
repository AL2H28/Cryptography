import secrets
from typing import List, Optional
import numpy as np

from crypto import Crypto
from padding import *
from permutations import *
from utils import *

class DES(Crypto):
	def __init__(self, key: bytes, block_size: int) -> None:
		super().__init__()
		self.key = key
		self.block_size = block_size
		self.rounded_keys = self._key_schedule()

	def encrypt(self, plaintext):
		pass

	def _key_schedule(self) -> List[List[int]]:
		iterations = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
		res = []
		key = int.from_bytes(self.key, byteorder='big')
		key = list(map(int, bin(key)[2:].zfill(64)))
		round_key = [key[i] for i in PC1]
		c, d = round_key[:28], round_key[28:]
		for n in range(16):
			left_shifts = iterations[n]
			c = c[left_shifts:] + c[:left_shifts]
			d = d[left_shifts:] + d[:left_shifts]
			round_key = c + d
			res.append([round_key[i] for i in PC2])
		return res

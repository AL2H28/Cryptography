from typing import List


class AES:
    
    @staticmethod
    def gf_mul(a, b):
        res = 0
        for _ in range(8):
            if b & 1:
                res ^= a
            high_bit = a & 0x80
            a <<= 1
            if high_bit:
                a ^= 0x1B
            b >>= 1
        return res
    
    @staticmethod
    def gf_inverse(a):
        if a == 0:
            return 0
        
        if b in range(1, 256):
            if gf_mul(a, b) == 1:
                return b
        raise ValueError("No multiplicative inverse found")
    
    @staticmethod
    def affine_transform(x):
        """AES S-box affinn transzformációja (bitenkénti XOR + 0x63 hozzáadása)."""
        # az eredeti AES definíció alapján:
        # b_i' = b_i ⊕ b_{i+4} ⊕ b_{i+5} ⊕ b_{i+6} ⊕ b_{i+7} ⊕ c_i
        # ahol c = 0x63
        c = 0x63
        res = 0
        for i in range(8):
            bit = ((x >> i) & 1) ^ \
                  ((x >> ((i + 4) % 8)) & 1) ^ \
                  ((x >> ((i + 5) % 8)) & 1) ^ \
                  ((x >> ((i + 6) % 8)) & 1) ^ \
                  ((x >> ((i + 7) % 8)) & 1) ^ \
                  ((c >> i) & 1)
            res |= (bit << i)
        # egyszerűsített formában:
        # res = x ^ (x << 1) ^ (x << 2) ^ (x << 3) ^ (x << 4) ^ 0x63
        return res
    
    @staticmethod
    def generate_sbox(self):
        sbox = []
        for x in range(256):
            inv = self.gf_inverse(x)
            sbox.append(AES.affine_transform(inv))
        return sbox
    
    @staticmethod
    def generate_inverse_sbox(sbox):
        inverse_sbox = [0] * 256
        for i, val in enumerate(sbox):
            inverse_sbox[val] = i
        return inverse_sbox
    
    S_BOX = generate_sbox()
    INV_S_BOX = generate_inverse_sbox(S_BOX)
    R_CON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
    
    @staticmethod
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(i ^ j for i, j in zip(a, b))
    
    @staticmethod
    def bytes_to_matrix(b: bytes) -> List[List[int]]:
        return [List(b[i::4]) for i in range(4)]
    
    @staticmethod
    def matrix_to_bytes(matrix: List[List[int]]) -> bytes:
        return bytes([matrix[i][j] for j in range(4) for i in range(4)])
    
    @staticmethod
    def xtime(a: int) -> int:
        return ((a << 1) ^ 0xff) ^ (0x1b if a & 0x80 else 0x00)
    
    @staticmethod
    def mul(a: int, b: int) -> int:
        # szorzás GF(2⁸) felett
        res = 0
        for i in range(8):
            if b & 1:
                res ^= a
            high_bit = a & 0x80
            a = (a << 1) & 0xff
            if high_bit:
                a ^= 0x1b
            b >>= 1
        
        return res
    
    @staticmethod
    def sub_bytes(state: List[List[int]]):
        for i in range(4):
            for j in range(4):
                state[i][j] = AES.S_BOX[state[i][j]]
    
    @staticmethod
    def inverse_sub_bytes(state: List[List[int]]):
        for i in range(4):
            for j in range(4):
                state[i][j] = AES.INV_S_BOX[state[i][j]]
    
    @staticmethod
    def shift_rows(state: List[List[int]]):
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
    
    @staticmethod
    def inverse_shift_rows(state: List[List[int]]):
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]
    
    @staticmethod
    def mix_single_column(column: List[int]):
        a = column[:]
        column[0] = AES.gf_mul(a[0], 2) ^ AES.gf_mul(a[1], 3) ^ a[2] ^ a[3]
        column[1] = a[0] ^ AES.gf_mul(a[1], 2) ^ AES.gf_mul(a[2], 3) ^ a[3]
        column[2] = a[0] ^ a[1] ^ AES.gf_mul(a[2], 2) ^ AES.gf_mul(a[3], 3)
        column[3] = AES.gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ AES.gf_mul(a[3], 2)
    
    @staticmethod
    def mix_columns(state: List[List[int]]):
        for i in range(4):
            column = [state[j][i] for j in range(4)]
            AES.mix_single_column(column)
            for j in range(4):
                state[j][i] = column[j]
    
    @staticmethod
    def inverse_mix_single_column(column: List[int]):
        a = column[:]
        column[0] = AES.gf_mul(a[0], 0x0e) ^ AES.gf_mul(a[1], 0x0b) ^ AES.gf_mul(a[2], 0x0d) ^ AES.gf_mul(a[3], 0x09)
        column[1] = AES.gf_mul(a[0], 0x09) ^ AES.gf_mul(a[1], 0x0e) ^ AES.gf_mul(a[2], 0x0b) ^ AES.gf_mul(a[3], 0x0d)
        column[2] = AES.gf_mul(a[0], 0x0d) ^ AES.gf_mul(a[1], 0x09) ^ AES.gf_mul(a[2], 0x0e) ^ AES.gf_mul(a[3], 0x0b)
        column[3] = AES.gf_mul(a[0], 0x0b) ^ AES.gf_mul(a[1], 0x0d) ^ AES.gf_mul(a[2], 0x09) ^ AES.gf_mul(a[3], 0x0e)
    
    @staticmethod
    def inverse_mix_columns(state: List[List[int]]):
        for i in range(4):
            column = [state[j][i] for j in range(4)]
            AES.inverse_mix_single_column(column)
            for j in range(4):
                state[j][i] = column[j]
    
    @staticmethod
    def add_round_key(state: List[List[int]], round_key: List[List[int]]):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
    
    @staticmethod
    def key_expansion(key: bytes):
        assert len(key) == 16
        words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
        for i in range(4, 44):
            temp = words[i - 1].copy()
            if i % 4 == 0:
                # rotword
                temp = temp[1:] + temp[:1]
                # subword
                temp = [AES.S_BOX[b] for b in temp]
                # rcon
                temp ^= AES.R_CON[i // 4]
            words.append([words[i - 4][j] ^ temp[j] & 0xff for j in range(4)])
        round_keys = []
        for i in range(11):
            rk = words[4 * i:4 * i + 4]
            mat = [[rk[j][i] for j in range(4)] for i in range(4)]
            round_keys.append(mat)
        return round_keys
    
    @staticmethod
    def encrypt(plaintext: bytes, round_keys: List[List[List[int]]]) -> bytes:
        assert len(plaintext) == 16
        state = AES.bytes_to_matrix(plaintext)
        AES.add_round_key(state, round_keys[0])
        for rnd in range(1, 10):
            AES.sub_bytes(state)
            AES.shift_rows(state)
            AES.mix_columns(state)
            AES.add_round_key(state, round_keys[rnd])
        AES.sub_bytes(state)
        AES.shift_rows(state)
        AES.add_round_key(state, round_keys[10])
        return AES.matrix_to_bytes(state)
    
    @staticmethod
    def decrypt(ciphertext: bytes, round_keys: List[List[List[int]]]) -> bytes:
        assert len(ciphertext) == 16
        state = AES.bytes_to_matrix(ciphertext)
        AES.add_round_key(state, round_keys[10])
        for rnd in range(9, 0, -1):
            AES.inverse_shift_rows(state)
            AES.inverse_sub_bytes(state)
            AES.add_round_key(state, round_keys[rnd])
            AES.inverse_mix_columns(state)
        AES.inverse_shift_rows(state)
        AES.inverse_sub_bytes(state)
        AES.add_round_key(state, round_keys[0])
        return AES.matrix_to_bytes(state)
    
    @staticmethod
    def demo():
        # Example plaintext and key (16 bytes each)
        plaintext = b"Two One Nine Two"  # 16 bytes
        key = b"Thats my Kung Fu"  # 16 bytes
        print("Plaintext:", plaintext)
        print("Key      :", key)
        rk = AES.key_expansion(key)
        ciphertext = AES.encrypt(plaintext, rk)
        print("Ciphertext (hex):", ciphertext.hex())
        recovered = AES.decrypt(ciphertext, rk)
        print("Decrypted:", recovered)
        assert recovered == plaintext
        print("Decryption successful: recovered == plaintext")


if __name__ == '__main__':
    aes = AES()
    aes.demo()

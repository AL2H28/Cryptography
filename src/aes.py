from typing import List


class AES:

    S_BOX = generate_sbox()
    INV_S_BOX = generate_inverse_sbox(S_BOX)
    R_CON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
    
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
    def gf_inv(a):
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
        #res = x ^ (x << 1) ^ (x << 2) ^ (x << 3) ^ (x << 4) ^ 0x63
        return res
    
    @staticmethod
    def generate_sbox():
        sbox = []
        for x in range(256):
            inv = gf_inverse(x)
            sbox.append(AES.affine_transform(inv))
        return sbox
    
    @staticmethod
    def generate_inverse_sbox(sbox):
        inverse_sbox = [0] * 256
        for i, val in enumerate(sbox):
            inverse_sbox[val] = i
        return inverse_sbox
    
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
    def mul(a:int, b:int) -> int:
        #szorzás GF(2⁸) felett
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
                state[i][j] = self.INV_S_BOX[state[i][j]]
    @staticmethod
    def shift_rows(self, state: List[List[int]]):
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
    
    @staticmethod
    def inverse_shift_rows(self, state: List[List[int]]):
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]
        
    def mix_single_column(self, column: List[int]):
        a = column[:]
        column[0] = self.mul(a[0], 2) ^ self.mul(a[1], 3) ^ a[2] ^ a[3]
        column[1] = a[0] ^ self.mul(a[1], 2) ^ self.mul(a[2], 3) ^ a[3]
        column[2] = a[0] ^ a[1] ^ self.mul(a[2], 2) ^ self.mul(a[3], 3)
        column[3] = self.mul(a[0], 3) ^ a[1] ^ a[2] ^ self.mul(a[3], 2)
        
    def mix_columns(self, state: List[List[int]]):
        for i in range(4):
            column = [state[j][i] for j in range(4)]
            self.mix_single_column(column)
            for j in range(4):
                state[j][i] = column[j]
                
    def inverse_mix_single_column(self, column: List[int]):
        a = column[:]
        column[0] = self.mul(a[0], 0x0e) ^ self.mul(a[1], 0x0b) ^ self.mul(a[2], 0x0d) ^ self.mul(a[3], 0x09)
        column[1] = self.mul(a[0], 0x09) ^ self.mul(a[1], 0x0e) ^ self.mul(a[2], 0x0b) ^ self.mul(a[3], 0x0d)
        column[2] = self.mul(a[0], 0x0d) ^ self.mul(a[1], 0x09) ^ self.mul(a[2], 0x0e) ^ self.mul(a[3], 0x0b)
        column[3] = self.mul(a[0], 0x0b) ^ self.mul(a[1], 0x0d) ^ self.mul(a[2], 0x09) ^ self.mul(a[3], 0x0e)
        
    
    def inverse_mix_columns(self, state: List[List[int]]):
        for i in range(4):
            column = [state[j][i] for j in range(4)]
            self.inverse_mix_single_column(column)
            for j in range(4):
                state[j][i] = column[j]
    
    @staticmethod
    def add_round_key(self, state: List[List[int]], round_key: List[List[int]]):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
                
    def key_expansion(self, key: bytes):
        assert len(key) == 16
        words = [list(key[i:i+4]) for i in range(0, 16, 4)]
        for i in range(4, 44):
            temp = words[i - 1].copy()
            if i % 4 == 0:
                #rotword
                temp = temp[1:] + temp[:1]
                #subword
                temp = [self.S_BOX[b] for b in temp]
                #rcon
                temp ^= self.R_CON[i//4]
            words.append([words[i - 4][j] ^ temp[j] & 0xff for j in range(4)])
        round_keys = []
        for i in range(11):
            rk = words[4*i:4*i+4]
            mat = [[rk[j][i] for j in range(4)] for i in range(4)]
            round_keys.append(mat)
        return round_keys

    def encrypt(self, plaintext: bytes, round_keys: List[List[List[int]]]) -> bytes:
        assert len(plaintext) == 16
        state = self.bytes_to_matrix(plaintext)
        self.add_round_key(state, round_keys[0])
        for rnd in range(1, 10):
            self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            self.add_round_key(state, round_keys[rnd])
        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, round_keys[10])
        return self.matrix_to_bytes(state)

    def decrypt(self, ciphertext: bytes, round_keys: List[List[List[int]]]) -> bytes:
        assert len(ciphertext) == 16
        state = self.bytes_to_matrix(ciphertext)
        self.add_round_key(state, round_keys[10])
        for rnd in range(9, 0, -1):
            self.inverse_shift_rows(state)
            self.inverse_sub_bytes(state)
            self.add_round_key(state, round_keys[rnd])
            self.inverse_mix_columns(state)
        self.inverse_shift_rows(state)
        self.inverse_sub_bytes(state)
        self.add_round_key(state, round_keys[0])
        return self.matrix_to_bytes(state)
        

    
    #kiszedni
    @staticmethod
    def compose_s_box(mtrx):
        s_box = [[0, 0, 0, 0],
                [0, 0, 0, 0],
                [0, 0, 0, 0],
                [0, 0, 0, 0]]
        for i in range(len(mtrx)):
            for j in range(len(mtrx[i])):
                s_box[i][j] = (mtrx[i][j] + 1) % 256
    #kiszedni
    @staticmethod
    def print_matrix(mtrx):
        print('---')

        for i in range(len(mtrx)):
            for j in range(len(mtrx[i])):
                if mtrx[i][j] != 0:
                    if mtrx[i][j] < 10:
                        print(mtrx[i][j], end='   ')
                    if mtrx[i][j] < 100:
                        print(mtrx[i][j], end='  ')
                    else:
                        print(mtrx[i][j], end=' ')
                else:
                    print('0', end='   ')
            print()
        print('---')
    #kiszedni
    def text_to_matrix(self, text):
        col = row = 0
        mtrx = [[0, 0, 0, 0],
                [0, 0, 0, 0],
                [0, 0, 0, 0],
                [0, 0, 0, 0]]
        matrices = []
        for c in text:
                
            mtrx[row][col] = ord(c)
            row += 1
            if row == 4:
                row = 0
                col += 1
            
            if col == 4:
                matrices.append(mtrx)
                mtrx = [[0, 0, 0, 0],
                        [0, 0, 0, 0],
                        [0, 0, 0, 0],
                        [0, 0, 0, 0]]
                col = 0
                row = 0

                
            if c == text[-1]:
                matrices.append(mtrx)
                
        return matrices
    #kiszedni
    @staticmethod
    def print_sbox(sbox):
        i = 0
        for num in sbox:
            if i % 16 == 0 and i != 0:
                print()
            if num > 0:
                if num < 10:
                    print(num, end='   ')
                if num < 100 and num >= 10:
                    print(num, end='  ')
                if num >= 100:
                    print(num, end=' ')
            if num == 0:
                print(0, end='   ')
            i += 1
        print()
            
        
        
if __name__ == '__main__':
    pass
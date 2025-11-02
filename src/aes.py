from typing import List

class AES:
    R_CON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
    S_BOX = None
    INV_S_BOX = None

    # --- GF(2^8) műveletek ----------------------------------------------------

    @staticmethod
    def mul(a: int, b: int) -> int:
        """Szorzás GF(2^8)-ban az AES polinommal (x^8 + x^4 + x^3 + x + 1)."""
        a &= 0xFF
        b &= 0xFF
        res = 0
        for _ in range(8):
            if b & 1:
                res ^= a
            hi_bit = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit:
                a ^= 0x1B
            b >>= 1
        return res & 0xFF

    @staticmethod
    def gf_inverse(a: int) -> int:
        """Multiplikatív inverz GF(2^8)-ban"""
        a &= 0xFF
        if a == 0:
            return 0
        for b in range(1, 256):
            if AES.mul(a, b) == 1:
                return b
        raise ValueError("Nincs multiplikatív inverz.")

    # --- S-box és inverse S-box generálás ------------------------------------

    @staticmethod
    def affine_transform(x: int) -> int:
        """Affine transzformáció (S-box definíció szerinti bitművelet)."""
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
        return res & 0xFF

    @staticmethod
    def generate_sbox() -> List[int]:
        sbox = []
        for x in range(256):
            inv = AES.gf_inverse(x)
            sbox.append(AES.affine_transform(inv))
        return sbox

    @staticmethod
    def generate_inverse_sbox(sbox: List[int]) -> List[int]:
        inv = [0] * 256
        for i, v in enumerate(sbox):
            inv[v] = i
        return inv

    # --- Segédfüggvények ------------------------------------------------------

    @staticmethod
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(i ^ j for i, j in zip(a, b))

    @staticmethod
    def bytes_to_matrix(b: bytes) -> List[List[int]]:
        """16 bájt -> 4x4 mátrix (column-major)."""
        return [list(b[i::4]) for i in range(4)]

    @staticmethod
    def matrix_to_bytes(matrix: List[List[int]]) -> bytes:
        """4x4 mátrix -> 16 bájt (column-major)."""
        return bytes([matrix[i][j] for j in range(4) for i in range(4)])

    # --- AES transzformációk --------------------------------------------------

    @staticmethod
    def sub_bytes(state: List[List[int]]):
        for r in range(4):
            for c in range(4):
                state[r][c] = AES.S_BOX[state[r][c]]

    @staticmethod
    def inverse_sub_bytes(state: List[List[int]]):
        for r in range(4):
            for c in range(4):
                state[r][c] = AES.INV_S_BOX[state[r][c]]

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
        column[0] = AES.mul(a[0], 2) ^ AES.mul(a[1], 3) ^ a[2] ^ a[3]
        column[1] = a[0] ^ AES.mul(a[1], 2) ^ AES.mul(a[2], 3) ^ a[3]
        column[2] = a[0] ^ a[1] ^ AES.mul(a[2], 2) ^ AES.mul(a[3], 3)
        column[3] = AES.mul(a[0], 3) ^ a[1] ^ a[2] ^ AES.mul(a[3], 2)

    @staticmethod
    def mix_columns(state: List[List[int]]):
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            AES.mix_single_column(col)
            for r in range(4):
                state[r][c] = col[r]

    @staticmethod
    def inverse_mix_single_column(column: List[int]):
        a = column[:]
        column[0] = AES.mul(a[0], 0x0e) ^ AES.mul(a[1], 0x0b) ^ AES.mul(a[2], 0x0d) ^ AES.mul(a[3], 0x09)
        column[1] = AES.mul(a[0], 0x09) ^ AES.mul(a[1], 0x0e) ^ AES.mul(a[2], 0x0b) ^ AES.mul(a[3], 0x0d)
        column[2] = AES.mul(a[0], 0x0d) ^ AES.mul(a[1], 0x09) ^ AES.mul(a[2], 0x0e) ^ AES.mul(a[3], 0x0b)
        column[3] = AES.mul(a[0], 0x0b) ^ AES.mul(a[1], 0x0d) ^ AES.mul(a[2], 0x09) ^ AES.mul(a[3], 0x0e)

    @staticmethod
    def inverse_mix_columns(state: List[List[int]]):
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            AES.inverse_mix_single_column(col)
            for r in range(4):
                state[r][c] = col[r]

    @staticmethod
    def add_round_key(state: List[List[int]], round_key: List[List[int]]):
        for r in range(4):
            for c in range(4):
                state[r][c] ^= round_key[r][c]

    # --- Kulcsexpanzió -------------------------------------------------------

    @staticmethod
    def key_expansion(key: bytes) -> List[List[List[int]]]:
        if len(key) not in (16, 24, 32):
            raise ValueError("Kulcs hossza csak 16, 24 vagy 32 bájt lehet (AES-128/192/256).")

        Nk = len(key) // 4
        Nb = 4
        Nr = {4: 10, 6: 12, 8: 14}[Nk]

        words = [list(key[i:i + 4]) for i in range(0, len(key), 4)] # a key elemei 4 karakteres blokkok listaja
        total_words = Nb * (Nr + 1)

        for i in range(len(words), total_words):
            temp = words[i - 1].copy()
            if i % Nk == 0:
                temp = temp[1:] + temp[:1]  # RotWord a temp 1. elemét a temp végére helyezi
                temp = [AES.S_BOX[b] for b in temp]  # SubWord
                temp[0] ^= AES.R_CON[i // Nk] #rcon alkalmazása
            elif Nk > 6 and (i % Nk) == 4:
                temp = [AES.S_BOX[b] for b in temp]
            words.append([(words[i - Nk][j] ^ temp[j]) & 0xFF for j in range(4)])

        round_keys = []
        for r in range(Nr + 1):
            block = words[r * Nb:(r + 1) * Nb]
            mat = [[block[col][row] for col in range(Nb)] for row in range(4)]
            round_keys.append(mat)
        return round_keys

    # --- Titkosítás / visszafejtés -------------------------------------------

    @staticmethod
    def encrypt_block(plaintext: bytes, round_keys: List[List[List[int]]]) -> bytes:
        assert len(plaintext) == 16
        state = AES.bytes_to_matrix(plaintext)
        AES.add_round_key(state, round_keys[0])
        for rnd in range(1, len(round_keys) - 1):
            AES.sub_bytes(state)
            AES.shift_rows(state)
            AES.mix_columns(state)
            AES.add_round_key(state, round_keys[rnd])
        AES.sub_bytes(state)
        AES.shift_rows(state)
        AES.add_round_key(state, round_keys[-1])
        return AES.matrix_to_bytes(state)

    @staticmethod
    def decrypt_block(ciphertext: bytes, round_keys: List[List[List[int]]]) -> bytes:
        assert len(ciphertext) == 16
        state = AES.bytes_to_matrix(ciphertext)
        AES.add_round_key(state, round_keys[-1])
        for rnd in range(len(round_keys) - 2, 0, -1):
            AES.inverse_shift_rows(state)
            AES.inverse_sub_bytes(state)
            AES.add_round_key(state, round_keys[rnd])
            AES.inverse_mix_columns(state)
        AES.inverse_shift_rows(state)
        AES.inverse_sub_bytes(state)
        AES.add_round_key(state, round_keys[0])
        return AES.matrix_to_bytes(state)


# --- DEMO -------------------------------------------------------------------

if __name__ == "__main__":
    AES.S_BOX = AES.generate_sbox()
    AES.INV_S_BOX = AES.generate_inverse_sbox(AES.S_BOX)

    plaintext = b"tizenhat byte!!!"
    key = b"16 byte-os kulcs"
    

    print("Plaintext:", plaintext)
    print("Key      :", key)

    round_keys = AES.key_expansion(key)
    ciphertext = AES.encrypt_block(plaintext, round_keys)
    decrypted = AES.decrypt_block(ciphertext, round_keys)

    print("Ciphertext (hex):", ciphertext.hex())
    print("Decrypted:", decrypted)
    print("Decryption successful:", decrypted == plaintext)

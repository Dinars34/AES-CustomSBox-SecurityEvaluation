import numpy as np

class SBoxGenerator:
    def __init__(self):
        # Irreducible polynomial m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B)
        self.irreducible_poly = 0x11B
        # Constant C = 0x63
        self.constant_c = 0x63
        # Affine Matrix K44 (Rows 0-7)
        # Note: We'll store this as a list of integers or a numpy array for bitwise ops
        # The input vector is usually [b0, b1, ..., b7]^T or similar depending on convention.
        # AES convention: b0 is LSB.
        # Let's define the matrix rows as integers for easier bitwise logic if we process manually,
        # or keep as bits for matrix multiplication.
        # Given the rows:
        # 1. 01110000
        # 2. 01110101
        # 3. 00111000
        # 4. 00011100
        # 5. 00001111
        # 6. 10000011
        # 7. 11000001
        # 8. 11100000
        # These look like MSB to LSB or vice versa?
        # Standard AES affine matrix row 0 is 10001111 (if b0 is LSB and we look at the equation).
        # Let's assume the provided rows are top-to-bottom, and bits are left-to-right.
        # We will interpret "01110000" as: column 0 to column 7?
        # Let's stick to a standard matrix multiplication approach.
        self.matrix_k44 = np.array([
            [0, 1, 1, 1, 0, 0, 0, 0],
            [0, 1, 1, 1, 0, 1, 0, 1],
            [0, 0, 1, 1, 1, 0, 0, 0],
            [0, 0, 0, 1, 1, 1, 0, 0],
            [0, 0, 0, 0, 1, 1, 1, 1],
            [1, 0, 0, 0, 0, 0, 1, 1],
            [1, 1, 0, 0, 0, 0, 0, 1],
            [1, 1, 1, 0, 0, 0, 0, 0]
        ], dtype=int)
        
        # Constant vector C = 0x63 = 01100011 (LSB first? or MSB?)
        # 0x63 = 0110 0011 in binary.
        # In AES, C is usually represented as vector.
        # If 0x63 is LSB at index 0: 1, 1, 0, 0, 0, 1, 1, 0
        # Let's assume standard byte representation where 0x63 = 99.
        self.c_vector = np.array([int(b) for b in format(0x63, '08b')[::-1]], dtype=int) # LSB at index 0

    def gf_multiply(self, a, b):
        """Galois Field multiplication of a and b in GF(2^8) modulo m(x)."""
        p = 0
        for i in range(8):
            if (b & 1):
                p ^= a
            hi_bit_set = (a & 0x80)
            a <<= 1
            if hi_bit_set:
                a ^= self.irreducible_poly
            b >>= 1
        return p & 0xFF

    def gf_inverse(self, byte):
        """Multiplicative inverse in GF(2^8). 0 maps to 0."""
        if byte == 0:
            return 0
        # Naive approach: try all values. Efficient enough for 256 values.
        # Or use Extended Euclidean Algorithm.
        # Since we generate the whole S-box once, brute force or power is fine.
        # a^(-1) = a^(254) in GF(2^8)
        # Using exponentiation by squaring
        res = 1
        base = byte
        exp = 254
        while exp > 0:
            if exp % 2 == 1:
                res = self.gf_multiply(res, base)
            base = self.gf_multiply(base, base)
            exp //= 2
        return res

    def affine_transform(self, byte):
        """Apply affine transformation: K44 * byte + C."""
        # Convert byte to bit vector (LSB at index 0)
        bits = np.array([int(b) for b in format(byte, '08b')[::-1]], dtype=int)
        
        # Matrix multiplication over GF(2)
        # K44 is 8x8, bits is 8x1.
        # We need to check if the matrix rows provided in instructions correspond to LSB..MSB or MSB..LSB.
        # The instructions say: "Rows 0-7: 01110000..."
        # Let's assume the matrix is given as printed in the paper, usually Row 0 corresponds to output bit 0 (LSB) or 7 (MSB).
        # In AES, the matrix is usually circulant.
        # Let's assume the provided matrix rows are for output bits b0, b1, ..., b7 (LSB to MSB) or b7..b0.
        # Let's try to interpret the matrix as: Row i produces bit i.
        # And the columns correspond to input bits.
        
        # Let's use the matrix as defined in __init__
        # We need to be careful about the bit order of the matrix rows.
        # The instruction says: "Use this exact binary matrix (Rows 0-7): 1. 01110000 ..."
        # Let's assume Row 0 is the top row.
        
        # We'll do: result_bits = (Matrix x input_bits) XOR C_bits
        
        # Note: The matrix in __init__ was defined with "01110000" as [0,1,1,1,0,0,0,0].
        # If this string is "b7 b6 ... b0" or "b0 b1 ... b7"?
        # Usually binary strings are MSB left.
        # So "01110000" -> MSB is 0, LSB is 0.
        # Let's re-parse the matrix rows from the strings assuming MSB-first strings.
        
        # Re-defining matrix inside here to be sure
        rows_str = [
            "01110000",
            "01110101",
            "00111000",
            "00011100",
            "00001111",
            "10000011",
            "11000001",
            "11100000"
        ]
        
        # If these are rows of the matrix, and we multiply by column vector x.
        # y = M * x + c
        # If x is [b0, ..., b7]^T (LSB top), then column j of M multiplies b_j.
        # If the string "01110000" represents the coefficients for [b7, ..., b0] or [b0, ..., b7]?
        # Let's assume standard convention:
        # Row 0 corresponds to the calculation of the LSB (or MSB) of the output.
        # The bits in the row correspond to weights of input bits.
        # Let's assume LSB is bit 0.
        # And the string is MSB..LSB (standard binary reading).
        # So "01110000" means coefficient for b6, b5, b4 are 1.
        
        # However, AES standard affine matrix is:
        # 1 0 0 0 1 1 1 1
        # 1 1 0 0 0 1 1 1
        # ...
        # This is often shown acting on [b0, ..., b7]^T.
        
        # Let's stick to: The string is MSB..LSB.
        # We convert input byte to bits [b7, ..., b0].
        # We multiply matrix by this vector.
        # Result is [y7, ..., y0].
        # Then we XOR with C.
        
        # Let's try this interpretation.
        
        input_bits_msb = np.array([int(b) for b in format(byte, '08b')], dtype=int) # [b7, b6, ..., b0]
        
        matrix = []
        for r in rows_str:
            matrix.append([int(x) for x in r])
        matrix = np.array(matrix, dtype=int)
        
        # Matrix multiplication modulo 2
        product = np.dot(matrix, input_bits_msb) % 2
        
        # Constant C = 0x63 = 01100011 (MSB..LSB)
        c_bits_msb = np.array([int(b) for b in format(0x63, '08b')], dtype=int)
        
        result_bits = (product + c_bits_msb) % 2
        
        # Convert back to integer
        res = 0
        for bit in result_bits:
            res = (res << 1) | bit
        return res

    def generate(self):
        """Generate the 16x16 S-box."""
        sbox = []
        for i in range(256):
            inv = self.gf_inverse(i)
            transformed = self.affine_transform(inv)
            sbox.append(transformed)
        return sbox

if __name__ == "__main__":
    gen = SBoxGenerator()
    sbox = gen.generate()
    print("Generated S-box (first 16 bytes):")
    print([hex(x) for x in sbox[:16]])

import numpy as np
from sbox_generator import SBoxGenerator

def check_matrix():
    gen = SBoxGenerator()
    matrix = gen.matrix_k44
    print("Matrix K44:")
    print(matrix)
    
    # Calculate determinant over GF(2)
    det = np.linalg.det(matrix)
    print(f"Determinant (real): {det}")
    det_gf2 = int(round(det)) % 2
    print(f"Determinant (GF2): {det_gf2}")
    
    if det_gf2 == 0:
        print("Matrix is SINGULAR over GF(2)!")
    else:
        print("Matrix is INVERTIBLE over GF(2).")

if __name__ == "__main__":
    check_matrix()

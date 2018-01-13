import sys

# wikipedia pseudocode
class RC4:

    def __init__(self, key, plaintext_length, use_ksa_star = False):
        self.plaintext_length = plaintext_length
        self.key = [ord(c) for c in key]

        if use_ksa_star:
            S = self.KSA_star(self.key)
        else:
            S = self.KSA(self.key)
        self.keystream = self.PRGA(S)

    def KSA(self, key):
        keylength = len(key)

        S = range(256)

        i = 0
        j = 0
        while i < 256:
            j = (j + S[i] + key[i % keylength]) % 256
            S[i], S[j] = S[j], S[i]  # swap
            i = i + 1

        return S

    def KSA_star(self, key):
        keylength = len(key)

        S = range(256)

        i = 0
        j = 0
        while i < 256:
            i = i + 1
            j = (j + S[i] + key[i % keylength]) % 256
            S[i], S[j] = S[j], S[i]  # swap

        return S

    def PRGA(self, S):
        i = 0
        j = 0
        K = ''
        for x in range(0, self.plaintext_length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]  # swap

            K += chr(S[(S[i] + S[j]) % 256])
        return K

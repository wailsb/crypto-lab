import string

def decrypt_caesar(text, key):
    result = ""
    for c in text:
        if c.isalpha():
            shift = ord('A')
            result += chr((ord(c) - shift - key) % 26 + shift)
        else:
            result += c
    return result

cipher = input("Encrypted text: ")

for key in range(26):
    print(f"Key {key}: {decrypt_caesar(cipher, key)}")

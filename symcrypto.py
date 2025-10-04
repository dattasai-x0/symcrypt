from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

import matplotlib.pyplot as plt


# Step 1: Original message
message = "Education loan approved for ₹10,00,000"

# Step 2: AES encryption
aes_key = get_random_bytes(16)
cipher_aes = AES.new(aes_key, AES.MODE_EAX)
ciphertext_aes, tag = cipher_aes.encrypt_and_digest(message.encode())

# Step 3: RSA encryption of AES key
rsa_key = RSA.generate(2048)
cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())
encrypted_aes_key = cipher_rsa.encrypt(aes_key)

# Output: Encrypted AES key + AES ciphertext


# Sample base64 string (from encrypted data)
encrypted_base64 = base64.b64encode(ciphertext_aes).decode()


#symbolencd
# Define a symbol map
symbol_map = {
    'A': '🔒', 'B': '🧠', 'C': '🧬', 'D': '💡', 'E': '🌐', 'F': '🛡️',
    'G': '⚙️', 'H': '📡', 'I': '🔍', 'J': '📦', 'K': '🧊', 'L': '🧪',
    'M': '🧱', 'N': '🧯', 'O': '🧞', 'P': '🧳', 'Q': '🧨', 'R': '🧵',
    'S': '🧶', 'T': '🧺', 'U': '🧼', 'V': '🧽', 'W': '🧻', 'X': '🪠',
    'Y': '🪤', 'Z': '🪢',
    'a': '🌟', 'b': '🚀', 'c': '🛰️', 'd': '🛸', 'e': '🌌', 'f': '🌠',
    'g': '🌈', 'h': '🔥', 'i': '💧', 'j': '🌊', 'k': '🌪️', 'l': '🌫️',
    'm': '🌋', 'n': '🪐', 'o': '☄️', 'p': '🌎', 'q': '🌍', 'r': '🌏',
    's': '🪺', 't': '🪹', 'u': '🪸', 'v': '🪷', 'w': '🪻', 'x': '🪼',
    'y': '🪿', 'z': '🫧',
    '0': '🔢', '1': '🔣', '2': '🔤', '3': '🔡', '4': '🔠', '5': '🔟',
    '6': '🔞', '7': '🔅', '8': '🔆', '9': '🔔',
    '+': '➕', '/': '➗', '=': '🟰'
}

# Convert encrypted string to symbols
symbolic_output = ''.join(symbol_map.get(char, char) for char in encrypted_base64)

print("Symbolic Encrypted Message:")
print(symbolic_output)


#decry
# Step 1: Reverse symbol map
reverse_symbol_map = {v: k for k, v in symbol_map.items()}

# Simulated symbolic input (from previous step)
symbolic_input = symbolic_output  # Replace with actual symbolic string

# Decode symbols back to base64 string
decoded_base64 = ''.join(reverse_symbol_map.get(sym, sym) for sym in symbolic_input)

# Convert base64 back to bytes
ciphertext_aes_decoded = base64.b64decode(decoded_base64)

# Step 2: RSA decryption of AES key
cipher_rsa_dec = PKCS1_OAEP.new(rsa_key)
decrypted_aes_key = cipher_rsa_dec.decrypt(encrypted_aes_key)

# Step 3: AES decryption
cipher_aes_dec = AES.new(decrypted_aes_key, AES.MODE_EAX, nonce=cipher_aes.nonce)
original_message = cipher_aes_dec.decrypt_and_verify(ciphertext_aes_decoded, tag)

print("Decrypted Message:")
print(original_message.decode())


# Visualization of the symbolic encrypted message
# Convert symbolic string to list of emojis
symbols = list(symbolic_output)

# Define grid size (e.g., 16x16)
grid_size = 16
rows = [symbols[i:i+grid_size] for i in range(0, len(symbols), grid_size)]

# Plot the grid
fig, ax = plt.subplots(figsize=(8, 8))
ax.axis('off')

for i, row in enumerate(rows):
    for j, sym in enumerate(row):
        ax.text(j, -i, sym, fontsize=14, ha='center', va='center')

plt.title("Encrypted Symbolic Grid", fontsize=16)
plt.show()

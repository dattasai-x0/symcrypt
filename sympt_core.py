from symcrypto import symcrypt_encrypt, symcrypt_decrypt, visualize_symbolic_grid

# Encrypt
result = symcrypt_encrypt("Education loan approved for ₹10,00,000")
print(result["symbolic_output"])

# Visualize
visualize_symbolic_grid(result["symbolic_output"])

# Decrypt
message = symcrypt_decrypt(
    result["symbolic_output"],
    result["encrypted_aes_key"],
    result["rsa_key"],
    result["nonce"],
    result["tag"]
)
print("Decrypted:", message)
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ==========================================
# RSA KEY GENERATION
# ==========================================
def generate_rsa_keys():
    os.makedirs("keys", exist_ok=True)

    private_key_path = "keys/private_key.pem"
    public_key_path = "keys/public_key.pem"

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        print("✅ RSA keys already exist.")
        return

    print("🔐 Generating RSA keys...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_key_path, "wb") as f:
        f.write(private_pem)

    with open(public_key_path, "wb") as f:
        f.write(public_pem)

    print("✅ RSA keys generated successfully.")


# ==========================================
# AES ENCRYPT
# ==========================================
def encrypt_file_aes(file_path):
    key = os.urandom(32)
    iv = os.urandom(16)

    with open(file_path, "rb") as f:
        data = f.read()

    from cryptography.hazmat.primitives import padding as sym_padding
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_file_path = file_path + ".enc"

    with open(encrypted_file_path, "wb") as f:
        f.write(iv + encrypted_data)

    return encrypted_file_path, key


# ==========================================
# AES DECRYPT
# ==========================================
def decrypt_file_aes(encrypted_file_path, key, output_folder="decrypted_files"):
    with open(encrypted_file_path, "rb") as f:
        file_data = f.read()

    iv = file_data[:16]
    encrypted_data = file_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    from cryptography.hazmat.primitives import padding as sym_padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    os.makedirs(output_folder, exist_ok=True)

    filename = os.path.basename(encrypted_file_path).replace(".enc", "")
    decrypted_file_path = os.path.join(output_folder, filename)

    with open(decrypted_file_path, "wb") as f:
        f.write(data)

    return decrypted_file_path


# ==========================================
# RSA ENCRYPT AES KEY
# ==========================================
def encrypt_key_rsa(aes_key):
    with open("keys/public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key


# ==========================================
# RSA DECRYPT AES KEY
# ==========================================
def decrypt_key_rsa(encrypted_key):
    with open("keys/private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_key
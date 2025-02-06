import os
import random
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC( 
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_honey(input_file, output_file, password):
    start_time = time.time()
    
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, "rb") as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext)
    fake_ciphertexts = [os.urandom(len(ciphertext)) for _ in range(4)]
    all_ciphertexts = fake_ciphertexts + [ciphertext]
    random.shuffle(all_ciphertexts)
    
    with open(output_file, "wb") as f:
        f.write(salt + nonce + b''.join(all_ciphertexts))
    
    elapsed_time = time.time() - start_time
    print(f"✅ ไฟล์ถูกเข้ารหัสและบันทึกที่: {output_file}")
    print(f"⏳ เวลาในการเข้ารหัส: {elapsed_time:.6f} วินาที")

def decrypt_honey(encrypted_file, output_file, password):
    start_time = time.time()
    
    with open(encrypted_file, "rb") as f:
        data = f.read()

    salt = data[:16]
    nonce = data[16:32]
    honey_ciphertexts = [data[i:i+len(data[32:])//5] for i in range(32, len(data), len(data[32:])//5)]

    key = derive_key(password, salt)
    decrypted_data = None
    
    for candidate in honey_ciphertexts:
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(candidate)

        if decrypted_data.startswith(b'Kaydara FBX Binary  '):
            break
    else:
        decrypted_data = os.urandom(len(decrypted_data))  # สร้างไฟล์ปลอม

    with open(output_file, "wb") as f:
        f.write(decrypted_data)
    
    elapsed_time = time.time() - start_time
    print(f"✅ ไฟล์ถูกถอดรหัสและบันทึกที่: {output_file}")
    print(f"⏳ เวลาในการถอดรหัส: {elapsed_time:.6f} วินาที")

# ใช้งาน
encrypt_honey("sid_costume_basic.fbx", "model_sid_encrypted.bin", "mypassword123")
decrypt_honey("model_sid_encrypted.bin", "model_sid_decrypted.fbx", "mypassword123")


#edit decrypt password for check wrong decrypt model
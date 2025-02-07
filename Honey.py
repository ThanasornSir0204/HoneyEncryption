import os
import random
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes):
    """ สร้างคีย์จากรหัสผ่าน """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_fake_fbx(length):
    """ สร้างข้อมูลปลอมที่มี Header คล้ายไฟล์ FBX """
    header = b'Kaydara FBX Binary  '
    fake_data = os.urandom(length - len(header))
    return header + fake_data

def encrypt_honey(input_file, output_file, password):
    """ เข้ารหัสไฟล์แบบ Honey Encryption (ไม่มี ChaCha20) """
    start_time = time.time()
    
    salt = os.urandom(16)
    key = derive_key(password, salt)

    with open(input_file, "rb") as f:
        plaintext = f.read()

    # 🔹 สร้างข้อมูลปลอม 4 อัน และผสมกับของจริง
    fake_ciphertexts = [generate_fake_fbx(len(plaintext)) for _ in range(4)]
    all_ciphertexts = fake_ciphertexts + [plaintext]
    random.shuffle(all_ciphertexts)

    # 🔹 บันทึกข้อมูลลงไฟล์
    with open(output_file, "wb") as f:
        f.write(salt + b''.join(all_ciphertexts))
    
    elapsed_time = time.time() - start_time
    print(f"✅ ไฟล์ถูกเข้ารหัสและบันทึกที่: {output_file}")
    print(f"⏳ เวลาในการเข้ารหัส: {elapsed_time:.6f} วินาที")

def decrypt_honey(encrypted_file, output_file, password):
    """ ถอดรหัสแบบ Honey Encryption """
    start_time = time.time()
    
    with open(encrypted_file, "rb") as f:
        data = f.read()

    salt = data[:16]
    honey_ciphertexts = [data[i:i+len(data[16:])//5] for i in range(16, len(data), len(data[16:])//5)]

    key = derive_key(password, salt)
    
    for candidate in honey_ciphertexts:
        if candidate.startswith(b'Kaydara FBX Binary  '):  # 🔹 ตรวจสอบ Header ไฟล์ FBX
            decrypted_data = candidate
            break
    else:
        decrypted_data = random.choice(honey_ciphertexts)  # 🔹 เลือกข้อมูลปลอมแบบสุ่ม
    
    with open(output_file, "wb") as f:
        f.write(decrypted_data)
    
    elapsed_time = time.time() - start_time
    print(f"✅ ไฟล์ถูกถอดรหัสและบันทึกที่: {output_file}")
    print(f"⏳ เวลาในการถอดรหัส: {elapsed_time:.6f} วินาที")

# 🔹 ทดสอบใช้งาน
encrypt_honey("sid_costume_basic.fbx", "model_sid_encrypted.bin", "mypassword123")
decrypt_honey("model_sid_encrypted.bin", "model_sid_decrypted.fbx", "mypassword1234")  # ทดสอบรหัสผิด

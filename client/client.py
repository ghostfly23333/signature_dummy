import json
import os
import socket
import base64
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# 导入私钥
def import_private_key():
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def sign_message_with_timestamp(private_key, action, value, user_password):
    timestamp = int(datetime.utcnow().timestamp())

    # 组织消息和时间戳
    data = {"action": action, "value": value, "timestamp": timestamp}
    json_data = json.dumps(data).encode("utf-8")

    # 使用用户密码加密 json_data
    encrypted_data = encrypt_data(json_data, user_password)

    encrypted_data_base64 = base64.b64encode(encrypted_data).decode("utf-8")

    # 使用私钥进行签名
    signature = private_key.sign(
        encrypted_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signature_base64 = base64.b64encode(signature).decode("utf-8")

    combined_data = {"username": username, "encrypted_data": encrypted_data_base64, "signature": signature_base64}
    send_data = json.dumps(combined_data).encode("utf-8")

    return send_data

def encrypt_data(data, password):
    # 使用 PBKDF2 密码导出器从用户密码生成密钥
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b'salt',
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    print("key: ", key)

    # 使用密钥创建 AES 密钥
    cipher_key = key[:16]
    iv = 16 * b'\x00'
    print("iv: ", iv)
    cipher = Cipher(algorithms.AES(cipher_key), mode=modes.CFB8(iv), backend=default_backend())
    
    # 使用 AES 密钥加密数据
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    return encrypted_data

host = "localhost"
port = 23333
username = "ghostfly233"
password = open("password.txt", "r").read()
print("password:", password)
message_preset = "Hello, World!"

def send_data(data):
    # 创建一个 socket 对象
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # 连接到服务器
        s.connect((host, port))

        # 发送数据
        print(f'Sending data: {data}')
        s.sendall(data)

    print("Message sent successfully.")

private_key = import_private_key()

while True:
    action = input("Action: ")
    value = input("Value: ")
    if action == "exit":
        break
    if action == "send_msg":
        value = message_preset
    send_data(sign_message_with_timestamp(private_key, action, value, password))
    if action == "chg_pwd":
        password = value
        open("password.txt", "w").write(password)
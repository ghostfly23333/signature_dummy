import json
import socket
import base64
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

account_dict = {}
def init_account_dict():
    with open("account.txt", "r") as f:
        for line in f.readlines():
            username, password = line.split()
            account_dict[username] = password
    print(account_dict)

# 导入公钥
def import_public_key():
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

public_key = import_public_key()

def decrypt_data(encrypted_data, password):
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

    # 提取初始化向量
    iv = 16 * b'\x00'
    print("iv: ", iv)

    # 使用密钥和初始化向量创建 AES 密钥
    cipher_key = key[:16]
    cipher = Cipher(algorithms.AES(cipher_key), mode=modes.CFB8(iv), backend=default_backend())
    
    # 使用 AES 密钥解密数据
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    return decrypted_data

# 验证签名和时间戳
def verify_signature(public_key, encrypt_data, signature):
    try:
        public_key.verify(
            signature,
            encrypt_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
        return True
    except Exception as e:
        print("Error verifying signature:", e)
        return False


def verify_timestamp(timestamp):    
    current_time = datetime.utcnow().timestamp()
    max_time_diff_seconds = timedelta(hours=1).total_seconds()  # 转换为秒
    time_diff = current_time - timestamp

    if abs(time_diff) > max_time_diff_seconds:
        print("Timestamp is too old. Signature is invalid.")
        return False

    print("Timestamp is valid.")
    return True

def update_account_file():
    for username, password in account_dict.items():
        with open("account.txt", "w") as f:
            f.write(f"{username} {password}\n")

def handle_client_data(username, encrypt_data, signature):
    # 验证签名
    if verify_signature(public_key, encrypt_data, signature):
        # 签名验证通过，解密数据
        origin_data = decrypt_data(encrypt_data, account_dict[username])
        try:
            origin_json_data = json.loads(origin_data.decode("utf-8"))
            timestamp = origin_json_data["timestamp"]
            if verify_timestamp(timestamp):
                action = origin_json_data["action"]
                value = origin_json_data["value"]
                if action == "send_msg":
                    print("client send_msg: ", value)
                elif action == "chg_pwd":
                    print("client chg_pwd: ", value)
                    account_dict[username] = value
                    update_account_file()
            else: 
                print("Timestamp is invalid.")
        except Exception as e:
            print("decrypt data failed! password mismatch.")
    else:
        # 签名验证失败，拒绝处理数据
        print("Invalid Signature. Data rejected.")

# 伪代码：接收客户端连接并处理数据
def receive_data_from_client():
    host = "localhost"
    port = 23333

    # 创建一个 socket 对象
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # 绑定到指定的地址和端口
        s.bind((host, port))
        # 监听连接
        s.listen()

        print(f"Server listening on {host}:{port}...")

        # 接受连接
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            received_data = conn.recv(1024)
            print("received_data: ", received_data)
            json_data_str = received_data.decode("utf-8")
            received_data_json = json.loads(json_data_str)
            username = received_data_json["username"]
            encrypt_data = base64.b64decode(received_data_json["encrypted_data"])
            signature = base64.b64decode(received_data_json["signature"])

            handle_client_data(username, encrypt_data, signature)

init_account_dict()
while True:
    receive_data_from_client()
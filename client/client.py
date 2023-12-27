import json
import socket
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# 导入私钥
def import_private_key():
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

# 生成带有时间戳的数字签名
def sign_message_with_timestamp(private_key, message):
    timestamp = int(datetime.utcnow().timestamp())

    # 使用 JSON 格式组织消息和时间戳
    data = {"message": message.decode("utf-8"), "timestamp": timestamp}
    json_data = json.dumps(data).encode("utf-8")

    # 使用私钥进行签名
    signature = private_key.sign(
        json_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return json_data, signature

# 示例用法
def send_data_to_server(json_data, signature):
    host = "localhost"
    port = 23333

    # 创建一个 socket 对象
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # 连接到服务器
        s.connect((host, port))

        # 发送数据
        print(json_data, signature)
        s.sendall(json_data)
        s.sendall(signature)

    print("Data sent successfully.")

private_key = import_private_key()

message_to_sign = open("message", "rb").read()

json_data, signature = sign_message_with_timestamp(private_key, message_to_sign)

send_data_to_server(json_data, signature)
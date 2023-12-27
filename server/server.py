import socket
import json
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# 导入公钥
def import_public_key():
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

# 验证签名和时间戳
def verify_signature(public_key, json_data, signature):
    #try:
    # 使用公钥验证签名
    public_key.verify(
        signature,
        json_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # 解析 JSON 数据
    data = json.loads(json_data.decode("utf-8"))
    timestamp = data["timestamp"]

    current_time = datetime.utcnow().timestamp()
    max_time_diff_seconds = timedelta(hours=1).total_seconds()  # 转换为秒
    time_diff = current_time - timestamp

    if abs(time_diff) > max_time_diff_seconds:
        print("Timestamp is too old. Signature is invalid.")
        return False

    print("Signature and timestamp are valid.")
    return True


# 伪代码：处理客户端数据
def handle_client_data(json_data, signature):
    # 导入服务器端的公钥
    public_key = import_public_key()

    # 验证签名
    if verify_signature(public_key, json_data, signature):
        # 签名验证通过，处理数据
        data = json.loads(json_data.decode("utf-8"))
        print("Received Data:")
        print("Message:", data["message"])
        print("Timestamp:", data["timestamp"])
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

            # 接收数据
            json_data = conn.recv(1024)
            signature = conn.recv(1024)

            # 处理客户端数据
            handle_client_data(json_data, signature)

# 示例用法
receive_data_from_client()
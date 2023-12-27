import json
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from keys_utils import import_private_key, import_public_key

# 生成签名
def sign_message(private_key, message):
    timestamp = int(datetime.utcnow().timestamp())

    data = {"message": message, "timestamp": timestamp}
    json_data = json.dumps(data).encode('utf-8')

    signature = private_key.sign(
        json_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return json_data, signature

# 验证签名
def verify_signature(public_key, json_data, signature):
    try:
        public_key.verify(
            signature,
            json_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("Signature is valid.")
        return True

    except Exception as e:
        print(f"Signature is invalid: {e}")
        return False

# 测试程序
def test_signature_verification():
    private_key = import_private_key()
    public_key = import_public_key()
    message_to_sign = "Hello, this is a test message."

    json_data, signature = sign_message(private_key, message_to_sign)

    # 输出签名结果
    print("JSON Data with Timestamp:", json_data)
    print("Signature:", signature)

    # 验证签名
    verify_signature(public_key, json_data, signature)

if __name__ == "__main__":
    test_signature_verification()
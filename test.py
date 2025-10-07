from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64
def sign_transaction(private_key_pem: str, sender: str, recipient: str, amount: int, fee: int, nonce: int) -> str:
    """
    Signiert eine Transaktion mit einem privaten PEM-Schlüssel.
    Gibt die Signatur als Base64-codierten String zurück.
    """
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)

    message = f"{sender}{recipient}{amount}{fee}{nonce}"
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode()
def verify_signature(public_key_pem, message: str, signature_b64: str) -> bool:
    try:
        if "BEGIN PUBLIC KEY" not in public_key_pem:
            public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{public_key_pem}\n-----END PUBLIC KEY-----"
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("Signature error:", e)
        return False
def load_key(filepath):
    with open(filepath, "rb") as key_file:
        return key_file.read().decode("utf-8")
privat_key = load_key("private_key.pem")
public_key = load_key("public_key.pem")

trans = {"sender": "akfasdlkjfakdfj", "recipient": "sdkfjalskdjf", "nonce": 0, "amount": 1, "fee": 0}
signature = sign_transaction(
    private_key_pem=privat_key,
    sender=trans["sender"],
    recipient=trans["recipient"],
    amount=trans["amount"],
    fee=trans["fee"],
    nonce=trans["nonce"]
)
message_str = f"{trans['sender']}{trans['recipient']}{trans['amount']}{trans['fee']}{trans['nonce']}"
print(verify_signature(public_key_pem=public_key, message=message_str, signature_b64=signature))
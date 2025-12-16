import hashlib
import secrets
from typing import Optional, Tuple


class SMPAuth:
    """SMP 协议认证管理器"""

    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """哈希密码，返回(哈希值, 盐值)"""
        if salt is None:
            salt = secrets.token_hex(16)

        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # 迭代次数
        ).hex()

        return password_hash, salt

    @staticmethod
    def verify_password(password: str, stored_hash: str, salt: str) -> bool:
        """验证密码"""
        password_hash, _ = SMPAuth.hash_password(password, salt)
        return password_hash == stored_hash

    @staticmethod
    def generate_token() -> str:
        """生成认证令牌"""
        return secrets.token_urlsafe(32)
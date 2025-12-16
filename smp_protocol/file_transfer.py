# file_transfer.py (V2 - Enhanced with State Management and Base64)

import os
import hashlib
import logging
import base64
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger('SMPFileTransfer')


class FileTransferState:
    """用于在服务器端跟踪单个文件传输的状态"""

    def __init__(self, transfer_id: str, filename: str, total_size: int, total_chunks: int, file_hash: str,
                 from_uid: str, to_uid: str):
        self.transfer_id = transfer_id
        self.filename = filename
        self.total_size = total_size
        self.total_chunks = total_chunks
        self.file_hash = file_hash
        self.from_uid = from_uid
        self.to_uid = to_uid
        self.received_chunks: Dict[int, bytes] = {}
        self.reassembled_path: Optional[str] = None

    def add_chunk(self, chunk_id: int, chunk_data: bytes):
        """添加一个文件块"""
        if chunk_id not in self.received_chunks:
            self.received_chunks[chunk_id] = chunk_data

    def is_complete(self) -> bool:
        """检查所有块是否都已接收"""
        return len(self.received_chunks) == self.total_chunks

    def reassemble_file(self, output_dir: str) -> bool:
        """在服务器上重新组装文件"""
        if not self.is_complete():
            return False

        # 创建一个安全的文件名，避免路径遍历攻击
        safe_filename = os.path.basename(self.filename)
        output_path = os.path.join(output_dir, f"{self.transfer_id}_{safe_filename}")

        try:
            with open(output_path, "wb") as f:
                for i in range(self.total_chunks):
                    f.write(self.received_chunks[i])

            self.reassembled_path = output_path
            logger.info(f"File reassembled at: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to reassemble file for transfer {self.transfer_id}: {e}")
            return False

    def verify_hash(self) -> bool:
        """验证重组后文件的哈希值"""
        if not self.reassembled_path or not os.path.exists(self.reassembled_path):
            return False

        calculated_hash = FileTransferManager.calculate_file_hash(self.reassembled_path)
        is_valid = calculated_hash == self.file_hash
        if not is_valid:
            logger.warning(
                f"File hash mismatch for {self.transfer_id}. Expected {self.file_hash}, got {calculated_hash}")
        return is_valid


class FileTransferManager:
    """文件传输工具管理器 (静态方法)"""

    CHUNK_SIZE = 8192  # 8KB 块大小，提高效率

    @staticmethod
    def calculate_file_hash(file_path: str) -> str:
        """计算文件哈希值"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            logger.error(f"Cannot calculate hash, file not found: {file_path}")
            return ""

    @staticmethod
    def encode_chunk(chunk_data: bytes) -> str:
        """将二进制块编码为Base64字符串，以便在JSON中传输"""
        return base64.b64encode(chunk_data).decode('ascii')

    @staticmethod
    def decode_chunk(chunk_b64: str) -> bytes:
        """将Base64字符串解码回二进制块"""
        return base64.b64decode(chunk_b64)

    @staticmethod
    def validate_file_size(file_path: str, max_size_mb: int = 20) -> bool:
        """验证文件大小"""
        try:
            max_size = max_size_mb * 1024 * 1024
            file_size = os.path.getsize(file_path)
            return file_size <= max_size
        except FileNotFoundError:
            return False
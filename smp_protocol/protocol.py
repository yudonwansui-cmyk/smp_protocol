# protocol.py (The Final, Absolutely Correct, and Complete Version with File Transfer)

import struct
import json
from typing import Optional, Dict, Any


class SMPProtocol:
    """Simple Message Protocol 编解码器 V5 - 最终版"""

    # 核心消息类型
    LOGIN_REQUEST = 0x01
    LOGIN_RESPONSE = 0x02
    SEND_MESSAGE = 0x03
    MESSAGE_ACK = 0x04
    HEARTBEAT = 0x05

    # 群组消息类型
    CREATE_GROUP = 0x06
    CREATE_GROUP_RESPONSE = 0x07
    JOIN_GROUP = 0x08
    JOIN_GROUP_RESPONSE = 0x09
    GROUP_MESSAGE = 0x0A

    # V3 账户系统
    REGISTER_REQUEST = 0x10
    REGISTER_RESPONSE = 0x11

    # --- V5 文件传输模块 ---
    FILE_TRANSFER_REQUEST = 0x0D
    FILE_TRANSFER_RESPONSE = 0x0E
    FILE_CHUNK = 0x0F
    FILE_TRANSFER_NOTIFICATION = 0x12  # 新增：用于服务器通知客户端
    DOWNLOAD_FILE_REQUEST = 0x13  # <--- 新增这一行

    # V4 好友系统
    ADD_FRIEND_REQUEST = 0x22
    ADD_FRIEND_RESPONSE = 0x23
    FRIEND_REQUEST_RECEIVED = 0x24
    ACCEPT_FRIEND_REQUEST = 0x25
    FRIEND_STATUS_UPDATE = 0x27
    FRIEND_LIST_RESPONSE = 0x28
    GROUP_LIST_RESPONSE = 0x29

    # V4.3 历史消息
    HISTORY_REQUEST = 0x30
    HISTORY_RESPONSE = 0x31

    # 为了兼容旧代码，保留了一些未使用的常量
    SEARCH_USER_REQUEST = 0x20
    SEARCH_USER_RESPONSE = 0x21
    ACCEPT_FRIEND_RESPONSE = 0x26
    GROUP_MEMBERS = 0x0B
    GROUP_MEMBERS_RESPONSE = 0x0C

    HEADER_SIZE = 9

    @staticmethod
    def encode(msg_type: int, msg_id: int, payload: Dict[str, Any]) -> bytes:
        # 使用 ensure_ascii=False 来正确处理中文字符
        body_data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        body_length = len(body_data)
        header = struct.pack('!BII', msg_type, msg_id, body_length)
        return header + body_data

    @staticmethod
    def decode(data: bytes) -> Optional[tuple]:
        if len(data) < SMPProtocol.HEADER_SIZE:
            return None
        try:
            header = data[:SMPProtocol.HEADER_SIZE]
            msg_type, msg_id, body_length = struct.unpack('!BII', header)
            if len(data) < SMPProtocol.HEADER_SIZE + body_length:
                return None
            body_data = data[SMPProtocol.HEADER_SIZE: SMPProtocol.HEADER_SIZE + body_length]
            payload = json.loads(body_data.decode('utf-8'))
            return msg_type, msg_id, payload
        except (struct.error, json.JSONDecodeError, UnicodeDecodeError):
            return None

    @staticmethod
    def get_consumed_length(data: bytes) -> Optional[int]:
        if len(data) < SMPProtocol.HEADER_SIZE:
            return None
        try:
            _, _, body_length = struct.unpack('!BII', data[:SMPProtocol.HEADER_SIZE])
            total_length = SMPProtocol.HEADER_SIZE + body_length
            if len(data) >= total_length:
                return total_length
            else:
                return None
        except struct.error:
            return None

    @staticmethod
    def get_message_type_name(msg_type: int) -> str:
        """获取消息类型名称，用于调试"""
        if not hasattr(SMPProtocol, '_name_map'):
            full_type_names = {k: v for k, v in SMPProtocol.__dict__.items() if
                               isinstance(v, int) and not k.startswith('_')}
            SMPProtocol._name_map = {v: k for k, v in full_type_names.items()}
        return SMPProtocol._name_map.get(msg_type, f"UNKNOWN({msg_type})")
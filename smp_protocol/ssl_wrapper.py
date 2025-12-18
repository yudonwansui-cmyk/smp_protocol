import ssl
import socket
import logging
from typing import Optional

logger = logging.getLogger('SMPSSL')


class SSLWrapper:
    """SSL/TLS 包装器"""

    @staticmethod
    def create_server_context(certfile: str, keyfile: str) -> ssl.SSLContext:
        """创建服务器 SSL 上下文"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # 对于自签名证书

        logger.info("Server SSL context created")
        return context

    @staticmethod
    def create_client_context(cafile: Optional[str] = None) -> ssl.SSLContext:
        """创建客户端 SSL 上下文"""
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        if cafile:
            context.load_verify_locations(cafile)
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        logger.info("Client SSL context created")
        return context

    @staticmethod
    def wrap_server_socket(sock: socket.socket, context: ssl.SSLContext) -> ssl.SSLSocket:
        """包装服务器 socket"""
        return context.wrap_socket(sock, server_side=True)

    @staticmethod
    def wrap_client_socket(sock: socket.socket, context: ssl.SSLContext,
                           server_hostname: Optional[str] = None) -> ssl.SSLSocket:
        """包装客户端 socket"""
        return context.wrap_socket(sock, server_hostname=server_hostname)
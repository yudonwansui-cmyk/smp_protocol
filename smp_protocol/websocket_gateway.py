import asyncio
import websockets
import json
import logging
import threading
import time
from typing import Dict, Any, Set
# 1. 从正确的子模块导入 WebSocketServerProtocol
from client_enhanced import SMPEnhancedClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('WebSocketGateway')


class WebSocketGateway:
    """WebSocket 网关，连接 Web 客户端和 SMP 服务器"""

    def __init__(self, smp_host='localhost', smp_port=8888, ws_port=8765):
        self.smp_host = smp_host
        self.smp_port = smp_port
        self.ws_port = ws_port
        # 1. 使用修正后的类型提示
        self.connected_websockets: Set['websockets.WebSocketServerProtocol'] = set()
        self.smp_client = None
        self.running = False

    async def start(self):
        """启动 WebSocket 服务器"""
        self.running = True

        # 启动 SMP 客户端
        self._start_smp_client()

        # 启动 WebSocket 服务器
        # 警告 2 可以忽略，因为我们的代码是正确的
        start_server = websockets.serve(self.handle_websocket, "localhost", self.ws_port)
        await start_server
        logger.info(f"WebSocket gateway started on port {self.ws_port}")

        # 保持运行
        while self.running:
            await asyncio.sleep(1)

    def _start_smp_client(self):
        """启动 SMP 客户端"""

        def client_thread():
            self.smp_client = SMPEnhancedClient(
                server_host=self.smp_host,
                server_port=self.smp_port
            )

            # 连接到 SMP 服务器（使用网关用户名）
            if self.smp_client.connect("WebGateway"):
                self.smp_client.start_heartbeat()
                logger.info("SMP client connected")

                # 处理来自 SMP 服务器的消息
                while self.running and self.smp_client.is_connected():
                    message = self.smp_client.get_message()
                    if message:
                        asyncio.run_coroutine_threadsafe(
                            self.broadcast_to_websockets(message),
                            asyncio.get_event_loop()
                        )
                    time.sleep(0.1)
            else:
                logger.error("Failed to connect SMP client")

        threading.Thread(target=client_thread, daemon=True).start()

    async def handle_websocket(self, websocket,_path):
        """处理 WebSocket 连接"""
        self.connected_websockets.add(websocket)
        logger.info(f"WebSocket client connected. Total: {len(self.connected_websockets)}")

        try:
            async for message in websocket:
                await self.handle_websocket_message(websocket, message)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.connected_websockets.remove(websocket)
            logger.info(f"WebSocket client disconnected. Total: {len(self.connected_websockets)}")

    async def handle_websocket_message(self, websocket, message: str):
        """处理来自 WebSocket 客户端的消息"""
        try:
            data = json.loads(message)
            action = data.get('action')

            if action == 'login':
                await self.handle_login(websocket, data)
            elif action == 'send_message':
                await self.handle_send_message(data)
            elif action == 'create_group':
                await self.handle_create_group(data)
            elif action == 'join_group':
                await self.handle_join_group(data)
            elif action == 'send_group_message':
                await self.handle_send_group_message(data)

        except json.JSONDecodeError:
            logger.error("Invalid JSON received from WebSocket")

    async def handle_login(self, websocket, data: Dict[str, Any]):
        """处理登录"""
        username = data.get('username', '').strip()

        if not username:
            response = {'action': 'login_response', 'status': 'error', 'message': 'Username required'}
            await websocket.send(json.dumps(response))
            return

        # 发送欢迎消息
        response = {
            'action': 'login_response',
            'status': 'success',
            'message': f'Welcome {username}!',
            'username': username
        }
        await websocket.send(json.dumps(response))

        # 广播用户加入
        join_message = {
            'action': 'system_message',
            'message': f'{username} joined the chat',
            'timestamp': time.time()
        }
        await self.broadcast_to_websockets(join_message)

    async def handle_send_message(self, data: Dict[str, Any]):
        """处理发送消息"""
        if not self.smp_client or not self.smp_client.is_connected():
            return

        message = data.get('message', '').strip()
        target = data.get('target', 'all')
        username = data.get('username', 'Unknown')

        if message:
            # 通过 SMP 客户端发送消息
            self.smp_client.send_message(f"{username}: {message}", target)

    async def handle_create_group(self, data: Dict[str, Any]):
        """处理创建群组"""
        if not self.smp_client or not self.smp_client.is_connected():
            return

        group_name = data.get('group_name', '').strip()
        username = data.get('username', 'Unknown')

        if group_name:
            if self.smp_client.create_group(group_name):
                # 通知 Web 客户端
                response = {
                    'action': 'system_message',
                    'message': f'{username} created group {group_name}',
                    'timestamp': time.time()
                }
                await self.broadcast_to_websockets(response)

    async def handle_join_group(self, data: Dict[str, Any]):
        """处理加入群组"""
        if not self.smp_client or not self.smp_client.is_connected():
            return

        group_name = data.get('group_name', '').strip()
        username = data.get('username', 'Unknown')

        if group_name:
            if self.smp_client.join_group(group_name):
                # 通知 Web 客户端
                response = {
                    'action': 'system_message',
                    'message': f'{username} joined group {group_name}',
                    'timestamp': time.time()
                }
                await self.broadcast_to_websockets(response)

    async def handle_send_group_message(self, data: Dict[str, Any]):
        """处理发送群组消息"""
        if not self.smp_client or not self.smp_client.is_connected():
            return

        group_name = data.get('group_name', '').strip()
        message = data.get('message', '').strip()
        username = data.get('username', 'Unknown')

        if group_name and message:
            self.smp_client.send_group_message(group_name, f"{username}: {message}")

    async def broadcast_to_websockets(self, message: Dict[str, Any]):
        """广播消息给所有 WebSocket 客户端"""
        if not self.connected_websockets:
            return

        message_json = json.dumps(message)

        disconnected = set()
        for websocket in self.connected_websockets:
            try:
                await websocket.send(message_json)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(websocket)

        # 移除断开的连接
        for websocket in disconnected:
            self.connected_websockets.remove(websocket)

    def stop(self):
        """停止网关"""
        self.running = False
        if self.smp_client:
            self.smp_client.disconnect()


async def main():
    """主函数"""
    gateway = WebSocketGateway()
    try:
        await gateway.start()
    except KeyboardInterrupt:
        gateway.stop()


if __name__ == "__main__":
    asyncio.run(main())
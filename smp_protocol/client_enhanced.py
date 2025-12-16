# client_enhanced.py (V-Final Perfected Version with File Transfer)

import socket, threading, time, json, logging, os
from queue import Queue, Empty
from tkinter import messagebox
from protocol import SMPProtocol
from file_transfer import FileTransferManager

# Placeholder for SSL module if not used
try:
    from ssl_wrapper import SSLWrapper
except ImportError:
    SSLWrapper = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SMPEnhancedClient')


class SMPEnhancedClient:
    def __init__(self, server_host='localhost', server_port=8899, use_ssl=False, cafile=None):
        self.server_host, self.server_port = server_host, server_port
        self.socket, self.connected, self.authenticated = None, False, False
        self.msg_counter, self.username, self.user_data = 0, "", {}
        self.response_queue, self.message_queue = Queue(), Queue()
        self.lock = threading.Lock()
        self.ssl_context = None
        if use_ssl and SSLWrapper: self.ssl_context = SSLWrapper.create_client_context(cafile)
        self.download_dir = "downloads"  # 新增：客户端下载文件夹
        if not os.path.exists(self.download_dir):
            os.makedirs(self.download_dir)
        self.active_downloads = {}  # 新增：跟踪下载状态

    def register(self, username: str, password: str) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.server_host, self.server_port))
                s.send(
                    SMPProtocol.encode(SMPProtocol.REGISTER_REQUEST, 0, {'username': username, 'password': password}))
                if data := s.recv(4096):
                    if msg := SMPProtocol.decode(data):
                        if msg[0] == SMPProtocol.REGISTER_RESPONSE and msg[2].get('status') == 'success':
                            messagebox.showinfo("Success", msg[2].get('message', 'Registration successful!'));
                            return True
                        else:
                            messagebox.showerror("Registration Failed", msg[2].get('message', 'Unknown error'))
                return False
        except Exception as e:
            messagebox.showerror("Error", f"Could not connect to server: {e}"); return False

    def connect(self, username: str, password: str) -> bool:
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            self.connected = True;
            self.username = username
            threading.Thread(target=self._receive_messages, daemon=True).start()
            with self.lock:
                msg_id = self.msg_counter; self.msg_counter += 1
            self.socket.send(
                SMPProtocol.encode(SMPProtocol.LOGIN_REQUEST, msg_id, {'username': username, 'password': password}))
            if (resp := self._wait_for_response(SMPProtocol.LOGIN_RESPONSE, msg_id)) and resp[2].get(
                    'status') == 'success':
                self.authenticated = True;
                self.user_data = resp[2];
                return True
            else:
                messagebox.showerror("Login Failed", resp[2].get('message', 'Timeout') if resp else 'Timeout');
                self.disconnect();
                return False
        except Exception as e:
            messagebox.showerror("Error", f"Could not connect to server: {e}"); return False

    def _receive_messages(self):
        buffer = b""
        while self.connected:
            try:
                data = self.socket.recv(8192)
                if not data: self.message_queue.put({'type': 'system', 'message': 'Server closed connection'}); break
                buffer += data
                while True:
                    if (length := SMPProtocol.get_consumed_length(buffer)) is None: break
                    if msg := SMPProtocol.decode(buffer[:length]): self._handle_received_message(*msg)
                    buffer = buffer[length:]
            except (ConnectionError, OSError):
                break
        self.disconnect()

    def _handle_received_message(self, msg_type: int, msg_id: int, payload: dict):
        response_types = {SMPProtocol.LOGIN_RESPONSE, SMPProtocol.REGISTER_RESPONSE, SMPProtocol.MESSAGE_ACK,
                          SMPProtocol.CREATE_GROUP_RESPONSE,
                          SMPProtocol.JOIN_GROUP_RESPONSE, SMPProtocol.ADD_FRIEND_RESPONSE,
                          SMPProtocol.FILE_TRANSFER_RESPONSE}

        # --- VVV 新增对下载文件块的处理 VVV ---
        if msg_type == SMPProtocol.FILE_CHUNK:
            transfer_id = payload.get('transfer_id')
            if transfer_id in self.active_downloads:
                state = self.active_downloads[transfer_id]

                if payload.get('final'):  # 检查是否是结束标志
                    output_path = os.path.join(self.download_dir, state.filename)
                    if state.reassemble(output_path):
                        messagebox.showinfo("Download Complete",
                                            f"File '{state.filename}' has been saved to your downloads folder.")
                    else:
                        messagebox.showerror("Error", f"Failed to reassemble file '{state.filename}'.")
                    del self.active_downloads[transfer_id]
                else:
                    chunk_data = FileTransferManager.decode_chunk(payload['data'])
                    state.add_chunk(payload['chunk_id'], chunk_data)
            return  # 直接返回，不放入任何队列
        # --- ^^^ 处理结束 ^^^ ---

        if msg_type in response_types:
            self.response_queue.put((msg_type, msg_id, payload))
        else:
            self.message_queue.put(payload)

    def download_file(self, transfer_id: str, filename: str, filesize: int):
        """向服务器请求下载文件"""
        if transfer_id in self.active_downloads:
            messagebox.showwarning("In Progress", "This file is already being downloaded.")
            return

        self.active_downloads[transfer_id] = FileDownloadState(transfer_id, filename, filesize)
        payload = {'transfer_id': transfer_id}
        with self.lock:
            msg_id = self.msg_counter;
            self.msg_counter += 1

        try:
            self.socket.send(SMPProtocol.encode(SMPProtocol.DOWNLOAD_FILE_REQUEST, msg_id, payload))
            messagebox.showinfo("Download Started", f"Downloading '{filename}'...")
        except Exception as e:
            logger.error(f"Failed to send download request for {transfer_id}: {e}")
            del self.active_downloads[transfer_id]

    def get_message(self):
        try:
            return self.message_queue.get_nowait()
        except Empty:
            return None

    def _wait_for_response(self, expected_type, expected_id, timeout=5):
        start = time.time();
        temp = []
        while time.time() - start < timeout:
            try:
                msg_type, msg_id, payload = self.response_queue.get(timeout=0.1)
                if msg_type == expected_type and msg_id == expected_id:
                    for item in temp: self.response_queue.put(item)
                    return msg_type, msg_id, payload
                else:
                    temp.append((msg_type, msg_id, payload))
            except Empty:
                continue
        for item in temp: self.response_queue.put(item)
        return None

    def start_heartbeat(self):
        def loop():
            while self.connected and self.authenticated:
                with self.lock:
                    msg_id = self.msg_counter; self.msg_counter += 1
                try:
                    self.socket.send(SMPProtocol.encode(SMPProtocol.HEARTBEAT, msg_id, {}))
                except (ConnectionError, OSError):
                    break
                time.sleep(10)

        threading.Thread(target=loop, daemon=True).start()

    def disconnect(self):
        if self.connected:
            self.connected = self.authenticated = False
            if self.socket:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.socket.close()
            logger.info("Disconnected")

    def _send_request_and_wait(self, msg_type, resp_type, payload):
        if not self.connected or not self.authenticated: return None
        with self.lock:
            msg_id = self.msg_counter; self.msg_counter += 1
        try:
            self.socket.send(SMPProtocol.encode(msg_type, msg_id, payload))
            if response := self._wait_for_response(resp_type, msg_id): return response[2]
        except Exception as e:
            logger.error(f"Request {SMPProtocol.get_message_type_name(msg_type)} failed: {e}")
        return None

    def send_private_message(self, target_id: str, message: str) -> bool:
        return self._send_request_and_wait(SMPProtocol.SEND_MESSAGE, SMPProtocol.MESSAGE_ACK,
                                           {'target_id': target_id, 'message': message}) is not None

    def send_group_message(self, group_id: str, message: str) -> bool:
        return self._send_request_and_wait(SMPProtocol.GROUP_MESSAGE, SMPProtocol.MESSAGE_ACK,
                                           {'group_id': group_id, 'message': message}) is not None

    def add_friend(self, target_id: str):
        return self._send_request_and_wait(SMPProtocol.ADD_FRIEND_REQUEST, SMPProtocol.ADD_FRIEND_RESPONSE,
                                           {'target_id': target_id})

    def create_group(self, name: str):
        return self._send_request_and_wait(SMPProtocol.CREATE_GROUP, SMPProtocol.CREATE_GROUP_RESPONSE,
                                           {'group_name': name})

    def join_group(self, group_id: str):
        return self._send_request_and_wait(SMPProtocol.JOIN_GROUP, SMPProtocol.JOIN_GROUP_RESPONSE,
                                           {'group_id': group_id})

    def accept_friend_request(self, requester_id: str):
        if not self.connected or not self.authenticated: return
        with self.lock:
            msg_id = self.msg_counter; self.msg_counter += 1
        try:
            self.socket.send(
                SMPProtocol.encode(SMPProtocol.ACCEPT_FRIEND_REQUEST, msg_id, {'requester_id': requester_id}))
        except Exception as e:
            logger.error(f"Failed to accept friend request: {e}")

    # --- 新增：文件传输方法 ---
    def initiate_file_transfer(self, file_path: str, target_id: str):
        """启动文件传输流程"""
        if not os.path.exists(file_path): return messagebox.showerror("Error", "File does not exist.")
        if not FileTransferManager.validate_file_size(file_path): return messagebox.showerror("Error",
                                                                                              "File is too large (max 20MB).")

        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        file_hash = FileTransferManager.calculate_file_hash(file_path)

        req_payload = {'target_id': target_id, 'filename': filename, 'size': file_size, 'hash': file_hash}

        response = self._send_request_and_wait(SMPProtocol.FILE_TRANSFER_REQUEST, SMPProtocol.FILE_TRANSFER_RESPONSE,
                                               req_payload)

        if response and response.get('status') == 'success':
            transfer_id = response.get('transfer_id')
            messagebox.showinfo("File Transfer",
                                f"Started uploading '{filename}'. You will be notified upon completion.")
            # 使用线程在后台发送文件块，避免UI冻结
            threading.Thread(target=self._send_file_chunks, args=(file_path, transfer_id), daemon=True).start()
        else:
            messagebox.showerror("Error",
                                 f"File transfer rejected: {response.get('message', 'Unknown error') if response else 'Timeout'}")

    def _send_file_chunks(self, file_path: str, transfer_id: str):
        """读取文件并发送所有块"""
        try:
            with open(file_path, "rb") as f:
                chunk_id = 0
                while True:
                    chunk_data = f.read(FileTransferManager.CHUNK_SIZE)
                    if not chunk_data: break

                    encoded_chunk = FileTransferManager.encode_chunk(chunk_data)
                    chunk_payload = {'transfer_id': transfer_id, 'chunk_id': chunk_id, 'data': encoded_chunk}

                    with self.lock:
                        msg_id = self.msg_counter; self.msg_counter += 1
                    self.socket.sendall(SMPProtocol.encode(SMPProtocol.FILE_CHUNK, msg_id, chunk_payload))
                    chunk_id += 1
                    time.sleep(0.01)  # 轻微延迟，防止网络拥塞
            logger.info(f"All chunks for transfer {transfer_id} have been sent.")
        except Exception as e:
            logger.error(f"Error sending file chunks for {transfer_id}: {e}")

# 添加一个新的下载状态类
class FileDownloadState:
    def __init__(self, transfer_id, filename, total_size):
        self.transfer_id = transfer_id
        self.filename = filename
        self.total_size = total_size
        self.received_chunks = {}
        self.received_size = 0

    def add_chunk(self, chunk_id, data):
        if chunk_id not in self.received_chunks:
            self.received_chunks[chunk_id] = data
            self.received_size += len(data)

    def reassemble(self, output_path):
        try:
            with open(output_path, "wb") as f:
                for i in range(len(self.received_chunks)):
                    f.write(self.received_chunks[i])
            return True
        except Exception:
            return False
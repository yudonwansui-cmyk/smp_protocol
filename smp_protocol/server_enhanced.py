# server_enhanced.py (The Final, Working Version with File Transfer)

import socket, threading, logging, json, time, traceback, os, uuid
from datetime import datetime

from protocol import SMPProtocol
from database import SMPDatabase
from auth import SMPAuth
from file_transfer import FileTransferManager, FileTransferState

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SMPServerV5-FT')


class SMPEnhancedServer:
    def __init__(self, host='0.0.0.0', port=8899):
        self.host, self.port, self.server_socket, self.running = host, port, None, False
        self.clients, self.groups = {}, {}
        self.lock, self.msg_counter = threading.Lock(), 0
        self.database = SMPDatabase()

        # --- 文件传输新增 ---
        self.active_transfers = {}
        self.server_download_dir = "server_files"
        if not os.path.exists(self.server_download_dir):
            os.makedirs(self.server_download_dir)
        # ---------------------
        logger.info("服务器 V5 (文件传输版) __init__ 完成")

    def _process_message(self, sock, cid, mtype, mid, payload):
        logger.info(f"--- SERVER RECEIVED --- Type: {SMPProtocol.get_message_type_name(mtype)}, From CID: {cid}")
        if mtype in [SMPProtocol.REGISTER_REQUEST, SMPProtocol.LOGIN_REQUEST]:
            if mtype == SMPProtocol.REGISTER_REQUEST: self._handle_register(sock, mid, payload)
            if mtype == SMPProtocol.LOGIN_REQUEST: return self._handle_login(sock, cid, mid, payload)
            return True

        with self.lock:
            if cid not in self.clients or not self.clients[cid][2]:
                logger.warning(f"客户端 {cid} 在未登录状态下尝试操作 {mtype}");
                return False

        handler = {
            SMPProtocol.SEND_MESSAGE: self._handle_message, SMPProtocol.GROUP_MESSAGE: self._handle_group_message,
            SMPProtocol.HEARTBEAT: self._handle_heartbeat, SMPProtocol.CREATE_GROUP: self._handle_create_group,
            SMPProtocol.JOIN_GROUP: self._handle_join_group,
            SMPProtocol.ADD_FRIEND_REQUEST: self._handle_add_friend_request,
            SMPProtocol.ACCEPT_FRIEND_REQUEST: self._handle_accept_friend_request,
            SMPProtocol.HISTORY_REQUEST: self._handle_history_request,
            # --- 文件传输新增处理器 ---
            SMPProtocol.FILE_TRANSFER_REQUEST: self._handle_file_transfer_request,
            SMPProtocol.FILE_CHUNK: self._handle_file_chunk,
            SMPProtocol.DOWNLOAD_FILE_REQUEST: self._handle_download_file_request,  # <--- 新增 handler
        }.get(mtype)

        if handler:
            handler(cid, mid, payload)
        else:
            logger.warning(f"收到未处理消息类型: {SMPProtocol.get_message_type_name(mtype)}")
        return True

    # --- 新增：文件传输处理器 ---
    def _handle_file_transfer_request(self, cid, mid, payload):
        with self.lock: sock, sname, suid, _ = self.clients[cid]
        target_uid = payload.get('target_id')
        target_cid = self._get_client_id_by_user_id(target_uid)

        if not target_cid:
            return self._send_response(sock, SMPProtocol.FILE_TRANSFER_RESPONSE, mid,
                                       {'status': 'error', 'message': 'User is offline.'})

        transfer_id = str(uuid.uuid4())
        total_chunks = (payload['size'] + FileTransferManager.CHUNK_SIZE - 1) // FileTransferManager.CHUNK_SIZE

        state = FileTransferState(transfer_id, payload['filename'], payload['size'], total_chunks, payload['hash'],
                                  suid, target_uid)
        with self.lock: self.active_transfers[transfer_id] = state

        self._send_response(sock, SMPProtocol.FILE_TRANSFER_RESPONSE, mid,
                            {'status': 'success', 'transfer_id': transfer_id})

        # 通知接收方
        with self.lock: target_sock, tname, _, _ = self.clients[target_cid]
        noti_payload = {'type': 'file_notification', 'from_username': sname, 'filename': payload['filename'],
                        'size': payload['size']}
        self._send_response(target_sock, SMPProtocol.FILE_TRANSFER_NOTIFICATION, self.msg_counter, noti_payload)
        self.msg_counter += 1

    def _handle_file_chunk(self, cid, mid, payload):
        transfer_id = payload.get('transfer_id')
        with self.lock:
            state = self.active_transfers.get(transfer_id)

        if not state: return logger.warning(f"Received chunk for unknown transfer_id: {transfer_id}")

        chunk_data = FileTransferManager.decode_chunk(payload['data'])
        state.add_chunk(payload['chunk_id'], chunk_data)

        if state.is_complete():
            logger.info(f"All chunks received for transfer {transfer_id}. Reassembling...")
            if state.reassemble_file(self.server_download_dir) and state.verify_hash():
                logger.info(f"File {state.filename} successfully transferred and verified.")
                # --- VVV 关键修改：通知中加入 transfer_id VVV ---
                success_payload = {
                    'from_username': self.clients[self._get_client_id_by_user_id(state.from_uid)][1],
                    'filename': state.filename,
                    'size': state.total_size,
                    'transfer_id': state.transfer_id  # 接收方需要这个ID来下载
                }
                # 通知发送方上传成功
                self._send_system_message_to_user(state.from_uid, f"File '{state.filename}' uploaded successfully.",
                                                  context_uid=state.to_uid)
                # 通知接收方文件已可供下载
                self._send_notification_to_user(state.to_uid, 'file_ready_for_download', success_payload)
                # --- ^^^ 修改结束 ^^^ ---
            else:
                logger.error(f"File reassembly or verification failed for {transfer_id}.")
                msg_text = f"File transfer for '{state.filename}' failed."
                self._send_system_message_to_user(state.from_uid, msg_text, context_uid=state.to_uid)
                self._send_system_message_to_user(state.to_uid, msg_text, context_uid=state.from_uid)

            # 不再删除 transfer，保留一段时间供下载
            # with self.lock: del self.active_transfers[transfer_id]

    def _handle_download_file_request(self, cid, mid, payload):
        """处理客户端的文件下载请求"""
        transfer_id = payload.get('transfer_id')
        with self.lock:
            state = self.active_transfers.get(transfer_id)
            sock, _, uid, _ = self.clients[cid]

        if not state or not state.reassembled_path:
            logger.warning(f"User {uid} requested invalid transfer {transfer_id}")
            return  # 可以选择发送一个错误通知

        # 验证请求下载的用户是否是合法的接收方
        if uid != state.to_uid:
            logger.warning(f"Unauthorized download attempt by {uid} for transfer {transfer_id}")
            return

        logger.info(f"User {uid} starting download for {state.filename} ({transfer_id})")
        # 使用线程在后台发送，避免阻塞服务器主线程
        threading.Thread(target=self._send_file_to_client, args=(sock, state), daemon=True).start()

    def _send_file_to_client(self, sock, state: FileTransferState):
        """从服务器读取文件并以块的形式发送给客户端"""
        try:
            with open(state.reassembled_path, "rb") as f:
                chunk_id = 0
                while True:
                    chunk_data = f.read(FileTransferManager.CHUNK_SIZE)
                    if not chunk_data:
                        break

                    encoded_chunk = FileTransferManager.encode_chunk(chunk_data)
                    # 复用 FILE_CHUNK 消息类型来发送下载的块
                    chunk_payload = {
                        'transfer_id': state.transfer_id,
                        'chunk_id': chunk_id,
                        'data': encoded_chunk,
                        'final': False  # 标记这不是最后一个块
                    }
                    sock.sendall(SMPProtocol.encode(SMPProtocol.FILE_CHUNK, 0, chunk_payload))
                    chunk_id += 1
                    time.sleep(0.01)

            # 发送一个特殊的结束块
            final_chunk_payload = {'transfer_id': state.transfer_id, 'final': True}
            sock.sendall(SMPProtocol.encode(SMPProtocol.FILE_CHUNK, 0, final_chunk_payload))
            logger.info(f"Finished sending file {state.filename} to client.")

        except Exception as e:
            logger.error(f"Error sending file chunks for download {state.transfer_id}: {e}")

    # 新增一个更通用的通知函数
    def _send_notification_to_user(self, user_id: str, noti_type: str, payload: dict):
        cid = self._get_client_id_by_user_id(user_id)
        if cid:
            with self.lock: sock, _, _, _ = self.clients[cid]
            payload['type'] = noti_type
            self._send_response(sock, SMPProtocol.FILE_TRANSFER_NOTIFICATION, self.msg_counter, payload)
            self.msg_counter += 1

    def _send_system_message_to_user(self, user_id: str, message: str, context_uid: str):
        """向特定用户发送私聊形式的系统消息,并提供上下文"""
        cid = self._get_client_id_by_user_id(user_id)
        if cid:
            with self.lock: sock, _, _, _ = self.clients[cid]
            # --- VVV CHANGE IS HERE VVV ---
            payload = {
                'type': 'message',
                'from_id': 'system',
                'from_username': 'System',
                'message': message,
                'context_uid': context_uid  # Add the ID of the other user in the conversation
            }
            # --- ^^^ CHANGE ENDS ^^^ ---
            self._send_response(sock, SMPProtocol.SEND_MESSAGE, self.msg_counter, payload)
            self.msg_counter += 1

    # --- 其他处理器保持不变 ---
    def _send_response(self, sock, ptype, mid, payload):
        try:
            sock.send(SMPProtocol.encode(ptype, mid, payload))
        except (OSError, ConnectionError) as e:
            logger.warning(f"发送响应失败: {e}")

    def _get_client_id_by_user_id(self, user_id: str) -> int | None:
        with self.lock:
            for cid, (_, _, uid, _) in self.clients.items():
                if uid == user_id: return cid
        return None

    def _handle_heartbeat(self, cid, mid, payload):
        with self.lock:
            if cid in self.clients: self.clients[cid] = (*self.clients[cid][:3], time.time())

    def _handle_register(self, sock, mid, payload):
        uname, pwd = payload.get('username', '').strip(), payload.get('password', '')
        if len(uname) < 3:
            resp = {'status': 'error', 'message': 'Username too short'}
        else:
            pwhash, salt = SMPAuth.hash_password(pwd)
            uid = self.database.add_user(uname, pwhash, salt)
            resp = {'status': 'success', 'message': 'Registration successful!', 'user_id': uid} if uid else {
                'status': 'error', 'message': 'Username exists or DB error'}
        self._send_response(sock, SMPProtocol.REGISTER_RESPONSE, mid, resp)

    def _handle_login(self, sock, cid, mid, payload):
        uname, pwd = payload.get('username', '').strip(), payload.get('password', '')
        udata = self.database.get_user_by_username(uname)
        if not udata:
            resp = {'status': 'error', 'message': 'User not found'}
        else:
            uid, _, pwhash, salt = udata
            if not SMPAuth.verify_password(pwd, pwhash, salt):
                resp = {'status': 'error', 'message': 'Invalid password'}
            else:
                with self.lock:
                    is_online = any(i[2] == uid for i in self.clients.values())
                if is_online:
                    resp = {'status': 'error', 'message': 'User already online'}
                else:
                    with self.lock:
                        self.clients[cid] = (sock, uname, uid, time.time())
                    resp = {'status': 'success', 'message': 'Login successful!', 'username': uname, 'user_id': uid}
                    logger.info(f"用户 '{uname}' (ID:{uid}) 登录成功")
                    friend_list = [{'user_id': fid, 'username': fname} for fid, fname in
                                   self.database.get_friend_list(uid)]
                    self._send_response(sock, SMPProtocol.FRIEND_LIST_RESPONSE, mid,
                                        {'type': 'friend_list', 'friends': friend_list})
                    group_list = [{'group_id': gid, 'group_name': gname} for gid, gname in
                                  self.database.get_user_groups(uid)]
                    self._send_response(sock, SMPProtocol.GROUP_LIST_RESPONSE, mid,
                                        {'type': 'group_list', 'groups': group_list})
        self._send_response(sock, SMPProtocol.LOGIN_RESPONSE, mid, resp)
        return resp.get('status') == 'success'

    def _handle_add_friend_request(self, cid, mid, payload):
        with self.lock:
            sock, sname, suid, _ = self.clients[cid]
        target_id = payload.get('target_id', '').strip()
        if not target_id or target_id == suid:
            resp = {'status': 'error', 'message': 'Invalid target ID.'}
            self._send_response(sock, SMPProtocol.ADD_FRIEND_RESPONSE, mid, resp);
            return
        if self.database.add_friend_request(suid, target_id):
            resp = {'status': 'success', 'message': 'Friend request sent.'}
            if target_cid := self._get_client_id_by_user_id(target_id):
                target_sock, _, _, _ = self.clients[target_cid]
                push_payload = {'type': 'friend_request_received', 'from_id': suid, 'from_username': sname}
                self._send_response(target_sock, SMPProtocol.FRIEND_REQUEST_RECEIVED, self.msg_counter, push_payload);
                self.msg_counter += 1
        else:
            resp = {'status': 'error', 'message': 'Request already sent or already friends.'}
        self._send_response(sock, SMPProtocol.ADD_FRIEND_RESPONSE, mid, resp)

    def _handle_accept_friend_request(self, cid, mid, payload):
        with self.lock:
            sock, accepter_name, accepter_id, _ = self.clients[cid]
        requester_id = payload.get('requester_id', '').strip()
        if not requester_id: return
        if self.database.accept_friend_request(requester_id, accepter_id):
            if requester_info := self.database.get_user_by_id(requester_id):
                update_payload = {'type': 'friend_status_update', 'friend_id': requester_info[0],
                                  'friend_name': requester_info[1], 'status': 'added'}
                self._send_response(sock, SMPProtocol.FRIEND_STATUS_UPDATE, self.msg_counter, update_payload)
            if requester_cid := self._get_client_id_by_user_id(requester_id):
                requester_sock, _, _, _ = self.clients[requester_cid]
                update_payload_requester = {'type': 'friend_status_update', 'friend_id': accepter_id,
                                            'friend_name': accepter_name, 'status': 'accepted_your_request'}
                self._send_response(requester_sock, SMPProtocol.FRIEND_STATUS_UPDATE, self.msg_counter,
                                    update_payload_requester)

    def _handle_message(self, cid, mid, payload):
        with self.lock:
            ssock, sname, suid, _ = self.clients[cid]
        msg, target_id = payload.get('message', '').strip(), payload.get('target_id', '')
        if not msg or not target_id: return
        if not self.database.are_friends(suid, target_id): return
        self.database.save_message(sname, target_id, 'private', msg)
        fwd_pl = {'type': 'message', 'from_id': suid, 'from_username': sname, 'message': msg}
        recipients_count = 0
        if target_cid := self._get_client_id_by_user_id(target_id):
            with self.lock: target_sock, _, _, _ = self.clients[target_cid]
            self._send_response(target_sock, SMPProtocol.SEND_MESSAGE, self.msg_counter, fwd_pl);
            self.msg_counter += 1
            recipients_count = 1
        self._send_response(ssock, SMPProtocol.MESSAGE_ACK, mid,
                            {'status': 'delivered', 'recipients': recipients_count})

    def _handle_create_group(self, cid, mid, payload):
        with self.lock:
            sock, uname, uid, _ = self.clients[cid]
        gname = payload.get('group_name', '').strip()
        if not gname:
            resp = {'status': 'error', 'message': 'Group name cannot be empty'}
        else:
            gid = self.database.create_group(gname, uid)
            if gid:
                with self.lock:
                    self.groups[gid] = [cid]
                resp = {'status': 'success', 'group_id': gid, 'group_name': gname}
            else:
                resp = {'status': 'error', 'message': 'Group name may exist'}
        self._send_response(sock, SMPProtocol.CREATE_GROUP_RESPONSE, mid, resp)

    def _handle_join_group(self, cid, mid, payload):
        with self.lock:
            sock, uname, uid, _ = self.clients[cid]
        gid = payload.get('group_id', '').strip()
        if not gid:
            resp = {'status': 'error', 'message': 'Group ID cannot be empty'}
        else:
            ginfo = self.database.get_group_by_id(gid)
            if not ginfo:
                resp = {'status': 'error', 'message': 'Group not found'}
            elif self.database.add_user_to_group(gid, uid):
                with self.lock:
                    if gid not in self.groups: self.groups[gid] = []
                    if cid not in self.groups[gid]: self.groups[gid].append(cid)
                _, gname = ginfo
                resp = {'status': 'success', 'group_id': gid, 'group_name': gname}
                self._notify_group_members(gid, f"'{uname}' has joined.", exclude_cid=cid)
            else:
                resp = {'status': 'error', 'message': 'Failed to join group'}
        self._send_response(sock, SMPProtocol.JOIN_GROUP_RESPONSE, mid, resp)

    def _handle_group_message(self, cid, mid, payload):
        with self.lock:
            ssock, sname, suid, _ = self.clients[cid]
        gid, msg = payload.get('group_id', ''), payload.get('message', '').strip()
        if not gid or not msg or not self.database.user_in_group(gid, suid): return
        ginfo = self.database.get_group_by_id(gid);
        gname = ginfo[1] if ginfo else gid
        self.database.save_message(sname, gid, 'group', msg)
        fwd_pl = {'type': 'group_message', 'from': sname, 'message': msg, 'group': gid, 'group_name': gname}
        with self.lock:
            if gid in self.groups:
                for mcid in self.groups[gid]:
                    if mcid != cid and mcid in self.clients:
                        self._send_response(self.clients[mcid][0], SMPProtocol.GROUP_MESSAGE, self.msg_counter, fwd_pl)
        self._send_response(ssock, SMPProtocol.MESSAGE_ACK, mid, {'status': 'delivered'})

    def _handle_history_request(self, cid, mid, payload):
        with self.lock:
            sock, _, suid, _ = self.clients[cid]
        target_type, target_id = payload.get('target_type'), payload.get('target_id')
        messages = []
        if target_type == 'user' and self.database.are_friends(suid, target_id):
            messages = self.database.get_history_messages(suid, target_id)
        elif target_type == 'group' and self.database.user_in_group(target_id, suid):
            messages = self.database.get_group_history(target_id)
        resp_payload = {'type': 'history_response', 'target_type': target_type, 'target_id': target_id,
                        'messages': messages}
        self._send_response(sock, SMPProtocol.HISTORY_RESPONSE, mid, resp_payload)

    def _notify_group_members(self, gid, message, exclude_cid=None):
        ginfo = self.database.get_group_by_id(gid);
        gname = ginfo[1] if ginfo else gid
        noti_pl = {'type': 'group_message', 'from': 'System', 'message': message, 'group': gid, 'group_name': gname,
                   'system': True}
        with self.lock:
            if gid in self.groups:
                for mcid in self.groups[gid]:
                    if mcid != exclude_cid and mcid in self.clients:
                        self._send_response(self.clients[mcid][0], SMPProtocol.GROUP_MESSAGE, self.msg_counter, noti_pl)

    def _handle_client(self, sock, cid):
        logger.info(f"客户端 {cid} 连接")
        buf = b""
        try:
            while self.running:
                try:
                    data = sock.recv(8192)
                    if not data: logger.info(f"客户端 {cid} 主动断开"); break
                    buf += data
                except (ConnectionError, OSError):
                    logger.warning(f"与客户端 {cid} 连接中断"); break
                while True:
                    consumed_length = SMPProtocol.get_consumed_length(buf)
                    if consumed_length is None: break
                    msg = SMPProtocol.decode(buf[:consumed_length])
                    buf = buf[consumed_length:]
                    if msg:
                        mtype, mid, payload = msg
                        if not self._process_message(sock, cid, mtype, mid, payload): raise ConnectionAbortedError()
        except Exception:
            pass
        finally:
            with self.lock:
                if cid in self.clients:
                    _, uname, uid, _ = self.clients[cid]
                    logger.info(f"客户端 {cid} ('{uname}') 线程结束")
                    for gid, members in list(self.groups.items()):
                        if cid in members:
                            members.remove(cid);
                            self._notify_group_members(gid, f"'{uname}' has left.")
                    del self.clients[cid]
            sock.close()

    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port));
            self.server_socket.listen(10)
            logger.info(f">>> 服务器 V5 已在 {self.host}:{self.port} 启动 <<<");
            self.running = True
            cid_counter = 0
            while self.running:
                try:
                    sock, addr = self.server_socket.accept();
                    cid_counter += 1
                    threading.Thread(target=self._handle_client, args=(sock, cid_counter), daemon=True).start()
                except OSError:
                    break
        except Exception:
            logger.error("!!! 服务器启动失败 !!!"); traceback.print_exc()
        finally:
            self.stop()

    def stop(self):
        if self.running:
            self.running = False;
            logger.info("正在停止服务器...")
            if self.server_socket: self.server_socket.close()
            with self.lock:
                for sock, _, _, _ in self.clients.values():
                    try:
                        sock.close()
                    except:
                        pass
            logger.info("服务器已停止")


if __name__ == "__main__":
    server = SMPEnhancedServer()
    try:
        server.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()